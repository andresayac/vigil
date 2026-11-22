//! Entries hidden from Windows' own lists, and services a standard user could take over.
//! READ-ONLY: the data comes from `vigil_sys::svcsec` (security descriptors, the service
//! database, the task cache); nothing is changed.
//!
//! - Collection puts everything under `sysconfig.service_security`.
//! - [`hidden_refs`] turns hidden services and tasks into references, so their programs are
//!   judged like any other startup entry; [`hidden_flag`] adds the "hidden" signal with its weight
//!   once the program's signature is known.
//! - [`items`] gives the configuration findings: services standard users can take over, hidden
//!   tasks whose action could not be read, and unquoted paths nobody can use.
//! - [`acl_writable`] tells the analysis, from real permissions, whether standard users can
//!   change a privileged service's program; the folder-name guess in `rules.rs` is only the
//!   fallback when the permissions could not be read.

use std::collections::HashMap;

use serde_json::{Map, Value, json};
use vigil_i18n::{tl, tr};

use crate::analyze::Ref;
use crate::cmdline::{ParsedCommand, expand_env, is_file, normalize_path, parse_command, resolve_program};
use crate::lenient::{Get, int_of, list, lower, rx, strip, text, truthy};
use crate::model::{Flag, Item, Role};
use crate::ntpath::isabs;
use crate::rules::{in_windows_dir, is_microsoft_signed, is_user_writable};

/// Where collection stores its results in the inventory.
pub(crate) const SECTION: &str = "service_security";

/// Whether a signer name belongs to a security vendor in [`SECURITY_VENDORS`].
pub(crate) fn is_security_vendor(signer: &str) -> bool {
    let signer = signer.to_lowercase();
    SECURITY_VENDORS.iter().any(|v| signer.contains(v))
}

/// Publishers whose programs hide their own services or tasks on purpose (tamper protection).
pub(crate) const SECURITY_VENDORS: &[&str] = &[
    "avast",
    "avg technologies",
    "bitdefender",
    "blackberry",
    "broadcom",
    "carbon black",
    "check point",
    "cisco",
    "crowdstrike",
    "cylance",
    "elastic",
    "emsisoft",
    "eset",
    "f-secure",
    "fortinet",
    "g data",
    "gen digital",
    "huntress",
    "kaspersky",
    "malwarebytes",
    "mcafee",
    "norton",
    "palo alto networks",
    "panda security",
    "sentinelone",
    "sophos",
    "symantec",
    "trellix",
    "trend micro",
    "vmware",
    "webroot",
    "withsecure",
];

// --------------------------------------------------------------------------- collection

/// Reads hidden services, hidden tasks and service permissions (Windows only).
#[cfg(windows)]
pub(crate) fn collect(elevated: bool) -> Value {
    use vigil_sys::svcsec;

    let mut notes: Vec<Value> = Vec::new();
    let Some(keys) = svcsec::service_keys() else {
        notes.push(
            json!({"area": tr!("services and drivers"), "message": tr!("the service database could not be read")}),
        );
        return json!({"elevated": elevated, "notes": notes});
    };

    let hidden_services = match svcsec::hidden_services(&keys) {
        Some(found) => Value::Array(
            found
                .into_iter()
                .map(|h| {
                    let dll = keys
                        .iter()
                        .find(|k| k.name.eq_ignore_ascii_case(&h.name))
                        .map(|k| k.service_dll.clone())
                        .unwrap_or_default();
                    json!({
                        "name": h.name,
                        "image": h.image,
                        "file": h.file,
                        "dll": dll,
                        "account": h.account,
                        "driver": h.driver,
                        "start": h.start,
                        "reason": h.reason,
                    })
                })
                .collect(),
        ),
        None => {
            notes.push(json!({"area": tr!("services and drivers"), "message": tr!("the list of services could not be compared with the registry")}));
            Value::Null
        }
    };

    let tasks = svcsec::hidden_tasks();
    if tasks.api_read && !tasks.registry_read && !tasks.files_read {
        notes.push(json!({
            "area": tr!("scheduled tasks"),
            "message": tr!("tasks hidden from Task Scheduler can only be found with administrator rights")
        }));
    }
    let hidden_tasks = json!({
        "api_read": tasks.api_read,
        "registry_read": tasks.registry_read,
        "files_read": tasks.files_read,
        "tasks": tasks.tasks.iter().map(|t| json!({
            "path": t.path,
            "reasons": t.reasons,
            "command": t.command,
            "arguments": t.arguments,
            "account": t.account,
        })).collect::<Vec<_>>(),
    });

    let perms = svcsec::permissions(&keys);
    if perms.unreadable > 0 && !elevated {
        notes.push(json!({
            "area": tr!("services and drivers"),
            "message": tr!("the permissions of {0} services could only be checked with administrator rights", perms.unreadable)
        }));
    }
    // Only programs the folder-name guess would call writable are kept: for them the real
    // permissions replace the guess.
    let binaries: Vec<Value> = perms
        .binaries
        .iter()
        .filter(|(path, _)| is_user_writable(path))
        .map(|(path, writable)| json!({"path": path, "writable": writable}))
        .collect();
    json!({
        "elevated": elevated,
        "hidden_services": hidden_services,
        "hidden_tasks": hidden_tasks,
        "permissions": {
            "checked": perms.checked,
            "unreadable": perms.unreadable,
            "weak": perms.weak.iter().map(|w| json!({
                "name": w.name,
                "account": w.account,
                "image": w.image,
                "driver": w.driver,
                "issues": w.issues.iter().map(|i| json!({
                    "kind": i.kind,
                    "target": i.target,
                    "rights": i.rights,
                    "exists": i.exists,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "unquoted_safe": perms.unquoted_safe,
            "binaries": binaries,
        },
        "notes": notes,
    })
}

#[cfg(not(windows))]
pub(crate) fn collect(elevated: bool) -> Value {
    json!({"elevated": elevated})
}

// --------------------------------------------------------------------------- references

fn section(raw: &Value) -> &Value {
    raw.at("sysconfig").at(SECTION)
}

fn map(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

rx!(EXEC_EXT, r"(?i)\.(exe|com|bat|cmd|vbs|js|ps1|msi|scr)$");

fn reason_text(reason: &str) -> String {
    match reason {
        "denied" => tr!("its permissions refuse even to show it"),
        "query_denied" => tr!("its permissions refuse to show it to administrators or everyone"),
        "unregistered" => {
            tr!("written to the registry without the Service Control Manager; it starts after the next restart")
        }
        "no_security_descriptor" => tr!("its security descriptor was removed"),
        "index_zero" => tr!("its index in the task cache was set to 0"),
        "file_only" => tr!("only its definition file is left"),
        _ => tr!("Task Scheduler does not list it"),
    }
}

/// Hidden services and tasks as references: their programs are judged like any other startup
/// entry, and [`hidden_flag`] adds the "hidden" signal.
pub(crate) fn hidden_refs(raw: &Value) -> Vec<Ref> {
    let mut refs = Vec::new();
    let sec = section(raw);
    for svc in list(sec.at("hidden_services")) {
        let name = text(svc.at("name"));
        let image = strip(&text(svc.at("image"))).to_string();
        let file = text(svc.at("file"));
        let reason = text(svc.at("reason"));
        let start = int_of(svc.at("start"));
        let driver = truthy(svc.at("driver"));
        let label = if driver {
            tr!(
                "driver \"{0}\" hidden from the Service Control Manager ({1})",
                name,
                reason_text(&reason)
            )
        } else {
            tr!(
                "service \"{0}\" hidden from the Service Control Manager ({1})",
                name,
                reason_text(&reason)
            )
        };
        let detail = map(vec![
            ("source", json!("hidden_service")),
            ("name", json!(name)),
            ("reason", json!(reason)),
            ("start", json!(start)),
        ]);
        let mut role = Role::new(if driver { "driver" } else { "service" }, label, detail);
        role.command = image.clone();
        role.persistent = start <= 2;
        role.privileged = true;
        role.active = start != 4;
        let mut parsed = if driver || isabs(&file) {
            ParsedCommand {
                program: Some(normalize_path(&file)),
                certain: true,
                ..ParsedCommand::new(&image)
            }
        } else {
            parse_command(&image, None)
        };
        let dll = normalize_path(&expand_env(&text(svc.at("dll"))));
        if !dll.is_empty() {
            parsed.host = Some("svchost.exe".into());
            parsed.payload = Some(if isabs(&dll) {
                dll
            } else {
                resolve_program(&dll, None).0
            });
        }
        refs.push(Ref::new(role, parsed));
    }
    for task in list(sec.at("hidden_tasks").at("tasks")) {
        let mut exe = strip(&text(task.at("command"))).to_string();
        if exe.is_empty() {
            continue;
        }
        let path = text(task.at("path"));
        let reasons: Vec<String> = list(task.at("reasons")).iter().map(text).collect();
        let args = strip(&text(task.at("arguments"))).to_string();
        if exe.contains(' ') && !exe.starts_with('"') && (is_file(&expand_env(&exe)) || EXEC_EXT.is_match(&exe)) {
            exe = format!("\"{exe}\"");
        }
        let command = if args.is_empty() { exe } else { format!("{exe} {args}") };
        let label = tr!(
            "scheduled task \"{0}\" hidden from Task Scheduler ({1})",
            path,
            reasons.iter().map(|r| reason_text(r)).collect::<Vec<_>>().join("; ")
        );
        let detail = map(vec![
            ("source", json!("hidden_task")),
            ("task_path", json!(path)),
            ("reasons", json!(reasons)),
            ("account", task.at("account").clone()),
        ]);
        let mut role = Role::new("task", label, detail);
        role.command = command.clone();
        role.persistent = true;
        role.active = true;
        let account = lower(&text(task.at("account")));
        role.privileged = account.is_empty() || account.contains("system") || account == "s-1-5-18";
        refs.push(Ref::new(role, parse_command(&command, None)));
    }
    refs
}

/// The "hidden" signal for an item whose references include a hidden service or task. Windows' own
/// components and security products restrict who may see their services on purpose: for them it is
/// information only.
pub(crate) fn hidden_flag(refs: &[Ref], info: Option<&Map<String, Value>>, path: &str) -> Option<Flag> {
    let source = refs.iter().find_map(|r| {
        let source = r.role.detail.get("source").and_then(Value::as_str)?;
        matches!(source, "hidden_service" | "hidden_task").then_some((source, r))
    })?;
    let (kind, reference) = source;
    let reason = text(reference.role.detail.at("reason"));
    let file_only = list(reference.role.detail.at("reasons"))
        .iter()
        .all(|r| text(r) == "file_only");
    let signer = info.map(|i| lower(&text(i.at("signer")))).unwrap_or_default();
    let valid = info.is_some_and(|i| i.at("sig_status").as_str() == Some("Valid"));
    let vendor = valid && SECURITY_VENDORS.iter().any(|v| signer.contains(v));
    let windows_part = is_microsoft_signed(info) && in_windows_dir(path);
    let weight = if vendor || windows_part {
        5
    } else if kind == "hidden_task" && file_only {
        // A leftover definition file: Task Scheduler does not run it.
        10
    } else if reason == "unregistered" {
        // Installers that write the registry directly do this too; it still skips the SCM.
        35
    } else {
        60
    };
    let text = if kind == "hidden_task" {
        tr!("scheduled task hidden from Task Scheduler")
    } else {
        tr!("service hidden from the Service Control Manager")
    };
    Some(Flag::new("hidden_entry", weight, text))
}

/// Lower-case program paths of privileged services whose real permissions were read, with whether
/// standard users can change the program or its folder.
pub(crate) fn acl_writable(raw: &Value) -> HashMap<String, bool> {
    list(section(raw).at("permissions").at("binaries"))
        .iter()
        .map(|b| (lower(&text(b.at("path"))), truthy(b.at("writable"))))
        .collect()
}

// --------------------------------------------------------------------------- findings

fn config(topic: &str, title: String, score: i64, text: String, facts: Map<String, Value>) -> Item {
    let mut item = Item::new("config", title, text.clone());
    let mut all = Map::new();
    all.insert("topic".into(), json!(topic));
    all.extend(facts);
    item.facts = all;
    item.add_flag(Flag::new(topic, score, text));
    item.rescore();
    item
}

fn right_text(right: &str) -> &'static str {
    match right {
        "write" => tl!("overwrite it"),
        "append" => tl!("add to it"),
        "add_file" => tl!("add files"),
        "delete_child" => tl!("delete files inside"),
        "set_value" => tl!("change its values"),
        "create_subkey" => tl!("add subkeys"),
        "change_config" => tl!("change its program or account"),
        "change_permissions" => tl!("change its permissions"),
        _ => tl!("take ownership"),
    }
}

fn issue_text(issue: &Value) -> (i64, String) {
    let target = text(issue.at("target"));
    let rights = list(issue.at("rights"))
        .iter()
        .map(|r| tr!(right_text(&text(r))))
        .collect::<Vec<_>>()
        .join(", ");
    match issue.at("kind").as_str().unwrap_or("") {
        "service" => (70, tr!("the service itself: standard users can {0}", rights)),
        "binary" => (70, tr!("its program {0}: standard users can {1}", target, rights)),
        "dll" => (70, tr!("its DLL {0}: standard users can {1}", target, rights)),
        "key" => (60, tr!("its registry key {0}: standard users can {1}", target, rights)),
        "folder" => (50, tr!("the folder {0}: standard users can {1}", target, rights)),
        _ if truthy(issue.at("exists")) => (
            80,
            tr!(
                "its path has spaces and no quotes, and {0} already exists: Windows runs it first",
                target
            ),
        ),
        _ => (
            55,
            tr!(
                "its path has spaces and no quotes: a program saved as {0} would run first",
                target
            ),
        ),
    }
}

/// Configuration findings: privileged services standard users can take over, hidden tasks whose
/// action could not be read, and unquoted paths nobody can use here.
pub(crate) fn items(raw: &Value) -> Vec<Item> {
    let mut out = Vec::new();
    let sec = section(raw);
    for svc in list(sec.at("permissions").at("weak")) {
        let name = text(svc.at("name"));
        let issues: Vec<(i64, String)> = list(svc.at("issues")).iter().map(issue_text).collect();
        let score = issues.iter().map(|(s, _)| *s).max().unwrap_or(0);
        let account = text(svc.at("account"));
        let account = if account.is_empty() {
            "LocalSystem".to_string()
        } else {
            account
        };
        let lines: Vec<String> = issues.iter().map(|(_, t)| t.clone()).collect();
        let text_all = if truthy(svc.at("driver")) {
            tr!(
                "the driver \"{0}\" runs in the Windows kernel; any program you run could use this to take over the computer: {1}",
                name,
                lines.join("; ")
            )
        } else {
            tr!(
                "the service \"{0}\" runs as {1}; any program you run could use this to gain those rights: {2}",
                name,
                account,
                lines.join("; ")
            )
        };
        out.push(config(
            "service_weak_permissions",
            tr!("Standard users can take over \"{0}\"", name),
            score,
            text_all,
            map(vec![
                ("service", json!(name)),
                ("account", json!(account)),
                ("image", svc.at("image").clone()),
                ("issues", svc.at("issues").clone()),
            ]),
        ));
    }
    for task in list(sec.at("hidden_tasks").at("tasks")) {
        if !strip(&text(task.at("command"))).is_empty() {
            continue;
        }
        let reasons: Vec<String> = list(task.at("reasons")).iter().map(text).collect();
        if reasons.iter().all(|r| r == "file_only") {
            continue;
        }
        let path = text(task.at("path"));
        out.push(config(
            "task_hidden_from_scheduler",
            tr!("Scheduled task hidden from Task Scheduler: {0}", path),
            60,
            tr!(
                "this task is registered but Task Scheduler does not show it ({0}); its action could not be read",
                reasons.iter().map(|r| reason_text(r)).collect::<Vec<_>>().join("; ")
            ),
            map(vec![("task_path", json!(path)), ("reasons", json!(reasons))]),
        ));
    }
    let safe = list(sec.at("permissions").at("unquoted_safe"));
    if !safe.is_empty() {
        out.push(config(
            "unquoted_service_path",
            tr!("Unquoted service paths that cannot be used here"),
            0,
            tr!(
                "these services have paths with spaces and no quotes; the folders where Windows would look first are protected, so no one can use them now"
            ),
            map(vec![("services", json!(safe))]),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory() -> Value {
        json!({"sysconfig": {SECTION: {
            "elevated": true,
            "hidden_services": [
                {"name": "FabrikamHelper", "image": "C:\\ProgramData\\Fabrikam\\helper.exe", "file": "C:\\ProgramData\\Fabrikam\\helper.exe",
                 "dll": "", "account": "LocalSystem", "driver": false, "start": 2, "reason": "denied"},
                {"name": "ZtHelperDemo", "image": "%SystemRoot%\\system32\\svchost.exe -k ZtHelper", "file": "C:\\Windows\\system32\\svchost.exe",
                 "dll": "C:\\Windows\\System32\\zthelper.dll", "account": "LocalSystem", "driver": false, "start": 3, "reason": "denied"}
            ],
            "hidden_tasks": {"api_read": true, "registry_read": true, "files_read": true, "tasks": [
                {"path": "\\ContosoSync", "reasons": ["not_listed", "no_security_descriptor"], "command": "C:\\Users\\Public\\sync.exe", "arguments": "--silent", "account": ""},
                {"path": "\\Ghost", "reasons": ["not_listed", "no_security_descriptor"], "command": "", "arguments": "", "account": ""},
                {"path": "\\Leftover", "reasons": ["file_only"], "command": "", "arguments": "", "account": ""}
            ]},
            "permissions": {
                "checked": 3, "unreadable": 0,
                "weak": [
                    {"name": "ContosoAgent", "account": "", "image": "C:\\Contoso Tools\\agent.exe", "driver": false, "issues": [
                        {"kind": "service", "target": "ContosoAgent", "rights": ["change_config"], "exists": false},
                        {"kind": "folder", "target": "C:\\Contoso Tools", "rights": ["add_file", "delete_child"], "exists": false},
                        {"kind": "unquoted", "target": "C:\\Contoso.exe", "rights": [], "exists": true}
                    ]}
                ],
                "unquoted_safe": ["TailspinVPN"],
                "binaries": [
                    {"path": "c:\\tools\\safe\\svc.exe", "writable": false},
                    {"path": "c:\\contoso tools\\agent.exe", "writable": true}
                ]
            }
        }}})
    }

    #[test]
    fn hidden_entries_become_references() {
        let refs = hidden_refs(&inventory());
        assert_eq!(refs.len(), 3, "two services and the task with an action");
        assert_eq!(refs[0].role.kind, "service");
        assert!(refs[0].role.privileged && refs[0].role.persistent);
        assert_eq!(
            refs[1].parsed.payload.as_deref(),
            Some("C:\\Windows\\System32\\zthelper.dll")
        );
        assert_eq!(refs[2].role.kind, "task");
        assert!(refs[2].role.command.contains("--silent"));
        assert!(refs[2].role.label.contains("ContosoSync"));
    }

    #[test]
    fn hidden_weight_depends_on_who_signed() {
        let refs = hidden_refs(&inventory());
        let unsigned = Map::new();
        let flag = hidden_flag(&refs[..1], Some(&unsigned), "C:\\ProgramData\\Fabrikam\\helper.exe").expect("flag");
        assert_eq!((flag.code.as_str(), flag.weight), ("hidden_entry", 60));
        let vendor = json!({"sig_status": "Valid", "signer": "Contoso Kaspersky Lab JSC"});
        let flag = hidden_flag(&refs[..1], vendor.as_object(), "C:\\ProgramData\\Fabrikam\\helper.exe").expect("flag");
        assert_eq!(flag.weight, 5);
        let windows = json!({"sig_status": "Valid", "os_binary": true});
        let flag = hidden_flag(&refs[1..2], windows.as_object(), "C:\\Windows\\System32\\zthelper.dll").expect("flag");
        assert_eq!(flag.weight, 5);
        assert!(hidden_flag(&[], None, "x").is_none());
    }

    #[test]
    fn weak_services_and_hidden_tasks_become_findings() {
        let found = items(&inventory());
        let topics: Vec<&str> = found
            .iter()
            .map(|i| i.facts.at("topic").as_str().unwrap_or(""))
            .collect();
        assert_eq!(
            topics,
            vec![
                "service_weak_permissions",
                "task_hidden_from_scheduler",
                "unquoted_service_path"
            ]
        );
        assert_eq!(
            found[0].score, 80,
            "an existing program on the unquoted path is the worst issue"
        );
        assert!(found[0].subtitle.contains("LocalSystem"));
        assert_eq!(found[1].score, 60);
        assert!(found[1].title.contains("\\Ghost"));
        assert_eq!(found[2].score, 0);
    }

    #[test]
    fn real_permissions_replace_the_folder_guess() {
        let acl = acl_writable(&inventory());
        assert_eq!(acl.get("c:\\tools\\safe\\svc.exe"), Some(&false));
        assert_eq!(acl.get("c:\\contoso tools\\agent.exe"), Some(&true));
        assert!(acl_writable(&json!({})).is_empty());
    }

    /// Prints counts only (run by hand): `cargo test -p vigil-scan svcsec_live -- --ignored --nocapture`.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn svcsec_live_counts() {
        let started = std::time::Instant::now();
        let collected = collect(crate::collect::is_admin());
        let raw = json!({"sysconfig": {SECTION: collected.clone()}});
        println!(
            "hidden services {} hidden tasks {} weak {} unquoted safe {} binaries {} notes {} refs {} items {} | {:?}",
            list(collected.at("hidden_services")).len(),
            list(collected.at("hidden_tasks").at("tasks")).len(),
            list(collected.at("permissions").at("weak")).len(),
            list(collected.at("permissions").at("unquoted_safe")).len(),
            list(collected.at("permissions").at("binaries")).len(),
            list(collected.at("notes")).len(),
            hidden_refs(&raw).len(),
            items(&raw).len(),
            started.elapsed()
        );
    }
}
