//! From the raw inventory to evaluated entities.
//!
//! An "entity" is the file (or the command) that actually decides what runs. Every way it
//! shows up on the system (processes, services, tasks, startup entries) is gathered into
//! it, so it is judged once and with the full context.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::cmdline::{
    ParsedCommand, SCRIPT_EXTS, expand_env, is_file, is_host, is_system_only_host, normalize_path, parse_command,
    resolve_program, split_command,
};
use crate::ip;
use crate::lenient::{Get, int_of, is_false, is_true, list, lower, or_empty, rx, str_of, strip, take, text, truthy};
use crate::model::{Flag, Item, Role};
use crate::ntpath::{SYSTEM32, basename, ext, isabs, join};
use crate::privacy::{clip, scrub_secrets};
use crate::rules::{
    file_exists, in_microsoft_home, is_microsoft_signed, is_user_writable, label_flags, location_flags, name_flags,
    scan_command,
};
use vigil_i18n::tr;

pub(crate) type Files = Map<String, Value>;

fn start_label(start: &str) -> String {
    match start {
        "Auto" => "automatic".into(),
        "Manual" => "manual".into(),
        "Disabled" => "disabled".into(),
        "Boot" => "boot".into(),
        "System" => "system".into(),
        "Unknown" => "unknown".into(),
        other => lower(other),
    }
}

fn state_label(state: &str) -> String {
    match state {
        "Running" => "running".into(),
        "Stopped" => "stopped".into(),
        other => lower(other),
    }
}

fn trigger_label(trigger: &Value) -> String {
    let name = match trigger {
        Value::Null => return tr!("other"),
        Value::String(s) => s.as_str(),
        other => return if truthy(other) { str_of(other) } else { tr!("other") },
    };
    match name {
        "Logon" => tr!("at logon"),
        "Boot" => tr!("at startup"),
        "Daily" => tr!("daily"),
        "Weekly" => tr!("weekly"),
        "Time" => tr!("scheduled"),
        "Event" => tr!("on an event"),
        "Idle" => tr!("when idle"),
        "Registration" => tr!("on registration"),
        "SessionStateChange" => tr!("on session change"),
        "" => tr!("other"),
        other => other.to_string(),
    }
}

/// Pure hosts: what they do is defined by another entry (the service DLL, the COM object).
const PURE_HOSTS: &[&str] = &["svchost.exe", "dllhost.exe"];
const SCRIPT_HOSTS: &[&str] = &["wscript.exe", "cscript.exe", "mshta.exe"];

fn lsa_defaults(name: &str) -> &'static [&'static str] {
    match name {
        "Authentication Packages" => &["msv1_0"],
        "Notification Packages" => &["scecli", "rassfm"],
        "Security Packages" => &[
            "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "livessp",
        ],
        _ => &[],
    }
}

/// One concrete occurrence of a command on the system.
#[derive(Clone, Debug)]
pub(crate) struct Ref {
    pub(crate) role: Role,
    pub(crate) parsed: ParsedCommand,
    pub(crate) flags: Vec<Flag>,
    pub(crate) pid: Option<i64>,
    pub(crate) parent: Option<String>,
}

impl Ref {
    fn new(role: Role, parsed: ParsedCommand) -> Self {
        Self {
            role,
            parsed,
            flags: Vec::new(),
            pid: None,
            parent: None,
        }
    }

    fn with_flags(mut self, flags: Vec<Flag>) -> Self {
        self.flags = flags;
        self
    }
}

/// Auxiliary data gathered while building the references.
#[derive(Clone, Debug, Default)]
pub(crate) struct Aux {
    /// Processes whose file could not be determined: (pid, name).
    pub(crate) pathless: Vec<(i64, String)>,
    pub(crate) unresolved_com: i64,
    /// Configuration findings from the startup entries (modified BootExecute...).
    pub(crate) config: Vec<Map<String, Value>>,
}

struct Entity {
    kind: &'static str,
    key: String,
    path: Option<String>,
    refs: Vec<Ref>,
}

fn is_system_account(account: &str) -> bool {
    matches!(
        lower(strip(account)).as_str(),
        "localsystem" | "nt authority\\system" | "system" | "s-1-5-18"
    )
}

/// Discards Windows sentinel dates (1999-11-30 = "never").
fn valid_date(value: &Value) -> Value {
    match value {
        Value::String(s) if !s.is_empty() && take(s, 4) >= "2000" => value.clone(),
        Value::String(_) | Value::Null => Value::Null,
        other if !truthy(other) => Value::Null,
        other => other.clone(),
    }
}

fn map(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

// --------------------------------------------------------------------------- references

/// PIDs of the scan itself and of its child processes, so that it does not analyze itself.
fn own_tree(processes: &[Value], self_pid: i64) -> HashSet<i64> {
    let mut own = HashSet::new();
    if self_pid == 0 {
        return own;
    }
    let mut children: HashMap<i64, Vec<i64>> = HashMap::new();
    for proc in processes {
        children
            .entry(int_of(proc.at("ppid")))
            .or_default()
            .push(int_of(proc.at("pid")));
    }
    let mut stack = vec![self_pid];
    while let Some(pid) = stack.pop() {
        if !own.insert(pid) {
            continue;
        }
        if let Some(kids) = children.get(&pid) {
            stack.extend(kids);
        }
    }
    own
}

fn process_refs(raw: &Value) -> (Vec<Ref>, Vec<(i64, String)>) {
    let processes = list(raw.at("processes"));
    let mut by_pid: HashMap<i64, &Value> = HashMap::new();
    for p in processes {
        by_pid.insert(int_of(p.at("pid")), p);
    }
    let self_pid = int_of(raw.at("meta").at("self_pid"));
    let own = own_tree(processes, self_pid);
    // The consoles the scan was launched from (cmd, PowerShell...) belong to the user.
    let mut launchers: HashSet<i64> = HashSet::new();
    let ppid_of = |pid: i64| by_pid.get(&pid).map_or(0, |p| int_of(p.at("ppid")));
    let mut pid = ppid_of(self_pid);
    while pid != 0 && !launchers.contains(&pid) && launchers.len() < 12 {
        launchers.insert(pid);
        pid = ppid_of(pid);
    }

    let mut refs = Vec::new();
    let mut pathless = Vec::new();
    for proc in processes {
        let pid = int_of(proc.at("pid"));
        if own.contains(&pid) || pid == 0 || pid == 4 {
            continue;
        }
        let name = text(proc.at("name"));
        if !truthy(proc.at("path")) {
            pathless.push((pid, name));
            continue;
        }
        if launchers.contains(&pid) && is_host(&lower(&name)) {
            continue;
        }
        let path = normalize_path(&str_of(proc.at("path")));
        let cmd = text(proc.at("cmd"));
        let args = if cmd.is_empty() {
            String::new()
        } else {
            split_command(&cmd, None).1
        };
        // The path reported by the system is the reliable one; only the arguments are taken
        // from the command line.
        let mut parsed = parse_command(strip(&format!("\"{path}\" {args}")), None);
        parsed.raw = if cmd.is_empty() { path.clone() } else { cmd.clone() };
        let parent = by_pid
            .get(&int_of(proc.at("ppid")))
            .map(|p| p.at("name"))
            .filter(|n| truthy(n))
            .map(str_of);
        let detail = map(vec![
            ("pid", json!(pid)),
            ("name", or_empty(proc.at("name"))),
            ("started", proc.at("started").clone()),
            ("session", proc.at("session").clone()),
        ]);
        let mut role = Role::new("process", format!("process \"{name}\""), detail);
        role.command = cmd;
        let mut reference = Ref::new(role, parsed);
        reference.pid = Some(pid);
        reference.parent = parent;
        refs.push(reference);
    }
    (refs, pathless)
}

fn service_refs(raw: &Value) -> Vec<Ref> {
    let mut refs = Vec::new();
    for svc in list(raw.at("services")) {
        let name = text(svc.at("name"));
        let command = strip(&text(svc.at("path"))).to_string();
        if command.is_empty() {
            continue;
        }
        let (start, state, account) = (text(svc.at("start")), text(svc.at("state")), text(svc.at("account")));
        let label = format!(
            "service \"{name}\" ({} start, {}{})",
            start_label(&start),
            state_label(&state),
            if account.is_empty() {
                String::new()
            } else {
                format!(", account {account}")
            }
        );
        let detail = map(vec![
            ("name", or_empty(svc.at("name"))),
            ("display", svc.at("display").clone()),
            ("start", json!(start)),
            ("state", json!(state)),
            ("account", json!(account)),
            ("description", svc.at("desc").clone()),
        ]);
        let mut role = Role::new("service", label, detail);
        role.command = command.clone();
        role.persistent = matches!(start.as_str(), "Auto" | "Boot" | "System");
        role.privileged = is_system_account(&account);
        role.active = start != "Disabled";
        let mut parsed = parse_command(&command, None);
        let dll = normalize_path(&text(svc.at("dll")));
        if !dll.is_empty() {
            // Service hosted in svchost: what matters is its DLL.
            if parsed.host.is_none() {
                parsed.host = Some("svchost.exe".into());
            }
            parsed.payload = Some(if isabs(&dll) {
                dll
            } else {
                resolve_program(&dll, None).0
            });
        }
        refs.push(Ref::new(role, parsed));
    }
    refs
}

fn driver_refs(raw: &Value) -> Vec<Ref> {
    let mut refs = Vec::new();
    for drv in list(raw.at("drivers")) {
        let path = normalize_path(&text(drv.at("path")));
        if path.is_empty() {
            continue;
        }
        let (name, start, state) = (text(drv.at("name")), text(drv.at("start")), text(drv.at("state")));
        let label = format!(
            "driver \"{name}\" ({} start, {})",
            start_label(&start),
            state_label(&state)
        );
        let detail = map(vec![
            ("name", or_empty(drv.at("name"))),
            ("display", drv.at("display").clone()),
            ("start", json!(start)),
            ("state", json!(state)),
        ]);
        let mut role = Role::new("driver", label, detail);
        role.command = path.clone();
        role.persistent = matches!(start.as_str(), "Auto" | "Boot" | "System");
        role.privileged = true;
        role.active = start != "Disabled";
        let parsed = ParsedCommand {
            program: Some(path.clone()),
            certain: true,
            ..ParsedCommand::new(&path)
        };
        refs.push(Ref::new(role, parsed));
    }
    refs
}

rx!(TASK_EXEC_EXT, r"(?i)\.(exe|com|bat|cmd|vbs|js|ps1|msi|scr)$");

fn task_refs(raw: &Value) -> (Vec<Ref>, i64) {
    let mut refs = Vec::new();
    let mut unresolved_com = 0;
    for task in list(raw.at("tasks")) {
        let task_path = text(task.at("path"));
        let full = format!(
            "{}{}",
            if task_path.is_empty() { "\\" } else { &task_path },
            text(task.at("name"))
        );
        let state = text(task.at("state"));
        let triggers: BTreeSet<String> = list(task.at("triggers")).iter().map(trigger_label).collect();
        let user = {
            let u = text(task.at("user"));
            if u.is_empty() { text(task.at("group")) } else { u }
        };
        let highest = text(task.at("runlevel")) == "Highest";
        let is_ms_path = lower(&full).starts_with("\\microsoft\\");
        let triggers_text = triggers.into_iter().collect::<Vec<_>>().join(", ");
        let triggers_text = if triggers_text.is_empty() {
            tr!("no trigger")
        } else {
            triggers_text
        };
        let user_text = if user.is_empty() { tr!("unknown") } else { user.clone() };
        let highest_text = if highest {
            tr!("; highest privileges")
        } else {
            String::new()
        };
        let disabled_text = if state == "Disabled" {
            tr!("; disabled")
        } else {
            String::new()
        };
        let label = tr!(
            "scheduled task \"{0}\" ({1}; as {2}{3}{4})",
            full,
            triggers_text,
            user_text,
            highest_text,
            disabled_text
        );
        let detail = map(vec![
            ("task_path", task.at("path").clone()),
            ("task_name", task.at("name").clone()),
            ("author", task.at("author").clone()),
            ("date", task.at("date").clone()),
            ("last_run", valid_date(task.at("last_run"))),
            ("hidden", json!(truthy(task.at("hidden")))),
            ("description", task.at("desc").clone()),
        ]);
        for action in list(task.at("actions")) {
            let (command, parsed) = match action.at("type").as_str() {
                Some("exec") => {
                    let mut exe = strip(&text(action.at("exe"))).to_string();
                    let args = strip(&text(action.at("args"))).to_string();
                    if exe.is_empty() {
                        continue;
                    }
                    // "Program" and "arguments" are separate fields: when the whole field is a path
                    // (it exists, or it ends in an executable extension) there is no ambiguity.
                    if exe.contains(' ')
                        && !exe.starts_with('"')
                        && (is_file(&expand_env(&exe)) || TASK_EXEC_EXT.is_match(&exe))
                    {
                        exe = format!("\"{exe}\"");
                    }
                    let command = if args.is_empty() { exe } else { format!("{exe} {args}") };
                    let cwd = text(action.at("cwd"));
                    let parsed = parse_command(&command, if cwd.is_empty() { None } else { Some(&cwd) });
                    (command, parsed)
                }
                Some("com") => {
                    let server = strip(&text(action.at("server"))).to_string();
                    if server.is_empty() {
                        if is_ms_path {
                            unresolved_com += 1;
                            continue;
                        }
                        let command = tr!("COM object {0} (not registered)", str_of(action.at("clsid")));
                        let parsed = ParsedCommand::new(&command);
                        (command, parsed)
                    } else {
                        let parsed = parse_command(&server, None);
                        (server, parsed)
                    }
                }
                _ => continue,
            };
            let mut role = Role::new("task", label.clone(), detail.clone());
            role.command = command;
            role.persistent = state != "Disabled";
            role.privileged = highest || is_system_account(&user);
            role.active = state != "Disabled";
            let mut flags = Vec::new();
            if truthy(task.at("hidden")) && !is_ms_path {
                flags.push(Flag::new("hidden_task", 10, tr!("scheduled task marked as hidden")));
            }
            refs.push(Ref::new(role, parsed).with_flags(flags));
        }
    }
    (refs, unresolved_com)
}

rx!(LIST_PART, r#""[^"]+"|[^\s,]+"#);
rx!(ACTIVE_SETUP_COMMAND, r"[\\.]");

/// Splits lists of paths (commas or spaces) while respecting quotes.
fn split_list(value: &str) -> Vec<String> {
    LIST_PART
        .find_all(value)
        .into_iter()
        .map(|p| p.trim_matches('"').to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Startup-entry references and configuration findings (modified BootExecute...).
/// The command of Vigil's own sign-in entry (Settings > Start with Windows): this very program,
/// started hidden in the tray. The same text as `vigil_sys::startup::own_command`.
pub fn own_autostart_command(exe: &std::path::Path) -> String {
    format!("\"{}\" --tray --no-elevate", exe.display())
}

/// Vigil's own entry: the user's Run value `Vigil` holding exactly that command. It is left out of
/// the inventory like Vigil's own processes; the same name with any other command is analyzed.
fn own_autostart(location: &str, name: &str, command: &str) -> bool {
    location.to_ascii_uppercase().starts_with("HKCU\\")
        && name.eq_ignore_ascii_case("Vigil")
        && std::env::current_exe().is_ok_and(|exe| command.trim().eq_ignore_ascii_case(&own_autostart_command(&exe)))
}

fn autorun_refs(raw: &Value) -> (Vec<Ref>, Vec<Map<String, Value>>) {
    let mut refs = Vec::new();
    let mut config = Vec::new();
    let mut shortcuts: HashMap<String, &Value> = HashMap::new();
    for s in list(raw.at("system").at("shortcuts")) {
        let key = s.get("lnk").map(str_of).unwrap_or_default();
        shortcuts.insert(lower(&key), s);
    }
    let userinit_default = lower(&join(&SYSTEM32, &["userinit.exe"]));

    for entry in list(raw.at("autoruns")) {
        let source_value = entry.at("source").clone();
        let source = source_value.as_str().unwrap_or("");
        let name = text(entry.at("name"));
        let command = strip(&text(entry.at("command"))).to_string();
        let location = text(entry.at("location"));
        let enabled = entry.get("enabled").is_none_or(truthy);
        let off = if enabled { String::new() } else { tr!(" (disabled)") };
        let privileged = location.starts_with("HKLM")
            && matches!(
                source,
                "winlogon" | "appinit_dlls" | "boot_execute" | "lsa_package" | "appcert_dlls"
            );

        let mut add = |cmd: &str,
                       label: String,
                       flags: Vec<Flag>,
                       detail: Option<Map<String, Value>>,
                       parsed: Option<ParsedCommand>| {
            let detail = detail.unwrap_or_else(|| {
                map(vec![
                    ("source", source_value.clone()),
                    ("reg_key", json!(location)),
                    ("value", or_empty(entry.at("name"))),
                ])
            });
            let mut role = Role::new("startup", label, detail);
            role.command = cmd.to_string();
            role.persistent = true;
            role.active = enabled;
            role.privileged = privileged;
            let parsed = parsed.unwrap_or_else(|| parse_command(cmd, None));
            refs.push(Ref::new(role, parsed).with_flags(flags));
        };

        match source {
            "run" if own_autostart(&location, &name, &command) => {}
            "run" => add(
                &command,
                tr!("startup entry \"{0}\" in {1}{2}", name, location, off),
                vec![],
                None,
                None,
            ),
            "startup_folder" => {
                let file_path = text(entry.at("file"));
                let detail = map(vec![
                    ("source", source_value.clone()),
                    ("file", or_empty(entry.at("file"))),
                ]);
                match shortcuts
                    .get(&lower(&file_path))
                    .filter(|s| truthy(s) && truthy(s.at("target")))
                {
                    Some(shortcut) => {
                        let cmd = strip(&format!(
                            "\"{}\" {}",
                            str_of(shortcut.at("target")),
                            text(shortcut.at("args"))
                        ))
                        .to_string();
                        add(
                            &cmd,
                            tr!("shortcut \"{0}\" in the Startup folder{1}", name, off),
                            vec![],
                            Some(detail),
                            None,
                        );
                    }
                    None => add(
                        &format!("\"{file_path}\""),
                        tr!("file \"{0}\" in the Startup folder{1}", name, off),
                        vec![],
                        Some(detail),
                        None,
                    ),
                }
            }
            "active_setup" => {
                // Some Windows components store a marker here ("U", "/UserInstall"), not a command.
                if ACTIVE_SETUP_COMMAND.is_match(&command) && !command.starts_with('/') {
                    add(&command, tr!("Active Setup \"{0}\"", name), vec![], None, None);
                }
            }
            "winlogon" => {
                if name == "Shell" {
                    if lower(&command) == "explorer.exe" && location.starts_with("HKLM") {
                        continue;
                    }
                    let flag = Flag::new(
                        "winlogon_modified",
                        70,
                        tr!("the Winlogon Shell is modified: it runs at every logon"),
                    );
                    for part in command.split(',') {
                        let part = strip(part);
                        if !part.is_empty() {
                            add(
                                part,
                                tr!("Winlogon Shell ({0})", location),
                                vec![flag.clone()],
                                None,
                                None,
                            );
                        }
                    }
                } else if name == "Userinit" {
                    for part in command.split(',') {
                        let part = strip(part);
                        if part.is_empty() || lower(&resolve_program(part, None).0) == userinit_default {
                            continue;
                        }
                        add(
                            part,
                            tr!("Winlogon Userinit ({0})", location),
                            vec![Flag::new(
                                "winlogon_modified",
                                70,
                                tr!("Winlogon Userinit launches an additional program at every logon"),
                            )],
                            None,
                            None,
                        );
                    }
                } else if name == "VmApplet" && lower(&command).starts_with("systempropertiesperformance.exe") {
                    continue;
                } else {
                    add(
                        &command,
                        format!("Winlogon {name} ({location})"),
                        vec![Flag::new(
                            "winlogon_modified",
                            60,
                            tr!("Winlogon value \"{0}\" is set (normally empty)", name),
                        )],
                        None,
                        None,
                    );
                }
            }
            "appinit_dlls" => {
                let weight = if enabled { 60 } else { 30 };
                for dll in split_list(&command) {
                    let path = normalize_path(&dll);
                    let parsed = ParsedCommand {
                        program: Some(path),
                        certain: true,
                        ..ParsedCommand::new(&dll)
                    };
                    add(
                        &dll,
                        tr!(
                            "AppInit_DLLs ({0}){1}",
                            location,
                            if enabled {
                                String::new()
                            } else {
                                tr!(" (loading disabled)")
                            }
                        ),
                        vec![Flag::new(
                            "appinit_dll",
                            weight,
                            tr!("DLL injected into every program with a graphical interface"),
                        )],
                        None,
                        Some(parsed),
                    );
                }
            }
            "appcert_dlls" => {
                let path = normalize_path(&command);
                let parsed = ParsedCommand {
                    program: Some(path),
                    certain: true,
                    ..ParsedCommand::new(&command)
                };
                add(
                    &command,
                    format!("AppCertDlls \"{name}\""),
                    vec![Flag::new(
                        "appcert_dll",
                        60,
                        tr!("DLL injected into every process that creates other processes"),
                    )],
                    None,
                    Some(parsed),
                );
            }
            "ifeo_debugger" => add(
                &command,
                tr!("debugger attached to \"{0}\" ({1})", name, location),
                vec![Flag::new(
                    "debugger_hook",
                    50,
                    tr!("runs instead of \"{0}\" every time that program is opened", name),
                )],
                None,
                None,
            ),
            "boot_execute" => {
                if !lower(&command).starts_with("autocheck autochk") {
                    config.push(map(vec![
                        ("topic", json!("boot_execute")),
                        ("title", json!(tr!("BootExecute modified"))),
                        ("score", json!(50)),
                        ("detail", json!({"value": command, "key": location})),
                        ("text", json!(tr!("a native program runs before Windows starts"))),
                    ]));
                }
            }
            "lsa_package" => {
                if lsa_defaults(&name).contains(&lower(&command).as_str()) {
                    continue;
                }
                let dll = if ext(&command).is_empty() {
                    format!("{command}.dll")
                } else {
                    command.clone()
                };
                let path = if isabs(&dll) { dll } else { join(&SYSTEM32, &[&dll]) };
                let parsed = ParsedCommand {
                    program: Some(path),
                    certain: true,
                    ..ParsedCommand::new(&command)
                };
                add(
                    &command,
                    tr!("LSA security package \"{0}\" ({1})", command, name),
                    vec![Flag::new(
                        "custom_lsa_package",
                        50,
                        tr!("loaded inside the process that holds Windows credentials"),
                    )],
                    None,
                    Some(parsed),
                );
            }
            "logon_script" | "legacy_load" => add(
                &command,
                tr!("logon script ({0} → {1})", location, name),
                vec![Flag::new(
                    "legacy_autostart",
                    40,
                    tr!("old and unusual startup mechanism, used for persistence"),
                )],
                None,
                None,
            ),
            _ => {}
        }
    }

    for consumer in list(raw.at("system").at("wmi").at("consumers")) {
        let class = text(consumer.at("class"));
        let cname = text(consumer.at("name"));
        if class == "CommandLineEventConsumer" {
            let cmd = {
                let c = text(consumer.at("command"));
                strip(&if c.is_empty() { text(consumer.at("exe")) } else { c }).to_string()
            };
            if cmd.is_empty() {
                continue;
            }
            let mut role = Role::new(
                "wmi",
                tr!("permanent WMI subscription \"{0}\"", cname),
                map(vec![("name", json!(cname)), ("class", json!(class))]),
            );
            role.command = cmd.clone();
            role.persistent = true;
            role.privileged = true;
            refs.push(Ref::new(role, parse_command(&cmd, None)).with_flags(vec![Flag::new(
                "wmi_persistence",
                50,
                tr!("runs through a permanent WMI subscription (low-visibility persistence)"),
            )]));
        } else if class == "ActiveScriptEventConsumer" {
            let script = {
                let s = text(consumer.at("script"));
                if s.is_empty() {
                    text(consumer.at("script_file"))
                } else {
                    s
                }
            };
            config.push(map(vec![
                ("topic", json!("wmi_script")),
                ("title", json!(tr!("Permanent WMI script \"{0}\"", cname))),
                ("score", json!(55)),
                (
                    "detail",
                    json!({"engine": consumer.at("engine"), "script": clip(&scrub_secrets(&script), 1500)}),
                ),
                (
                    "text",
                    json!(tr!("script that WMI runs on its own (low-visibility persistence)")),
                ),
                ("scan", json!(script)),
            ]));
        }
    }
    (refs, config)
}

/// Every occurrence of a command on the system, plus auxiliary data.
pub(crate) fn build_references(raw: &Value) -> (Vec<Ref>, Aux) {
    let (mut refs, pathless) = process_refs(raw);
    let (tasks, unresolved_com) = task_refs(raw);
    let (autoruns, config) = autorun_refs(raw);
    refs.extend(service_refs(raw));
    refs.extend(driver_refs(raw));
    refs.extend(tasks);
    refs.extend(autoruns);
    (
        refs,
        Aux {
            pathless,
            unresolved_com,
            config,
        },
    )
}

/// Files whose signature must be checked.
pub(crate) fn needed_paths(refs: &[Ref]) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for r in refs {
        for candidate in [&r.parsed.program, &r.parsed.payload].into_iter().flatten() {
            if !candidate.is_empty() && (isabs(candidate) || candidate.starts_with("\\\\")) {
                paths.insert(candidate.clone());
            }
        }
    }
    paths.into_iter().collect()
}

// --------------------------------------------------------------------------- network

#[derive(Default)]
pub(crate) struct NetEntry {
    listen: BTreeSet<String>,
    exposed: BTreeSet<String>,
    remote: BTreeSet<String>,
}

pub(crate) fn network_by_pid(raw: &Value) -> HashMap<i64, NetEntry> {
    let net = raw.at("network");
    let mut out: HashMap<i64, NetEntry> = HashMap::new();
    for conn in list(net.at("tcp")) {
        let pid = int_of(conn.at("pid"));
        if conn.at("state").as_str() == Some("Listen") {
            let endpoint = format!("tcp {}:{}", str_of(conn.at("laddr")), str_of(conn.at("lport")));
            let entry = out.entry(pid).or_default();
            entry.listen.insert(endpoint.clone());
            if !ip::is_loopback_text(&text(conn.at("laddr"))) {
                entry.exposed.insert(endpoint);
            }
        } else if ip::is_public(&text(conn.at("raddr"))) {
            let remote = format!("{}:{}", str_of(conn.at("raddr")), str_of(conn.at("rport")));
            out.entry(pid).or_default().remote.insert(remote);
        }
    }
    for endpoint in list(net.at("udp")) {
        // Ephemeral UDP ports (>= 49152) are noise: only the fixed ones matter.
        if int_of(endpoint.at("lport")) < 49152 && !ip::is_loopback_text(&text(endpoint.at("laddr"))) {
            let text = format!("udp {}:{}", str_of(endpoint.at("laddr")), str_of(endpoint.at("lport")));
            let entry = out.entry(int_of(endpoint.at("pid"))).or_default();
            entry.listen.insert(text.clone());
            entry.exposed.insert(text);
        }
    }
    out
}

// --------------------------------------------------------------------------- entities

rx!(WHITESPACE_RUN, r"\s+");

fn command_key(raw_command: &str) -> String {
    lower(strip(&WHITESPACE_RUN.replace_all(raw_command, " ")))
}

pub(crate) fn file_info<'a>(files: &'a Files, path: &str) -> Option<&'a Map<String, Value>> {
    files.get(&lower(path)).and_then(Value::as_object)
}

/// The program is a Microsoft binary in one of its usual folders.
fn is_windows_binary(program: Option<&str>, files: &Files) -> bool {
    match program {
        Some(p) if !p.is_empty() && isabs(p) => is_microsoft_signed(file_info(files, p)) && in_microsoft_home(p),
        _ => true, // bare unresolved name: treated as the system interpreter
    }
}

fn entity_key(r: &Ref, files: &Files) -> (&'static str, String, Option<String>) {
    let parsed = &r.parsed;
    if parsed.host.is_some() {
        if let Some(payload) = parsed.payload.as_deref()
            && !payload.is_empty()
            && isabs(payload)
            && !parsed.compound
        {
            return ("file", lower(payload), Some(payload.to_string()));
        }
        // No payload file: with a Windows interpreter what counts is the command. With a
        // third-party interpreter (Git bash, python, node...) what must be judged is the
        // binary itself, unless it starts automatically with inline code.
        let persistent_code = r.role.persistent
            && (parsed.inline.as_deref().is_some_and(|i| !i.is_empty()) || !strip(&parsed.args).is_empty());
        if is_windows_binary(parsed.program.as_deref(), files) || persistent_code {
            return ("cmd", command_key(&parsed.raw), None);
        }
    }
    if let Some(program) = parsed.program.as_deref().filter(|p| !p.is_empty()) {
        return ("file", lower(program), Some(program.to_string()));
    }
    ("cmd", command_key(&parsed.raw), None)
}

fn signature_text_of(info: Option<&Map<String, Value>>) -> String {
    let Some(info) = info.filter(|i| !i.is_empty()) else {
        return tr!("not checked");
    };
    if is_false(info.at("exists")) {
        return tr!("the file does not exist");
    }
    let signer = text(info.at("signer"));
    match info.at("sig_status") {
        Value::String(s) if s == "Valid" => {
            if signer.is_empty() {
                "valid".into()
            } else {
                format!("valid · {signer}")
            }
        }
        Value::String(s) if s == "NotSigned" => "unsigned".into(),
        Value::String(s) if s == "HashMismatch" => tr!("BROKEN (file modified after signing) · {0}", signer),
        Value::String(s) if s == "NotTrusted" => tr!("untrusted (unknown issuer) · {0}", signer),
        Value::Null => tr!("unverifiable (no access)"),
        other => format!("unverifiable ({})", str_of(other)),
    }
}

/// Checks that the Windows interpreter launching the command is the original binary.
fn host_flag(parsed: &ParsedCommand, files: &Files) -> Option<Flag> {
    let host = parsed.host.as_deref()?;
    let program = parsed.program.as_deref().filter(|p| !p.is_empty())?;
    if !is_system_only_host(host) || !isabs(program) {
        return None;
    }
    let info = file_info(files, program)?;
    if !is_true(info.at("exists")) {
        return None;
    }
    if !is_microsoft_signed(Some(info)) {
        return Some(Flag::new(
            "fake_host",
            70,
            tr!(
                "\"{0}\" is not the original Windows binary (possible impersonation)",
                host
            ),
        ));
    }
    if !in_microsoft_home(program) {
        return Some(Flag::new(
            "misplaced_host",
            35,
            tr!(
                "copy of \"{0}\" outside the Windows folders (possible DLL side-loading)",
                host
            ),
        ));
    }
    None
}

// MSIX/Store packages: the files carry no individual signature, the whole package is signed
// and Windows protects the folder. 8wekyb3d8bbwe and cw5n1h2txyewy are Microsoft's publisher IDs.
rx!(
    MSIX_RE,
    r"(?i)^[a-z]:\\program files\\windowsapps\\(?P<name>[^\\_]+)_[^\\_]*_[^\\_]*_[^\\_]*_(?P<pub>[a-z0-9]{13})\\"
);
const MS_PACKAGE_PUBLISHERS: &[&str] = &["8wekyb3d8bbwe", "cw5n1h2txyewy"];

/// Signature status in plain language.
pub fn signature_text(item: &Item) -> String {
    let info = item.file.as_ref();
    let not_signed = info.is_some_and(|i| i.at("sig_status").as_str() == Some("NotSigned"));
    if truthy(item.facts.at("msix_package")) && not_signed {
        return tr!(
            "signed at MSIX package level ({0})",
            str_of(item.facts.at("msix_package"))
        );
    }
    if let Some(i) = info.filter(|i| !i.is_empty())
        && is_true(i.at("exists"))
        && let Some(path) = item.path.as_deref().filter(|p| !p.is_empty())
        && SCRIPT_EXTS.iter().any(|e| lower(path).ends_with(e))
        && i.at("sig_status").as_str() != Some("Valid")
    {
        return tr!("unsigned script (normal for scripts)");
    }
    signature_text_of(info)
}

/// Signals that depend on how it is invoked (valid for files and commands).
fn common_flags(item: &mut Item, refs: &[Ref], files: &Files) {
    for r in refs {
        let parsed = &r.parsed;
        for flag in &r.flags {
            item.add_flag(flag.clone());
        }
        for flag in scan_command(&[Some(&parsed.raw), parsed.inline.as_deref(), parsed.decoded.as_deref()]) {
            item.add_flag(flag);
        }
        if parsed.hidden {
            item.add_flag(Flag::new("hidden_window", 15, tr!("runs with a hidden window")));
        }
        if parsed.decoded.as_deref().is_some_and(|d| !d.is_empty()) {
            item.add_flag(Flag::new(
                "encoded_powershell",
                20,
                tr!("PowerShell command encoded in Base64"),
            ));
        }
        if parsed.payload_url.as_deref().is_some_and(|u| !u.is_empty()) {
            item.add_flag(Flag::new("remote_payload", 50, tr!("runs content directly from a URL")));
        }
        if let Some(flag) = host_flag(parsed, files) {
            item.add_flag(flag);
        }
        if parsed.host.as_deref().is_some_and(|h| SCRIPT_HOSTS.contains(&h)) && r.role.persistent && r.role.active {
            item.add_flag(Flag::new(
                "startup_script",
                15,
                tr!("script launched automatically by a Windows script host"),
            ));
        }
    }
}

fn collect_roles(item: &mut Item, refs: &[Ref], network: &HashMap<i64, NetEntry>) {
    let process_refs: Vec<&Ref> = refs.iter().filter(|r| r.role.kind == "process").collect();
    if !process_refs.is_empty() {
        let parents: Vec<String> = process_refs
            .iter()
            .filter_map(|r| r.parent.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(4)
            .collect();
        let names: Vec<String> = process_refs
            .iter()
            .map(|r| text(r.role.detail.at("name")))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let count = process_refs.len();
        let mut label = if count == 1 {
            tr!("{0} running process", count)
        } else {
            tr!("{0} running processes", count)
        };
        if !parents.is_empty() {
            label.push_str(&tr!(" (launched by {0})", parents.join(", ")));
        }
        let pids: Vec<Value> = process_refs.iter().map(|r| json!(r.pid)).take(10).collect();
        item.roles.push(Role::new(
            "process",
            label,
            map(vec![
                ("pids", Value::Array(pids)),
                ("count", json!(count)),
                ("names", json!(names)),
                ("parents", json!(parents)),
            ]),
        ));
        let (mut listen, mut exposed, mut remote) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        for r in &process_refs {
            let pid = r.pid.filter(|&p| p != 0).unwrap_or(-1);
            if let Some(entry) = network.get(&pid) {
                listen.extend(entry.listen.iter().cloned());
                exposed.extend(entry.exposed.iter().cloned());
                remote.extend(entry.remote.iter().cloned());
            }
        }
        if !listen.is_empty() || !remote.is_empty() {
            let first = |set: &BTreeSet<String>, n: usize| set.iter().take(n).cloned().collect::<Vec<_>>();
            item.network = map(vec![
                ("listen", json!(first(&listen, 12))),
                ("exposed", json!(first(&exposed, 12))),
                ("remote", json!(first(&remote, 10))),
                ("remote_total", json!(remote.len())),
            ]);
        }
    }
    let mut seen: HashSet<&str> = HashSet::new();
    for r in refs {
        if r.role.kind == "process" || seen.contains(r.role.label.as_str()) {
            continue;
        }
        seen.insert(&r.role.label);
        item.roles.push(r.role.clone());
    }

    let mut commands: Vec<String> = Vec::new();
    let mut ordered: Vec<&Ref> = refs.iter().collect();
    ordered.sort_by_key(|r| (r.flags.is_empty(), r.role.kind == "process"));
    let path_lower = lower(item.path.as_deref().unwrap_or(""));
    for r in ordered {
        let text = strip(&scrub_secrets(&r.parsed.raw)).to_string();
        if !text.is_empty() && !commands.contains(&text) && lower(&text) != path_lower {
            commands.push(text);
        }
        if let Some(decoded) = r.parsed.decoded.as_deref() {
            let decoded = strip(&scrub_secrets(decoded)).to_string();
            if !decoded.is_empty() && !item.decoded.contains(&decoded) {
                item.decoded.push(decoded);
            }
        }
    }
    if commands.len() > 4 {
        item.facts
            .insert("other_command_lines".into(), json!(commands.len() - 4));
    }
    commands.truncate(4);
    item.commands = commands;
    item.decoded.truncate(2);
}

struct Ctx {
    network: HashMap<i64, NetEntry>,
    detected_paths: HashSet<String>,
    exclusions: Vec<String>,
}

fn evaluate_file(entity: &Entity, files: &Files, ctx: &Ctx) -> Item {
    let path = entity.path.clone().unwrap_or_else(|| entity.key.clone());
    let info = file_info(files, &path);
    let base = basename(&path).to_string();
    let extension = lower(ext(&base));
    let is_script = SCRIPT_EXTS.contains(&extension.as_str());
    let valid = info.is_some_and(|i| !i.is_empty() && i.at("sig_status").as_str() == Some("Valid"));
    let ms_signed = is_microsoft_signed(info);

    let description = info.map(|i| text(i.at("description"))).unwrap_or_default();
    let company = info.map(|i| text(i.at("company"))).unwrap_or_default();
    let subtitle = [description.as_str(), company.as_str()]
        .into_iter()
        .filter(|x| !x.is_empty())
        .collect::<Vec<_>>()
        .join(" · ");
    let mut item = Item::new(
        "executable",
        base.clone(),
        if subtitle.is_empty() { path.clone() } else { subtitle },
    );
    item.path = Some(path.clone());
    item.file = info.cloned();
    let msix = MSIX_RE.captures(&path);
    let has_info = info.is_some_and(|i| !i.is_empty());
    let package_signed =
        msix.is_some() && has_info && info.is_some_and(|i| i.at("sig_status").as_str() == Some("NotSigned"));
    let ms_package = msix
        .as_ref()
        .and_then(|m| m.name("pub"))
        .is_some_and(|p| MS_PACKAGE_PUBLISHERS.contains(&lower(p.as_str()).as_str()));
    if let Some(name) = msix.as_ref().and_then(|m| m.name("name")) {
        item.facts.insert("msix_package".into(), json!(name.as_str()));
    }
    collect_roles(&mut item, &entity.refs, &ctx.network);
    let hosts: BTreeSet<String> = entity
        .refs
        .iter()
        .filter_map(|r| r.parsed.host.clone())
        .filter(|h| !h.is_empty())
        .collect();
    if !hosts.is_empty() {
        item.facts
            .insert("launched_by".into(), json!(hosts.into_iter().collect::<Vec<_>>()));
    }

    let is_running = entity.refs.iter().any(|r| r.role.kind == "process");
    let has_persistent = entity.refs.iter().any(|r| r.role.persistent && r.role.active);

    // --- existence and signature
    match info {
        None => item.add_flag(Flag::new("not_found", 0, tr!("the file it runs could not be located"))),
        Some(i) if is_false(i.at("exists")) => {
            if is_running {
                item.add_flag(Flag::new(
                    "process_without_file",
                    25,
                    tr!("the process is still alive but its file no longer exists on disk"),
                ));
            } else if entity.refs.iter().all(|r| r.parsed.certain) {
                item.add_flag(Flag::new(
                    "orphan",
                    5,
                    tr!("points to a file that no longer exists (leftover of an uninstalled program)"),
                ));
            } else {
                item.add_flag(Flag::new("not_found", 0, tr!("the file it runs could not be located")));
            }
        }
        Some(i) if i.at("exists").is_null() => {
            item.add_flag(Flag::new(
                "unverifiable",
                0,
                tr!("no access to verify the file (requires administrator)"),
            ));
        }
        Some(i) => {
            let status = i.at("sig_status");
            match status.as_str() {
                Some("HashMismatch") => item.add_flag(Flag::new(
                    "broken_signature",
                    60,
                    tr!("the digital signature does not match: the file was modified after it was signed"),
                )),
                Some("NotTrusted") => item.add_flag(Flag::new(
                    "untrusted_signature",
                    35,
                    tr!("signed with a certificate that Windows does not trust"),
                )),
                Some("NotSigned") => {
                    if extension == ".sys" {
                        item.add_flag(Flag::new(
                            "unsigned_driver",
                            50,
                            tr!("kernel driver without a digital signature"),
                        ));
                    } else if !is_script && !package_signed {
                        // Only an administrator can write to Program Files: it weighs less than in a user folder.
                        item.add_flag(Flag::new(
                            "unsigned",
                            if is_user_writable(&path) { 20 } else { 10 },
                            tr!("no digital signature"),
                        ));
                    }
                }
                Some("Valid") => {}
                _ if !is_script => item.add_flag(Flag::new(
                    "unverifiable_signature",
                    10,
                    tr!("the signature could not be verified ({0})", str_of(status)),
                )),
                _ => {}
            }
            if !is_script
                && !valid
                && !package_signed
                && company.is_empty()
                && description.is_empty()
                && is_user_writable(&path)
            {
                item.add_flag(Flag::new(
                    "no_metadata",
                    10,
                    tr!("the file declares no publisher or description"),
                ));
            }
        }
    }

    // --- location and name
    for flag in location_flags(&path) {
        if valid {
            // Signed installers and updaters routinely use temporary folders.
            if flag.weight >= 30 {
                item.add_flag(Flag::new(flag.code, flag.weight.div_euclid(2), flag.text));
            }
        } else {
            item.add_flag(flag);
        }
    }
    for flag in name_flags(&path, ms_signed || ms_package, valid || package_signed) {
        item.add_flag(flag);
    }

    common_flags(&mut item, &entity.refs, files);

    let product = info.map(|i| text(i.at("product"))).unwrap_or_default();
    let mut names = vec![path.clone(), description.clone(), product];
    for r in &entity.refs {
        for key in ["name", "display", "task_name", "value"] {
            names.push(text(r.role.detail.at(key)));
        }
    }
    for flag in label_flags(&names.iter().map(String::as_str).collect::<Vec<_>>()) {
        item.add_flag(flag);
    }

    // --- privileges and persistence
    if !valid && file_exists(info) && is_user_writable(&path) {
        if entity
            .refs
            .iter()
            .any(|r| r.role.kind == "service" && r.role.privileged && r.role.active)
        {
            item.add_flag(Flag::new(
                "system_service_user_path",
                25,
                tr!("service with SYSTEM privileges whose file is in a user-writable folder"),
            ));
        }
        if entity
            .refs
            .iter()
            .any(|r| r.role.kind == "task" && r.role.privileged && r.role.active)
        {
            item.add_flag(Flag::new(
                "elevated_task_user_path",
                20,
                tr!("task with highest privileges whose file is in a user-writable folder"),
            ));
        }
        if has_persistent && !is_script {
            item.add_flag(Flag::new(
                "unsigned_autostart_user_path",
                10,
                tr!("starts automatically, is unsigned and lives in a user folder"),
            ));
        }
    }
    if !valid && truthy(item.network.at("exposed")) {
        item.add_flag(Flag::new(
            "network_listener",
            10,
            tr!("accepts network connections from other computers and is unsigned"),
        ));
    }

    let low = lower(&path);
    if ctx.detected_paths.contains(&low) {
        item.add_flag(Flag::new(
            "defender_detected",
            60,
            tr!("Microsoft Defender detected this same file before"),
        ));
    }
    for excluded in &ctx.exclusions {
        if &low == excluded || low.starts_with(&format!("{}\\", excluded.trim_end_matches('\\'))) {
            item.add_flag(Flag::new(
                "defender_excluded",
                30,
                tr!("is inside an antivirus exclusion (Defender does not scan it)"),
            ));
            break;
        }
    }

    item.rescore();
    let weighted = item.flags.iter().any(|f| f.weight > 0);
    let clean_invocation = !entity.refs.iter().any(|r| r.parsed.compound);
    let genuine_microsoft = (ms_signed && in_microsoft_home(&path)) || (ms_package && (valid || package_signed));
    item.trusted = genuine_microsoft && !weighted && clean_invocation;
    if item.trusted {
        item.what = tr!("Microsoft component with a valid signature");
    }
    item
}

fn evaluate_command(entity: &Entity, files: &Files, ctx: &Ctx) -> Item {
    let first = &entity.refs[0].parsed;
    let host = match &first.host {
        Some(h) if !h.is_empty() => h.clone(),
        _ => match first.program.as_deref().filter(|p| !p.is_empty()) {
            Some(program) => lower(basename(program)),
            None => "command".into(),
        },
    };
    let raw = strip(&scrub_secrets(&first.raw)).to_string();
    let title = clip(&raw, 110);
    let mut item = Item::new(
        "command",
        if title.is_empty() { host.clone() } else { title },
        tr!("command run by {0}", host),
    );
    item.facts.insert("host".into(), json!(host));
    if !first.chain.is_empty() {
        let mut chain = vec![host.clone()];
        chain.extend(first.chain.iter().cloned());
        item.facts.insert("chain".into(), json!(chain));
    }
    collect_roles(&mut item, &entity.refs, &ctx.network);
    if item.commands.is_empty() && !raw.is_empty() {
        item.commands = vec![raw];
    }
    common_flags(&mut item, &entity.refs, files);
    let mut names = vec![first.raw.clone()];
    for r in &entity.refs {
        for key in ["name", "task_name", "value"] {
            names.push(text(r.role.detail.at(key)));
        }
    }
    for flag in label_flags(&names.iter().map(String::as_str).collect::<Vec<_>>()) {
        item.add_flag(flag);
    }
    if let Some(program) = first.program.as_deref()
        && !program.is_empty()
        && !isabs(program)
        && first.host.is_none()
    {
        item.add_flag(Flag::new(
            "not_found",
            0,
            tr!("the program it runs could not be located"),
        ));
    }
    item.rescore();

    let weighted = item.flags.iter().any(|f| f.weight > 0);
    // An interpreter process without any signal adds nothing; those that start automatically are still reviewed.
    item.trusted = !weighted && (!item.persistent() || PURE_HOSTS.contains(&host.as_str()));
    if item.trusted {
        item.what = tr!("Windows interpreter process with no risk signals");
    }
    item
}

/// Groups by publisher the binaries that have a valid signature and no signals.
fn group_signed(items: Vec<Item>) -> Vec<Item> {
    let mut groups: Vec<(String, Vec<Item>)> = Vec::new();
    let mut rest = Vec::new();
    for item in items {
        let signer = item
            .file
            .as_ref()
            .map(|i| strip(&text(i.at("signer"))).to_string())
            .unwrap_or_default();
        let valid = item
            .file
            .as_ref()
            .is_some_and(|i| i.at("sig_status").as_str() == Some("Valid"));
        if item.kind == "executable" && !item.trusted && item.score == 0 && valid && !signer.is_empty() {
            match groups.iter_mut().find(|(s, _)| *s == signer) {
                Some((_, members)) => members.push(item),
                None => groups.push((signer, vec![item])),
            }
        } else {
            rest.push(item);
        }
    }

    for (signer, mut members) in groups {
        if members.len() == 1 {
            rest.extend(members);
            continue;
        }
        members.sort_by_key(|m| lower(m.path.as_deref().unwrap_or("")));
        let mut group = Item::new(
            "group",
            signer,
            tr!("{0} components with a valid signature", members.len()),
        );
        for member in &members {
            let info = member.file.clone().unwrap_or_default();
            group.members.push(json!({
                "name": member.title, "path": member.path,
                "description": or_empty(info.at("description")), "company": or_empty(info.at("company")),
                "roles": member.roles.iter().map(|r| r.label.clone()).collect::<Vec<_>>(),
                "network": member.network,
            }));
            group
                .roles
                .extend(member.roles.iter().filter(|r| r.kind != "process").cloned());
            for flag in &member.flags {
                group.add_flag(flag.clone());
            }
        }
        let running = members
            .iter()
            .filter(|m| m.roles.iter().any(|r| r.kind == "process"))
            .count();
        group.facts.insert("running".into(), json!(running));
        group.rescore();
        rest.push(group);
    }
    rest
}

rx!(
    DETECTION_RESOURCE,
    r"(?i)^(?:file|containerfile|process):_?(.+?)(?:->.*)?$"
);

pub(crate) fn evaluate_entities(raw: &Value, refs: Vec<Ref>, files: &Files) -> Vec<Item> {
    let mut entities: Vec<Entity> = Vec::new();
    let mut index: HashMap<(&'static str, String), usize> = HashMap::new();
    for r in refs {
        let (kind, key, path) = entity_key(&r, files);
        if key.is_empty() {
            continue;
        }
        match index.get(&(kind, key.clone())) {
            Some(&i) => entities[i].refs.push(r),
            None => {
                index.insert((kind, key.clone()), entities.len());
                entities.push(Entity {
                    kind,
                    key,
                    path,
                    refs: vec![r],
                });
            }
        }
    }

    let system = raw.at("system");
    let mut detected = HashSet::new();
    for detection in list(system.at("defender_detections")) {
        for resource in list(detection.at("resources")) {
            if let Some(caps) = DETECTION_RESOURCE.captures(&str_of(resource))
                && let Some(found) = caps.get(1)
            {
                detected.insert(lower(strip(found.as_str())));
            }
        }
    }
    let exclusions = list(system.at("defender_pref").at("exclusion_path"))
        .iter()
        .filter(|p| truthy(p) && !str_of(p).starts_with("N/A"))
        .map(|p| lower(&str_of(p)))
        .collect();
    let ctx = Ctx {
        network: network_by_pid(raw),
        detected_paths: detected,
        exclusions,
    };

    let items = entities
        .iter()
        .map(|entity| {
            if entity.kind == "file" {
                evaluate_file(entity, files, &ctx)
            } else {
                evaluate_command(entity, files, &ctx)
            }
        })
        .collect();
    group_signed(items)
}

// --------------------------------------------------------------------------- hashes

fn sha256_file(path: &str, limit: u64) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > limit {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Some(digest.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Computes the SHA-256 of the files that are not trusted (to look them up on VirusTotal).
pub(crate) fn add_hashes(items: &mut [Item]) -> usize {
    let targets: Vec<&mut Item> = items
        .iter_mut()
        .filter(|item| {
            item.kind == "executable"
                && !item.trusted
                && item.path.as_deref().is_some_and(|p| !p.is_empty())
                && file_exists(item.file.as_ref())
                && (item
                    .file
                    .as_ref()
                    .is_some_and(|i| i.at("sig_status").as_str() != Some("Valid"))
                    || item.score >= 15)
        })
        .collect();
    let chunk = targets.len().div_ceil(4).max(1);
    let mut targets = targets;
    std::thread::scope(|scope| {
        for part in targets.chunks_mut(chunk) {
            scope.spawn(move || {
                for item in part.iter_mut() {
                    item.sha256 = item.path.as_deref().and_then(|p| sha256_file(p, 512 * 1024 * 1024));
                }
            });
        }
    });
    targets.iter().filter(|item| item.sha256.is_some()).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(
            split_list(r#""C:\a b\x.dll", y.dll z.dll"#),
            vec![r"C:\a b\x.dll", "y.dll", "z.dll"]
        );
        assert_eq!(command_key("  A \t B  "), "a b");
        assert_eq!(valid_date(&json!("1999-11-30T00:00:00")), Value::Null);
        assert_eq!(valid_date(&json!("2024-01-01")), json!("2024-01-01"));
        assert!(DETECTION_RESOURCE.is_valid() && MSIX_RE.is_valid() && LIST_PART.is_valid());
    }

    #[test]
    fn vigil_own_sign_in_entry_is_not_inventoried() {
        let exe = std::env::current_exe().expect("test program");
        let own = own_autostart_command(&exe);
        let run = |location: &str, name: &str, command: &str| json!({"source": "run", "location": location, "name": name, "command": command, "enabled": true});
        let user_run = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let raw = json!({"autoruns": [
            run(user_run, "Vigil", &own),
            run(user_run, "Vigil", &format!("{own} & calc.exe")),
            run(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "Vigil", &own),
            run(user_run, "Updater", r#""C:\Program Files\Example\updater.exe""#),
        ]});
        let (refs, _) = autorun_refs(&raw);
        assert_eq!(refs.len(), 3, "only the exact own entry is left out");
    }
}
