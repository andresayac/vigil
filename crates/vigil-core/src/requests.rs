//! Turns what the UI asks for into an action Rust trusts.
//!
//! The window sends small requests ("end process 1234 started at T", "run action 2 of finding
//! B1"). Nothing in them is used as is: Rust rebuilds the ActionSpec from its own state (the report
//! it loaded, the live process list, the targets it measured), validates every value, and writes
//! the texts the confirmation shows. A misbehaving window can at most ask for an action the user
//! then sees and declines.

use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};
use vigil_actions::ActionSpec;

use crate::planner::{self, SpecExt, spec};
use vigil_i18n::{tl, tr};

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Request {
    /// Action `index` of a finding's offered actions, with the op and target the page showed: if
    /// the report changed meanwhile (another one was opened, a scan finished), the same index can
    /// mean another action, and the request is refused.
    #[serde(rename_all = "camelCase")]
    Finding {
        item_id: String,
        index: usize,
        op: String,
        target: String,
    },
    #[serde(rename_all = "camelCase")]
    Process {
        op: String,
        pid: u32,
        created_ms: i64,
        priority: Option<String>,
        /// End task on a group: every process of the group (at most `MAX_GROUP`).
        #[serde(default)]
        pids: Vec<ProcessRef>,
        /// Processor affinity: the logical-processor indexes the process may use.
        #[serde(default)]
        cores: Vec<u32>,
    },
    /// Run new task: a program (full path or bare name), its arguments, and whether to ask for
    /// administrator rights.
    Run {
        path: String,
        #[serde(default)]
        args: String,
        #[serde(default)]
        admin: bool,
    },
    #[serde(rename_all = "camelCase")]
    Role {
        op: String,
        item_id: String,
        role: usize,
    },
    Journal {
        op: String,
        id: String,
    },
    Tuning {
        op: String,
        #[serde(default)]
        params: Value,
    },
    Cleanup {
        keys: Vec<String>,
    },
    Recycle {
        paths: Vec<String>,
    },
    /// Copies found by the last duplicate search, sent to the Recycle Bin (checked against that
    /// search in `service::build_plan`; see `duplicates::plan`).
    Duplicates {
        paths: Vec<String>,
    },
    Shell {
        op: String,
        path: Option<String>,
        url: Option<String>,
        name: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Service {
        op: String,
        name: String,
        start_type: Option<String>,
    },
    /// Turn a startup app on or off (`id` from `startup_list`).
    Startup {
        op: String,
        id: String,
    },
    /// Enable, disable, run or delete a scheduled task (`path` from `tasks_list`).
    Task {
        op: String,
        path: String,
    },
    /// Turn a firewall rule on or off, or delete it (`key` from `firewall_list`).
    #[serde(rename = "firewall-rule")]
    FirewallRule {
        op: String,
        key: String,
    },
    /// Uninstall a program, remove its leftover entry or open its install folder (`id` from
    /// `programs_list`; the program is read again from its Uninstall key).
    Program {
        op: String,
        id: String,
    },
    /// From the Accounts page: disable a local account (`sid`), remove a member (`sid`) from
    /// `group` ("administrators" or "remote_desktop_users"), or sign out a `session`. Everything is
    /// read again and checked with the action engine's guards (see `accounts::plan`).
    Account {
        op: String,
        #[serde(default)]
        sid: String,
        #[serde(default)]
        group: String,
        #[serde(default)]
        session: u32,
    },
    /// Microsoft Defender, from the Protection page: scans, update, turning a setting on
    /// (`setting`), removing an exclusion (`list` + `value`) or the active threats. Checked
    /// against a fresh read (see `protection::plan`).
    Defender {
        op: String,
        #[serde(default)]
        setting: String,
        #[serde(default)]
        list: String,
        #[serde(default)]
        value: String,
    },
    /// Raise one setting of the Security posture page (`op`: "uac-default", "rdp-nla",
    /// "smb1-off"...). Checked against a fresh read (see `posture::plan`).
    Posture {
        op: String,
    },
    /// A browser extension, from the Browser extensions page: open the browser's extensions page
    /// (of the extension's browser, or of `browser` by name) or the extension's folder. `key` comes
    /// from `extensions_list`; everything is read again (see `extensions::plan_extension`).
    Extension {
        op: String,
        #[serde(default)]
        key: String,
        #[serde(default)]
        browser: String,
    },
    /// Remove a browser policy (`id` from `extensions_list`), read again from the registry.
    #[serde(rename = "browser-policy")]
    BrowserPolicy {
        op: String,
        id: String,
    },
}

/// One process instance as the page saw it.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessRef {
    pub pid: u32,
    pub created_ms: i64,
}

/// The most processes one End task may name.
pub const MAX_GROUP: usize = 256;

/// What to do with a request once it is understood.
#[derive(Debug, Clone)]
pub enum Plan {
    /// Confirm natively, then run through the action engine. `item` is the finding it belongs to.
    Run {
        spec: ActionSpec,
        item: Option<String>,
    },
    /// Opens something (Explorer, a console, a web page); runs without confirmation.
    Shell(ActionSpec),
    Undo(String),
    UndoBatch(String),
    Restore(String),
    Delete(String),
}

/// The state a request is checked against.
pub struct Context<'a> {
    /// The current report (render_json form).
    pub analysis: Option<&'a Value>,
    /// The live process list.
    pub processes: &'a [vigil_sys::process::ProcessRow],
    /// The cleanup targets measured last (serialized `CleanupTarget`s: key, label, size, admin).
    pub cleanup: &'a [Value],
    /// Files listed by the last space scan: (path, size).
    pub space_files: &'a [(String, u64)],
    /// Power plans: (guid, name, active).
    pub power_plans: &'a [(String, String, bool)],
    /// Drive letter (upper case, no colon) -> media ("SSD", "HDD").
    pub drive_media: &'a [(String, String)],
    /// The live Windows services (read for service requests only).
    pub services: &'a [vigil_sys::services::Service],
    /// The live startup apps (read for startup requests only).
    pub startup: &'a [vigil_sys::startup::StartupEntry],
    /// The live scheduled tasks (read for task requests only).
    pub tasks: &'a [vigil_sys::tasks::ScheduledTask],
    /// The live firewall rules (read for firewall-rule requests only).
    pub firewall: &'a [vigil_sys::firewall::FirewallRule],
}

pub const PRIORITY_LABEL: [(&str, &str); 5] = [
    ("idle", tl!("Low")),
    ("below_normal", tl!("Below normal")),
    ("normal", tl!("Normal")),
    ("above_normal", tl!("Above normal")),
    ("high", tl!("High")),
];
pub const GPU_PREFERENCE_LABEL: [(u64, &str); 3] = [
    (0, tl!("Let Windows decide")),
    (1, tl!("Power saving")),
    (2, tl!("High performance")),
];

pub fn size_text(value: u64) -> String {
    let mut v = value as f64;
    for unit in ["bytes", "KB", "MB", "GB", "TB"] {
        if v.abs() < 1024.0 || unit == "TB" {
            return if unit == "bytes" {
                format!("{} bytes", thousands(value))
            } else {
                format!("{v:.1} {unit}")
            };
        }
        v /= 1024.0;
    }
    String::new()
}

pub fn thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn items(analysis: Option<&Value>) -> &[Value] {
    analysis
        .and_then(|a| a.get("items"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

pub fn find_item<'v>(analysis: Option<&'v Value>, id: &str) -> Option<&'v Value> {
    items(analysis)
        .iter()
        .find(|i| i.get("id").and_then(Value::as_str) == Some(id))
}

pub fn scan_started(analysis: Option<&Value>) -> Option<&str> {
    analysis
        .and_then(|a| a.get("meta"))
        .and_then(|m| m.get("started"))
        .and_then(Value::as_str)
}

const SHELL_OPS: [&str; 10] = [
    "shell.location",
    "shell.properties",
    "shell.folder",
    "shell.regedit",
    "shell.url",
    "shell.browser",
    "shell.hosts",
    "shell.console",
    "shell.tool",
    "signature.verify",
];

fn classify(spec: ActionSpec, item: Option<String>) -> Plan {
    if SHELL_OPS.contains(&spec.op.as_str()) {
        Plan::Shell(spec)
    } else {
        Plan::Run { spec, item }
    }
}

/// URLs the app opens: Windows Security and Settings pages, and a VirusTotal hash lookup.
pub fn allowed_url(url: &str) -> bool {
    let low = url.to_ascii_lowercase();
    let simple = |rest: &str| rest.chars().all(|c| c.is_ascii_alphanumeric() || "-_/.".contains(c));
    if let Some(rest) = low.strip_prefix("windowsdefender://") {
        return simple(rest);
    }
    if let Some(rest) = low.strip_prefix("ms-settings:") {
        return !rest.is_empty() && simple(rest);
    }
    if let Some(hash) = low.strip_prefix("https://www.virustotal.com/gui/file/") {
        return hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit());
    }
    false
}

pub fn build(request: &Request, ctx: &Context<'_>) -> Result<Plan, String> {
    match request {
        Request::Finding {
            item_id,
            index,
            op,
            target,
        } => {
            let item = find_item(ctx.analysis, item_id).ok_or(tr!("The finding is no longer in the report."))?;
            let specs = planner::plan_actions(item, scan_started(ctx.analysis));
            let spec = specs
                .into_iter()
                .nth(*index)
                .ok_or(tr!("That action is no longer offered for this finding."))?;
            if spec.op != *op || spec.target != *target {
                return Err(tr!(
                    "The report changed since this finding was shown. Look at the finding again."
                ));
            }
            Ok(classify(spec, Some(item_id.clone())))
        }
        Request::Role { op, item_id, role } => role_plan(op, item_id, *role, ctx),
        Request::Process {
            op,
            pid,
            created_ms,
            priority,
            pids,
            cores,
        } => {
            if !pids.is_empty() && matches!(op.as_str(), "terminate" | "terminate_tree") {
                return group_terminate_plan(*pid, *created_ms, pids, op == "terminate_tree", ctx);
            }
            if op == "affinity" {
                return affinity_plan(*pid, *created_ms, cores, ctx);
            }
            process_plan(op, *pid, *created_ms, priority.as_deref(), ctx)
        }
        Request::Run { path, args, admin } => run_plan(path, args, *admin),
        Request::Journal { op, id } => {
            let id = id.trim();
            if id.is_empty() || id.len() > 80 || !id.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:".contains(c)) {
                return Err(tr!("Unknown record."));
            }
            match op.as_str() {
                "undo" => Ok(Plan::Undo(id.into())),
                "undo_batch" => Ok(Plan::UndoBatch(id.into())),
                "restore" => Ok(Plan::Restore(id.into())),
                "delete" => Ok(Plan::Delete(id.into())),
                _ => Err(tr!("Unknown request: {0}", op)),
            }
        }
        Request::Tuning { op, params } => tuning_plan(op, params, ctx),
        Request::Cleanup { keys } => cleanup_plan(keys, ctx),
        Request::Recycle { paths } => recycle_plan(paths, ctx),
        // Planned in `service::build_plan` from the last duplicate search (not part of `Context`).
        Request::Duplicates { .. } => Err(tr!("Unknown request: {0}", "duplicates")),
        Request::Shell { op, path, url, name } => shell_plan(op, path.as_deref(), url.as_deref(), name.as_deref()),
        Request::Service { op, name, start_type } => service_plan(op, name, start_type.as_deref(), ctx),
        Request::Startup { op, id } => startup_plan(op, id, ctx),
        Request::Task { op, path } => task_plan(op, path, ctx),
        Request::FirewallRule { op, key } => crate::firewall::plan(op, key, ctx),
        Request::Program { op, id } => crate::programs::plan(op, id),
        Request::Account {
            op,
            sid,
            group,
            session,
        } => crate::accounts::plan(op, sid, group, *session),
        // Planned in `commands::build_plan` from a fresh read of Defender (not part of `Context`).
        Request::Defender { op, .. } => Err(tr!("Unknown request: {0}", op)),
        // Planned in `commands::build_plan` from a fresh read of the posture.
        Request::Posture { op } => Err(tr!("Unknown request: {0}", op)),
        // Planned in `commands::build_plan` from a fresh read of the browsers (see `extensions`).
        Request::Extension { op, .. } | Request::BrowserPolicy { op, .. } => Err(tr!("Unknown request: {0}", op)),
    }
}

/// A scheduled task. It must be in the live list and outside `\Microsoft\`; its folder and name
/// come from that list, never from the page. The action engine checks the guard again.
fn task_plan(op: &str, path: &str, ctx: &Context<'_>) -> Result<Plan, String> {
    let task = ctx
        .tasks
        .iter()
        .find(|t| t.path.eq_ignore_ascii_case(path.trim()))
        .ok_or(tr!("The scheduled task is no longer there. Refresh the list."))?;
    if task.microsoft {
        return Err(tr!(
            "Tasks under \\Microsoft\\ belong to Windows and are not changed from Vigil."
        ));
    }
    let quoted = format!("\"{}\"", task.path);
    let target = tr!("scheduled task {0}", task.path);
    let risky = task.elevated && task.user_writable;
    let built = match op {
        "enable" => {
            if task.enabled {
                return Err(tr!("The task is already enabled."));
            }
            let built = spec(
                "task.enable",
                tr!("Enable task {0}", quoted),
                target,
                tr!("Task Scheduler starts it again when its triggers fire. It is not run now."),
            )
            .group("fix");
            if risky {
                built.warning(&tr!(
                    "This task runs with full rights a program from a folder that standard users can change. Enable it only if you trust that program."
                ))
            } else if !task.program.is_empty() && !task.program_exists {
                built.warning(&tr!("The program this task starts was not found, so the task will fail when it runs."))
            } else {
                built
            }
        }
        "disable" => {
            if !task.enabled {
                return Err(tr!("The task is already disabled."));
            }
            spec(
                "task.disable",
                tr!("Disable task {0}", quoted),
                target,
                tr!("Turns the scheduled task off; it stays in Task Scheduler and can be enabled again."),
            )
            .group("disable")
        }
        "run" => {
            if !task.enabled {
                return Err(tr!("Enable the task before running it."));
            }
            let explain = if task.account.is_empty() {
                tr!("Starts the task now, as Task Scheduler's Run command does: with the task's own account and rights, not yours. Running it cannot be undone.")
            } else {
                tr!(
                    "Starts the task now, as Task Scheduler's Run command does: as {0}, with the task's own rights, not yours. Running it cannot be undone.",
                    task.account
                )
            };
            let built = spec("task.run", tr!("Run task {0}", quoted), target, explain)
                .group("inspect")
                .irreversible();
            if risky {
                built.warning(&tr!(
                    "This task runs with full rights a program from a folder that standard users can change. Run it only if you trust that program."
                ))
            } else {
                built
            }
        }
        // The password a task stores is not part of its definition: such a task cannot be recreated.
        "delete" if task.logon_type == "password" => spec(
            "task.delete",
            tr!("Delete task {0}", quoted),
            target,
            tr!(
                "Removes the task from Task Scheduler. It runs with a stored password, which its saved definition does not contain, so it cannot be recreated from History: you would have to create it again by hand. The program it starts is not deleted."
            ),
        )
        .group("remove")
        .destructive()
        .irreversible(),
        "delete" => spec(
            "task.delete",
            tr!("Delete task {0}", quoted),
            target,
            tr!(
                "Removes the task from Task Scheduler. Its XML definition is saved first, so History can recreate it. The program it starts is not deleted."
            ),
        )
        .group("remove")
        .destructive(),
        _ => return Err(tr!("Unknown request: {0}", op)),
    };
    Ok(Plan::Run {
        spec: built.params(json!({ "path": task.folder, "name": task.name })),
        item: None,
    })
}

/// Turning a startup app on or off. The entry must be in the live list; its key, value or file
/// come from that list, never from the page.
fn startup_plan(op: &str, id: &str, ctx: &Context<'_>) -> Result<Plan, String> {
    let entry = ctx
        .startup
        .iter()
        .find(|e| e.id == id)
        .ok_or(tr!("The startup app is no longer there. Refresh the list."))?;
    if !entry.can_toggle && (op == "disable" || op == "enable") {
        return Err(if entry.kind == "policy" {
            tr!("A policy sets this entry; it has no on/off switch. You can delete it instead.")
        } else {
            tr!("This entry runs only once and has no on/off switch.")
        });
    }
    if op == "delete" && entry.kind != "policy" {
        return Err(tr!("Unknown request: {0}", op));
    }
    let (params, target) = if entry.kind == "folder" {
        (json!({ "file": entry.file }), entry.file.clone())
    } else {
        (
            json!({ "key": entry.location, "value": entry.value }),
            format!("{}\\{}", entry.location, entry.value),
        )
    };
    let shown = if entry.description.is_empty() {
        &entry.name
    } else {
        &entry.description
    };
    let quoted = format!("\"{shown}\"");
    let built = match op {
        "disable" => spec(
            "startup.disable",
            tr!("Disable startup app {0}", quoted),
            target,
            tr!(
                "Windows will not start it the next time you sign in. Nothing is closed or deleted: the entry stays where it is, with the same switch Task Manager uses, and you can turn it back on here or in Task Manager."
            ),
        )
        .group("disable"),
        "enable" => {
            let built = spec(
                "startup.enable",
                tr!("Enable startup app {0}", quoted),
                target,
                tr!("Windows starts it again the next time you sign in. It is not started now."),
            )
            .group("fix");
            if entry.exists {
                built
            } else {
                built.warning(&tr!("The program this entry starts was not found, so Windows cannot start it."))
            }
        }
        // A Run key set by policy has no switch: the value itself is removed (and saved first).
        "delete" => spec(
            "registry.delete",
            tr!("Delete startup entry {0}", quoted),
            target,
            tr!(
                "Removes this value from a Run key that is normally set by a policy. Windows will not start the program at the next sign-in. The value is saved first, so History can put it back. The program itself is not deleted, and a policy that still sets the value may write it again."
            ),
        )
        .group("remove")
        .destructive(),
        _ => return Err(tr!("Unknown request: {0}", op)),
    };
    let built = built.params(params);
    // The user's own entries live in their part of the registry: no administrator rights needed.
    // (Policy keys are protected even in the user's own part of the registry.)
    let built = if entry.scope == "user" && op != "delete" {
        built.no_admin()
    } else {
        built
    };
    Ok(Plan::Run {
        spec: built,
        item: None,
    })
}

/// A service the action engine refuses to change: an essential Windows service, or a Windows
/// component (its binary, or the DLL svchost loads for it, lives in the Windows folder). The page
/// uses it to lock its buttons; the engine's own guard stays the authority.
pub fn protected_service(service: &vigil_sys::services::Service) -> bool {
    let windir = std::env::var("SystemRoot")
        .unwrap_or_else(|_| r"C:\Windows".into())
        .trim_end_matches('\\')
        .to_lowercase();
    let target = if service.dll.is_empty() {
        &service.executable
    } else {
        &service.dll
    };
    vigil_actions::ESSENTIAL_SERVICES.contains(&service.name.to_lowercase().as_str())
        || target.to_lowercase().starts_with(&format!("{windir}\\"))
}

/// The startup types the Services page offers, with their display names.
pub const START_TYPES: [(&str, &str); 4] = [
    ("auto", tl!("Automatic")),
    ("delayed-auto", tl!("Automatic (delayed start)")),
    ("demand", tl!("Manual")),
    ("disabled", tl!("Disabled")),
];

fn service_plan(op: &str, name: &str, start_type: Option<&str>, ctx: &Context<'_>) -> Result<Plan, String> {
    // The service must exist right now; its canonical name is used from here on.
    let service = ctx
        .services
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(name))
        .ok_or(tr!("The service no longer exists."))?;
    let name = service.name.as_str();
    let target = if service.display_name.is_empty() || service.display_name == name {
        name.to_string()
    } else {
        format!("{} ({name})", service.display_name)
    };
    let quoted = format!("\"{}\"", service.display_name);
    let spec = match op {
        "start" => spec(
            "service.start",
            tr!("Start service {0}", quoted),
            target,
            tr!("Starts the service now. Its startup type does not change."),
        )
        .params(json!({"name": name}))
        .group("fix")
        .irreversible(),
        "stop" => spec(
            "service.stop",
            tr!("Stop service {0}", quoted),
            target,
            tr!(
                "Stops the service now. Programs that depend on it may stop working until it runs again; with an automatic startup type it starts again at the next restart."
            ),
        )
        .params(json!({"name": name}))
        .group("contain"),
        "restart" => spec(
            "service.restart",
            tr!("Restart service {0}", quoted),
            target,
            tr!("Stops the service and starts it again. Programs that use it may lose their connection for a moment."),
        )
        .params(json!({"name": name}))
        .group("fix")
        .irreversible(),
        "start_type" => {
            let wanted = start_type.unwrap_or("");
            let (value, text) = START_TYPES
                .iter()
                .find(|(value, _)| *value == wanted)
                .copied()
                .ok_or(tr!("Unknown startup type."))?;
            let explain = match value {
                "auto" => tr!("Windows starts the service at every boot."),
                "delayed-auto" => tr!("Windows starts the service shortly after boot, once the desktop is ready."),
                "demand" => tr!("Windows starts the service only when a program asks for it."),
                _ => tr!("The service no longer starts, not even when a program asks for it."),
            };
            let built = spec(
                "service.start_type",
                tr!("Startup type of {0}: {1}", quoted, tr!(text)),
                target,
                format!("{explain} {}", tr!("You can undo it from History.")),
            )
            .params(json!({"name": name, "start_type": value}))
            .group("disable");
            if value == "disabled" {
                built.warning(&tr!(
                    "Programs that need this service fail while it is disabled. Disable only services you know you do not use."
                ))
            } else {
                built
            }
        }
        _ => return Err(tr!("Unknown request: {0}", op)),
    };
    Ok(Plan::Run { spec, item: None })
}

fn role_plan(op: &str, item_id: &str, index: usize, ctx: &Context<'_>) -> Result<Plan, String> {
    let item = find_item(ctx.analysis, item_id).ok_or(tr!("The finding is no longer in the report."))?;
    let role = item
        .get("roles")
        .and_then(Value::as_array)
        .and_then(|roles| roles.get(index))
        .ok_or(tr!("That entry is no longer in the report."))?;
    let kind = role.get("kind").and_then(Value::as_str).unwrap_or("");
    let spec =
        match (op, kind) {
            ("startup.disable", "startup") => planner::startup_specs(role).into_iter().find(|s| s.op == op),
            ("task.disable", "task") => planner::task_specs(role).into_iter().find(|s| s.op == op),
            ("service.manual", "service") => {
                let name = role
                    .get("detail")
                    .and_then(|d| d.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                (!name.is_empty()).then(|| {
                    spec(
                    "service.manual",
                    tr!("Start {0} only when needed", name),
                    format!("service {name}"),
                    tr!("Changes the start type from automatic to manual: Windows starts the service when a program \
                     asks for it instead of at every boot."),
                )
                .params(json!({"name": name}))
                .group("disable")
                })
            }
            _ => None,
        };
    let spec = spec.ok_or(tr!("This entry cannot be changed from here."))?;
    Ok(Plan::Run {
        spec,
        item: Some(item_id.to_string()),
    })
}

fn process_plan(
    op: &str,
    pid: u32,
    created_ms: i64,
    priority: Option<&str>,
    ctx: &Context<'_>,
) -> Result<Plan, String> {
    // Re-read the process: the PID must still belong to the process the user selected.
    let row = live_row(ctx, pid, created_ms).ok_or(tr!("The process has exited."))?;
    let name = format!("{} (PID {})", row.name, row.pid);
    let ident = json!({"pid": row.pid, "create_time": row.created_ms as f64 / 1000.0});
    let exe = row.exe.clone();
    let need_exe = || {
        if exe.is_empty() {
            Err(tr!("Windows does not report the file of this process."))
        } else {
            Ok(())
        }
    };
    let spec = match op {
        "terminate" | "terminate_tree" => {
            let tree = op == "terminate_tree";
            if row.pid <= 4 {
                return Err(tr!("This is a core Windows process and cannot be ended."));
            }
            spec(
                "process.terminate",
                if tree { tr!("End process tree") } else { tr!("End process") },
                &name,
                if tree {
                    tr!("Ends the process and every process it started. Unsaved work in them is lost.")
                } else {
                    tr!("Ends the process. Unsaved work in it is lost.")
                },
            )
            .params(json!({"pids": [row.pid], "names": [row.name], "tree": tree, "scan_started": null,
                           "create_time": row.created_ms as f64 / 1000.0}))
            .group("contain")
            .destructive()
            .irreversible()
            .no_admin()
        }
        "suspend" | "resume" => {
            let suspend = op == "suspend";
            if suspend && row.pid <= 4 {
                return Err(tr!("This is a core Windows process and cannot be suspended."));
            }
            spec(
                if suspend { "process.suspend" } else { "process.resume" },
                if suspend { "Suspend" } else { "Resume" },
                &name,
                if suspend { tr!("Freezes the process without ending it.") } else { tr!("Lets a suspended process run again.") },
            )
            .params(ident)
            .group("contain")
            .no_admin()
        }
        "priority" => {
            let key = priority.unwrap_or("");
            let (key, text) =
                PRIORITY_LABEL.iter().find(|(k, _)| *k == key).copied().ok_or(tr!("Unknown priority."))?;
            let text = tr!(text);
            let mut params = ident;
            params["priority"] = json!(key);
            spec(
                "process.priority",
                tr!("Priority: {0}", text),
                &name,
                tr!("Sets the CPU priority of the process to {0} until it exits.", text),
            )
            .params(params)
            .group("fix")
            .no_admin()
            .warning(&if key == "high" {
                tr!("High priority can make the rest of Windows less responsive.")
            } else {
                String::new()
            })
        }
        "efficiency" => spec(
            "process.efficiency",
            tr!("Efficiency mode"),
            &name,
            tr!("Runs the process at low priority on power-efficient cores, like Task Manager's efficiency mode. It \
             keeps working, just more slowly."),
        )
        .params(ident)
        .group("contain")
        .no_admin(),
        "background" => spec(
            "process.background",
            tr!("Low disk and memory priority"),
            &name,
            tr!("Its disk reads and writes wait behind other programs', and its memory is the first to leave RAM when memory is short. Its CPU priority does not change. Undo restores the previous priorities."),
        )
        .params(ident)
        .group("fix")
        .no_admin(),
        "trim" => spec(
            "process.trim",
            tr!("Trim memory"),
            &name,
            tr!("Asks Windows to move the pages this process is not using out of RAM. It reloads them when needed, so \
             this only helps when memory is short."),
        )
        .params(ident)
        .group("fix")
        .irreversible()
        .no_admin(),
        "quarantine" => {
            need_exe()?;
            spec("file.quarantine", tr!("Quarantine file"), &exe, tr!("Ends every process running this file and moves it into quarantine."))
                .params(json!({"path": exe, "reason": row.name, "kill": true}))
                .group("remove")
                .destructive()
        }
        "block" => {
            need_exe()?;
            spec("firewall.block", tr!("Block network access"), &exe, tr!("Adds Windows Firewall rules that block all its traffic."))
                .params(json!({"path": exe}))
                .group("contain")
        }
        "location" | "properties" | "verify" => {
            need_exe()?;
            let (op, label) = match op {
                "location" => ("shell.location", tr!("Open file location")),
                "properties" => ("shell.properties", tr!("Properties")),
                _ => ("signature.verify", tr!("Verify signature")),
            };
            spec(op, label, &exe, "").params(json!({"path": exe})).no_admin()
        }
        _ => return Err(tr!("Unknown request: {0}", op)),
    };
    Ok(classify(spec, None))
}

/// The running process with this PID and start time. Both must match: a start time of 0 names no
/// process (it is not a wildcard), so a PID reused by another process is never acted on.
fn live_row<'r>(ctx: &'r Context<'_>, pid: u32, created_ms: i64) -> Option<&'r vigil_sys::process::ProcessRow> {
    if created_ms == 0 {
        return None;
    }
    ctx.processes
        .iter()
        .find(|r| r.pid == pid && r.created_ms == created_ms)
}

/// End task on a group row: one `process.terminate` for every process of the group that still runs
/// (same PID and start time). Protected processes are left out, and the confirmation says so.
fn group_terminate_plan(
    pid: u32,
    created_ms: i64,
    refs: &[ProcessRef],
    tree: bool,
    ctx: &Context<'_>,
) -> Result<Plan, String> {
    if refs.len() > MAX_GROUP {
        return Err(tr!("Too many processes at once (at most {0}).", MAX_GROUP));
    }
    let mut live: Vec<&vigil_sys::process::ProcessRow> = Vec::new();
    let mut protected: Vec<String> = Vec::new();
    for r in refs {
        let Some(row) = ctx
            .processes
            .iter()
            .find(|row| row.pid == r.pid && row.created_ms == r.created_ms)
        else {
            continue;
        };
        if live.iter().any(|l| l.pid == row.pid) {
            continue;
        }
        let proc = vigil_actions::Proc {
            pid: row.pid,
            name: row.name.clone(),
        };
        if let Some(reason) = vigil_actions::process_protection(&proc) {
            protected.push(format!("{} (PID {}): {reason}", row.name, row.pid));
        } else {
            live.push(row);
        }
    }
    if live.is_empty() {
        return Err(if protected.is_empty() {
            tr!("These processes have exited.")
        } else {
            tr!("Every process here is protected: {0}", protected.join("; "))
        });
    }
    let main = live_row(ctx, pid, created_ms).unwrap_or(live[0]);
    let program = if main.description.trim().is_empty() {
        main.name.clone()
    } else {
        main.description.trim().to_string()
    };
    let count = live.len();
    let mut names: Vec<&str> = live.iter().map(|r| r.name.as_str()).collect();
    names.sort_unstable_by_key(|n| n.to_lowercase());
    names.dedup_by_key(|n| n.to_lowercase());
    let explain = match (count, tree) {
        (1, false) => tr!("Ends {0}. Unsaved work in it is lost.", program),
        (1, true) => tr!(
            "Ends {0} and every process it started. Unsaved work in them is lost.",
            program
        ),
        (_, false) => tr!(
            "Ends the {0} processes of {1}. Unsaved work in them is lost.",
            count,
            program
        ),
        (_, true) => tr!(
            "Ends the {0} processes of {1} and every process they started. Unsaved work in them is lost.",
            count,
            program
        ),
    };
    let target = if count == 1 {
        format!("{} (PID {})", main.name, live[0].pid)
    } else {
        tr!("{0} ({1} processes)", program, count)
    };
    let warning = if protected.is_empty() {
        String::new()
    } else {
        tr!("Left out because they are protected: {0}", protected.join("; "))
    };
    let instances: Vec<Value> = live
        .iter()
        .map(|r| json!({"pid": r.pid, "create_time": r.created_ms as f64 / 1000.0}))
        .collect();
    let spec = spec("process.terminate", tr!("End task"), target, explain)
        .params(json!({
            "pids": live.iter().map(|r| r.pid).collect::<Vec<_>>(),
            "names": names,
            "tree": tree,
            "scan_started": null,
            "instances": instances,
        }))
        .group("contain")
        .destructive()
        .irreversible()
        .no_admin()
        .warning(&warning);
    Ok(classify(spec, None))
}

/// "0-3, 8, 10-11": processor indexes for people.
fn index_ranges(indexes: &[u32]) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0;
    while i < indexes.len() {
        let start = indexes[i];
        let mut end = start;
        while i + 1 < indexes.len() && indexes[i + 1] == end + 1 {
            i += 1;
            end = indexes[i];
        }
        parts.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        i += 1;
    }
    parts.join(", ")
}

/// Processor affinity: the logical processors (Vigil's indexes, as `cpu_topology` lists them) a
/// process may use.
fn affinity_plan(pid: u32, created_ms: i64, cores: &[u32], ctx: &Context<'_>) -> Result<Plan, String> {
    let row = live_row(ctx, pid, created_ms).ok_or(tr!("The process has exited."))?;
    let total = vigil_sys::cpusets::logical_processors().len() as u32;
    if total == 0 {
        return Err(tr!("Windows did not report the processors of this computer."));
    }
    let mut chosen: Vec<u32> = cores.to_vec();
    chosen.sort_unstable();
    chosen.dedup();
    if chosen.is_empty() {
        return Err(tr!("Choose at least one processor."));
    }
    if chosen.iter().any(|c| *c >= total) {
        return Err(tr!("Unknown processor."));
    }
    let name = format!("{} (PID {})", row.name, row.pid);
    let count = chosen.len() as u32;
    let explain = if count == total {
        tr!("Lets the process use every logical processor, as Windows does by default.")
    } else {
        tr!(
            "Limits the process to {0} of the {1} logical processors (CPU {2}) until it exits. Undo restores the previous choice.",
            count,
            total,
            index_ranges(&chosen)
        )
    };
    let warning = if count < total && count <= total / 4 {
        tr!("With few processors, the program can become much slower.")
    } else {
        String::new()
    };
    let spec = spec("process.affinity", tr!("Processor affinity"), &name, explain)
        .params(json!({"pid": row.pid, "create_time": row.created_ms as f64 / 1000.0, "cores": chosen}))
        .group("fix")
        .no_admin()
        .warning(&warning);
    Ok(classify(spec, None))
}

/// Run new task: the program is resolved to one existing file and the confirmation shows the exact
/// command line that will start.
fn run_plan(path: &str, args: &str, admin: bool) -> Result<Plan, String> {
    let program = vigil_actions::run::resolve_program(path).map_err(|e| e.to_string())?;
    vigil_actions::run::check_args(args).map_err(|e| e.to_string())?;
    let args = args.trim();
    let line = vigil_actions::run::command_line(&program, args);
    let elevated = vigil_actions::is_admin();
    let mut explain = format!("{}\n{line}\n\n", tr!("Starts this command:"));
    explain.push_str(&if admin && !elevated {
        tr!("Windows asks for administrator permission first.")
    } else if elevated {
        tr!("Vigil runs as administrator, so the program also gets administrator rights.")
    } else {
        tr!("It runs with your normal rights.")
    });
    let spec = spec("process.run", tr!("Run new task"), "", explain)
        .params(json!({"path": program, "args": args, "admin": admin}))
        .group("fix")
        .irreversible()
        .no_admin();
    Ok(Plan::Run { spec, item: None })
}

fn flag(params: &Value, key: &str) -> Result<bool, String> {
    params
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| tr!("Missing value: {0}", key))
}

fn tuning_plan(op: &str, params: &Value, ctx: &Context<'_>) -> Result<Plan, String> {
    let spec = match op {
        "power.plan" => {
            let guid = params
                .get("guid")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            let (guid, name, _) = ctx
                .power_plans
                .iter()
                .find(|(g, _, _)| g.to_ascii_lowercase() == guid)
                .ok_or(tr!("That power plan no longer exists."))?;
            let previous = ctx
                .power_plans
                .iter()
                .find(|(_, _, active)| *active)
                .map(|(_, n, _)| n.clone());
            spec(
                "power.plan",
                tr!("Use the {0} plan", name),
                tr!("Windows power plan"),
                tr!("Switches the active power plan to {0}.", name),
            )
            .params(json!({"guid": guid, "name": name, "previous_name": previous}))
            .group("fix")
            .no_admin()
        }
        "power.ultimate" => spec(
            "power.ultimate",
            tr!("Add the Ultimate Performance plan"),
            tr!("Windows power plans"),
            tr!("Ultimate Performance removes the last power-saving delays. For desktops doing sustained heavy work; it \
             raises idle power use."),
        )
        .group("fix"),
        "memory.purge_standby" => spec(
            "memory.purge_standby",
            tr!("Free standby memory"),
            tr!("Windows memory"),
            tr!("Empties the standby list (the file cache) into free memory. Programs may load slightly slower until the \
             cache fills again."),
        )
        .group("fix")
        .irreversible(),
        "memory.trim_all" => spec(
            "memory.trim_all",
            tr!("Trim all programs"),
            tr!("Every running program"),
            tr!("Asks every program to give back the memory it is not using right now. They reload it on demand, so the \
             effect is temporary."),
        )
        .group("fix")
        .irreversible(),
        "gaming.game_mode" => {
            let on = flag(params, "on")?;
            spec(
                "gaming.game_mode",
                if on { tr!("Turn Game Mode on") } else { tr!("Turn Game Mode off") },
                tr!("Windows Game Mode"),
                tr!("Changes the Game Mode switch (the same one as in Settings)."),
            )
            .params(json!({"on": on}))
            .group("fix")
            .no_admin()
        }
        "gaming.hags" => {
            let on = flag(params, "on")?;
            spec(
                "gaming.hags",
                if on { tr!("Turn GPU scheduling on") } else { tr!("Turn GPU scheduling off") },
                tr!("Windows graphics settings"),
                tr!("Changes hardware-accelerated GPU scheduling. It takes effect after a restart."),
            )
            .params(json!({"on": on}))
            .group("fix")
        }
        "gpu.preference" => {
            let exe = params.get("exe").and_then(Value::as_str).unwrap_or("");
            let path = Path::new(exe);
            let is_exe = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe"));
            if !path.is_absolute() || !is_exe || !path.is_file() {
                return Err(tr!("Choose a program (.exe) that exists."));
            }
            let value = params.get("preference").and_then(Value::as_u64).unwrap_or(99);
            let (value, text) = GPU_PREFERENCE_LABEL
                .iter()
                .find(|(v, _)| *v == value)
                .copied()
                .ok_or(tr!("Unknown GPU preference."))?;
            let text = tr!(text);
            spec(
                "gpu.preference",
                tr!("GPU for {0}: {1}", base_name(exe), text),
                exe,
                tr!("Sets the graphics preference Windows uses for this app (Settings > Display > Graphics)."),
            )
            .params(json!({"exe": exe, "preference": value}))
            .group("fix")
            .no_admin()
        }
        "power.hibernate" => {
            let on = flag(params, "on")?;
            spec(
                "power.hibernate",
                if on { tr!("Turn hibernation on") } else { tr!("Turn hibernation off") },
                tr!("Windows hibernation"),
                if on {
                    tr!("Runs powercfg /hibernate on.")
                } else {
                    tr!("Runs powercfg /hibernate off. Laptops lose the Hibernate option.")
                },
            )
            .params(json!({"on": on}))
            .group("fix")
        }
        "disk.optimize" => {
            let drive = params
                .get("drive")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim_end_matches(':')
                .to_ascii_uppercase();
            let (letter, media) = ctx
                .drive_media
                .iter()
                .find(|(l, m)| *l == drive && matches!(m.to_ascii_uppercase().as_str(), "SSD" | "HDD"))
                .ok_or(tr!("That drive is not an SSD or hard disk with a drive letter."))?;
            let ssd = media.eq_ignore_ascii_case("SSD");
            spec(
                "disk.optimize",
                format!("Optimize {letter}:"),
                format!("drive {letter}: ({media})"),
                if ssd {
                    tr!("Runs Optimize-Volume -ReTrim.")
                } else {
                    tr!("Runs Optimize-Volume -Defrag (can take a long time on a full disk).")
                },
            )
            .params(json!({"drive": letter, "media": media}))
            .group("fix")
            .irreversible()
        }
        "disk.component_cleanup" => spec(
            "disk.component_cleanup",
            tr!("Clean up the component store"),
            "Windows (WinSxS)",
            tr!("Runs DISM /StartComponentCleanup. It can take 5 to 20 minutes."),
        )
        .group("fix")
        .irreversible(),
        "vigil.autostart" => {
            let on = flag(params, "on")?;
            let command = crate::autostart::command().map_err(|e| e.to_string())?;
            spec(
                "vigil.autostart",
                if on {
                    tr!("Start Vigil in the tray when I sign in")
                } else {
                    tr!("Do not start Vigil when I sign in")
                },
                format!(r"{}\{}", crate::autostart::RUN_KEY, vigil_sys::startup::OWN_VALUE),
                if on {
                    tr!(
                        "Adds Vigil to the programs Windows starts when you sign in (your account only). It \
                         starts hidden in the tray, without asking for administrator rights: {0}",
                        command
                    )
                } else {
                    tr!("Removes Vigil from the programs Windows starts when you sign in.")
                },
            )
            .params(json!({"on": on}))
            .group("fix")
            .no_admin()
        }
        "system.restore_point" => {
            let typed = params.get("description").and_then(Value::as_str).unwrap_or("");
            let description = crate::restore::description(typed)?;
            spec(
                "system.restore_point",
                tr!("Create a restore point"),
                description.clone(),
                tr!(
                    "Creates a System Restore point you can return to. Windows makes at most one every 24 hours: if one was made recently, it keeps that one."
                ),
            )
            .params(json!({"description": description}))
            .group("fix")
            .irreversible()
        }
        "defender.full_scan" => spec(
            "defender.full_scan",
            tr!("Run a full Defender scan"),
            tr!("Microsoft Defender"),
            tr!("Starts a full scan in the background."),
        )
        .group("fix")
        .irreversible(),
        "defender.update" => spec(
            "defender.update",
            tr!("Update security intelligence"),
            tr!("Microsoft Defender"),
            tr!("Downloads the latest Defender definitions."),
        )
        .group("fix")
        .irreversible(),
        _ => return Err(tr!("Unknown request: {0}", op)),
    };
    Ok(Plan::Run { spec, item: None })
}

fn cleanup_plan(keys: &[String], ctx: &Context<'_>) -> Result<Plan, String> {
    let chosen: Vec<&Value> = ctx
        .cleanup
        .iter()
        .filter(|t| keys.iter().any(|k| t.get("key").and_then(Value::as_str) == Some(k)))
        .collect();
    if chosen.is_empty() {
        return Err(tr!("Measure the locations first, then choose what to clean."));
    }
    let total: u64 = chosen
        .iter()
        .filter_map(|t| t.get("size").and_then(Value::as_u64))
        .sum();
    let labels: Vec<&str> = chosen
        .iter()
        .filter_map(|t| t.get("label").and_then(Value::as_str))
        .collect();
    let mut names = labels.iter().take(6).copied().collect::<Vec<_>>().join(", ");
    if labels.len() > 6 {
        names.push('…');
    }
    let admin = chosen
        .iter()
        .any(|t| t.get("admin").and_then(Value::as_bool).unwrap_or(false));
    let keys: Vec<&str> = chosen
        .iter()
        .filter_map(|t| t.get("key").and_then(Value::as_str))
        .collect();
    let mut spec = spec(
        "storage.clean",
        tr!("Clean selected"),
        format!("{} places, about {}", chosen.len(), size_text(total)),
        tr!(
            "Deletes temporary and cache files from: {0}. Files in use are skipped; programs recreate their \
             caches when they need them.",
            names
        ),
    )
    .params(json!({"keys": keys}))
    .group("remove")
    .destructive()
    .irreversible();
    spec.admin = admin;
    Ok(Plan::Run { spec, item: None })
}

fn recycle_plan(paths: &[String], ctx: &Context<'_>) -> Result<Plan, String> {
    if paths.is_empty() || paths.len() > 500 {
        return Err(tr!("Choose the files to remove."));
    }
    let mut total = 0u64;
    for path in paths {
        let (_, size) = ctx
            .space_files
            .iter()
            .find(|(p, _)| p.eq_ignore_ascii_case(path))
            .ok_or(tr!(
                "Only files listed by the last space analysis can be removed from here."
            ))?;
        total += size;
    }
    let what = if paths.len() == 1 {
        base_name(&paths[0]).to_string()
    } else {
        format!("{} files", paths.len())
    };
    let spec = spec(
        "storage.recycle",
        tr!("Send to Recycle Bin"),
        format!("{what} ({})", size_text(total)),
        tr!("Moves the files to the Recycle Bin. The space is freed when the bin is emptied; until then you can restore \
         them from it."),
    )
    .params(json!({"paths": paths}))
    .group("remove")
    .destructive()
    .irreversible()
    .no_admin()
    .warning(
        &tr!("Check that these files are not needed by a program (game data, virtual disks, databases) before removing \
         them."),
    );
    Ok(Plan::Run { spec, item: None })
}

fn shell_plan(op: &str, path: Option<&str>, url: Option<&str>, name: Option<&str>) -> Result<Plan, String> {
    let spec = match op {
        "location" => {
            let path = path
                .filter(|p| Path::new(p).is_absolute())
                .ok_or(tr!("Unknown file."))?;
            spec("shell.location", tr!("Open file location"), path, "").params(json!({"path": path}))
        }
        "properties" => {
            let path = path
                .filter(|p| Path::new(p).is_absolute())
                .ok_or(tr!("Unknown file."))?;
            spec("shell.properties", tr!("Properties"), path, "").params(json!({"path": path}))
        }
        "url" => {
            let url = url
                .filter(|u| allowed_url(u))
                .ok_or(tr!("This address is not opened from Vigil."))?;
            spec("shell.url", "Open", url, "").params(json!({"url": url}))
        }
        "console" => {
            let name = name.unwrap_or("");
            if !matches!(
                name,
                "taskschd.msc" | "services.msc" | "eventvwr.msc" | "wf.msc" | "lusrmgr.msc"
            ) {
                return Err(tr!("Unknown console."));
            }
            spec("shell.console", name, "", "").params(json!({"name": name}))
        }
        "tool" => {
            let name = name.unwrap_or("");
            // The action engine checks its own allowlist again.
            if name.is_empty() || name.contains(['\\', '/', ':']) {
                return Err(tr!("Unknown tool."));
            }
            spec("shell.tool", name, "", "").params(json!({"name": name}))
        }
        _ => return Err(tr!("Unknown request: {0}", op)),
    };
    Ok(Plan::Shell(spec.no_admin()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_read_with_thousands_and_one_decimal() {
        assert_eq!(size_text(0), "0 bytes");
        assert_eq!(size_text(1023), "1,023 bytes");
        assert_eq!(size_text(1536), "1.5 KB");
        assert_eq!(size_text(5 * 1024 * 1024 * 1024), "5.0 GB");
    }

    #[test]
    fn only_known_urls_open() {
        assert!(allowed_url("windowsdefender://threatsettings"));
        assert!(allowed_url("ms-settings:storagesense"));
        assert!(allowed_url(&format!(
            "https://www.virustotal.com/gui/file/{}",
            "a".repeat(64)
        )));
        assert!(!allowed_url("ms-msdt:/id PCWDiagnostic"));
        assert!(!allowed_url("https://example.com/"));
        assert!(!allowed_url("file:///C:/Windows/System32/calc.exe"));
        assert!(!allowed_url("ms-settings:"));
    }

    #[test]
    fn requests_parse() {
        let r: Request =
            serde_json::from_value(json!({"kind": "process", "op": "terminate", "pid": 10, "createdMs": 5}))
                .unwrap_or(Request::Cleanup { keys: vec![] });
        assert!(matches!(
            r,
            Request::Process {
                pid: 10,
                created_ms: 5,
                ..
            }
        ));
        let r: Request = serde_json::from_value(
            json!({"kind": "finding", "itemId": "B1", "index": 2, "op": "file.quarantine", "target": r"C:\x.exe"}),
        )
        .unwrap_or(Request::Cleanup { keys: vec![] });
        assert!(matches!(r, Request::Finding { index: 2, .. }));
        // A finding request names the action the page showed, or it is not understood.
        assert!(serde_json::from_value::<Request>(json!({"kind": "finding", "itemId": "B1", "index": 2})).is_err());
        assert!(serde_json::from_value::<Request>(json!({"kind": "exec", "cmd": "calc"})).is_err());
    }

    /// A start time of 0 is not a wildcard: the request names no process and is refused, even when
    /// a process with that PID runs (it may have taken the PID of the one the page showed).
    #[test]
    fn a_zero_start_time_names_no_process() {
        let rows = [row(4242, "notes.exe", 1000)];
        let ctx = context(&rows);
        let ask = |created_ms: i64, op: &str| {
            build(
                &Request::Process {
                    op: op.into(),
                    pid: 4242,
                    created_ms,
                    priority: None,
                    pids: Vec::new(),
                    cores: Vec::new(),
                },
                &ctx,
            )
        };
        assert!(ask(1000, "terminate").is_ok());
        for op in ["terminate", "block", "suspend", "location"] {
            assert!(ask(0, op).is_err(), "{op} with a zero start time");
        }
        assert!(ask(999, "terminate").is_err(), "another start time is another process");
    }

    fn fixture_analysis() -> Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join("fixture-analysis.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_default()).unwrap_or(Value::Null)
    }

    /// The same index can mean another action once another report is loaded: the op and target the
    /// page showed must still match, or nothing runs.
    #[test]
    fn a_finding_action_must_be_the_one_shown() {
        let analysis = fixture_analysis();
        let started = scan_started(Some(&analysis));
        let (item_id, spec) = items(Some(&analysis))
            .iter()
            .find_map(|item| {
                let specs = planner::plan_actions(item, started);
                let id = item.get("id").and_then(Value::as_str)?.to_string();
                specs.into_iter().next().map(|spec| (id, spec))
            })
            .unwrap_or_default();
        assert!(!item_id.is_empty(), "the fixture offers actions");
        let mut ctx = context(&[]);
        ctx.analysis = Some(&analysis);
        let ask = |op: &str, target: &str| {
            build(
                &Request::Finding {
                    item_id: item_id.clone(),
                    index: 0,
                    op: op.into(),
                    target: target.into(),
                },
                &ctx,
            )
        };
        assert!(ask(&spec.op, &spec.target).is_ok());
        assert!(ask("not.this.op", &spec.target).is_err(), "a different op is refused");
        assert!(ask(&spec.op, r"C:\Windows\explorer.exe").is_err());
    }

    fn row(pid: u32, name: &str, created_ms: i64) -> vigil_sys::process::ProcessRow {
        vigil_sys::process::ProcessRow {
            pid,
            ppid: 0,
            name: name.into(),
            exe: format!(r"C:\Program Files\Contoso\{name}"),
            user: String::new(),
            cmdline: String::new(),
            cpu: 0.0,
            private_bytes: 0,
            working_set: 0,
            threads: 1,
            handles: 1,
            session: 1,
            created_ms,
            io_bps: 0.0,
            status: vigil_sys::process::ProcessStatus::Running,
            window: false,
            description: "Contoso Notes".into(),
        }
    }

    fn context(processes: &[vigil_sys::process::ProcessRow]) -> Context<'_> {
        Context {
            analysis: None,
            processes,
            cleanup: &[],
            space_files: &[],
            power_plans: &[],
            drive_media: &[],
            services: &[],
            startup: &[],
            tasks: &[],
            firewall: &[],
        }
    }

    fn spec_of(plan: Result<Plan, String>) -> ActionSpec {
        match plan {
            Ok(Plan::Run { spec, .. }) => spec,
            other => panic!("not a confirmed action: {other:?}"),
        }
    }

    #[test]
    fn group_end_task_names_the_program_and_drops_what_is_gone_or_protected() {
        let processes = [
            row(5001, "notes.exe", 1_000),
            row(5002, "notes.exe", 2_000),
            row(5003, "notes.exe", 3_000),
            row(std::process::id(), "vigil.exe", 500),
        ];
        let ctx = context(&processes);
        let request: Request = serde_json::from_value(json!({
            "kind": "process", "op": "terminate", "pid": 5001, "createdMs": 1000,
            "pids": [
                {"pid": 5001, "createdMs": 1000},
                {"pid": 5002, "createdMs": 2000},
                {"pid": 5003, "createdMs": 9999},
                {"pid": std::process::id(), "createdMs": 500},
            ],
        }))
        .expect("request");
        let spec = spec_of(build(&request, &ctx));
        assert_eq!(spec.op, "process.terminate");
        assert_eq!(spec.target, "Contoso Notes (2 processes)");
        assert_eq!(
            spec.explain,
            "Ends the 2 processes of Contoso Notes. Unsaved work in them is lost."
        );
        assert_eq!(
            spec.params["pids"],
            json!([5001, 5002]),
            "5003 started at another time: its PID was reused"
        );
        assert_eq!(spec.params["instances"][1], json!({"pid": 5002, "create_time": 2.0}));
        assert_eq!(spec.params["tree"], json!(false));
        assert!(
            spec.warning
                .starts_with("Left out because they are protected: vigil.exe"),
            "{}",
            spec.warning
        );
        assert!(spec.destructive && !spec.reversible);

        let only_protected: Request = serde_json::from_value(json!({
            "kind": "process", "op": "terminate", "pid": 1, "createdMs": 0,
            "pids": [{"pid": std::process::id(), "createdMs": 500}],
        }))
        .expect("request");
        assert!(build(&only_protected, &ctx).is_err_and(|e| e.starts_with("Every process here is protected")));
        let too_many = Request::Process {
            op: "terminate".into(),
            pid: 5001,
            created_ms: 1000,
            priority: None,
            pids: vec![
                ProcessRef {
                    pid: 5001,
                    created_ms: 1000
                };
                MAX_GROUP + 1
            ],
            cores: vec![],
        };
        assert!(build(&too_many, &ctx).is_err());
    }

    #[test]
    fn affinity_requests_are_checked_against_the_processors() {
        let processes = [row(5001, "notes.exe", 1_000)];
        let ctx = context(&processes);
        let total = vigil_sys::cpusets::logical_processors().len() as u32;
        let ask = |cores: Vec<u32>| {
            build(
                &Request::Process {
                    op: "affinity".into(),
                    pid: 5001,
                    created_ms: 1000,
                    priority: None,
                    pids: vec![],
                    cores,
                },
                &ctx,
            )
        };
        assert_eq!(ask(vec![]).err().as_deref(), Some("Choose at least one processor."));
        assert_eq!(ask(vec![total]).err().as_deref(), Some("Unknown processor."));
        let spec = spec_of(ask(vec![0, 0]));
        assert_eq!(spec.op, "process.affinity");
        assert_eq!(spec.params["cores"], json!([0]));
        assert_eq!(spec.params["create_time"], json!(1.0));
        assert!(spec.reversible);
        if total > 1 {
            assert!(spec.explain.starts_with(&format!(
                "Limits the process to 1 of the {total} logical processors (CPU 0)"
            )));
        }
        let all = spec_of(ask((0..total).rev().collect()));
        assert!(all.explain.starts_with("Lets the process use every logical processor"));
        assert_eq!(index_ranges(&[0, 1, 2, 3, 8, 10, 11]), "0-3, 8, 10-11");
    }

    #[test]
    fn run_requests_resolve_one_program_and_show_its_command_line() {
        let request: Request =
            serde_json::from_value(json!({"kind": "run", "path": "notepad", "args": "  C:\\notes.txt  "}))
                .expect("request");
        let spec = spec_of(build(&request, &context(&[])));
        assert_eq!(spec.op, "process.run");
        let path = spec.params["path"].as_str().unwrap_or("").to_string();
        assert!(path.to_lowercase().ends_with(r"\notepad.exe"), "{path}");
        assert_eq!(spec.params["args"], json!(r"C:\notes.txt"));
        assert!(
            spec.explain.contains(&format!("\"{path}\" C:\\notes.txt")),
            "{}",
            spec.explain
        );
        assert!(!spec.reversible);
        for bad in [
            json!({"kind": "run", "path": ""}),
            json!({"kind": "run", "path": r"\\203.0.113.5\share\tool.exe"}),
            json!({"kind": "run", "path": "notepad", "args": "a\nb"}),
            json!({"kind": "run", "path": "readme.txt"}),
        ] {
            let request: Request = serde_json::from_value(bad.clone()).expect("request");
            assert!(build(&request, &context(&[])).is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_or_stale_requests_are_refused() {
        let ctx = Context {
            analysis: None,
            processes: &[],
            cleanup: &[],
            space_files: &[],
            power_plans: &[],
            drive_media: &[],
            services: &[],
            startup: &[],
            tasks: &[],
            firewall: &[],
        };
        let stale = Request::Process {
            op: "terminate".into(),
            pid: 1234,
            created_ms: 1,
            priority: None,
            pids: vec![],
            cores: vec![],
        };
        assert!(build(&stale, &ctx).is_err());
        let recycle = Request::Recycle {
            paths: vec!["C:\\Users\\jdoe\\big.iso".into()],
        };
        assert!(build(&recycle, &ctx).is_err());
        let tuning = Request::Tuning {
            op: "registry.delete".into(),
            params: json!({}),
        };
        assert!(build(&tuning, &ctx).is_err());
        let console = Request::Shell {
            op: "console".into(),
            path: None,
            url: None,
            name: Some("cmd.exe".into()),
        };
        assert!(build(&console, &ctx).is_err());
    }

    fn service(name: &str, display: &str, executable: &str, dll: &str) -> vigil_sys::services::Service {
        vigil_sys::services::Service {
            name: name.into(),
            display_name: display.into(),
            description: String::new(),
            state: "running".into(),
            start_type: "auto".into(),
            pid: 4242,
            service_type: if dll.is_empty() { "own".into() } else { "share".into() },
            path: executable.into(),
            executable: executable.into(),
            dll: dll.into(),
            account: "LocalSystem".into(),
            group: String::new(),
        }
    }

    #[test]
    fn service_requests_are_checked_against_the_live_list() {
        let services = [service(
            "UpdaterSvc",
            "Example Updater",
            r"C:\Program Files\Example\updater.exe",
            "",
        )];
        let ctx = Context {
            analysis: None,
            processes: &[],
            cleanup: &[],
            space_files: &[],
            power_plans: &[],
            drive_media: &[],
            services: &services,
            startup: &[],
            tasks: &[],
            firewall: &[],
        };
        let ask = |op: &str, name: &str, start: Option<&str>| {
            build(
                &Request::Service {
                    op: op.into(),
                    name: name.into(),
                    start_type: start.map(str::to_string),
                },
                &ctx,
            )
        };
        let Ok(Plan::Run { spec, .. }) = ask("stop", "updatersvc", None) else {
            panic!("stop is offered")
        };
        assert_eq!(spec.op, "service.stop");
        assert_eq!(spec.params["name"], "UpdaterSvc", "the canonical name is used");
        let Ok(Plan::Run { spec, .. }) = ask("start_type", "UpdaterSvc", Some("disabled")) else {
            panic!("start type is offered")
        };
        assert_eq!(spec.params["start_type"], "disabled");
        assert!(spec.reversible && !spec.warning.is_empty());
        let Ok(Plan::Run { spec, .. }) = ask("restart", "UpdaterSvc", None) else {
            panic!("restart")
        };
        assert!(!spec.reversible);
        assert!(ask("start", "GhostSvc", None).is_err(), "unknown services are refused");
        assert!(
            ask("start_type", "UpdaterSvc", Some("boot")).is_err(),
            "only the four startup types"
        );
        assert!(ask("start_type", "UpdaterSvc", None).is_err());
        assert!(ask("delete", "UpdaterSvc", None).is_err(), "only the page's operations");
        let parsed: Request = serde_json::from_value(
            json!({"kind": "service", "op": "start_type", "name": "UpdaterSvc", "startType": "demand"}),
        )
        .expect("request");
        assert!(matches!(parsed, Request::Service { ref start_type, .. } if start_type.as_deref() == Some("demand")));
    }

    fn startup_entry(id: &str, kind: &str, scope: &str) -> vigil_sys::startup::StartupEntry {
        let folder = kind == "folder";
        vigil_sys::startup::StartupEntry {
            id: id.into(),
            name: "Updater".into(),
            command: r#""C:\Program Files\Example\updater.exe" --tray"#.into(),
            executable: r"C:\Program Files\Example\updater.exe".into(),
            location: if folder {
                r"C:\Users\jdoe\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup".into()
            } else {
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".into()
            },
            kind: kind.into(),
            scope: scope.into(),
            enabled: true,
            disabled_at_ms: None,
            can_toggle: kind != "run_once",
            approved_key: String::new(),
            value: if folder { "Updater.lnk".into() } else { "Updater".into() },
            file: if folder {
                r"C:\Users\jdoe\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Updater.lnk".into()
            } else {
                String::new()
            },
            publisher: "Example Corp".into(),
            description: "Example Updater".into(),
            exists: true,
            host: false,
            own: false,
        }
    }

    #[test]
    fn startup_requests_are_checked_against_the_live_list() {
        let mut missing = startup_entry("reg:machine", "run", "machine");
        missing.exists = false;
        let mut policy = startup_entry("reg:policy", "policy", "user");
        policy.can_toggle = false;
        policy.location = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run".into();
        let entries = [
            startup_entry("reg:user", "run", "user"),
            startup_entry("file:user", "folder", "user"),
            startup_entry("reg:once", "run_once", "user"),
            missing,
            policy,
        ];
        let ctx = Context {
            analysis: None,
            processes: &[],
            cleanup: &[],
            space_files: &[],
            power_plans: &[],
            drive_media: &[],
            services: &[],
            startup: &entries,
            tasks: &[],
            firewall: &[],
        };
        let ask = |op: &str, id: &str| {
            build(
                &Request::Startup {
                    op: op.into(),
                    id: id.into(),
                },
                &ctx,
            )
        };
        let Ok(Plan::Run { spec, .. }) = ask("disable", "reg:user") else {
            panic!("disable is offered")
        };
        assert_eq!(spec.op, "startup.disable");
        assert_eq!(
            spec.params["key"],
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        );
        assert_eq!(spec.params["value"], "Updater");
        assert!(
            spec.reversible && !spec.admin,
            "the user's own entry needs no administrator"
        );
        assert!(spec.label.contains("Example Updater"));
        let Ok(Plan::Run { spec, .. }) = ask("enable", "file:user") else {
            panic!("enable is offered")
        };
        assert_eq!(spec.op, "startup.enable");
        assert!(spec.params["file"].as_str().is_some_and(|f| f.ends_with("Updater.lnk")));
        assert!(spec.params.get("key").is_none());
        let Ok(Plan::Run { spec, .. }) = ask("enable", "reg:machine") else {
            panic!("machine entry")
        };
        assert!(spec.admin, "an entry for every user needs administrator rights");
        assert!(!spec.warning.is_empty(), "a missing program is pointed out");
        assert!(ask("disable", "reg:once").is_err(), "RunOnce has no switch");
        assert!(ask("disable", "reg:ghost").is_err(), "unknown ids are refused");
        assert!(ask("delete", "reg:user").is_err(), "only enable and disable");
        // A Run key set by policy has no switch; its value can be deleted (and put back).
        let refused = ask("disable", "reg:policy").err().unwrap_or_default();
        assert!(refused.contains("policy"), "{refused}");
        let Ok(Plan::Run { spec, .. }) = ask("delete", "reg:policy") else {
            panic!("delete is offered for policy entries")
        };
        assert_eq!(spec.op, "registry.delete");
        assert_eq!(
            spec.params["key"],
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        );
        assert!(spec.destructive && spec.reversible && spec.admin);
        let parsed: Request =
            serde_json::from_value(json!({"kind": "startup", "op": "enable", "id": "reg:user"})).expect("request");
        assert!(matches!(parsed, Request::Startup { ref op, .. } if op == "enable"));
    }

    fn task(path: &str, enabled: bool) -> vigil_sys::tasks::ScheduledTask {
        let (folder, name) = path.rsplit_once('\\').expect("a library path");
        vigil_sys::tasks::ScheduledTask {
            path: path.into(),
            name: name.into(),
            folder: if folder.is_empty() { "\\".into() } else { folder.into() },
            enabled,
            state: if enabled { "ready" } else { "disabled" }.into(),
            account: r"DESKTOP-ABC123\jdoe".into(),
            account_kind: "user".into(),
            program: r"C:\Program Files\Vendor\updater.exe".into(),
            program_exists: true,
            microsoft: path.to_lowercase().starts_with("\\microsoft\\"),
            ..Default::default()
        }
    }

    #[test]
    fn task_requests_are_checked_against_the_live_list() {
        let mut risky = task(r"\Vendor\Helper", false);
        risky.elevated = true;
        risky.user_writable = true;
        let mut password = task(r"\Vendor\Nightly Backup", true);
        password.logon_type = "password".into();
        let tasks = [
            task(r"\Vendor\Updater Task", true),
            task(r"\Root task", false),
            task(r"\Microsoft\Windows\Defrag\ScheduledDefrag", true),
            risky,
            password,
        ];
        let ctx = Context {
            analysis: None,
            processes: &[],
            cleanup: &[],
            space_files: &[],
            power_plans: &[],
            drive_media: &[],
            services: &[],
            startup: &[],
            tasks: &tasks,
            firewall: &[],
        };
        let ask = |op: &str, path: &str| {
            build(
                &Request::Task {
                    op: op.into(),
                    path: path.into(),
                },
                &ctx,
            )
        };
        let disable = spec_of(ask("disable", r"\vendor\updater task"));
        assert_eq!(disable.op, "task.disable");
        assert_eq!(disable.params, json!({"path": r"\Vendor", "name": "Updater Task"}));
        assert!(disable.reversible && disable.admin && !disable.destructive);
        let run = spec_of(ask("run", r"\Vendor\Updater Task"));
        assert_eq!(run.op, "task.run");
        assert!(!run.reversible, "running a task cannot be undone");
        assert!(run.explain.contains(r"DESKTOP-ABC123\jdoe"), "{}", run.explain);
        let delete = spec_of(ask("delete", r"\Vendor\Updater Task"));
        assert!(delete.destructive && delete.reversible);
        assert!(delete.explain.contains("XML"), "{}", delete.explain);
        let stored = spec_of(ask("delete", r"\Vendor\Nightly Backup"));
        assert!(
            stored.destructive && !stored.reversible,
            "a stored password cannot be recreated"
        );
        assert!(stored.explain.contains("password"), "{}", stored.explain);
        let enable = spec_of(ask("enable", r"\Root task"));
        assert_eq!(enable.params, json!({"path": "\\", "name": "Root task"}));
        assert!(enable.warning.is_empty());
        assert!(
            !spec_of(ask("enable", r"\Vendor\Helper")).warning.is_empty(),
            "full rights from a writable folder"
        );
        assert!(ask("enable", r"\Vendor\Updater Task").is_err(), "already enabled");
        assert!(ask("disable", r"\Root task").is_err(), "already disabled");
        assert!(ask("run", r"\Root task").is_err(), "a disabled task is not run");
        for op in ["disable", "run", "delete"] {
            assert!(
                ask(op, r"\Microsoft\Windows\Defrag\ScheduledDefrag").is_err(),
                "Windows tasks stay as they are"
            );
        }
        assert!(ask("disable", r"\Vendor\Ghost").is_err(), "unknown tasks are refused");
        assert!(
            ask("export", r"\Vendor\Updater Task").is_err(),
            "unknown operations are refused"
        );
        let parsed: Request =
            serde_json::from_value(json!({"kind": "task", "op": "run", "path": r"\Vendor\Updater Task"}))
                .expect("request");
        assert!(matches!(parsed, Request::Task { ref op, .. } if op == "run"));
    }

    #[test]
    fn windows_components_and_essential_services_are_locked() {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let hosted = service(
            "Dnscache",
            "DNS Client",
            &format!(r"{windir}\system32\svchost.exe"),
            &format!(r"{windir}\System32\dnsrslvr.dll"),
        );
        assert!(protected_service(&hosted));
        let foreign_dll = service(
            "OddSvc",
            "Odd",
            &format!(r"{windir}\system32\svchost.exe"),
            r"C:\ProgramData\odd\odd.dll",
        );
        assert!(
            !protected_service(&foreign_dll),
            "a third-party DLL in svchost is not a Windows component"
        );
        assert!(protected_service(&service(
            "WinDefend",
            "Microsoft Defender",
            r"C:\ProgramData\x\MsMpEng.exe",
            ""
        )));
        assert!(!protected_service(&service(
            "UpdaterSvc",
            "Example Updater",
            r"C:\Program Files\Example\updater.exe",
            ""
        )));
    }

    #[test]
    fn autostart_request_is_rebuilt_by_rust() {
        let ctx = context(&[]);
        let ask = |params: Value| {
            build(
                &Request::Tuning {
                    op: "vigil.autostart".into(),
                    params,
                },
                &ctx,
            )
        };
        let on = spec_of(ask(json!({"on": true, "command": "calc.exe"})));
        assert_eq!(on.params, json!({"on": true}), "the page cannot choose the command");
        assert!(!on.admin && on.reversible && !on.destructive);
        assert!(on.target.ends_with(r"CurrentVersion\Run\Vigil"));
        assert!(on.explain.contains("--tray --no-elevate"));
        assert_eq!(spec_of(ask(json!({"on": false}))).params, json!({"on": false}));
        assert!(ask(json!({})).is_err());
    }
}
