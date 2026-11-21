//! Turns what the UI asks for into an action Rust trusts.
//!
//! The web view sends small requests ("end process 1234 started at T", "run action 2 of finding
//! B1"). Nothing in them is used as is: Rust rebuilds the ActionSpec from its own state (the report
//! it loaded, the live process list, the targets it measured), validates every value, and writes
//! the texts the confirmation shows. A compromised page can at most ask for an action the user
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
    #[serde(rename_all = "camelCase")]
    Finding {
        item_id: String,
        index: usize,
    },
    #[serde(rename_all = "camelCase")]
    Process {
        op: String,
        pid: u32,
        created_ms: i64,
        priority: Option<String>,
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
}

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
        Request::Finding { item_id, index } => {
            let item = find_item(ctx.analysis, item_id).ok_or(tr!("The finding is no longer in the report."))?;
            let specs = planner::plan_actions(item, scan_started(ctx.analysis));
            let spec = specs
                .into_iter()
                .nth(*index)
                .ok_or(tr!("That action is no longer offered for this finding."))?;
            Ok(classify(spec, Some(item_id.clone())))
        }
        Request::Role { op, item_id, role } => role_plan(op, item_id, *role, ctx),
        Request::Process {
            op,
            pid,
            created_ms,
            priority,
        } => process_plan(op, *pid, *created_ms, priority.as_deref(), ctx),
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
        Request::Shell { op, path, url, name } => shell_plan(op, path.as_deref(), url.as_deref(), name.as_deref()),
        Request::Service { op, name, start_type } => service_plan(op, name, start_type.as_deref(), ctx),
    }
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
    let row = ctx
        .processes
        .iter()
        .find(|r| r.pid == pid && (created_ms == 0 || r.created_ms == created_ms))
        .ok_or(tr!("The process has exited."))?;
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
        "system.restore_point" => spec(
            "system.restore_point",
            tr!("Create a restore point"),
            "Windows",
            tr!("Creates a System Restore point you can return to."),
        )
        .group("fix")
        .irreversible(),
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
        "url" => {
            let url = url
                .filter(|u| allowed_url(u))
                .ok_or(tr!("This address is not opened from Vigil."))?;
            spec("shell.url", "Open", url, "").params(json!({"url": url}))
        }
        "console" => {
            let name = name.unwrap_or("");
            if !matches!(name, "taskschd.msc" | "services.msc" | "eventvwr.msc") {
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
        let r: Request = serde_json::from_value(json!({"kind": "finding", "itemId": "B1", "index": 2}))
            .unwrap_or(Request::Cleanup { keys: vec![] });
        assert!(matches!(r, Request::Finding { index: 2, .. }));
        assert!(serde_json::from_value::<Request>(json!({"kind": "exec", "cmd": "calc"})).is_err());
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
        };
        let stale = Request::Process {
            op: "terminate".into(),
            pid: 1234,
            created_ms: 1,
            priority: None,
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
}
