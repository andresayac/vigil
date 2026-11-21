//! Which actions make sense for each finding.
//!
//! The planner only proposes; nothing here changes the system. Trusted items (Microsoft components
//! verified automatically) never get actions that change anything. It works on the report JSON of
//! an item (the snake_case keys every Vigil version writes), so it does not depend on how the scan
//! crate models items internally.

use serde_json::{Value, json};
use vigil_actions::{ActionSpec, approved_location};
use vigil_i18n::tr;

/// An ActionSpec with the defaults: group "inspect", reversible, needs administrator rights.
pub fn spec(op: &str, label: impl Into<String>, target: impl Into<String>, explain: impl Into<String>) -> ActionSpec {
    ActionSpec {
        op: op.to_string(),
        label: label.into(),
        target: target.into(),
        explain: explain.into(),
        params: json!({}),
        group: "inspect".to_string(),
        destructive: false,
        reversible: true,
        admin: true,
        warning: String::new(),
        steps: Vec::new(),
    }
}

/// Small builder helpers so the tables below read like a list of facts.
pub trait SpecExt {
    fn params(self, params: Value) -> Self;
    fn group(self, group: &str) -> Self;
    fn destructive(self) -> Self;
    fn irreversible(self) -> Self;
    fn no_admin(self) -> Self;
    fn warning(self, text: &str) -> Self;
}

impl SpecExt for ActionSpec {
    fn params(mut self, params: Value) -> Self {
        self.params = params;
        self
    }
    fn group(mut self, group: &str) -> Self {
        self.group = group.to_string();
        self
    }
    fn destructive(mut self) -> Self {
        self.destructive = true;
        self
    }
    fn irreversible(mut self) -> Self {
        self.reversible = false;
        self
    }
    fn no_admin(mut self) -> Self {
        self.admin = false;
        self
    }
    fn warning(mut self, text: &str) -> Self {
        self.warning = text.to_string();
        self
    }
}

fn q(text: &str) -> String {
    format!("\"{text}\"")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn detail(role: &Value) -> &Value {
    role.get("detail").unwrap_or(&Value::Null)
}

fn file_exists(item: &Value) -> bool {
    item.get("file").and_then(|f| f.get("exists")).and_then(Value::as_bool) == Some(true)
}

fn trusted(item: &Value) -> bool {
    item.get("trusted").and_then(Value::as_bool).unwrap_or(false)
}

fn facts(item: &Value) -> &Value {
    item.get("facts").unwrap_or(&Value::Null)
}

fn process_spec(item: &Value, role: &Value, scan_started: Option<&str>) -> ActionSpec {
    let d = detail(role);
    let names: Vec<&str> = list(d, "names").iter().filter_map(Value::as_str).collect();
    let pids = list(d, "pids");
    let count = d
        .get("count")
        .and_then(Value::as_u64)
        .filter(|c| *c > 0)
        .unwrap_or(pids.len() as u64);
    let target = if names.is_empty() {
        text(item, "title").to_string()
    } else {
        names.join(", ")
    };
    spec(
        "process.terminate",
        if count == 1 {
            tr!("End process")
        } else {
            tr!("End processes")
        },
        target,
        tr!("Ends the running instances right now. It may start again if something launches it at startup."),
    )
    .params(json!({"path": item.get("path"), "pids": pids, "names": names, "scan_started": scan_started}))
    .group("contain")
    .destructive()
    .irreversible()
}

fn service_specs(role: &Value, driver: bool) -> Vec<ActionSpec> {
    let name = text(detail(role), "name");
    if name.is_empty() {
        return Vec::new();
    }
    if driver {
        return vec![
            spec(
                "driver.disable",
                tr!("Disable driver {0}", q(name)),
                tr!("driver {0}", name),
                tr!("Sets the driver to disabled; it stops loading at the next restart."),
            )
            .params(json!({"name": name}))
            .group("disable")
            .warning(&tr!(
                "Disabling a driver that hardware or Windows needs can stop the computer from starting. Create a \
                 restore point first."
            )),
        ];
    }
    vec![
        spec(
            "service.stop",
            tr!("Stop service {0}", q(name)),
            tr!("service {0}", name),
            tr!("Stops the service now; it will start again at the next restart unless you disable it."),
        )
        .params(json!({"name": name}))
        .group("contain"),
        spec(
            "service.disable",
            tr!("Disable service {0}", q(name)),
            tr!("service {0}", name),
            tr!("Stops the service and sets it to disabled so it no longer starts."),
        )
        .params(json!({"name": name, "stop": true}))
        .group("disable"),
        spec(
            "service.delete",
            tr!("Delete service {0}", q(name)),
            tr!("service {0}", name),
            tr!("Removes the service from Windows. Its registry key is exported first so it can be restored."),
        )
        .params(json!({"name": name}))
        .group("remove")
        .destructive(),
    ]
}

pub fn task_specs(role: &Value) -> Vec<ActionSpec> {
    let d = detail(role);
    let path = match text(d, "task_path") {
        "" => "\\",
        p => p,
    };
    let name = text(d, "task_name");
    if name.is_empty() || path.to_lowercase().starts_with("\\microsoft\\") {
        return Vec::new();
    }
    let full = if path.ends_with('\\') {
        format!("{path}{name}")
    } else {
        format!("{path}\\{name}")
    };
    vec![
        spec(
            "task.disable",
            tr!("Disable task {0}", q(&full)),
            tr!("scheduled task {0}", full),
            tr!("Turns the scheduled task off; it stays in Task Scheduler and can be enabled again."),
        )
        .params(json!({"path": path, "name": name}))
        .group("disable"),
        spec(
            "task.delete",
            tr!("Delete task {0}", q(&full)),
            tr!("scheduled task {0}", full),
            tr!("Deletes the scheduled task. Its definition is saved first so it can be recreated."),
        )
        .params(json!({"path": path, "name": name}))
        .group("remove")
        .destructive(),
    ]
}

pub fn startup_specs(role: &Value) -> Vec<ActionSpec> {
    let d = detail(role);
    let source = text(d, "source");
    let key = text(d, "reg_key");
    let value = text(d, "value");
    let file = text(d, "file");
    if source == "startup_folder" && !file.is_empty() {
        let base = basename(file);
        return vec![
            spec(
                "startup.disable",
                tr!("Disable startup entry {0}", q(base)),
                tr!("Startup folder: {0}", base),
                tr!("Turns the entry off with the same switch as Task Manager; the file stays where it is."),
            )
            .params(json!({"file": file}))
            .group("disable"),
            spec(
                "file.quarantine",
                tr!("Quarantine {0}", q(base)),
                file,
                tr!("Moves the file out of the Startup folder into quarantine."),
            )
            .params(json!({"path": file, "reason": "startup folder entry", "kill": false}))
            .group("remove")
            .destructive(),
        ];
    }
    if source == "run" && !key.is_empty() && !value.is_empty() {
        let mut specs = Vec::new();
        if matches!(approved_location(key), Ok(Some(_))) {
            specs.push(
                spec(
                    "startup.disable",
                    tr!("Disable startup entry {0}", q(value)),
                    format!("{key}\\{value}"),
                    tr!("Turns the entry off with the same switch as Task Manager."),
                )
                .params(json!({"key": key, "value": value}))
                .group("disable"),
            );
        }
        specs.push(
            spec(
                "registry.delete",
                tr!("Delete startup entry {0}", q(value)),
                format!("{key}\\{value}"),
                tr!("Deletes the registry value. Its data is saved so it can be restored."),
            )
            .params(json!({"key": key, "value": value}))
            .group("remove")
            .destructive(),
        );
        return specs;
    }
    if source == "ifeo_debugger" && !key.is_empty() {
        let value_name = if key.to_lowercase().contains("silentprocessexit") {
            "MonitorProcess"
        } else {
            "Debugger"
        };
        return vec![
            spec(
                "registry.delete",
                tr!("Remove the hook on {0}", q(value)),
                format!("{key}\\{value_name}"),
                tr!(
                    "Deletes the {0} value so \"{1}\" opens normally again.",
                    value_name,
                    value
                ),
            )
            .params(json!({"key": key, "value": value_name}))
            .group("remove")
            .destructive(),
        ];
    }
    if source == "winlogon" && !key.is_empty() && !value.is_empty() {
        return vec![
            spec(
                "winlogon.restore",
                tr!("Restore Winlogon {0}", value),
                format!("{key}\\{value}"),
                tr!("Puts the Windows default back (or removes the per-user override). The current value is saved."),
            )
            .params(json!({"key": key, "value": value}))
            .group("remove")
            .destructive()
            .warning(&tr!(
                "A wrong Winlogon value can prevent signing in. The default is restored, which is what a clean \
                 Windows uses."
            )),
        ];
    }
    if source == "appinit_dlls" && !key.is_empty() {
        return vec![
            spec(
                "appinit.off",
                tr!("Turn off AppInit DLL loading"),
                format!("{key}\\LoadAppInit_DLLs"),
                tr!("Stops Windows from injecting AppInit DLLs into programs."),
            )
            .params(json!({"key": key}))
            .group("disable"),
        ];
    }
    if matches!(source, "logon_script" | "legacy_load") && !key.is_empty() && !value.is_empty() {
        return vec![
            spec(
                "registry.delete",
                tr!("Delete {0}", value),
                format!("{key}\\{value}"),
                tr!("Deletes the value that runs at sign-in. Its data is saved so it can be restored."),
            )
            .params(json!({"key": key, "value": value}))
            .group("remove")
            .destructive(),
        ];
    }
    Vec::new()
}

fn wmi_specs(role: &Value) -> Vec<ActionSpec> {
    let name = text(detail(role), "name");
    if name.is_empty() {
        return Vec::new();
    }
    vec![
        spec(
            "wmi.remove",
            tr!("Remove WMI subscription {0}", q(name)),
            tr!("WMI subscription {0}", name),
            tr!("Deletes the permanent WMI subscription (consumer, binding and filter)."),
        )
        .params(json!({"name": name}))
        .group("remove")
        .destructive()
        .irreversible(),
    ]
}

fn inspect_file_specs(item: &Value) -> Vec<ActionSpec> {
    let path = text(item, "path");
    if path.is_empty() {
        return Vec::new();
    }
    let mut specs = vec![
        spec(
            "shell.location",
            tr!("Open file location"),
            path,
            tr!("Opens the folder with the file selected."),
        )
        .params(json!({"path": path}))
        .no_admin(),
    ];
    if file_exists(item) {
        specs.extend([
            spec(
                "shell.properties",
                tr!("File properties"),
                path,
                tr!("Opens the Windows Properties dialog."),
            )
            .params(json!({"path": path}))
            .no_admin(),
            spec(
                "signature.verify",
                tr!("Verify signature now"),
                path,
                tr!("Checks the digital signature again, live."),
            )
            .params(json!({"path": path}))
            .no_admin(),
            spec(
                "defender.scan_file",
                tr!("Scan with Microsoft Defender"),
                path,
                tr!("Runs a Defender scan on this file; if it finds a threat, Defender handles it."),
            )
            .params(json!({"path": path}))
            .no_admin()
            .irreversible(),
        ]);
    }
    let sha = text(item, "sha256");
    if !sha.is_empty() {
        specs.push(
            spec(
                "shell.url",
                tr!("Look up on VirusTotal"),
                sha,
                tr!("Opens VirusTotal in your browser with the file hash (the file is not uploaded)."),
            )
            .params(json!({"url": format!("https://www.virustotal.com/gui/file/{sha}")}))
            .no_admin(),
        );
    }
    specs
}

fn role_specs(item: &Value, scan_started: Option<&str>) -> Vec<ActionSpec> {
    let mut specs = Vec::new();
    for role in list(item, "roles") {
        match text(role, "kind") {
            "process" if !list(detail(role), "pids").is_empty() || !text(item, "path").is_empty() => {
                specs.push(process_spec(item, role, scan_started))
            }
            "service" => specs.extend(service_specs(role, false)),
            "driver" => specs.extend(service_specs(role, true)),
            "task" => specs.extend(task_specs(role)),
            "startup" => specs.extend(startup_specs(role)),
            "wmi" => specs.extend(wmi_specs(role)),
            _ => {}
        }
    }
    specs
}

/// "Remove completely": stop it, turn off every way it starts, quarantine the file.
fn removal(item: &Value, specs: &[ActionSpec]) -> Option<ActionSpec> {
    let mut steps: Vec<ActionSpec> = specs.iter().filter(|s| s.op == "process.terminate").cloned().collect();
    // Targets in first-seen order.
    let mut targets: Vec<&str> = Vec::new();
    for s in specs {
        if !targets.contains(&s.target.as_str()) {
            targets.push(&s.target);
        }
    }
    const PREFERENCE: [&str; 8] = [
        "service.disable",
        "driver.disable",
        "task.disable",
        "startup.disable",
        "appinit.off",
        "winlogon.restore",
        "registry.delete",
        "wmi.remove",
    ];
    for target in targets {
        // The last spec with each op wins.
        let options: Vec<&ActionSpec> = specs.iter().filter(|s| s.target == target).collect();
        let chosen = PREFERENCE
            .iter()
            .find_map(|op| options.iter().rev().find(|s| s.op == *op));
        if let Some(chosen) = chosen {
            steps.push((*chosen).clone());
        }
    }
    let path = text(item, "path");
    let title = text(item, "title");
    if text(item, "kind") == "executable" && !path.is_empty() && file_exists(item) {
        steps.push(
            spec(
                "file.quarantine",
                tr!("Quarantine {0}", q(title)),
                path,
                tr!("Moves the file into quarantine."),
            )
            .params(json!({"path": path, "reason": title, "kill": true}))
            .group("remove")
            .destructive(),
        );
    }
    if steps.len() < 2 {
        return None;
    }
    let reversible = steps
        .iter()
        .filter(|s| s.op != "process.terminate")
        .all(|s| s.reversible);
    let mut plan = spec(
        "plan.remove",
        tr!("Remove completely"),
        title,
        if reversible {
            tr!(
                "Ends it, turns off every way it starts and moves its file to quarantine. Every step except ending the process can be undone from History."
            )
        } else {
            tr!("Ends it, turns off every way it starts and moves its file to quarantine. Some steps cannot be undone.")
        },
    )
    .group("remove")
    .destructive();
    plan.reversible = reversible;
    plan.steps = steps;
    Some(plan)
}

fn file_change_specs(item: &Value) -> Vec<ActionSpec> {
    let path = text(item, "path");
    if text(item, "kind") != "executable" || path.is_empty() || !file_exists(item) {
        return Vec::new();
    }
    vec![
        spec(
            "file.quarantine",
            tr!("Quarantine file"),
            path,
            tr!("Ends any process running it, then moves the file into quarantine (it can be restored)."),
        )
        .params(json!({"path": path, "reason": text(item, "title"), "kill": true}))
        .group("remove")
        .destructive(),
        spec(
            "firewall.block",
            tr!("Block network access"),
            path,
            tr!("Adds Windows Firewall rules that block all its incoming and outgoing traffic."),
        )
        .params(json!({"path": path}))
        .group("contain"),
    ]
}

fn program_specs(item: &Value) -> Vec<ActionSpec> {
    let f = facts(item);
    let title = text(item, "title");
    let key = text(f, "registry_key");
    let folder = text(f, "folder");
    let mut specs = Vec::new();
    if !key.is_empty()
        && f.get("uninstall")
            .is_some_and(|u| !u.is_null() && u != "" && u != false)
    {
        specs.push(
            spec(
                "program.uninstall",
                tr!("Uninstall {0}", q(title)),
                title,
                tr!("Starts the program's own uninstaller; follow its window to finish."),
            )
            .params(json!({"registry_key": key, "name": title}))
            .group("remove")
            .destructive()
            .irreversible(),
        );
    }
    if !folder.is_empty() {
        specs.push(
            spec(
                "shell.folder",
                tr!("Open install folder"),
                folder,
                tr!("Opens the folder."),
            )
            .params(json!({"path": folder}))
            .no_admin(),
        );
    }
    if !key.is_empty() {
        specs.push(
            spec(
                "shell.regedit",
                tr!("Open in Registry Editor"),
                key,
                tr!("Opens Registry Editor at the program's uninstall entry."),
            )
            .params(json!({"key": key}))
            .no_admin(),
        );
    }
    if specs.is_empty() || key.is_empty() {
        specs.push(
            spec(
                "shell.url",
                tr!("Open Installed apps"),
                tr!("Settings"),
                tr!("Opens Settings → Apps → Installed apps."),
            )
            .params(json!({"url": "ms-settings:appsfeatures"}))
            .no_admin(),
        );
    }
    specs
}

fn extension_specs(item: &Value) -> Vec<ActionSpec> {
    let f = facts(item);
    let browser = text(f, "browser");
    let folder = text(f, "folder");
    let mut specs = vec![
        spec(
            "shell.browser",
            tr!("Open {0} extensions page", browser),
            browser,
            tr!(
                "Opens the browser's extensions page so you can remove it there (browsers protect their extension \
             settings, so removal happens in the browser)."
            ),
        )
        .params(json!({"browser": browser}))
        .no_admin(),
    ];
    if !folder.is_empty() {
        specs.push(
            spec(
                "shell.folder",
                tr!("Open extension folder"),
                folder,
                tr!("Opens the folder."),
            )
            .params(json!({"path": folder}))
            .no_admin(),
        );
    }
    specs
}

fn rdp_off() -> ActionSpec {
    spec(
        "rdp.disable",
        tr!("Turn Remote Desktop off"),
        tr!("Remote Desktop"),
        tr!("Stops the computer from accepting Remote Desktop connections."),
    )
    .group("fix")
}

fn proxy_off() -> ActionSpec {
    spec(
        "proxy.disable",
        tr!("Turn the proxy off"),
        tr!("Internet settings"),
        tr!("Turns off the proxy server and proxy script for your account."),
    )
    .group("fix")
}

fn config_specs(item: &Value) -> Vec<ActionSpec> {
    let f = facts(item);
    let topic = text(f, "topic");
    let mut specs = match topic {
        "firewall_disabled" => vec![
            spec(
                "firewall.enable",
                tr!("Turn the firewall on"),
                tr!("Windows Firewall"),
                tr!("Turns Windows Firewall on for the profiles where it is off."),
            )
            .group("fix"),
        ],
        "defender_off" => vec![
            spec(
                "defender.realtime_on",
                tr!("Turn real-time protection on"),
                tr!("Microsoft Defender"),
                tr!("Turns real-time protection back on."),
            )
            .group("fix")
            .irreversible(),
        ],
        "outdated_signatures" => vec![
            spec(
                "defender.update",
                tr!("Update security intelligence"),
                tr!("Microsoft Defender"),
                tr!("Downloads the latest Defender definitions."),
            )
            .group("fix")
            .irreversible(),
        ],
        "rdp_enabled" | "rdp_without_nla" => vec![rdp_off()],
        "proxy_enabled" | "proxy_auto_config" => vec![proxy_off()],
        "guest_enabled" => vec![
            spec(
                "account.disable",
                tr!("Disable the Guest account"),
                tr!("Guest account"),
                tr!("Disables the built-in Guest account."),
            )
            .params(json!({"guest": true}))
            .group("fix"),
        ],
        "hosts" => vec![
            spec(
                "shell.hosts",
                tr!("Edit the hosts file"),
                tr!("hosts file"),
                tr!("Opens the hosts file in Notepad (as administrator)."),
            )
            .group("fix"),
        ],
        "tamper_protection_off" => vec![
            spec(
                "shell.url",
                tr!("Open Virus & threat protection"),
                tr!("Windows Security"),
                tr!("Tamper Protection can only be turned on from Windows Security."),
            )
            .params(json!({"url": "windowsdefender://threatsettings"}))
            .no_admin(),
        ],
        "defender_layers_disabled" => vec![
            spec(
                "shell.url",
                tr!("Open Virus & threat protection"),
                tr!("Windows Security"),
                tr!("Opens the Defender settings."),
            )
            .params(json!({"url": "windowsdefender://threatsettings"}))
            .no_admin(),
        ],
        _ => Vec::new(),
    };
    if topic == "defender_exclusions" {
        for (kind, key) in [("path", "paths"), ("process", "processes"), ("extension", "extensions")] {
            for value in list(f, key).iter().take(20) {
                let value = match value {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                specs.push(
                    spec(
                        "defender.remove_exclusion",
                        tr!("Remove exclusion {0}", q(&value)),
                        &value,
                        tr!("Lets Defender scan it again."),
                    )
                    .params(json!({"kind": kind, "value": value}))
                    .group("fix"),
                );
            }
        }
    }
    if topic == "additional_accounts" {
        for account in list(f, "accounts").iter().take(10) {
            let name = match account {
                Value::Object(_) => text(account, "name").to_string(),
                Value::String(s) => s.clone(),
                _ => String::new(),
            };
            if !name.is_empty() {
                specs.push(
                    spec(
                        "account.disable",
                        tr!("Disable account {0}", q(&name)),
                        tr!("local account {0}", name),
                        tr!("Disables the local account; it can be enabled again."),
                    )
                    .params(json!({"name": name}))
                    .group("fix")
                    .destructive(),
                );
            }
        }
    }
    specs
}

fn event_specs(item: &Value) -> Vec<ActionSpec> {
    match text(facts(item), "category") {
        "antivirus_detection" => vec![
            spec(
                "defender.full_scan",
                tr!("Run a full Defender scan"),
                tr!("Microsoft Defender"),
                tr!("Starts a full scan in the background (it can take an hour)."),
            )
            .group("fix")
            .irreversible(),
            spec(
                "shell.url",
                tr!("Open Protection history"),
                tr!("Windows Security"),
                tr!("Opens Windows Security at the list of detected threats."),
            )
            .params(json!({"url": "windowsdefender://history"}))
            .no_admin(),
        ],
        "remote_desktop"
        | "remote_logon"
        | "failed_logons"
        | "remote_session"
        | "remote_session_internet"
        | "remote_logon_internet" => vec![rdp_off()],
        _ => Vec::new(),
    }
}

fn registry_inspect(item: &Value) -> Vec<ActionSpec> {
    let mut specs = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for role in list(item, "roles") {
        let kind = text(role, "kind");
        let key = if kind == "startup" {
            text(detail(role), "reg_key")
        } else {
            ""
        };
        if !key.is_empty() && !seen.iter().any(|s| s == key) {
            seen.push(key.to_string());
            specs.push(
                spec(
                    "shell.regedit",
                    tr!("Open in Registry Editor"),
                    key,
                    tr!("Opens Registry Editor at this key."),
                )
                .params(json!({"key": key}))
                .no_admin(),
            );
        }
        if kind == "task" && !seen.iter().any(|s| s == "taskschd") {
            seen.push("taskschd".into());
            specs.push(
                spec(
                    "shell.console",
                    tr!("Open Task Scheduler"),
                    tr!("Task Scheduler"),
                    tr!("Opens Task Scheduler."),
                )
                .params(json!({"name": "taskschd.msc"}))
                .no_admin(),
            );
        }
        if matches!(kind, "service" | "driver") && !seen.iter().any(|s| s == "services") {
            seen.push("services".into());
            specs.push(
                spec(
                    "shell.console",
                    tr!("Open Services"),
                    tr!("Services"),
                    tr!("Opens the Services console."),
                )
                .params(json!({"name": "services.msc"}))
                .no_admin(),
            );
        }
    }
    specs.truncate(4);
    specs
}

/// Every action available for an item, most decisive first (composite removal, then the rest).
pub fn plan_actions(item: &Value, scan_started: Option<&str>) -> Vec<ActionSpec> {
    match text(item, "kind") {
        "program" => return if trusted(item) { Vec::new() } else { program_specs(item) },
        "extension" => return extension_specs(item),
        "config" => return config_specs(item),
        "event" => return event_specs(item),
        "group" => return Vec::new(),
        _ => {}
    }
    let mut inspect = inspect_file_specs(item);
    inspect.extend(registry_inspect(item));
    if trusted(item) {
        return inspect;
    }
    let mut changes = role_specs(item, scan_started);
    changes.extend(file_change_specs(item));
    let mut out: Vec<ActionSpec> = removal(item, &changes).into_iter().collect();
    out.extend(changes);
    out.extend(inspect);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(name);
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }

    /// The recorded plans for every item of the infected test computer.
    #[test]
    fn plans_match_the_reference() {
        let analysis = load("fixture-analysis.json");
        let golden = load("planner.json");
        let started = golden.get("scan_started").and_then(Value::as_str);
        let items = analysis
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(items.len(), 23);
        let mut compared = 0;
        for item in &items {
            let id = text(item, "id");
            let ours = serde_json::to_value(plan_actions(item, started)).unwrap_or(Value::Null);
            let theirs = golden
                .get("plans")
                .and_then(|p| p.get(id))
                .cloned()
                .unwrap_or(Value::Null);
            assert_eq!(ours, theirs, "plan for item {id}");
            compared += theirs.as_array().map_or(0, Vec::len);
        }
        assert_eq!(compared, 61);
    }
}
