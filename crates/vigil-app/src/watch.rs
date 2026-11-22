//! Background watch: Vigil keeps an eye on the places malware uses to stay on a computer.
//!
//! Once a minute a background thread reads a small fingerprint of the computer and compares it
//! with the last one:
//!
//! - startup entries (the Run keys, the Run keys set by policy and the Startup folders, as the
//!   Startup apps page lists them);
//! - services: new ones, a start type changed to automatic, a changed program or svchost DLL. The
//!   per-sign-in copies of per-user services (`CDPUserSvc_4a5b2`) are left out: their names change
//!   at every sign-in, and their template is watched;
//! - scheduled tasks (only when elevated, because standard users cannot read `System32\Tasks`):
//!   new tasks outside `\Microsoft\`, and tasks whose actions changed. Under `\Microsoft\` only a new
//!   task or a changed action that runs a program outside the Windows folder is news (Windows
//!   updates rewrite those tasks all the time);
//! - the security switches: Defender real-time protection, the three firewall profiles, UAC and
//!   Remote Desktop (registry reads, no PowerShell);
//! - remote-access ports (SSH, Telnet, Remote Desktop, VNC, TeamViewer, WinRM) listening on every
//!   network interface, and the program listening. A port counts as closed only after it has been
//!   gone for several checks, so a listener that restarts is not reported again.
//!
//! Each difference becomes an alert. The fingerprint is saved, so changes made while Vigil was
//! closed are reported at the next start. The watch only reads: nothing is ever changed. Every
//! read is the light one (no version resources, signatures, descriptions or process paths), and a
//! section that could not be read completely is skipped, never taken as "everything was removed".
//!
//! The state lives in `%LOCALAPPDATA%\Vigil\watch\watch.json` for elevated and standard runs
//! alike, so the copy started in the tray at sign-in (standard rights) and an elevated window show
//! the same alerts. Only one copy runs the checks and owns the tray icon (a named mutex decides);
//! the other refreshes its window when the file changes. The folder is the user's, so it is opened
//! by handle and never through a link (see `userdir`), every change takes a lock shared by both
//! copies, and the file is replaced by a flushed temporary file and a rename.

use std::collections::BTreeMap;
use std::io;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use vigil_i18n::tr;

use crate::userdir::Dir;

/// How often the fingerprint is compared.
pub const INTERVAL: Duration = Duration::from_secs(60);
/// How often a window looks whether the other copy of Vigil changed the saved state.
pub const REFRESH: Duration = Duration::from_secs(3);
/// The most alerts kept (the oldest are dropped first).
pub const MAX_ALERTS: usize = 200;
/// Unread critical alerts are never dropped to make room, up to this many alerts in all.
pub const MAX_KEPT: usize = 400;
/// Notifications closer together than this are grouped into one.
pub const TOAST_GAP_MS: u64 = 2 * 60 * 1000;
/// "Pause notifications for 1 hour".
pub const PAUSE_MS: i64 = 60 * 60 * 1000;
/// The most scheduled task files read per check (a bound, not an expected size).
const MAX_TASKS: usize = 5000;
/// A listening port counts as closed after this many checks in a row without it.
pub const PORT_GRACE: u32 = 5;
/// The fingerprint's format. 2: Run keys set by policy are read (entries found there by the first
/// check of a newer Vigil are not news).
pub const FINGERPRINT_VERSION: u32 = 2;
/// How long a change waits for the other copy of Vigil to finish its own.
const LOCK_WAIT: Duration = Duration::from_secs(5);
const FILE: &str = "watch.json";
const DAMAGED: &str = "watch.json.bad";
const LOCK: &str = "watch.lock";

/// Ports of remote-access services, with the name shown in alerts.
pub const REMOTE_PORTS: [(u16, &str); 7] = [
    (22, "SSH"),
    (23, "Telnet"),
    (3389, "Remote Desktop"),
    (5900, "VNC"),
    (5938, "TeamViewer"),
    (5985, "WinRM"),
    (5986, "WinRM (HTTPS)"),
];

// ------------------------------------------------------------------------------------ settings

/// The watch settings (Settings > Background watch).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct WatchSettings {
    /// The checks run (the tray's Pause / Resume watching).
    pub watching: bool,
    /// Closing the window keeps Vigil watching in the tray; off: closing quits.
    pub close_to_tray: bool,
    pub notify_startup: bool,
    pub notify_services: bool,
    pub notify_tasks: bool,
    pub notify_security: bool,
    pub notify_ports: bool,
    /// The "Vigil keeps watching in the tray" notice was shown once.
    pub tray_notice_shown: bool,
}

impl Default for WatchSettings {
    fn default() -> Self {
        Self {
            watching: true,
            close_to_tray: true,
            notify_startup: true,
            notify_services: true,
            notify_tasks: true,
            notify_security: true,
            notify_ports: true,
            tray_notice_shown: false,
        }
    }
}

impl WatchSettings {
    /// Whether alerts of this kind raise a notification.
    pub fn notifies(&self, kind: &str) -> bool {
        match kind {
            "startup" => self.notify_startup,
            "service" => self.notify_services,
            "task" => self.notify_tasks,
            "security" => self.notify_security,
            "port" => self.notify_ports,
            _ => true,
        }
    }
}

// ------------------------------------------------------------------------------------ alerts

/// One change Vigil noticed. Texts are written in the language of the moment they were found.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub id: u64,
    /// When it was noticed (ms since 1970).
    pub time: i64,
    /// "startup", "service", "task", "security", "port", or "watch" (about the watch itself).
    pub kind: String,
    pub title: String,
    pub detail: String,
    /// "info", "warning" or "critical".
    pub severity: String,
    /// The page that shows it: "startup", "services", "tasks", "network" or "alerts".
    pub target: String,
    #[serde(default)]
    pub read: bool,
}

fn alert(kind: &str, severity: &str, target: &str, title: String, detail: String) -> Alert {
    Alert {
        id: 0,
        time: 0,
        kind: kind.into(),
        title,
        detail,
        severity: severity.into(),
        target: target.into(),
        read: false,
    }
}

/// 2 for critical, 1 for warning, 0 for the rest.
pub fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 2,
        "warning" => 1,
        _ => 0,
    }
}

// ------------------------------------------------------------------------------------ fingerprint

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StartupPrint {
    pub name: String,
    pub command: String,
    pub location: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServicePrint {
    pub display: String,
    /// "auto", "delayed-auto", "demand", "disabled", "boot", "system"; "" when it could not be read.
    pub start: String,
    /// "" when it could not be read (standard users cannot query every service).
    pub path: String,
    /// The DLL svchost loads for it ("" for other services, or when it could not be read).
    #[serde(default)]
    pub dll: String,
}

/// One task file of `System32\Tasks`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct TaskPrint {
    /// `\Folder\Name` as Windows shows it.
    pub path: String,
    pub size: u64,
    /// Last write (ms since 1970): the file is read again only when it or the size changed.
    pub modified: i64,
    /// What its actions run (see `vigil_sys::tasks::file_actions`).
    pub actions: String,
    /// The first program or DLL it runs outside the Windows folder ("" when there is none).
    pub outside: String,
}

/// What the watch compares. A section is `None` when it was not read (no rights, or an error):
/// then it is neither compared nor replaced.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct Fingerprint {
    /// Startup entry id -> entry.
    pub startup: Option<BTreeMap<String, StartupPrint>>,
    /// Service name (lower case) -> service.
    pub services: Option<BTreeMap<String, ServicePrint>>,
    /// Task path (lower case) -> task path as Windows shows it (`\Folder\Name`), outside `\Microsoft\`.
    pub tasks: Option<BTreeMap<String, String>>,
    /// Task path (lower case) -> task file, every folder.
    pub task_files: Option<BTreeMap<String, TaskPrint>>,
    /// Security switch -> it protects (true) or not.
    pub security: Option<BTreeMap<String, bool>>,
    /// "tcp:3389" -> the program listening.
    pub ports: Option<BTreeMap<String, String>>,
    /// Ports of `ports` not seen by the last checks -> how many checks in a row.
    pub ports_absent: BTreeMap<String, u32>,
    /// [`FINGERPRINT_VERSION`] of the Vigil that saved it (0: before versions were recorded).
    pub version: u32,
}

fn auto_start(start: &str) -> bool {
    matches!(start, "auto" | "delayed-auto")
}

fn policy_location(location: &str) -> bool {
    location.to_lowercase().ends_with(r"\policies\explorer\run")
}

fn microsoft_task(key: &str) -> bool {
    key.starts_with(r"\microsoft\")
}

fn last_part(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

/// The alerts for what changed between two fingerprints (sections missing on either side are skipped).
pub fn diff(old: &Fingerprint, new: &Fingerprint) -> Vec<Alert> {
    let mut out = Vec::new();
    let migrating = old.version < 2;
    if let (Some(old), Some(new)) = (&old.startup, &new.startup) {
        for (id, entry) in new {
            let (severity, title) = match old.get(id) {
                // An older Vigil did not read the policy Run keys: what is there now is not news.
                None if migrating && policy_location(&entry.location) => continue,
                None => ("warning", tr!("New startup entry: {0}", entry.name)),
                Some(before) if !before.command.eq_ignore_ascii_case(&entry.command) => {
                    ("warning", tr!("Startup entry changed: {0}", entry.name))
                }
                Some(before) if !before.enabled && entry.enabled => {
                    ("info", tr!("Startup entry turned on: {0}", entry.name))
                }
                Some(_) => continue,
            };
            let shown = tr!("{0} (in {1})", entry.command, entry.location);
            out.push(alert("startup", severity, "startup", title, shown));
        }
    }
    if let (Some(old), Some(new)) = (&old.services, &new.services) {
        for (name, service) in new {
            let display = if service.display.is_empty() {
                name
            } else {
                &service.display
            };
            let shown = || {
                if service.path.is_empty() {
                    name.clone()
                } else {
                    service.path.clone()
                }
            };
            let Some(before) = old.get(name) else {
                out.push(alert(
                    "service",
                    "warning",
                    "services",
                    tr!("New service: {0}", display),
                    shown(),
                ));
                continue;
            };
            if !before.path.is_empty() && !service.path.is_empty() && !before.path.eq_ignore_ascii_case(&service.path) {
                out.push(alert(
                    "service",
                    "warning",
                    "services",
                    tr!("Service program changed: {0}", display),
                    tr!("{0} (was {1})", service.path, before.path),
                ));
            }
            if !before.dll.is_empty() && !service.dll.is_empty() && !before.dll.eq_ignore_ascii_case(&service.dll) {
                out.push(alert(
                    "service",
                    "warning",
                    "services",
                    tr!("Service DLL changed: {0}", display),
                    tr!("{0} (was {1})", service.dll, before.dll),
                ));
            }
            if !before.start.is_empty() && !auto_start(&before.start) && auto_start(&service.start) {
                out.push(alert(
                    "service",
                    "warning",
                    "services",
                    tr!("Service now starts automatically: {0}", display),
                    shown(),
                ));
            }
        }
    }
    if let (Some(old), Some(new)) = (&old.tasks, &new.tasks) {
        for (key, path) in new {
            if !old.contains_key(key) {
                out.push(alert(
                    "task",
                    "warning",
                    "tasks",
                    tr!("New scheduled task: {0}", last_part(path)),
                    path.clone(),
                ));
            }
        }
    }
    if let (Some(old), Some(new)) = (&old.task_files, &new.task_files) {
        for (key, task) in new {
            let name = last_part(&task.path);
            match old.get(key) {
                // New tasks outside \Microsoft\ are reported from `tasks` above.
                None if microsoft_task(key) && !task.outside.is_empty() => out.push(alert(
                    "task",
                    "warning",
                    "tasks",
                    tr!("New scheduled task in a Windows folder: {0}", name),
                    tr!("{0} runs {1}", task.path, task.outside),
                )),
                None => {}
                Some(before) => {
                    let changed =
                        !before.actions.is_empty() && !task.actions.is_empty() && before.actions != task.actions;
                    if changed && (!microsoft_task(key) || !task.outside.is_empty()) {
                        let runs = if task.outside.is_empty() {
                            task.actions.lines().next().unwrap_or_default().to_string()
                        } else {
                            task.outside.clone()
                        };
                        out.push(alert(
                            "task",
                            "warning",
                            "tasks",
                            tr!("Scheduled task changed: {0}", name),
                            tr!("{0} now runs {1}", task.path, runs),
                        ));
                    }
                }
            }
        }
    }
    if let (Some(old), Some(new)) = (&old.security, &new.security) {
        for (switch, protects) in new {
            if *protects || old.get(switch) != Some(&true) {
                continue;
            }
            if let Some((severity, title, detail)) = security_text(switch) {
                out.push(alert("security", severity, "alerts", title, detail));
            }
        }
    }
    if let (Some(old), Some(new)) = (&old.ports, &new.ports) {
        for (key, program) in new {
            let port: u16 = key.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(0);
            let service = REMOTE_PORTS.iter().find(|(p, _)| *p == port).map_or("", |(_, n)| *n);
            let shown = if program.is_empty() {
                tr!("an unknown program")
            } else {
                program.clone()
            };
            match old.get(key) {
                None => out.push(alert(
                    "port",
                    "warning",
                    "network",
                    tr!("Port {0} ({1}) is open to the network", port, service),
                    tr!("{0} accepts connections on every network interface.", shown),
                )),
                Some(before) if !before.is_empty() && !program.is_empty() && !before.eq_ignore_ascii_case(program) => {
                    out.push(alert(
                        "port",
                        "warning",
                        "network",
                        tr!("Another program now listens on port {0} ({1})", port, service),
                        tr!("{0} (was {1})", program, before),
                    ));
                }
                Some(_) => {}
            }
        }
    }
    out
}

fn security_text(switch: &str) -> Option<(&'static str, String, String)> {
    let firewall = || tr!("Programs on this computer can be reached from the network without the firewall's rules.");
    Some(match switch {
        "defender" => (
            "critical",
            tr!("Microsoft Defender real-time protection is off"),
            tr!(
                "Files are no longer scanned when they are opened. If you installed another antivirus, it may have taken over."
            ),
        ),
        "firewall.domain" => ("critical", tr!("The firewall is off for domain networks"), firewall()),
        "firewall.private" => ("critical", tr!("The firewall is off for private networks"), firewall()),
        "firewall.public" => ("critical", tr!("The firewall is off for public networks"), firewall()),
        "uac" => (
            "critical",
            tr!("User Account Control is off"),
            tr!("Programs can get administrator rights without asking you."),
        ),
        "rdp" => (
            "warning",
            tr!("Remote Desktop connections are now allowed"),
            tr!("Other computers can sign in to this one over the network (port 3389)."),
        ),
        _ => return None,
    })
}

/// The next baseline: each section read now replaces the old one; a section not read keeps it.
/// A security switch that could not be read keeps its last value; a port that disappeared stays
/// for [`PORT_GRACE`] checks, so a listener that comes back is not news.
pub fn merged(old: &Fingerprint, new: Fingerprint) -> Fingerprint {
    let security = match (&old.security, new.security) {
        (Some(before), Some(now)) => {
            let mut all = before.clone();
            all.extend(now);
            Some(all)
        }
        (before, now) => now.or_else(|| before.clone()),
    };
    let (ports, ports_absent) = match new.ports {
        Some(now) => {
            let mut kept = now.clone();
            let mut absent = BTreeMap::new();
            for (key, program) in old.ports.iter().flatten() {
                if now.contains_key(key) {
                    continue;
                }
                let count = old.ports_absent.get(key).copied().unwrap_or(0) + 1;
                if count < PORT_GRACE {
                    kept.insert(key.clone(), program.clone());
                    absent.insert(key.clone(), count);
                }
            }
            (Some(kept), absent)
        }
        None => (old.ports.clone(), old.ports_absent.clone()),
    };
    Fingerprint {
        startup: new.startup.or_else(|| old.startup.clone()),
        services: new.services.or_else(|| old.services.clone()),
        tasks: new.tasks.or_else(|| old.tasks.clone()),
        task_files: new.task_files.or_else(|| old.task_files.clone()),
        security,
        ports,
        ports_absent,
        version: FINGERPRINT_VERSION,
    }
}

// ------------------------------------------------------------------------------------ reading the computer

/// Reads the fingerprint now (a fraction of a second; no PowerShell, no external tool). Task files
/// that did not change since `previous` are not read again.
pub fn read_fingerprint(elevated: bool, previous: &Fingerprint) -> Fingerprint {
    let (tasks, task_files) = if elevated {
        match read_tasks(&tasks_root(), previous.task_files.as_ref()) {
            Some((names, files)) => (Some(names), Some(files)),
            None => (None, None),
        }
    } else {
        (None, None)
    };
    Fingerprint {
        startup: startup_print(),
        services: vigil_sys::services::list_light().ok().map(|list| service_print(&list)),
        tasks,
        task_files,
        security: Some(security_print()),
        ports: vigil_sys::net::listening_tcp().ok().map(|c| port_print(&c)),
        ports_absent: BTreeMap::new(),
        version: FINGERPRINT_VERSION,
    }
}

/// The startup entries; `None` when a key or folder could not be read completely.
fn startup_print() -> Option<BTreeMap<String, StartupPrint>> {
    let (entries, complete) = vigil_sys::startup::list_checked(true);
    complete.then(|| {
        entries
            .into_iter()
            // Vigil's own sign-in entry (Settings > Start with Windows) is not news.
            .filter(|e| !e.own)
            .map(|e| {
                (
                    e.id,
                    StartupPrint {
                        name: e.name,
                        command: e.command,
                        location: e.location,
                        enabled: e.enabled,
                    },
                )
            })
            .collect()
    })
}

/// The services, without the per-sign-in copies of per-user services.
pub fn service_print(list: &[vigil_sys::services::ServiceConfig]) -> BTreeMap<String, ServicePrint> {
    list.iter()
        .filter(|s| !s.user_instance)
        .map(|s| {
            (
                s.name.to_lowercase(),
                ServicePrint {
                    display: s.display_name.clone(),
                    start: s.start_type.clone(),
                    path: s.path.clone(),
                    dll: s.dll.clone(),
                },
            )
        })
        .collect()
}

/// Listening remote-access ports bound to every interface (`0.0.0.0` or `[::]`).
pub fn port_print(connections: &[vigil_sys::net::Connection]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for c in connections {
        if c.state != "LISTEN" || !c.protocol.starts_with("TCP") {
            continue;
        }
        let Some((address, port)) = c.local.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else { continue };
        if !matches!(address, "0.0.0.0" | "[::]") || !REMOTE_PORTS.iter().any(|(p, _)| *p == port) {
            continue;
        }
        let slot = out.entry(format!("tcp:{port}")).or_insert_with(String::new);
        if slot.is_empty() {
            *slot = c.process.clone();
        }
    }
    out
}

fn windows_folder() -> PathBuf {
    std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
}

fn tasks_root() -> PathBuf {
    windows_folder().join(r"System32\Tasks")
}

/// The scheduled task names outside `\Microsoft\` (lower-case path -> `\Folder\Name`).
/// `None` when the folder cannot be read.
#[cfg(test)]
fn task_files(root: &Path) -> Option<BTreeMap<String, String>> {
    read_tasks(root, None).map(|(names, _)| names)
}

fn modified_ms(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Every task file under `root`: the names outside `\Microsoft\`, and each file's print. A file
/// whose size and time match `previous` keeps its print without being read.
fn read_tasks(
    root: &Path,
    previous: Option<&BTreeMap<String, TaskPrint>>,
) -> Option<(BTreeMap<String, String>, BTreeMap<String, TaskPrint>)> {
    const REPARSE_POINT: u32 = 0x400;
    let windows = format!("{}\\", windows_folder().display()).to_lowercase();
    let mut names = BTreeMap::new();
    let mut files = BTreeMap::new();
    std::fs::read_dir(root).ok()?;
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((folder, prefix)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.file_attributes() & REPARSE_POINT != 0 {
                continue;
            }
            let path = format!("{prefix}\\{name}");
            if meta.is_dir() {
                pending.push((entry.path(), path));
                continue;
            }
            if files.len() >= MAX_TASKS {
                continue;
            }
            let key = path.to_lowercase();
            if !microsoft_task(&key) {
                names.insert(key.clone(), path.clone());
            }
            let (size, modified) = (meta.len(), modified_ms(&meta));
            let print = match previous.and_then(|p| p.get(&key)) {
                Some(before) if before.size == size && before.modified == modified => before.clone(),
                _ => {
                    let text = std::fs::read(entry.path())
                        .map(|bytes| vigil_sys::tasks::decode_task_file(&bytes))
                        .unwrap_or_default();
                    let actions = vigil_sys::tasks::file_actions(&path, &text);
                    let outside = actions
                        .programs
                        .iter()
                        .find(|p| !p.to_lowercase().starts_with(&windows))
                        .cloned()
                        .unwrap_or_default();
                    TaskPrint {
                        path: path.clone(),
                        size,
                        modified,
                        actions: actions.summary,
                        outside,
                    }
                }
            };
            files.insert(key, print);
        }
    }
    Some((names, files))
}

const POLICY_FIREWALL: &str = r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall";
const FIREWALL: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

fn dword(key: &str, value: &str) -> Option<i64> {
    vigil_actions::reg_read(key, value)
        .ok()
        .flatten()
        .and_then(|v| v.get("data").and_then(serde_json::Value::as_i64))
}

/// The security switches from the registry (readable by standard users; group policy wins).
fn security_print() -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    let defender_off = [
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
    ]
    .iter()
    .find_map(|key| dword(key, "DisableRealtimeMonitoring"))
    .unwrap_or(0);
    out.insert("defender".to_string(), defender_off == 0);
    for (switch, policy, profile) in [
        ("firewall.domain", "DomainProfile", "DomainProfile"),
        ("firewall.private", "PrivateProfile", "StandardProfile"),
        ("firewall.public", "PublicProfile", "PublicProfile"),
    ] {
        let on = dword(&format!(r"{POLICY_FIREWALL}\{policy}"), "EnableFirewall")
            .or_else(|| dword(&format!(r"{FIREWALL}\{profile}"), "EnableFirewall"));
        if let Some(on) = on {
            out.insert(switch.to_string(), on != 0);
        }
    }
    if let Some(lua) = dword(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA",
    ) {
        out.insert("uac".to_string(), lua != 0);
    }
    let deny = dword(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "fDenyTSConnections",
    )
    .or_else(|| {
        dword(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
        )
    });
    if let Some(deny) = deny {
        out.insert("rdp".to_string(), deny != 0);
    }
    out
}

// ------------------------------------------------------------------------------------ the saved state

/// `watch.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct WatchFile {
    pub settings: WatchSettings,
    pub baseline: Fingerprint,
    /// Newest first, at most [`MAX_ALERTS`] (plus unread critical ones, up to [`MAX_KEPT`]).
    pub alerts: Vec<Alert>,
    pub next_id: u64,
    /// Notifications are paused until then (ms since 1970).
    pub notify_paused_until: Option<i64>,
    /// The language the user chose last, in any copy of Vigil ("es"); "" before one was chosen.
    /// Alerts, notifications and the tray menu use it.
    pub language: String,
}

/// Drops the oldest alerts beyond [`MAX_ALERTS`], never an unread critical one (up to [`MAX_KEPT`]).
fn keep_alerts(alerts: &mut Vec<Alert>) {
    let mut excess = alerts.len().saturating_sub(MAX_ALERTS);
    let mut index = alerts.len();
    while excess > 0 && index > 0 {
        index -= 1;
        if alerts[index].severity == "critical" && !alerts[index].read {
            continue;
        }
        alerts.remove(index);
        excess -= 1;
    }
    alerts.truncate(MAX_KEPT);
}

impl WatchFile {
    /// Stores new alerts and returns them with their ids and time, most severe first. The list
    /// stays newest first, and within one check the most severe alert comes first.
    pub fn add_alerts(&mut self, mut alerts: Vec<Alert>, now: i64) -> Vec<Alert> {
        // Most severe first, in the order they were found within one severity; the ids count
        // down along that order, so the list (newest, i.e. highest id, first) shows it too.
        alerts.sort_by_key(|a| std::cmp::Reverse(severity_rank(&a.severity)));
        let count = alerts.len() as u64;
        for (index, alert) in alerts.iter_mut().enumerate() {
            alert.id = self.next_id + count - index as u64;
            alert.time = now;
        }
        self.next_id += count;
        let mut all = alerts.clone();
        all.append(&mut self.alerts);
        keep_alerts(&mut all);
        self.alerts = all;
        alerts
    }

    /// Notifications are paused now. A pause that ends further away than [`PAUSE_MS`] (the clock
    /// was set back) has ended.
    pub fn notifications_paused(&self, now: i64) -> bool {
        self.notify_paused_until
            .is_some_and(|until| until > now && until - now <= PAUSE_MS)
    }
}

/// Where `watch.json` lives.
#[derive(Debug, Clone)]
struct Location {
    /// A folder opened by path: `%LOCALAPPDATA%`.
    base: PathBuf,
    /// The folders below it, opened by handle: `Vigil\watch`.
    parts: Vec<String>,
    /// The folder the base must be in once links are resolved: the user's profile.
    inside: Option<PathBuf>,
}

/// Reads and writes `watch.json`. Every change is load-modify-save under a lock that both copies
/// of Vigil take (elevated and not), so neither undoes the other's "mark as read".
pub struct Store {
    location: Location,
    lock: Mutex<()>,
}

/// The state as read, and whether it had to be rebuilt.
struct Loaded {
    file: WatchFile,
    /// The file did not exist yet.
    missing: bool,
    /// The file was damaged: its bytes, to keep aside when the new state is saved (the state
    /// starts again, and an alert says so).
    damaged: Option<Vec<u8>>,
}

impl Store {
    /// `watch.json` in `dir` (tests, and the data folder when the profile cannot be found).
    pub fn new(dir: PathBuf) -> Self {
        let name = dir.file_name().map(|n| n.to_string_lossy().into_owned());
        let (base, parts) = match (dir.parent(), name) {
            (Some(parent), Some(name)) => (parent.to_path_buf(), vec![name]),
            _ => (dir, Vec::new()),
        };
        Self {
            location: Location {
                base,
                parts,
                inside: None,
            },
            lock: Mutex::new(()),
        }
    }

    /// `%LOCALAPPDATA%\Vigil\watch`, shared by elevated and standard runs; `None` without a profile.
    pub fn in_profile() -> Option<Self> {
        let base = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty())?;
        let profile = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty())?;
        Some(Self {
            location: Location {
                base: PathBuf::from(base),
                parts: vec!["Vigil".into(), "watch".into()],
                inside: Some(PathBuf::from(profile)),
            },
            lock: Mutex::new(()),
        })
    }

    fn guard(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn folder(&self) -> PathBuf {
        let mut path = self.location.base.clone();
        path.extend(&self.location.parts);
        path
    }

    /// The file's path (only to see whether it changed; it is never opened by this path).
    pub fn path(&self) -> PathBuf {
        self.folder().join(FILE)
    }

    fn open(&self) -> io::Result<Dir> {
        let parts: Vec<&str> = self.location.parts.iter().map(String::as_str).collect();
        Dir::open(&self.location.base, &parts, self.location.inside.as_deref())
    }

    fn read(dir: &Dir) -> Result<Loaded, String> {
        match dir.read(FILE) {
            Ok(bytes) => match serde_json::from_slice::<WatchFile>(&bytes) {
                Ok(mut file) => {
                    keep_alerts(&mut file.alerts);
                    Ok(Loaded {
                        file,
                        missing: false,
                        damaged: None,
                    })
                }
                Err(_) => {
                    // Damaged (a crash or power loss while it was written, or edited by hand):
                    // start again, saying so; `update` keeps the damaged file for a look.
                    let mut file = WatchFile::default();
                    file.add_alerts(
                        vec![alert(
                            "watch",
                            "info",
                            "alerts",
                            tr!("The background watch started again"),
                            tr!(
                                "Its saved state was damaged and was set aside as {0}. Changes made before this moment may not be reported.",
                                DAMAGED
                            ),
                        )],
                        now_ms(),
                    );
                    Ok(Loaded {
                        file,
                        missing: false,
                        damaged: Some(bytes),
                    })
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Loaded {
                file: WatchFile::default(),
                missing: true,
                damaged: None,
            }),
            Err(error) => Err(error.to_string()),
        }
    }

    /// The saved state (defaults when it cannot be read; nothing is written).
    pub fn load(&self) -> WatchFile {
        let _guard = self.guard();
        self.open()
            .map_err(|e| e.to_string())
            .and_then(|dir| Self::read(&dir))
            .map(|loaded| loaded.file)
            .unwrap_or_default()
    }

    /// Changes the saved state; it is written only when something changed. A state that cannot
    /// be read (other than missing or damaged) is not overwritten.
    pub fn update<T>(&self, change: impl FnOnce(&mut WatchFile) -> T) -> Result<T, String> {
        let _guard = self.guard();
        let dir = self.open().map_err(|e| e.to_string())?;
        let _lock = dir.lock(LOCK, LOCK_WAIT).map_err(|e| e.to_string())?;
        let Loaded {
            mut file,
            missing,
            damaged,
        } = Self::read(&dir)?;
        if let Some(bytes) = &damaged {
            dir.write(DAMAGED, bytes).map_err(|e| e.to_string())?;
        }
        let before = file.clone();
        let result = change(&mut file);
        if missing || damaged.is_some() || file != before {
            let text = serde_json::to_vec(&file).map_err(|e| e.to_string())?;
            dir.write(FILE, &text).map_err(|e| e.to_string())?;
        }
        Ok(result)
    }
}

// ------------------------------------------------------------------------------------ notifications

/// Milliseconds on a clock that never goes back (unlike the wall clock).
pub fn monotonic_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Groups bursts: the first alert is shown at once; alerts that come within [`TOAST_GAP_MS`] of the
/// last notification wait and are shown together. Times are [`monotonic_ms`].
#[derive(Debug, Default)]
pub struct RateLimit {
    gap_ms: u64,
    last: Option<u64>,
    pending: Vec<Alert>,
}

impl RateLimit {
    pub fn new(gap_ms: u64) -> Self {
        Self {
            gap_ms,
            last: None,
            pending: Vec::new(),
        }
    }

    /// Queues alerts and returns the batch to show now as one notification (empty: nothing yet).
    pub fn offer(&mut self, alerts: Vec<Alert>, now: u64) -> Vec<Alert> {
        self.pending.extend(alerts);
        if self.pending.len() > MAX_ALERTS {
            let extra = self.pending.len() - MAX_ALERTS;
            self.pending.drain(..extra);
        }
        if self.pending.is_empty() || self.last.is_some_and(|last| now.saturating_sub(last) < self.gap_ms) {
            return Vec::new();
        }
        self.last = Some(now);
        std::mem::take(&mut self.pending)
    }

    /// Drops what is waiting (notifications were paused or turned off).
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

/// The notification for a batch: (title, body, page to open). The most severe alerts are named.
pub fn toast_text(batch: &[Alert]) -> (String, String, String) {
    match batch {
        [] => (String::new(), String::new(), String::new()),
        [one] => (one.title.clone(), one.detail.clone(), one.target.clone()),
        many => {
            let mut sorted: Vec<&Alert> = many.iter().collect();
            sorted.sort_by_key(|a| std::cmp::Reverse(severity_rank(&a.severity)));
            let mut lines: Vec<String> = sorted.iter().take(3).map(|a| a.title.clone()).collect();
            if many.len() > 3 {
                lines.push(tr!("and {0} more", many.len() - 3));
            }
            let first = &many[0].target;
            let target = if many.iter().all(|a| &a.target == first) {
                first.clone()
            } else {
                "alerts".into()
            };
            (tr!("Vigil noticed {0} changes", many.len()), lines.join("\n"), target)
        }
    }
}

/// Runs `f` in the language saved in the state ("" keeps this copy's own language).
pub fn in_language<R>(language: &str, f: impl FnOnce() -> R) -> R {
    if language.is_empty() {
        f()
    } else {
        vigil_i18n::with_language(language, f)
    }
}

// ------------------------------------------------------------------------------------ one copy watches

/// Holds the named mutex that makes this copy the one that watches (and shows the tray icon).
/// Another copy of Vigil (elevated or not) finds it taken.
pub fn claim_watch() -> bool {
    use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::core::w;
    static HELD: AtomicBool = AtomicBool::new(false);
    if HELD.load(Ordering::Acquire) {
        return true;
    }
    // SAFETY: plain Win32 call with a static name; the handle is kept open for the life of the
    // process on purpose (closing it would let another copy start watching).
    let handle = unsafe { CreateMutexW(None, false, w!("Local\\Vigil.Watch")) };
    match handle {
        // SAFETY: GetLastError reads this thread's last error, set by CreateMutexW above.
        Ok(handle) if !handle.is_invalid() && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS => {
            HELD.store(true, Ordering::Release);
            true
        }
        Ok(handle) => {
            if !handle.is_invalid() {
                // SAFETY: the handle was just returned by CreateMutexW and is not used again.
                let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
            }
            false
        }
        // Access denied: an elevated copy created it.
        Err(_) => false,
    }
}

// ------------------------------------------------------------------------------------ the watcher

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// What the UI shows (Overview card, Alerts page, sidebar, Settings).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// This copy runs the checks; false: another Vigil window does.
    pub owner: bool,
    pub watching: bool,
    /// Last check by this copy (ms since 1970).
    pub last_check: Option<i64>,
    pub unread: usize,
    pub notify_paused_until: Option<i64>,
    /// Scheduled tasks are watched only when elevated.
    pub tasks_watched: bool,
    pub settings: WatchSettings,
    /// Vigil starts in the tray at sign-in.
    pub autostart: bool,
    /// The newest alerts (at most five).
    pub recent: Vec<Alert>,
    /// The last check failed to save its state (shown, never fatal).
    pub error: Option<String>,
}

pub struct Watcher {
    pub store: Store,
    elevated: bool,
    owner: AtomicBool,
    last_check: AtomicI64,
    error: Mutex<Option<String>>,
    wake: (Mutex<bool>, Condvar),
    limiter: Mutex<RateLimit>,
    /// The saved state's size and time when this copy last looked (to see the other copy's changes).
    seen: Mutex<Option<(u64, i64)>>,
}

impl Watcher {
    pub fn new(store: Store, elevated: bool, owner: bool) -> Self {
        Self {
            store,
            elevated,
            owner: AtomicBool::new(owner),
            last_check: AtomicI64::new(0),
            error: Mutex::new(None),
            wake: (Mutex::new(false), Condvar::new()),
            limiter: Mutex::new(RateLimit::new(TOAST_GAP_MS)),
            seen: Mutex::new(None),
        }
    }

    pub fn owner(&self) -> bool {
        self.owner.load(Ordering::Acquire)
    }

    pub fn settings(&self) -> WatchSettings {
        self.store.load().settings
    }

    /// The language alerts and the tray use ("" when none was chosen yet).
    pub fn language(&self) -> String {
        self.store.load().language
    }

    /// Records the language the user chose (in this copy's Settings).
    pub fn set_language(&self, language: &str) {
        let _ = self.store.update(|file| file.language = language.to_string());
    }

    /// At start: a state without a language takes this copy's one.
    pub fn adopt_language(&self, language: &str) {
        let _ = self.store.update(|file| {
            if file.language.is_empty() {
                file.language = language.to_string();
            }
        });
    }

    pub fn status(&self) -> Status {
        let file = self.store.load();
        let last = self.last_check.load(Ordering::Acquire);
        Status {
            owner: self.owner(),
            watching: file.settings.watching,
            last_check: (last > 0).then_some(last),
            unread: file.alerts.iter().filter(|a| !a.read).count(),
            notify_paused_until: file.notify_paused_until.filter(|_| file.notifications_paused(now_ms())),
            // Another copy does the checks: whether it can read the tasks is not known here.
            tasks_watched: self.elevated && self.owner(),
            autostart: crate::autostart::enabled(),
            recent: file.alerts.iter().take(5).cloned().collect(),
            settings: file.settings,
            error: self.error.lock().unwrap_or_else(PoisonError::into_inner).clone(),
        }
    }

    /// Wakes the thread for a check now (after Resume watching).
    pub fn check_soon(&self) {
        let (lock, wake) = &self.wake;
        *lock.lock().unwrap_or_else(PoisonError::into_inner) = true;
        wake.notify_all();
    }

    /// Waits up to `timeout`; true when woken by [`check_soon`](Self::check_soon).
    fn sleep(&self, timeout: Duration) -> bool {
        let (lock, wake) = &self.wake;
        let flag = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut flag, _) = wake
            .wait_timeout_while(flag, timeout, |woken| !*woken)
            .unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut *flag)
    }

    /// Whether the saved state changed since this copy last looked (another copy wrote it).
    fn state_changed(&self) -> bool {
        let now = std::fs::metadata(self.store.path())
            .ok()
            .map(|meta| (meta.len(), modified_ms(&meta)));
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let changed = seen.is_some() && *seen != now;
        *seen = now;
        changed
    }

    /// One check: read, compare, store. Returns the new alerts.
    fn check(&self) -> Vec<Alert> {
        let previous = self.store.load().baseline;
        let current = read_fingerprint(self.elevated, &previous);
        let now = now_ms();
        let result = self.store.update(|file| {
            let alerts = diff(&file.baseline, &current);
            file.baseline = merged(&file.baseline, current);
            file.add_alerts(alerts, now)
        });
        self.last_check.store(now, Ordering::Release);
        let mut error = self.error.lock().unwrap_or_else(PoisonError::into_inner);
        match result {
            Ok(alerts) => {
                *error = None;
                alerts
            }
            Err(problem) => {
                *error = Some(problem);
                Vec::new()
            }
        }
    }

    /// The alerts to show now as one notification, after the settings, the pause and the rate limit.
    fn to_notify(&self, alerts: Vec<Alert>) -> Vec<Alert> {
        let file = self.store.load();
        let mut limiter = self.limiter.lock().unwrap_or_else(PoisonError::into_inner);
        if file.notifications_paused(now_ms()) {
            limiter.clear();
            return Vec::new();
        }
        let wanted = alerts.into_iter().filter(|a| file.settings.notifies(&a.kind)).collect();
        limiter.offer(wanted, monotonic_ms())
    }

    /// Starts the background thread (checks only while this copy owns the watch).
    pub fn start(self: &Arc<Self>, app: AppHandle) {
        let watcher = Arc::clone(self);
        let spawned = thread::Builder::new()
            .name("vigil-watch".into())
            .spawn(move || watcher.run(&app));
        if let Err(error) = spawned {
            eprintln!("could not start the watch: {error}");
        }
    }

    fn run(&self, app: &AppHandle) {
        crate::notify::init_thread();
        let mut next_check = Instant::now();
        loop {
            if !self.owner() && claim_watch() {
                self.owner.store(true, Ordering::Release);
                crate::tray::became_owner(app);
                next_check = Instant::now();
            }
            if self.owner() && Instant::now() >= next_check {
                next_check = Instant::now() + INTERVAL;
                if self.settings().watching {
                    let language = self.language();
                    in_language(&language, || {
                        let alerts = self.check();
                        let batch = self.to_notify(alerts);
                        if !batch.is_empty() {
                            let (title, body, target) = toast_text(&batch);
                            crate::notify::show(app, &title, &body, &target);
                        }
                    });
                    self.state_changed();
                    let _ = app.emit("watch", self.status());
                    crate::tray::refresh(app);
                }
            } else if self.state_changed() {
                // The other copy (or a window of this one) changed the state: show it.
                let _ = app.emit("watch", self.status());
                crate::tray::refresh(app);
            }
            let until_check = next_check.saturating_duration_since(Instant::now());
            if self.sleep(until_check.min(REFRESH)) {
                next_check = Instant::now();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn startup(name: &str, command: &str, enabled: bool) -> StartupPrint {
        StartupPrint {
            name: name.into(),
            command: command.into(),
            location: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".into(),
            enabled,
        }
    }

    fn service(display: &str, start: &str, path: &str) -> ServicePrint {
        ServicePrint {
            display: display.into(),
            start: start.into(),
            path: path.into(),
            dll: String::new(),
        }
    }

    fn baseline() -> Fingerprint {
        Fingerprint {
            startup: Some(BTreeMap::from([
                (
                    "reg:a".into(),
                    startup("Updater", r"C:\Program Files\Example\updater.exe", true),
                ),
                (
                    "reg:b".into(),
                    startup("Helper", r"C:\Program Files\Example\helper.exe", false),
                ),
            ])),
            services: Some(BTreeMap::from([
                (
                    "updatersvc".into(),
                    service("Example Updater", "demand", r"C:\Program Files\Example\svc.exe"),
                ),
                ("locked".into(), service("Locked", "", "")),
            ])),
            tasks: None,
            task_files: None,
            security: Some(BTreeMap::from([
                ("defender".into(), true),
                ("firewall.public".into(), true),
                ("rdp".into(), true),
                ("uac".into(), false),
            ])),
            ports: Some(BTreeMap::new()),
            ports_absent: BTreeMap::new(),
            version: FINGERPRINT_VERSION,
        }
    }

    fn kinds(alerts: &[Alert]) -> Vec<(String, String)> {
        alerts.iter().map(|a| (a.kind.clone(), a.title.clone())).collect()
    }

    #[test]
    fn nothing_changed_means_no_alert() {
        let old = baseline();
        assert!(diff(&old, &old.clone()).is_empty());
        // A section missing on either side is not compared.
        assert!(diff(&Fingerprint::default(), &old).is_empty());
        assert!(diff(&old, &Fingerprint::default()).is_empty());
    }

    #[test]
    fn changes_become_alerts() {
        vigil_i18n::with_language("en", || {
            let old = baseline();
            let mut new = old.clone();
            let startup_new = new.startup.as_mut().expect("startup");
            startup_new.insert(
                "reg:c".into(),
                startup("Evil", r"C:\Users\jdoe\AppData\Local\Temp\x.exe", true),
            );
            startup_new.insert(
                "reg:b".into(),
                startup("Helper", r"C:\Program Files\Example\helper.exe", true),
            );
            // Removing an entry is not an alert.
            startup_new.remove("reg:a");
            let services = new.services.as_mut().expect("services");
            services.insert(
                "evilsvc".into(),
                service("Evil Service", "auto", r"C:\Users\Public\evil.exe"),
            );
            services.insert(
                "updatersvc".into(),
                service("Example Updater", "auto", r"C:\Users\Public\svc.exe"),
            );
            // Unknown before (no rights to read it): never reported as a change.
            services.insert("locked".into(), service("Locked", "auto", r"C:\Windows\locked.exe"));
            let security = new.security.as_mut().expect("security");
            security.insert("defender".into(), false);
            security.insert("rdp".into(), false);
            // Already off before: no news; a switch turned back on is not an alert either.
            security.insert("uac".into(), false);
            new.ports = Some(BTreeMap::from([("tcp:3389".into(), "svchost.exe".into())]));
            let alerts = diff(&old, &new);
            assert_eq!(
                kinds(&alerts),
                [
                    ("startup", "Startup entry turned on: Helper"),
                    ("startup", "New startup entry: Evil"),
                    ("service", "New service: Evil Service"),
                    ("service", "Service program changed: Example Updater"),
                    ("service", "Service now starts automatically: Example Updater"),
                    ("security", "Microsoft Defender real-time protection is off"),
                    ("security", "Remote Desktop connections are now allowed"),
                    ("port", "Port 3389 (Remote Desktop) is open to the network"),
                ]
                .map(|(k, t)| (k.to_string(), t.to_string()))
            );
            let severities: Vec<&str> = alerts.iter().map(|a| a.severity.as_str()).collect();
            assert_eq!(severities[5], "critical");
            assert_eq!(alerts[7].target, "network");
            assert!(alerts[7].detail.starts_with("svchost.exe"));
        });
    }

    #[test]
    fn per_user_service_copies_are_not_news() {
        let config = |name: &str, instance: bool, dll: &str| vigil_sys::services::ServiceConfig {
            name: name.into(),
            display_name: name.into(),
            start_type: "demand".into(),
            path: r"C:\Windows\system32\svchost.exe -k UnistackSvcGroup".into(),
            dll: dll.into(),
            user_instance: instance,
        };
        let first = service_print(&[
            config("CDPUserSvc", false, r"C:\Windows\System32\CDPUserSvc.dll"),
            config("CDPUserSvc_4a5b2", true, r"C:\Windows\System32\CDPUserSvc.dll"),
        ]);
        assert_eq!(first.keys().collect::<Vec<_>>(), ["cdpusersvc"]);
        // The next sign-in: a new instance name, the same template.
        let second = service_print(&[
            config("CDPUserSvc", false, r"C:\Windows\System32\CDPUserSvc.dll"),
            config("CDPUserSvc_77c91", true, r"C:\Windows\System32\CDPUserSvc.dll"),
        ]);
        let old = Fingerprint {
            services: Some(first),
            ..Fingerprint::default()
        };
        let new = Fingerprint {
            services: Some(second),
            ..Fingerprint::default()
        };
        assert!(diff(&old, &new).is_empty());
        // A swapped svchost DLL is news; a DLL not known before is not.
        vigil_i18n::with_language("en", || {
            let mut swapped = new.clone();
            if let Some(s) = swapped.services.as_mut().and_then(|s| s.get_mut("cdpusersvc")) {
                s.dll = r"C:\Users\Public\evil.dll".into();
            }
            assert_eq!(
                kinds(&diff(&new, &swapped)),
                [("service".to_string(), "Service DLL changed: CDPUserSvc".to_string())]
            );
            let mut unknown = new.clone();
            if let Some(s) = unknown.services.as_mut().and_then(|s| s.get_mut("cdpusersvc")) {
                s.dll.clear();
            }
            assert!(diff(&unknown, &swapped).is_empty());
        });
    }

    #[test]
    fn new_tasks_are_reported_once_tasks_can_be_read() {
        vigil_i18n::with_language("en", || {
            let old = baseline();
            let mut new = old.clone();
            new.tasks = Some(BTreeMap::from([(r"\updater".into(), r"\Updater".into())]));
            // First read of the tasks (Vigil now elevated): it becomes the baseline, no alert.
            assert!(diff(&old, &new).is_empty());
            let next = merged(&old, new.clone());
            assert!(next.tasks.is_some());
            let mut later = new.clone();
            later.tasks = Some(BTreeMap::from([
                (r"\updater".into(), r"\Updater".into()),
                (r"\folder\sync".into(), r"\Folder\Sync".into()),
            ]));
            let alerts = diff(&next, &later);
            assert_eq!(
                kinds(&alerts),
                [("task".to_string(), "New scheduled task: Sync".to_string())]
            );
            assert_eq!(alerts[0].detail, r"\Folder\Sync");
            // Not elevated any more: the tasks keep their last baseline.
            later.tasks = None;
            assert_eq!(merged(&next, later).tasks, next.tasks);
        });
    }

    fn task_print(path: &str, actions: &str, outside: &str) -> TaskPrint {
        TaskPrint {
            path: path.into(),
            size: 100,
            modified: 1,
            actions: actions.into(),
            outside: outside.into(),
        }
    }

    #[test]
    fn changed_task_actions_and_windows_tasks() {
        vigil_i18n::with_language("en", || {
            let windows = r"exec %windir%\system32\defrag.exe -c";
            let old = Fingerprint {
                task_files: Some(BTreeMap::from([
                    (
                        r"\vendor\updater".into(),
                        task_print(
                            r"\Vendor\Updater",
                            "exec updater.exe",
                            r"C:\Program Files\Vendor\updater.exe",
                        ),
                    ),
                    (
                        r"\microsoft\windows\defrag\scheduleddefrag".into(),
                        task_print(r"\Microsoft\Windows\Defrag\ScheduledDefrag", windows, ""),
                    ),
                    (
                        r"\microsoft\windows\other\refresh".into(),
                        task_print(r"\Microsoft\Windows\Other\Refresh", windows, ""),
                    ),
                ])),
                ..Fingerprint::default()
            };
            let mut new = old.clone();
            let files = new.task_files.as_mut().expect("files");
            files.insert(
                r"\vendor\updater".into(),
                task_print(
                    r"\Vendor\Updater",
                    r"exec C:\Users\Public\x.exe",
                    r"C:\Users\Public\x.exe",
                ),
            );
            // A Windows update rewrote a Windows task: still Windows' own program, no news.
            files.insert(
                r"\microsoft\windows\defrag\scheduleddefrag".into(),
                task_print(
                    r"\Microsoft\Windows\Defrag\ScheduledDefrag",
                    r"exec %windir%\system32\defrag.exe -c -h",
                    "",
                ),
            );
            // A Windows task now runs something outside the Windows folder: news.
            files.insert(
                r"\microsoft\windows\other\refresh".into(),
                task_print(
                    r"\Microsoft\Windows\Other\Refresh",
                    r"exec C:\ProgramData\x\run.exe",
                    r"C:\ProgramData\x\run.exe",
                ),
            );
            files.insert(
                r"\microsoft\windows\new\planted".into(),
                task_print(
                    r"\Microsoft\Windows\New\Planted",
                    r"exec C:\Users\jdoe\AppData\Roaming\p.exe",
                    r"C:\Users\jdoe\AppData\Roaming\p.exe",
                ),
            );
            files.insert(
                r"\microsoft\windows\new\update".into(),
                task_print(r"\Microsoft\Windows\New\Update", windows, ""),
            );
            let alerts = diff(&old, &new);
            let mut titles: Vec<String> = alerts.iter().map(|a| a.title.clone()).collect();
            titles.sort();
            assert_eq!(
                titles,
                [
                    "New scheduled task in a Windows folder: Planted",
                    "Scheduled task changed: Refresh",
                    "Scheduled task changed: Updater",
                ]
            );
            assert!(
                alerts
                    .iter()
                    .any(|a| a.detail == r"\Vendor\Updater now runs C:\Users\Public\x.exe")
            );
        });
    }

    #[test]
    fn task_files_are_read_once_and_listed_without_microsoft_names() {
        let root = std::env::temp_dir().join(format!("vigil-watch-tasks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(r"Microsoft\Windows")).ok();
        std::fs::create_dir_all(root.join("Vendor")).ok();
        let task = |command: &str| {
            format!(r#"<?xml version="1.0"?><Task><Actions><Exec><Command>{command}</Command></Exec></Actions></Task>"#)
        };
        std::fs::write(
            root.join(r"Microsoft\Windows\Defrag"),
            task(r"%windir%\system32\defrag.exe"),
        )
        .ok();
        std::fs::write(root.join("Updater"), task(r"C:\Program Files\Vendor\updater.exe")).ok();
        std::fs::write(root.join(r"Vendor\Sync"), task(r"C:\Users\jdoe\AppData\Local\sync.exe")).ok();
        let tasks = task_files(&root).expect("readable");
        assert_eq!(
            tasks.values().cloned().collect::<Vec<_>>(),
            [r"\Updater", r"\Vendor\Sync"]
        );
        let (_, files) = read_tasks(&root, None).expect("readable");
        assert_eq!(files.len(), 3);
        let defrag = &files[r"\microsoft\windows\defrag"];
        assert!(defrag.outside.is_empty(), "{defrag:?}");
        assert!(defrag.actions.contains("defrag.exe"));
        assert_eq!(files[r"\vendor\sync"].outside, r"C:\Users\jdoe\AppData\Local\sync.exe");
        // Unchanged files keep their print without being read: a fake print survives.
        let mut previous = files.clone();
        if let Some(p) = previous.get_mut(r"\updater") {
            p.actions = "kept".into();
        }
        let (_, again) = read_tasks(&root, Some(&previous)).expect("readable");
        assert_eq!(again[r"\updater"].actions, "kept");
        assert!(task_files(&root.join("missing")).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn only_remote_access_ports_on_every_interface_count() {
        let row = |protocol: &str, local: &str, state: &str, process: &str| vigil_sys::net::Connection {
            pid: 1,
            process: process.into(),
            exe: String::new(),
            protocol: protocol.into(),
            local: local.into(),
            remote: String::new(),
            remote_ip: String::new(),
            state: state.into(),
            public: false,
        };
        let ports = port_print(&[
            row("TCP", "0.0.0.0:3389", "LISTEN", "svchost.exe"),
            row("TCPv6", "[::]:3389", "LISTEN", ""),
            row("TCP", "127.0.0.1:5900", "LISTEN", "vnc.exe"),
            row("TCPv6", "[::]:22", "LISTEN", "sshd.exe"),
            row("TCP", "0.0.0.0:8080", "LISTEN", "web.exe"),
            row("UDP", "0.0.0.0:3389", "LISTEN", "svchost.exe"),
            row("TCP", "203.0.113.5:5985", "ESTABLISHED", "x.exe"),
        ]);
        assert_eq!(
            ports,
            BTreeMap::from([
                ("tcp:22".to_string(), "sshd.exe".to_string()),
                ("tcp:3389".to_string(), "svchost.exe".to_string()),
            ])
        );
    }

    #[test]
    fn ports_restarting_or_taken_over() {
        vigil_i18n::with_language("en", || {
            let with = |program: Option<&str>| Fingerprint {
                ports: Some(match program {
                    Some(p) => BTreeMap::from([("tcp:22".to_string(), p.to_string())]),
                    None => BTreeMap::new(),
                }),
                ..Fingerprint::default()
            };
            let mut baseline = merged(&Fingerprint::default(), with(Some("sshd.exe")));
            // Gone for a few checks (a restart): kept, so its return is not news.
            for _ in 1..PORT_GRACE {
                baseline = merged(&baseline, with(None));
                assert!(baseline.ports.as_ref().is_some_and(|p| p.contains_key("tcp:22")));
            }
            assert!(diff(&baseline, &with(Some("sshd.exe"))).is_empty());
            let back = merged(&baseline, with(Some("sshd.exe")));
            assert!(back.ports_absent.is_empty());
            // Another program on the same port is news.
            assert_eq!(
                kinds(&diff(&back, &with(Some("evil.exe")))),
                [(
                    "port".to_string(),
                    "Another program now listens on port 22 (SSH)".to_string()
                )]
            );
            // Gone for good: dropped after the grace, then its return is news again.
            let mut gone = back;
            for _ in 0..PORT_GRACE {
                gone = merged(&gone, with(None));
            }
            assert!(gone.ports.as_ref().is_some_and(BTreeMap::is_empty));
            assert_eq!(diff(&gone, &with(Some("sshd.exe"))).len(), 1);
        });
    }

    #[test]
    fn unread_switches_and_policy_entries_do_not_raise_alerts() {
        vigil_i18n::with_language("en", || {
            // A switch that could not be read keeps its last value...
            let old = baseline();
            let mut partial = old.clone();
            partial.security = Some(BTreeMap::from([("defender".into(), true)]));
            let next = merged(&old, partial);
            assert_eq!(next.security.as_ref().and_then(|s| s.get("rdp")), Some(&true));
            // ...so turning it off later is still news.
            let mut off = next.clone();
            off.security = Some(BTreeMap::from([("rdp".into(), false)]));
            assert_eq!(diff(&next, &off).len(), 1);
            // Policy Run entries an older Vigil did not read are not news once; later they are.
            let mut older = baseline();
            older.version = 0;
            let mut now = older.clone();
            let policy = StartupPrint {
                location: r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run".into(),
                ..startup("Agent", r"C:\Tools\agent.exe", true)
            };
            now.startup
                .as_mut()
                .map(|s| s.insert("reg:policy".into(), policy.clone()));
            assert!(diff(&older, &now).is_empty());
            let upgraded = merged(&older, now.clone());
            assert_eq!(upgraded.version, FINGERPRINT_VERSION);
            let mut more = now.clone();
            more.startup
                .as_mut()
                .map(|s| s.insert("reg:policy2".into(), policy.clone()));
            assert_eq!(diff(&upgraded, &more).len(), 1);
        });
    }

    fn some_alert(kind: &str, target: &str) -> Alert {
        alert(kind, "warning", target, format!("{kind} changed"), "detail".into())
    }

    #[test]
    fn alerts_are_kept_newest_first_up_to_the_limit() {
        let mut file = WatchFile::default();
        let first = file.add_alerts(vec![some_alert("startup", "startup")], 1000);
        assert_eq!((first[0].id, first[0].time), (1, 1000));
        for round in 0..30 {
            file.add_alerts(
                (0..10).map(|_| some_alert("service", "services")).collect(),
                2000 + round,
            );
        }
        assert_eq!(file.alerts.len(), MAX_ALERTS);
        assert_eq!(file.next_id, 301);
        assert_eq!(file.alerts[0].id, 301, "newest first");
        assert!(
            file.alerts.iter().all(|a| a.kind == "service"),
            "the oldest were dropped"
        );
        let added = file.add_alerts(vec![some_alert("task", "tasks"), some_alert("port", "network")], 9000);
        assert_eq!(added.iter().map(|a| a.id).collect::<Vec<_>>(), [303, 302]);
        assert_eq!(file.alerts[0].kind, "task");
        assert_eq!(file.alerts[1].kind, "port");
    }

    #[test]
    fn the_most_severe_come_first_and_unread_critical_ones_stay() {
        let mut file = WatchFile::default();
        let critical = alert("security", "critical", "alerts", "off".into(), String::new());
        let added = file.add_alerts(
            vec![
                some_alert("service", "services"),
                critical.clone(),
                alert("startup", "info", "startup", "on".into(), String::new()),
            ],
            1,
        );
        let severities: Vec<&str> = added.iter().map(|a| a.severity.as_str()).collect();
        assert_eq!(severities, ["critical", "warning", "info"]);
        assert_eq!(file.alerts[0].severity, "critical", "first in the list too");
        // A flood of new alerts does not push out the unread critical one.
        for round in 0..40 {
            file.add_alerts((0..10).map(|_| some_alert("service", "services")).collect(), 10 + round);
        }
        assert_eq!(file.alerts.len(), MAX_ALERTS);
        assert!(file.alerts.iter().any(|a| a.severity == "critical"));
        // Once read, it may go.
        for a in &mut file.alerts {
            a.read = true;
        }
        file.add_alerts((0..10).map(|_| some_alert("service", "services")).collect(), 99);
        assert!(file.alerts.iter().all(|a| a.severity != "critical"));
        // The toast names the most severe alerts first, whatever order they came in.
        let (_, body, _) = vigil_i18n::with_language("en", || {
            toast_text(&[
                some_alert("service", "services"),
                some_alert("task", "tasks"),
                some_alert("port", "network"),
                critical.clone(),
            ])
        });
        assert!(body.starts_with("off\n"), "{body}");
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!("vigil-watch-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn state_round_trips_and_damage_is_kept_and_said() {
        let temp = TempDir::new("store");
        std::fs::create_dir_all(&temp.0).ok();
        let dir = temp.0.join("watch");
        let store = Store::new(dir.clone());
        assert_eq!(store.load(), WatchFile::default());
        assert!(store.load().settings.close_to_tray, "keep in tray by default");
        store
            .update(|file| {
                file.settings.notify_ports = false;
                file.settings.tray_notice_shown = true;
                file.baseline = baseline();
                file.add_alerts(vec![some_alert("startup", "startup")], 5);
            })
            .expect("saved");
        let loaded = store.load();
        assert!(!loaded.settings.notify_ports && loaded.settings.tray_notice_shown);
        assert_eq!(loaded.baseline, baseline());
        assert_eq!(loaded.alerts.len(), 1);
        let text = std::fs::read_to_string(dir.join("watch.json")).unwrap_or_default();
        assert!(text.contains("\"notifyPorts\":false") && text.contains("\"closeToTray\":true"));
        // Unknown keys are ignored, missing ones take their default (a state saved by 1.4.0
        // has no language, task files or version).
        std::fs::write(
            dir.join("watch.json"),
            r#"{"settings": {"watching": false}, "baseline": {"ports": {"tcp:22": "sshd.exe"}}, "unknown": 1}"#,
        )
        .ok();
        let partial = store.load();
        assert!(!partial.settings.watching && partial.settings.notify_startup);
        assert_eq!(partial.baseline.version, 0);
        assert!(partial.language.is_empty());
        // Damaged (zeroed by a power loss): kept aside, started again with an alert, and saved.
        std::fs::write(dir.join("watch.json"), [0u8; 64]).ok();
        vigil_i18n::with_language("en", || {
            store.update(|file| file.settings.watching = true).expect("saved");
        });
        assert_eq!(std::fs::read(dir.join("watch.json.bad")).ok(), Some(vec![0u8; 64]));
        let reset = store.load();
        assert_eq!(reset.alerts.len(), 1);
        assert_eq!(reset.alerts[0].kind, "watch");
        assert_eq!(reset.alerts[0].title, "The background watch started again");
        assert!(reset.baseline.startup.is_none(), "a new baseline is taken next");
    }

    #[test]
    fn two_copies_do_not_lose_each_others_changes() {
        let temp = TempDir::new("copies");
        std::fs::create_dir_all(&temp.0).ok();
        let dir = temp.0.join("watch");
        // Two stores on the same file behave like the elevated window and the tray copy.
        let one = Arc::new(Store::new(dir.clone()));
        let two = Arc::new(Store::new(dir.clone()));
        let threads: Vec<_> = [one, two]
            .into_iter()
            .map(|store| {
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        store
                            .update(|file| {
                                file.add_alerts(vec![some_alert("startup", "startup")], 1);
                            })
                            .expect("saved");
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("thread");
        }
        let all = Store::new(dir).load();
        assert_eq!(all.alerts.len(), 40, "every change kept");
        assert_eq!(all.next_id, 40);
    }

    #[test]
    fn bursts_are_grouped_and_rate_limited() {
        let mut limit = RateLimit::new(TOAST_GAP_MS);
        assert!(limit.offer(Vec::new(), 0).is_empty());
        let first = limit.offer(vec![some_alert("startup", "startup")], 1_000);
        assert_eq!(first.len(), 1, "the first alert is shown at once");
        assert!(limit.offer(vec![some_alert("service", "services")], 2_000).is_empty());
        assert!(limit.offer(vec![some_alert("task", "tasks")], 60_000).is_empty());
        assert!(limit.offer(Vec::new(), 1_000 + TOAST_GAP_MS - 1).is_empty());
        let grouped = limit.offer(Vec::new(), 1_000 + TOAST_GAP_MS);
        assert_eq!(grouped.len(), 2, "what waited comes as one notification");
        limit.offer(vec![some_alert("port", "network")], 1_000 + TOAST_GAP_MS + 5);
        limit.clear();
        assert!(limit.offer(Vec::new(), 10 * TOAST_GAP_MS).is_empty());
        // The monotonic clock only goes forward.
        let a = monotonic_ms();
        assert!(monotonic_ms() >= a);
    }

    #[test]
    fn grouped_notification_text() {
        vigil_i18n::with_language("en", || {
            let one = toast_text(&[some_alert("startup", "startup")]);
            assert_eq!(one, ("startup changed".into(), "detail".into(), "startup".into()));
            let same = toast_text(&[some_alert("startup", "startup"), some_alert("startup", "startup")]);
            assert_eq!(
                (same.0.as_str(), same.2.as_str()),
                ("Vigil noticed 2 changes", "startup")
            );
            let batch: Vec<Alert> = ["startup", "service", "task", "port", "security"]
                .iter()
                .map(|k| some_alert(k, k))
                .collect();
            let (title, body, target) = toast_text(&batch);
            assert_eq!(title, "Vigil noticed 5 changes");
            assert_eq!(body, "startup changed\nservice changed\ntask changed\nand 2 more");
            assert_eq!(target, "alerts");
            // Alerts follow the language saved in the state.
            let spanish = in_language("es", || tr!("New startup entry: {0}", "x"));
            assert_ne!(spanish, "New startup entry: x");
            assert_eq!(
                in_language("", || tr!("New startup entry: {0}", "x")),
                "New startup entry: x"
            );
        });
    }

    #[test]
    fn notification_switches_and_pause() {
        let mut settings = WatchSettings::default();
        assert!(
            ["startup", "service", "task", "security", "port"]
                .iter()
                .all(|k| settings.notifies(k))
        );
        settings.notify_tasks = false;
        assert!(!settings.notifies("task") && settings.notifies("service"));
        let file = WatchFile {
            notify_paused_until: Some(5_000),
            ..WatchFile::default()
        };
        assert!(file.notifications_paused(4_999));
        assert!(!file.notifications_paused(5_000));
        // The clock was set back by hours: the pause does not last that long.
        assert!(!file.notifications_paused(5_000 - PAUSE_MS - 1));
    }
}
