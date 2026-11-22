//! Background watch: Vigil keeps an eye on the places malware uses to stay on a computer.
//!
//! Once a minute a background thread reads a small fingerprint of the computer and compares it
//! with the last one:
//!
//! - startup entries (the Run keys and Startup folders, as the Startup apps page lists them);
//! - services: new ones, a start type changed to automatic, a changed program path;
//! - scheduled tasks outside `\Microsoft\` (names only; only when elevated, because standard users
//!   cannot read `System32\Tasks`);
//! - the security switches: Defender real-time protection, the three firewall profiles, UAC and
//!   Remote Desktop (registry reads, no PowerShell);
//! - remote-access ports (SSH, Telnet, Remote Desktop, VNC, TeamViewer, WinRM) listening on every
//!   network interface.
//!
//! Each difference becomes an alert. The fingerprint is saved, so changes made while Vigil was
//! closed are reported at the next start. The watch only reads: nothing is ever changed.
//!
//! The state lives in `%LOCALAPPDATA%\Vigil\watch\watch.json` for elevated and standard runs
//! alike, so the copy started in the tray at sign-in (standard rights) and an elevated window show
//! the same alerts. Only one copy runs the checks and owns the tray icon (a named mutex decides).

use std::collections::BTreeMap;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use vigil_i18n::tr;

/// How often the fingerprint is compared.
pub const INTERVAL: Duration = Duration::from_secs(60);
/// The most alerts kept (the oldest are dropped).
pub const MAX_ALERTS: usize = 200;
/// Notifications closer together than this are grouped into one.
pub const TOAST_GAP_MS: i64 = 2 * 60 * 1000;
/// "Pause notifications for 1 hour".
pub const PAUSE_MS: i64 = 60 * 60 * 1000;
/// The most scheduled task files read per check (a bound, not an expected size).
const MAX_TASKS: usize = 5000;

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
    /// "startup", "service", "task", "security" or "port".
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
    /// Task path (lower case) -> task path as Windows shows it (`\Folder\Name`).
    pub tasks: Option<BTreeMap<String, String>>,
    /// Security switch -> it protects (true) or not.
    pub security: Option<BTreeMap<String, bool>>,
    /// "tcp:3389" -> the program listening.
    pub ports: Option<BTreeMap<String, String>>,
}

fn auto_start(start: &str) -> bool {
    matches!(start, "auto" | "delayed-auto")
}

/// The alerts for what changed between two fingerprints (sections missing on either side are skipped).
pub fn diff(old: &Fingerprint, new: &Fingerprint) -> Vec<Alert> {
    let mut out = Vec::new();
    if let (Some(old), Some(new)) = (&old.startup, &new.startup) {
        for (id, entry) in new {
            let (severity, title) = match old.get(id) {
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
            match old.get(name) {
                None => out.push(alert(
                    "service",
                    "warning",
                    "services",
                    tr!("New service: {0}", display),
                    if service.path.is_empty() {
                        name.clone()
                    } else {
                        service.path.clone()
                    },
                )),
                Some(before) => {
                    if !before.path.is_empty()
                        && !service.path.is_empty()
                        && !before.path.eq_ignore_ascii_case(&service.path)
                    {
                        out.push(alert(
                            "service",
                            "warning",
                            "services",
                            tr!("Service program changed: {0}", display),
                            tr!("{0} (was {1})", service.path, before.path),
                        ));
                    }
                    if !before.start.is_empty() && !auto_start(&before.start) && auto_start(&service.start) {
                        out.push(alert(
                            "service",
                            "warning",
                            "services",
                            tr!("Service now starts automatically: {0}", display),
                            if service.path.is_empty() {
                                name.clone()
                            } else {
                                service.path.clone()
                            },
                        ));
                    }
                }
            }
        }
    }
    if let (Some(old), Some(new)) = (&old.tasks, &new.tasks) {
        for (key, path) in new {
            if !old.contains_key(key) {
                let name = path.rsplit('\\').next().unwrap_or(path);
                out.push(alert(
                    "task",
                    "warning",
                    "tasks",
                    tr!("New scheduled task: {0}", name),
                    path.clone(),
                ));
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
            if old.contains_key(key) {
                continue;
            }
            let port: u16 = key.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(0);
            let service = REMOTE_PORTS.iter().find(|(p, _)| *p == port).map_or("", |(_, n)| *n);
            let program = if program.is_empty() {
                tr!("an unknown program")
            } else {
                program.clone()
            };
            out.push(alert(
                "port",
                "warning",
                "network",
                tr!("Port {0} ({1}) is open to the network", port, service),
                tr!("{0} accepts connections on every network interface.", program),
            ));
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
pub fn merged(old: &Fingerprint, new: Fingerprint) -> Fingerprint {
    Fingerprint {
        startup: new.startup.or_else(|| old.startup.clone()),
        services: new.services.or_else(|| old.services.clone()),
        tasks: new.tasks.or_else(|| old.tasks.clone()),
        security: new.security.or_else(|| old.security.clone()),
        ports: new.ports.or_else(|| old.ports.clone()),
    }
}

// ------------------------------------------------------------------------------------ reading the computer

/// Reads the fingerprint now (a fraction of a second; no PowerShell, no external tool).
pub fn read_fingerprint(elevated: bool) -> Fingerprint {
    Fingerprint {
        startup: Some(startup_print()),
        services: vigil_sys::services::list().ok().map(|list| {
            list.into_iter()
                .map(|s| {
                    (
                        s.name.to_lowercase(),
                        ServicePrint {
                            display: s.display_name,
                            start: s.start_type,
                            path: s.path,
                        },
                    )
                })
                .collect()
        }),
        tasks: if elevated { task_print() } else { None },
        security: Some(security_print()),
        ports: vigil_sys::net::connections().ok().map(|c| port_print(&c)),
    }
}

fn startup_print() -> BTreeMap<String, StartupPrint> {
    vigil_sys::startup::list()
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
        let program = if c.process.is_empty() {
            String::new()
        } else {
            c.process.clone()
        };
        let slot = out.entry(format!("tcp:{port}")).or_insert_with(String::new);
        if slot.is_empty() {
            *slot = program;
        }
    }
    out
}

/// The scheduled tasks outside `\Microsoft\`, read from the files in `System32\Tasks` (names only).
fn task_print() -> Option<BTreeMap<String, String>> {
    let windir = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    task_files(&windir.join(r"System32\Tasks"))
}

/// Task files under a folder: lower-case path -> `\Folder\Name`. `None` when the folder cannot be read.
pub fn task_files(root: &Path) -> Option<BTreeMap<String, String>> {
    const REPARSE_POINT: u32 = 0x400;
    let mut out = BTreeMap::new();
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
                if !(prefix.is_empty() && name.eq_ignore_ascii_case("Microsoft")) {
                    pending.push((entry.path(), path));
                }
            } else if out.len() < MAX_TASKS {
                out.insert(path.to_lowercase(), path);
            }
        }
    }
    Some(out)
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
    /// Newest first, at most [`MAX_ALERTS`].
    pub alerts: Vec<Alert>,
    pub next_id: u64,
    /// Notifications are paused until then (ms since 1970).
    pub notify_paused_until: Option<i64>,
}

impl WatchFile {
    /// Stores new alerts (newest first) and returns them with their ids and time.
    pub fn add_alerts(&mut self, alerts: Vec<Alert>, now: i64) -> Vec<Alert> {
        let mut added = Vec::with_capacity(alerts.len());
        for mut alert in alerts {
            self.next_id += 1;
            alert.id = self.next_id;
            alert.time = now;
            added.push(alert);
        }
        let mut all: Vec<Alert> = added.iter().rev().cloned().collect();
        all.append(&mut self.alerts);
        all.truncate(MAX_ALERTS);
        self.alerts = all;
        added
    }

    pub fn notifications_paused(&self, now: i64) -> bool {
        self.notify_paused_until.is_some_and(|until| until > now)
    }
}

/// Where `watch.json` lives, shared by elevated and standard runs: `%LOCALAPPDATA%\Vigil\watch`.
pub fn default_dir() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty())?;
    Some(PathBuf::from(base).join("Vigil").join("watch"))
}

/// Reads and writes `watch.json`. Every change is load-modify-save, so two Vigil windows (one
/// elevated) never undo each other's "mark as read".
pub struct Store {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            lock: Mutex::new(()),
        }
    }

    fn guard(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn path(&self) -> PathBuf {
        self.dir.join("watch.json")
    }

    fn load_unlocked(&self) -> WatchFile {
        std::fs::read_to_string(self.path())
            .ok()
            .and_then(|text| serde_json::from_str::<WatchFile>(&text).ok())
            .map(|mut file| {
                file.alerts.truncate(MAX_ALERTS);
                file
            })
            .unwrap_or_default()
    }

    /// The folder is user-writable and an elevated Vigil writes to it: a junction or symbolic link
    /// planted there could redirect the write, so links are refused and the file is replaced by a
    /// rename instead of being written in place.
    fn save_unlocked(&self, file: &WatchFile) -> Result<(), String> {
        let refuse = |path: &Path| {
            if vigil_actions::is_reparse_point(path) {
                Err(tr!(
                    "{0} is a link; Vigil does not write through links.",
                    path.display()
                ))
            } else {
                Ok(())
            }
        };
        if let Some(parent) = self.dir.parent() {
            refuse(parent)?;
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        refuse(&self.dir)?;
        let text = serde_json::to_string(file).map_err(|e| e.to_string())?;
        let temp = self.dir.join(format!("watch.{}.tmp", std::process::id()));
        if temp.exists() {
            refuse(&temp)?;
            let _ = std::fs::remove_file(&temp);
        }
        std::fs::write(&temp, text).map_err(|e| format!("{}: {e}", temp.display()))?;
        let target = self.path();
        refuse(&target)?;
        std::fs::rename(&temp, &target).map_err(|e| {
            let _ = std::fs::remove_file(&temp);
            format!("{}: {e}", target.display())
        })
    }

    pub fn load(&self) -> WatchFile {
        let _guard = self.guard();
        self.load_unlocked()
    }

    /// Changes the saved state; it is written only when something changed.
    pub fn update<T>(&self, change: impl FnOnce(&mut WatchFile) -> T) -> Result<T, String> {
        let _guard = self.guard();
        let mut file = self.load_unlocked();
        let before = file.clone();
        let result = change(&mut file);
        if file != before || !self.path().exists() {
            self.save_unlocked(&file)?;
        }
        Ok(result)
    }
}

// ------------------------------------------------------------------------------------ notifications

/// Groups bursts: the first alert is shown at once; alerts that come within [`TOAST_GAP_MS`] of the
/// last notification wait and are shown together.
#[derive(Debug, Default)]
pub struct RateLimit {
    gap_ms: i64,
    last: Option<i64>,
    pending: Vec<Alert>,
}

impl RateLimit {
    pub fn new(gap_ms: i64) -> Self {
        Self {
            gap_ms,
            last: None,
            pending: Vec::new(),
        }
    }

    /// Queues alerts and returns the batch to show now as one notification (empty: nothing yet).
    pub fn offer(&mut self, alerts: Vec<Alert>, now: i64) -> Vec<Alert> {
        self.pending.extend(alerts);
        if self.pending.len() > MAX_ALERTS {
            let extra = self.pending.len() - MAX_ALERTS;
            self.pending.drain(..extra);
        }
        if self.pending.is_empty() || self.last.is_some_and(|last| now - last < self.gap_ms) {
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

/// The notification for a batch: (title, body, page to open).
pub fn toast_text(batch: &[Alert]) -> (String, String, String) {
    match batch {
        [] => (String::new(), String::new(), String::new()),
        [one] => (one.title.clone(), one.detail.clone(), one.target.clone()),
        many => {
            let mut lines: Vec<String> = many.iter().take(3).map(|a| a.title.clone()).collect();
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
}

impl Watcher {
    pub fn new(dir: PathBuf, elevated: bool, owner: bool) -> Self {
        Self {
            store: Store::new(dir),
            elevated,
            owner: AtomicBool::new(owner),
            last_check: AtomicI64::new(0),
            error: Mutex::new(None),
            wake: (Mutex::new(false), Condvar::new()),
            limiter: Mutex::new(RateLimit::new(TOAST_GAP_MS)),
        }
    }

    pub fn owner(&self) -> bool {
        self.owner.load(Ordering::Acquire)
    }

    pub fn settings(&self) -> WatchSettings {
        self.store.load().settings
    }

    pub fn status(&self) -> Status {
        let file = self.store.load();
        let last = self.last_check.load(Ordering::Acquire);
        Status {
            owner: self.owner(),
            watching: file.settings.watching,
            last_check: (last > 0).then_some(last),
            unread: file.alerts.iter().filter(|a| !a.read).count(),
            notify_paused_until: file.notify_paused_until.filter(|until| *until > now_ms()),
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

    fn sleep(&self) {
        let (lock, wake) = &self.wake;
        let flag = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut flag, _) = wake
            .wait_timeout_while(flag, INTERVAL, |woken| !*woken)
            .unwrap_or_else(PoisonError::into_inner);
        *flag = false;
    }

    /// One check: read, compare, store. Returns the new alerts.
    fn check(&self) -> Vec<Alert> {
        let current = read_fingerprint(self.elevated);
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
        limiter.offer(wanted, now_ms())
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
        loop {
            if !self.owner() && claim_watch() {
                self.owner.store(true, Ordering::Release);
                crate::tray::became_owner(app);
            }
            if self.owner() && self.settings().watching {
                let alerts = self.check();
                let _ = app.emit("watch", self.status());
                let batch = self.to_notify(alerts);
                if !batch.is_empty() {
                    let (title, body, target) = toast_text(&batch);
                    crate::notify::show(app, &title, &body, &target);
                }
            }
            self.sleep();
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
            security: Some(BTreeMap::from([
                ("defender".into(), true),
                ("firewall.public".into(), true),
                ("rdp".into(), true),
                ("uac".into(), false),
            ])),
            ports: Some(BTreeMap::new()),
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

    #[test]
    fn tasks_are_listed_without_microsoft_ones() {
        let root = std::env::temp_dir().join(format!("vigil-watch-tasks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(r"Microsoft\Windows")).ok();
        std::fs::create_dir_all(root.join("Vendor")).ok();
        std::fs::write(root.join(r"Microsoft\Windows\Defrag"), "<Task/>").ok();
        std::fs::write(root.join("Updater"), "<Task/>").ok();
        std::fs::write(root.join(r"Vendor\Sync"), "<Task/>").ok();
        let tasks = task_files(&root).expect("readable");
        assert_eq!(
            tasks.values().cloned().collect::<Vec<_>>(),
            [r"\Updater", r"\Vendor\Sync"]
        );
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
        assert_eq!(added.iter().map(|a| a.id).collect::<Vec<_>>(), [302, 303]);
        assert_eq!(file.alerts[0].kind, "port");
        assert_eq!(file.alerts[1].kind, "task");
    }

    #[test]
    fn state_round_trips_and_damage_falls_back() {
        let dir = std::env::temp_dir().join(format!("vigil-watch-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
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
        // Unknown keys are ignored, missing ones take their default.
        std::fs::write(
            dir.join("watch.json"),
            r#"{"settings": {"watching": false}, "unknown": 1}"#,
        )
        .ok();
        let partial = store.load();
        assert!(!partial.settings.watching && partial.settings.notify_startup);
        std::fs::write(dir.join("watch.json"), "{ damaged").ok();
        assert_eq!(store.load(), WatchFile::default());
        let _ = std::fs::remove_dir_all(&dir);
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
    }
}
