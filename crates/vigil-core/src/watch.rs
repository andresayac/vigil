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
//!   gone for several checks, so a listener that restarts is not reported again;
//! - the registry places Windows reads to load or run something (`vigil_sys::hooks`): image
//!   hijacks, Winlogon, AppInit and AppCert DLLs, BootExecute, the LSA packages, per-user class
//!   handlers used to bypass UAC, the .NET profiler variables, NetSh helpers, print monitors, time
//!   providers and Microsoft Defender exclusions (those only when readable: standard users cannot
//!   read the non-policy exclusion keys);
//! - kernel and file system drivers: a new one, or a driver file that moved outside the Windows
//!   driver folders (driver updates inside them are not news);
//! - the hosts file: its size and time each check, its contents only when they changed;
//! - a few Windows log events (`vigil_sys::watchlog`), read from where the last check stopped:
//!   a service installed, a log cleared, a new account or administrator, a scheduled task created,
//!   Microsoft Defender detections and changes, and new permanent WMI subscriptions. They catch
//!   changes undone within the minute; an event that a fingerprint section already reports is not
//!   reported twice. Logs this copy cannot read (the Security log without administrator rights)
//!   are skipped and named in the status.
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
use vigil_i18n::tr;

use vigil_sys::watchlog::LogEvent;

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
/// check of a newer Vigil are not news). 3: hook values, drivers, the hosts file and log marks
/// (new sections: the first check that reads them only records them).
pub const FINGERPRINT_VERSION: u32 = 3;
/// The most events read from one log per check (the next check goes on from there).
const MAX_EVENTS: usize = 50;
/// The most alerts made from log events per check; the rest are counted in one alert.
const MAX_EVENT_ALERTS: usize = 25;
/// The most WMI subscription hashes remembered.
const MAX_WMI_SEEN: usize = 200;
/// The hosts file is read up to this size.
const MAX_HOSTS: u64 = 4 * 1024 * 1024;
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
    /// Hook values, drivers and the hosts file.
    pub notify_hooks: bool,
    /// Events read from the Windows logs.
    pub notify_events: bool,
    /// The "Vigil keeps watching in the tray" notice was shown once.
    pub tray_notice_shown: bool,
    /// Automatic scans (`crate::autoscan`): "off", "daily" or "weekly".
    pub scan_schedule: String,
    /// The day of a weekly scan: 1 = Monday … 7 = Sunday.
    pub scan_day: u8,
    /// The time of the scan, "HH:MM" in local time.
    pub scan_time: String,
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
            notify_hooks: true,
            notify_events: true,
            tray_notice_shown: false,
            scan_schedule: "off".into(),
            scan_day: 1,
            scan_time: "12:30".into(),
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
            "hook" | "driver" | "hosts" => self.notify_hooks,
            "event" => self.notify_events,
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
    /// "startup", "service", "task", "security", "port", "hook", "driver", "hosts", "event", "scan"
    /// (an automatic scan found something), or "watch" (about the watch itself).
    pub kind: String,
    pub title: String,
    pub detail: String,
    /// "info", "warning" or "critical".
    pub severity: String,
    /// The page that shows it: "startup", "services", "tasks", "network", "protection", "posture",
    /// "firewall", "accounts", "findings" (the report of an automatic scan) or "alerts".
    pub target: String,
    #[serde(default)]
    pub read: bool,
}

pub(crate) fn alert(kind: &str, severity: &str, target: &str, title: String, detail: String) -> Alert {
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
    /// Hook source id (see `vigil_sys::hooks`) -> value name -> value. A source this copy could not
    /// read is missing, and only sources read on both sides are compared.
    pub hooks: BTreeMap<String, BTreeMap<String, String>>,
    /// Driver service name (lower case) -> driver.
    pub drivers: Option<BTreeMap<String, DriverPrint>>,
    pub hosts: Option<HostsPrint>,
    /// Log name -> where the last check stopped reading it.
    pub events: BTreeMap<String, LogMark>,
    /// Permanent WMI subscriptions already reported (a short hash of each), so the same one logged
    /// again is not news.
    pub wmi_seen: Vec<String>,
    /// The events read by this check (not saved: only `events` says where reading stopped).
    #[serde(skip)]
    pub event_hits: Vec<LogEvent>,
    /// Logs this check could not read (not saved).
    #[serde(skip)]
    pub logs_hidden: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct DriverPrint {
    /// ImagePath as written; "" means the default `System32\drivers\<name>.sys`.
    pub path: String,
    pub start: String,
}

/// The hosts file: its size and time (read each check) and, read only when they changed, a hash
/// of its contents and the names it redirects.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct HostsPrint {
    pub size: u64,
    pub modified: i64,
    pub hash: String,
    /// Host name (lower case) -> the address it now leads to.
    pub redirects: BTreeMap<String, String>,
}

/// Where reading a log stopped: its record number then (each log numbers records in order) and that
/// record's time (used when the log was cleared and the numbers started again).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct LogMark {
    pub record: u64,
    pub time: i64,
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
                out.push(alert("security", severity, security_target(switch), title, detail));
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
    out.extend(hook_alerts(&old.hooks, &new.hooks));
    if let (Some(old), Some(new)) = (&old.drivers, &new.drivers) {
        out.extend(driver_alerts(old, new));
    }
    if let (Some(old), Some(new)) = (&old.hosts, &new.hosts) {
        out.extend(hosts_alert(old, new));
    }
    out.extend(event_alerts(&new.event_hits, old, new));
    out
}

/// The page a security switch belongs to.
fn security_target(switch: &str) -> &'static str {
    if switch.starts_with("defender") {
        "protection"
    } else if switch.starts_with("firewall") {
        "firewall"
    } else {
        "posture"
    }
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
        "defender.tamper" => (
            "critical",
            tr!("Microsoft Defender tamper protection is off"),
            tr!("Programs can now change Microsoft Defender's settings, including turning it off."),
        ),
        "defender.policy" => (
            "critical",
            tr!("A policy turns Microsoft Defender off"),
            tr!(
                "The DisableAntiSpyware policy is set. Malware sets it to switch Defender off; companies rarely do, and only when another antivirus protects the computer."
            ),
        ),
        "wdigest" => (
            "critical",
            tr!("Windows now keeps sign-in passwords in memory (WDigest)"),
            tr!(
                "Password-stealing tools can read them from memory. Malware turns this on before it steals credentials."
            ),
        ),
        "lsa" => (
            "warning",
            tr!("LSA protection is off"),
            tr!("Other programs can again read passwords and tokens from the process that signs you in."),
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
    // A hook source read now replaces the old one; one not read keeps it.
    let mut hooks = old.hooks.clone();
    hooks.extend(new.hooks);
    let mut events = old.events.clone();
    events.extend(new.events);
    let mut wmi_seen = old.wmi_seen.clone();
    for hit in new.event_hits.iter().filter(|e| e.event_id == 5861) {
        let key = wmi_key(hit);
        if !wmi_seen.contains(&key) {
            wmi_seen.push(key);
        }
    }
    let excess = wmi_seen.len().saturating_sub(MAX_WMI_SEEN);
    wmi_seen.drain(..excess);
    Fingerprint {
        startup: new.startup.or_else(|| old.startup.clone()),
        services: new.services.or_else(|| old.services.clone()),
        tasks: new.tasks.or_else(|| old.tasks.clone()),
        task_files: new.task_files.or_else(|| old.task_files.clone()),
        security,
        ports,
        ports_absent,
        version: FINGERPRINT_VERSION,
        hooks,
        drivers: new.drivers.or_else(|| old.drivers.clone()),
        hosts: new.hosts.or_else(|| old.hosts.clone()),
        events,
        wmi_seen,
        event_hits: Vec::new(),
        logs_hidden: Vec::new(),
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
    let (events, event_hits, logs_hidden) = read_events(&WindowsLogs, &previous.events, now_ms());
    Fingerprint {
        startup: startup_print(),
        services: vigil_sys::services::list_light().ok().map(|list| service_print(&list)),
        tasks,
        task_files,
        security: Some(security_print()),
        ports: vigil_sys::net::listening_tcp().ok().map(|c| port_print(&c)),
        ports_absent: BTreeMap::new(),
        version: FINGERPRINT_VERSION,
        hooks: vigil_sys::hooks::read(&vigil_sys::hooks::default_sources()),
        drivers: vigil_sys::hooks::drivers().map(|list| driver_print(&list)),
        hosts: read_hosts(&hosts_path(), previous.hosts.as_ref()),
        events,
        wmi_seen: Vec::new(),
        event_hits,
        logs_hidden,
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
    // Tamper protection: 1 or 5 on, 0 or 4 off; the value exists once Defender has set it.
    if let Some(tamper) = dword(r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection") {
        out.insert("defender.tamper".to_string(), tamper & 1 == 1);
    }
    let policy = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender";
    if let Some(off) = dword_or(policy, "DisableAntiSpyware", 0) {
        out.insert("defender.policy".to_string(), off != 1);
    }
    let wdigest = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
    if let Some(keep) = dword_or(wdigest, "UseLogonCredential", 0) {
        out.insert("wdigest".to_string(), keep != 1);
    }
    if let Some(ppl) = dword_or(r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 0) {
        out.insert("lsa".to_string(), matches!(ppl, 1 | 2));
    }
    out
}

/// A DWORD, `default` when the value does not exist, `None` when it cannot be read.
fn dword_or(key: &str, value: &str, default: i64) -> Option<i64> {
    match vigil_actions::reg_read(key, value) {
        Ok(Some(v)) => v.get("data").and_then(serde_json::Value::as_i64),
        Ok(None) => Some(default),
        Err(_) => None,
    }
}

// ------------------------------------------------------------------------------------ hooks

/// The places Vigil reads, by source id: (kind, location as shown).
fn hook_sources() -> BTreeMap<String, (&'static str, String)> {
    vigil_sys::hooks::default_sources()
        .into_iter()
        .map(|s| {
            let location = s.location();
            (s.id, (s.kind, location))
        })
        .collect()
}

/// Programs Windows starts at the sign-in screen with full rights (Ease of Access and friends): an
/// image hijack on them gives a command prompt to anyone at the keyboard.
const ACCESSIBILITY: [&str; 7] = [
    "sethc.exe",
    "utilman.exe",
    "osk.exe",
    "magnify.exe",
    "narrator.exe",
    "displayswitch.exe",
    "atbroker.exe",
];

/// Whether a hook value points into the Windows folder (or is a bare DLL name Windows loads from
/// System32).
fn windows_hook_value(value: &str) -> bool {
    let lower = value.to_lowercase();
    let windows = format!("{}\\", windows_folder().display()).to_lowercase();
    !lower.contains('\\') || lower.starts_with(&windows) || lower.starts_with(r"%systemroot%\")
}

fn hook_label(kind: &str) -> String {
    match kind {
        "winlogon" => tr!("Winlogon (the programs Windows starts at sign-in)"),
        "appinit" => tr!("AppInit DLLs (loaded into every program)"),
        "appcert" => tr!("AppCert DLLs (loaded with every new program)"),
        "boot_execute" => tr!("BootExecute (programs run while Windows starts)"),
        "lsa" => tr!("LSA packages (loaded into the process that signs you in)"),
        "class" => tr!("A per-user handler for the Settings app or consoles"),
        "profiler" => tr!(".NET profiler (loaded into .NET programs)"),
        "netsh" => tr!("NetSh helpers"),
        "print_monitor" => tr!("Print monitors (loaded by the print spooler)"),
        "time_provider" => tr!("Time providers (loaded by the time service)"),
        other => other.to_string(),
    }
}

/// Alerts for hook values that are new or changed, in sources read on both sides.
pub fn hook_alerts(
    old: &BTreeMap<String, BTreeMap<String, String>>,
    new: &BTreeMap<String, BTreeMap<String, String>>,
) -> Vec<Alert> {
    let sources = hook_sources();
    let mut out = Vec::new();
    for (id, values) in new {
        let Some(before) = old.get(id) else { continue };
        let (kind, location) = sources.get(id).cloned().unwrap_or(("", String::new()));
        for (name, value) in values {
            let changed = match before.get(name) {
                Some(was) if was.eq_ignore_ascii_case(value) => continue,
                Some(_) => true,
                None => false,
            };
            if let Some(found) = hook_alert(kind, &location, name, value, changed) {
                out.push(found);
            }
        }
    }
    out
}

fn hook_alert(kind: &str, location: &str, name: &str, value: &str, changed: bool) -> Option<Alert> {
    let (image, value_name) = name.split_once('\\').unwrap_or((name, ""));
    let accessibility = ACCESSIBILITY.iter().any(|a| a.eq_ignore_ascii_case(image));
    Some(match kind {
        "ifeo" if value_name.eq_ignore_ascii_case("Debugger") => alert(
            "hook",
            if accessibility { "critical" } else { "warning" },
            "alerts",
            tr!("A program now starts instead of {0}", image),
            tr!(
                "Windows runs {0} whenever {1} is started (in {2}).",
                value,
                image,
                location
            ),
        ),
        "ifeo" => alert(
            "hook",
            if accessibility { "critical" } else { "warning" },
            "alerts",
            tr!("A DLL is now loaded into {0}", image),
            tr!("{0} (in {1})", value, location),
        ),
        "silent_exit" => alert(
            "hook",
            "warning",
            "alerts",
            tr!("A program now runs when {0} closes", image),
            tr!("{0} (in {1})", value, location),
        ),
        // A changed exclusion value means nothing; a new name is a new exclusion.
        "exclusion" if changed => return None,
        "exclusion" => alert(
            "security",
            "critical",
            "protection",
            tr!("New Microsoft Defender exclusion: {0}", name),
            tr!(
                "Microsoft Defender no longer scans it. Malware adds exclusions to hide; if you did not add it, remove it on the Protection page."
            ),
        ),
        "appinit" if name.eq_ignore_ascii_case("LoadAppInit_DLLs") && value == "0" => return None,
        "appinit" | "appcert" | "winlogon" | "lsa" | "class" => alert(
            "hook",
            if name.eq_ignore_ascii_case("LoadAppInit_DLLs") {
                "warning"
            } else {
                "critical"
            },
            "alerts",
            tr!("Change in {0}", hook_label(kind)),
            tr!("{0} is now {1} (in {2})", name, value, location),
        ),
        "netsh" | "print_monitor" | "time_provider" => alert(
            "hook",
            if windows_hook_value(value) { "info" } else { "warning" },
            "alerts",
            tr!("Change in {0}", hook_label(kind)),
            tr!("{0} is now {1} (in {2})", name, value, location),
        ),
        _ => alert(
            "hook",
            "warning",
            "alerts",
            tr!("Change in {0}", hook_label(kind)),
            tr!("{0} is now {1} (in {2})", name, value, location),
        ),
    })
}

// ------------------------------------------------------------------------------------ drivers

pub fn driver_print(list: &[vigil_sys::hooks::Driver]) -> BTreeMap<String, DriverPrint> {
    list.iter()
        .map(|d| {
            (
                d.name.to_lowercase(),
                DriverPrint {
                    path: d.path.clone(),
                    start: d.start.clone(),
                },
            )
        })
        .collect()
}

/// Whether a path is in a folder standard users can write to.
fn user_writable(path: &str) -> bool {
    let lower = path.to_lowercase();
    [r"\users\", r"\programdata\", r"\temp\", r"\appdata\"]
        .iter()
        .any(|part| lower.contains(part))
}

pub fn driver_alerts(old: &BTreeMap<String, DriverPrint>, new: &BTreeMap<String, DriverPrint>) -> Vec<Alert> {
    use vigil_sys::hooks::standard_driver_path;
    let mut out = Vec::new();
    for (name, driver) in new {
        let shown = if driver.path.is_empty() {
            tr!("{0}.sys in the Windows driver folder", name)
        } else {
            driver.path.clone()
        };
        let outside = if user_writable(&driver.path) {
            "critical"
        } else {
            "warning"
        };
        match old.get(name) {
            None if standard_driver_path(&driver.path) => {
                out.push(alert("driver", "info", "alerts", tr!("New driver: {0}", name), shown))
            }
            None => out.push(alert(
                "driver",
                outside,
                "alerts",
                tr!("New driver outside the Windows driver folders: {0}", name),
                shown,
            )),
            Some(before) if !before.path.eq_ignore_ascii_case(&driver.path) => {
                // A driver update moves the file within the driver store: not news.
                if standard_driver_path(&before.path) && standard_driver_path(&driver.path) {
                    continue;
                }
                out.push(alert(
                    "driver",
                    if standard_driver_path(&driver.path) {
                        "info"
                    } else {
                        outside
                    },
                    "alerts",
                    tr!("Driver file changed: {0}", name),
                    tr!("{0} (was {1})", shown, before.path),
                ));
            }
            Some(_) => {}
        }
    }
    out
}

// ------------------------------------------------------------------------------------ hosts file

fn hosts_path() -> PathBuf {
    windows_folder().join(r"System32\drivers\etc\hosts")
}

/// FNV-1a, as hex: enough to see that the file's contents changed.
fn short_hash(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// The names a hosts file redirects (lower case) -> the address; `localhost` names are left out.
pub fn hosts_redirects(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut parts = line.split_whitespace();
        let Some(address) = parts.next() else { continue };
        if address.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        for name in parts {
            let name = name.to_lowercase();
            if matches!(
                name.as_str(),
                "localhost" | "localhost.localdomain" | "ip6-localhost" | "ip6-loopback" | "broadcasthost"
            ) {
                continue;
            }
            out.entry(name).or_insert_with(|| address.to_string());
        }
    }
    out
}

/// The hosts file's print; `None` when it cannot be read. When its size and time match `previous`,
/// the file is not read again.
fn read_hosts(path: &Path, previous: Option<&HostsPrint>) -> Option<HostsPrint> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        // No hosts file at all: nothing is redirected.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Some(HostsPrint::default()),
        Err(_) => return None,
    };
    let (size, modified) = (meta.len(), modified_ms(&meta));
    if let Some(before) = previous
        && before.size == size
        && before.modified == modified
    {
        return Some(before.clone());
    }
    let mut bytes = Vec::new();
    {
        use std::io::Read;
        let file = std::fs::File::open(path).ok()?;
        file.take(MAX_HOSTS).read_to_end(&mut bytes).ok()?;
    }
    Some(HostsPrint {
        size,
        modified,
        hash: short_hash(&bytes),
        redirects: hosts_redirects(&String::from_utf8_lossy(&bytes)),
    })
}

/// Security, update and banking names malware redirects (to block updates or show fake sites).
const SENSITIVE_HOSTS: [&str; 18] = [
    "microsoft.com",
    "windowsupdate",
    "windows.com",
    "live.com",
    "defender",
    "virustotal",
    "malwarebytes",
    "kaspersky",
    "eset.com",
    "avast",
    "avg.com",
    "bitdefender",
    "norton",
    "mcafee",
    "sophos",
    "trendmicro",
    "paypal",
    "bank",
];

fn blocking_address(address: &str) -> bool {
    matches!(address, "0.0.0.0" | "127.0.0.1" | "::" | "::1" | "::0")
}

pub fn hosts_alert(old: &HostsPrint, new: &HostsPrint) -> Option<Alert> {
    if old.hash == new.hash && !old.hash.is_empty() {
        return None;
    }
    let added: Vec<(&String, &String)> = new
        .redirects
        .iter()
        .filter(|(name, address)| old.redirects.get(*name) != Some(*address))
        .collect();
    if added.is_empty() {
        return None;
    }
    let sensitive = added
        .iter()
        .any(|(name, _)| SENSITIVE_HOSTS.iter().any(|s| name.contains(s)));
    let blocking_only = added.iter().all(|(_, address)| blocking_address(address));
    let severity = if sensitive {
        "critical"
    } else if blocking_only {
        "info"
    } else {
        "warning"
    };
    let mut names: Vec<&str> = added.iter().take(3).map(|(name, _)| name.as_str()).collect();
    let more = added.len().saturating_sub(names.len());
    let shown_more = tr!("and {0} more", more);
    if more > 0 {
        names.push(&shown_more);
    }
    let mut addresses: Vec<&str> = added.iter().map(|(_, address)| address.as_str()).collect();
    addresses.sort_unstable();
    addresses.dedup();
    Some(alert(
        "hosts",
        severity,
        "alerts",
        tr!("The hosts file now redirects {0}", names.join(", ")),
        tr!(
            "These names now lead to {0} instead of their real servers. Malware does this to block security updates or to send you to fake sites; ad blockers do it too.",
            addresses.join(", ")
        ),
    ))
}

// ------------------------------------------------------------------------------------ Windows logs

/// Where the watch reads log events from (Windows, or a fake in tests). `Err(())` only says "could
/// not be read": the watch skips that log for this check, it has nothing more to report.
#[allow(clippy::result_unit_err)]
pub trait LogSource {
    /// The newest record of a log: `Ok(None)` when it is empty, `Err` when it cannot be read.
    fn newest(&self, log: &str) -> Result<Option<(u64, i64)>, ()>;
    /// The events with one of `ids` after record `after`, oldest first, at most `max`.
    fn read_after(&self, log: &str, ids: &[u32], after: u64, max: usize) -> Result<Vec<LogEvent>, ()>;
}

struct WindowsLogs;

impl LogSource for WindowsLogs {
    fn newest(&self, log: &str) -> Result<Option<(u64, i64)>, ()> {
        vigil_sys::watchlog::newest(log).map_err(|_| ())
    }

    fn read_after(&self, log: &str, ids: &[u32], after: u64, max: usize) -> Result<Vec<LogEvent>, ()> {
        vigil_sys::watchlog::read_after(log, ids, after, max).map_err(|_| ())
    }
}

pub const SYSTEM_LOG: &str = "System";
pub const SECURITY_LOG: &str = "Security";
pub const DEFENDER_LOG: &str = "Microsoft-Windows-Windows Defender/Operational";
pub const WMI_LOG: &str = "Microsoft-Windows-WMI-Activity/Operational";

/// The logs and event ids the watch reads.
pub const WATCHED_LOGS: [(&str, &[u32]); 4] = [
    // A service installed; a log cleared.
    (SYSTEM_LOG, &[7045, 104]),
    // The Security log cleared; account created; member added to a group; scheduled task created.
    (SECURITY_LOG, &[1102, 4720, 4732, 4698]),
    // Threat found; action taken; real-time protection off; configuration changed.
    (DEFENDER_LOG, &[1116, 1117, 5001, 5007]),
    // A permanent WMI event subscription.
    (WMI_LOG, &[5861]),
];

/// Reads each watched log from where `previous` stopped: the new marks (logs that could not be
/// read are left out, so the old mark stays), the events found, and the logs that could not be
/// read. A log seen for the first time is only marked: what it already holds is not news.
pub fn read_events(
    source: &dyn LogSource,
    previous: &BTreeMap<String, LogMark>,
    now: i64,
) -> (BTreeMap<String, LogMark>, Vec<LogEvent>, Vec<String>) {
    let mut marks = BTreeMap::new();
    let mut hits = Vec::new();
    let mut hidden = Vec::new();
    for (log, ids) in WATCHED_LOGS {
        let newest = match source.newest(log) {
            Ok(newest) => newest.map_or(LogMark { record: 0, time: now }, |(record, time)| LogMark {
                record,
                time,
            }),
            Err(()) => {
                hidden.push(log.to_string());
                continue;
            }
        };
        let Some(before) = previous.get(log) else {
            marks.insert(log.to_string(), newest);
            continue;
        };
        if newest.record == before.record {
            marks.insert(log.to_string(), *before);
            continue;
        }
        // The numbers went back: the log was cleared (or recreated). Read it all, keep what is
        // newer than the last check's mark.
        let reset = newest.record < before.record;
        let after = if reset { 0 } else { before.record };
        let Ok(found) = source.read_after(log, ids, after, MAX_EVENTS) else {
            hidden.push(log.to_string());
            continue;
        };
        // Capped: go on from the last event read next time, so nothing is skipped.
        let mark = match found.last() {
            Some(last) if found.len() >= MAX_EVENTS && !reset => LogMark {
                record: last.record_id,
                time: last.time_ms,
            },
            _ => newest,
        };
        hits.extend(found.into_iter().filter(|e| !reset || e.time_ms > before.time));
        marks.insert(log.to_string(), mark);
    }
    (marks, hits, hidden)
}

/// The hash a WMI subscription is remembered by.
fn wmi_key(event: &LogEvent) -> String {
    let text = format!("{}|{}", event.get("Namespace"), event.get("CONSUMER")).to_lowercase();
    short_hash(text.as_bytes())
}

/// A path from an event, without Defender's `file:_` style prefix.
fn event_path(text: &str) -> String {
    text.split_once(":_").map_or(text, |(_, rest)| rest).to_string()
}

fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() > max {
        format!("{}…", text.chars().take(max).collect::<String>())
    } else {
        text.to_string()
    }
}

/// An account name from an event; "" for the "-" Windows writes when there is none.
fn account(event: &LogEvent, name: &str, sid: &str) -> String {
    let value = event.get(name);
    if value.is_empty() || value == "-" {
        event.get(sid).to_string()
    } else {
        value.to_string()
    }
}

/// Alerts for the events read by this check. An event that a fingerprint section already reports
/// (a new service, a new task, Defender turned off, a new exclusion) is left out, as is a WMI
/// subscription reported before.
pub fn event_alerts(hits: &[LogEvent], old: &Fingerprint, new: &Fingerprint) -> Vec<Alert> {
    let mut out: Vec<Alert> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for event in hits {
        let Some(found) = event_alert(event, old, new) else {
            continue;
        };
        // The same event logged several times in one minute (a threat found again) is one alert.
        if !seen.insert((found.title.clone(), found.detail.clone())) {
            continue;
        }
        out.push(found);
    }
    if out.len() > MAX_EVENT_ALERTS {
        let more = out.len() - MAX_EVENT_ALERTS;
        out.truncate(MAX_EVENT_ALERTS);
        out.push(alert(
            "event",
            "info",
            "alerts",
            tr!("{0} more events from the Windows logs", more),
            tr!("Open Event Viewer to see them all."),
        ));
    }
    out
}

fn event_alert(event: &LogEvent, old: &Fingerprint, new: &Fingerprint) -> Option<Alert> {
    let by = || {
        let who = account(event, "SubjectUserName", "SubjectUserSid");
        if who.is_empty() { tr!("an unknown account") } else { who }
    };
    Some(match (event.log.as_str(), event.event_id) {
        (SYSTEM_LOG, 7045) => {
            let name = event.get("ServiceName");
            // The services section reports a service that is still there.
            if let Some(services) = &new.services
                && (services.contains_key(&name.to_lowercase())
                    || services.values().any(|s| s.display.eq_ignore_ascii_case(name)))
            {
                return None;
            }
            alert(
                "event",
                "warning",
                "services",
                tr!("Service installed: {0}", name),
                event.get("ImagePath").to_string(),
            )
        }
        (SYSTEM_LOG, 104) | (SECURITY_LOG, 1102) => {
            let channel = match event.get("Channel") {
                "" => SECURITY_LOG,
                channel => channel,
            };
            alert(
                "event",
                "critical",
                "alerts",
                tr!("The {0} log was cleared", channel),
                tr!(
                    "Cleared by {0}. Clearing a log erases the record of what happened; intruders do it to hide their tracks.",
                    by()
                ),
            )
        }
        (SECURITY_LOG, 4720) => alert(
            "event",
            "warning",
            "accounts",
            tr!("New account: {0}", account(event, "TargetUserName", "TargetSid")),
            tr!("Created by {0}.", by()),
        ),
        (SECURITY_LOG, 4732) => {
            // Only Administrators (S-1-5-32-544): other groups are routine.
            if !event.get("TargetSid").eq_ignore_ascii_case("S-1-5-32-544") {
                return None;
            }
            alert(
                "event",
                "critical",
                "accounts",
                tr!(
                    "Added to Administrators: {0}",
                    account(event, "MemberName", "MemberSid")
                ),
                tr!("Added by {0}.", by()),
            )
        }
        (SECURITY_LOG, 4698) => {
            let task = event.get("TaskName");
            let key = task.to_lowercase();
            if new.task_files.as_ref().is_some_and(|files| files.contains_key(&key)) {
                return None;
            }
            alert(
                "event",
                "warning",
                "tasks",
                tr!("Scheduled task created: {0}", last_part(task)),
                tr!("{0}, created by {1}.", task, by()),
            )
        }
        (DEFENDER_LOG, 1116) => alert(
            "event",
            "critical",
            "protection",
            tr!("Microsoft Defender found a threat: {0}", event.get("Threat Name")),
            event_path(event.get("Path")),
        ),
        (DEFENDER_LOG, 1117) => alert(
            "event",
            "info",
            "protection",
            tr!("Microsoft Defender acted on a threat: {0}", event.get("Threat Name")),
            tr!("{0}: {1}", event.get("Action Name"), event_path(event.get("Path"))),
        ),
        (DEFENDER_LOG, 5001) => {
            // Still off: the security switch reports it.
            if new.security.as_ref().and_then(|s| s.get("defender")) == Some(&false) {
                return None;
            }
            alert(
                "event",
                "critical",
                "protection",
                tr!("Microsoft Defender real-time protection was turned off"),
                tr!("It is on again now, but files were not scanned for a while."),
            )
        }
        (DEFENDER_LOG, 5007) => {
            let value = event.get("New Value");
            let lower = value.to_lowercase();
            let marker = r"\exclusions\";
            let at = lower.find(marker)?;
            // `...\Exclusions\Paths\C:\Temp = 0x0`: the list, then the excluded name.
            let rest = &value[at + marker.len()..];
            let name = rest.split_once('\\').map_or(rest, |(_, name)| name);
            let name = name.split(" = ").next().unwrap_or(name).trim();
            if name.is_empty() {
                return None;
            }
            // The exclusion keys are readable here: the hook section reports it.
            if new
                .hooks
                .keys()
                .any(|id| id.starts_with("exclusions_") && !id.starts_with("exclusions_policy"))
            {
                return None;
            }
            alert(
                "security",
                "critical",
                "protection",
                tr!("New Microsoft Defender exclusion: {0}", name),
                tr!(
                    "Microsoft Defender no longer scans it. Malware adds exclusions to hide; if you did not add it, remove it on the Protection page."
                ),
            )
        }
        (WMI_LOG, 5861) => {
            if old.wmi_seen.contains(&wmi_key(event)) {
                return None;
            }
            alert(
                "event",
                "critical",
                "alerts",
                tr!("New permanent WMI event subscription"),
                tr!(
                    "{0} (in {1}). Permanent subscriptions run a command when something happens; malware uses them to start again.",
                    shorten(event.get("CONSUMER"), 300),
                    event.get("Namespace")
                ),
            )
        }
        _ => return None,
    })
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
    /// Automatic scans: the schedule's arming time, the last run and its result.
    pub auto_scan: crate::autoscan::AutoScanState,
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
    /// Windows logs the last check could not read (the Security log without administrator rights).
    pub logs_hidden: Vec<String>,
    pub settings: WatchSettings,
    /// Vigil starts in the tray at sign-in.
    pub autostart: bool,
    /// The newest alerts (at most five).
    pub recent: Vec<Alert>,
    /// The last check failed to save its state (shown, never fatal).
    pub error: Option<String>,
    /// Automatic scans: the schedule, the next and the last one.
    pub auto_scan: crate::autoscan::AutoScanView,
}

/// What the watch needs from the front end it runs in.
pub trait WatchHost: Send + Sync {
    /// This copy took over the watch from one that quit: it gets the tray icon.
    fn became_owner(&self);
    /// Shows a notification about `page` (already in the watch's language).
    fn notify(&self, title: &str, body: &str, page: &str);
    /// The watch's state changed: refresh the window and the tray menu.
    fn changed(&self, status: &Status);
}

/// The tray menu's two changing texts, for the state in `file`: (watching, notifications).
pub fn tray_texts(file: &WatchFile) -> (String, String) {
    let watching = if file.settings.watching {
        tr!("Pause watching")
    } else {
        tr!("Resume watching")
    };
    let notifications = if file.notifications_paused(now_ms()) {
        tr!("Resume notifications")
    } else {
        tr!("Pause notifications for 1 hour")
    };
    (watching, notifications)
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
    /// Logs the last check could not read.
    logs_hidden: Mutex<Vec<String>>,
    /// Where automatic scans save their reports (the data folder's `scans`); unset: no scans.
    pub(crate) scans: OnceLock<PathBuf>,
    /// An automatic scan runs in this copy.
    pub(crate) scan_running: AtomicBool,
    /// Battery, full screen and processor use, for automatic scans.
    pub(crate) conditions: crate::autoscan::SystemConditions,
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
            logs_hidden: Mutex::new(Vec::new()),
            scans: OnceLock::new(),
            scan_running: AtomicBool::new(false),
            conditions: crate::autoscan::SystemConditions::default(),
        }
    }

    /// Lets this copy run automatic scans, saving their reports in `dir`.
    pub fn set_scans_dir(&self, dir: PathBuf) {
        let _ = self.scans.set(dir);
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
            logs_hidden: if self.owner() {
                self.logs_hidden.lock().unwrap_or_else(PoisonError::into_inner).clone()
            } else {
                Vec::new()
            },
            autostart: crate::autostart::enabled(),
            recent: file.alerts.iter().take(5).cloned().collect(),
            auto_scan: crate::autoscan::view(
                &file.settings,
                &file.auto_scan,
                self.scan_running.load(Ordering::Acquire),
            ),
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

    /// Turns the checks on or off (`None` toggles). Returns whether watching is on now.
    pub fn set_watching(&self, value: Option<bool>) -> bool {
        self.store
            .update(|file| {
                file.settings.watching = value.unwrap_or(!file.settings.watching);
                file.settings.watching
            })
            .unwrap_or(false)
    }

    /// Pauses notifications for an hour (true) or resumes them (false).
    pub fn pause_notifications(&self, pause: bool) {
        let _ = self.store.update(|file| {
            file.notify_paused_until = pause.then(|| now_ms() + PAUSE_MS);
        });
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
        *self.logs_hidden.lock().unwrap_or_else(PoisonError::into_inner) = current.logs_hidden.clone();
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

    /// Starts the background thread (checks only while this copy owns the watch). `host` is the
    /// front end: it gets the tray icon when this copy takes the watch over, shows the
    /// notifications and refreshes what shows the watch's state.
    pub fn start(self: &Arc<Self>, host: Arc<dyn WatchHost>) {
        let watcher = Arc::clone(self);
        let spawned = thread::Builder::new()
            .name("vigil-watch".into())
            .spawn(move || watcher.run(&host));
        if let Err(error) = spawned {
            eprintln!("could not start the watch: {error}");
        }
    }

    fn run(self: &Arc<Self>, host: &Arc<dyn WatchHost>) {
        crate::notify::init_thread();
        let mut next_check = Instant::now();
        loop {
            if !self.owner() && claim_watch() {
                self.owner.store(true, Ordering::Release);
                host.became_owner();
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
                            host.notify(&title, &body, &target);
                        }
                    });
                    // An automatic scan, when one is due (it runs on its own thread).
                    crate::autoscan::tick(self, host);
                    self.state_changed();
                    host.changed(&self.status());
                }
            } else if self.state_changed() {
                // The other copy (or a window of this one) changed the state: show it.
                host.changed(&self.status());
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
            ..Fingerprint::default()
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

#[cfg(test)]
mod live {
    use super::*;

    #[test]
    #[ignore = "reads this computer; run by hand"]
    fn cycle_cost() {
        let start = Instant::now();
        let first = read_fingerprint(false, &Fingerprint::default());
        let cold = start.elapsed();
        let mut times = Vec::new();
        let mut previous = first;
        for _ in 0..5 {
            let start = Instant::now();
            let next = read_fingerprint(false, &previous);
            times.push(start.elapsed());
            previous = merged(&previous, next);
        }
        times.sort();
        println!("cycle: cold {cold:?}, warm median {:?}", times[times.len() / 2]);
        println!(
            "sections: hook sources {} ({} values), drivers {:?}, hosts redirects {:?}, logs marked {}, logs hidden {:?}",
            previous.hooks.len(),
            previous.hooks.values().map(BTreeMap::len).sum::<usize>(),
            previous.drivers.as_ref().map(BTreeMap::len),
            previous.hosts.as_ref().map(|h| h.redirects.len()),
            previous.events.len(),
            read_fingerprint(false, &previous).logs_hidden,
        );
    }
}

#[cfg(test)]
mod more_tests {
    use std::cell::RefCell;

    use super::*;

    fn titles(alerts: &[Alert]) -> Vec<(String, String, String)> {
        alerts
            .iter()
            .map(|a| (a.kind.clone(), a.severity.clone(), a.title.clone()))
            .collect()
    }

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn hook_values_become_alerts() {
        vigil_i18n::with_language("en", || {
            let old = BTreeMap::from([
                ("ifeo".to_string(), values(&[])),
                ("appinit".to_string(), values(&[("LoadAppInit_DLLs", "0")])),
                ("lsa".to_string(), values(&[("Security Packages", "kerberos; msv1_0")])),
                ("exclusions_policy_paths".to_string(), values(&[])),
            ]);
            let new = BTreeMap::from([
                (
                    "ifeo".to_string(),
                    values(&[(r"sethc.exe\Debugger", r"C:\Windows\System32\cmd.exe")]),
                ),
                ("appinit".to_string(), values(&[("LoadAppInit_DLLs", "0")])),
                (
                    "lsa".to_string(),
                    values(&[("Security Packages", "kerberos; msv1_0; evil")]),
                ),
                (
                    "exclusions_policy_paths".to_string(),
                    values(&[(r"C:\Users\jdoe\Downloads", "0")]),
                ),
                // Not read before (a source this copy could not read): not compared.
                (
                    "netsh".to_string(),
                    values(&[("Contoso", r"C:\ProgramData\Contoso\h.dll")]),
                ),
            ]);
            let alerts = hook_alerts(&old, &new);
            let got = titles(&alerts);
            assert_eq!(got.len(), 3, "{got:?}");
            assert_eq!(
                got[0],
                (
                    "security".into(),
                    "critical".into(),
                    r"New Microsoft Defender exclusion: C:\Users\jdoe\Downloads".into()
                )
            );
            assert_eq!(alerts[0].target, "protection");
            assert_eq!(
                got[1],
                (
                    "hook".into(),
                    "critical".into(),
                    "A program now starts instead of sethc.exe".into()
                )
            );
            assert_eq!(got[2].1, "critical");
            assert!(got[2].2.starts_with("Change in LSA packages"));
            // The same values again: nothing.
            assert!(hook_alerts(&new, &new).is_empty());
        });
    }

    #[test]
    fn hook_severity_by_place() {
        vigil_i18n::with_language("en", || {
            let ifeo = hook_alert("ifeo", "HKLM", r"notepad.exe\Debugger", "x.exe", false).expect("alert");
            assert_eq!(ifeo.severity, "warning");
            assert!(hook_alert("appinit", "HKLM", "LoadAppInit_DLLs", "0", true).is_none());
            let load = hook_alert("appinit", "HKLM", "LoadAppInit_DLLs", "1", true).expect("alert");
            assert_eq!(load.severity, "warning");
            let monitor =
                hook_alert("print_monitor", "HKLM", r"Local Port\Driver", "localspl.dll", false).expect("alert");
            assert_eq!(monitor.severity, "info");
            let monitor = hook_alert(
                "print_monitor",
                "HKLM",
                r"Contoso\Driver",
                r"C:\ProgramData\Contoso\mon.dll",
                false,
            )
            .expect("alert");
            assert_eq!(monitor.severity, "warning");
            assert!(hook_alert("exclusion", "HKLM", r"C:\x", "0", true).is_none());
        });
    }

    fn driver(path: &str) -> DriverPrint {
        DriverPrint {
            path: path.into(),
            start: "system".into(),
        }
    }

    #[test]
    fn drivers_become_alerts() {
        vigil_i18n::with_language("en", || {
            let old = BTreeMap::from([
                (
                    "nvlddmkm".to_string(),
                    driver(r"\SystemRoot\System32\DriverStore\FileRepository\nv_1\nvlddmkm.sys"),
                ),
                (
                    "contoso".to_string(),
                    driver(r"\SystemRoot\System32\drivers\contoso.sys"),
                ),
            ]);
            let new = BTreeMap::from([
                // A driver update within the driver store: not news.
                (
                    "nvlddmkm".to_string(),
                    driver(r"\SystemRoot\System32\DriverStore\FileRepository\nv_2\nvlddmkm.sys"),
                ),
                // Moved to a folder users can write to.
                ("contoso".to_string(), driver(r"\??\C:\ProgramData\Contoso\contoso.sys")),
                ("tcpip2".to_string(), driver("")),
                (
                    "evil".to_string(),
                    driver(r"\??\C:\Users\jdoe\AppData\Local\Temp\e.sys"),
                ),
                ("vendor".to_string(), driver(r"\??\D:\Tools\vendor.sys")),
            ]);
            let got = titles(&driver_alerts(&old, &new));
            assert_eq!(
                got,
                vec![
                    (
                        "driver".into(),
                        "critical".into(),
                        "Driver file changed: contoso".into()
                    ),
                    (
                        "driver".into(),
                        "critical".into(),
                        "New driver outside the Windows driver folders: evil".into()
                    ),
                    ("driver".into(), "info".into(), "New driver: tcpip2".into()),
                    (
                        "driver".into(),
                        "warning".into(),
                        "New driver outside the Windows driver folders: vendor".into()
                    ),
                ]
            );
        });
    }

    #[test]
    fn hosts_lines_are_read() {
        let text = "# comment\n127.0.0.1 localhost\n::1 localhost\n0.0.0.0 ads.example # blocked\n\
                    203.0.113.5 Update.Microsoft.com download.windowsupdate.com\nnot-an-ip example.org\n";
        assert_eq!(
            hosts_redirects(text),
            values(&[
                ("ads.example", "0.0.0.0"),
                ("download.windowsupdate.com", "203.0.113.5"),
                ("update.microsoft.com", "203.0.113.5"),
            ])
        );
    }

    fn hosts(hash: &str, pairs: &[(&str, &str)]) -> HostsPrint {
        HostsPrint {
            size: 10,
            modified: 1,
            hash: hash.into(),
            redirects: values(pairs),
        }
    }

    #[test]
    fn hosts_changes_become_alerts() {
        vigil_i18n::with_language("en", || {
            let old = hosts("a", &[("ads.example", "0.0.0.0")]);
            assert!(hosts_alert(&old, &old.clone()).is_none());
            let blocking = hosts("b", &[("ads.example", "0.0.0.0"), ("tracker.example", "0.0.0.0")]);
            let found = hosts_alert(&old, &blocking).expect("alert");
            assert_eq!(found.severity, "info");
            assert_eq!(found.title, "The hosts file now redirects tracker.example");
            let fake = hosts("c", &[("shop.example", "203.0.113.9")]);
            assert_eq!(hosts_alert(&old, &fake).expect("alert").severity, "warning");
            let blocked_updates = hosts("d", &[("update.microsoft.com", "0.0.0.0")]);
            assert_eq!(hosts_alert(&old, &blocked_updates).expect("alert").severity, "critical");
            // Lines removed only: nothing new is redirected.
            assert!(hosts_alert(&blocking, &hosts("e", &[])).is_none());
        });
    }

    #[test]
    fn the_hosts_file_is_read_only_when_it_changed() {
        let dir = std::env::temp_dir().join(format!("vigil-hosts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("hosts");
        std::fs::write(&path, "203.0.113.5 bank.example\n").expect("write");
        let first = read_hosts(&path, None).expect("read");
        assert_eq!(
            first.redirects.get("bank.example").map(String::as_str),
            Some("203.0.113.5")
        );
        // Same size and time: the previous print is kept without reading the file.
        let mut kept = first.clone();
        kept.redirects.clear();
        assert_eq!(read_hosts(&path, Some(&kept)), Some(kept.clone()));
        // A missing file redirects nothing.
        assert_eq!(read_hosts(&dir.join("none"), None), Some(HostsPrint::default()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A log source in memory: each log's events, and logs it cannot read.
    #[derive(Default)]
    struct FakeLogs {
        records: RefCell<BTreeMap<String, Vec<LogEvent>>>,
        hidden: Vec<String>,
    }

    impl FakeLogs {
        fn add(&self, log: &str, event_id: u32, record: u64, time: i64, data: &[(&str, &str)]) {
            self.records.borrow_mut().entry(log.into()).or_default().push(LogEvent {
                log: log.into(),
                provider: String::new(),
                event_id,
                record_id: record,
                time_ms: time,
                data: data.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            });
        }
    }

    impl LogSource for FakeLogs {
        fn newest(&self, log: &str) -> Result<Option<(u64, i64)>, ()> {
            if self.hidden.iter().any(|h| h == log) {
                return Err(());
            }
            Ok(self
                .records
                .borrow()
                .get(log)
                .and_then(|list| list.iter().max_by_key(|e| e.record_id))
                .map(|e| (e.record_id, e.time_ms)))
        }

        fn read_after(&self, log: &str, ids: &[u32], after: u64, max: usize) -> Result<Vec<LogEvent>, ()> {
            let mut out: Vec<LogEvent> = self
                .records
                .borrow()
                .get(log)
                .map(|list| {
                    list.iter()
                        .filter(|e| e.record_id > after && ids.contains(&e.event_id))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            out.sort_by_key(|e| e.record_id);
            out.truncate(max);
            Ok(out)
        }
    }

    #[test]
    fn logs_are_read_from_where_the_last_check_stopped() {
        let logs = FakeLogs {
            hidden: vec![SECURITY_LOG.into()],
            ..FakeLogs::default()
        };
        logs.add(SYSTEM_LOG, 7045, 10, 1_000, &[("ServiceName", "Old")]);
        // First read: only marked (what the log already holds is not news).
        let (marks, hits, hidden) = read_events(&logs, &BTreeMap::new(), 5_000);
        assert!(hits.is_empty());
        assert_eq!(hidden, vec![SECURITY_LOG.to_string()]);
        assert_eq!(
            marks[SYSTEM_LOG],
            LogMark {
                record: 10,
                time: 1_000
            }
        );
        assert_eq!(marks[DEFENDER_LOG], LogMark { record: 0, time: 5_000 }, "an empty log");
        assert!(!marks.contains_key(SECURITY_LOG));

        // New events after the mark (other ids are not read); then a restart: no replay.
        logs.add(SYSTEM_LOG, 7036, 11, 2_000, &[]);
        logs.add(SYSTEM_LOG, 7045, 12, 2_100, &[("ServiceName", "New")]);
        let (next, hits, _) = read_events(&logs, &marks, 6_000);
        assert_eq!(hits.iter().map(|e| e.record_id).collect::<Vec<_>>(), vec![12]);
        assert_eq!(next[SYSTEM_LOG].record, 12);
        let (again, hits, _) = read_events(&logs, &next, 7_000);
        assert!(hits.is_empty(), "nothing is replayed");
        assert_eq!(again[SYSTEM_LOG].record, 12);

        // A hidden log keeps its old mark when merged.
        let old = Fingerprint {
            events: BTreeMap::from([(SECURITY_LOG.to_string(), LogMark { record: 7, time: 1 })]),
            ..Fingerprint::default()
        };
        let now = Fingerprint {
            events: again,
            ..Fingerprint::default()
        };
        assert_eq!(merged(&old, now).events[SECURITY_LOG].record, 7);
    }

    #[test]
    fn many_events_are_read_over_several_checks() {
        let logs = FakeLogs::default();
        logs.add(SYSTEM_LOG, 104, 1, 1, &[]);
        let (marks, _, _) = read_events(&logs, &BTreeMap::new(), 10);
        for record in 2..(2 + MAX_EVENTS as u64 + 10) {
            logs.add(SYSTEM_LOG, 104, record, record as i64, &[("Channel", "Application")]);
        }
        let (marks, first, _) = read_events(&logs, &marks, 20);
        assert_eq!(first.len(), MAX_EVENTS);
        assert_eq!(marks[SYSTEM_LOG].record, first.last().map_or(0, |e| e.record_id));
        let (_, rest, _) = read_events(&logs, &marks, 30);
        assert_eq!(rest.len(), 10, "the next check goes on from there");
    }

    #[test]
    fn a_cleared_log_is_read_by_time() {
        let logs = FakeLogs::default();
        logs.add(SYSTEM_LOG, 104, 3, 500, &[]);
        let previous = BTreeMap::from([(SYSTEM_LOG.to_string(), LogMark { record: 900, time: 400 })]);
        let (marks, hits, _) = read_events(&logs, &previous, 1_000);
        assert_eq!(hits.len(), 1);
        assert_eq!(marks[SYSTEM_LOG].record, 3);
        let logs = FakeLogs::default();
        logs.add(SYSTEM_LOG, 104, 3, 300, &[]);
        let (_, hits, _) = read_events(&logs, &previous, 1_000);
        assert!(hits.is_empty(), "older than the last mark");
    }

    fn event(log: &str, id: u32, data: &[(&str, &str)]) -> LogEvent {
        LogEvent {
            log: log.into(),
            provider: String::new(),
            event_id: id,
            record_id: 1,
            time_ms: 1,
            data: data.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    #[test]
    fn events_become_alerts_once() {
        vigil_i18n::with_language("en", || {
            let new = Fingerprint {
                services: Some(BTreeMap::from([(
                    "contosohelper".to_string(),
                    ServicePrint {
                        display: "Contoso Helper".into(),
                        start: "auto".into(),
                        path: r"C:\Program Files\Contoso\h.exe".into(),
                        dll: String::new(),
                    },
                )])),
                security: Some(BTreeMap::from([("defender".to_string(), true)])),
                ..Fingerprint::default()
            };
            let threat = [
                ("Threat Name", "Trojan:Win32/Fake"),
                ("Path", r"file:_C:\Users\jdoe\x.exe"),
            ];
            let hits = vec![
                // Still installed: the services section reports it.
                event(SYSTEM_LOG, 7045, &[("ServiceName", "Contoso Helper")]),
                // Installed and gone within the minute: only the log knows.
                event(
                    SYSTEM_LOG,
                    7045,
                    &[("ServiceName", "Fleeting"), ("ImagePath", r"C:\Users\jdoe\f.exe")],
                ),
                event(SECURITY_LOG, 1102, &[("SubjectUserName", "jdoe")]),
                event(
                    SECURITY_LOG,
                    4732,
                    &[
                        ("TargetSid", "S-1-5-32-555"),
                        ("MemberName", "-"),
                        ("MemberSid", "S-1-5-21-1-2-3-1002"),
                    ],
                ),
                event(
                    SECURITY_LOG,
                    4732,
                    &[
                        ("TargetSid", "S-1-5-32-544"),
                        ("MemberName", "-"),
                        ("MemberSid", "S-1-5-21-1-2-3-1002"),
                        ("SubjectUserName", "jdoe"),
                    ],
                ),
                event(DEFENDER_LOG, 1116, &threat),
                event(DEFENDER_LOG, 1116, &threat),
                // Defender is on again now: the switch did not see it, the log did.
                event(DEFENDER_LOG, 5001, &[]),
                event(
                    DEFENDER_LOG,
                    5007,
                    &[(
                        "New Value",
                        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Temp = 0x0",
                    )],
                ),
                event(
                    DEFENDER_LOG,
                    5007,
                    &[("New Value", r"HKLM\SOFTWARE\Microsoft\Windows Defender\Scan\X = 0x1")],
                ),
                event(
                    WMI_LOG,
                    5861,
                    &[
                        ("Namespace", "//./root/subscription"),
                        ("CONSUMER", "CommandLineEventConsumer=\"x\""),
                    ],
                ),
            ];
            let old = Fingerprint::default();
            let alerts = event_alerts(&hits, &old, &new);
            let got: Vec<String> = alerts.iter().map(|a| a.title.clone()).collect();
            assert_eq!(
                got,
                vec![
                    "Service installed: Fleeting",
                    "The Security log was cleared",
                    "Added to Administrators: S-1-5-21-1-2-3-1002",
                    "Microsoft Defender found a threat: Trojan:Win32/Fake",
                    "Microsoft Defender real-time protection was turned off",
                    r"New Microsoft Defender exclusion: C:\Temp",
                    "New permanent WMI event subscription",
                ]
            );
            assert_eq!(alerts[3].detail, r"C:\Users\jdoe\x.exe");

            // Defender still off: the switch reports it. A subscription reported before: not again.
            let off = Fingerprint {
                security: Some(BTreeMap::from([("defender".to_string(), false)])),
                ..Fingerprint::default()
            };
            let remembered = merged(
                &Fingerprint::default(),
                Fingerprint {
                    event_hits: hits.clone(),
                    ..Fingerprint::default()
                },
            );
            assert_eq!(remembered.wmi_seen.len(), 1);
            let again = event_alerts(&hits[7..], &remembered, &off);
            assert_eq!(
                again.iter().map(|a| a.title.as_str()).collect::<Vec<_>>(),
                vec![r"New Microsoft Defender exclusion: C:\Temp"]
            );
            // The exclusion keys are readable: the hook section reports exclusions instead.
            let readable = Fingerprint {
                hooks: BTreeMap::from([("exclusions_paths".to_string(), BTreeMap::new())]),
                ..off
            };
            assert!(event_alerts(&hits[8..9], &remembered, &readable).is_empty());
        });
    }

    #[test]
    fn event_alerts_are_capped() {
        vigil_i18n::with_language("en", || {
            let hits: Vec<LogEvent> = (0..40)
                .map(|i| event(SYSTEM_LOG, 7045, &[("ServiceName", &format!("svc{i}"))]))
                .collect();
            let alerts = event_alerts(&hits, &Fingerprint::default(), &Fingerprint::default());
            assert_eq!(alerts.len(), MAX_EVENT_ALERTS + 1);
            assert_eq!(alerts[MAX_EVENT_ALERTS].title, "15 more events from the Windows logs");
        });
    }

    #[test]
    fn the_first_check_with_new_sections_is_quiet() {
        // Saved by 1.5.0: no hooks, drivers, hosts or log marks.
        let old = Fingerprint {
            security: Some(BTreeMap::from([("defender".to_string(), true)])),
            version: 2,
            ..Fingerprint::default()
        };
        let new = Fingerprint {
            security: Some(BTreeMap::from([
                ("defender".to_string(), true),
                ("wdigest".to_string(), false),
                ("lsa".to_string(), false),
            ])),
            hooks: BTreeMap::from([("ifeo".to_string(), values(&[(r"sethc.exe\Debugger", "cmd.exe")]))]),
            drivers: Some(BTreeMap::from([("evil".to_string(), driver(r"C:\Users\jdoe\e.sys"))])),
            hosts: Some(hosts("x", &[("bank.example", "203.0.113.5")])),
            ..Fingerprint::default()
        };
        assert!(diff(&old, &new).is_empty());
        let next = merged(&old, new.clone());
        assert_eq!(next.version, FINGERPRINT_VERSION);
        assert!(diff(&next, &new).is_empty());
    }

    #[test]
    fn new_switches_and_kinds() {
        vigil_i18n::with_language("en", || {
            let old = Fingerprint {
                security: Some(BTreeMap::from([
                    ("wdigest".to_string(), true),
                    ("defender.tamper".to_string(), true),
                ])),
                ..Fingerprint::default()
            };
            let new = Fingerprint {
                security: Some(BTreeMap::from([
                    ("wdigest".to_string(), false),
                    ("defender.tamper".to_string(), false),
                ])),
                ..Fingerprint::default()
            };
            let alerts = diff(&old, &new);
            assert_eq!(alerts.len(), 2);
            assert!(alerts.iter().all(|a| a.severity == "critical"));
            assert_eq!(alerts[0].target, "protection");
            assert_eq!(alerts[1].target, "posture");
        });
        let mut settings = WatchSettings::default();
        assert!(settings.notifies("hook") && settings.notifies("event"));
        settings.notify_hooks = false;
        settings.notify_events = false;
        assert!(!settings.notifies("driver") && !settings.notifies("hosts") && !settings.notifies("event"));
        // Settings saved before these switches existed turn them on.
        let old: WatchSettings = serde_json::from_str(r#"{"watching":true}"#).expect("settings");
        assert!(old.notify_hooks && old.notify_events);
    }

    #[test]
    fn rendered_log_events_are_understood() {
        vigil_i18n::with_language("en", || {
            let cleared = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Eventlog"/><EventID>104</EventID><Level>4</Level>
<TimeCreated SystemTime="2026-11-20T10:00:00.0000000Z"/><EventRecordID>77</EventRecordID><Channel>System</Channel>
<Computer>PC-VICTIM</Computer></System><UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
<SubjectUserName>jdoe</SubjectUserName><SubjectDomainName>PC-VICTIM</SubjectDomainName><Channel>Application</Channel>
<BackupPath></BackupPath></LogFileCleared></UserData></Event>"#;
            let wmi = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-WMI-Activity"/><EventID>5861</EventID><Level>0</Level>
<TimeCreated SystemTime="2026-11-20T10:01:00.0000000Z"/><EventRecordID>12</EventRecordID>
<Channel>Microsoft-Windows-WMI-Activity/Operational</Channel><Computer>PC-VICTIM</Computer></System>
<UserData><Operation_ESStoConsumerBinding xmlns="http://manifests.microsoft.com/win/2006/windows/WMI">
<Namespace>//./root/subscription</Namespace><ESS>Updater</ESS>
<CONSUMER>CommandLineEventConsumer="Updater"</CONSUMER><PossibleCause>Binding EventFilter</PossibleCause>
</Operation_ESStoConsumerBinding></UserData></Event>"#;
            let hits: Vec<LogEvent> = [(SYSTEM_LOG, cleared), (WMI_LOG, wmi)]
                .iter()
                .filter_map(|(log, xml)| LogEvent::from_xml(log, xml))
                .collect();
            assert_eq!(hits.len(), 2);
            let alerts = event_alerts(&hits, &Fingerprint::default(), &Fingerprint::default());
            assert_eq!(alerts[0].title, "The Application log was cleared");
            assert!(alerts[0].detail.starts_with("Cleared by jdoe."));
            assert!(
                alerts[1]
                    .detail
                    .starts_with("CommandLineEventConsumer=\"Updater\" (in //./root/subscription)")
            );
        });
    }
}
