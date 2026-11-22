//! Windows Update, as this computer recorded it. READ-ONLY and LOCAL ONLY: Vigil never searches
//! for updates (a search contacts Microsoft's servers, and Vigil sends nothing off the computer),
//! never downloads, installs, pauses or restarts anything.
//!
//! What is read:
//! - the update history: from the Windows Update Agent (`IUpdateSearcher::QueryHistory`, a local
//!   read of its data store) when the Windows Update service already runs; otherwise from the
//!   System log (Windows Update events 19 and 20), so reading never starts the service;
//! - the last successful install and search (the agent's `Auto Update\Results` keys), a pending
//!   restart (Windows Update, servicing and pending file renames), paused updates, active hours;
//! - the policies that block, defer or redirect updates (WSUS), and the service's start type;
//! - the Windows build, the servicing stack, and when Microsoft Defender's security intelligence
//!   was last updated.
//!
//! [`finish`] turns that into grouped failures and plain hints; the app writes the texts.

use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::Duration;

use serde::Serialize;
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY};

use crate::hooks::{Key, text};
use crate::reliability::{LogReader, Record, iso_utc_ms, local_time};
use crate::util::{hklm_dword, hklm_string, now_unix_ms};

/// History entries kept (newest first).
pub const MAX_HISTORY: usize = 200;
/// How long the Windows Update Agent may take to hand out its history.
const AGENT_TIMEOUT: Duration = Duration::from_secs(20);
const DAY_MS: i64 = 86_400_000;
/// A restart pending this long becomes a hint.
const RESTART_HINT_DAYS: i64 = 2;
/// No successful install for this long becomes a hint.
const STALE_INSTALL_DAYS: i64 = 45;

const AU_RESULTS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results";
const UX_SETTINGS: &str = r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings";
const POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
const POLICY_AU: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// One install or removal from the history, newest first.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateEntry {
    pub time_ms: i64,
    /// Local time, ISO 8601.
    pub time: String,
    pub title: String,
    /// "KB5040442", or "" when the title names none.
    pub kb: String,
    /// "install" or "uninstall".
    pub operation: String,
    /// "succeeded", "succeeded_with_errors", "failed", "aborted", "in_progress" or "not_started".
    pub result: String,
    /// The error, as `0x80070643` ("" when it succeeded).
    pub code: String,
}

/// Failures of one update.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FailureGroup {
    pub title: String,
    pub kb: String,
    pub count: usize,
    pub last_ms: i64,
    pub last_time: String,
    /// The error of the last failure.
    pub code: String,
    /// The same update installed later.
    pub fixed_later: bool,
}

/// Policies that change how updates arrive (Group Policy or MDM written to the registry).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePolicy {
    /// Any of the values below is set.
    pub set: bool,
    /// A WSUS server the organization runs ("" when none).
    pub wsus_server: String,
    pub use_wsus: bool,
    /// Automatic updates turned off (`NoAutoUpdate` = 1).
    pub no_auto_update: bool,
    /// `AUOptions`: 2 notify, 3 download, 4 install on a schedule, 5 let the administrator choose.
    pub au_options: Option<u32>,
    /// The Windows Update settings page is turned off for users.
    pub disable_access: bool,
    /// Windows Update's internet locations are blocked (only the organization's server).
    pub block_internet: bool,
    pub defer_feature_days: Option<u32>,
    pub defer_quality_days: Option<u32>,
    /// Pinned to a release ("23H2"; "" when not).
    pub target_version: String,
}

/// A plain pointer drawn from the state; the app writes its text from `code`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateHint {
    /// "failing_repeatedly", "updates_disabled", "service_disabled", "paused", "restart_pending",
    /// "no_recent_install", "managed" or "deferred".
    pub code: &'static str,
    /// "warn" or "info".
    pub severity: &'static str,
    pub subject: String,
    pub count: u64,
    pub detail: String,
}

/// Everything the Windows Update page shows.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Updates {
    pub read_ms: i64,
    /// "Windows 11 Pro", "24H2", "26100", 2454.
    pub product: String,
    pub display_version: String,
    pub build: String,
    pub ubr: Option<u32>,
    /// The newest servicing stack version Windows lists ("" when unknown).
    pub servicing_stack: String,
    /// "agent" (the Windows Update Agent), "events" (the System log) or "none".
    pub history_source: String,
    pub history: Vec<UpdateEntry>,
    pub failures: Vec<FailureGroup>,
    /// The last successful install: the agent's record, or else the newest success in the history.
    pub last_install_ms: Option<i64>,
    pub last_install_title: String,
    pub last_search_ms: Option<i64>,
    pub reboot_pending: bool,
    /// "windows_update", "servicing" or "file_rename".
    pub reboot_reasons: Vec<String>,
    /// Since when Windows Update or servicing has been waiting for a restart (when it says).
    pub reboot_since_ms: Option<i64>,
    pub paused: bool,
    pub pause_until_ms: Option<i64>,
    pub pause_feature_until_ms: Option<i64>,
    pub pause_quality_until_ms: Option<i64>,
    pub active_hours_start: Option<u32>,
    pub active_hours_end: Option<u32>,
    /// Windows sets the active hours from how the computer is used.
    pub active_hours_automatic: bool,
    pub policy: UpdatePolicy,
    /// The Windows Update service: "auto", "delayed", "demand", "disabled" or "" (unknown).
    pub service_start: String,
    pub service_running: Option<bool>,
    /// Updates cannot arrive: turned off by policy or the service is disabled.
    pub disabled: bool,
    pub defender_version: String,
    pub defender_updated_ms: Option<i64>,
    pub hints: Vec<UpdateHint>,
    /// "history_from_events" (the service was not running) or "history_unreadable".
    pub notes: Vec<String>,
}

// ------------------------------------------------------------------------------ reading

/// Reads the local Windows Update state. Never searches, never starts the service.
pub fn read() -> Updates {
    let mut u = Updates {
        read_ms: now_unix_ms(),
        product: hklm_string(CURRENT_VERSION, "ProductName"),
        display_version: hklm_string(CURRENT_VERSION, "DisplayVersion"),
        build: hklm_string(CURRENT_VERSION, "CurrentBuild"),
        ubr: hklm_dword(CURRENT_VERSION, "UBR"),
        servicing_stack: servicing_stack(),
        ..Updates::default()
    };
    // Windows 11 still says "Windows 10" in ProductName: the build tells them apart.
    if u.build.parse::<u32>().is_ok_and(|b| b >= 22000) && u.product.starts_with("Windows 10") {
        u.product = u.product.replacen("Windows 10", "Windows 11", 1);
    }
    u.last_install_ms = registry_time(&format!(r"{AU_RESULTS}\Install"), "LastSuccessTime");
    u.last_search_ms = registry_time(&format!(r"{AU_RESULTS}\Detect"), "LastSuccessTime");
    read_reboot(&mut u);
    u.pause_until_ms = registry_time(UX_SETTINGS, "PauseUpdatesExpiryTime");
    u.pause_feature_until_ms = registry_time(UX_SETTINGS, "PauseFeatureUpdatesEndTime");
    u.pause_quality_until_ms = registry_time(UX_SETTINGS, "PauseQualityUpdatesEndTime");
    u.active_hours_start = hklm_dword(UX_SETTINGS, "ActiveHoursStart");
    u.active_hours_end = hklm_dword(UX_SETTINGS, "ActiveHoursEnd");
    u.active_hours_automatic = hklm_dword(UX_SETTINGS, "SmartActiveHoursState") == Some(1);
    u.policy = read_policy();
    u.service_start = start_type(r"SYSTEM\CurrentControlSet\Services\wuauserv");
    u.service_running = service_running("wuauserv");
    read_defender(&mut u);

    let history = if u.service_running == Some(true) {
        match agent_history(MAX_HISTORY) {
            Ok(history) => Some(("agent", history)),
            Err(_) => None,
        }
    } else {
        None
    };
    match history {
        Some((source, history)) => {
            u.history_source = source.into();
            u.history = history;
        }
        None => match event_history(MAX_HISTORY) {
            Some(history) => {
                u.history_source = "events".into();
                u.history = history;
                u.notes.push("history_from_events".into());
            }
            None => {
                u.history_source = "none".into();
                u.notes.push("history_unreadable".into());
            }
        },
    }
    finish(&mut u, now_unix_ms());
    u
}

/// A registry time ("2026-01-01 10:05:00" or "2026-01-01T10:05:00Z", UTC) as Unix ms.
fn registry_time(key: &str, value: &str) -> Option<i64> {
    let text = hklm_string(key, value);
    if text.is_empty() { None } else { iso_utc_ms(&text) }
}

/// "auto", "delayed", "demand", "disabled" or "" from a service key's Start value.
fn start_type(key: &str) -> String {
    match hklm_dword(key, "Start") {
        Some(2) if hklm_dword(key, "DelayedAutostart") == Some(1) => "delayed",
        Some(2) => "auto",
        Some(3) => "demand",
        Some(4) => "disabled",
        Some(0 | 1) => "boot",
        _ => "",
    }
    .into()
}

/// Whether a service runs now (`None`: it could not be asked). Only its status is queried.
fn service_running(name: &str) -> Option<bool> {
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
        SERVICE_RUNNING, SERVICE_STATUS,
    };
    let wide = windows::core::HSTRING::from(name);
    // SAFETY: plain SCM calls; every handle opened here is closed before returning.
    unsafe {
        let manager = OpenSCManagerW(None, None, SC_MANAGER_CONNECT).ok()?;
        let result = match OpenServiceW(manager, &wide, SERVICE_QUERY_STATUS) {
            Ok(service) => {
                let mut status = SERVICE_STATUS::default();
                let read = QueryServiceStatus(service, &mut status).is_ok();
                let _ = CloseServiceHandle(service);
                read.then_some(status.dwCurrentState == SERVICE_RUNNING)
            }
            Err(_) => None,
        };
        let _ = CloseServiceHandle(manager);
        result
    }
}

fn open(sub: &str) -> Option<Key> {
    Key::open(HKEY_LOCAL_MACHINE, sub, KEY_WOW64_64KEY).ok().flatten()
}

fn read_reboot(u: &mut Updates) {
    let mut since: Option<i64> = None;
    for (reason, key) in [
        (
            "windows_update",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        ),
        (
            "servicing",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        ),
    ] {
        if let Some(key) = open(key) {
            u.reboot_reasons.push(reason.into());
            if let Some(written) = key.last_write_ms() {
                since = Some(since.map_or(written, |s| s.min(written)));
            }
        }
    }
    // Installers also ask Windows to replace files at the next start: a restart is pending, but
    // not one Windows Update waits for.
    let renames = open(r"SYSTEM\CurrentControlSet\Control\Session Manager")
        .and_then(|key| key.raw_values())
        .is_some_and(|values| {
            values.iter().any(|(name, kind, data)| {
                name.eq_ignore_ascii_case("PendingFileRenameOperations") && !text(*kind, data).trim().is_empty()
            })
        });
    if renames {
        u.reboot_reasons.push("file_rename".into());
    }
    u.reboot_pending = !u.reboot_reasons.is_empty();
    u.reboot_since_ms = since;
}

fn read_policy() -> UpdatePolicy {
    let days = |enabled: &str, period: &str| {
        (hklm_dword(POLICY, enabled) == Some(1))
            .then(|| hklm_dword(POLICY, period))
            .flatten()
    };
    let p = UpdatePolicy {
        wsus_server: hklm_string(POLICY, "WUServer"),
        use_wsus: hklm_dword(POLICY_AU, "UseWUServer") == Some(1),
        no_auto_update: hklm_dword(POLICY_AU, "NoAutoUpdate") == Some(1),
        au_options: hklm_dword(POLICY_AU, "AUOptions"),
        disable_access: hklm_dword(POLICY, "DisableWindowsUpdateAccess") == Some(1),
        block_internet: hklm_dword(POLICY, "DoNotConnectToWindowsUpdateInternetLocations") == Some(1),
        defer_feature_days: days("DeferFeatureUpdates", "DeferFeatureUpdatesPeriodInDays"),
        defer_quality_days: days("DeferQualityUpdates", "DeferQualityUpdatesPeriodInDays"),
        target_version: if hklm_dword(POLICY, "TargetReleaseVersion") == Some(1) {
            hklm_string(POLICY, "TargetReleaseVersionInfo")
        } else {
            String::new()
        },
        set: false,
    };
    with_set(p)
}

fn with_set(mut p: UpdatePolicy) -> UpdatePolicy {
    p.set = !p.wsus_server.is_empty()
        || p.use_wsus
        || p.no_auto_update
        || p.au_options.is_some()
        || p.disable_access
        || p.block_internet
        || p.defer_feature_days.is_some()
        || p.defer_quality_days.is_some()
        || !p.target_version.is_empty();
    p
}

/// The newest version under `Component Based Servicing\Version` ("" when unknown).
fn servicing_stack() -> String {
    let Some(values) = open(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Version")
        .and_then(|key| key.raw_values())
    else {
        return String::new();
    };
    newest_version(values.into_iter().map(|(name, _, _)| name))
}

/// The highest dotted version among `names` ("" when none parses).
pub fn newest_version(names: impl IntoIterator<Item = String>) -> String {
    let parse = |v: &str| -> Option<Vec<u32>> { v.split('.').map(|p| p.parse().ok()).collect() };
    names
        .into_iter()
        .filter_map(|name| parse(&name).map(|parts| (parts, name)))
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
        .unwrap_or_default()
}

fn read_defender(u: &mut Updates) {
    let Some(values) = open(r"SOFTWARE\Microsoft\Windows Defender\Signature Updates").and_then(|key| key.raw_values())
    else {
        return;
    };
    for (name, kind, data) in values {
        if name.eq_ignore_ascii_case("AVSignatureVersion") {
            u.defender_version = text(kind, &data);
        } else if name.eq_ignore_ascii_case("SignaturesLastUpdated") && data.len() >= 8 {
            let raw = i64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
            if raw > 0 {
                u.defender_updated_ms = Some(crate::util::filetime_to_unix_ms(raw));
            }
        }
    }
}

/// The history from the Windows Update Agent (a local read; it never searches). Only called while
/// the service runs, so the read does not start it.
fn agent_history(max: usize) -> Result<Vec<UpdateEntry>, String> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("vigil-updates".into())
        .spawn(move || {
            use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize};
            // SAFETY: COM for this worker thread only; balanced below when it succeeded.
            let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
            let result = agent_history_now(max);
            if initialized {
                // SAFETY: balances the successful CoInitializeEx above; every interface was released.
                unsafe { CoUninitialize() };
            }
            let _ = tx.send(result);
        })
        .map_err(|e| e.to_string())?;
    rx.recv_timeout(AGENT_TIMEOUT)
        .map_err(|_| "Windows Update did not answer in time".to_string())?
}

fn agent_history_now(max: usize) -> Result<Vec<UpdateEntry>, String> {
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
    use windows::Win32::System::UpdateAgent::{IUpdateSession, UpdateSession};
    // SAFETY: COM calls on a thread where COM is initialized; every interface is released when its
    // wrapper drops; BSTRs are owned by their wrappers.
    unsafe {
        let session: IUpdateSession =
            CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER).map_err(|e| e.to_string())?;
        let searcher = session.CreateUpdateSearcher().map_err(|e| e.to_string())?;
        let total = searcher.GetTotalHistoryCount().map_err(|e| e.to_string())?;
        let count = total.clamp(0, i32::try_from(max).unwrap_or(i32::MAX));
        if count == 0 {
            return Ok(Vec::new());
        }
        let entries = searcher.QueryHistory(0, count).map_err(|e| e.to_string())?;
        let n = entries.Count().map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for i in 0..n {
            let Ok(entry) = entries.get_Item(i) else { continue };
            let title = entry.Title().map(|b| b.to_string()).unwrap_or_default();
            let time_ms = entry.Date().map(ole_date_ms).unwrap_or(0);
            let result = entry.ResultCode().map(|c| c.0).unwrap_or(-1);
            let operation = entry.Operation().map(|o| o.0).unwrap_or(1);
            let hresult = entry.HResult().unwrap_or(0);
            out.push(entry_from(time_ms, title, operation, result, hresult));
        }
        out.sort_by_key(|e| std::cmp::Reverse(e.time_ms));
        Ok(out)
    }
}

/// An OLE automation date (days since 1899-12-30, UTC here) as Unix ms.
pub fn ole_date_ms(date: f64) -> i64 {
    ((date - 25_569.0) * DAY_MS as f64).round() as i64
}

/// An entry from the agent's codes (`OperationResultCode`, `UpdateOperation`, the HRESULT).
pub fn entry_from(time_ms: i64, title: String, operation: i32, result: i32, hresult: i32) -> UpdateEntry {
    let result = match result {
        0 => "not_started",
        1 => "in_progress",
        2 => "succeeded",
        3 => "succeeded_with_errors",
        4 => "failed",
        5 => "aborted",
        _ => "unknown",
    };
    let code = if matches!(result, "failed" | "aborted" | "succeeded_with_errors") && hresult != 0 {
        format!("0x{:08X}", hresult as u32)
    } else {
        String::new()
    };
    UpdateEntry {
        time: local_time(time_ms),
        time_ms,
        kb: kb_of(&title),
        title,
        operation: if operation == 2 { "uninstall" } else { "install" }.into(),
        result: result.into(),
        code,
    }
}

/// The history from the System log: Windows Update events 19 (installed) and 20 (failed).
fn event_history(max: usize) -> Option<Vec<UpdateEntry>> {
    const QUERY: &str =
        "*[System[Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and (EventID=19 or EventID=20)]]";
    let (records, _) = LogReader::default().query("System", QUERY, false).ok()?;
    let mut out: Vec<UpdateEntry> = records.iter().filter_map(|(xml, _)| entry_from_event(xml)).collect();
    out.sort_by_key(|e| std::cmp::Reverse(e.time_ms));
    out.truncate(max);
    Some(out)
}

/// A Windows Update event 19 or 20 as a history entry.
pub fn entry_from_event(xml: &str) -> Option<UpdateEntry> {
    let record = Record::parse(xml)?;
    let title = record.get("updateTitle", usize::MAX).to_string();
    if title.is_empty() {
        return None;
    }
    let (result, code) = match record.event_id {
        19 => ("succeeded", String::new()),
        20 => {
            let raw = record.get("errorCode", usize::MAX).trim().to_string();
            ("failed", normalize_code(&raw))
        }
        _ => return None,
    };
    Some(UpdateEntry {
        time_ms: record.time_ms,
        time: local_time(record.time_ms),
        kb: kb_of(&title),
        title,
        operation: "install".into(),
        result: result.into(),
        code,
    })
}

/// `0x80070643`, `80070643` or a decimal HRESULT as `0x80070643`.
fn normalize_code(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return String::new();
    }
    let hex = raw.trim_start_matches("0x").trim_start_matches("0X");
    if let Ok(value) = u32::from_str_radix(hex, 16)
        && (raw.starts_with("0x") || raw.starts_with("0X") || hex.len() == 8)
    {
        return format!("0x{value:08X}");
    }
    if let Ok(value) = raw.parse::<i64>() {
        return format!("0x{:08X}", value as u32);
    }
    raw.to_string()
}

/// "KB5040442" from a title ("" when it names none).
pub fn kb_of(title: &str) -> String {
    let upper = title.to_ascii_uppercase();
    let mut rest = upper.as_str();
    while let Some(at) = rest.find("KB") {
        let digits: String = rest[at + 2..].chars().take_while(char::is_ascii_digit).collect();
        if digits.len() >= 6 {
            return format!("KB{digits}");
        }
        rest = &rest[at + 2..];
    }
    String::new()
}

// ------------------------------------------------------------------------------ judging

/// Groups the failures and draws the hints (pure: tests call it on fixture data).
pub fn finish(u: &mut Updates, now_ms: i64) {
    u.history.sort_by_key(|e| std::cmp::Reverse(e.time_ms));
    u.history.truncate(MAX_HISTORY);
    let newest_success = u
        .history
        .iter()
        .find(|e| e.operation == "install" && e.result.starts_with("succeeded"))
        .map(|e| (e.time_ms, e.title.clone()));
    if let Some((time_ms, title)) = newest_success {
        // The agent's own record wins when it has one; the history gives the title.
        let last = u.last_install_ms.get_or_insert(time_ms);
        *last = (*last).max(time_ms);
        u.last_install_title = title;
    }
    u.paused = u.pause_until_ms.is_some_and(|until| until > now_ms);
    u.disabled = u.policy.no_auto_update || u.policy.disable_access || u.service_start == "disabled";
    u.failures = group_failures(&u.history);
    u.hints = hints(u, now_ms);
}

/// The identity of an update across its tries: its KB, or else its title.
fn identity(e: &UpdateEntry) -> String {
    if e.kb.is_empty() {
        e.title.to_lowercase()
    } else {
        e.kb.clone()
    }
}

/// Failures grouped by update, most recent first.
pub fn group_failures(history: &[UpdateEntry]) -> Vec<FailureGroup> {
    let mut groups: BTreeMap<String, FailureGroup> = BTreeMap::new();
    for e in history
        .iter()
        .filter(|e| e.operation == "install" && matches!(e.result.as_str(), "failed" | "aborted"))
    {
        let group = groups.entry(identity(e)).or_insert_with(|| FailureGroup {
            title: e.title.clone(),
            kb: e.kb.clone(),
            ..FailureGroup::default()
        });
        group.count += 1;
        if e.time_ms >= group.last_ms {
            group.last_ms = e.time_ms;
            group.last_time = e.time.clone();
            group.code = e.code.clone();
            group.title = e.title.clone();
        }
    }
    let mut out: Vec<FailureGroup> = groups
        .into_iter()
        .map(|(id, mut group)| {
            group.fixed_later = history.iter().any(|e| {
                e.operation == "install"
                    && e.result.starts_with("succeeded")
                    && identity(e) == id
                    && e.time_ms > group.last_ms
            });
            group
        })
        .collect();
    out.sort_by_key(|g| std::cmp::Reverse(g.last_ms));
    out
}

fn hint(code: &'static str, severity: &'static str, subject: &str, count: u64, detail: &str) -> UpdateHint {
    UpdateHint {
        code,
        severity,
        subject: subject.to_string(),
        count,
        detail: detail.to_string(),
    }
}

/// The hints, most pressing first.
pub fn hints(u: &Updates, now_ms: i64) -> Vec<UpdateHint> {
    let mut out = Vec::new();
    if u.policy.no_auto_update || u.policy.disable_access {
        out.push(hint("updates_disabled", "warn", "", 0, ""));
    } else if u.service_start == "disabled" {
        out.push(hint("service_disabled", "warn", "", 0, ""));
    }
    for group in u.failures.iter().filter(|g| g.count >= 2 && !g.fixed_later).take(3) {
        out.push(hint(
            "failing_repeatedly",
            "warn",
            &group.title,
            group.count as u64,
            &group.code,
        ));
    }
    if let Some(since) = u.reboot_since_ms
        && u.reboot_reasons.iter().any(|r| r != "file_rename")
    {
        let days = (now_ms - since).max(0) / DAY_MS;
        if days >= RESTART_HINT_DAYS {
            out.push(hint("restart_pending", "warn", "", days as u64, ""));
        }
    }
    if let Some(last) = u.last_install_ms {
        let days = (now_ms - last).max(0) / DAY_MS;
        if days >= STALE_INSTALL_DAYS && !u.paused {
            out.push(hint("no_recent_install", "warn", "", days as u64, ""));
        }
    }
    if u.paused
        && let Some(until) = u.pause_until_ms
    {
        let days = ((until - now_ms).max(0) + DAY_MS - 1) / DAY_MS;
        out.push(hint("paused", "info", "", days as u64, &local_time(until)));
    }
    if !u.policy.wsus_server.is_empty() && (u.policy.use_wsus || u.policy.block_internet) {
        out.push(hint("managed", "info", &u.policy.wsus_server, 0, ""));
    }
    let deferred = u
        .policy
        .defer_feature_days
        .unwrap_or(0)
        .max(u.policy.defer_quality_days.unwrap_or(0));
    if deferred > 0 {
        out.push(hint("deferred", "info", "", u64::from(deferred), ""));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    fn entry(days_ago: i64, title: &str, result: &str, code: &str) -> UpdateEntry {
        UpdateEntry {
            time_ms: NOW - days_ago * DAY_MS,
            time: String::new(),
            title: title.into(),
            kb: kb_of(title),
            operation: "install".into(),
            result: result.into(),
            code: code.into(),
        }
    }

    #[test]
    fn kb_numbers_dates_and_codes() {
        assert_eq!(
            kb_of("2026-01 Cumulative Update for Windows 11 (KB5040442)"),
            "KB5040442"
        );
        assert_eq!(
            kb_of("Security Intelligence Update - KB2267602 (Version 1.421.1)"),
            "KB2267602"
        );
        assert_eq!(kb_of("Contoso driver 1.2"), "");
        assert_eq!(kb_of("KB12 short"), "");
        assert_eq!(ole_date_ms(25_569.0), 0);
        assert_eq!(ole_date_ms(25_570.5), DAY_MS + DAY_MS / 2);
        assert_eq!(normalize_code("0x80070643"), "0x80070643");
        assert_eq!(normalize_code("80073d02"), "0x80073D02");
        assert_eq!(normalize_code("-2147023293"), "0x80070643");
        assert_eq!(
            newest_version(["10.0.26100.1".into(), "10.0.26100.2454".into(), "junk".into()]),
            "10.0.26100.2454"
        );
    }

    #[test]
    fn agent_codes_are_read() {
        let e = entry_from(0, "Update for Contoso (KB5000001)".into(), 1, 4, 0x8007_0643_u32 as i32);
        assert_eq!(
            (e.result.as_str(), e.code.as_str(), e.kb.as_str()),
            ("failed", "0x80070643", "KB5000001")
        );
        let ok = entry_from(0, "x".into(), 2, 2, 0);
        assert_eq!(
            (ok.operation.as_str(), ok.result.as_str(), ok.code.as_str()),
            ("uninstall", "succeeded", "")
        );
    }

    fn event(id: u32, title: &str, code: &str) -> String {
        format!(
            r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-WindowsUpdateClient"/><EventID>{id}</EventID><Level>4</Level><TimeCreated SystemTime="2026-11-20T10:00:00.0000000Z"/><EventRecordID>77</EventRecordID><Channel>System</Channel><Computer>PC-VICTIM</Computer></System><EventData><Data Name="errorCode">{code}</Data><Data Name="updateTitle">{title}</Data><Data Name="updateGuid">{{00000000-0000-0000-0000-000000000000}}</Data><Data Name="updateRevisionNumber">1</Data></EventData></Event>"#
        )
    }

    #[test]
    fn events_become_history() {
        let ok = entry_from_event(&event(19, "2026-11 Cumulative Update (KB5050001)", "")).expect("19");
        assert_eq!((ok.result.as_str(), ok.kb.as_str()), ("succeeded", "KB5050001"));
        let bad = entry_from_event(&event(20, "Contoso Display driver 31.0", "0x80073701")).expect("20");
        assert_eq!(
            (bad.result.as_str(), bad.code.as_str(), bad.kb.as_str()),
            ("failed", "0x80073701", "")
        );
        assert!(entry_from_event(&event(43, "x", "")).is_none());
        assert!(entry_from_event(&event(19, "", "")).is_none());
    }

    #[test]
    fn failures_are_grouped_and_a_later_success_counts() {
        let history = vec![
            entry(1, "Cumulative Update (KB5050001)", "succeeded", ""),
            entry(3, "Cumulative Update (KB5050001)", "failed", "0x80070643"),
            entry(5, "Cumulative Update (KB5050001)", "failed", "0x80070643"),
            entry(2, "Contoso driver 1.2", "failed", "0x80073701"),
            entry(4, "Contoso driver 1.2", "failed", "0x80073702"),
            entry(9, "Fabrikam Store app", "aborted", "0x80240022"),
        ];
        let groups = group_failures(&history);
        assert_eq!(groups.len(), 3);
        let driver = groups.iter().find(|g| g.title == "Contoso driver 1.2").expect("driver");
        assert_eq!(
            (driver.count, driver.code.as_str(), driver.fixed_later),
            (2, "0x80073701", false)
        );
        let cumulative = groups.iter().find(|g| g.kb == "KB5050001").expect("kb");
        assert!(cumulative.fixed_later);
        assert_eq!(groups[0].title, "Contoso driver 1.2", "most recent first");
    }

    #[test]
    fn hints_say_what_deserves_a_look() {
        let mut u = Updates {
            history: vec![
                entry(60, "Cumulative Update (KB5040001)", "succeeded", ""),
                entry(2, "Contoso driver 1.2", "failed", "0x80073701"),
                entry(4, "Contoso driver 1.2", "failed", "0x80073701"),
            ],
            reboot_reasons: vec!["windows_update".into()],
            reboot_since_ms: Some(NOW - 5 * DAY_MS),
            policy: with_set(UpdatePolicy {
                wsus_server: "https://wsus.contoso.example:8531".into(),
                use_wsus: true,
                defer_quality_days: Some(7),
                ..UpdatePolicy::default()
            }),
            ..Updates::default()
        };
        finish(&mut u, NOW);
        let codes: Vec<&str> = u.hints.iter().map(|h| h.code).collect();
        assert_eq!(
            codes,
            [
                "failing_repeatedly",
                "restart_pending",
                "no_recent_install",
                "managed",
                "deferred"
            ]
        );
        assert_eq!(u.last_install_ms, Some(NOW - 60 * DAY_MS), "taken from the history");
        assert_eq!(u.hints[1].count, 5);
        assert!(u.policy.set && !u.disabled && !u.paused);
    }

    #[test]
    fn disabled_and_paused_updates() {
        let mut off = Updates {
            policy: with_set(UpdatePolicy {
                no_auto_update: true,
                ..UpdatePolicy::default()
            }),
            ..Updates::default()
        };
        finish(&mut off, NOW);
        assert!(off.disabled);
        assert_eq!(off.hints[0].code, "updates_disabled");

        let mut service = Updates {
            service_start: "disabled".into(),
            ..Updates::default()
        };
        finish(&mut service, NOW);
        assert_eq!(service.hints[0].code, "service_disabled");

        let mut paused = Updates {
            pause_until_ms: Some(NOW + 10 * DAY_MS),
            last_install_ms: Some(NOW - 50 * DAY_MS),
            ..Updates::default()
        };
        finish(&mut paused, NOW);
        assert!(paused.paused);
        let codes: Vec<&str> = paused.hints.iter().map(|h| h.code).collect();
        assert_eq!(codes, ["paused"], "a pause explains the missing installs");
        assert_eq!(paused.hints[0].count, 10);

        let mut over = Updates {
            pause_until_ms: Some(NOW - DAY_MS),
            ..Updates::default()
        };
        finish(&mut over, NOW);
        assert!(!over.paused);
    }

    #[test]
    fn a_recent_restart_or_file_renames_alone_are_no_hint() {
        let mut u = Updates {
            reboot_reasons: vec!["windows_update".into()],
            reboot_since_ms: Some(NOW - DAY_MS / 2),
            ..Updates::default()
        };
        finish(&mut u, NOW);
        assert!(u.hints.is_empty());
        let mut renames = Updates {
            reboot_reasons: vec!["file_rename".into()],
            reboot_since_ms: Some(NOW - 9 * DAY_MS),
            ..Updates::default()
        };
        finish(&mut renames, NOW);
        assert!(renames.hints.is_empty());
    }

    #[test]
    #[ignore = "reads this computer's Windows Update state; run by hand"]
    fn live_read_counts_only() {
        let started = std::time::Instant::now();
        let u = read();
        println!(
            "source {} entries {} failures {} last install {} search {} reboot {:?} paused {} policy {} service {} {:?} hints {:?} notes {:?} in {:?}",
            u.history_source,
            u.history.len(),
            u.failures.len(),
            u.last_install_ms.is_some(),
            u.last_search_ms.is_some(),
            u.reboot_reasons,
            u.paused,
            u.policy.set,
            u.service_start,
            u.service_running,
            u.hints.iter().map(|h| h.code).collect::<Vec<_>>(),
            u.notes,
            started.elapsed()
        );
    }
}
