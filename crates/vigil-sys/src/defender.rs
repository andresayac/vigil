//! Microsoft Defender, read live through WMI (`ROOT\Microsoft\Windows\Defender` and
//! `ROOT\SecurityCenter2`): the protection switches, security intelligence and scan times, other
//! antivirus products, the threat history and the exclusions. Read-only: nothing is changed here.
//!
//! Standard users see everything except the exclusions, which Defender hides from them (the list
//! then holds a "N/A: Must be an administrator..." placeholder). Every part degrades on its own:
//! with Defender removed or off the page still shows what Windows Security Center reports.
//!
//! The WMI rows are turned into [`Protection`] by pure functions ([`assemble`] and the helpers
//! below), so the tests feed them recorded rows instead of a real Defender.

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;

use serde::Serialize;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoUninitialize,
    EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, SAFEARRAY,
};
use windows::Win32::System::Ole::{SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound};
use windows::Win32::System::Variant::{
    VARIANT, VT_ARRAY, VT_BOOL, VT_BSTR, VT_I1, VT_I2, VT_I4, VT_I8, VT_INT, VT_UI1, VT_UI2, VT_UI4, VT_UI8, VT_UINT,
    VariantClear,
};
use windows::Win32::System::Wmi::{
    IEnumWbemClassObject, IWbemClassObject, IWbemLocator, IWbemServices, WBEM_FLAG_FORWARD_ONLY,
    WBEM_FLAG_RETURN_IMMEDIATELY, WbemLocator,
};
use windows::core::{BSTR, HSTRING, PCWSTR};

use crate::SysError;
use crate::firewall::Folders;
use crate::startup::expand;
use crate::util::now_unix_ms;

/// How long one read may take before the page is told Defender did not answer.
const TIMEOUT: Duration = Duration::from_secs(30);
/// One WMI enumeration step (milliseconds).
const STEP_MS: i32 = 15_000;
const MAX_THREATS: usize = 200;
const MAX_DETECTIONS: usize = 2000;
const MAX_RESOURCES: usize = 25;
const MAX_EXCLUSIONS: usize = 500;
/// A scan that started this recently and has not ended is reported as running.
const RUNNING_WINDOW_MS: i64 = 6 * 3600 * 1000;

const NS_DEFENDER: &str = r"ROOT\Microsoft\Windows\Defender";
const NS_SECURITY_CENTER: &str = r"ROOT\SecurityCenter2";

// ------------------------------------------------------------------------------ model

/// Everything the Protection page shows.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Protection {
    /// Defender's WMI classes answered.
    pub available: bool,
    /// Why they did not (empty when `available`).
    pub problem: String,
    /// The Defender antivirus service runs.
    pub service_enabled: bool,
    pub antivirus_enabled: bool,
    /// "normal", "passive" (another antivirus protects the computer), "edr" (EDR in block mode),
    /// "off" or "" when unknown.
    pub mode: String,
    pub switches: Vec<Switch>,
    pub signature_version: String,
    /// When the security intelligence was last updated (Unix ms; 0 when unknown).
    pub signature_updated_ms: i64,
    /// Days since then, as Defender counts them.
    pub signature_age_days: Option<u32>,
    pub signature_out_of_date: bool,
    pub engine_version: String,
    /// The antimalware platform (client) version.
    pub platform_version: String,
    pub quick_scan: ScanTimes,
    pub full_scan: ScanTimes,
    /// Defender asks for a full scan to finish cleaning something.
    pub full_scan_required: bool,
    /// A scan started and has not ended yet ("quick" or "full"; started by anyone).
    pub running_scan: Option<RunningScan>,
    /// Where tamper protection is set from ("UI", "Intune", ...; as Defender reports it).
    pub tamper_source: String,
    /// Antivirus products registered with Windows Security Center other than Defender.
    pub other_antivirus: Vec<AntivirusProduct>,
    /// Security Center lists Defender itself and says whether it is on.
    pub defender_registered: Option<bool>,
    /// Newest first, active ones first.
    pub threats: Vec<Threat>,
    pub exclusions: Vec<Exclusion>,
    /// Defender hides the exclusions from standard users.
    pub exclusions_hidden: bool,
}

/// A protection switch, as Windows Security shows it.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Switch {
    /// "realtime", "behavior", "tamper", "cloud", "samples", "pua", "network", "cfa".
    pub key: String,
    /// "on", "off", "audit" or "unknown".
    pub state: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanTimes {
    /// Unix ms; 0 when it never ran.
    pub start_ms: i64,
    pub end_ms: i64,
    pub age_days: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RunningScan {
    /// "quick" or "full".
    pub kind: String,
    pub start_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AntivirusProduct {
    pub name: String,
    pub enabled: bool,
    pub up_to_date: bool,
}

/// A threat Defender detected, with its latest detection.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Threat {
    pub id: String,
    /// Defender's name ("Trojan:Win32/Example.A"), not translated.
    pub name: String,
    /// "low", "moderate", "high", "severe" or "unknown".
    pub severity: String,
    /// "virus", "trojan", "backdoor", "ransomware", "worm", "spyware", "exploit", "tool", "pua" or "other".
    pub category: String,
    /// Files, registry keys and other places it was found (prefixes such as `file:_` removed).
    pub resources: Vec<String>,
    /// Detected and not remediated yet.
    pub active: bool,
    /// Defender saw it run.
    pub executed: bool,
    /// What happened at the latest detection: "detected", "cleaned", "quarantined", "removed",
    /// "allowed", "blocked", "failed", "abandoned" or "unknown".
    pub status: String,
    /// The latest detection's action succeeded.
    pub action_success: bool,
    /// When it was first detected, latest detection (Unix ms; 0 when unknown).
    pub detected_ms: i64,
    /// When its status last changed (Unix ms).
    pub changed_ms: i64,
    /// The program that had it open when it was detected (may be "Unknown").
    pub process: String,
    pub detections: u32,
}

/// A Defender exclusion. `flags`: "drive" (a whole drive or everything), "writable" (a folder any
/// program can write to, so malware can hide there), "executable" (a program or script file
/// type), "anyFolder" (a process excluded by name, wherever it runs from).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Exclusion {
    /// "path", "process" or "extension" (the names `defender.remove_exclusion` takes).
    pub kind: String,
    pub value: String,
    pub flags: Vec<String>,
}

// ------------------------------------------------------------------------------ WMI values

/// A WMI property value.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Null,
    Bool(bool),
    Int(i64),
    Text(String),
    List(Vec<String>),
}

/// One WMI object: property name -> value.
pub type Row = HashMap<String, Val>;

fn get<'a>(row: &'a Row, name: &str) -> &'a Val {
    row.get(name).unwrap_or(&Val::Null)
}

fn text(row: &Row, name: &str) -> String {
    match get(row, name) {
        Val::Text(s) => s.trim().to_string(),
        Val::Int(n) => n.to_string(),
        Val::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn int(row: &Row, name: &str) -> Option<i64> {
    match get(row, name) {
        Val::Int(n) => Some(*n),
        Val::Bool(b) => Some(i64::from(*b)),
        Val::Text(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn boolean(row: &Row, name: &str) -> Option<bool> {
    match get(row, name) {
        Val::Bool(b) => Some(*b),
        Val::Int(n) => Some(*n != 0),
        _ => None,
    }
}

fn list(row: &Row, name: &str) -> Vec<String> {
    match get(row, name) {
        Val::List(items) => items
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Val::Text(s) if !s.trim().is_empty() => vec![s.trim().to_string()],
        _ => Vec::new(),
    }
}

/// A day count Defender reports; `u32::MAX` (or -1) means "never".
fn age(row: &Row, name: &str) -> Option<u32> {
    int(row, name)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n != u32::MAX)
}

// ------------------------------------------------------------------------------ pure helpers

/// A CIM datetime (`yyyymmddHHMMSS.mmmmmmsUUU`, UUU = minutes from UTC) as Unix ms; 0 when empty
/// or before 1971 (Defender writes year 1601 for "never").
pub fn cim_time_ms(text: &str) -> i64 {
    let t = text.trim();
    let digits = |range: std::ops::Range<usize>| t.get(range).and_then(|s| s.parse::<i64>().ok());
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(0..4),
        digits(4..6),
        digits(6..8),
        digits(8..10),
        digits(10..12),
        digits(12..14),
    ) else {
        return 0;
    };
    if year < 1971 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return 0;
    }
    let micros = digits(15..21).unwrap_or(0);
    let offset = match (t.get(21..22), digits(22..25)) {
        (Some("-"), Some(m)) => -m,
        (Some("+"), Some(m)) => m,
        _ => 0,
    };
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset * 60;
    seconds * 1000 + micros / 1000
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn severity_key(id: i64) -> &'static str {
    match id {
        1 => "low",
        2 => "moderate",
        4 => "high",
        5 => "severe",
        _ => "unknown",
    }
}

/// Defender's threat categories, grouped into the few the page names.
pub fn category_key(id: i64) -> &'static str {
    match id {
        42 => "virus",
        4 | 8 | 9 | 11 | 17 | 22 | 26 | 29 | 36 | 37 | 38 | 40 => "trojan",
        6 | 7 => "backdoor",
        50 => "ransomware",
        5 => "worm",
        2 | 3 | 10 | 12 | 39 => "spyware",
        16 | 28 | 30 | 47 => "exploit",
        18 | 20 | 25 | 31 | 32 | 33 | 34 => "tool",
        1 | 13 | 14 | 15 | 19 | 21 | 23 | 24 | 27 | 49 => "pua",
        _ => "other",
    }
}

/// `MSFT_MpThreatDetection.ThreatStatusID` as a key, as Microsoft documents the enumeration:
/// 102 QuarantineFailed, 103 RemoveFailed, 104 AllowFailed, 105 Abandoned, 107 BlockedFailed.
/// Undocumented values (106 occurs in practice) are "unknown"; whether the threat is still active
/// comes from `MSFT_MpThreat.IsActive`, not from this value.
pub fn status_key(id: i64) -> &'static str {
    match id {
        1 => "detected",
        2 => "cleaned",
        3 => "quarantined",
        4 => "removed",
        5 => "allowed",
        6 => "blocked",
        102..=104 | 107 => "failed",
        105 => "abandoned",
        _ => "unknown",
    }
}

/// `file:_C:\x.exe` -> `C:\x.exe`; `containerfile:_C:\a.zip->b.exe` keeps the inner name.
pub fn clean_resource(raw: &str) -> String {
    let raw = raw.trim();
    match raw.split_once(":_") {
        Some((prefix, rest)) if !prefix.is_empty() && prefix.chars().all(|c| c.is_ascii_alphanumeric()) => {
            rest.trim().to_string()
        }
        _ => raw.to_string(),
    }
}

/// "on", "off", "audit" or "unknown" for a preference value.
fn pref_state(key: &str, value: Option<i64>) -> &'static str {
    let Some(value) = value else {
        return "unknown";
    };
    match (key, value) {
        ("cloud", 0) => "off",
        ("cloud", 1 | 2) => "on",
        ("samples", 1 | 3) => "on",
        ("samples", 0 | 2) => "off",
        ("pua" | "network", 0) => "off",
        ("pua" | "network", 1) => "on",
        ("pua" | "network", 2) => "audit",
        ("cfa", 0) => "off",
        ("cfa", 1 | 3) => "on",
        ("cfa", 2 | 4) => "audit",
        _ => "unknown",
    }
}

fn bool_state(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "on",
        Some(false) => "off",
        None => "unknown",
    }
}

/// The running mode Defender reports (`AMRunningMode`) as a key.
pub fn mode_key(raw: &str, service_enabled: bool) -> &'static str {
    let low = raw.to_ascii_lowercase();
    if low.contains("passive") {
        "passive"
    } else if low.contains("edr") {
        "edr"
    } else if low.contains("normal") {
        "normal"
    } else if !service_enabled || low.contains("not running") {
        "off"
    } else {
        ""
    }
}

/// Security Center's `productState`: (enabled, up to date).
pub fn product_state(state: i64) -> (bool, bool) {
    let state = state.max(0) as u64;
    ((state >> 8) & 0x10 != 0, state & 0xFF == 0)
}

/// File types that run code: excluding one lets any program of that type go unscanned.
const EXECUTABLE_TYPES: [&str; 22] = [
    "exe", "dll", "sys", "scr", "com", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "msi", "msp", "jar", "lnk", "cpl", "pif",
];

/// Why an exclusion deserves a look (see [`Exclusion`]).
pub fn exclusion_flags(kind: &str, value: &str, folders: &Folders) -> Vec<String> {
    let mut flags = Vec::new();
    let raw = value.trim();
    let expanded = expand(raw);
    let path = expanded.trim().trim_matches('"').replace('/', "\\");
    match kind {
        "extension" => {
            let ext = path
                .trim_start_matches('*')
                .trim_start_matches('.')
                .to_ascii_lowercase();
            if ext == "*" || ext.is_empty() || EXECUTABLE_TYPES.contains(&ext.as_str()) {
                flags.push("executable".to_string());
            }
        }
        _ => {
            let low = path.to_ascii_lowercase();
            let bare = low.trim_end_matches(['\\', '*']).trim_end_matches('\\');
            let drive =
                bare.is_empty() || (bare.len() == 2 && bare.ends_with(':') && bare.as_bytes()[0].is_ascii_alphabetic());
            if drive && kind == "path" {
                flags.push("drive".to_string());
            }
            let folder = format!("{}\\x", path.trim_end_matches('\\'));
            if !drive && (folders.user_writable(&path) || (kind == "path" && folders.user_writable(&folder))) {
                flags.push("writable".to_string());
            }
            if kind == "process" && !path.contains('\\') {
                flags.push("anyFolder".to_string());
            }
            if kind == "path" {
                let name = low.rsplit('\\').next().unwrap_or("");
                if let Some(ext) = name.strip_prefix("*.")
                    && EXECUTABLE_TYPES.contains(&ext)
                {
                    flags.push("executable".to_string());
                }
            }
        }
    }
    flags
}

/// The Defender placeholder standard users get instead of the exclusions.
fn hidden_placeholder(value: &str) -> bool {
    let v = value.trim().trim_start_matches('{').to_ascii_uppercase();
    v.starts_with("N/A:") || v.starts_with("N/A ")
}

/// Builds the page's view from the WMI rows. `status` / `preference` are None when Defender's
/// classes did not answer.
pub fn assemble(
    status: Option<&Row>,
    preference: Option<&Row>,
    threats: &[Row],
    detections: &[Row],
    antivirus: Option<&[Row]>,
    folders: &Folders,
    now_ms: i64,
) -> Protection {
    let mut out = Protection::default();
    if let Some(status) = status {
        out.available = true;
        out.service_enabled = boolean(status, "AMServiceEnabled").unwrap_or(false);
        out.antivirus_enabled = boolean(status, "AntivirusEnabled").unwrap_or(false);
        out.mode = mode_key(&text(status, "AMRunningMode"), out.service_enabled).to_string();
        out.signature_version = text(status, "AntivirusSignatureVersion");
        out.signature_updated_ms = cim_time_ms(&text(status, "AntivirusSignatureLastUpdated"));
        out.signature_age_days = age(status, "AntivirusSignatureAge");
        out.signature_out_of_date = boolean(status, "DefenderSignaturesOutOfDate").unwrap_or(false);
        out.engine_version = text(status, "AMEngineVersion");
        out.platform_version = text(status, "AMProductVersion");
        out.tamper_source = text(status, "TamperProtectionSource");
        out.full_scan_required = boolean(status, "FullScanRequired").unwrap_or(false);
        out.quick_scan = ScanTimes {
            start_ms: cim_time_ms(&text(status, "QuickScanStartTime")),
            end_ms: cim_time_ms(&text(status, "QuickScanEndTime")),
            age_days: age(status, "QuickScanAge"),
        };
        out.full_scan = ScanTimes {
            start_ms: cim_time_ms(&text(status, "FullScanStartTime")),
            end_ms: cim_time_ms(&text(status, "FullScanEndTime")),
            age_days: age(status, "FullScanAge"),
        };
        out.running_scan = [("quick", &out.quick_scan), ("full", &out.full_scan)]
            .into_iter()
            .filter(|(_, s)| s.start_ms > s.end_ms && now_ms - s.start_ms < RUNNING_WINDOW_MS && s.start_ms <= now_ms)
            .max_by_key(|(_, s)| s.start_ms)
            .map(|(kind, s)| RunningScan {
                kind: kind.to_string(),
                start_ms: s.start_ms,
            });
    } else {
        out.problem = "Microsoft Defender did not answer".to_string();
    }
    let pref = preference.cloned().unwrap_or_default();
    let status_row = status.cloned().unwrap_or_default();
    let switch = |key: &str, state: &str| Switch {
        key: key.to_string(),
        state: if out.available {
            state.to_string()
        } else {
            "unknown".to_string()
        },
    };
    out.switches = vec![
        switch(
            "realtime",
            bool_state(boolean(&status_row, "RealTimeProtectionEnabled")),
        ),
        switch("behavior", bool_state(boolean(&status_row, "BehaviorMonitorEnabled"))),
        switch("tamper", bool_state(boolean(&status_row, "IsTamperProtected"))),
        switch("cloud", pref_state("cloud", int(&pref, "MAPSReporting"))),
        switch("samples", pref_state("samples", int(&pref, "SubmitSamplesConsent"))),
        switch("pua", pref_state("pua", int(&pref, "PUAProtection"))),
        switch("network", pref_state("network", int(&pref, "EnableNetworkProtection"))),
        switch("cfa", pref_state("cfa", int(&pref, "EnableControlledFolderAccess"))),
    ];

    // Exclusions.
    for (kind, name) in [
        ("path", "ExclusionPath"),
        ("process", "ExclusionProcess"),
        ("extension", "ExclusionExtension"),
    ] {
        for value in list(&pref, name) {
            if hidden_placeholder(&value) {
                out.exclusions_hidden = true;
                continue;
            }
            if out.exclusions.len() >= MAX_EXCLUSIONS {
                break;
            }
            out.exclusions.push(Exclusion {
                kind: kind.to_string(),
                flags: exclusion_flags(kind, &value, folders),
                value,
            });
        }
    }

    // Threats, joined with their detections.
    let mut by_threat: HashMap<String, Vec<&Row>> = HashMap::new();
    for detection in detections.iter().take(MAX_DETECTIONS) {
        by_threat
            .entry(text(detection, "ThreatID"))
            .or_default()
            .push(detection);
    }
    for threat in threats {
        let id = text(threat, "ThreatID");
        let found = by_threat.get(&id).map(Vec::as_slice).unwrap_or(&[]);
        let latest = found
            .iter()
            .max_by_key(|d| cim_time_ms(&text(d, "InitialDetectionTime")))
            .copied();
        let mut resources: Vec<String> = list(threat, "Resources")
            .iter()
            .chain(latest.map(|d| list(d, "Resources")).unwrap_or_default().iter())
            .map(|r| clean_resource(r))
            .filter(|r| !r.is_empty())
            .collect();
        resources.dedup();
        let mut seen = std::collections::HashSet::new();
        resources.retain(|r| seen.insert(r.to_lowercase()));
        resources.truncate(MAX_RESOURCES);
        let empty = Row::new();
        let d = latest.unwrap_or(&empty);
        out.threats.push(Threat {
            name: text(threat, "ThreatName"),
            severity: severity_key(int(threat, "SeverityID").unwrap_or(0)).to_string(),
            category: category_key(int(threat, "CategoryID").unwrap_or(0)).to_string(),
            resources,
            active: boolean(threat, "IsActive").unwrap_or(false),
            executed: boolean(threat, "DidThreatExecute").unwrap_or(false),
            status: status_key(int(d, "ThreatStatusID").unwrap_or(0)).to_string(),
            action_success: boolean(d, "ActionSuccess").unwrap_or(false),
            detected_ms: cim_time_ms(&text(d, "InitialDetectionTime")),
            changed_ms: cim_time_ms(&text(d, "LastThreatStatusChangeTime")),
            process: text(d, "ProcessName"),
            detections: u32::try_from(found.len()).unwrap_or(u32::MAX),
            id,
        });
    }
    out.threats.sort_by(|a, b| {
        b.active
            .cmp(&a.active)
            .then(b.detected_ms.cmp(&a.detected_ms))
            .then(a.name.cmp(&b.name))
    });
    out.threats.truncate(MAX_THREATS);

    // Security Center.
    if let Some(products) = antivirus {
        for product in products {
            let name = text(product, "displayName");
            let path = text(product, "pathToSignedProductExe").to_ascii_lowercase();
            let (enabled, up_to_date) = product_state(int(product, "productState").unwrap_or(0));
            if path.starts_with("windowsdefender:") || name.to_ascii_lowercase().contains("defender") {
                out.defender_registered = Some(enabled);
                continue;
            }
            if !name.is_empty() {
                out.other_antivirus.push(AntivirusProduct {
                    name,
                    enabled,
                    up_to_date,
                });
            }
        }
    }
    out
}

// ------------------------------------------------------------------------------ live read

/// Reads Defender's state now. Never fails as a whole: what could not be read is left out and
/// `available` / `problem` say why.
pub fn read() -> Protection {
    let (tx, rx) = mpsc::channel();
    let started = std::thread::Builder::new()
        .name("vigil-defender".into())
        .spawn(move || {
            let _ = tx.send(read_all());
        });
    if started.is_err() {
        return unavailable("could not start reading Microsoft Defender");
    }
    rx.recv_timeout(TIMEOUT)
        .unwrap_or_else(|_| unavailable("Microsoft Defender did not answer in time"))
}

fn unavailable(problem: &str) -> Protection {
    let mut out = assemble(None, None, &[], &[], None, &Folders::from_env(), now_unix_ms());
    out.problem = problem.to_string();
    out
}

const STATUS_PROPS: [&str; 26] = [
    "AMServiceEnabled",
    "AntivirusEnabled",
    "AMRunningMode",
    "AntivirusSignatureVersion",
    "AntivirusSignatureLastUpdated",
    "AntivirusSignatureAge",
    "DefenderSignaturesOutOfDate",
    "AMEngineVersion",
    "AMProductVersion",
    "TamperProtectionSource",
    "FullScanRequired",
    "QuickScanStartTime",
    "QuickScanEndTime",
    "QuickScanAge",
    "FullScanStartTime",
    "FullScanEndTime",
    "FullScanAge",
    "RealTimeProtectionEnabled",
    "BehaviorMonitorEnabled",
    "IsTamperProtected",
    "OnAccessProtectionEnabled",
    "IoavProtectionEnabled",
    "NISEnabled",
    "AntispywareEnabled",
    "QuickScanOverdue",
    "FullScanOverdue",
];
const PREFERENCE_PROPS: [&str; 8] = [
    "MAPSReporting",
    "SubmitSamplesConsent",
    "PUAProtection",
    "EnableNetworkProtection",
    "EnableControlledFolderAccess",
    "ExclusionPath",
    "ExclusionProcess",
    "ExclusionExtension",
];
const THREAT_PROPS: [&str; 7] = [
    "ThreatID",
    "ThreatName",
    "SeverityID",
    "CategoryID",
    "Resources",
    "IsActive",
    "DidThreatExecute",
];
const DETECTION_PROPS: [&str; 7] = [
    "ThreatID",
    "InitialDetectionTime",
    "LastThreatStatusChangeTime",
    "ThreatStatusID",
    "ActionSuccess",
    "Resources",
    "ProcessName",
];
const PRODUCT_PROPS: [&str; 3] = ["displayName", "productState", "pathToSignedProductExe"];

fn read_all() -> Protection {
    // SAFETY: COM for this worker thread only; balanced below when it succeeded.
    let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
    let result = read_wmi();
    if initialized {
        // SAFETY: balances the successful CoInitializeEx above; every interface was released.
        unsafe { CoUninitialize() };
    }
    result
}

fn read_wmi() -> Protection {
    let folders = Folders::from_env();
    let now = now_unix_ms();
    let antivirus = connect(NS_SECURITY_CENTER)
        .ok()
        .and_then(|svc| query(&svc, "AntiVirusProduct", &PRODUCT_PROPS, 50).ok());
    let defender = match connect(NS_DEFENDER) {
        Ok(svc) => svc,
        Err(error) => {
            let mut out = assemble(None, None, &[], &[], antivirus.as_deref(), &folders, now);
            out.problem = error.to_string();
            return out;
        }
    };
    let status = match query(&defender, "MSFT_MpComputerStatus", &STATUS_PROPS, 1) {
        Ok(rows) if !rows.is_empty() => rows.into_iter().next(),
        Ok(_) => None,
        Err(error) => {
            let mut out = assemble(None, None, &[], &[], antivirus.as_deref(), &folders, now);
            out.problem = error.to_string();
            return out;
        }
    };
    let preference = query(&defender, "MSFT_MpPreference", &PREFERENCE_PROPS, 1)
        .ok()
        .and_then(|rows| rows.into_iter().next());
    let threats = query(&defender, "MSFT_MpThreat", &THREAT_PROPS, MAX_THREATS * 4).unwrap_or_default();
    let detections = query(&defender, "MSFT_MpThreatDetection", &DETECTION_PROPS, MAX_DETECTIONS).unwrap_or_default();
    let mut out = assemble(
        status.as_ref(),
        preference.as_ref(),
        &threats,
        &detections,
        antivirus.as_deref(),
        &folders,
        now,
    );
    if status.is_none() {
        out.problem = "Microsoft Defender reported no status".to_string();
    }
    out
}

/// Connects to a WMI namespace as the current user (COM must be initialized on this thread).
pub(crate) fn connect(namespace: &str) -> Result<IWbemServices, SysError> {
    // SAFETY: creates the in-process WMI locator; released when dropped.
    let locator: IWbemLocator = unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| SysError::from_windows("WMI is not available", &e))?;
    // SAFETY: plain call on a valid interface; the BSTRs outlive it. Empty user and password
    // connect as the current user.
    let services = unsafe {
        locator.ConnectServer(
            &BSTR::from(namespace),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        )
    }
    .map_err(|e| SysError::from_windows(&format!("could not open {namespace}"), &e))?;
    // SAFETY: sets the proxy's security on a valid interface (RPC_C_AUTHN_WINNT = 10,
    // RPC_C_AUTHZ_NONE = 0); a failure leaves the defaults, which work for local reads.
    let _ = unsafe {
        CoSetProxyBlanket(
            &services,
            10,
            0,
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
    };
    Ok(services)
}

/// `SELECT props FROM class` (`class` may end with a `WHERE` clause), at most `max` rows.
pub(crate) fn query(services: &IWbemServices, class: &str, props: &[&str], max: usize) -> Result<Vec<Row>, SysError> {
    let wql = format!("SELECT {} FROM {class}", props.join(", "));
    // SAFETY: plain call on a valid interface; the BSTRs outlive it.
    let rows: IEnumWbemClassObject = unsafe {
        services.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from(wql.as_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )
    }
    .map_err(|e| SysError::from_windows(&format!("could not read {class}"), &e))?;
    let mut out = Vec::new();
    while out.len() < max {
        let mut objects: [Option<IWbemClassObject>; 1] = [None];
        let mut returned = 0u32;
        // SAFETY: one slot to fill and a valid counter.
        let hr = unsafe { rows.Next(STEP_MS, &mut objects, &mut returned) };
        if hr.is_err() && returned == 0 {
            if out.is_empty() {
                return Err(SysError::new(format!("could not read {class}"), hr.0));
            }
            break;
        }
        let Some(object) = objects[0].take().filter(|_| returned > 0) else {
            break;
        };
        let mut row = Row::new();
        for name in props {
            row.insert((*name).to_string(), property(&object, name));
        }
        out.push(row);
    }
    Ok(out)
}

/// CIM type of unsigned 32-bit integers, which WMI hands over as VT_I4.
const CIM_UINT32: i32 = 19;

fn property(object: &IWbemClassObject, name: &str) -> Val {
    let mut value = VARIANT::default();
    let mut cim_type = 0i32;
    // SAFETY: valid interface and out pointers; the VARIANT is cleared below.
    let got = unsafe { object.Get(&HSTRING::from(name), 0, &mut value, Some(&mut cim_type), None) };
    if got.is_err() {
        return Val::Null;
    }
    // SAFETY: the VARIANT was just filled by WMI; its tag says which member is active.
    let result = unsafe { convert(&value, cim_type) };
    // SAFETY: releases what the VARIANT owns (BSTR, SAFEARRAY).
    let _ = unsafe { VariantClear(&mut value) };
    result
}

/// # Safety
/// `value` must be a VARIANT filled by WMI, whose tag matches its active member.
unsafe fn convert(value: &VARIANT, cim_type: i32) -> Val {
    // SAFETY: reading the tag and the member it names (caller's contract).
    unsafe {
        let inner = &*value.Anonymous.Anonymous;
        let data = &inner.Anonymous;
        match inner.vt {
            VT_BOOL => Val::Bool(data.boolVal.0 != 0),
            VT_BSTR => Val::Text(data.bstrVal.to_string()),
            VT_I4 | VT_INT if cim_type == CIM_UINT32 => Val::Int(i64::from(data.lVal as u32)),
            VT_I4 | VT_INT => Val::Int(i64::from(data.lVal)),
            VT_UI4 | VT_UINT => Val::Int(i64::from(data.ulVal)),
            VT_UI1 => Val::Int(i64::from(data.bVal)),
            VT_I1 => Val::Int(i64::from(data.cVal)),
            VT_I2 => Val::Int(i64::from(data.iVal)),
            VT_UI2 => Val::Int(i64::from(data.uiVal)),
            VT_I8 => Val::Int(data.llVal),
            VT_UI8 => Val::Int(i64::try_from(data.ullVal).unwrap_or(i64::MAX)),
            vt if vt.0 == (VT_ARRAY.0 | VT_BSTR.0) => Val::List(strings(data.parray)),
            // Arrays of integers (Win32_DeviceGuard's service lists) as their decimal text.
            vt if vt.0 == (VT_ARRAY.0 | VT_I4.0) || vt.0 == (VT_ARRAY.0 | VT_UI4.0) => Val::List(integers(data.parray)),
            _ => Val::Null,
        }
    }
}

/// The strings of a one-dimensional SAFEARRAY of BSTR.
fn strings(array: *mut SAFEARRAY) -> Vec<String> {
    if array.is_null() {
        return Vec::new();
    }
    // SAFETY: a valid one-dimensional array owned by the VARIANT being read.
    let (Ok(low), Ok(high)) = (unsafe { SafeArrayGetLBound(array, 1) }, unsafe {
        SafeArrayGetUBound(array, 1)
    }) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for index in low..=high.min(low.saturating_add(4096)) {
        let mut item = BSTR::new();
        // SAFETY: the index is within the bounds; the element is copied into `item`, which frees it.
        if unsafe { SafeArrayGetElement(array, &index, (&raw mut item).cast()) }.is_ok() {
            out.push(item.to_string());
        }
    }
    out
}

/// The values of a one-dimensional SAFEARRAY of 32-bit integers, as decimal text.
fn integers(array: *mut SAFEARRAY) -> Vec<String> {
    if array.is_null() {
        return Vec::new();
    }
    // SAFETY: a valid one-dimensional array owned by the VARIANT being read.
    let (Ok(low), Ok(high)) = (unsafe { SafeArrayGetLBound(array, 1) }, unsafe {
        SafeArrayGetUBound(array, 1)
    }) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for index in low..=high.min(low.saturating_add(4096)) {
        let mut item = 0i32;
        // SAFETY: the index is within the bounds; the 4-byte element is copied into `item`.
        if unsafe { SafeArrayGetElement(array, &index, (&raw mut item).cast()) }.is_ok() {
            out.push(item.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn row(value: Value) -> Row {
        let Value::Object(map) = value else {
            return Row::new();
        };
        map.into_iter()
            .map(|(k, v)| {
                let v = match v {
                    Value::Bool(b) => Val::Bool(b),
                    Value::Number(n) => Val::Int(n.as_i64().unwrap_or(0)),
                    Value::String(s) => Val::Text(s),
                    Value::Array(items) => Val::List(
                        items
                            .into_iter()
                            .filter_map(|i| i.as_str().map(str::to_string))
                            .collect(),
                    ),
                    _ => Val::Null,
                };
                (k, v)
            })
            .collect()
    }

    fn folders() -> Folders {
        Folders::new(
            &[
                r"C:\Users\jdoe",
                r"C:\Users\jdoe\AppData\Local\Temp",
                r"C:\ProgramData",
                r"C:\Users",
                r"C:\Windows\Temp",
            ],
            &[
                r"C:\Windows",
                r"C:\Program Files",
                r"C:\Program Files (x86)",
                r"C:\ProgramData\Microsoft",
            ],
        )
    }

    const NOW: i64 = 1_795_288_000_000; // 2026-11-21T19:06:40Z

    #[test]
    fn cim_times() {
        assert_eq!(cim_time_ms("20261121103019.000000+000"), 1_795_257_019_000);
        assert_eq!(cim_time_ms("20261121053019.000000-300"), 1_795_257_019_000);
        assert_eq!(cim_time_ms("20261121103019.250000+000"), 1_795_257_019_250);
        assert_eq!(cim_time_ms("16010101000000.000000+000"), 0);
        assert_eq!(cim_time_ms(""), 0);
        assert_eq!(cim_time_ms("garbage"), 0);
        assert_eq!(cim_time_ms("19700102000000.000000+000"), 0);
        assert_eq!(cim_time_ms("20000301000000.000000+000"), 951_868_800_000);
    }

    #[test]
    fn keys() {
        assert_eq!(severity_key(5), "severe");
        assert_eq!(severity_key(3), "unknown");
        assert_eq!(category_key(27), "pua");
        assert_eq!(category_key(8), "trojan");
        assert_eq!(category_key(50), "ransomware");
        assert_eq!(category_key(999), "other");
        assert_eq!(status_key(3), "quarantined");
        assert_eq!(status_key(103), "failed");
        assert_eq!(status_key(105), "abandoned");
        assert_eq!(status_key(106), "unknown");
        assert_eq!(mode_key("Normal", true), "normal");
        assert_eq!(mode_key("Passive Mode", true), "passive");
        assert_eq!(mode_key("SxS Passive Mode", true), "passive");
        assert_eq!(mode_key("EDR Block Mode", true), "edr");
        assert_eq!(mode_key("", false), "off");
        assert_eq!(mode_key("", true), "");
        assert_eq!(product_state(0x061100), (true, true));
        assert_eq!(product_state(0x060100), (false, true));
        assert_eq!(product_state(0x041010), (true, false));
        assert_eq!(
            clean_resource(r"file:_C:\Users\jdoe\Downloads\tool.exe"),
            r"C:\Users\jdoe\Downloads\tool.exe"
        );
        assert_eq!(
            clean_resource(r"containerfile:_C:\Users\jdoe\Downloads\pack.zip"),
            r"C:\Users\jdoe\Downloads\pack.zip"
        );
        assert_eq!(clean_resource(r"C:\plain.exe"), r"C:\plain.exe");
    }

    #[test]
    fn exclusion_flagging() {
        let f = folders();
        let flags = |kind: &str, value: &str| exclusion_flags(kind, value, &f);
        assert_eq!(flags("path", r"C:\"), vec!["drive"]);
        assert_eq!(flags("path", "D:"), vec!["drive"]);
        assert_eq!(flags("path", r"C:\*"), vec!["drive"]);
        assert_eq!(flags("path", r"C:\Users\jdoe\Downloads"), vec!["writable"]);
        assert_eq!(flags("path", r"C:\Users\jdoe\AppData\Local\Temp\"), vec!["writable"]);
        assert_eq!(flags("path", r"C:\ProgramData"), vec!["writable"]);
        assert_eq!(flags("path", r"C:\Program Files\Vendor\data"), Vec::<String>::new());
        assert_eq!(
            flags("path", r"C:\ProgramData\Microsoft\Windows Defender"),
            Vec::<String>::new()
        );
        assert_eq!(flags("path", r"C:\Tools\*.exe"), vec!["executable"]);
        assert_eq!(flags("process", "powershell.exe"), vec!["anyFolder"]);
        assert_eq!(
            flags("process", r"C:\Users\jdoe\AppData\Roaming\x\agent.exe"),
            vec!["writable"]
        );
        assert_eq!(
            flags("process", r"C:\Program Files\Vendor\app.exe"),
            Vec::<String>::new()
        );
        assert_eq!(flags("extension", ".exe"), vec!["executable"]);
        assert_eq!(flags("extension", "PS1"), vec!["executable"]);
        assert_eq!(flags("extension", "log"), Vec::<String>::new());
    }

    fn status_row() -> Row {
        row(json!({
            "AMServiceEnabled": true,
            "AntivirusEnabled": true,
            "AMRunningMode": "Normal",
            "AntivirusSignatureVersion": "1.400.100.0",
            "AntivirusSignatureLastUpdated": "20261121103019.000000+000",
            "AntivirusSignatureAge": 0,
            "DefenderSignaturesOutOfDate": false,
            "AMEngineVersion": "1.1.24000.1",
            "AMProductVersion": "4.18.24000.1",
            "TamperProtectionSource": "UI",
            "FullScanRequired": false,
            "QuickScanStartTime": "20261121113100.000000+000",
            "QuickScanEndTime": "20261121113308.000000+000",
            "QuickScanAge": 0,
            "FullScanStartTime": "",
            "FullScanEndTime": "",
            "FullScanAge": 4_294_967_295i64,
            "RealTimeProtectionEnabled": true,
            "BehaviorMonitorEnabled": true,
            "IsTamperProtected": true,
        }))
    }

    #[test]
    fn assembles_a_healthy_defender() {
        let pref = row(json!({
            "MAPSReporting": 2, "SubmitSamplesConsent": 1, "PUAProtection": 0, "EnableNetworkProtection": 2,
            "EnableControlledFolderAccess": 0,
            "ExclusionPath": [r"C:\Users\jdoe\Downloads", r"C:\Program Files\Vendor\cache"],
            "ExclusionProcess": ["agent.exe"],
            "ExclusionExtension": [".log"],
        }));
        let threats = [
            row(
                json!({"ThreatID": "2147735503", "ThreatName": "PUA:Win32/Example", "SeverityID": 1, "CategoryID": 27,
                "Resources": [r"file:_C:\Users\jdoe\Downloads\setup.exe"], "IsActive": false, "DidThreatExecute": false}),
            ),
            row(
                json!({"ThreatID": "2147800000", "ThreatName": "Trojan:Win32/Example.A", "SeverityID": 5, "CategoryID": 8,
                "Resources": [r"file:_C:\Users\jdoe\AppData\Local\Temp\x.exe"], "IsActive": true, "DidThreatExecute": true}),
            ),
        ];
        let detections = [
            row(
                json!({"ThreatID": "2147735503", "InitialDetectionTime": "20261101090000.000000+000",
                "ThreatStatusID": 3, "ActionSuccess": true, "ProcessName": "Unknown"}),
            ),
            row(
                json!({"ThreatID": "2147735503", "InitialDetectionTime": "20261110090000.000000+000",
                "LastThreatStatusChangeTime": "20261110090100.000000+000", "ThreatStatusID": 4, "ActionSuccess": true,
                "Resources": [r"file:_C:\Users\jdoe\Downloads\setup.exe"], "ProcessName": r"C:\Windows\explorer.exe"}),
            ),
            row(
                json!({"ThreatID": "2147800000", "InitialDetectionTime": "20261120090000.000000+000",
                "ThreatStatusID": 103, "ActionSuccess": false}),
            ),
        ];
        let av = [row(
            json!({"displayName": "Windows Defender", "productState": 0x061100, "pathToSignedProductExe": "windowsdefender://"}),
        )];
        let p = assemble(
            Some(&status_row()),
            Some(&pref),
            &threats,
            &detections,
            Some(&av),
            &folders(),
            NOW,
        );
        assert!(p.available && p.service_enabled && p.antivirus_enabled);
        assert_eq!(p.mode, "normal");
        assert_eq!(p.signature_updated_ms, 1_795_257_019_000);
        assert_eq!(p.full_scan.age_days, None);
        assert_eq!(p.full_scan.start_ms, 0);
        assert_eq!(p.quick_scan.age_days, Some(0));
        assert_eq!(p.running_scan, None);
        let state = |key: &str| {
            p.switches
                .iter()
                .find(|s| s.key == key)
                .map(|s| s.state.clone())
                .unwrap_or_default()
        };
        assert_eq!(state("realtime"), "on");
        assert_eq!(state("cloud"), "on");
        assert_eq!(state("samples"), "on");
        assert_eq!(state("pua"), "off");
        assert_eq!(state("network"), "audit");
        assert_eq!(state("cfa"), "off");
        assert!(!p.exclusions_hidden);
        assert_eq!(p.exclusions.len(), 4);
        assert_eq!(p.exclusions[0].flags, vec!["writable"]);
        assert!(p.exclusions[1].flags.is_empty());
        assert_eq!(p.exclusions[2].flags, vec!["anyFolder"]);
        assert!(p.exclusions[3].flags.is_empty());
        // The active threat comes first; detections are joined by id, the latest one wins.
        assert_eq!(p.threats.len(), 2);
        assert_eq!(p.threats[0].name, "Trojan:Win32/Example.A");
        assert!(p.threats[0].active && p.threats[0].executed);
        assert_eq!(p.threats[0].status, "failed");
        assert_eq!(p.threats[0].severity, "severe");
        assert_eq!(p.threats[0].category, "trojan");
        assert_eq!(p.threats[1].status, "removed");
        assert_eq!(p.threats[1].detections, 2);
        assert_eq!(p.threats[1].process, r"C:\Windows\explorer.exe");
        assert_eq!(p.threats[1].resources, vec![r"C:\Users\jdoe\Downloads\setup.exe"]);
        assert_eq!(p.defender_registered, Some(true));
        assert!(p.other_antivirus.is_empty());
    }

    #[test]
    fn standard_users_and_other_antivirus() {
        let mut status = status_row();
        status.insert("AMRunningMode".into(), Val::Text("Passive Mode".into()));
        status.insert("RealTimeProtectionEnabled".into(), Val::Bool(false));
        // A quick scan started an hour ago and has not ended.
        status.insert(
            "QuickScanStartTime".into(),
            Val::Text("20261121180640.000000+000".into()),
        );
        let pref = row(json!({
            "ExclusionPath": ["N/A: Must be and administrator to view exclusions"],
            "ExclusionProcess": ["N/A: Must be and administrator to view exclusions"],
        }));
        let av = [
            row(
                json!({"displayName": "Windows Defender", "productState": 0x060100, "pathToSignedProductExe": "windowsdefender://"}),
            ),
            row(
                json!({"displayName": "Example Antivirus", "productState": 0x041000, "pathToSignedProductExe": r"C:\Program Files\Example\av.exe"}),
            ),
        ];
        let p = assemble(Some(&status), Some(&pref), &[], &[], Some(&av), &folders(), NOW);
        assert_eq!(p.mode, "passive");
        assert!(p.exclusions_hidden);
        assert!(p.exclusions.is_empty());
        assert_eq!(p.defender_registered, Some(false));
        assert_eq!(
            p.other_antivirus,
            vec![AntivirusProduct {
                name: "Example Antivirus".into(),
                enabled: true,
                up_to_date: true
            }]
        );
        assert_eq!(
            p.running_scan,
            Some(RunningScan {
                kind: "quick".into(),
                start_ms: 1_795_284_400_000
            })
        );
    }

    #[test]
    fn defender_missing() {
        let p = assemble(None, None, &[], &[], None, &folders(), NOW);
        assert!(!p.available);
        assert!(!p.problem.is_empty());
        assert!(p.switches.iter().all(|s| s.state == "unknown"));
        assert_eq!(p.switches.len(), 8);
    }

    /// Reads the real Defender (read-only) and checks the shape; prints counts only.
    #[test]
    #[ignore = "reads the live Defender state"]
    fn live_read() {
        let p = read();
        println!(
            "available {} mode {} switches {} threats {} exclusions {} hidden {} other av {}",
            p.available,
            p.mode,
            p.switches.len(),
            p.threats.len(),
            p.exclusions.len(),
            p.exclusions_hidden,
            p.other_antivirus.len()
        );
    }
}
