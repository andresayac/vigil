//! The security posture: the Windows settings that protect the computer as a whole (Secure Boot,
//! TPM, Memory integrity, BitLocker, UAC, Remote Desktop, SMBv1, SmartScreen...), read live.
//! Read-only: nothing is changed here.
//!
//! The values are read into [`Raw`] (registry, WMI, the TPM API, one event log query, Microsoft
//! Defender's state); [`evaluate`] turns them into checks and a score. It is a pure function, so
//! the tests feed it recorded values. Each check also names the actions Vigil can take to raise
//! it (`fixes`); the app offers only those, checked again against a fresh read.

use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::Duration;

use serde::Serialize;
use windows::Win32::Foundation::TBS_E_TPM_NOT_FOUND;
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_STATUS, SERVICE_STOPPED,
};
use windows::Win32::System::SystemInformation::{FIRMWARE_TYPE, FirmwareTypeBios, FirmwareTypeUefi, GetFirmwareType};
use windows::Win32::System::TpmBaseServices::{TBS_SUCCESS, TPM_DEVICE_INFO, Tbsi_GetDeviceInfo};
use windows::core::{HSTRING, PCWSTR};

use crate::defender::{self, Row, Val};
use crate::util::{hkcu_dword, hklm_dword, hklm_string, now_unix_ms};

const DAY_MS: i64 = 24 * 3600 * 1000;
/// How long the slow parts (WMI, Defender, the event log) may take.
const WAIT: Duration = Duration::from_secs(25);
/// Windows 11 2022 Update: LSA protection without the UEFI lock, the vulnerable driver blocklist on
/// by default, and their switches in Windows Security.
pub const BUILD_22H2: u32 = 22_621;

// ------------------------------------------------------------------------------ model

/// Everything the Security posture page shows.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Posture {
    pub checks: Vec<Check>,
    pub score: Score,
    /// The drives BitLocker reports (empty when it could not be read).
    pub volumes: Vec<Volume>,
    /// Read with administrator rights.
    pub elevated: bool,
    /// `EditionID` ("Professional", "Core", "Enterprise"...).
    pub edition: String,
    pub build: u32,
}

/// One recommended setting.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    /// "secure_boot", "tpm", "memory_integrity", "credential_guard", "lsa", "driver_blocklist",
    /// "bitlocker", "uac", "rdp", "remote_registry", "smb1", "firewall", "smartscreen",
    /// "powershell2", "autorun", "defender", "defender_updates" or "windows_update".
    pub id: String,
    /// "device", "data", "signin", "network", "apps" or "protection".
    pub group: String,
    /// "on" (as recommended), "partial", "off", "unknown" (could not be read) or "na" (does not
    /// apply to this computer).
    pub state: String,
    /// How much it counts in the score: 1 to 3.
    pub weight: u32,
    /// What exactly was found, as a key the page words ("legacy_bios", "pending_restart"...);
    /// empty for the plain case.
    pub detail: String,
    /// Values the detail refers to ("version" -> "2.0", "profiles" -> "public").
    pub facts: BTreeMap<String, String>,
    /// It could not be read without administrator rights.
    pub needs_admin: bool,
    /// What Vigil can do to raise it: request ops of the page ("uac-default", "rdp-nla"...).
    pub fixes: Vec<String>,
    /// Where it is shown or changed: a Windows Security or Settings link, `tool:<name>`, or a
    /// Vigil page (`page:<key>`); empty when there is nothing to open.
    pub open: String,
}

/// "N of M recommended settings are on". Each setting counts its weight; partly on counts half.
/// Settings that do not apply or could not be read are left out.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Score {
    pub on: u32,
    pub partial: u32,
    pub off: u32,
    /// The settings counted (on + partial + off).
    pub counted: u32,
    /// Weighted share of what is on, 0-100.
    pub percent: u32,
}

/// A drive BitLocker reports.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    /// "C:"; may be empty for a drive without a letter.
    pub letter: String,
    /// "os", "fixed" or "removable".
    pub kind: String,
    /// "on", "off" or "unknown".
    pub protection: String,
    /// "decrypted", "encrypted", "encrypting", "decrypting", "paused" or "unknown".
    pub encryption: String,
}

/// The values a posture is judged on. Every field is what Windows said (`None`: could not be read
/// or not set); the tests build it by hand.
#[derive(Debug, Clone, Default)]
pub struct Raw {
    pub elevated: bool,
    pub edition: String,
    pub build: u32,
    /// UEFI firmware (`Some(false)`: legacy BIOS).
    pub uefi: Option<bool>,
    /// `UEFISecureBootEnabled`.
    pub secure_boot: Option<u32>,
    /// TPM version: `Some(0)` none, `Some(1)` 1.2, `Some(2)` 2.0.
    pub tpm: Option<u32>,
    /// BitLocker's drives; `None` when they could not be read.
    pub volumes: Option<Vec<VolumeRaw>>,
    pub device_guard: Option<DeviceGuardRaw>,
    /// `HypervisorEnforcedCodeIntegrity\Enabled`.
    pub hvci_enabled: Option<u32>,
    /// `LsaCfgFlags` (Credential Guard), the policy's or the local one.
    pub lsa_cfg_flags: Option<u32>,
    pub driver_blocklist: Option<u32>,
    pub run_as_ppl: Option<u32>,
    pub run_as_ppl_boot: Option<u32>,
    /// `SmartScreenEnabled` ("Warn", "RequireAdmin", "Off"; "" when not set).
    pub smartscreen: String,
    /// The `EnableSmartScreen` policy.
    pub smartscreen_policy: Option<u32>,
    pub enable_lua: Option<u32>,
    pub consent_admin: Option<u32>,
    pub secure_desktop: Option<u32>,
    /// `Win32_OptionalFeature.InstallState` of SMB1Protocol: 1 enabled, 2 disabled, 3 absent.
    pub smb1_feature: Option<u32>,
    /// Start type of the SMBv1 client driver (`mrxsmb10`); `None` when it is not installed.
    pub smb1_client_start: Option<u32>,
    /// `InstallState` of MicrosoftWindowsPowerShellV2Root.
    pub ps2_feature: Option<u32>,
    /// `NoDriveTypeAutoRun` for the computer and for the user.
    pub autorun_machine: Option<u32>,
    pub autorun_user: Option<u32>,
    /// `fDenyTSConnections` (policy first).
    pub rdp_deny: Option<u32>,
    /// `UserAuthentication` of RDP-Tcp (policy first): 1 = Network Level Authentication required.
    pub rdp_nla: Option<u32>,
    /// Start type of the Remote Registry service (`None`: not installed).
    pub remote_registry_start: Option<u32>,
    pub remote_registry_running: Option<bool>,
    /// Firewall on for the domain, private and public profiles.
    pub firewall: [Option<bool>; 3],
    pub defender: Option<DefenderRaw>,
    /// When the last Windows update (not a definition update) was installed.
    pub last_update_ms: Option<i64>,
    pub now_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeRaw {
    pub letter: String,
    /// `VolumeType`: 0 operating system, 1 fixed data, 2 removable.
    pub kind: u32,
    /// `ProtectionStatus`: 0 off, 1 on, 2 unknown.
    pub protection: Option<u32>,
    /// `ConversionStatus`: 0 decrypted, 1 encrypted, 2 encrypting, 3 decrypting, 4/5 paused.
    pub conversion: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceGuardRaw {
    /// Security services configured and running: 1 Credential Guard, 2 Memory integrity.
    pub configured: Vec<u32>,
    pub running: Vec<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefenderRaw {
    /// Defender's WMI classes answered.
    pub available: bool,
    /// The antivirus service and engine are on.
    pub active: bool,
    /// Real-time protection: "on", "off" or "unknown".
    pub realtime: String,
    /// Defender runs in passive mode (another antivirus protects the computer).
    pub passive: bool,
    pub signature_age_days: Option<u32>,
    /// Other antivirus products that are on.
    pub other: Vec<String>,
}

// ------------------------------------------------------------------------------ evaluation

fn check(id: &str, group: &str, weight: u32, state: &str) -> Check {
    Check {
        id: id.to_string(),
        group: group.to_string(),
        state: state.to_string(),
        weight,
        ..Check::default()
    }
}

impl Check {
    fn detail(mut self, detail: &str) -> Self {
        self.detail = detail.to_string();
        self
    }
    fn fact(mut self, key: &str, value: impl Into<String>) -> Self {
        self.facts.insert(key.to_string(), value.into());
        self
    }
    fn fix(mut self, op: &str) -> Self {
        self.fixes.push(op.to_string());
        self
    }
    fn open(mut self, target: &str) -> Self {
        self.open = target.to_string();
        self
    }
}

const DEVICE_SECURITY: &str = "windowsdefender://devicesecurity";
const CORE_ISOLATION: &str = "windowsdefender://coreisolation";

/// Home editions ("Core", "CoreN", "CoreSingleLanguage"...).
pub fn is_home(edition: &str) -> bool {
    edition.to_ascii_lowercase().starts_with("core")
}

/// Editions where Credential Guard exists.
pub fn has_credential_guard(edition: &str) -> bool {
    let low = edition.to_ascii_lowercase();
    low.contains("enterprise") || low.contains("education") || low.contains("server")
}

fn secure_boot(raw: &Raw) -> Check {
    let base = |state| check("secure_boot", "device", 2, state).open(DEVICE_SECURITY);
    match (raw.uefi, raw.secure_boot) {
        (Some(false), _) => base("off").detail("legacy_bios"),
        (_, Some(1)) => base("on"),
        (_, Some(0)) => base("off").detail("uefi_off"),
        _ => base("unknown"),
    }
}

fn tpm(raw: &Raw) -> Check {
    let base = |state| check("tpm", "device", 2, state).open(DEVICE_SECURITY);
    match raw.tpm {
        Some(2) => base("on").fact("version", "2.0"),
        Some(1) => base("partial").detail("old_version").fact("version", "1.2"),
        Some(0) => base("off").detail("absent"),
        _ => base("unknown"),
    }
}

fn memory_integrity(raw: &Raw) -> Check {
    let base = |state| check("memory_integrity", "device", 3, state).open(CORE_ISOLATION);
    let running = raw.device_guard.as_ref().is_some_and(|d| d.running.contains(&2));
    let configured =
        raw.hvci_enabled == Some(1) || raw.device_guard.as_ref().is_some_and(|d| d.configured.contains(&2));
    if running {
        base("on")
    } else if configured {
        base("partial").detail("pending_restart")
    } else {
        base("off")
    }
}

fn credential_guard(raw: &Raw) -> Check {
    let base = |state| check("credential_guard", "device", 1, state);
    if !has_credential_guard(&raw.edition) {
        return base("na").detail("edition");
    }
    let running = raw.device_guard.as_ref().is_some_and(|d| d.running.contains(&1));
    let configured = matches!(raw.lsa_cfg_flags, Some(1 | 2))
        || raw.device_guard.as_ref().is_some_and(|d| d.configured.contains(&1));
    if running {
        base("on")
    } else if configured {
        base("partial").detail("pending_restart")
    } else if raw.device_guard.is_none() && raw.lsa_cfg_flags.is_none() {
        base("unknown")
    } else {
        base("off")
    }
}

fn lsa(raw: &Raw) -> Check {
    let on = matches!(raw.run_as_ppl, Some(1 | 2)) || matches!(raw.run_as_ppl_boot, Some(1 | 2));
    let base = check("lsa", "device", 2, if on { "on" } else { "off" });
    // Windows 11 2022 Update and later: a switch in Windows Security, and a value Vigil can set
    // without locking it in the firmware (so History can undo it).
    let modern = raw.build >= BUILD_22H2;
    match (on, modern) {
        (true, true) => base.open(CORE_ISOLATION),
        (true, false) => base,
        (false, true) => base.fix("lsa-on").open(CORE_ISOLATION),
        (false, false) => base.detail("old_windows"),
    }
}

fn driver_blocklist(raw: &Raw) -> Check {
    let base = |state| check("driver_blocklist", "device", 2, state).open(CORE_ISOLATION);
    let hvci_running = raw.device_guard.as_ref().is_some_and(|d| d.running.contains(&2));
    match raw.driver_blocklist {
        Some(0) => base("off").fix("driver-blocklist-on"),
        Some(_) => base("on"),
        // Not set: on by default since the Windows 11 2022 Update, and always with Memory integrity.
        None if raw.build >= BUILD_22H2 || hvci_running => base("on").detail("default"),
        None => base("off").fix("driver-blocklist-on"),
    }
}

fn volume_kind(kind: u32) -> &'static str {
    match kind {
        0 => "os",
        2 => "removable",
        _ => "fixed",
    }
}

fn encryption(conversion: Option<u32>) -> &'static str {
    match conversion {
        Some(0) => "decrypted",
        Some(1) => "encrypted",
        Some(2) => "encrypting",
        Some(3) => "decrypting",
        Some(4 | 5) => "paused",
        _ => "unknown",
    }
}

fn protection(value: Option<u32>) -> &'static str {
    match value {
        Some(1) => "on",
        Some(0) => "off",
        _ => "unknown",
    }
}

/// The drives as the page lists them: the system drive first, then by letter.
pub fn volumes(raw: &[VolumeRaw]) -> Vec<Volume> {
    let mut out: Vec<Volume> = raw
        .iter()
        .map(|v| Volume {
            letter: v.letter.clone(),
            kind: volume_kind(v.kind).to_string(),
            protection: protection(v.protection).to_string(),
            encryption: encryption(v.conversion).to_string(),
        })
        .collect();
    out.sort_by(|a, b| (a.kind != "os").cmp(&(b.kind != "os")).then(a.letter.cmp(&b.letter)));
    out
}

fn bitlocker(raw: &Raw) -> Check {
    let open = if is_home(&raw.edition) {
        "ms-settings:deviceencryption"
    } else {
        "tool:bitlocker"
    };
    let base = |state| check("bitlocker", "data", 3, state).open(open);
    let Some(list) = &raw.volumes else {
        let mut out = base("unknown");
        if !raw.elevated {
            out.needs_admin = true;
            out.detail = "needs_admin".to_string();
        }
        return out;
    };
    let Some(system) = list.iter().find(|v| v.kind == 0) else {
        // Read with the rights to see it, and no system drive listed: BitLocker is not there.
        return base("off").detail("not_available");
    };
    let unprotected: Vec<String> = list
        .iter()
        .filter(|v| v.kind == 1 && v.protection != Some(1) && !v.letter.is_empty())
        .map(|v| v.letter.clone())
        .collect();
    match (system.protection, system.conversion) {
        (Some(1), _) if unprotected.is_empty() => base("on"),
        (Some(1), _) => base("partial")
            .detail("data_drives")
            .fact("drives", unprotected.join(", ")),
        (_, Some(2)) => base("partial").detail("encrypting"),
        (_, Some(1)) => base("partial").detail("suspended"),
        (Some(0), _) => base("off"),
        _ => base("unknown"),
    }
}

fn uac(raw: &Raw) -> Check {
    let lua = raw.enable_lua.unwrap_or(1);
    let consent = raw.consent_admin.unwrap_or(5);
    let secure = raw.secure_desktop.unwrap_or(1);
    let base = |state| check("uac", "signin", 3, state);
    if lua == 0 {
        return base("off").detail("disabled").fix("uac-default");
    }
    if consent == 0 {
        return base("off").detail("never_notify").fix("uac-default");
    }
    // 1 and 2 always use the secure desktop; 3, 4 and 5 follow PromptOnSecureDesktop.
    if secure == 0 && !matches!(consent, 1 | 2) {
        return base("partial").detail("no_dimming").fix("uac-default");
    }
    if matches!(consent, 1..=4) {
        base("on").detail("always")
    } else {
        base("on")
    }
}

fn rdp(raw: &Raw) -> Check {
    let base = |state| check("rdp", "signin", 2, state).open("ms-settings:remotedesktop");
    if is_home(&raw.edition) {
        return check("rdp", "signin", 2, "na").detail("edition");
    }
    if raw.rdp_deny.unwrap_or(1) != 0 {
        return base("on").detail("closed");
    }
    if raw.rdp_nla.unwrap_or(1) == 1 {
        base("on").detail("open_nla").fix("rdp-off")
    } else {
        base("off").detail("open_no_nla").fix("rdp-nla").fix("rdp-off")
    }
}

fn remote_registry(raw: &Raw) -> Check {
    let base = |state| check("remote_registry", "signin", 1, state);
    match (raw.remote_registry_start, raw.remote_registry_running) {
        (None, _) => base("na").detail("missing"),
        (_, Some(true)) => base("off").detail("running").fix("remote-registry-off"),
        (Some(2), _) => base("off").detail("automatic").fix("remote-registry-off"),
        (Some(4), _) => base("on").detail("disabled"),
        (Some(_), _) => base("on").detail("manual"),
    }
}

fn smb1(raw: &Raw) -> Check {
    let base = |state| check("smb1", "network", 2, state);
    match raw.smb1_feature {
        Some(1) => base("off").detail("enabled").fix("smb1-off"),
        Some(2) => base("on").detail("disabled"),
        Some(3) => base("on").detail("removed"),
        // The feature list could not be read: the SMBv1 client driver tells whether it is there.
        _ => match raw.smb1_client_start {
            Some(4) | None => base("on").detail("driver_off"),
            Some(_) => base("off").detail("client").fix("smb1-off"),
        },
    }
}

const PROFILES: [&str; 3] = ["domain", "private", "public"];

fn firewall(raw: &Raw) -> Check {
    let base = |state| check("firewall", "network", 3, state).open("page:firewall");
    if raw.firewall.iter().all(Option::is_none) {
        return base("unknown");
    }
    let off: Vec<&str> = PROFILES
        .iter()
        .zip(raw.firewall.iter())
        .filter(|(_, on)| **on == Some(false))
        .map(|(name, _)| *name)
        .collect();
    if off.is_empty() {
        base("on")
    } else {
        base("off").detail("profiles_off").fact("profiles", off.join(","))
    }
}

fn smartscreen(raw: &Raw) -> Check {
    let base = |state| check("smartscreen", "apps", 2, state).open("windowsdefender://appbrowser");
    match raw.smartscreen_policy {
        Some(0) => return base("off").detail("policy"),
        Some(_) => return base("on").detail("policy"),
        None => {}
    }
    if raw.smartscreen.eq_ignore_ascii_case("off") {
        base("off")
    } else {
        base("on")
    }
}

fn powershell2(raw: &Raw) -> Check {
    let base = |state| check("powershell2", "apps", 1, state);
    match raw.ps2_feature {
        Some(1) => base("off").detail("enabled").fix("ps2-off"),
        Some(2) => base("on").detail("disabled"),
        Some(3) => base("on").detail("removed"),
        _ => base("unknown"),
    }
}

fn autorun(raw: &Raw) -> Check {
    let base = |state| check("autorun", "apps", 1, state);
    // The computer's policy applies to every user and wins over the user's.
    match raw.autorun_machine.or(raw.autorun_user) {
        Some(value) if value & 0xFF == 0xFF => base("on"),
        Some(0) => base("off").detail("all_drives").fix("autorun-off"),
        Some(value) => base("partial")
            .detail("some_drives")
            .fact("value", format!("0x{value:02X}"))
            .fix("autorun-off"),
        None => base("partial").detail("default").fix("autorun-off"),
    }
}

fn defender_check(raw: &Raw) -> Check {
    let base = |state| check("defender", "protection", 3, state).open("page:protection");
    let Some(d) = &raw.defender else {
        return base("unknown");
    };
    if !d.other.is_empty() && (d.passive || !d.active || !d.available) {
        return base("on").detail("other").fact("names", d.other.join(", "));
    }
    if !d.available {
        return base("off").detail("unavailable");
    }
    match (d.active, d.realtime.as_str()) {
        (true, "on") => base("on"),
        (false, _) | (_, "off") => base("off").detail("realtime_off"),
        _ => base("unknown"),
    }
}

fn defender_updates(raw: &Raw) -> Check {
    let base = |state| check("defender_updates", "protection", 2, state).open("page:protection");
    let Some(d) = &raw.defender else {
        return base("unknown");
    };
    if !d.other.is_empty() && (d.passive || !d.active || !d.available) {
        return base("na").detail("other");
    }
    if !d.available {
        return base("na").detail("unavailable");
    }
    match d.signature_age_days {
        Some(days) if days <= 3 => base("on").fact("days", days.to_string()),
        Some(days) if days <= 7 => base("partial").fact("days", days.to_string()),
        Some(days) => base("off").fact("days", days.to_string()),
        None => base("unknown"),
    }
}

fn windows_update(raw: &Raw) -> Check {
    let base = |state| check("windows_update", "protection", 2, state).open("ms-settings:windowsupdate");
    let Some(last) = raw.last_update_ms else {
        return base("unknown").detail("no_record");
    };
    let days = (raw.now_ms - last).max(0) / DAY_MS;
    let state = match days {
        0..=35 => "on",
        36..=60 => "partial",
        _ => "off",
    };
    base(state).fact("days", days.to_string())
}

/// The score of a list of checks.
pub fn score(checks: &[Check]) -> Score {
    let mut out = Score::default();
    let (mut points, mut max) = (0u32, 0u32);
    for c in checks.iter().filter(|c| c.weight > 0) {
        let half_points = match c.state.as_str() {
            "on" => {
                out.on += 1;
                2
            }
            "partial" => {
                out.partial += 1;
                1
            }
            "off" => {
                out.off += 1;
                0
            }
            _ => continue,
        };
        points += half_points * c.weight;
        max += 2 * c.weight;
    }
    out.counted = out.on + out.partial + out.off;
    out.percent = (points * 100 + max / 2).checked_div(max).unwrap_or(0);
    out
}

/// Judges the values read: every check in the page's order, the score and the drives.
pub fn evaluate(raw: &Raw) -> Posture {
    let checks = vec![
        secure_boot(raw),
        tpm(raw),
        memory_integrity(raw),
        credential_guard(raw),
        lsa(raw),
        driver_blocklist(raw),
        bitlocker(raw),
        uac(raw),
        rdp(raw),
        remote_registry(raw),
        smb1(raw),
        firewall(raw),
        smartscreen(raw),
        powershell2(raw),
        autorun(raw),
        defender_check(raw),
        defender_updates(raw),
        windows_update(raw),
    ];
    Posture {
        score: score(&checks),
        checks,
        volumes: raw.volumes.as_deref().map(volumes).unwrap_or_default(),
        elevated: raw.elevated,
        edition: raw.edition.clone(),
        build: raw.build,
    }
}

/// A Windows update title that is only a Defender definition or platform update (installed
/// several times a day, so it says nothing about Windows itself being updated).
pub fn is_definition_update(title: &str) -> bool {
    let low = title.to_ascii_lowercase();
    ["kb2267602", "kb4052623", "kb2461484", "kb915597", "kb5007651"]
        .iter()
        .any(|kb| low.contains(kb))
        || low.contains("security intelligence")
}

/// A title of a Windows update with a KB number ("2026-11 Cumulative Update ... (KB5099999)"),
/// as opposed to a Store app or driver update.
pub fn is_windows_update(title: &str) -> bool {
    let low = title.to_ascii_lowercase();
    let has_kb = low
        .match_indices("kb")
        .any(|(i, _)| low[i + 2..].chars().take_while(char::is_ascii_digit).count() >= 6);
    has_kb && !is_definition_update(title)
}

// ------------------------------------------------------------------------------ live read

const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const UAC: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const RDP_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
const AUTORUN: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
const FIREWALL_POLICY: &str = r"SOFTWARE\Policies\Microsoft\WindowsFirewall";
const FIREWALL: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

/// Reads the posture now. Never fails as a whole: what could not be read is "unknown".
pub fn read(elevated: bool) -> Posture {
    evaluate(&read_raw(elevated))
}

/// Starts `work` on its own thread; the receiver gets its result.
fn background<T: Send + 'static>(name: &str, work: impl FnOnce() -> T + Send + 'static) -> mpsc::Receiver<T> {
    let (tx, rx) = mpsc::channel();
    let _ = std::thread::Builder::new().name(name.to_string()).spawn(move || {
        let _ = tx.send(work());
    });
    rx
}

/// Every value, the slow ones (WMI, Defender, the event log) on their own threads.
pub fn read_raw(elevated: bool) -> Raw {
    let wmi = background("vigil-posture-wmi", move || read_wmi(elevated));
    let smb1 = background("vigil-posture-smb1", || feature_state("SMB1Protocol"));
    let ps2 = background("vigil-posture-ps2", || {
        feature_state("MicrosoftWindowsPowerShellV2Root")
    });
    let protection = background("vigil-posture-defender", defender::read);
    let update = background("vigil-posture-update", last_update_ms);
    let mut raw = read_registry(elevated);
    raw.uefi = firmware_uefi();
    raw.tpm = tpm_version();
    raw.remote_registry_running = service_running("RemoteRegistry");
    raw.now_ms = now_unix_ms();
    if let Ok(found) = wmi.recv_timeout(WAIT) {
        raw.device_guard = found.device_guard;
        raw.volumes = found.volumes;
    }
    raw.smb1_feature = smb1.recv_timeout(WAIT).ok().flatten();
    raw.ps2_feature = ps2.recv_timeout(WAIT).ok().flatten();
    if let Ok(state) = protection.recv_timeout(WAIT) {
        raw.defender = Some(defender_raw(&state));
    }
    raw.last_update_ms = update.recv_timeout(WAIT).ok().flatten();
    raw
}

/// The registry part (fast; every value here is readable by standard users).
fn read_registry(elevated: bool) -> Raw {
    let first = |pairs: &[(&str, &str)]| pairs.iter().find_map(|(key, value)| hklm_dword(key, value));
    let firewall = |policy: &str, profile: &str| {
        first(&[
            (&format!(r"{FIREWALL_POLICY}\{policy}"), "EnableFirewall"),
            (&format!(r"{FIREWALL}\{profile}"), "EnableFirewall"),
        ])
        .map(|on| on != 0)
    };
    Raw {
        elevated,
        edition: hklm_string(CURRENT_VERSION, "EditionID"),
        build: hklm_string(CURRENT_VERSION, "CurrentBuildNumber").parse().unwrap_or(0),
        secure_boot: hklm_dword(
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled",
        ),
        hvci_enabled: hklm_dword(
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
            "Enabled",
        ),
        lsa_cfg_flags: first(&[
            (r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "LsaCfgFlags"),
            (LSA, "LsaCfgFlags"),
        ]),
        driver_blocklist: hklm_dword(
            r"SYSTEM\CurrentControlSet\Control\CI\Config",
            "VulnerableDriverBlocklistEnable",
        ),
        run_as_ppl: hklm_dword(LSA, "RunAsPPL"),
        run_as_ppl_boot: hklm_dword(LSA, "RunAsPPLBoot"),
        smartscreen: hklm_string(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "SmartScreenEnabled",
        ),
        smartscreen_policy: hklm_dword(r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen"),
        enable_lua: hklm_dword(UAC, "EnableLUA"),
        consent_admin: hklm_dword(UAC, "ConsentPromptBehaviorAdmin"),
        secure_desktop: hklm_dword(UAC, "PromptOnSecureDesktop"),
        smb1_client_start: hklm_dword(r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start"),
        autorun_machine: hklm_dword(AUTORUN, "NoDriveTypeAutoRun"),
        autorun_user: hkcu_dword(AUTORUN, "NoDriveTypeAutoRun"),
        rdp_deny: first(&[
            (RDP_POLICY, "fDenyTSConnections"),
            (
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                "fDenyTSConnections",
            ),
        ]),
        rdp_nla: first(&[
            (RDP_POLICY, "UserAuthentication"),
            (
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthentication",
            ),
        ]),
        remote_registry_start: hklm_dword(r"SYSTEM\CurrentControlSet\Services\RemoteRegistry", "Start"),
        firewall: [
            firewall("DomainProfile", "DomainProfile"),
            firewall("PrivateProfile", "StandardProfile"),
            firewall("PublicProfile", "PublicProfile"),
        ],
        ..Raw::default()
    }
}

fn firmware_uefi() -> Option<bool> {
    let mut kind = FIRMWARE_TYPE::default();
    // SAFETY: `kind` is a valid out pointer.
    unsafe { GetFirmwareType(&mut kind) }.ok()?;
    if kind == FirmwareTypeUefi {
        Some(true)
    } else if kind == FirmwareTypeBios {
        Some(false)
    } else {
        None
    }
}

/// The TPM's version (`Some(0)`: no TPM). Works without administrator rights.
fn tpm_version() -> Option<u32> {
    let mut info = TPM_DEVICE_INFO::default();
    // SAFETY: `info` is writable for the size passed.
    let status = unsafe { Tbsi_GetDeviceInfo(size_of::<TPM_DEVICE_INFO>() as u32, (&raw mut info).cast()) };
    if status == TBS_SUCCESS {
        Some(info.tpmVersion).filter(|v| matches!(v, 1 | 2))
    } else if status == TBS_E_TPM_NOT_FOUND.0 as u32 {
        Some(0)
    } else {
        None
    }
}

/// A Service Control Manager handle, closed when dropped.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW/OpenServiceW and is closed only here.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

/// Whether a service runs now (`None`: it does not exist or cannot be asked).
fn service_running(name: &str) -> Option<bool> {
    // SAFETY: plain calls; the handles are closed when dropped.
    let manager = ScHandle(unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }.ok()?);
    // SAFETY: valid manager handle and a NUL-terminated name that outlives the call.
    let service = ScHandle(unsafe { OpenServiceW(manager.0, &HSTRING::from(name), SERVICE_QUERY_STATUS) }.ok()?);
    let mut status = SERVICE_STATUS::default();
    // SAFETY: valid service handle and out pointer.
    unsafe { QueryServiceStatus(service.0, &mut status) }.ok()?;
    Some(status.dwCurrentState != SERVICE_STOPPED)
}

fn defender_raw(state: &defender::Protection) -> DefenderRaw {
    DefenderRaw {
        available: state.available,
        active: state.service_enabled && state.antivirus_enabled,
        realtime: state
            .switches
            .iter()
            .find(|s| s.key == "realtime")
            .map_or("unknown", |s| s.state.as_str())
            .to_string(),
        passive: state.mode == "passive",
        signature_age_days: state.signature_age_days,
        other: state
            .other_antivirus
            .iter()
            .filter(|a| a.enabled)
            .map(|a| a.name.clone())
            .collect(),
    }
}

/// When the newest Windows update with a KB number was installed (event 19 of Windows Update).
fn last_update_ms() -> Option<i64> {
    const QUERY: &str = "*[System[Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and EventID=19]]";
    let xml = crate::reliability::newest_event_xml("System", QUERY, 500, |xml| is_windows_update(&update_title(xml)))?;
    let root = crate::xml::parse_xml(&xml)?;
    let time = root
        .child("System")?
        .child("TimeCreated")?
        .attr("SystemTime")
        .to_string();
    crate::reliability::iso_utc_ms(&time)
}

/// The `updateTitle` of a Windows Update event.
fn update_title(xml: &str) -> String {
    crate::xml::parse_xml(xml)
        .and_then(|root| {
            root.child("EventData")?
                .children
                .iter()
                .find(|d| d.attr("Name") == "updateTitle")
                .map(|d| d.text.trim().to_string())
        })
        .unwrap_or_default()
}

/// What WMI says about Device Guard and BitLocker's drives.
#[derive(Default)]
struct WmiRaw {
    device_guard: Option<DeviceGuardRaw>,
    volumes: Option<Vec<VolumeRaw>>,
}

fn row_int(row: &Row, name: &str) -> Option<u32> {
    match row.get(name) {
        Some(Val::Int(n)) => u32::try_from(*n).ok(),
        Some(Val::Bool(b)) => Some(u32::from(*b)),
        Some(Val::Text(s)) => s.trim().parse().ok(),
        _ => None,
    }
}

fn row_ints(row: &Row, name: &str) -> Vec<u32> {
    match row.get(name) {
        Some(Val::List(items)) => items.iter().filter_map(|s| s.trim().parse().ok()).collect(),
        Some(Val::Int(n)) => u32::try_from(*n).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn row_text(row: &Row, name: &str) -> String {
    match row.get(name) {
        Some(Val::Text(s)) => s.trim().to_string(),
        _ => String::new(),
    }
}

/// Device Guard's services from its WMI row.
pub fn device_guard_from(row: &Row) -> DeviceGuardRaw {
    DeviceGuardRaw {
        configured: row_ints(row, "SecurityServicesConfigured"),
        running: row_ints(row, "SecurityServicesRunning"),
    }
}

/// A BitLocker drive from its WMI row.
pub fn volume_from(row: &Row) -> VolumeRaw {
    VolumeRaw {
        letter: row_text(row, "DriveLetter"),
        kind: row_int(row, "VolumeType").unwrap_or(1),
        protection: row_int(row, "ProtectionStatus"),
        conversion: row_int(row, "ConversionStatus"),
    }
}

/// The install state of an optional feature from its `Win32_OptionalFeature` row: 1 enabled,
/// 2 disabled; no row means the feature does not exist on this Windows (3, absent).
pub fn feature_from(rows: &[Row]) -> Option<u32> {
    rows.first().map_or(Some(3), |row| row_int(row, "InstallState"))
}

/// Runs `work` with COM initialized for the calling worker thread.
fn with_com<T>(work: impl FnOnce() -> T) -> T {
    // SAFETY: COM for this worker thread only; balanced below when it succeeded.
    let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
    let out = work();
    if initialized {
        // SAFETY: balances the successful CoInitializeEx above; `work` released its interfaces.
        unsafe { CoUninitialize() };
    }
    out
}

/// Device Guard and, with administrator rights, BitLocker's drives. BitLocker's namespace refuses
/// standard users only after several seconds, so it is not asked then.
fn read_wmi(elevated: bool) -> WmiRaw {
    with_com(|| {
        let mut out = WmiRaw::default();
        if let Ok(services) = defender::connect(r"ROOT\Microsoft\Windows\DeviceGuard") {
            out.device_guard = defender::query(
                &services,
                "Win32_DeviceGuard",
                &["SecurityServicesConfigured", "SecurityServicesRunning"],
                1,
            )
            .ok()
            .and_then(|rows| rows.first().map(device_guard_from));
        }
        if elevated && let Ok(services) = defender::connect(r"ROOT\CIMV2\Security\MicrosoftVolumeEncryption") {
            out.volumes = defender::query(
                &services,
                "Win32_EncryptableVolume",
                &["DriveLetter", "VolumeType", "ProtectionStatus", "ConversionStatus"],
                64,
            )
            .ok()
            .map(|rows| rows.iter().map(volume_from).collect());
        }
        out
    })
}

/// The install state of one optional feature (`None`: unknown). One query per name: the provider
/// looks a single name up in under a second, while "OR" makes it enumerate every feature.
fn feature_state(name: &'static str) -> Option<u32> {
    with_com(|| {
        let services = defender::connect(r"ROOT\CIMV2").ok()?;
        let class = format!("Win32_OptionalFeature WHERE Name='{name}'");
        let rows = defender::query(&services, &class, &["Name", "InstallState"], 1).ok()?;
        feature_from(&rows)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-kept Windows 11 Pro computer.
    fn good() -> Raw {
        Raw {
            elevated: true,
            edition: "Professional".into(),
            build: 26_100,
            uefi: Some(true),
            secure_boot: Some(1),
            tpm: Some(2),
            volumes: Some(vec![VolumeRaw {
                letter: "C:".into(),
                kind: 0,
                protection: Some(1),
                conversion: Some(1),
            }]),
            device_guard: Some(DeviceGuardRaw {
                configured: vec![2],
                running: vec![2],
            }),
            hvci_enabled: Some(1),
            driver_blocklist: Some(1),
            run_as_ppl: Some(2),
            enable_lua: Some(1),
            consent_admin: Some(5),
            secure_desktop: Some(1),
            smb1_feature: Some(2),
            ps2_feature: Some(3),
            autorun_machine: Some(255),
            rdp_deny: Some(1),
            remote_registry_start: Some(4),
            remote_registry_running: Some(false),
            firewall: [Some(true); 3],
            defender: Some(DefenderRaw {
                available: true,
                active: true,
                realtime: "on".into(),
                signature_age_days: Some(0),
                ..DefenderRaw::default()
            }),
            last_update_ms: Some(1_000 * DAY_MS),
            now_ms: 1_010 * DAY_MS,
            ..Raw::default()
        }
    }

    fn find<'a>(p: &'a Posture, id: &str) -> &'a Check {
        p.checks.iter().find(|c| c.id == id).expect("check")
    }

    #[test]
    fn a_well_kept_computer_has_everything_on() {
        let p = evaluate(&good());
        for c in &p.checks {
            assert!(
                c.state == "on" || c.state == "na",
                "{} is {} ({})",
                c.id,
                c.state,
                c.detail
            );
            assert!(c.fixes.is_empty(), "{} offers {:?}", c.id, c.fixes);
        }
        assert_eq!(find(&p, "credential_guard").detail, "edition");
        assert_eq!(p.score.percent, 100);
        assert_eq!(p.score.on, p.score.counted);
        assert_eq!(p.volumes[0].kind, "os");
        assert_eq!(p.volumes[0].protection, "on");
    }

    #[test]
    fn weak_settings_are_off_and_offer_their_fix() {
        let mut raw = good();
        raw.enable_lua = Some(1);
        raw.consent_admin = Some(0);
        raw.rdp_deny = Some(0);
        raw.rdp_nla = Some(0);
        raw.smb1_feature = Some(1);
        raw.ps2_feature = Some(1);
        raw.autorun_machine = None;
        raw.autorun_user = None;
        raw.driver_blocklist = Some(0);
        raw.run_as_ppl = None;
        raw.remote_registry_start = Some(2);
        raw.firewall = [Some(true), Some(true), Some(false)];
        let p = evaluate(&raw);
        let state = |id| (find(&p, id).state.clone(), find(&p, id).fixes.clone());
        assert_eq!(state("uac"), ("off".into(), vec!["uac-default".into()]));
        assert_eq!(state("rdp"), ("off".into(), vec!["rdp-nla".into(), "rdp-off".into()]));
        assert_eq!(state("smb1"), ("off".into(), vec!["smb1-off".into()]));
        assert_eq!(state("powershell2"), ("off".into(), vec!["ps2-off".into()]));
        assert_eq!(state("autorun"), ("partial".into(), vec!["autorun-off".into()]));
        assert_eq!(
            state("driver_blocklist"),
            ("off".into(), vec!["driver-blocklist-on".into()])
        );
        assert_eq!(state("lsa"), ("off".into(), vec!["lsa-on".into()]));
        assert_eq!(
            state("remote_registry"),
            ("off".into(), vec!["remote-registry-off".into()])
        );
        let fw = find(&p, "firewall");
        assert_eq!((fw.state.as_str(), fw.facts["profiles"].as_str()), ("off", "public"));
        assert!(fw.fixes.is_empty() && fw.open == "page:firewall");
    }

    #[test]
    fn uac_levels() {
        let level = |lua, consent, secure| {
            let mut raw = good();
            (raw.enable_lua, raw.consent_admin, raw.secure_desktop) = (Some(lua), Some(consent), Some(secure));
            let c = uac(&raw);
            (c.state, c.detail)
        };
        assert_eq!(level(1, 5, 1), ("on".into(), String::new()));
        assert_eq!(level(1, 2, 1), ("on".into(), "always".into()));
        assert_eq!(level(1, 2, 0), ("on".into(), "always".into()));
        assert_eq!(level(1, 5, 0), ("partial".into(), "no_dimming".into()));
        assert_eq!(level(1, 0, 0), ("off".into(), "never_notify".into()));
        assert_eq!(level(0, 5, 1), ("off".into(), "disabled".into()));
    }

    #[test]
    fn device_security_states() {
        let mut raw = good();
        raw.uefi = Some(false);
        raw.secure_boot = None;
        raw.tpm = Some(0);
        raw.device_guard = Some(DeviceGuardRaw {
            configured: vec![2],
            running: vec![],
        });
        let p = evaluate(&raw);
        assert_eq!(find(&p, "secure_boot").detail, "legacy_bios");
        assert_eq!(find(&p, "tpm").state, "off");
        let hvci = find(&p, "memory_integrity");
        assert_eq!(
            (hvci.state.as_str(), hvci.detail.as_str()),
            ("partial", "pending_restart")
        );
        // Nothing to set here: Windows Security checks the drivers before turning it on.
        assert!(hvci.fixes.is_empty() && hvci.open == CORE_ISOLATION);

        raw.build = 19_045;
        raw.driver_blocklist = None;
        raw.device_guard = None;
        raw.run_as_ppl = None;
        let p = evaluate(&raw);
        assert_eq!(find(&p, "driver_blocklist").state, "off");
        // Before the Windows 11 2022 Update LSA protection locks itself in the firmware: no fix.
        let lsa = find(&p, "lsa");
        assert_eq!((lsa.state.as_str(), lsa.detail.as_str()), ("off", "old_windows"));
        assert!(lsa.fixes.is_empty());

        raw.edition = "Enterprise".into();
        raw.lsa_cfg_flags = Some(1);
        assert_eq!(credential_guard(&raw).state, "partial");
    }

    #[test]
    fn bitlocker_needs_admin_and_reads_drives() {
        let mut raw = good();
        raw.elevated = false;
        raw.volumes = None;
        let c = bitlocker(&raw);
        assert_eq!(
            (c.state.as_str(), c.needs_admin, c.open.as_str()),
            ("unknown", true, "tool:bitlocker")
        );

        raw.elevated = true;
        raw.edition = "Core".into();
        raw.volumes = Some(vec![
            VolumeRaw {
                letter: "D:".into(),
                kind: 1,
                protection: Some(0),
                conversion: Some(0),
            },
            VolumeRaw {
                letter: "C:".into(),
                kind: 0,
                protection: Some(1),
                conversion: Some(1),
            },
        ]);
        let p = evaluate(&raw);
        let c = find(&p, "bitlocker");
        assert_eq!((c.state.as_str(), c.facts["drives"].as_str()), ("partial", "D:"));
        assert_eq!(c.open, "ms-settings:deviceencryption");
        assert_eq!(p.volumes[0].letter, "C:");
        assert_eq!(p.volumes[1].encryption, "decrypted");

        raw.volumes = Some(vec![]);
        assert_eq!(bitlocker(&raw).detail, "not_available");
    }

    #[test]
    fn protection_summary() {
        let mut raw = good();
        raw.defender = Some(DefenderRaw {
            available: true,
            active: false,
            realtime: "off".into(),
            passive: true,
            signature_age_days: Some(40),
            other: vec!["Contoso Antivirus".into()],
        });
        raw.last_update_ms = Some(raw.now_ms - 90 * DAY_MS);
        let p = evaluate(&raw);
        let d = find(&p, "defender");
        assert_eq!(
            (d.state.as_str(), d.facts["names"].as_str()),
            ("on", "Contoso Antivirus")
        );
        assert_eq!(find(&p, "defender_updates").state, "na");
        let wu = find(&p, "windows_update");
        assert_eq!((wu.state.as_str(), wu.facts["days"].as_str()), ("off", "90"));

        raw.defender = None;
        raw.last_update_ms = None;
        let p = evaluate(&raw);
        assert_eq!(find(&p, "defender").state, "unknown");
        assert_eq!(find(&p, "windows_update").detail, "no_record");
    }

    #[test]
    fn score_weights_and_leaves_out_what_does_not_count() {
        let c = |state: &str, weight| Check {
            state: state.into(),
            weight,
            ..Check::default()
        };
        let s = score(&[c("on", 3), c("partial", 2), c("off", 1), c("na", 3), c("unknown", 2)]);
        assert_eq!((s.on, s.partial, s.off, s.counted), (1, 1, 1, 3));
        // (3 + 1) of 6 points.
        assert_eq!(s.percent, 67);
        assert_eq!(score(&[]).percent, 0);
    }

    #[test]
    fn windows_update_titles() {
        assert!(is_windows_update(
            "2026-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5099999)"
        ));
        assert!(!is_windows_update(
            "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.421.300.0)"
        ));
        assert!(!is_windows_update(
            "Actualización de inteligencia de seguridad para Microsoft Defender Antivirus - KB2267602"
        ));
        assert!(!is_windows_update("9WZDNCRFJ3PT-Microsoft.ZuneMusic"));
        assert!(!is_windows_update("Contoso - Display - 31.0.101.4502"));
    }

    #[test]
    fn wmi_rows_are_read() {
        let row = |pairs: &[(&str, Val)]| {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect::<Row>()
        };
        let dg = device_guard_from(&row(&[
            ("SecurityServicesConfigured", Val::List(vec!["1".into(), "2".into()])),
            ("SecurityServicesRunning", Val::List(vec!["2".into()])),
        ]));
        assert_eq!((dg.configured, dg.running), (vec![1, 2], vec![2]));
        let v = volume_from(&row(&[
            ("DriveLetter", Val::Text("C:".into())),
            ("VolumeType", Val::Int(0)),
            ("ProtectionStatus", Val::Int(1)),
            ("ConversionStatus", Val::Int(1)),
        ]));
        assert_eq!((v.letter.as_str(), v.kind, v.protection), ("C:", 0, Some(1)));
        let smb1 = feature_from(&[row(&[
            ("Name", Val::Text("SMB1Protocol".into())),
            ("InstallState", Val::Int(2)),
        ])]);
        assert_eq!((smb1, feature_from(&[])), (Some(2), Some(3)));
    }

    /// Reads this computer and prints the states only. Run by hand:
    /// `cargo test -p vigil-sys posture::tests::live_read -- --ignored --nocapture`
    #[test]
    #[ignore = "reads this computer"]
    fn live_read() {
        let started = std::time::Instant::now();
        let p = read(crate::elevation::is_elevated());
        for c in &p.checks {
            println!("{:18} {:8} {}", c.id, c.state, c.detail);
        }
        println!(
            "score {}% ({} of {} on), {} drives, {:?}",
            p.score.percent,
            p.score.on,
            p.score.counted,
            p.volumes.len(),
            started.elapsed()
        );
    }
}
