//! Battery and sleep, read only: what Windows says about the battery, what keeps the computer
//! awake, what woke it lately, what may wake it, and the active power plan's sleep settings.
//! Nothing here changes anything.
//!
//! - The battery: the battery driver's own figures (`IOCTL_BATTERY_QUERY_*` on each battery device
//!   interface): design and full-charge capacity, cycle count, chemistry, maker, charge and rate.
//!   Windows keeps no cheap capacity history, so only the present is read.
//! - What keeps it awake now: the power requests, as `powercfg /requests` lists them. Windows
//!   only lists them for administrators, so a standard copy says so instead of guessing.
//! - What woke it: the System log (Power-Troubleshooter 1 for the wake source, Kernel-Power 42 and
//!   107 for sleep and resume, 506 and 507 for modern standby), the last 7 days.
//! - What may wake it: scheduled tasks allowed to wake the computer (`WakeToRun`), the power
//!   plan's "allow wake timers", and the devices armed to wake it (`powercfg /devicequery
//!   wake_armed`).
//! - The active power plan: sleep, hibernate and display timeouts, the lid action (plugged in and
//!   on battery), and whether sleep, hibernation and modern standby are available.
//!
//! `powercfg.exe` is run from System32 by its full path, with fixed arguments and no window; it
//! only reads. [`finish`] draws the plain hints; the app writes their texts.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::os::windows::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, SP_DEVICE_INTERFACE_DATA, SP_DEVICE_INTERFACE_DETAIL_DATA_W,
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
};
use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Power::{
    BATTERY_INFORMATION, BATTERY_QUERY_INFORMATION, BATTERY_QUERY_INFORMATION_LEVEL, BATTERY_STATUS,
    BATTERY_WAIT_STATUS, BatteryDeviceName, BatteryEstimatedTime, BatteryInformation, BatteryManufactureName,
    GUID_DEVICE_BATTERY, GetPwrCapabilities, GetSystemPowerStatus, IOCTL_BATTERY_QUERY_INFORMATION,
    IOCTL_BATTERY_QUERY_STATUS, IOCTL_BATTERY_QUERY_TAG, PowerGetActiveScheme, PowerReadACValueIndex,
    PowerReadDCValueIndex, PowerReadFriendlyName, SYSTEM_POWER_CAPABILITIES, SYSTEM_POWER_STATUS,
};
use windows::core::{GUID, PCWSTR};

use crate::reliability::{LogReader, Record, iso_utc_ms, local_time};
use crate::util::{from_wide, now_unix_ms};

const DAY_MS: i64 = 86_400_000;
/// How far back the sleep and wake events are read.
pub const EVENT_DAYS: i64 = 7;
/// Events kept (newest first); modern standby can log hundreds a day.
pub const MAX_EVENTS: usize = 400;
/// Batteries read (a laptop has one or two; UPS units may add more).
const MAX_BATTERIES: u32 = 8;
/// Power requests and wake devices kept.
const MAX_LISTED: usize = 100;
/// How long `powercfg` may take.
const TOOL_TIMEOUT: Duration = Duration::from_secs(15);
/// Health under this percentage: the battery is worn.
pub const WORN_PERCENT: u32 = 80;
/// Health under this percentage: consider replacing it.
pub const REPLACE_PERCENT: u32 = 60;

// Power setting GUIDs (winnt.h), so the reader does not depend on where a crate version puts them.
const SUB_SLEEP: GUID = GUID::from_u128(0x238c9fa8_0aad_41ed_83f4_97be242c8f20);
const STANDBY_TIMEOUT: GUID = GUID::from_u128(0x29f6c1db_86da_48c5_9fdb_f2b67b1f44da);
const HIBERNATE_TIMEOUT: GUID = GUID::from_u128(0x9d7815a6_7ee4_497e_8888_515a05f02364);
const ALLOW_WAKE_TIMERS: GUID = GUID::from_u128(0xbd3b718a_0680_4d9d_8ab2_e1d2b4ac806d);
const SUB_VIDEO: GUID = GUID::from_u128(0x7516b95f_f776_4464_8c53_06167f40cc99);
const VIDEO_TIMEOUT: GUID = GUID::from_u128(0x3c0bc021_c8a8_4e07_a973_6b14cbcb2b7e);
const SUB_BUTTONS: GUID = GUID::from_u128(0x4f971e89_eebd_4455_a8de_9e59040e7347);
const LID_ACTION: GUID = GUID::from_u128(0x5ca83367_6e45_459f_a27b_476b1d01c936);

// Battery driver constants (batclass.h).
const BATTERY_CAPACITY_RELATIVE: u32 = 0x4000_0000;
const BATTERY_UNKNOWN_CAPACITY: u32 = 0xFFFF_FFFF;
const BATTERY_UNKNOWN_VOLTAGE: u32 = 0xFFFF_FFFF;
const BATTERY_UNKNOWN_RATE: i32 = i32::MIN;
const BATTERY_UNKNOWN_TIME: u32 = 0xFFFF_FFFF;
const BATTERY_POWER_ON_LINE: u32 = 1;
const BATTERY_DISCHARGING: u32 = 2;
const BATTERY_CHARGING: u32 = 4;
const BATTERY_CRITICAL: u32 = 8;

/// One battery, as its driver reports it.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Battery {
    /// The battery's own name ("DELL 5K9CP...", "" when it gives none).
    pub name: String,
    pub manufacturer: String,
    /// "LION", "LiP", "PbAc", "NiMH" … as the battery reports it ("" when unknown).
    pub chemistry: String,
    pub rechargeable: bool,
    /// Capacities are in relative units, not milliwatt-hours (some batteries only report that).
    pub relative: bool,
    pub design_mwh: Option<u32>,
    pub full_mwh: Option<u32>,
    /// Full-charge capacity as a percentage of the design capacity.
    pub health_percent: Option<u32>,
    pub cycle_count: Option<u32>,
    pub remaining_mwh: Option<u32>,
    /// Charge now, as a percentage of the full-charge capacity.
    pub charge_percent: Option<u32>,
    /// Milliwatts: positive while charging, negative while discharging.
    pub rate_mw: Option<i32>,
    pub voltage_mv: Option<u32>,
    /// "charging", "discharging", "plugged_in" (on power, not charging) or "unknown".
    pub state: String,
    pub critical: bool,
    /// Seconds left at the current drain, when the driver estimates it.
    pub estimated_seconds: Option<u32>,
}

/// Something that keeps the computer (or its display) awake now.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PowerRequest {
    /// "display", "system", "awaymode", "execution", "perfboost" or "activelockscreen".
    pub kind: String,
    /// "process", "service", "driver" or "other".
    pub source: String,
    /// The program, service or device (paths with drive letters when they map).
    pub name: String,
    /// The reason the requester gave ("" when none).
    pub reason: String,
}

/// One sleep, resume or wake, from the System log.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SleepEvent {
    pub time_ms: i64,
    /// Local time, ISO 8601.
    pub time: String,
    /// "sleep", "hibernate", "resume", "wake" (with its source), "standby_enter" or
    /// "standby_exit" (modern standby).
    pub kind: String,
    /// What woke the computer ("Power Button", "USB Root Hub", a timer's owner; "" when unknown).
    pub source: String,
    /// "device", "timer" or "" (unknown).
    pub source_kind: String,
    /// How long it slept, for a wake that says.
    pub slept_minutes: Option<u64>,
    /// The raw reason number of a modern standby or sleep event ("" when none).
    pub reason: String,
}

/// Wakes grouped by what caused them.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WakeSource {
    pub source: String,
    pub source_kind: String,
    pub count: usize,
    pub last_ms: i64,
}

/// Sleeps and wakes of one day (local date).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PowerDay {
    /// `2026-01-01`.
    pub date: String,
    pub sleeps: usize,
    pub wakes: usize,
}

/// A scheduled task allowed to wake the computer.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WakeTask {
    pub path: String,
    pub name: String,
    pub enabled: bool,
    /// Next run (local ISO time; "" when none is scheduled).
    pub next_run: String,
    pub program: String,
    /// It belongs to Windows (`\Microsoft\`).
    pub microsoft: bool,
}

/// The active power plan's sleep settings (plugged in / on battery).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PowerPlan {
    pub name: String,
    pub guid: String,
    /// Seconds; `Some(0)` means never.
    pub sleep_ac: Option<u32>,
    pub sleep_dc: Option<u32>,
    pub hibernate_ac: Option<u32>,
    pub hibernate_dc: Option<u32>,
    pub display_ac: Option<u32>,
    pub display_dc: Option<u32>,
    /// Closing the lid: 0 nothing, 1 sleep, 2 hibernate, 3 shut down.
    pub lid_ac: Option<u32>,
    pub lid_dc: Option<u32>,
    /// Wake timers: 0 off, 1 on, 2 only important ones.
    pub wake_timers_ac: Option<u32>,
    pub wake_timers_dc: Option<u32>,
}

/// A plain pointer drawn from the state; the app writes its text from `code`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PowerHint {
    /// "battery_replace", "battery_worn", "kept_awake", "timer_wakes", "frequent_wakes" or
    /// "wake_tasks".
    pub code: &'static str,
    /// "warn" or "info".
    pub severity: &'static str,
    pub subject: String,
    pub count: u64,
}

/// Everything the Battery and sleep page shows.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Power {
    pub read_ms: i64,
    /// Plugged in (`None`: Windows does not know).
    pub on_ac: Option<bool>,
    /// Windows' own charge figure for all batteries together.
    pub battery_percent: Option<u32>,
    pub has_battery: bool,
    pub batteries: Vec<Battery>,
    pub lid_present: bool,
    pub sleep_available: bool,
    pub hibernate_available: bool,
    pub hiberfile_present: bool,
    /// Modern standby (S0 low power idle) instead of classic sleep.
    pub modern_standby: bool,
    pub plan: PowerPlan,
    /// The power requests could be read (administrator rights).
    pub requests_read: bool,
    pub requests: Vec<PowerRequest>,
    pub events: Vec<SleepEvent>,
    pub wake_sources: Vec<WakeSource>,
    pub days: Vec<PowerDay>,
    pub sleeps: usize,
    pub wakes: usize,
    pub wake_tasks: Vec<WakeTask>,
    pub wake_devices_read: bool,
    pub wake_devices: Vec<String>,
    pub hints: Vec<PowerHint>,
    /// "requests_need_admin", "requests_unreadable", "events_unreadable", "battery_unreadable",
    /// "tasks_unreadable", "wake_devices_unreadable".
    pub notes: Vec<String>,
}

// ------------------------------------------------------------------------------ reading

/// Reads the battery, power requests, sleep history, wake sources and power plan. Changes nothing.
pub fn read() -> Power {
    let mut p = Power {
        read_ms: now_unix_ms(),
        ..Power::default()
    };
    read_status(&mut p);
    read_capabilities(&mut p);
    if p.has_battery {
        match read_batteries() {
            Ok(batteries) => p.batteries = batteries,
            Err(_) => p.notes.push("battery_unreadable".into()),
        }
    }
    p.plan = read_plan();
    if crate::elevation::is_elevated() {
        match powercfg(&["/requests"]) {
            Some(text) => {
                p.requests = map_paths(parse_requests(&text));
                p.requests_read = true;
            }
            None => p.notes.push("requests_unreadable".into()),
        }
    } else {
        p.notes.push("requests_need_admin".into());
    }
    match read_events() {
        Some(events) => p.events = events,
        None => p.notes.push("events_unreadable".into()),
    }
    match crate::tasks::list() {
        Ok(tasks) => p.wake_tasks = wake_tasks(&tasks),
        Err(_) => p.notes.push("tasks_unreadable".into()),
    }
    match powercfg(&["/devicequery", "wake_armed"]) {
        Some(text) => {
            p.wake_devices = parse_device_list(&text);
            p.wake_devices_read = true;
        }
        None => p.notes.push("wake_devices_unreadable".into()),
    }
    finish(&mut p, now_unix_ms());
    p
}

fn read_status(p: &mut Power) {
    let mut status = SYSTEM_POWER_STATUS::default();
    // SAFETY: `status` is a valid, writable structure for the call.
    if unsafe { GetSystemPowerStatus(&mut status) }.is_err() {
        return;
    }
    p.on_ac = match status.ACLineStatus {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    };
    // 128: no system battery; 255: unknown.
    p.has_battery = status.BatteryFlag != 128 && status.BatteryFlag != 255;
    if p.has_battery && status.BatteryLifePercent <= 100 {
        p.battery_percent = Some(u32::from(status.BatteryLifePercent));
    }
}

fn read_capabilities(p: &mut Power) {
    let mut caps = SYSTEM_POWER_CAPABILITIES::default();
    // SAFETY: `caps` is a valid, writable structure for the call.
    if !unsafe { GetPwrCapabilities(&mut caps) } {
        return;
    }
    p.lid_present = caps.LidPresent;
    p.sleep_available = caps.SystemS3 || caps.SystemS1 || caps.SystemS2 || caps.AoAc;
    p.hibernate_available = caps.SystemS4 && caps.HiberFilePresent;
    p.hiberfile_present = caps.HiberFilePresent;
    p.modern_standby = caps.AoAc;
    p.has_battery |= caps.SystemBatteriesPresent;
}

/// The batteries through their device interfaces.
fn read_batteries() -> Result<Vec<Battery>, String> {
    // SAFETY: SetupAPI calls on a device information set owned here and destroyed below; buffers
    // passed are writable for the sizes given.
    unsafe {
        let set = SetupDiGetClassDevsW(
            Some(&GUID_DEVICE_BATTERY),
            PCWSTR::null(),
            None,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
        .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for index in 0..MAX_BATTERIES {
            let mut data = SP_DEVICE_INTERFACE_DATA {
                cbSize: std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
                ..Default::default()
            };
            if SetupDiEnumDeviceInterfaces(set, None, &GUID_DEVICE_BATTERY, index, &mut data).is_err() {
                break;
            }
            let mut needed = 0u32;
            let _ = SetupDiGetDeviceInterfaceDetailW(set, &data, None, 0, Some(&mut needed), None);
            if !(8..=4096).contains(&needed) {
                continue;
            }
            // u64 storage keeps the structure aligned.
            let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
            let detail = storage.as_mut_ptr().cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
            (*detail).cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
            if SetupDiGetDeviceInterfaceDetailW(set, &data, Some(detail), needed, None, None).is_err() {
                continue;
            }
            let path_ptr = std::ptr::addr_of!((*detail).DevicePath).cast::<u16>();
            if let Some(battery) = read_battery(PCWSTR(path_ptr)) {
                out.push(battery);
            }
        }
        let _ = SetupDiDestroyDeviceInfoList(set);
        Ok(out)
    }
}

/// One battery by its device path.
///
/// # Safety
/// `path` must be a valid NUL-terminated wide string for the duration of the call.
unsafe fn read_battery(path: PCWSTR) -> Option<Battery> {
    // SAFETY: the caller guarantees `path`; the handle is closed below on every path.
    let handle = unsafe {
        CreateFileW(
            path,
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .ok()?;
    let battery = query_battery(handle);
    // SAFETY: closes the handle opened above, exactly once.
    let _ = unsafe { CloseHandle(handle) };
    battery
}

fn ioctl<I, O>(handle: HANDLE, code: u32, input: &I, output: &mut O) -> bool {
    let mut returned = 0u32;
    // SAFETY: `input` and `output` are valid for their sizes for the duration of the call.
    unsafe {
        DeviceIoControl(
            handle,
            code,
            Some(std::ptr::from_ref(input).cast()),
            std::mem::size_of::<I>() as u32,
            Some(std::ptr::from_mut(output).cast()),
            std::mem::size_of::<O>() as u32,
            Some(&mut returned),
            None,
        )
    }
    .is_ok()
}

/// A wide string the battery driver returns for an information level ("" when it has none).
fn battery_text(handle: HANDLE, tag: u32, level: BATTERY_QUERY_INFORMATION_LEVEL) -> String {
    let query = BATTERY_QUERY_INFORMATION {
        BatteryTag: tag,
        InformationLevel: level,
        AtRate: 0,
    };
    let mut buffer = [0u16; 128];
    if ioctl(handle, IOCTL_BATTERY_QUERY_INFORMATION, &query, &mut buffer) {
        from_wide(&buffer).trim().to_string()
    } else {
        String::new()
    }
}

fn query_battery(handle: HANDLE) -> Option<Battery> {
    let wait = 0u32;
    let mut tag = 0u32;
    if !ioctl(handle, IOCTL_BATTERY_QUERY_TAG, &wait, &mut tag) || tag == 0 {
        return None;
    }
    let query = BATTERY_QUERY_INFORMATION {
        BatteryTag: tag,
        InformationLevel: BatteryInformation,
        AtRate: 0,
    };
    let mut info = BATTERY_INFORMATION::default();
    if !ioctl(handle, IOCTL_BATTERY_QUERY_INFORMATION, &query, &mut info) {
        return None;
    }
    let wait_status = BATTERY_WAIT_STATUS {
        BatteryTag: tag,
        ..Default::default()
    };
    let mut status = BATTERY_STATUS::default();
    let status = ioctl(handle, IOCTL_BATTERY_QUERY_STATUS, &wait_status, &mut status).then_some(status);
    let estimate_query = BATTERY_QUERY_INFORMATION {
        BatteryTag: tag,
        InformationLevel: BatteryEstimatedTime,
        AtRate: 0,
    };
    let mut estimate = BATTERY_UNKNOWN_TIME;
    if !ioctl(handle, IOCTL_BATTERY_QUERY_INFORMATION, &estimate_query, &mut estimate) {
        estimate = BATTERY_UNKNOWN_TIME;
    }
    Some(battery_from(
        &info,
        status.as_ref(),
        battery_text(handle, tag, BatteryDeviceName),
        battery_text(handle, tag, BatteryManufactureName),
        estimate,
    ))
}

/// A battery from the driver's structures (pure: tests call it on fixture values).
pub fn battery_from(
    info: &BATTERY_INFORMATION,
    status: Option<&BATTERY_STATUS>,
    name: String,
    manufacturer: String,
    estimate: u32,
) -> Battery {
    let known = |value: u32| (value != BATTERY_UNKNOWN_CAPACITY && value != 0).then_some(value);
    let design = known(info.DesignedCapacity);
    let full = known(info.FullChargedCapacity);
    let health_percent = match (design, full) {
        (Some(d), Some(f)) => Some(((u64::from(f) * 100 + u64::from(d) / 2) / u64::from(d)) as u32),
        _ => None,
    };
    let chemistry: String = info
        .Chemistry
        .iter()
        .take_while(|&&b| b != 0)
        .filter(|b| b.is_ascii_graphic())
        .map(|&b| char::from(b))
        .collect();
    let mut battery = Battery {
        name,
        manufacturer,
        chemistry,
        rechargeable: info.Technology == 1,
        relative: info.Capabilities & BATTERY_CAPACITY_RELATIVE != 0,
        design_mwh: design,
        full_mwh: full,
        health_percent,
        cycle_count: (info.CycleCount > 0).then_some(info.CycleCount),
        state: "unknown".into(),
        estimated_seconds: (estimate != BATTERY_UNKNOWN_TIME && estimate > 0).then_some(estimate),
        ..Battery::default()
    };
    if let Some(s) = status {
        battery.remaining_mwh = (s.Capacity != BATTERY_UNKNOWN_CAPACITY).then_some(s.Capacity);
        battery.voltage_mv = (s.Voltage != BATTERY_UNKNOWN_VOLTAGE && s.Voltage > 0).then_some(s.Voltage);
        battery.rate_mw = (s.Rate != BATTERY_UNKNOWN_RATE).then_some(s.Rate);
        battery.critical = s.PowerState & BATTERY_CRITICAL != 0;
        battery.state = if s.PowerState & BATTERY_CHARGING != 0 {
            "charging"
        } else if s.PowerState & BATTERY_DISCHARGING != 0 {
            "discharging"
        } else if s.PowerState & BATTERY_POWER_ON_LINE != 0 {
            "plugged_in"
        } else {
            "unknown"
        }
        .into();
        if let (Some(remaining), Some(full)) = (battery.remaining_mwh, full) {
            battery.charge_percent = Some((u64::from(remaining) * 100 / u64::from(full)).min(100) as u32);
        }
    }
    battery
}

/// The active power plan's sleep settings.
fn read_plan() -> PowerPlan {
    let mut plan = PowerPlan::default();
    let mut pointer: *mut GUID = std::ptr::null_mut();
    // SAFETY: `pointer` receives a GUID allocated by Windows, freed below with LocalFree.
    let status = unsafe { PowerGetActiveScheme(None, &mut pointer) };
    if status != ERROR_SUCCESS || pointer.is_null() {
        return plan;
    }
    // SAFETY: on success `pointer` points at a valid GUID; copied before it is freed.
    let scheme = unsafe { *pointer };
    // SAFETY: frees the buffer PowerGetActiveScheme allocated, exactly once.
    let _ = unsafe { LocalFree(Some(HLOCAL(pointer.cast()))) };
    plan.guid = format!("{scheme:?}").to_lowercase();
    plan.name = plan_name(&scheme);
    let read = |sub: &GUID, setting: &GUID| -> (Option<u32>, Option<u32>) {
        let (mut ac, mut dc) = (0u32, 0u32);
        // SAFETY: every GUID pointer is valid for the call; the outputs are writable.
        let ac_ok = unsafe { PowerReadACValueIndex(None, Some(&scheme), Some(sub), Some(setting), &mut ac) };
        // SAFETY: as above.
        let dc_ok = unsafe { PowerReadDCValueIndex(None, Some(&scheme), Some(sub), Some(setting), &mut dc) };
        (
            (ac_ok == ERROR_SUCCESS).then_some(ac),
            (dc_ok == ERROR_SUCCESS.0).then_some(dc),
        )
    };
    (plan.sleep_ac, plan.sleep_dc) = read(&SUB_SLEEP, &STANDBY_TIMEOUT);
    (plan.hibernate_ac, plan.hibernate_dc) = read(&SUB_SLEEP, &HIBERNATE_TIMEOUT);
    (plan.wake_timers_ac, plan.wake_timers_dc) = read(&SUB_SLEEP, &ALLOW_WAKE_TIMERS);
    (plan.display_ac, plan.display_dc) = read(&SUB_VIDEO, &VIDEO_TIMEOUT);
    (plan.lid_ac, plan.lid_dc) = read(&SUB_BUTTONS, &LID_ACTION);
    plan
}

fn plan_name(scheme: &GUID) -> String {
    let mut size = 0u32;
    // SAFETY: a null buffer asks for the size only; `scheme` and `size` are valid.
    let status = unsafe { PowerReadFriendlyName(None, Some(scheme), None, None, None, &mut size) };
    if status != ERROR_SUCCESS || size == 0 || size > 4096 {
        return String::new();
    }
    let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
    let mut bytes = (buffer.len() * 2) as u32;
    // SAFETY: `buffer` is writable and `bytes` holds its size in bytes.
    let status = unsafe {
        PowerReadFriendlyName(
            None,
            Some(scheme),
            None,
            None,
            Some(buffer.as_mut_ptr().cast()),
            &mut bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return String::new();
    }
    from_wide(&buffer).trim().to_string()
}

/// `%SystemRoot%\System32\powercfg.exe` with `args`: its output, or `None` when it failed.
fn powercfg(args: &[&str]) -> Option<String> {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut dir = [0u16; 260];
    // SAFETY: the buffer is writable for its whole length.
    let length = unsafe { GetSystemDirectoryW(Some(&mut dir)) } as usize;
    if length == 0 || length >= dir.len() {
        return None;
    }
    let exe = std::path::PathBuf::from(String::from_utf16_lossy(&dir[..length])).join("powercfg.exe");
    let mut command = Command::new(exe);
    crate::paths::apply_child_env(&mut command);
    let mut child = command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.by_ref().take(1 << 20).read_to_end(&mut bytes);
        bytes
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() < TOOL_TIMEOUT => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let bytes = reader.join().ok()?;
    if !status?.success() {
        return None;
    }
    Some(decode(&bytes))
}

/// Console output: UTF-8 when it is valid, else the OEM code page the console uses.
fn decode(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    use windows::Win32::Globalization::{CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS, MultiByteToWideChar};
    // SAFETY: a null output buffer asks for the length only.
    let length = unsafe { MultiByteToWideChar(CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, None) };
    if length <= 0 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut wide = vec![0u16; length as usize];
    // SAFETY: `wide` is writable for the length asked above.
    let written = unsafe { MultiByteToWideChar(CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, Some(&mut wide)) };
    String::from_utf16_lossy(&wide[..written.max(0) as usize])
}

/// The power requests from `powercfg /requests` output (pure: tests call it on fixture text).
///
/// The output is a section per request kind (`DISPLAY:`, `SYSTEM:`, `AWAYMODE:`, `EXECUTION:`,
/// `PERFBOOST:`, `ACTIVELOCKSCREEN:`), each listing `[PROCESS] path`, `[SERVICE] name` or
/// `[DRIVER] device` lines, each followed by the reason the requester gave. A section with no
/// request says "None." in the system's language.
pub fn parse_requests(text: &str) -> Vec<PowerRequest> {
    let mut out: Vec<PowerRequest> = Vec::new();
    let mut kind = String::new();
    let mut current: Option<PowerRequest> = None;
    let flush = |current: &mut Option<PowerRequest>, out: &mut Vec<PowerRequest>| {
        if let Some(mut request) = current.take() {
            request.reason = request.reason.trim().to_string();
            if out.len() < MAX_LISTED {
                out.push(request);
            }
        }
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            flush(&mut current, &mut out);
            continue;
        }
        if let Some(head) = line.strip_suffix(':')
            && !head.is_empty()
            && head.chars().all(|c| c.is_ascii_uppercase())
        {
            flush(&mut current, &mut out);
            kind = head.to_ascii_lowercase();
            continue;
        }
        if let Some(rest) = line.strip_prefix('[')
            && let Some((tag, name)) = rest.split_once(']')
        {
            flush(&mut current, &mut out);
            if kind.is_empty() {
                continue;
            }
            let source = match tag.trim().to_ascii_uppercase().as_str() {
                "PROCESS" => "process",
                "SERVICE" => "service",
                "DRIVER" => "driver",
                _ => "other",
            };
            current = Some(PowerRequest {
                kind: kind.clone(),
                source: source.into(),
                name: name.trim().to_string(),
                reason: String::new(),
            });
            continue;
        }
        // A reason line (or a section's "None.", which belongs to no request).
        if let Some(request) = current.as_mut() {
            if !request.reason.is_empty() {
                request.reason.push(' ');
            }
            request.reason.push_str(line);
        }
    }
    flush(&mut current, &mut out);
    out
}

/// Device paths of process requests as drive-letter paths.
fn map_paths(mut requests: Vec<PowerRequest>) -> Vec<PowerRequest> {
    if requests.iter().any(|r| r.name.starts_with(r"\Device\")) {
        let resolver = crate::process::PathResolver::new();
        for request in &mut requests {
            if request.name.starts_with(r"\Device\") {
                request.name = resolver.map(&request.name);
            }
        }
    }
    requests
}

/// Device names from `powercfg /devicequery` output; "NONE" (or an empty list) means none.
pub fn parse_device_list(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.eq_ignore_ascii_case("none") {
            return Vec::new();
        }
        if out.len() < MAX_LISTED && !out.iter().any(|d| d == line) {
            out.push(line.to_string());
        }
    }
    out
}

/// The sleep and wake events of the last [`EVENT_DAYS`] days, newest first.
fn read_events() -> Option<Vec<SleepEvent>> {
    let window_ms = EVENT_DAYS * DAY_MS;
    let query = format!(
        "*[System[TimeCreated[timediff(@SystemTime) <= {window_ms}] and \
         ((Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1) or \
         (Provider[@Name='Microsoft-Windows-Kernel-Power'] and \
         (EventID=42 or EventID=107 or EventID=506 or EventID=507)))]]"
    );
    let (records, _) = LogReader::default().query("System", &query, false).ok()?;
    let mut events: Vec<SleepEvent> = records.iter().filter_map(|(xml, _)| event_from(xml)).collect();
    events.sort_by_key(|e| std::cmp::Reverse(e.time_ms));
    events.truncate(MAX_EVENTS);
    Some(events)
}

/// One sleep, resume or wake event (pure: tests call it on fixture XML).
pub fn event_from(xml: &str) -> Option<SleepEvent> {
    let record = Record::parse(xml)?;
    let provider = record.provider.to_ascii_lowercase();
    let mut event = SleepEvent {
        time_ms: record.time_ms,
        time: local_time(record.time_ms),
        ..SleepEvent::default()
    };
    if provider.ends_with("power-troubleshooter") && record.event_id == 1 {
        event.kind = "wake".into();
        let text = record.get("WakeSourceText", usize::MAX).trim().to_string();
        let owner = record.get("WakeTimerOwner", usize::MAX).trim().to_string();
        if !owner.is_empty() {
            event.source = owner;
            event.source_kind = "timer".into();
        } else if !text.is_empty() {
            event.source = text;
            event.source_kind = "device".into();
        }
        if let (Some(slept), Some(woke)) = (
            iso_utc_ms(record.get("SleepTime", usize::MAX)),
            iso_utc_ms(record.get("WakeTime", usize::MAX)),
        ) && woke > slept
        {
            event.slept_minutes = Some(((woke - slept) / 60_000) as u64);
        }
        return Some(event);
    }
    if !provider.ends_with("kernel-power") {
        return None;
    }
    let reason = record.get("Reason", usize::MAX).trim().to_string();
    match record.event_id {
        42 => {
            // TargetState is a SYSTEM_POWER_STATE: 5 is hibernation, 2–4 are sleep states.
            event.kind = if record.get("TargetState", usize::MAX).trim() == "5" {
                "hibernate"
            } else {
                "sleep"
            }
            .into();
            event.reason = reason;
        }
        107 => event.kind = "resume".into(),
        506 => {
            event.kind = "standby_enter".into();
            event.reason = reason;
        }
        507 => {
            event.kind = "standby_exit".into();
            event.reason = reason;
        }
        _ => return None,
    }
    Some(event)
}

/// Tasks allowed to wake the computer (enabled first).
pub fn wake_tasks(tasks: &[crate::tasks::ScheduledTask]) -> Vec<WakeTask> {
    let mut out: Vec<WakeTask> = tasks
        .iter()
        .filter(|t| t.wake_to_run)
        .map(|t| WakeTask {
            path: t.path.clone(),
            name: t.name.clone(),
            enabled: t.enabled,
            next_run: t.next_run.clone(),
            program: t.program.clone(),
            microsoft: t.microsoft,
        })
        .collect();
    out.sort_by(|a, b| b.enabled.cmp(&a.enabled).then_with(|| a.path.cmp(&b.path)));
    out.truncate(MAX_LISTED);
    out
}

// ------------------------------------------------------------------------------ judging

/// Groups the wakes, counts the days and draws the hints (pure: tests call it on fixture data).
pub fn finish(p: &mut Power, now_ms: i64) {
    p.events.sort_by_key(|e| std::cmp::Reverse(e.time_ms));
    p.events.truncate(MAX_EVENTS);
    let is_sleep = |e: &SleepEvent| matches!(e.kind.as_str(), "sleep" | "hibernate");
    p.sleeps = p.events.iter().filter(|e| is_sleep(e)).count();
    p.wakes = p.events.iter().filter(|e| e.kind == "wake").count();
    let mut groups: BTreeMap<String, WakeSource> = BTreeMap::new();
    for e in p.events.iter().filter(|e| e.kind == "wake") {
        let key = e.source.to_lowercase();
        let group = groups.entry(key).or_insert_with(|| WakeSource {
            source: e.source.clone(),
            source_kind: e.source_kind.clone(),
            ..WakeSource::default()
        });
        group.count += 1;
        group.last_ms = group.last_ms.max(e.time_ms);
    }
    p.wake_sources = groups.into_values().collect();
    p.wake_sources
        .sort_by(|a, b| b.count.cmp(&a.count).then(b.last_ms.cmp(&a.last_ms)));
    let mut days: BTreeMap<String, PowerDay> = BTreeMap::new();
    for e in &p.events {
        let date = e.time.get(..10).unwrap_or_default().to_string();
        if date.len() != 10 {
            continue;
        }
        let day = days.entry(date.clone()).or_insert_with(|| PowerDay {
            date,
            ..PowerDay::default()
        });
        if is_sleep(e) {
            day.sleeps += 1;
        } else if e.kind == "wake" {
            day.wakes += 1;
        }
    }
    p.days = days.into_values().collect();
    p.hints = hints(p, now_ms);
}

fn hint(code: &'static str, severity: &'static str, subject: &str, count: u64) -> PowerHint {
    PowerHint {
        code,
        severity,
        subject: subject.to_string(),
        count,
    }
}

/// The hints, most pressing first.
pub fn hints(p: &Power, _now_ms: i64) -> Vec<PowerHint> {
    let mut out = Vec::new();
    for battery in &p.batteries {
        let Some(health) = battery.health_percent.filter(|_| !battery.relative) else {
            continue;
        };
        if health < REPLACE_PERCENT {
            out.push(hint("battery_replace", "warn", &battery.name, u64::from(health)));
        } else if health < WORN_PERCENT {
            out.push(hint("battery_worn", "warn", &battery.name, u64::from(health)));
        }
    }
    let awake: Vec<&PowerRequest> = p
        .requests
        .iter()
        .filter(|r| matches!(r.kind.as_str(), "display" | "system" | "awaymode"))
        .collect();
    if let Some(first) = awake.first() {
        out.push(hint("kept_awake", "info", &first.name, awake.len() as u64));
    }
    if let Some(timer) = p
        .wake_sources
        .iter()
        .filter(|s| s.source_kind == "timer")
        .max_by_key(|s| s.count)
        .filter(|s| s.count >= 3)
    {
        out.push(hint("timer_wakes", "info", &timer.source, timer.count as u64));
    }
    if p.wakes >= (EVENT_DAYS as usize) * 3 {
        out.push(hint("frequent_wakes", "info", "", p.wakes as u64));
    }
    let timers_on = p.plan.wake_timers_ac.is_some_and(|v| v != 0) || p.plan.wake_timers_dc.is_some_and(|v| v != 0);
    let enabled = p.wake_tasks.iter().filter(|t| t.enabled && !t.microsoft).count();
    if timers_on && enabled > 0 {
        out.push(hint("wake_tasks", "info", "", enabled as u64));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    fn info(design: u32, full: u32, cycles: u32) -> BATTERY_INFORMATION {
        BATTERY_INFORMATION {
            Capabilities: 0x8000_0000,
            Technology: 1,
            Chemistry: *b"LION",
            DesignedCapacity: design,
            FullChargedCapacity: full,
            CycleCount: cycles,
            ..Default::default()
        }
    }

    #[test]
    fn battery_figures_are_read() {
        let status = BATTERY_STATUS {
            PowerState: BATTERY_DISCHARGING,
            Capacity: 27_000,
            Voltage: 11_400,
            Rate: -8_500,
        };
        let b = battery_from(
            &info(54_000, 40_500, 312),
            Some(&status),
            "Contoso 5K9".into(),
            "Contoso".into(),
            10_800,
        );
        assert_eq!(b.health_percent, Some(75));
        assert_eq!(b.cycle_count, Some(312));
        assert_eq!(b.chemistry, "LION");
        assert!(b.rechargeable && !b.relative);
        assert_eq!(b.state, "discharging");
        assert_eq!(b.charge_percent, Some(66));
        assert_eq!((b.rate_mw, b.voltage_mv), (Some(-8_500), Some(11_400)));
        assert_eq!(b.estimated_seconds, Some(10_800));

        let charging = BATTERY_STATUS {
            PowerState: BATTERY_POWER_ON_LINE | BATTERY_CHARGING,
            Capacity: BATTERY_UNKNOWN_CAPACITY,
            Voltage: BATTERY_UNKNOWN_VOLTAGE,
            Rate: BATTERY_UNKNOWN_RATE,
        };
        let c = battery_from(
            &info(BATTERY_UNKNOWN_CAPACITY, 40_000, 0),
            Some(&charging),
            String::new(),
            String::new(),
            BATTERY_UNKNOWN_TIME,
        );
        assert_eq!(c.state, "charging");
        assert_eq!((c.health_percent, c.cycle_count, c.remaining_mwh), (None, None, None));
        assert_eq!((c.rate_mw, c.voltage_mv, c.estimated_seconds), (None, None, None));

        let plugged = BATTERY_STATUS {
            PowerState: BATTERY_POWER_ON_LINE,
            ..Default::default()
        };
        let mut relative = info(100, 100, 0);
        relative.Capabilities |= BATTERY_CAPACITY_RELATIVE;
        let r = battery_from(&relative, Some(&plugged), String::new(), String::new(), 0);
        assert!(r.relative);
        assert_eq!(r.state, "plugged_in");
        assert_eq!(
            battery_from(&relative, None, String::new(), String::new(), 0).state,
            "unknown"
        );
    }

    const REQUESTS: &str = "DISPLAY:\r\n[PROCESS] \\Device\\HarddiskVolume3\\Program Files\\Contoso\\Player\\player.exe\r\nVideo Wake Lock\r\n\r\nSYSTEM:\r\n[DRIVER] Contoso High Definition Audio Device (HDAUDIO\\FUNC_01&VEN_10EC&DEV_0897)\r\nAn audio stream is currently in use.\r\n[SERVICE] \\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe (Fabrikam Sync)\r\nSyncing files\r\nto the cloud\r\n\r\nAWAYMODE:\r\nNone.\r\n\r\nEXECUTION:\r\nNinguno.\r\n\r\nPERFBOOST:\r\nNone.\r\n\r\nACTIVELOCKSCREEN:\r\nNone.\r\n";

    #[test]
    fn power_requests_are_parsed() {
        let r = parse_requests(REQUESTS);
        assert_eq!(r.len(), 3);
        assert_eq!(
            (r[0].kind.as_str(), r[0].source.as_str(), r[0].reason.as_str()),
            ("display", "process", "Video Wake Lock")
        );
        assert!(r[0].name.ends_with(r"Contoso\Player\player.exe"));
        assert_eq!((r[1].kind.as_str(), r[1].source.as_str()), ("system", "driver"));
        assert_eq!(r[2].source, "service");
        assert_eq!(r[2].reason, "Syncing files to the cloud");
        assert!(parse_requests("DISPLAY:\nNone.\n\nSYSTEM:\nNone.\n").is_empty());
        assert!(parse_requests("").is_empty());
    }

    #[test]
    fn wake_devices_are_parsed() {
        assert_eq!(
            parse_device_list("HID Keyboard Device\r\nContoso Ethernet Controller\r\nHID Keyboard Device\r\n\r\n"),
            ["HID Keyboard Device", "Contoso Ethernet Controller"]
        );
        assert!(parse_device_list("NONE\r\n").is_empty());
        assert!(parse_device_list("").is_empty());
    }

    fn xml(provider: &str, id: u32, time: &str, data: &[(&str, &str)]) -> String {
        let data: String = data
            .iter()
            .map(|(n, v)| format!(r#"<Data Name="{n}">{v}</Data>"#))
            .collect();
        format!(
            r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{provider}"/><EventID>{id}</EventID><Level>4</Level><TimeCreated SystemTime="{time}"/><EventRecordID>9</EventRecordID><Channel>System</Channel><Computer>PC-VICTIM</Computer></System><EventData>{data}</EventData></Event>"#
        )
    }

    #[test]
    fn sleep_and_wake_events_are_read() {
        let wake = event_from(&xml(
            "Microsoft-Windows-Power-Troubleshooter",
            1,
            "2026-11-20T07:00:05.0000000Z",
            &[
                ("SleepTime", "2026-11-19T23:00:00.0000000Z"),
                ("WakeTime", "2026-11-20T07:00:00.0000000Z"),
                ("WakeSourceType", "5"),
                ("WakeSourceText", "Power Button"),
                ("WakeTimerOwner", ""),
            ],
        ))
        .expect("wake");
        assert_eq!(
            (wake.kind.as_str(), wake.source.as_str(), wake.source_kind.as_str()),
            ("wake", "Power Button", "device")
        );
        assert_eq!(wake.slept_minutes, Some(480));

        let timer = event_from(&xml(
            "Microsoft-Windows-Power-Troubleshooter",
            1,
            "2026-11-20T03:00:00.0000000Z",
            &[
                ("WakeSourceText", ""),
                (
                    "WakeTimerOwner",
                    r"\Device\HarddiskVolume3\Windows\System32\svchost.exe",
                ),
            ],
        ))
        .expect("timer");
        assert_eq!(timer.source_kind, "timer");

        let kernel = |id: u32, data: &[(&str, &str)]| {
            event_from(&xml("Microsoft-Windows-Kernel-Power", id, "2026-11-20T01:00:00Z", data)).expect("kernel")
        };
        assert_eq!(kernel(42, &[("TargetState", "4"), ("Reason", "0")]).kind, "sleep");
        assert_eq!(kernel(42, &[("TargetState", "5")]).kind, "hibernate");
        assert_eq!(kernel(107, &[]).kind, "resume");
        let exit = kernel(507, &[("Reason", "31")]);
        assert_eq!((exit.kind.as_str(), exit.reason.as_str()), ("standby_exit", "31"));
        assert_eq!(kernel(506, &[]).kind, "standby_enter");
        assert!(event_from(&xml("Microsoft-Windows-Kernel-Power", 41, "2026-11-20T01:00:00Z", &[])).is_none());
        assert!(event_from(&xml("Contoso-Power", 1, "2026-11-20T01:00:00Z", &[])).is_none());
    }

    fn wake_event(day: u32, hour: u32, source: &str, kind: &str) -> SleepEvent {
        let time = format!("2026-11-{day:02}T{hour:02}:00:00");
        SleepEvent {
            time_ms: NOW - i64::from(30 - day) * DAY_MS + i64::from(hour) * 3_600_000,
            time,
            kind: "wake".into(),
            source: source.into(),
            source_kind: kind.into(),
            ..SleepEvent::default()
        }
    }

    #[test]
    fn wakes_are_grouped_and_hints_drawn() {
        let mut events = vec![
            wake_event(18, 3, "Contoso Updater", "timer"),
            wake_event(19, 3, "Contoso Updater", "timer"),
            wake_event(20, 3, "Contoso Updater", "timer"),
            wake_event(20, 8, "Power Button", "device"),
        ];
        events.push(SleepEvent {
            time: "2026-11-20T01:00:00".into(),
            time_ms: NOW - 10 * DAY_MS,
            kind: "sleep".into(),
            ..SleepEvent::default()
        });
        let mut p = Power {
            batteries: vec![battery_from(
                &info(50_000, 27_000, 800),
                None,
                "Contoso 5K9".into(),
                String::new(),
                0,
            )],
            requests: parse_requests(REQUESTS),
            events,
            plan: PowerPlan {
                wake_timers_ac: Some(1),
                ..PowerPlan::default()
            },
            wake_tasks: vec![WakeTask {
                path: r"\Contoso\Updater".into(),
                enabled: true,
                ..WakeTask::default()
            }],
            ..Power::default()
        };
        finish(&mut p, NOW);
        assert_eq!((p.wakes, p.sleeps), (4, 1));
        assert_eq!(p.wake_sources[0].source, "Contoso Updater");
        assert_eq!(p.wake_sources[0].count, 3);
        assert_eq!(p.days.len(), 3);
        assert_eq!(p.days.last().map(|d| (d.wakes, d.sleeps)), Some((2, 1)));
        let codes: Vec<&str> = p.hints.iter().map(|h| h.code).collect();
        assert_eq!(codes, ["battery_replace", "kept_awake", "timer_wakes", "wake_tasks"]);
        assert_eq!(p.hints[0].count, 54);
        assert_eq!(p.hints[1].count, 3, "the display and system requests");

        let mut worn = Power {
            batteries: vec![battery_from(
                &info(50_000, 37_500, 0),
                None,
                String::new(),
                String::new(),
                0,
            )],
            ..Power::default()
        };
        finish(&mut worn, NOW);
        assert_eq!(worn.hints[0].code, "battery_worn");
        let mut healthy = Power {
            batteries: vec![battery_from(
                &info(50_000, 48_000, 0),
                None,
                String::new(),
                String::new(),
                0,
            )],
            ..Power::default()
        };
        finish(&mut healthy, NOW);
        assert!(healthy.hints.is_empty());
    }

    #[test]
    fn wake_tasks_come_from_the_task_list() {
        let task = |path: &str, wake: bool, enabled: bool| crate::tasks::ScheduledTask {
            path: path.into(),
            name: path.rsplit('\\').next().unwrap_or_default().into(),
            wake_to_run: wake,
            enabled,
            microsoft: path.starts_with(r"\Microsoft\"),
            ..Default::default()
        };
        let tasks = vec![
            task(r"\Microsoft\Windows\UpdateOrchestrator\Reboot", true, false),
            task(r"\Contoso\Backup", true, true),
            task(r"\Fabrikam\Report", false, true),
        ];
        let w = wake_tasks(&tasks);
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].path, r"\Contoso\Backup", "enabled first");
        let xml = r"<Task><Settings><WakeToRun>true</WakeToRun></Settings></Task>";
        assert!(crate::tasks::from_xml(r"\Contoso\Backup", xml).wake_to_run);
        assert!(!crate::tasks::from_xml(r"\Contoso\Backup", "<Task/>").wake_to_run);
    }

    #[test]
    #[ignore = "reads this computer's battery, power requests and sleep history; run by hand"]
    fn live_read_counts_only() {
        let started = Instant::now();
        let p = read();
        println!(
            "battery {} ({} read) ac {:?} sleep {} hibernate {} modern standby {} lid {} requests read {} ({}) events {} wakes {} sleeps {} sources {} days {} wake tasks {} wake devices read {} ({}) plan timeouts {:?}/{:?} hints {:?} notes {:?} in {:?}",
            p.has_battery,
            p.batteries.len(),
            p.on_ac,
            p.sleep_available,
            p.hibernate_available,
            p.modern_standby,
            p.lid_present,
            p.requests_read,
            p.requests.len(),
            p.events.len(),
            p.wakes,
            p.sleeps,
            p.wake_sources.len(),
            p.days.len(),
            p.wake_tasks.len(),
            p.wake_devices_read,
            p.wake_devices.len(),
            p.plan.sleep_ac,
            p.plan.sleep_dc,
            p.hints.iter().map(|h| h.code).collect::<Vec<_>>(),
            p.notes,
            started.elapsed()
        );
    }
}
