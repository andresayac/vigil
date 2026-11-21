//! Optimization operations: process priority and efficiency mode, memory, power plans, hibernation,
//! per-app GPU preference, gaming settings, service start type, drive optimization and component cleanup.
//!
//! The honest rule for memory: Windows already uses free RAM as a cache and gives it back the moment a
//! program needs it, so trimming working sets or purging the standby list only helps in specific cases.
//! The explanations shown in the app say so; nothing here pretends to make a PC faster by itself.

use std::ffi::c_void;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};
use windows::Win32::Foundation::{CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, LUID, NTSTATUS};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{HSTRING, PCWSTR};

use crate::cmdline::{basename, is_abs, normpath};
use crate::engine::{Builtin, Outcome, run_fn, undo_fn};
use crate::error::{ActionError, Result, fail};
use crate::guards::guard_service;
use crate::ops::{live_process, sc, service_reg, service_start, start_arg, undo_service_disable};
use crate::params::{Params, text_of};
use crate::procs;
use crate::registry::{reg_read, reg_write, restore_value};
use crate::runner::{first_line, ps_ok, run, tool};
use crate::store::Store;
use vigil_i18n::{tl, tr};

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtQuerySystemInformation(class: i32, info: *mut c_void, length: u32, returned: *mut u32) -> NTSTATUS;
    fn NtSetSystemInformation(class: i32, info: *mut c_void, length: u32) -> NTSTATUS;
}

pub const BALANCED_PLAN: &str = "381b4222-f694-41f0-9685-ff5bb260df2e";
pub const ULTIMATE_TEMPLATE: &str = "e9a42b02-d5df-448d-aa00-03f14749eb61";
const SYSTEM_MEMORY_LIST_INFORMATION: i32 = 80;
const MEMORY_PURGE_STANDBY_LIST: i32 = 4;

static GUID_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}").ok());

fn priority_label(name: &str) -> String {
    match name {
        "idle" => tr!("Low"),
        "below_normal" => tr!("Below normal"),
        "above_normal" => tr!("Above normal"),
        "high" => tr!("High"),
        _ => tr!("Normal"),
    }
}

/// A number with thousands separated by commas and a fixed count of decimals.
fn grouped(value: f64, decimals: usize) -> String {
    let text = format!("{:.*}", decimals, value.abs());
    let (whole, fraction) = text
        .split_once('.')
        .map_or((text.as_str(), None), |(w, f)| (w, Some(f)));
    let mut out = String::new();
    for (index, digit) in whole.chars().enumerate() {
        if index > 0 && (whole.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    if let Some(fraction) = fraction {
        out.push('.');
        out.push_str(fraction);
    }
    if value < 0.0 && text.chars().any(|c| c != '0' && c != '.') {
        format!("-{out}")
    } else {
        out
    }
}

/// A size for people: `1,234 bytes`, `12.5 MB`.
pub fn size_text(value: f64) -> String {
    let mut value = value;
    for unit in ["bytes", "KB", "MB", "GB", "TB"] {
        if value.abs() < 1024.0 || unit == "TB" {
            return if unit == "bytes" {
                format!("{} {unit}", grouped(value, 0))
            } else {
                format!("{} {unit}", grouped(value, 1))
            };
        }
        value /= 1024.0;
    }
    String::new()
}

// --------------------------------------------------------------------------- processes

fn op_priority(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let proc = live_process(p, true)?;
    let wanted = p.req_str("priority")?;
    let before = procs::set_priority(proc.pid, &wanted)?;
    let created = proc.create_time().map_or(Value::Null, |t| json!(t));
    Ok(Outcome::new(
        tr!(
            "{0} now runs at {1} priority (it was {2})",
            proc.describe(),
            priority_label(&wanted),
            priority_label(before)
        ),
        Some(json!({ "pid": proc.pid, "create_time": created, "priority": before })),
    ))
}

fn undo_priority(u: Params<'_>, store: &Store) -> Result<String> {
    Ok(op_priority(u, store, "")?.message)
}

fn op_efficiency(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let proc = live_process(p, true)?;
    procs::set_throttling(proc.pid, Some(true))?;
    let before = procs::set_priority(proc.pid, "idle")?;
    let created = proc.create_time().map_or(Value::Null, |t| json!(t));
    Ok(Outcome::new(
        tr!("{0} now runs in efficiency mode", proc.describe()),
        Some(json!({ "pid": proc.pid, "create_time": created, "priority": before })),
    ))
}

fn undo_efficiency(u: Params<'_>, _store: &Store) -> Result<String> {
    let proc = live_process(u, true)?;
    procs::set_throttling(proc.pid, None)?;
    let priority = u.str_or_empty("priority");
    procs::set_priority(proc.pid, if priority.is_empty() { "normal" } else { &priority })?;
    Ok(tr!("{0} left efficiency mode", proc.describe()))
}

/// Disk and memory priority only go down: the process keeps its CPU priority, but its reads and writes
/// wait behind other programs' and its pages are the first to leave RAM when memory runs short.
fn op_background(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let proc = live_process(p, true)?;
    let (io, memory) = procs::io_memory_priority(proc.pid)?;
    procs::set_io_memory_priority(proc.pid, io.min(1), memory.min(2))?;
    let created = proc.create_time().map_or(Value::Null, |t| json!(t));
    Ok(Outcome::new(
        tr!(
            "{0} now reads and writes at low priority, and its memory is the first to leave RAM when memory is short",
            proc.describe()
        ),
        Some(json!({ "pid": proc.pid, "create_time": created, "io_priority": io, "memory_priority": memory })),
    ))
}

fn undo_background(u: Params<'_>, _store: &Store) -> Result<String> {
    let proc = live_process(u, true)?;
    let io = u.int_or("io_priority", 2)?.clamp(0, 2) as u32;
    let memory = u.int_or("memory_priority", 5)?.clamp(1, 5) as u32;
    procs::set_io_memory_priority(proc.pid, io, memory)?;
    Ok(tr!(
        "{0} has its previous disk and memory priority again",
        proc.describe()
    ))
}

fn op_trim(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let proc = live_process(p, false)?;
    if proc.pid <= 4 {
        return fail(tr!("not allowed: it is part of the Windows kernel"));
    }
    let before = procs::rss(proc.pid);
    if !procs::empty_working_set(proc.pid) {
        // SAFETY: plain call.
        let code = unsafe { GetLastError() }.0;
        return fail(tr!("Windows refused the change (error {0})", code));
    }
    let after = procs::rss(proc.pid);
    Ok(Outcome::done(tr!(
        "{0} uses {1} of RAM now ({2} before). Windows brings pages back as soon as the program needs them.",
        proc.describe(),
        size_text(after as f64),
        size_text(before as f64)
    )))
}

const SKIP_TRIM: [&str; 5] = [
    "system",
    "registry",
    "memory compression",
    "secure system",
    "system idle process",
];

fn op_trim_all(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let available = procs::available_memory();
    let own = std::process::id();
    let mut trimmed = 0usize;
    for row in procs::list() {
        if row.pid <= 4 || row.pid == own || SKIP_TRIM.contains(&row.name.to_lowercase().as_str()) {
            continue;
        }
        if procs::empty_working_set(row.pid) {
            trimmed += 1;
        }
    }
    let after = procs::available_memory();
    Ok(Outcome::done(tr!(
        "trimmed {0} processes; available memory {1} → {2}. Pages come back on demand, so the number drifts back \
         as programs work.",
        trimmed,
        size_text(available as f64),
        size_text(after as f64)
    )))
}

struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcessToken and is closed only here.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn enable_privilege(name: &str) -> Result<()> {
    let mut handle = HANDLE::default();
    // SAFETY: valid out pointer; the token is closed by `Token`.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut handle) }
        .map_err(|_| ActionError::new(tr!("cannot open the process token")))?;
    let token = Token(handle);
    let mut luid = LUID::default();
    let wide = HSTRING::from(name);
    // SAFETY: `wide` outlives the call; valid out pointer.
    unsafe { LookupPrivilegeValueW(PCWSTR::null(), &wide, &mut luid) }
        .map_err(|_| ActionError::new(tr!("unknown privilege {0}", name)))?;
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: `privileges` is a valid TOKEN_PRIVILEGES with one entry.
    let adjusted = unsafe { AdjustTokenPrivileges(token.0, false, Some(&privileges), 0, None, None) };
    // SAFETY: plain call, right after AdjustTokenPrivileges.
    let last = unsafe { GetLastError() };
    if adjusted.is_err() || last == ERROR_NOT_ALL_ASSIGNED {
        return fail(tr!("this needs Vigil to run as administrator"));
    }
    Ok(())
}

/// SYSTEM_MEMORY_LIST_INFORMATION: 5 counters, then 8 standby counts by priority, 8 repurposed, 1 more.
fn standby_pages() -> Option<u64> {
    let mut info = [0usize; 22];
    // SAFETY: `info` is large enough for the structure and its size is passed.
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_MEMORY_LIST_INFORMATION,
            info.as_mut_ptr().cast::<c_void>(),
            size_of_val(&info) as u32,
            std::ptr::null_mut(),
        )
    };
    status.is_ok().then(|| info[5..13].iter().map(|&n| n as u64).sum())
}

fn page_size() -> u64 {
    let mut info = SYSTEM_INFO::default();
    // SAFETY: valid out pointer.
    unsafe { GetSystemInfo(&mut info) };
    u64::from(info.dwPageSize.max(4096))
}

fn op_purge_standby(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    enable_privilege("SeProfileSingleProcessPrivilege")?;
    let before = standby_pages();
    let mut command = MEMORY_PURGE_STANDBY_LIST;
    // SAFETY: `command` is a 4-byte integer, as the purge command expects.
    let status = unsafe {
        NtSetSystemInformation(
            SYSTEM_MEMORY_LIST_INFORMATION,
            (&raw mut command).cast::<c_void>(),
            size_of::<i32>() as u32,
        )
    };
    if status.is_err() {
        return fail(tr!(
            "Windows refused to purge the standby list (0x{0})",
            format!("{:08X}", status.0 as u32)
        ));
    }
    let after = standby_pages();
    if let (Some(before), Some(after)) = (before, after) {
        let freed = before.saturating_sub(after) * page_size();
        return Ok(Outcome::done(tr!(
            "emptied {0} of standby cache into free memory. Windows refills the cache as files are read again.",
            size_text(freed as f64)
        )));
    }
    Ok(Outcome::done(tr!("emptied the standby cache")))
}

// --------------------------------------------------------------------------- power

fn powercfg(args: &[&str], what: &str) -> Result<String> {
    let command: Vec<String> = std::iter::once(tool("powercfg.exe"))
        .chain(args.iter().map(|a| (*a).to_string()))
        .collect();
    let result = run(command, 60)?;
    if result.code != 0 {
        let line = first_line(&result.text());
        let detail = if line.is_empty() {
            tr!("exit code {0}", result.code)
        } else {
            line
        };
        return fail(format!("{what} failed: {detail}"));
    }
    Ok(result.out)
}

fn find_guid(text: &str) -> Option<String> {
    GUID_RE.as_ref()?.find(text).map(|m| m.as_str().to_lowercase())
}

/// The GUID of the active power plan.
pub fn active_plan() -> Result<Option<String>> {
    Ok(find_guid(&powercfg(
        &["/getactivescheme"],
        &tr!("reading the power plan"),
    )?))
}

fn guid(value: &str) -> Result<String> {
    let full = GUID_RE
        .as_ref()
        .and_then(|re| re.find(value))
        .is_some_and(|m| m.start() == 0 && m.end() == value.len());
    if !full {
        return fail(tr!("that is not a power plan identifier"));
    }
    Ok(value.to_lowercase())
}

fn op_power_plan(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let wanted = guid(&p.req_str("guid")?)?;
    let before = active_plan()?;
    powercfg(&["/setactive", &wanted], &tr!("switching the power plan"))?;
    let previous_name = {
        let name = p.str_or_empty("previous_name");
        if name.is_empty() {
            tr!("the previous plan")
        } else {
            name
        }
    };
    let undo = before.map(|before| json!({ "guid": before, "name": previous_name }));
    let name = {
        let name = p.str_or_empty("name");
        if name.is_empty() { wanted.clone() } else { name }
    };
    Ok(Outcome::new(tr!("the power plan is now \"{0}\"", name), undo))
}

fn undo_power_plan(u: Params<'_>, _store: &Store) -> Result<String> {
    let saved = u.req_str("guid")?;
    powercfg(&["/setactive", &guid(&saved)?], &tr!("restoring the power plan"))?;
    let name = u.str_or_empty("name");
    Ok(tr!(
        "restored the power plan \"{0}\"",
        if name.is_empty() { saved } else { name }
    ))
}

fn op_power_ultimate(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let out = powercfg(
        &["-duplicatescheme", ULTIMATE_TEMPLATE],
        &tr!("adding the Ultimate Performance plan"),
    )?;
    let Some(created) = find_guid(&out.replace(ULTIMATE_TEMPLATE, "")) else {
        return fail(tr!("Windows did not report the new plan"));
    };
    Ok(Outcome::new(
        tr!("added the Ultimate Performance plan; choose it in the list to use it"),
        Some(json!({ "guid": created })),
    ))
}

fn undo_power_ultimate(u: Params<'_>, _store: &Store) -> Result<String> {
    let plan = guid(&u.req_str("guid")?)?;
    if active_plan()?.as_deref() == Some(plan.as_str()) {
        powercfg(&["/setactive", BALANCED_PLAN], &tr!("switching back to Balanced"))?;
    }
    powercfg(&["/delete", &plan], &tr!("removing the plan"))?;
    Ok(tr!("removed the Ultimate Performance plan"))
}

fn op_hibernate(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let on = p.flag("on");
    powercfg(
        &["/hibernate", if on { "on" } else { "off" }],
        &tr!("changing hibernation"),
    )?;
    if on {
        return Ok(Outcome::new(
            tr!("hibernation and Fast Startup are available again"),
            Some(json!({ "on": false })),
        ));
    }
    Ok(Outcome::new(
        tr!("turned hibernation off: Windows deletes hiberfil.sys and Fast Startup stops working"),
        Some(json!({ "on": true })),
    ))
}

fn undo_hibernate(u: Params<'_>, store: &Store) -> Result<String> {
    Ok(op_hibernate(u, store, "")?.message)
}

// --------------------------------------------------------------------------- registry settings

const GPU_KEY: &str = r"HKCU\Software\Microsoft\DirectX\UserGpuPreferences";
const GAME_MODE: (&str, &str) = (r"HKCU\Software\Microsoft\GameBar", "AutoGameModeEnabled");
const HAGS: (&str, &str) = (r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode");

fn gpu_preference_label(value: i64) -> Option<&'static str> {
    match value {
        0 => Some(tl!("Let Windows decide")),
        1 => Some(tl!("Power saving")),
        2 => Some(tl!("High performance")),
        _ => None,
    }
}

fn set_value(key: &str, value: &str, snapshot: &Value) -> Result<Value> {
    let before = reg_read(key, value)?;
    reg_write(key, value, snapshot)?;
    Ok(json!({ "key": key, "value": value, "before": before }))
}

fn undo_value(u: Params<'_>, _store: &Store) -> Result<String> {
    let key = u.req_str("key")?;
    let value = u.req_str("value")?;
    restore_value(&key, &value, u.0.get("before"))?;
    let leaf = key.rsplit('\\').next().unwrap_or(&key);
    Ok(format!(
        "restored {leaf}\\{}",
        if value.is_empty() { "(default)" } else { &value }
    ))
}

fn op_gpu_preference(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let exe = normpath(&p.str_or_empty("exe"));
    let preference = p.int_or("preference", 2)?;
    if !(is_abs(&exe) && exe.to_lowercase().ends_with(".exe") && Path::new(&exe).is_file()) {
        return fail(tr!("choose an existing .exe file"));
    }
    let Some(label) = gpu_preference_label(preference) else {
        return fail(tr!("unknown GPU preference"));
    };
    let gpu_key = crate::testing::setting_key("gpu").unwrap_or_else(|| GPU_KEY.to_string());
    let current = reg_read(&gpu_key, &exe)?;
    // Windows keeps other per-app graphics settings in the same string: change only GpuPreference.
    let data = current
        .as_ref()
        .and_then(|s| s.get("data"))
        .filter(|d| crate::params::truthy(d))
        .map(text_of);
    let mut fields: Vec<(String, String)> = Vec::new();
    for part in data.unwrap_or_default().split(';') {
        if let Some((k, v)) = part.split_once('=') {
            match fields.iter_mut().find(|(name, _)| name == k) {
                Some(field) => field.1 = v.to_string(),
                None => fields.push((k.to_string(), v.to_string())),
            }
        }
    }
    match fields.iter_mut().find(|(name, _)| name == "GpuPreference") {
        Some(field) => field.1 = preference.to_string(),
        None => fields.push(("GpuPreference".to_string(), preference.to_string())),
    }
    let text: String = fields.iter().map(|(k, v)| format!("{k}={v};")).collect();
    let undo = set_value(&gpu_key, &exe, &json!({ "type": "REG_SZ", "data": text }))?;
    Ok(Outcome::new(
        tr!(
            "{0} now uses: {1} (applies the next time it starts)",
            basename(&exe),
            tr!(label)
        ),
        Some(undo),
    ))
}

fn op_game_mode(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let on = p.flag("on");
    let game_key = crate::testing::setting_key("game_mode").unwrap_or_else(|| GAME_MODE.0.to_string());
    let undo = set_value(
        &game_key,
        GAME_MODE.1,
        &json!({ "type": "REG_DWORD", "data": i32::from(on) }),
    )?;
    Ok(Outcome::new(
        if on {
            tr!("Game Mode is on")
        } else {
            tr!("Game Mode is off")
        },
        Some(undo),
    ))
}

fn op_hags(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let on = p.flag("on");
    let undo = set_value(
        HAGS.0,
        HAGS.1,
        &json!({ "type": "REG_DWORD", "data": if on { 2 } else { 1 } }),
    )?;
    Ok(Outcome::new(
        if on {
            tr!("hardware-accelerated GPU scheduling will be on after the next restart")
        } else {
            tr!("hardware-accelerated GPU scheduling will be off after the next restart")
        },
        Some(undo),
    ))
}

// --------------------------------------------------------------------------- services and drives

fn op_service_manual(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let name = p.req_str("name")?;
    let values = service_reg(&name)?;
    guard_service(&name, &values)?;
    let (start, delayed) = service_start(&values)?;
    if start == 0 || start == 1 {
        return fail(tr!("drivers that load during boot are not changed"));
    }
    if start == 3 {
        return Ok(Outcome::done(tr!("\"{0}\" already starts only when needed", name)));
    }
    sc(
        &["config", &name, "start=", "demand"],
        &tr!("changing the start type of \"{0}\"", name),
    )?;
    Ok(Outcome::new(
        tr!(
            "\"{0}\" now starts only when needed (it was set to {1} start)",
            name,
            start_arg(start, delayed)
        ),
        Some(json!({ "name": name, "start": start, "delayed": delayed, "was_running": false })),
    ))
}

fn op_disk_optimize(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let drive = p.str_or_empty("drive");
    let drive = drive.trim().trim_end_matches([':', '\\']);
    if !(drive.len() == 1 && drive.chars().all(|c| c.is_ascii_alphabetic())) {
        return fail(tr!("unknown drive"));
    }
    let ssd = p.str_or_empty("media").to_uppercase() == "SSD";
    let verb = if ssd { "-ReTrim" } else { "-Defrag" };
    ps_ok(
        &format!("Optimize-Volume -DriveLetter $env:PC_DRIVE {verb}"),
        &tr!("optimizing {0}:", drive),
        7200,
        &[("drive", drive)],
    )?;
    Ok(Outcome::done(if ssd {
        tr!("{0}: was trimmed (the SSD now knows which blocks are free)", drive)
    } else {
        tr!("{0}: was defragmented", drive)
    }))
}

fn op_component_cleanup(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let args = vec![
        tool("Dism.exe"),
        "/Online".into(),
        "/Cleanup-Image".into(),
        "/StartComponentCleanup".into(),
    ];
    let result = run(args, 7200)?;
    if result.code != 0 && result.code != 3010 {
        let line = first_line(&result.text());
        let detail = if line.is_empty() {
            tr!("exit code {0}", result.code)
        } else {
            line
        };
        return fail(tr!("DISM failed: {0}", detail));
    }
    Ok(Outcome::done(tr!(
        "removed superseded Windows update files from the component store"
    )))
}

pub(crate) fn builtin() -> Vec<Builtin> {
    vec![
        (
            "process.priority",
            run_fn(op_priority),
            Some(undo_fn(undo_priority)),
            true,
        ),
        (
            "process.efficiency",
            run_fn(op_efficiency),
            Some(undo_fn(undo_efficiency)),
            true,
        ),
        (
            "process.background",
            run_fn(op_background),
            Some(undo_fn(undo_background)),
            true,
        ),
        ("process.trim", run_fn(op_trim), None, true),
        ("memory.trim_all", run_fn(op_trim_all), None, false),
        ("memory.purge_standby", run_fn(op_purge_standby), None, false),
        (
            "power.plan",
            run_fn(op_power_plan),
            Some(undo_fn(undo_power_plan)),
            true,
        ),
        (
            "power.ultimate",
            run_fn(op_power_ultimate),
            Some(undo_fn(undo_power_ultimate)),
            false,
        ),
        (
            "power.hibernate",
            run_fn(op_hibernate),
            Some(undo_fn(undo_hibernate)),
            false,
        ),
        (
            "gpu.preference",
            run_fn(op_gpu_preference),
            Some(undo_fn(undo_value)),
            true,
        ),
        (
            "gaming.game_mode",
            run_fn(op_game_mode),
            Some(undo_fn(undo_value)),
            true,
        ),
        ("gaming.hags", run_fn(op_hags), Some(undo_fn(undo_value)), false),
        (
            "service.manual",
            run_fn(op_service_manual),
            Some(undo_fn(undo_service_disable)),
            false,
        ),
        ("disk.optimize", run_fn(op_disk_optimize), None, false),
        ("disk.component_cleanup", run_fn(op_component_cleanup), None, false),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_read_like_vigil_2() {
        assert_eq!(size_text(0.0), "0 bytes");
        assert_eq!(size_text(1000.0), "1,000 bytes");
        assert_eq!(size_text(1536.0), "1.5 KB");
        assert_eq!(
            size_text(5.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 2000.0),
            "10,000.0 TB"
        );
    }

    #[test]
    fn plan_identifiers_are_validated() {
        assert!(guid(BALANCED_PLAN).is_ok());
        assert!(guid("not-a-guid").is_err());
        assert!(guid(&format!("{BALANCED_PLAN} /x")).is_err());
    }
}
