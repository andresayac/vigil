//! Live processes: finding the target again, refusing critical ones, ending, suspending, priorities,
//! efficiency mode, processor sets and working sets.

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, NTSTATUS, WAIT_OBJECT_0,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::{K32EmptyWorkingSet, K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, GetPriorityClass, GetProcessTimes, IsProcessCritical, OpenProcess, PROCESS_ACCESS_RIGHTS,
    PROCESS_CREATION_FLAGS, PROCESS_NAME_WIN32, PROCESS_POWER_THROTTLING_CURRENT_VERSION,
    PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SET_INFORMATION, PROCESS_SET_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_SUSPEND_RESUME,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, ProcessPowerThrottling, QueryFullProcessImageNameW, SetPriorityClass,
    SetProcessDefaultCpuSets, SetProcessInformation, TerminateProcess, WaitForSingleObject,
};
use windows::core::PWSTR;

use crate::cmdline::{in_dir, is_abs, normcase};
use crate::error::{ActionError, Result, fail};
use crate::runner::windir;
use vigil_i18n::tr;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtSuspendProcess(process: HANDLE) -> NTSTATUS;
    fn NtResumeProcess(process: HANDLE) -> NTSTATUS;
    fn NtQueryInformationProcess(
        process: HANDLE,
        class: u32,
        info: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> NTSTATUS;
    fn NtSetInformationProcess(process: HANDLE, class: u32, info: *const c_void, length: u32) -> NTSTATUS;
}

/// ProcessIoPriority: 0 very low, 1 low, 2 normal (3 high needs a privilege).
const PROCESS_IO_PRIORITY: u32 = 33;
/// ProcessPagePriority (memory priority): 1 very low ... 5 normal.
const PROCESS_PAGE_PRIORITY: u32 = 39;

pub const CRITICAL_PROCESSES: [&str; 25] = [
    "system",
    "registry",
    "secure system",
    "memory compression",
    "memcompression",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "msmpeng.exe",
    "nissrv.exe",
    "mpdefendercoreservice.exe",
    "securityhealthservice.exe",
    "sgrmbroker.exe",
    "wudfhost.exe",
    "conhost.exe",
    "sihost.exe",
    "ctfmon.exe",
    "audiodg.exe",
];

const STILL_ACTIVE: u32 = 259;

/// An open process handle, closed when dropped.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcess/CreateToolhelp32Snapshot and is closed only here.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

enum OpenError {
    Gone,
    Denied,
    Other(String),
}

fn open(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> std::result::Result<Handle, OpenError> {
    // SAFETY: plain call; the returned handle is owned by `Handle`.
    match unsafe { OpenProcess(access, false, pid) } {
        Ok(handle) => Ok(Handle(handle)),
        Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => Err(OpenError::Gone),
        Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => Err(OpenError::Denied),
        Err(e) => Err(OpenError::Other(e.message())),
    }
}

/// One row of the process list.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
}

/// Every running process (pid, parent, image name).
pub fn list() -> Vec<ProcInfo> {
    let mut out = Vec::new();
    // SAFETY: plain call; the snapshot handle is owned by `Handle`.
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return out;
    };
    let snapshot = Handle(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: `entry` is a valid PROCESSENTRY32W with dwSize set.
    let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) }.is_ok();
    while more {
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        out.push(ProcInfo {
            pid: entry.th32ProcessID,
            ppid: entry.th32ParentProcessID,
            name: String::from_utf16_lossy(&entry.szExeFile[..len]),
        });
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot.0, &mut entry) }.is_ok();
    }
    out
}

/// The full path of a process image (`None` when Windows does not tell).
pub fn exe_path(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return None;
    }
    let handle = open(pid, PROCESS_QUERY_LIMITED_INFORMATION).ok()?;
    let mut buffer = vec![0u16; 32_768];
    let mut size = buffer.len() as u32;
    // SAFETY: `buffer` holds `size` UTF-16 units.
    unsafe { QueryFullProcessImageNameW(handle.0, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut size) }.ok()?;
    let path = String::from_utf16_lossy(&buffer[..size as usize]);
    if path.is_empty() { None } else { Some(path) }
}

fn filetime_seconds(time: FILETIME) -> f64 {
    let ticks = (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
    (ticks as f64 - 116_444_736_000_000_000.0) / 10_000_000.0
}

/// When the process started, in seconds since 1970 (as undo records store it).
pub fn create_time(pid: u32) -> Option<f64> {
    let handle = open(pid, PROCESS_QUERY_LIMITED_INFORMATION).ok()?;
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: four valid FILETIME out pointers.
    unsafe { GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) }.ok()?;
    Some(filetime_seconds(created))
}

/// A process that exists right now.
#[derive(Debug, Clone)]
pub struct Proc {
    pub pid: u32,
    pub name: String,
}

impl Proc {
    /// `psutil.Process(pid)`: fails when no process has that PID.
    pub fn get(pid: i64) -> Result<Proc> {
        let pid = u32::try_from(pid).map_err(|_| ActionError::new(tr!("the process is no longer running")))?;
        let row = list().into_iter().find(|p| p.pid == pid);
        match row {
            Some(row) => Ok(Proc {
                pid,
                name: display_name(&row),
            }),
            None => fail(tr!("the process is no longer running")),
        }
    }

    pub fn describe(&self) -> String {
        if self.name.is_empty() {
            format!("PID {}", self.pid)
        } else {
            format!("{} (PID {})", self.name, self.pid)
        }
    }

    pub fn exe(&self) -> Option<String> {
        exe_path(self.pid)
    }

    pub fn create_time(&self) -> Option<f64> {
        create_time(self.pid)
    }
}

fn display_name(row: &ProcInfo) -> String {
    if !row.name.is_empty() {
        return row.name.clone();
    }
    exe_path(row.pid)
        .map(|exe| crate::cmdline::basename(&exe).to_string())
        .unwrap_or_default()
}

/// Windows' IsProcessCritical: ending such a process blue-screens the computer.
fn is_critical_flag(pid: u32) -> bool {
    let Ok(handle) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
        return false;
    };
    let mut critical = windows::core::BOOL(0);
    // SAFETY: valid handle and out pointer.
    unsafe { IsProcessCritical(handle.0, &mut critical) }.is_ok() && critical.as_bool()
}

/// This process and the programs that started it.
pub fn own_lineage() -> HashSet<u32> {
    let own = std::process::id();
    let mut pids = HashSet::from([own]);
    let parents: HashMap<u32, u32> = list().into_iter().map(|p| (p.pid, p.ppid)).collect();
    let mut current = own;
    while let Some(&parent) = parents.get(&current) {
        if parent == 0 || pids.contains(&parent) {
            break;
        }
        // A parent that started after its child is an unrelated process that reused the PID.
        if let (Some(child_time), Some(parent_time)) = (create_time(current), create_time(parent))
            && parent_time > child_time
        {
            break;
        }
        pids.insert(parent);
        current = parent;
    }
    pids
}

/// Why a process must not be ended or suspended (`None` = it may).
pub fn process_protection(proc: &Proc) -> Option<String> {
    let pid = proc.pid;
    if pid == 0 || pid == 4 {
        return Some(tr!("it is part of the Windows kernel"));
    }
    if own_lineage().contains(&pid) {
        return Some(tr!("it is Vigil itself or the program that started it"));
    }
    let name = proc.name.to_lowercase();
    let exe = proc.exe().unwrap_or_default();
    let windir = windir().to_string_lossy().into_owned();
    if CRITICAL_PROCESSES.contains(&name.as_str()) && (exe.is_empty() || in_dir(&exe, &windir)) {
        return Some(tr!("{0} is a critical Windows process", proc.name));
    }
    let program_data = vigil_sys::paths::program_data().to_string_lossy().into_owned();
    if !exe.is_empty() && in_dir(&exe, &format!("{program_data}\\Microsoft\\Windows Defender")) {
        return Some(tr!("it is part of Microsoft Defender"));
    }
    if is_critical_flag(pid) {
        return Some(tr!("Windows marks it as critical: ending it would crash the computer"));
    }
    None
}

fn parse_time(value: Option<&str>) -> Option<f64> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(time) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some(time.timestamp_millis() as f64 / 1000.0);
    }
    let naive = [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M",
    ]
    .iter()
    .find_map(|format| chrono::NaiveDateTime::parse_from_str(value, format).ok())
    .or_else(|| {
        chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .ok()
            .and_then(|d| d.and_hms_opt(0, 0, 0))
    })?;
    let local = naive.and_local_timezone(chrono::Local).earliest()?;
    Some(local.timestamp_millis() as f64 / 1000.0)
}

/// Live processes that are the target: same image path, or the scanned PIDs if they still belong to
/// the same process instance (same name and started before the scan).
pub fn find_processes(path: Option<&str>, pids: &[i64], names: &[String], scan_started: Option<&str>) -> Vec<Proc> {
    let rows = list();
    let mut found: Vec<Proc> = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();
    if let Some(want) = path.filter(|p| is_abs(p)).map(normcase) {
        for row in &rows {
            if let Some(exe) = exe_path(row.pid)
                && normcase(&exe) == want
                && seen.insert(row.pid)
            {
                found.push(Proc {
                    pid: row.pid,
                    name: display_name(row),
                });
            }
        }
    }
    let limit = parse_time(scan_started);
    let wanted: HashSet<String> = names
        .iter()
        .filter(|n| !n.is_empty())
        .map(|n| n.to_lowercase())
        .collect();
    for &pid in pids {
        let Ok(pid) = u32::try_from(pid) else {
            continue;
        };
        if seen.contains(&pid) {
            continue;
        }
        let Some(row) = rows.iter().find(|r| r.pid == pid) else {
            continue;
        };
        let name = display_name(row);
        let same_name = wanted.is_empty() || wanted.contains(&name.to_lowercase());
        let same_instance = match limit {
            None => true,
            Some(limit) => create_time(pid).is_some_and(|t| t <= limit + 1.0),
        };
        if same_name && same_instance && seen.insert(pid) {
            found.push(Proc { pid, name });
        }
    }
    found
}

fn descendants(root: u32, rows: &[ProcInfo]) -> Vec<Proc> {
    let mut out = Vec::new();
    let mut pending = vec![root];
    let mut seen = HashSet::from([root]);
    while let Some(parent) = pending.pop() {
        let parent_time = create_time(parent);
        for row in rows.iter().filter(|r| r.ppid == parent && r.pid != parent) {
            // A "child" older than its parent got the parent's old PID by chance.
            let older = matches!((parent_time, create_time(row.pid)), (Some(p), Some(c)) if c < p);
            if older || !seen.insert(row.pid) {
                continue;
            }
            out.push(Proc {
                pid: row.pid,
                name: display_name(row),
            });
            pending.push(row.pid);
        }
    }
    out
}

/// Ends the processes (and with `tree` their descendants). Returns (ended, not ended) descriptions.
pub fn terminate(procs: &[Proc], tree: bool) -> (Vec<String>, Vec<String>) {
    let rows = if tree { list() } else { Vec::new() };
    let mut targets: Vec<Proc> = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();
    for proc in procs {
        if tree {
            for child in descendants(proc.pid, &rows) {
                if seen.insert(child.pid) {
                    targets.push(child);
                }
            }
        }
        if seen.insert(proc.pid) {
            targets.push(proc.clone());
        }
    }
    let (mut done, mut failed) = (Vec::new(), Vec::new());
    let mut waiting: Vec<(u32, Handle)> = Vec::new();
    for proc in &targets {
        let label = proc.describe();
        if let Some(reason) = process_protection(proc) {
            failed.push(tr!("{0}: not ended, {1}", label, reason));
            continue;
        }
        match open(
            proc.pid,
            PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
        ) {
            Err(OpenError::Gone) => done.push(tr!("{0} (had already exited)", label)),
            Err(OpenError::Denied) => failed.push(tr!("{0}: access denied (it may be a protected process)", label)),
            Err(OpenError::Other(message)) => failed.push(format!("{label}: {message}")),
            Ok(handle) => {
                // SAFETY: the handle was opened with PROCESS_TERMINATE.
                match unsafe { TerminateProcess(handle.0, 1) } {
                    Ok(()) => {
                        done.push(label);
                        waiting.push((proc.pid, handle));
                    }
                    Err(_) if has_exited(&handle) => done.push(tr!("{0} (had already exited)", label)),
                    Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => {
                        failed.push(tr!("{0}: access denied (it may be a protected process)", label));
                    }
                    Err(e) => failed.push(format!("{label}: {}", e.message())),
                }
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    for (pid, handle) in waiting {
        let left = deadline.saturating_duration_since(Instant::now()).as_millis() as u32;
        // SAFETY: the handle was opened with SYNCHRONIZE.
        if unsafe { WaitForSingleObject(handle.0, left) } != WAIT_OBJECT_0 {
            failed.push(tr!("PID {0} is still running", pid));
        }
    }
    (done, failed)
}

fn has_exited(handle: &Handle) -> bool {
    let mut code = 0u32;
    // SAFETY: valid handle and out pointer.
    unsafe { GetExitCodeProcess(handle.0, &mut code) }.is_ok() && code != STILL_ACTIVE
}

fn open_for(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<Handle> {
    match open(pid, access) {
        Ok(handle) => Ok(handle),
        Err(OpenError::Gone) => fail(tr!("the process is no longer running")),
        Err(OpenError::Denied) => fail(tr!("access denied")),
        Err(OpenError::Other(message)) => fail(message),
    }
}

/// Suspends (or resumes) every thread of a process.
pub fn suspend(pid: u32, resume: bool) -> Result<()> {
    let handle = open_for(pid, PROCESS_SUSPEND_RESUME)?;
    // SAFETY: the handle was opened with PROCESS_SUSPEND_RESUME.
    let status = unsafe {
        if resume {
            NtResumeProcess(handle.0)
        } else {
            NtSuspendProcess(handle.0)
        }
    };
    if status.is_ok() {
        return Ok(());
    }
    if status.0 as u32 == 0xC000_0022 {
        return fail(tr!("access denied"));
    }
    fail(tr!(
        "Windows refused the change (0x{0})",
        format!("{:08X}", status.0 as u32)
    ))
}

/// Priority classes by the names undo records store.
pub const PRIORITIES: [(&str, u32); 5] = [
    ("idle", 0x40),
    ("below_normal", 0x4000),
    ("normal", 0x20),
    ("above_normal", 0x8000),
    ("high", 0x80),
];

pub fn priority_value(name: &str) -> Option<u32> {
    PRIORITIES.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

fn priority_name(value: u32) -> &'static str {
    PRIORITIES
        .iter()
        .find(|(_, v)| *v == value)
        .map(|(n, _)| *n)
        .unwrap_or("normal")
}

/// Sets a priority class and returns the previous one.
pub fn set_priority(pid: u32, name: &str) -> Result<&'static str> {
    let Some(value) = priority_value(name) else {
        return fail(tr!("unknown priority {0}", name));
    };
    let handle = match open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION) {
        Ok(handle) => handle,
        Err(OpenError::Gone) => return fail(tr!("the process is no longer running")),
        Err(_) => return fail(tr!("Windows does not let Vigil change that process")),
    };
    // SAFETY: the handle has PROCESS_QUERY_LIMITED_INFORMATION.
    let before = priority_name(unsafe { GetPriorityClass(handle.0) });
    // SAFETY: the handle has PROCESS_SET_INFORMATION.
    unsafe { SetPriorityClass(handle.0, PROCESS_CREATION_FLAGS(value)) }
        .map_err(|_| ActionError::new(tr!("Windows does not let Vigil change that process")))?;
    Ok(before)
}

/// EcoQoS for a process: `Some(true)` = efficiency mode, `None` = let Windows decide again.
pub fn set_throttling(pid: u32, on: Option<bool>) -> Result<()> {
    let handle = open(pid, PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION).map_err(|e| {
        let code = match e {
            OpenError::Gone => 87,
            OpenError::Denied => 5,
            OpenError::Other(_) => 0,
        };
        ActionError::new(tr!("cannot open the process (error {0})", code))
    })?;
    let state = PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: if on.is_none() {
            0
        } else {
            PROCESS_POWER_THROTTLING_EXECUTION_SPEED
        },
        StateMask: if on == Some(true) {
            PROCESS_POWER_THROTTLING_EXECUTION_SPEED
        } else {
            0
        },
    };
    // SAFETY: `state` is a valid PROCESS_POWER_THROTTLING_STATE of the size passed.
    unsafe {
        SetProcessInformation(
            handle.0,
            ProcessPowerThrottling,
            (&raw const state).cast::<c_void>(),
            size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        )
    }
    .map_err(|e| ActionError::new(tr!("Windows refused the change (error {0})", e.code().0 & 0xFFFF)))
}

fn open_for_info(pid: u32) -> Result<Handle> {
    open(pid, PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION).map_err(|e| {
        let code = match e {
            OpenError::Gone => 87,
            OpenError::Denied => 5,
            OpenError::Other(_) => 0,
        };
        ActionError::new(tr!("cannot open the process (error {0})", code))
    })
}

fn query_u32(handle: HANDLE, class: u32) -> Result<u32> {
    let mut value = 0u32;
    let mut returned = 0u32;
    // SAFETY: `value` is a writable u32 of the size passed; the handle allows limited queries.
    let status = unsafe { NtQueryInformationProcess(handle, class, (&raw mut value).cast(), 4, &mut returned) };
    if status.0 < 0 {
        return fail(tr!(
            "Windows did not report it (status 0x{0})",
            format!("{:08X}", status.0)
        ));
    }
    Ok(value)
}

fn set_u32(handle: HANDLE, class: u32, value: u32) -> Result<()> {
    // SAFETY: `value` is a u32 of the size passed; the handle has PROCESS_SET_INFORMATION.
    let status = unsafe { NtSetInformationProcess(handle, class, (&raw const value).cast(), 4) };
    if status.0 < 0 {
        return fail(tr!(
            "Windows refused the change (status 0x{0})",
            format!("{:08X}", status.0)
        ));
    }
    Ok(())
}

/// The I/O priority (0..2) and memory priority (1..5) of a process.
pub fn io_memory_priority(pid: u32) -> Result<(u32, u32)> {
    let handle = open_for_info(pid)?;
    Ok((
        query_u32(handle.0, PROCESS_IO_PRIORITY)?,
        query_u32(handle.0, PROCESS_PAGE_PRIORITY)?,
    ))
}

/// Sets the I/O priority (clamped to 0..2, never high) and the memory priority (clamped to 1..5).
pub fn set_io_memory_priority(pid: u32, io: u32, memory: u32) -> Result<()> {
    let handle = open_for_info(pid)?;
    set_u32(handle.0, PROCESS_IO_PRIORITY, io.min(2))?;
    set_u32(handle.0, PROCESS_PAGE_PRIORITY, memory.clamp(1, 5))
}

/// Limits a process to these CPU Set ids by default (its threads without their own sets follow it);
/// an empty list lets it use every processor again.
pub fn set_cpu_sets(pid: u32, ids: &[u32]) -> Result<()> {
    let handle =
        open(pid, PROCESS_SET_LIMITED_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION).map_err(|e| match e {
            OpenError::Gone => ActionError::new(tr!("the process is no longer running")),
            OpenError::Denied => ActionError::new(tr!("access denied")),
            OpenError::Other(message) => ActionError::new(message),
        })?;
    let ids = (!ids.is_empty()).then_some(ids);
    // SAFETY: the handle has PROCESS_SET_LIMITED_INFORMATION; `ids` is read for its length.
    unsafe { SetProcessDefaultCpuSets(handle.0, ids) }
        .ok()
        .map_err(|e| ActionError::new(tr!("Windows refused the change (error {0})", e.code().0 & 0xFFFF)))
}

/// Empties a working set; false when Windows refused.
pub fn empty_working_set(pid: u32) -> bool {
    let Ok(handle) = open(pid, PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION) else {
        return false;
    };
    // SAFETY: the handle has PROCESS_SET_QUOTA.
    unsafe { K32EmptyWorkingSet(handle.0) }.as_bool()
}

/// Resident memory (working set) of a process, 0 when unknown.
pub fn rss(pid: u32) -> u64 {
    let Ok(handle) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
        return 0;
    };
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    // SAFETY: `counters` is valid and its size is passed.
    if unsafe { K32GetProcessMemoryInfo(handle.0, &mut counters, counters.cb) }.as_bool() {
        counters.WorkingSetSize as u64
    } else {
        0
    }
}

/// Physical memory available now.
pub fn available_memory() -> u64 {
    let mut status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: `status` is valid with dwLength set.
    if unsafe { GlobalMemoryStatusEx(&mut status) }.is_ok() {
        status.ullAvailPhys
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_process_and_kernel_are_protected() {
        let own = Proc::get(i64::from(std::process::id())).map_err(|e| e.to_string());
        assert!(own.as_ref().is_ok_and(|p| process_protection(p).is_some()), "{own:?}");
        assert!(
            process_protection(&Proc {
                pid: 4,
                name: "System".into()
            })
            .is_some()
        );
    }

    #[test]
    fn create_time_matches_the_clock() {
        let now = chrono::Utc::now().timestamp() as f64;
        let started = create_time(std::process::id()).unwrap_or(0.0);
        assert!(started > now - 3600.0 && started <= now + 1.0, "{started} vs {now}");
    }

    #[test]
    fn scan_times_are_local() {
        assert!(parse_time(Some("2000-01-01T00:00:00")).is_some_and(|t| t > 9.0e8 && t < 9.5e8));
        assert_eq!(parse_time(Some("")), None);
    }
}
