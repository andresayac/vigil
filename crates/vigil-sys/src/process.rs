//! Running processes, sampled the way Task Manager does it.
//!
//! One kernel call returns the figures of every process (CPU times, memory, threads, I/O).
//! What never changes for a given process (image path, user, command line) is read once per
//! process instance, identified by PID + creation time, and dropped when the process exits.

use std::collections::HashMap;
use std::time::Instant;

use serde::Serialize;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, PSID, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::core::{PCWSTR, PWSTR};

use crate::SysError;
use crate::nt::{self, RawProcess, SystemProcesses};
use crate::util::{filetime_to_unix_ms, from_wide, logical_processors, wide};

const PROCESS_COMMAND_LINE_INFORMATION: i32 = 60;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;
const SYSTEM_SID: &str = "S-1-5-18";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProcessStatus {
    Running,
    Suspended,
}

/// One running process.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessRow {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    /// Full path of the image ("" when Windows does not map it to a drive letter).
    pub exe: String,
    /// "DOMAIN\user" ("" when the process cannot be opened).
    pub user: String,
    pub cmdline: String,
    /// Share of the whole machine (every logical processor), 0-100. 0 on the first snapshot.
    pub cpu: f32,
    /// Private working set: the "Memory" column of Task Manager.
    pub private_bytes: u64,
    pub working_set: u64,
    pub threads: u32,
    pub handles: u32,
    pub session: u32,
    /// Creation time, milliseconds since the Unix epoch. With `pid` it identifies the process.
    pub created_ms: i64,
    /// Bytes read and written per second (disk, network and devices).
    pub io_bps: f64,
    pub status: ProcessStatus,
    /// Owns a window on the desktop: Task Manager lists it under "Apps".
    pub window: bool,
    /// The file description of the image ("Google Chrome"); "" when it has none.
    pub description: String,
}

/// A process handle that is closed when dropped.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by OpenProcess/OpenProcessToken and is closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Maps NT device paths ("\Device\HarddiskVolume3\...") to drive letters ("C:\...").
pub(crate) struct PathResolver {
    devices: Vec<(String, String)>,
}

impl PathResolver {
    pub(crate) fn new() -> Self {
        let mut drives = vec![0u16; 512];
        // SAFETY: the buffer is writable for its whole length.
        let length = unsafe { GetLogicalDriveStringsW(Some(&mut drives)) } as usize;
        let mut devices = Vec::new();
        for drive in drives[..length.min(drives.len())].split(|&u| u == 0) {
            let drive = String::from_utf16_lossy(drive);
            let letter = drive.trim_end_matches('\\');
            if letter.is_empty() {
                continue;
            }
            let name = wide(letter);
            let mut target = vec![0u16; 1024];
            // SAFETY: `name` is NUL-terminated; `target` is writable for its whole length.
            let written = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut target)) };
            if written > 0 {
                devices.push((format!("{}\\", from_wide(&target)), format!("{letter}\\")));
            }
        }
        Self { devices }
    }

    pub(crate) fn dos_path(&self, pid: u32) -> String {
        let Some(nt_path) = nt::nt_image_path(pid) else {
            return String::new();
        };
        for (device, letter) in &self.devices {
            let prefix = nt_path.as_bytes().get(..device.len());
            if prefix.is_some_and(|p| p.eq_ignore_ascii_case(device.as_bytes()))
                && let Some(rest) = nt_path.get(device.len()..)
            {
                return format!("{letter}{rest}");
            }
        }
        // Processes without a file (Registry, Memory Compression) or volumes without a letter.
        if nt_path.starts_with('\\') {
            String::new()
        } else {
            nt_path
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Details {
    exe: String,
    user: String,
    cmdline: String,
    description: String,
}

/// Reads path, user and command line of a process.
struct DetailsReader {
    paths: PathResolver,
    accounts: HashMap<String, String>,
    system_account: String,
}

impl DetailsReader {
    fn new() -> Self {
        let mut reader = Self {
            paths: PathResolver::new(),
            accounts: HashMap::new(),
            system_account: String::new(),
        };
        reader.system_account = reader
            .well_known_account(SYSTEM_SID)
            .unwrap_or_else(|| "NT AUTHORITY\\SYSTEM".into());
        reader
    }

    fn read(&mut self, pid: u32, created_raw: i64) -> Details {
        let exe = self.paths.dos_path(pid);
        // Cached per executable path: read once per program, not per process.
        let description = crate::apps::file_description(&exe).unwrap_or_default();
        if pid <= 4 {
            return Details {
                exe,
                user: self.system_account.clone(),
                cmdline: String::new(),
                description,
            };
        }
        // SAFETY: plain call; the returned handle is owned by OwnedHandle below.
        let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
            return Details {
                exe,
                description,
                ..Details::default()
            };
        };
        let handle = OwnedHandle(handle);
        let created = creation_time(handle.0);
        if created != 0 && created_raw != 0 && created != created_raw {
            return Details {
                exe,
                description,
                ..Details::default()
            }; // the PID now belongs to another process
        }
        let user = self.token_user(handle.0).unwrap_or_default();
        Details {
            exe,
            user,
            cmdline: command_line(handle.0),
            description,
        }
    }

    fn token_user(&mut self, process: HANDLE) -> Option<String> {
        let mut token = HANDLE::default();
        // SAFETY: `process` is a valid handle; `token` receives a new handle owned below.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.ok()?;
        let token = OwnedHandle(token);
        let mut buffer = vec![0u64; 32];
        for _ in 0..2 {
            let mut needed = 0u32;
            let length = (buffer.len() * 8) as u32;
            // SAFETY: the buffer is writable for `length` bytes and 8-byte aligned.
            let result = unsafe {
                GetTokenInformation(
                    token.0,
                    TokenUser,
                    Some(buffer.as_mut_ptr().cast()),
                    length,
                    &mut needed,
                )
            };
            if result.is_ok() {
                // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points inside it.
                let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
                return Some(self.account(sid));
            }
            if needed as usize <= buffer.len() * 8 {
                return None;
            }
            buffer = vec![0u64; (needed as usize).div_ceil(8)];
        }
        None
    }

    /// "DOMAIN\name" for a SID, cached by its string form; the SID string when it has no name.
    fn account(&mut self, sid: PSID) -> String {
        let mut text = PWSTR::null();
        // SAFETY: `sid` is valid for the call; `text` receives a LocalAlloc'd string freed below.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) }.is_err() {
            return String::new();
        }
        // SAFETY: on success `text` is a valid NUL-terminated string.
        let key = unsafe { text.to_string() }.unwrap_or_default();
        // SAFETY: `text` was allocated by ConvertSidToStringSidW and is freed once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        }
        if let Some(name) = self.accounts.get(&key) {
            return name.clone();
        }
        let name = lookup_account(sid).unwrap_or_else(|| key.clone());
        self.accounts.insert(key, name.clone());
        name
    }

    fn well_known_account(&mut self, sid_text: &str) -> Option<String> {
        let text = wide(sid_text);
        let mut sid = PSID::default();
        // SAFETY: `text` is NUL-terminated; `sid` receives a LocalAlloc'd SID freed below.
        unsafe { ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &mut sid) }.ok()?;
        let name = lookup_account(sid);
        // SAFETY: the SID was allocated by ConvertStringSidToSidW and is freed once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sid.0)));
        }
        name
    }
}

fn lookup_account(sid: PSID) -> Option<String> {
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut use_ = SID_NAME_USE::default();
    // SAFETY: both buffers are writable for the lengths passed; `sid` is valid for the call.
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut use_,
        )
    }
    .ok()?;
    let name = from_wide(&name);
    let domain = from_wide(&domain);
    Some(if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    })
}

/// FILETIME of the creation of an open process (0 when unknown).
fn creation_time(process: HANDLE) -> i64 {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: four writable FILETIMEs; `process` is a valid handle.
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) }.is_err() {
        return 0;
    }
    ((created.dwHighDateTime as i64) << 32) | created.dwLowDateTime as i64
}

/// The command line of an open process; text after an embedded NUL is shown, not cut off.
fn command_line(process: HANDLE) -> String {
    let mut size = 2048usize;
    for _ in 0..4 {
        let mut buffer = vec![0u64; size.div_ceil(8)];
        let length = (buffer.len() * 8) as u32;
        let mut needed = 0u32;
        // SAFETY: the buffer is writable for `length` bytes; `process` is a valid handle.
        let status = unsafe {
            NtQueryInformationProcess(
                process,
                PROCESSINFOCLASS(PROCESS_COMMAND_LINE_INFORMATION),
                buffer.as_mut_ptr().cast(),
                length,
                &mut needed,
            )
        };
        match status.0 {
            STATUS_INFO_LENGTH_MISMATCH | STATUS_BUFFER_TOO_SMALL | STATUS_BUFFER_OVERFLOW => {
                size = (needed as usize).max(size * 2);
            }
            code if code < 0 => return String::new(),
            _ => {
                let text = nt::unicode_string_at(nt::as_bytes(&buffer), 0).unwrap_or_default();
                return text.replace('\0', " ").trim().to_string();
            }
        }
    }
    String::new()
}

/// Successive snapshots of every process; CPU and I/O rates are measured between two calls.
pub struct ProcessSampler {
    system: SystemProcesses,
    reader: DetailsReader,
    details: HashMap<(u32, i64), Details>,
    times: HashMap<(u32, i64), i64>,
    io: HashMap<(u32, i64), u64>,
    last: Option<Instant>,
    cpus: f64,
}

impl ProcessSampler {
    pub fn new() -> Result<Self, SysError> {
        Ok(Self {
            system: SystemProcesses::new(),
            reader: DetailsReader::new(),
            details: HashMap::new(),
            times: HashMap::new(),
            io: HashMap::new(),
            last: None,
            cpus: f64::from(logical_processors()),
        })
    }

    pub fn snapshot(&mut self) -> Result<Vec<ProcessRow>, SysError> {
        let samples = self.system.sample()?;
        let now = Instant::now();
        let seconds = self.last.map(|t| now.duration_since(t).as_secs_f64()).unwrap_or(0.0);
        let capacity = seconds * 1e7 * self.cpus; // 100 ns units of CPU time available
        let mut details = HashMap::with_capacity(samples.len());
        let mut times = HashMap::with_capacity(samples.len());
        let mut io = HashMap::with_capacity(samples.len());
        let mut rows = Vec::with_capacity(samples.len());
        // Which processes own a desktop window: one EnumWindows pass per sample (well under 1 ms).
        let windows = crate::apps::window_pids();
        for sample in samples {
            let key = (sample.pid, sample.created_raw);
            let info = match self.details.remove(&key) {
                Some(info) => info,
                None => self.reader.read(sample.pid, sample.created_raw),
            };
            let cpu = match self.times.get(&key) {
                Some(&before) if capacity > 0.0 => {
                    ((sample.cpu_time - before) as f64 * 100.0 / capacity).clamp(0.0, 100.0)
                }
                _ => 0.0,
            };
            let transferred = sample.io_read.saturating_add(sample.io_write);
            let io_bps = match self.io.get(&key) {
                Some(&before) if seconds > 0.0 => transferred.saturating_sub(before) as f64 / seconds,
                _ => 0.0,
            };
            times.insert(key, sample.cpu_time);
            io.insert(key, transferred);
            rows.push(row(&sample, &info, cpu, io_bps, windows.contains(&sample.pid)));
            details.insert(key, info);
        }
        self.details = details;
        self.times = times;
        self.io = io;
        self.last = Some(now);
        Ok(rows)
    }
}

fn row(sample: &RawProcess, info: &Details, cpu: f64, io_bps: f64, window: bool) -> ProcessRow {
    ProcessRow {
        pid: sample.pid,
        ppid: sample.ppid,
        name: sample.name.clone(),
        exe: info.exe.clone(),
        user: info.user.clone(),
        cmdline: info.cmdline.clone(),
        cpu: ((cpu * 10.0).round() / 10.0) as f32,
        private_bytes: sample.private_ws,
        working_set: sample.working_set,
        threads: sample.threads,
        handles: sample.handles,
        session: sample.session,
        created_ms: filetime_to_unix_ms(sample.created_raw),
        io_bps,
        status: if sample.suspended {
            ProcessStatus::Suspended
        } else {
            ProcessStatus::Running
        },
        window,
        description: info.description.clone(),
    }
}
