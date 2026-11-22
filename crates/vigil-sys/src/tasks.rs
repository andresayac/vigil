//! Scheduled tasks, read live through the Task Scheduler COM API — what the Task Scheduler library
//! shows: every folder, hidden tasks included, with their triggers, actions, account and run level,
//! and when they last ran and run next. Read-only: nothing is registered, changed or started here.
//!
//! The COM interfaces give the state and the run times; everything else comes from each task's
//! XML definition, read with the small parser at the end of this file.

use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use serde::Serialize;
use windows::Win32::Foundation::{HLOCAL, LocalFree, SYSTEMTIME};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::Win32::Security::{LookupAccountNameW, PSID, SID_NAME_USE};
use windows::Win32::Storage::FileSystem::SearchPathW;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::{
    IRegisteredTask, ITaskFolder, ITaskService, TASK_ENUM_HIDDEN, TASK_STATE_DISABLED, TASK_STATE_QUEUED,
    TASK_STATE_READY, TASK_STATE_RUNNING, TaskScheduler,
};
use windows::Win32::System::Variant::{VARIANT, VT_I4, VariantTimeToSystemTime};
use windows::Win32::UI::Shell::SHLoadIndirectString;
use windows::core::{BSTR, PCWSTR, PWSTR};

use crate::SysError;
use crate::process::lookup_account;
use crate::startup::expand;
use crate::util::{from_wide, hkcu_string, hklm_string, wide};
use crate::xml::{Node, parse_xml};

/// How long a listing may take before the page is told Task Scheduler did not answer.
const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_TASKS: usize = 5000;
const MAX_FOLDER_DEPTH: usize = 32;

/// One scheduled task.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScheduledTask {
    /// Full path in the Task Scheduler library: `\Vendor\Updater`.
    pub path: String,
    pub name: String,
    /// The folder: `\Vendor` (`\` for the root).
    pub folder: String,
    /// "ready", "running", "disabled", "queued" or "unknown".
    pub state: String,
    pub enabled: bool,
    /// Marked hidden (Task Scheduler shows it only with "Show hidden tasks").
    pub hidden: bool,
    pub author: String,
    pub description: String,
    /// When it was registered, as written in the task (local ISO time; may be empty).
    pub created: String,
    pub triggers: Vec<TaskTrigger>,
    pub actions: Vec<TaskAction>,
    /// The account it runs as ("NT AUTHORITY\SYSTEM", "DESKTOP-ABC123\jdoe", "BUILTIN\Users");
    /// empty when the task names none.
    pub account: String,
    /// "system" (LocalSystem), "service" (Local or Network Service), "group", "user" or "" (none named).
    pub account_kind: String,
    /// "highest" (with administrator rights when the account has them) or "least".
    pub run_level: String,
    /// "interactive" (only while the user is signed in), "password", "s4u" (signed in or not),
    /// "service", "group" or "".
    pub logon_type: String,
    /// Runs with full rights: the highest run level or as LocalSystem.
    pub elevated: bool,
    /// Last run (local ISO time); empty when it never ran.
    pub last_run: String,
    /// The result of the last run: an exit code or an HRESULT (`None` when unknown).
    pub last_result: Option<i32>,
    /// Next scheduled run (local ISO time); empty when none is scheduled.
    pub next_run: String,
    /// The task's definition file under `%SystemRoot%\System32\Tasks`.
    pub file: String,
    /// The program the first action starts (or the DLL of its COM handler); empty when unknown.
    pub program: String,
    /// `program` exists on disk.
    pub program_exists: bool,
    /// The task belongs to Windows (`\Microsoft\...`): the action engine refuses to change it.
    pub microsoft: bool,
    /// A program it runs (or a script a host such as PowerShell runs) is in a folder a standard
    /// user can change. Filled in by the caller, which owns that policy; false here.
    pub user_writable: bool,
}

/// When a task starts.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TaskTrigger {
    /// "logon", "boot", "idle", "time", "daily", "weekly", "monthly", "monthly_dow", "event",
    /// "registration", "session" or "custom".
    pub kind: String,
    pub enabled: bool,
    /// Start boundary as written in the task (`2024-01-01T03:00:00`, maybe with an offset or `Z`).
    pub start: String,
    pub end: String,
    /// Daily: every N days. Weekly: every N weeks. 0 otherwise.
    pub every: u32,
    /// Weekly and monthly_dow: "monday".."sunday". Monthly: day numbers and "last".
    pub days: Vec<String>,
    /// Monthly_dow: "1".."4" and "last".
    pub weeks: Vec<String>,
    /// Monthly and monthly_dow: "january".."december"; empty means every month.
    pub months: Vec<String>,
    /// Repeats every N seconds after it fires (0 = no repetition).
    pub repeat_secs: u64,
    /// For how long it repeats (0 = indefinitely).
    pub repeat_for_secs: u64,
    pub delay_secs: u64,
    pub random_delay_secs: u64,
    /// Logon: the user ("" = any user). Event: the event logs it watches. Session: the change
    /// ("console_connect", "console_disconnect", "remote_connect", "remote_disconnect",
    /// "session_lock", "session_unlock").
    pub detail: String,
}

/// What a task does when it starts.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TaskAction {
    /// "exec", "com", "email" or "message" (the last two are deprecated and no longer run).
    pub kind: String,
    /// Exec: the program as written in the task.
    pub command: String,
    pub arguments: String,
    pub working_dir: String,
    /// COM handler: the class it creates.
    pub class_id: String,
    /// COM handler: the data passed to it. Message: its title.
    pub data: String,
    /// The file that really runs: the resolved program, or the COM handler's DLL; empty when unknown.
    pub program: String,
}

/// Every scheduled task, sorted by path. Folders the account may not read are skipped. Runs on a
/// worker thread and gives up after a timeout.
pub fn list() -> Result<Vec<ScheduledTask>, SysError> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("vigil-tasks".into())
        .spawn(move || {
            let _ = tx.send(read_all());
        })
        .map_err(|e| SysError::new(format!("could not start reading scheduled tasks: {e}"), 0))?;
    match rx.recv_timeout(TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SysError::new("Task Scheduler did not answer in time", 0)),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SysError::new("reading scheduled tasks failed", 0)),
    }
}

/// The XML definition of one task (`\Folder\Name`), exactly as Task Scheduler stores it: the text
/// `IRegisteredTask::Xml` returns, without any code page conversion. Read on a worker thread with
/// a timeout, like the listing.
pub fn definition(path: &str) -> Result<String, SysError> {
    let path = path.to_string();
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("vigil-task-xml".into())
        .spawn(move || {
            // SAFETY: COM for this worker thread only; balanced below when it succeeded.
            let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
            let result = read_definition(&path);
            if initialized {
                // SAFETY: balances the successful CoInitializeEx above; every interface was released.
                unsafe { CoUninitialize() };
            }
            let _ = tx.send(result);
        })
        .map_err(|e| SysError::new(format!("could not start reading the scheduled task: {e}"), 0))?;
    match rx.recv_timeout(TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SysError::new("Task Scheduler did not answer in time", 0)),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SysError::new("reading the scheduled task failed", 0)),
    }
}

fn read_definition(path: &str) -> Result<String, SysError> {
    // SAFETY: creates the in-process Task Scheduler object; released when dropped.
    let service: ITaskService = unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| SysError::from_windows("Task Scheduler is not available", &e))?;
    let empty = VARIANT::default();
    // SAFETY: empty VARIANTs connect to this computer as the current user.
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }
        .map_err(|e| SysError::from_windows("could not connect to Task Scheduler", &e))?;
    // SAFETY: plain calls on valid interfaces; the BSTRs outlive them.
    let root = unsafe { service.GetFolder(&BSTR::from("\\")) }
        .map_err(|e| SysError::from_windows("could not open the Task Scheduler library", &e))?;
    // SAFETY: as above; a path relative to the root folder finds the task in any folder.
    let task = unsafe { root.GetTask(&BSTR::from(path)) }
        .map_err(|e| SysError::from_windows("the scheduled task was not found", &e))?;
    // SAFETY: plain property read on a valid interface.
    let xml = unsafe { task.Xml() }.map_err(|e| SysError::from_windows("the task definition could not be read", &e))?;
    Ok(xml.to_string())
}

/// The text of a task file in `System32\Tasks` (UTF-16 with a byte order mark, as Task Scheduler
/// writes them; UTF-8 otherwise).
pub fn decode_task_file(bytes: &[u8]) -> String {
    let utf16 = |data: &[u8], big: bool| {
        let units: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                if big {
                    u16::from_be_bytes(*pair)
                } else {
                    u16::from_le_bytes(*pair)
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, false),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, true),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        // No mark: UTF-16 LE when every other byte of the start is zero ("<\0?\0").
        [_, 0, _, 0, ..] => utf16(bytes, false),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// What a task does, for the background watch: a summary of its actions to compare between two
/// readings, and the files they run (programs, COM servers), resolved like the listing does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileActions {
    /// One line per action: the command and its arguments, or the COM class and its data.
    pub summary: String,
    /// The programs and DLLs the actions run (empty entries left out).
    pub programs: Vec<String>,
}

/// The actions of a task definition (`path` is only used for its name).
pub fn file_actions(path: &str, xml: &str) -> FileActions {
    let task = from_xml(path, xml);
    let mut summary = Vec::new();
    let mut programs = Vec::new();
    for action in &task.actions {
        match action.kind.as_str() {
            "exec" => {
                summary.push(format!("exec {} {}", action.command.trim(), action.arguments.trim()));
                programs.push(resolve_program(&action.command, &action.working_dir));
            }
            "com" => {
                summary.push(format!("com {} {}", action.class_id.trim(), action.data.trim()));
                programs.push(com_server(&action.class_id));
            }
            other => summary.push(other.to_string()),
        }
    }
    programs.retain(|p| !p.is_empty());
    FileActions {
        summary: summary.join("\n").trim().to_string(),
        programs,
    }
}

fn read_all() -> Result<Vec<ScheduledTask>, SysError> {
    // SAFETY: COM for this worker thread only; balanced below when it succeeded.
    let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
    let result = read_library();
    if initialized {
        // SAFETY: balances the successful CoInitializeEx above; every interface was released.
        unsafe { CoUninitialize() };
    }
    result
}

fn read_library() -> Result<Vec<ScheduledTask>, SysError> {
    // SAFETY: creates the in-process Task Scheduler object; released when dropped.
    let service: ITaskService = unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| SysError::from_windows("Task Scheduler is not available", &e))?;
    let empty = VARIANT::default();
    // SAFETY: empty VARIANTs connect to this computer as the current user.
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }
        .map_err(|e| SysError::from_windows("could not connect to Task Scheduler", &e))?;
    // SAFETY: plain call on a valid interface; the BSTR outlives it.
    let root = unsafe { service.GetFolder(&BSTR::from("\\")) }
        .map_err(|e| SysError::from_windows("could not open the Task Scheduler library", &e))?;
    let mut reader = Reader::default();
    let mut tasks = Vec::new();
    reader.walk(&root, 0, &mut tasks);
    tasks.sort_by_cached_key(|t| t.path.to_lowercase());
    Ok(tasks)
}

/// A 1-based collection index as COM wants it.
fn index(i: i32) -> VARIANT {
    let mut value = VARIANT::default();
    // SAFETY: fills the active members of a zeroed VARIANT: the VT_I4 tag and its 32-bit value.
    unsafe {
        let inner = &mut *value.Anonymous.Anonymous;
        inner.vt = VT_I4;
        inner.Anonymous.lVal = i;
    }
    value
}

/// Lookups shared by every task of one listing.
#[derive(Default)]
struct Reader {
    strings: HashMap<String, String>,
    accounts: HashMap<String, (String, String)>,
    programs: HashMap<String, String>,
}

impl Reader {
    fn walk(&mut self, folder: &ITaskFolder, depth: usize, out: &mut Vec<ScheduledTask>) {
        // SAFETY: plain calls on valid interfaces; failures (access denied) skip the folder.
        if let Ok(tasks) = unsafe { folder.GetTasks(TASK_ENUM_HIDDEN.0) } {
            let count = unsafe { tasks.Count() }.unwrap_or(0);
            for i in 1..=count {
                if out.len() >= MAX_TASKS {
                    return;
                }
                // SAFETY: the index is within 1..=Count.
                if let Ok(task) = unsafe { tasks.get_Item(&index(i)) } {
                    out.push(self.task(&task));
                }
            }
        }
        if depth >= MAX_FOLDER_DEPTH {
            return;
        }
        // SAFETY: as above.
        if let Ok(folders) = unsafe { folder.GetFolders(0) } {
            let count = unsafe { folders.Count() }.unwrap_or(0);
            for i in 1..=count {
                // SAFETY: the index is within 1..=Count.
                if let Ok(sub) = unsafe { folders.get_Item(&index(i)) } {
                    self.walk(&sub, depth + 1, out);
                }
            }
        }
    }

    fn task(&mut self, task: &IRegisteredTask) -> ScheduledTask {
        // SAFETY: plain property reads on a valid interface.
        let (path, xml, state, enabled, last_run, last_result, next_run) = unsafe {
            (
                task.Path().map(|b| b.to_string()).unwrap_or_default(),
                task.Xml().map(|b| b.to_string()).unwrap_or_default(),
                task.State().ok(),
                task.Enabled().ok().map(|b| b.0 != 0),
                task.LastRunTime().ok(),
                task.LastTaskResult().ok(),
                task.NextRunTime().ok(),
            )
        };
        let mut entry = from_xml(&path, &xml);
        entry.state = match state {
            Some(TASK_STATE_READY) => "ready",
            Some(TASK_STATE_RUNNING) => "running",
            Some(TASK_STATE_DISABLED) => "disabled",
            Some(TASK_STATE_QUEUED) => "queued",
            _ => "unknown",
        }
        .to_string();
        if let Some(enabled) = enabled {
            entry.enabled = enabled;
        }
        entry.last_run = last_run.and_then(local_time).unwrap_or_default();
        entry.last_result = last_result;
        entry.next_run = next_run.and_then(local_time).unwrap_or_default();
        self.resolve(&mut entry);
        entry
    }

    /// Fills in what needs the live system: resource strings, account names, program paths.
    fn resolve(&mut self, task: &mut ScheduledTask) {
        task.author = self.indirect(&task.author);
        task.description = self.indirect(&task.description);
        if !task.account.is_empty() {
            let (name, kind) = self.account(&task.account, task.account_kind == "group");
            task.account = name;
            task.account_kind = kind;
        }
        task.elevated = task.run_level == "highest" || task.account_kind == "system";
        for trigger in &mut task.triggers {
            if trigger.kind == "logon" && trigger.detail.starts_with("S-1-") {
                trigger.detail = self.account(&trigger.detail, false).0;
            }
        }
        for action in &mut task.actions {
            action.program = match action.kind.as_str() {
                "exec" => self.program(&action.command, &action.working_dir),
                "com" => com_server(&action.class_id),
                _ => String::new(),
            };
        }
        task.program = task
            .actions
            .iter()
            .map(|a| a.program.as_str())
            .find(|p| !p.is_empty())
            .unwrap_or("")
            .to_string();
        task.program_exists = !task.program.is_empty() && Path::new(&task.program).is_file();
    }

    /// A `$(@%SystemRoot%\system32\file.dll,-101)` resource reference read from the file; other text as is.
    fn indirect(&mut self, text: &str) -> String {
        let Some(source) = text.strip_prefix("$(").and_then(|t| t.strip_suffix(')')) else {
            return text.to_string();
        };
        if let Some(found) = self.strings.get(source) {
            return found.clone();
        }
        let input = wide(source);
        let mut buffer = vec![0u16; 1024];
        // SAFETY: `input` is NUL-terminated; `buffer` is writable for its length.
        let read = unsafe { SHLoadIndirectString(PCWSTR(input.as_ptr()), &mut buffer, None) };
        let value = match read {
            Ok(()) => from_wide(&buffer).trim().to_string(),
            Err(_) => text.to_string(),
        };
        self.strings.insert(source.to_string(), value.clone());
        value
    }

    /// The display name and kind of an account named by SID or by name.
    fn account(&mut self, text: &str, group: bool) -> (String, String) {
        if let Some(found) = self.accounts.get(text) {
            return found.clone();
        }
        let (name, sid) = if text.starts_with("S-1-") {
            (sid_name(text).unwrap_or_else(|| text.to_string()), text.to_string())
        } else {
            (text.to_string(), name_sid(text).unwrap_or_default())
        };
        let kind = account_kind(&sid, &name, group).to_string();
        self.accounts.insert(text.to_string(), (name.clone(), kind.clone()));
        (name, kind)
    }

    /// The file an Exec action starts, found the way CreateProcess finds it.
    fn program(&mut self, command: &str, working_dir: &str) -> String {
        let key = format!("{command}\n{working_dir}");
        if let Some(found) = self.programs.get(&key) {
            return found.clone();
        }
        let found = resolve_program(command, working_dir);
        self.programs.insert(key, found.clone());
        found
    }
}

fn resolve_program(command: &str, working_dir: &str) -> String {
    let program = expand(command.trim().trim_matches('"').trim());
    if program.is_empty() {
        return program;
    }
    let path = Path::new(&program);
    if path.is_absolute() {
        return program;
    }
    if program.contains(['\\', '/']) {
        let dir = expand(working_dir.trim().trim_matches('"'));
        return if dir.is_empty() {
            program
        } else {
            Path::new(&dir).join(&program).display().to_string()
        };
    }
    search_path(&program).unwrap_or(program)
}

/// A bare program name looked up in the system folders and PATH.
fn search_path(name: &str) -> Option<String> {
    let file = wide(name);
    let extension = wide(".exe");
    let mut buffer = vec![0u16; 1024];
    // SAFETY: the strings are NUL-terminated; `buffer` is writable for its length.
    let written = unsafe {
        SearchPathW(
            PCWSTR::null(),
            PCWSTR(file.as_ptr()),
            PCWSTR(extension.as_ptr()),
            Some(&mut buffer),
            None,
        )
    };
    (written > 0 && (written as usize) < buffer.len()).then(|| from_wide(&buffer))
}

/// The DLL of a COM class (the user's registration first: it wins for that user's tasks).
fn com_server(class_id: &str) -> String {
    let id = class_id.trim();
    if !(id.starts_with('{') && id.ends_with('}') && id.len() == 38) {
        return String::new();
    }
    let user = hkcu_string(&format!(r"Software\Classes\CLSID\{id}\InprocServer32"), "");
    let dll = if user.is_empty() {
        hklm_string(&format!(r"SOFTWARE\Classes\CLSID\{id}\InprocServer32"), "")
    } else {
        user
    };
    let dll = expand(dll.trim().trim_matches('"'));
    if dll.is_empty() || Path::new(&dll).is_absolute() {
        return dll;
    }
    search_path(&dll).unwrap_or(dll)
}

/// "system", "service", "group" or "user" for an account (SID when known, else by name).
pub fn account_kind(sid: &str, name: &str, group: bool) -> &'static str {
    match sid {
        "S-1-5-18" => return "system",
        "S-1-5-19" | "S-1-5-20" => return "service",
        _ => {}
    }
    if group {
        return "group";
    }
    let upper = name.to_uppercase();
    let bare = upper.strip_prefix(r"NT AUTHORITY\").unwrap_or(&upper);
    match bare {
        "SYSTEM" | "LOCALSYSTEM" => "system",
        "LOCAL SERVICE" | "LOCALSERVICE" | "NETWORK SERVICE" | "NETWORKSERVICE" => "service",
        _ => "user",
    }
}

/// "DOMAIN\name" of a SID string.
fn sid_name(text: &str) -> Option<String> {
    let text = wide(text);
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

/// The SID string of an account name.
fn name_sid(name: &str) -> Option<String> {
    let account = wide(name);
    let mut sid = vec![0u64; 16];
    let mut sid_len = (sid.len() * 8) as u32;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut use_ = SID_NAME_USE::default();
    // SAFETY: the buffers are writable for the lengths passed (the SID buffer is 8-byte aligned).
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            Some(PSID(sid.as_mut_ptr().cast())),
            &mut sid_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut use_,
        )
    }
    .ok()?;
    let mut text = PWSTR::null();
    // SAFETY: the buffer now holds a valid SID; `text` receives a LocalAlloc'd string freed below.
    unsafe { ConvertSidToStringSidW(PSID(sid.as_mut_ptr().cast()), &mut text) }.ok()?;
    // SAFETY: on success `text` is a valid NUL-terminated string.
    let value = unsafe { text.to_string() }.ok();
    // SAFETY: `text` was allocated by ConvertSidToStringSidW and is freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
    }
    value
}

/// Whether a date is one of Task Scheduler's "never" markers: before 1971 (the OLE zero date,
/// 1899) or 30 November 1999, which it reports as the last run of a task that never ran.
pub fn never_date(year: u16, month: u16, day: u16) -> bool {
    year < 1971 || (year, month, day) == (1999, 11, 30)
}

/// An OLE automation date (local time) as a local ISO time; `None` for "never" or nonsense.
fn local_time(date: f64) -> Option<String> {
    if !date.is_finite() || date < 2.0 {
        return None;
    }
    let mut time = SYSTEMTIME::default();
    // SAFETY: `time` is a valid output structure.
    if unsafe { VariantTimeToSystemTime(date, &mut time) } == 0 || never_date(time.wYear, time.wMonth, time.wDay) {
        return None;
    }
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond
    ))
}

// --------------------------------------------------------------------------- task definitions

/// A task as its XML definition describes it. `path` is its library path. What needs the live
/// system (resource strings, account names, program paths, state, run times) is left as written.
pub fn from_xml(path: &str, xml: &str) -> ScheduledTask {
    let (folder, name) = match path.rfind('\\') {
        Some(0) => ("\\".to_string(), path[1..].to_string()),
        Some(i) => (path[..i].to_string(), path[i + 1..].to_string()),
        None => ("\\".to_string(), path.to_string()),
    };
    let root = parse_xml(xml).unwrap_or_default();
    let settings = root.child("Settings");
    let flag = |name: &str, default: bool| {
        settings
            .and_then(|s| s.child(name))
            .map_or(default, |n| n.text.trim().eq_ignore_ascii_case("true"))
    };
    let principal = root.child("Principals").and_then(|p| p.child("Principal"));
    let user = principal.map_or("", |p| p.text_at(&["UserId"]));
    let group = principal.map_or("", |p| p.text_at(&["GroupId"]));
    let (account, account_kind) = match (user, group) {
        ("", "") => (String::new(), String::new()),
        ("", group) => (group.to_string(), "group".to_string()),
        (user, _) => (user.to_string(), account_kind(user, user, false).to_string()),
    };
    let run_level = match principal.map_or("", |p| p.text_at(&["RunLevel"])) {
        "HighestAvailable" => "highest",
        _ => "least",
    };
    let logon_type = match principal.map_or("", |p| p.text_at(&["LogonType"])) {
        "InteractiveToken" => "interactive",
        "Password" | "InteractiveTokenOrPassword" => "password",
        "S4U" => "s4u",
        "ServiceAccount" => "service",
        "Group" => "group",
        _ if account_kind == "system" || account_kind == "service" => "service",
        _ if account_kind == "group" => "group",
        _ => "",
    };
    let root_dir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let elevated = run_level == "highest" || account_kind == "system";
    ScheduledTask {
        path: path.to_string(),
        name,
        folder,
        state: String::new(),
        enabled: flag("Enabled", true),
        hidden: flag("Hidden", false),
        author: root.text_at(&["RegistrationInfo", "Author"]).to_string(),
        description: root.text_at(&["RegistrationInfo", "Description"]).to_string(),
        created: root.text_at(&["RegistrationInfo", "Date"]).to_string(),
        triggers: root
            .child("Triggers")
            .map(|t| t.children.iter().map(trigger).collect())
            .unwrap_or_default(),
        actions: root
            .child("Actions")
            .map(|a| a.children.iter().filter_map(action).collect())
            .unwrap_or_default(),
        account,
        account_kind,
        run_level: run_level.to_string(),
        logon_type: logon_type.to_string(),
        elevated,
        last_run: String::new(),
        last_result: None,
        next_run: String::new(),
        file: format!(r"{}\System32\Tasks{}", root_dir.trim_end_matches('\\'), path),
        program: String::new(),
        program_exists: false,
        microsoft: path.to_lowercase().starts_with("\\microsoft\\"),
        user_writable: false,
    }
}

const WEEKDAYS: [&str; 7] = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
];
const MONTHS: [&str; 12] = [
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];

fn trigger(node: &Node) -> TaskTrigger {
    let text = |name: &str| node.text_at(&[name]).to_string();
    let mut found = TaskTrigger {
        kind: String::new(),
        enabled: !node.text_at(&["Enabled"]).eq_ignore_ascii_case("false"),
        start: text("StartBoundary"),
        end: text("EndBoundary"),
        repeat_secs: duration_secs(node.text_at(&["Repetition", "Interval"])),
        repeat_for_secs: duration_secs(node.text_at(&["Repetition", "Duration"])),
        delay_secs: duration_secs(node.text_at(&["Delay"])),
        random_delay_secs: duration_secs(node.text_at(&["RandomDelay"])),
        ..TaskTrigger::default()
    };
    let kind = match node.name.as_str() {
        "LogonTrigger" => {
            found.detail = text("UserId");
            "logon"
        }
        "BootTrigger" => "boot",
        "IdleTrigger" => "idle",
        "TimeTrigger" => "time",
        "RegistrationTrigger" => "registration",
        "EventTrigger" => {
            found.detail = event_logs(node.text_at(&["Subscription"]));
            "event"
        }
        "SessionStateChangeTrigger" => {
            found.detail = snake(node.text_at(&["StateChange"]));
            "session"
        }
        "CalendarTrigger" => calendar(node, &mut found),
        _ => "custom",
    };
    found.kind = kind.to_string();
    found
}

fn calendar(node: &Node, found: &mut TaskTrigger) -> &'static str {
    let interval = |schedule: &Node, name: &str| schedule.text_at(&[name]).parse().unwrap_or(1).max(1);
    let names = |list: Option<&Node>, known: &[&str]| -> Vec<String> {
        let mut names: Vec<String> = list
            .map(|l| l.children.iter().map(|c| c.name.to_lowercase()).collect())
            .unwrap_or_default();
        names.retain(|n| known.contains(&n.as_str()));
        names.sort_by_key(|n| known.iter().position(|k| k == n));
        names.dedup();
        names
    };
    let months = |schedule: &Node| {
        let months = names(schedule.child("Months"), &MONTHS);
        if months.len() == MONTHS.len() {
            Vec::new()
        } else {
            months
        }
    };
    let values = |list: Option<&Node>, name: &str| -> Vec<String> {
        list.map(|l| {
            l.children
                .iter()
                .filter(|c| c.name == name)
                .map(|c| c.text.trim().to_lowercase())
                .collect()
        })
        .unwrap_or_default()
    };
    if let Some(schedule) = node.child("ScheduleByDay") {
        found.every = interval(schedule, "DaysInterval");
        "daily"
    } else if let Some(schedule) = node.child("ScheduleByWeek") {
        found.every = interval(schedule, "WeeksInterval");
        found.days = names(schedule.child("DaysOfWeek"), &WEEKDAYS);
        "weekly"
    } else if let Some(schedule) = node.child("ScheduleByMonth") {
        found.days = values(schedule.child("DaysOfMonth"), "Day");
        found.months = months(schedule);
        "monthly"
    } else if let Some(schedule) = node.child("ScheduleByMonthDayOfWeek") {
        found.weeks = values(schedule.child("Weeks"), "Week");
        found.days = names(schedule.child("DaysOfWeek"), &WEEKDAYS);
        found.months = months(schedule);
        "monthly_dow"
    } else {
        "time"
    }
}

/// The event logs an event trigger's query watches ("System, Application").
fn event_logs(subscription: &str) -> String {
    let Some(query) = parse_xml(subscription) else {
        return String::new();
    };
    let mut logs: Vec<String> = Vec::new();
    let mut add = |path: &str| {
        let path = path.trim();
        if !path.is_empty() && !logs.iter().any(|l| l.eq_ignore_ascii_case(path)) {
            logs.push(path.to_string());
        }
    };
    for q in query.children.iter().filter(|c| c.name == "Query") {
        let selects: Vec<&Node> = q.children.iter().filter(|c| c.name == "Select").collect();
        if selects.is_empty() {
            add(q.attr("Path"));
        }
        for select in selects {
            let path = select.attr("Path");
            add(if path.is_empty() { q.attr("Path") } else { path });
        }
    }
    logs.join(", ")
}

/// "SessionUnlock" -> "session_unlock".
fn snake(text: &str) -> String {
    let mut out = String::new();
    for (i, c) in text.trim().chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.extend(c.to_lowercase());
    }
    out
}

fn action(node: &Node) -> Option<TaskAction> {
    let text = |name: &str| node.text_at(&[name]).to_string();
    let found = match node.name.as_str() {
        "Exec" => TaskAction {
            kind: "exec".into(),
            command: text("Command"),
            arguments: text("Arguments"),
            working_dir: text("WorkingDirectory"),
            ..TaskAction::default()
        },
        "ComHandler" => TaskAction {
            kind: "com".into(),
            class_id: text("ClassId"),
            data: text("Data"),
            ..TaskAction::default()
        },
        "SendEmail" => TaskAction {
            kind: "email".into(),
            ..TaskAction::default()
        },
        "ShowMessage" => TaskAction {
            kind: "message".into(),
            data: text("Title"),
            ..TaskAction::default()
        },
        _ => return None,
    };
    Some(found)
}

/// An ISO 8601 duration ("PT15M", "P1DT12H", "PT30S") in seconds; 0 when empty or unreadable.
/// Months and years count as 30 and 365 days: only used to describe a schedule.
pub fn duration_secs(text: &str) -> u64 {
    let Some(body) = text.trim().strip_prefix('P') else {
        return 0;
    };
    let mut total: u64 = 0;
    let mut number = String::new();
    let mut in_time = false;
    for c in body.chars() {
        match c {
            'T' => in_time = true,
            '0'..='9' | '.' => number.push(c),
            unit => {
                let value: f64 = number.parse().unwrap_or(0.0);
                number.clear();
                let seconds = match (unit, in_time) {
                    ('Y', false) => 365.0 * 86_400.0,
                    ('M', false) => 30.0 * 86_400.0,
                    ('W', false) => 7.0 * 86_400.0,
                    ('D', false) => 86_400.0,
                    ('H', true) => 3_600.0,
                    ('M', true) => 60.0,
                    ('S', true) => 1.0,
                    _ => return 0,
                };
                total = total.saturating_add((value * seconds) as u64);
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    const TASK: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <!-- a comment -->
  <RegistrationInfo>
    <Date>2025-03-01T10:00:00</Date>
    <Author>Contoso Ltd.</Author>
    <Description>Keeps Contoso &amp; friends up to date</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>DESKTOP-ABC123\jdoe</UserId><Delay>PT30S</Delay></LogonTrigger>
    <BootTrigger><Enabled>false</Enabled></BootTrigger>
    <CalendarTrigger>
      <StartBoundary>2025-03-01T03:00:00</StartBoundary>
      <ScheduleByDay><DaysInterval>2</DaysInterval></ScheduleByDay>
      <RandomDelay>PT1H</RandomDelay>
    </CalendarTrigger>
    <TimeTrigger>
      <Repetition><Interval>PT15M</Interval><Duration>P1D</Duration></Repetition>
      <StartBoundary>2025-03-01T00:00:00Z</StartBoundary>
    </TimeTrigger>
    <CalendarTrigger>
      <StartBoundary>2025-03-03T09:30:00</StartBoundary>
      <ScheduleByWeek><DaysOfWeek><Friday /><Monday /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>
    </CalendarTrigger>
    <CalendarTrigger>
      <StartBoundary>2025-03-01T12:00:00</StartBoundary>
      <ScheduleByMonth>
        <DaysOfMonth><Day>1</Day><Day>Last</Day></DaysOfMonth>
        <Months><January /><July /></Months>
      </ScheduleByMonth>
    </CalendarTrigger>
    <CalendarTrigger>
      <StartBoundary>2025-03-01T12:00:00</StartBoundary>
      <ScheduleByMonthDayOfWeek>
        <Weeks><Week>1</Week><Week>Last</Week></Weeks>
        <DaysOfWeek><Sunday /></DaysOfWeek>
        <Months><January /><February /><March /><April /><May /><June /><July /><August /><September /><October /><November /><December /></Months>
      </ScheduleByMonthDayOfWeek>
    </CalendarTrigger>
    <EventTrigger>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[EventID=6005]]&lt;/Select&gt;&lt;Select Path='Application'&gt;*&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
    <SessionStateChangeTrigger><StateChange>SessionUnlock</StateChange></SessionStateChangeTrigger>
    <IdleTrigger />
    <RegistrationTrigger />
    <WnfStateChangeTrigger><StateName>7508BCA3</StateName></WnfStateChangeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>false</Enabled>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"%ProgramFiles%\Contoso\updater.exe"</Command>
      <Arguments>/check --quiet "a b"</Arguments>
      <WorkingDirectory>C:\Program Files\Contoso</WorkingDirectory>
    </Exec>
    <ComHandler><ClassId>{01234567-89AB-CDEF-0123-456789ABCDEF}</ClassId><Data><![CDATA[<run mode="x"/>]]></Data></ComHandler>
    <ShowMessage><Title>Hello</Title><Body>World</Body></ShowMessage>
  </Actions>
</Task>"#;

    fn kinds(task: &ScheduledTask) -> Vec<&str> {
        task.triggers.iter().map(|t| t.kind.as_str()).collect()
    }

    #[test]
    fn a_definition_is_read_from_its_xml() {
        let task = from_xml(r"\Contoso\Updater Task", TASK);
        assert_eq!(task.name, "Updater Task");
        assert_eq!(task.folder, r"\Contoso");
        assert_eq!(task.author, "Contoso Ltd.");
        assert_eq!(task.description, "Keeps Contoso & friends up to date");
        assert_eq!(task.created, "2025-03-01T10:00:00");
        assert!(!task.enabled);
        assert!(task.hidden);
        assert!(!task.microsoft);
        assert_eq!(task.account, "S-1-5-18");
        assert_eq!(task.account_kind, "system");
        assert_eq!(task.run_level, "highest");
        assert_eq!(task.logon_type, "service");
        assert!(task.elevated);
        assert!(task.file.ends_with(r"\System32\Tasks\Contoso\Updater Task"));

        assert_eq!(task.actions.len(), 3);
        let exec = &task.actions[0];
        assert_eq!(exec.kind, "exec");
        assert_eq!(exec.command, r#""%ProgramFiles%\Contoso\updater.exe""#);
        assert_eq!(exec.arguments, r#"/check --quiet "a b""#);
        assert_eq!(exec.working_dir, r"C:\Program Files\Contoso");
        assert_eq!(task.actions[1].kind, "com");
        assert_eq!(task.actions[1].class_id, "{01234567-89AB-CDEF-0123-456789ABCDEF}");
        assert_eq!(task.actions[1].data, r#"<run mode="x"/>"#);
        assert_eq!(
            (task.actions[2].kind.as_str(), task.actions[2].data.as_str()),
            ("message", "Hello")
        );
    }

    #[test]
    fn triggers_are_summarised() {
        let task = from_xml(r"\Contoso\Updater Task", TASK);
        assert_eq!(
            kinds(&task),
            [
                "logon",
                "boot",
                "daily",
                "time",
                "weekly",
                "monthly",
                "monthly_dow",
                "event",
                "session",
                "idle",
                "registration",
                "custom"
            ]
        );
        let t = &task.triggers;
        assert_eq!(
            (t[0].detail.as_str(), t[0].delay_secs, t[0].enabled),
            (r"DESKTOP-ABC123\jdoe", 30, true)
        );
        assert!(!t[1].enabled);
        assert_eq!(
            (t[2].every, t[2].start.as_str(), t[2].random_delay_secs),
            (2, "2025-03-01T03:00:00", 3600)
        );
        assert_eq!((t[3].repeat_secs, t[3].repeat_for_secs), (900, 86_400));
        assert_eq!(t[3].start, "2025-03-01T00:00:00Z");
        assert_eq!(
            (t[4].every, t[4].days.clone()),
            (1, vec!["monday".to_string(), "friday".to_string()])
        );
        assert_eq!(t[5].days, ["1", "last"]);
        assert_eq!(t[5].months, ["january", "july"]);
        assert_eq!(t[6].weeks, ["1", "last"]);
        assert_eq!(t[6].days, ["sunday"]);
        assert!(t[6].months.is_empty(), "all twelve months read as every month");
        assert_eq!(t[7].detail, "System, Application");
        assert_eq!(t[8].detail, "session_unlock");
    }

    #[test]
    fn accounts_and_run_levels() {
        let xml = |principal: &str| {
            format!("<Task><Principals><Principal id=\"Author\">{principal}</Principal></Principals></Task>")
        };
        let user = from_xml(
            r"\T",
            &xml("<UserId>DESKTOP-ABC123\\jdoe</UserId><LogonType>InteractiveToken</LogonType>"),
        );
        assert_eq!(
            (user.account_kind.as_str(), user.logon_type.as_str()),
            ("user", "interactive")
        );
        assert_eq!(user.run_level, "least");
        assert!(!user.elevated);
        let users = from_xml(
            r"\T",
            &xml("<GroupId>S-1-5-32-545</GroupId><RunLevel>HighestAvailable</RunLevel>"),
        );
        assert_eq!(
            (users.account_kind.as_str(), users.logon_type.as_str()),
            ("group", "group")
        );
        assert!(users.elevated);
        let service = from_xml(r"\T", &xml("<UserId>NT AUTHORITY\\LOCAL SERVICE</UserId>"));
        assert_eq!(service.account_kind, "service");
        assert!(!service.elevated);
        let none = from_xml(r"\Microsoft\Windows\T", "<Task />");
        assert_eq!((none.account.as_str(), none.account_kind.as_str()), ("", ""));
        assert!(none.microsoft);
        assert!(none.enabled && none.triggers.is_empty() && none.actions.is_empty());
        let root = from_xml(r"\Root task", "not xml at all");
        assert_eq!((root.folder.as_str(), root.name.as_str()), (r"\", "Root task"));
    }

    #[test]
    fn durations_and_names() {
        assert_eq!(duration_secs("PT15M"), 900);
        assert_eq!(duration_secs("P1DT12H"), 129_600);
        assert_eq!(duration_secs("PT1H30M5S"), 5_405);
        assert_eq!(duration_secs("P2W"), 1_209_600);
        assert_eq!(duration_secs(""), 0);
        assert_eq!(duration_secs("15 minutes"), 0);
        assert_eq!(snake("ConsoleConnect"), "console_connect");
    }

    #[test]
    fn never_run_dates_and_task_files() {
        assert!(never_date(1899, 12, 30) && never_date(1999, 11, 30));
        assert!(!never_date(1999, 11, 29) && !never_date(2026, 11, 30));
        let xml = r#"<?xml version="1.0" encoding="UTF-16"?><Task><Actions Context="Author">
            <Exec><Command>"%SystemRoot%\System32\cmd.exe"</Command><Arguments>/c echo</Arguments></Exec>
            <ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId><Data>x</Data></ComHandler>
            </Actions></Task>"#;
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(xml.encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(decode_task_file(&utf16), xml);
        let no_mark: Vec<u8> = xml.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode_task_file(&no_mark), xml);
        assert_eq!(decode_task_file(xml.as_bytes()), xml);
        let actions = file_actions(r"\Vendor\Updater", &decode_task_file(&utf16));
        assert_eq!(
            actions.summary,
            "exec \"%SystemRoot%\\System32\\cmd.exe\" /c echo\ncom {00000000-0000-0000-0000-000000000000} x"
        );
        // The program is expanded and found; an unregistered COM class names no file.
        assert_eq!(actions.programs.len(), 1, "{:?}", actions.programs);
        assert!(
            actions.programs[0].to_lowercase().ends_with(r"\system32\cmd.exe"),
            "{:?}",
            actions.programs
        );
        assert_eq!(file_actions("x", "not xml"), FileActions::default());
    }

    #[test]
    fn a_missing_task_has_no_definition() {
        assert!(definition(r"\Vigil test\No such task 7f3a").is_err());
    }

    #[test]
    fn the_live_library_is_listed_read_only() {
        let started = std::time::Instant::now();
        let tasks = list().expect("Task Scheduler answers");
        assert!(!tasks.is_empty(), "Windows always has scheduled tasks");
        assert!(tasks.iter().all(|t| t.path.starts_with('\\') && !t.name.is_empty()));
        assert!(tasks.iter().any(|t| t.microsoft));
        assert!(tasks.iter().all(|t| !t.state.is_empty()));
        let mut sorted: Vec<String> = tasks.iter().map(|t| t.path.to_lowercase()).collect();
        sorted.sort();
        assert_eq!(sorted, tasks.iter().map(|t| t.path.to_lowercase()).collect::<Vec<_>>());
        assert!(started.elapsed() < TIMEOUT);
    }
}
