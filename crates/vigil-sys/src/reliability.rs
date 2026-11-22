//! Reliability: what went wrong on this computer lately, read from the Windows event logs. That
//! means blue screens, unexpected shutdowns, application crashes and hangs, service failures,
//! hardware (WHEA) and disk errors, and failed Windows updates, plus program installs and boot
//! times for context.
//!
//! Read-only: the logs are queried through the Event Log API (`wevtapi`) and never cleared or
//! written. Event data is untrusted text (an application may log anything); it is carried as text
//! and only the fields below are interpreted.
//!
//! [`read`] queries the live logs; [`event_from_xml`], [`summarize`] and [`hints`] work on
//! rendered event XML, so they can be tested with recorded, fictitious events.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use serde::Serialize;
use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EvtClose, EvtFormatMessage, EvtFormatMessageEvent, EvtNext, EvtOpenPublisherMetadata, EvtQuery,
    EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml,
};
use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
use windows::core::{HSTRING, PCWSTR};

use crate::SysError;
use crate::util::{EPOCH_AS_FILETIME, from_wide, now_unix_ms};
use crate::xml::{Node, parse_xml};

/// The windows the page offers; anything else is clamped into 1..=MAX_DAYS.
pub const DEFAULT_DAYS: u32 = 30;
pub const MAX_DAYS: u32 = 365;
/// Events read per log at most (newest first); older ones are dropped and `truncated` is set.
const MAX_PER_LOG: usize = 5000;
/// Rendered messages are cut to this many characters.
const MAX_MESSAGE: usize = 2000;
const DAY_MS: i64 = 86_400_000;
/// Records of one incident (a crash and the reboot after it) are logged within this window.
const SAME_INCIDENT_MS: i64 = 30 * 60 * 1000;

/// The categories, in the order the page shows them.
pub const CATEGORIES: [&str; 9] = [
    "bluescreen",
    "shutdown",
    "app_crash",
    "app_hang",
    "service",
    "hardware",
    "disk",
    "update",
    "install",
];

/// Everything the Reliability page shows.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reliability {
    /// The window read, in days.
    pub days: u32,
    /// Its start (ms since 1970) and the moment it was read.
    pub since_ms: i64,
    pub read_ms: i64,
    /// Newest first.
    pub events: Vec<ReliabilityEvent>,
    /// Events per category (every category is present).
    pub counts: BTreeMap<&'static str, usize>,
    /// Application crashes and hangs grouped by program, most frequent first.
    pub crashing_apps: Vec<AppGroup>,
    pub hanging_apps: Vec<AppGroup>,
    /// Boot durations (Diagnostics-Performance), newest first; empty when that log is unreadable.
    pub boots: Vec<Boot>,
    pub hints: Vec<Hint>,
    /// Logs that could not be read (for example the boot performance log without administrator
    /// rights).
    pub unread_logs: Vec<String>,
    /// A log had more events than are read; the oldest were left out.
    pub truncated: bool,
}

/// One event, interpreted.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReliabilityEvent {
    /// Unique within a read: "System:12345".
    pub id: String,
    /// One of [`CATEGORIES`].
    pub category: &'static str,
    /// What happened, within the category:
    /// - bluescreen: "bugcheck" (BugCheck 1001) or "kernel_power" (stop code recorded only by
    ///   Kernel-Power 41);
    /// - shutdown: "power_loss", "power_button" or "unexpected" (EventLog 6008);
    /// - app_crash: "crash"; app_hang: "hang";
    /// - service: "crashed", "start_failed", "start_timeout" or "stopped_with_error";
    /// - hardware: "fatal" or "corrected";
    /// - disk: "bad_block", "controller_error", "paging_error", "retried", "corruption" or
    ///   "needs_repair";
    /// - update: "install_failed";
    /// - install: "installed", "install_failed", "removed" or "remove_failed".
    pub kind: &'static str,
    /// "critical", "error", "warning" or "info".
    pub severity: &'static str,
    pub time_ms: i64,
    /// Local time, ISO 8601 (`2026-01-01T10:05:00`).
    pub time: String,
    pub log: String,
    pub provider: String,
    pub event_id: u32,
    pub record_id: u64,
    /// What it is about: the program, service, update, product, device or volume ("" when none).
    pub subject: String,
    pub version: String,
    /// The faulting module of an application crash.
    pub module: String,
    pub module_version: String,
    /// Stop code, exception code or error code, as `0x0000009F` / `0xC0000005`, or a Win32 error
    /// number.
    pub code: String,
    /// The symbolic name of `code` when it is a known stop or exception code.
    pub code_name: String,
    /// Stop code parameters, crash offset, hang type.
    pub parameters: String,
    /// The program's path, or the memory dump of a blue screen.
    pub path: String,
    /// The memory dump still exists (blue screens only).
    pub path_exists: Option<bool>,
    /// The manufacturer of an installed product.
    pub publisher: String,
    /// How many times a service has terminated so far (as Windows counted it).
    pub count: u32,
    /// The event's message as Windows formats it (in the system's language); may be empty.
    pub message: String,
}

/// Crashes or hangs of one program.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppGroup {
    /// The program name in lower case.
    pub key: String,
    pub name: String,
    /// The most recent path.
    pub path: String,
    pub count: usize,
    pub first_ms: i64,
    pub last_ms: i64,
    /// The versions seen, newest first (at most five).
    pub versions: Vec<String>,
    /// The module named most often as the faulting one (crashes only).
    pub top_module: String,
    pub top_module_count: usize,
    /// The ids of its events, newest first.
    pub events: Vec<String>,
}

/// One boot, as Diagnostics-Performance measured it.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Boot {
    pub time_ms: i64,
    pub time: String,
    /// From power on to a usable desktop, then the background work after it (milliseconds).
    pub boot_ms: u64,
    pub main_path_ms: u64,
    pub post_boot_ms: u64,
}

/// A plain-language pointer drawn from the events. Its texts are built by the app from `code`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Hint {
    /// "hardware_errors", "graphics_driver", "memory_stop_codes", "disk_errors", "disk_retries",
    /// "repeated_stop_code", "power_loss", "power_button", "shared_module", "app_repeat",
    /// "update_repeat", "service_repeat" or "manual_crash".
    pub code: &'static str,
    /// "warn" (worth acting on) or "info".
    pub severity: &'static str,
    /// The program, module, stop code name, update, service or device it is about ("" when none).
    pub subject: String,
    pub count: usize,
    /// An error code that goes with it ("" when none).
    pub detail: String,
    /// The events behind it, newest first (at most 50).
    pub events: Vec<String>,
    /// Filled in by the app, in the user's language.
    pub title: String,
    pub text: String,
}

// ------------------------------------------------------------------------------ known codes

/// Common stop codes: (code, name, family). Families: "memory", "graphics", "hardware", "storage",
/// "driver", "system" and "manual" (started on purpose).
const STOP_CODES: &[(u32, &str, &str)] = &[
    (0x0A, "IRQL_NOT_LESS_OR_EQUAL", "driver"),
    (0x19, "BAD_POOL_HEADER", "driver"),
    (0x1A, "MEMORY_MANAGEMENT", "memory"),
    (0x1E, "KMODE_EXCEPTION_NOT_HANDLED", "driver"),
    (0x24, "NTFS_FILE_SYSTEM", "storage"),
    (0x3B, "SYSTEM_SERVICE_EXCEPTION", "driver"),
    (0x4E, "PFN_LIST_CORRUPT", "memory"),
    (0x50, "PAGE_FAULT_IN_NONPAGED_AREA", "memory"),
    (0x77, "KERNEL_STACK_INPAGE_ERROR", "storage"),
    (0x7A, "KERNEL_DATA_INPAGE_ERROR", "storage"),
    (0x7B, "INACCESSIBLE_BOOT_DEVICE", "storage"),
    (0x7E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "driver"),
    (0x7F, "UNEXPECTED_KERNEL_MODE_TRAP", "driver"),
    (0x8E, "KERNEL_MODE_EXCEPTION_NOT_HANDLED", "driver"),
    (0x9F, "DRIVER_POWER_STATE_FAILURE", "driver"),
    (0xA0, "INTERNAL_POWER_ERROR", "driver"),
    (0xC2, "BAD_POOL_CALLER", "driver"),
    (0xC4, "DRIVER_VERIFIER_DETECTED_VIOLATION", "driver"),
    (0xC5, "DRIVER_CORRUPTED_EXPOOL", "driver"),
    (0xD1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL", "driver"),
    (0xD5, "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL", "driver"),
    (0xE2, "MANUALLY_INITIATED_CRASH", "manual"),
    (0xED, "UNMOUNTABLE_BOOT_VOLUME", "storage"),
    (0xEF, "CRITICAL_PROCESS_DIED", "system"),
    (0xF4, "CRITICAL_OBJECT_TERMINATION", "system"),
    (0xFC, "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY", "driver"),
    (0x101, "CLOCK_WATCHDOG_TIMEOUT", "hardware"),
    (0x109, "CRITICAL_STRUCTURE_CORRUPTION", "system"),
    (0x10E, "VIDEO_MEMORY_MANAGEMENT_INTERNAL", "graphics"),
    (0x116, "VIDEO_TDR_FAILURE", "graphics"),
    (0x117, "VIDEO_TDR_TIMEOUT_DETECTED", "graphics"),
    (0x119, "VIDEO_SCHEDULER_INTERNAL_ERROR", "graphics"),
    (0x124, "WHEA_UNCORRECTABLE_ERROR", "hardware"),
    (0x12B, "FAULTY_HARDWARE_CORRUPTED_PAGE", "memory"),
    (0x133, "DPC_WATCHDOG_VIOLATION", "driver"),
    (0x139, "KERNEL_SECURITY_CHECK_FAILURE", "driver"),
    (0x13A, "KERNEL_MODE_HEAP_CORRUPTION", "driver"),
    (0x144, "BUGCODE_USB3_DRIVER", "driver"),
    (0x154, "UNEXPECTED_STORE_EXCEPTION", "storage"),
    (0x1C7, "STORE_DATA_STRUCTURE_CORRUPTION", "memory"),
    (0x1C8, "MANUALLY_INITIATED_POWER_BUTTON_HOLD", "manual"),
    (0xDEAD_DEAD, "MANUALLY_INITIATED_CRASH1", "manual"),
];

/// The name and family of a stop code ("" for both when it is not in the table). The `0x1000xxxx`
/// variants (the same stop with extra flags) share the name of the base code.
pub fn stop_code(code: u32) -> (&'static str, &'static str) {
    let lookup = |value: u32| STOP_CODES.iter().find(|(c, _, _)| *c == value);
    lookup(code)
        .or_else(|| {
            (code & 0xF000_0000 == 0x1000_0000)
                .then(|| lookup(code & 0x0FFF_FFFF))
                .flatten()
        })
        .map_or(("", ""), |(_, name, family)| (*name, *family))
}

/// Common exception codes of application crashes.
const EXCEPTIONS: &[(u32, &str)] = &[
    (0x4000_0015, "FATAL_APP_EXIT"),
    (0x8000_0003, "BREAKPOINT"),
    (0xC000_0005, "ACCESS_VIOLATION"),
    (0xC000_0006, "IN_PAGE_ERROR"),
    (0xC000_001D, "ILLEGAL_INSTRUCTION"),
    (0xC000_0025, "NONCONTINUABLE_EXCEPTION"),
    (0xC000_0094, "INTEGER_DIVIDE_BY_ZERO"),
    (0xC000_0096, "PRIVILEGED_INSTRUCTION"),
    (0xC000_00FD, "STACK_OVERFLOW"),
    (0xC000_0142, "DLL_INIT_FAILED"),
    (0xC000_0194, "POSSIBLE_DEADLOCK"),
    (0xC000_0374, "HEAP_CORRUPTION"),
    (0xC000_0409, "STACK_BUFFER_OVERRUN"),
    (0xC000_041D, "FATAL_USER_CALLBACK_EXCEPTION"),
    (0xC000_0420, "ASSERTION_FAILURE"),
    (0xC000_0602, "FAIL_FAST_EXCEPTION"),
    (0xC06D_007E, "MODULE_NOT_FOUND"),
    (0xC06D_007F, "PROCEDURE_NOT_FOUND"),
    (0xE043_4352, "CLR_EXCEPTION"),
    (0xE06D_7363, "CPP_EXCEPTION"),
];

pub fn exception_name(code: u32) -> &'static str {
    EXCEPTIONS.iter().find(|(c, _)| *c == code).map_or("", |(_, name)| name)
}

/// Graphics driver modules (lower case, prefixes): crashes in them point to the display driver.
const GPU_MODULES: [&str; 22] = [
    "nvlddmkm",
    "nvwgf2um",
    "nvoglv",
    "nvd3dum",
    "nvcuda",
    "nvapi",
    "nvgpucomp",
    "amdkmdag",
    "atikmpag",
    "atikmdag",
    "atidxx",
    "amdxx",
    "atiumd",
    "aticfx",
    "amdvlk",
    "amdihk",
    "igdkmd",
    "igd10iumd",
    "igd12umd",
    "igdumdim",
    "igc64",
    "ig9icd",
];

pub fn is_gpu_module(module: &str) -> bool {
    let lower = module.to_ascii_lowercase();
    GPU_MODULES.iter().any(|m| lower.starts_with(m))
}

/// Modules every crash passes through: naming them as "the cause" would mislead.
fn generic_module(module: &str) -> bool {
    let lower = module.to_ascii_lowercase();
    lower.is_empty()
        || lower == "unknown"
        || lower.starts_with("stackhash")
        || [
            "ntdll.dll",
            "kernelbase.dll",
            "kernel32.dll",
            "ucrtbase.dll",
            "msvcrt.dll",
            "combase.dll",
            "user32.dll",
            "win32u.dll",
            "vcruntime140.dll",
            "vcruntime140_1.dll",
            "msvcp140.dll",
            "coreclr.dll",
            "clr.dll",
            "kernel.appcore.dll",
            "rpcrt4.dll",
        ]
        .contains(&lower.as_str())
}

/// `0x0000009f`, `9f`, `159` (decimal, as Kernel-Power writes it) to a number.
fn parse_code(text: &str, decimal: bool) -> Option<u32> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok().map(|v| v as u32);
    }
    if decimal {
        text.parse::<u64>().ok().map(|v| v as u32)
    } else {
        u64::from_str_radix(text, 16).ok().map(|v| v as u32)
    }
}

fn hex8(code: u32) -> String {
    format!("0x{code:08X}")
}

// ------------------------------------------------------------------------------ live read

/// Reads the last `days` days of the System and Application logs (and the boot performance log
/// when allowed), on a worker thread that gives up after `timeout`.
pub fn read(days: u32, timeout: Duration) -> Result<Reliability, SysError> {
    let days = days.clamp(1, MAX_DAYS);
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("vigil-reliability".into())
        .spawn(move || {
            let _ = tx.send(read_now(days));
        })
        .map_err(|e| SysError::new(format!("could not start reading the event logs: {e}"), 0))?;
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SysError::new("the event logs did not answer in time", 0)),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SysError::new("reading the event logs failed", 0)),
    }
}

const SYSTEM_SELECT: &str = "(Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and EventID=1001) \
or (Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41) \
or (Provider[@Name='EventLog'] and EventID=6008) \
or (Provider[@Name='Service Control Manager'] and (EventID=7031 or EventID=7034 or EventID=7000 or EventID=7009 or EventID=7023)) \
or (Provider[@Name='Microsoft-Windows-WHEA-Logger'] and (Level=1 or Level=2 or Level=3)) \
or (Provider[@Name='disk'] and (EventID=7 or EventID=11 or EventID=51 or EventID=153)) \
or (Provider[@Name='Microsoft-Windows-Ntfs' or @Name='Ntfs'] and (EventID=55 or EventID=98) and (Level=1 or Level=2 or Level=3)) \
or (Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and EventID=20)";

const APPLICATION_SELECT: &str = "(Provider[@Name='Application Error'] and EventID=1000) \
or (Provider[@Name='Application Hang'] and EventID=1002) \
or (Provider[@Name='MsiInstaller'] and (EventID=1033 or EventID=1034 or EventID=11707 or EventID=11724))";

const BOOT_LOG: &str = "Microsoft-Windows-Diagnostics-Performance/Operational";

fn read_now(days: u32) -> Result<Reliability, SysError> {
    let window_ms = i64::from(days) * DAY_MS;
    let mut reader = LogReader::default();
    let mut events = Vec::new();
    let mut unread = Vec::new();
    let mut truncated = false;
    let mut first_error = None;
    for (log, select) in [("System", SYSTEM_SELECT), ("Application", APPLICATION_SELECT)] {
        let query = format!("*[System[TimeCreated[timediff(@SystemTime) <= {window_ms}] and ({select})]]");
        match reader.query(log, &query, true) {
            Ok((records, cut)) => {
                truncated |= cut;
                events.extend(records.iter().filter_map(|(xml, message)| event_from_xml(xml, message)));
            }
            Err(error) => {
                unread.push(log.to_string());
                first_error.get_or_insert(error);
            }
        }
    }
    if unread.len() == 2
        && let Some(error) = first_error
    {
        return Err(error);
    }
    let boot_query = format!("*[System[EventID=100 and TimeCreated[timediff(@SystemTime) <= {window_ms}]]]");
    let boots = match reader.query(BOOT_LOG, &boot_query, false) {
        Ok((records, _)) => records.iter().filter_map(|(xml, _)| boot_from_xml(xml)).collect(),
        Err(error) => {
            // A log that does not exist is simply not there; anything else (access denied) is said.
            if error.code() != ERROR_EVT_CHANNEL_NOT_FOUND {
                unread.push(BOOT_LOG.to_string());
            }
            Vec::new()
        }
    };
    for event in &mut events {
        if event.category == "bluescreen" && !event.path.is_empty() {
            event.path_exists = Some(Path::new(&event.path).exists());
        }
    }
    let now = now_unix_ms();
    let mut result = summarize(events, days, now - window_ms, now);
    result.boots = boots;
    result.unread_logs = unread;
    result.truncated = truncated;
    Ok(result)
}

/// `ERROR_EVT_CHANNEL_NOT_FOUND` as an HRESULT.
pub(crate) const ERROR_EVT_CHANNEL_NOT_FOUND: i32 = 0x8007_3A9F_u32 as i32;

/// An event log handle closed when dropped.
pub(crate) struct Handle(pub(crate) EVT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the handle came from the Event Log API and is closed once.
            unsafe {
                let _ = EvtClose(self.0);
            }
        }
    }
}

/// Publisher metadata, opened once per provider, to format messages.
#[derive(Default)]
pub(crate) struct LogReader {
    publishers: HashMap<String, Option<Handle>>,
}

impl LogReader {
    /// Rendered XML and formatted message of each matching event, newest first, and whether the
    /// cap cut the list.
    pub(crate) fn query(
        &mut self,
        log: &str,
        query: &str,
        messages: bool,
    ) -> Result<(Vec<(String, String)>, bool), SysError> {
        let flags = EvtQueryChannelPath.0 | EvtQueryReverseDirection.0;
        // SAFETY: both strings are NUL-terminated HSTRINGs that outlive the call.
        let results = unsafe { EvtQuery(None, &HSTRING::from(log), &HSTRING::from(query), flags) }
            .map(Handle)
            .map_err(|e| SysError::from_windows(&format!("could not read the {log} log"), &e))?;
        let mut out = Vec::new();
        let mut batch = [0isize; 64];
        loop {
            let mut returned = 0u32;
            // SAFETY: `batch` is writable for its length; `returned` receives how many were filled.
            if unsafe { EvtNext(results.0, &mut batch, 5000, 0, &mut returned) }.is_err() {
                // ERROR_NO_MORE_ITEMS (the end) or a failure: either way, keep what was read.
                return Ok((out, false));
            }
            let handles: Vec<Handle> = batch[..returned as usize]
                .iter()
                .map(|&raw| Handle(EVT_HANDLE(raw)))
                .collect();
            for event in &handles {
                if out.len() >= MAX_PER_LOG {
                    return Ok((out, true));
                }
                let Some(xml) = render_xml(event.0) else { continue };
                let message = if messages {
                    self.message(&xml, event.0)
                } else {
                    String::new()
                };
                out.push((xml, message));
            }
        }
    }

    fn message(&mut self, xml: &str, event: EVT_HANDLE) -> String {
        let provider = provider_of(xml);
        if provider.is_empty() {
            return String::new();
        }
        let meta = self.publishers.entry(provider.clone()).or_insert_with(|| {
            // SAFETY: the provider name is a NUL-terminated HSTRING; no log file, default locale.
            unsafe { EvtOpenPublisherMetadata(None, &HSTRING::from(provider.as_str()), PCWSTR::null(), 0, 0) }
                .ok()
                .map(Handle)
        });
        let Some(meta) = meta else { return String::new() };
        format_message(meta.0, event)
    }
}

/// The rendered XML of the newest event of `log` matching `query` that `accept` takes, looking at
/// most at `max` events (newest first). `None` when none was found or the log cannot be read.
pub(crate) fn newest_event_xml(log: &str, query: &str, max: usize, accept: impl Fn(&str) -> bool) -> Option<String> {
    let flags = EvtQueryChannelPath.0 | EvtQueryReverseDirection.0;
    // SAFETY: both strings are NUL-terminated HSTRINGs that outlive the call.
    let results = unsafe { EvtQuery(None, &HSTRING::from(log), &HSTRING::from(query), flags) }
        .map(Handle)
        .ok()?;
    let mut seen = 0usize;
    let mut batch = [0isize; 16];
    while seen < max {
        let mut returned = 0u32;
        // SAFETY: `batch` is writable for its length; `returned` receives how many were filled.
        if unsafe { EvtNext(results.0, &mut batch, 5000, 0, &mut returned) }.is_err() {
            return None;
        }
        let handles: Vec<Handle> = batch[..returned as usize]
            .iter()
            .map(|&raw| Handle(EVT_HANDLE(raw)))
            .collect();
        for event in &handles {
            seen += 1;
            if let Some(xml) = render_xml(event.0)
                && accept(&xml)
            {
                return Some(xml);
            }
        }
    }
    None
}

/// The provider name in rendered event XML.
fn provider_of(xml: &str) -> String {
    parse_xml(xml)
        .and_then(|root| {
            root.child("System")
                .and_then(|s| s.child("Provider"))
                .map(|p| p.attr("Name").to_string())
        })
        .unwrap_or_default()
}

pub(crate) fn render_xml(event: EVT_HANDLE) -> Option<String> {
    let mut used = 0u32;
    let mut count = 0u32;
    // SAFETY: a size query: no buffer, `used` receives the size needed in bytes.
    let _ = unsafe { EvtRender(None, event, EvtRenderEventXml.0, 0, None, &mut used, &mut count) };
    if used == 0 || used > 4 * 1024 * 1024 {
        return None;
    }
    let mut buffer = vec![0u16; (used as usize).div_ceil(2) + 1];
    let size = (buffer.len() * 2) as u32;
    // SAFETY: `buffer` is writable for `size` bytes.
    unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            size,
            Some(buffer.as_mut_ptr().cast()),
            &mut used,
            &mut count,
        )
    }
    .ok()?;
    Some(from_wide(&buffer))
}

fn format_message(meta: EVT_HANDLE, event: EVT_HANDLE) -> String {
    let mut used = 0u32;
    // SAFETY: a size query: no buffer, `used` receives the length needed in characters.
    let _ = unsafe {
        EvtFormatMessage(
            Some(meta),
            Some(event),
            0,
            None,
            EvtFormatMessageEvent.0,
            None,
            &mut used,
        )
    };
    if used == 0 || used > 256 * 1024 {
        return String::new();
    }
    let mut buffer = vec![0u16; used as usize + 1];
    // SAFETY: `buffer` is writable for its length. A message whose inserts could not all be
    // resolved still comes back (with the error), so the buffer is read either way.
    let _ = unsafe {
        EvtFormatMessage(
            Some(meta),
            Some(event),
            0,
            None,
            EvtFormatMessageEvent.0,
            Some(&mut buffer),
            &mut used,
        )
    };
    clean_message(&from_wide(&buffer))
}

/// A message as text: line ends normalized, direction marks dropped, blank runs collapsed, capped.
pub fn clean_message(text: &str) -> String {
    let text = text.replace("\r\n", "\n").replace(['\u{200E}', '\u{200F}', '\r'], "");
    let mut out = String::new();
    let mut blank = 0;
    for line in text.lines() {
        let line = line.trim_end();
        if line.trim().is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    let out = out.trim();
    if out.chars().count() > MAX_MESSAGE {
        format!("{}…", out.chars().take(MAX_MESSAGE).collect::<String>())
    } else {
        out.to_string()
    }
}

/// Unix milliseconds as local ISO time (`2026-01-01T10:05:00`); "" when out of range.
pub fn local_time(unix_ms: i64) -> String {
    if unix_ms <= 0 {
        return String::new();
    }
    let raw = unix_ms.saturating_mul(10_000).saturating_add(EPOCH_AS_FILETIME);
    let filetime = FILETIME {
        dwLowDateTime: raw as u32,
        dwHighDateTime: (raw >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    // SAFETY: plain conversions between valid structures; no pointers are kept.
    let ok = unsafe {
        FileTimeToSystemTime(&filetime, &mut utc).is_ok()
            && SystemTimeToTzSpecificLocalTime(None, &utc, &mut local).is_ok()
    };
    if !ok {
        return String::new();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute, local.wSecond
    )
}

// ------------------------------------------------------------------------------ parsing

/// The parts of a rendered event every category uses.
pub(crate) struct Record {
    pub(crate) provider: String,
    pub(crate) event_id: u32,
    pub(crate) level: u8,
    pub(crate) time_ms: i64,
    pub(crate) record_id: u64,
    pub(crate) log: String,
    /// EventData `<Data>` values (with their Name, "" when unnamed) or UserData leaves.
    pub(crate) data: Vec<(String, String)>,
}

impl Record {
    pub(crate) fn parse(xml: &str) -> Option<Self> {
        let root = parse_xml(xml)?;
        let system = root.child("System")?;
        let provider = system.child("Provider")?.attr("Name").to_string();
        let event_id = system.text_at(&["EventID"]).parse().ok()?;
        let time_ms = system
            .child("TimeCreated")
            .and_then(|t| iso_utc_ms(t.attr("SystemTime")))?;
        let mut data = Vec::new();
        if let Some(event_data) = root.child("EventData") {
            for item in event_data.children.iter().filter(|c| c.name == "Data") {
                data.push((item.attr("Name").to_string(), item.text.trim().to_string()));
            }
        }
        if let Some(user_data) = root.child("UserData") {
            leaves(user_data, &mut data, 0);
        }
        Some(Self {
            provider,
            event_id,
            level: system.text_at(&["Level"]).parse().unwrap_or(0),
            time_ms,
            record_id: system.text_at(&["EventRecordID"]).parse().unwrap_or(0),
            log: system.text_at(&["Channel"]).to_string(),
            data,
        })
    }

    /// A data value by name, or else by position when the event names none of its values ("" when
    /// missing). An empty `name` reads by position only.
    pub(crate) fn get(&self, name: &str, index: usize) -> &str {
        if !name.is_empty()
            && let Some((_, value)) = self.data.iter().find(|(n, _)| n.eq_ignore_ascii_case(name))
        {
            return value;
        }
        if self.data.iter().any(|(n, _)| !n.is_empty()) {
            return "";
        }
        self.data.get(index).map_or("", |(_, v)| v.as_str())
    }
}

fn leaves(node: &Node, out: &mut Vec<(String, String)>, depth: usize) {
    for child in &node.children {
        if child.children.is_empty() {
            out.push((child.name.clone(), child.text.trim().to_string()));
        } else if depth < 4 {
            leaves(child, out, depth + 1);
        }
    }
}

/// `2026-03-01T10:11:12.1234567Z` (UTC) to Unix milliseconds.
pub(crate) fn iso_utc_ms(text: &str) -> Option<i64> {
    let text = text.trim();
    let num = |range: std::ops::Range<usize>| text.get(range).and_then(|s| s.parse::<i64>().ok());
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut millis = 0;
    if let Some(fraction) = text.get(19..).and_then(|r| r.strip_prefix('.')) {
        let digits: String = fraction.chars().take_while(char::is_ascii_digit).take(3).collect();
        millis = format!("{digits:0<3}").parse().unwrap_or(0);
    }
    // Days since 1970-01-01 (proleptic Gregorian calendar).
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + millis)
}

/// `%%1053` (an insert Windows resolves to an error text) to `1053`.
fn insert_code(text: &str) -> String {
    text.trim().trim_start_matches("%%").to_string()
}

/// A rendered event (`EvtRenderEventXml`) and its formatted message, interpreted; `None` for
/// events that are not one of the kinds read here (or are not problems, like a healthy volume).
pub fn event_from_xml(xml: &str, message: &str) -> Option<ReliabilityEvent> {
    let record = Record::parse(xml)?;
    let r = &record;
    let mut event = ReliabilityEvent {
        id: format!("{}:{}", if r.log.is_empty() { "Log" } else { &r.log }, r.record_id),
        time_ms: r.time_ms,
        time: local_time(r.time_ms),
        log: r.log.clone(),
        provider: r.provider.clone(),
        event_id: r.event_id,
        record_id: r.record_id,
        message: clean_message(message),
        ..ReliabilityEvent::default()
    };
    match (r.provider.as_str(), r.event_id) {
        ("Microsoft-Windows-WER-SystemErrorReporting", 1001) => {
            // param1: "0x0000009f (0x0000000000000003, 0xffff..., ...)"; param2: the dump.
            let text = r.get("param1", 0);
            let (code, parameters) = match text.split_once('(') {
                Some((code, rest)) => (code.trim(), rest.trim_end().trim_end_matches(')').trim()),
                None => (text.trim(), ""),
            };
            let value = parse_code(code, false)?;
            let (name, _) = stop_code(value);
            event.category = "bluescreen";
            event.kind = "bugcheck";
            event.severity = "critical";
            event.code = hex8(value);
            event.code_name = name.to_string();
            event.subject = if name.is_empty() {
                event.code.clone()
            } else {
                name.to_string()
            };
            event.parameters = parameters.to_string();
            event.path = r.get("param2", 1).to_string();
        }
        ("Microsoft-Windows-Kernel-Power", 41) => {
            let code = parse_code(r.get("BugcheckCode", 0), true).unwrap_or(0);
            if code != 0 {
                let (name, _) = stop_code(code);
                event.category = "bluescreen";
                event.kind = "kernel_power";
                event.severity = "critical";
                event.code = hex8(code);
                event.code_name = name.to_string();
                event.subject = if name.is_empty() {
                    event.code.clone()
                } else {
                    name.to_string()
                };
                event.parameters = (1..=4)
                    .map(|i| r.get(&format!("BugcheckParameter{i}"), i).to_string())
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
                    .join(", ");
            } else {
                let pressed = r.get("PowerButtonTimestamp", 6).trim();
                let long_press = r.get("LongPowerButtonPressDetected", 15).eq_ignore_ascii_case("true");
                event.category = "shutdown";
                event.kind = if long_press || !(pressed.is_empty() || pressed == "0") {
                    "power_button"
                } else {
                    "power_loss"
                };
                event.severity = "error";
            }
        }
        ("EventLog", 6008) => {
            event.category = "shutdown";
            event.kind = "unexpected";
            event.severity = "error";
        }
        ("Service Control Manager", 7031 | 7034) => {
            event.category = "service";
            event.kind = "crashed";
            event.severity = "error";
            event.subject = r.get("param1", 0).to_string();
            event.count = r.get("param2", 1).trim().parse().unwrap_or(0);
        }
        ("Service Control Manager", 7000 | 7023) => {
            event.category = "service";
            event.kind = if r.event_id == 7000 {
                "start_failed"
            } else {
                "stopped_with_error"
            };
            event.severity = "warning";
            event.subject = r.get("param1", 0).to_string();
            event.code = insert_code(r.get("param2", 1));
        }
        ("Service Control Manager", 7009) => {
            event.category = "service";
            event.kind = "start_timeout";
            event.severity = "warning";
            event.subject = r.get("param2", 1).to_string();
            event.parameters = r.get("param1", 0).to_string();
        }
        ("Microsoft-Windows-WHEA-Logger", _) => {
            event.category = "hardware";
            let fatal = matches!(r.level, 1 | 2);
            event.kind = if fatal { "fatal" } else { "corrected" };
            event.severity = if fatal { "critical" } else { "warning" };
            event.subject = ["PrimaryDeviceName", "DeviceName", "ErrorSource"]
                .iter()
                .map(|n| r.get(n, usize::MAX))
                .find(|v| !v.is_empty())
                .unwrap_or("")
                .to_string();
        }
        ("disk", 7 | 11 | 51 | 153) => {
            event.category = "disk";
            event.kind = match r.event_id {
                7 => "bad_block",
                11 => "controller_error",
                51 => "paging_error",
                _ => "retried",
            };
            event.severity = if r.event_id == 153 { "warning" } else { "error" };
            event.subject = r.get("DeviceName", 0).to_string();
        }
        ("Microsoft-Windows-Ntfs" | "Ntfs", 55 | 98) => {
            if !matches!(r.level, 1..=3) {
                return None;
            }
            event.category = "disk";
            event.kind = if r.event_id == 55 { "corruption" } else { "needs_repair" };
            event.severity = if r.event_id == 55 { "error" } else { "warning" };
            event.subject = ["DriveName", "VolumeName"]
                .iter()
                .map(|n| r.get(n, 0))
                .find(|v| !v.is_empty())
                .unwrap_or("")
                .to_string();
        }
        ("Microsoft-Windows-WindowsUpdateClient", 20) => {
            event.category = "update";
            event.kind = "install_failed";
            event.severity = "warning";
            event.subject = r.get("updateTitle", 1).to_string();
            let code = r.get("errorCode", 0);
            event.code = parse_code(code, false).map_or_else(|| code.to_string(), hex8);
        }
        ("Application Error", 1000) => {
            event.category = "app_crash";
            event.kind = "crash";
            event.severity = "error";
            event.subject = r.get("AppName", 0).to_string();
            event.version = r.get("AppVersion", 1).to_string();
            event.module = r.get("ModuleName", 3).to_string();
            event.module_version = r.get("ModuleVersion", 4).to_string();
            if let Some(code) = parse_code(r.get("ExceptionCode", 6), false) {
                event.code = hex8(code);
                event.code_name = exception_name(code).to_string();
            }
            event.parameters = r.get("FaultingOffset", 7).to_string();
            event.path = r.get("AppPath", 10).to_string();
        }
        ("Application Hang", 1002) => {
            event.category = "app_hang";
            event.kind = "hang";
            event.severity = "warning";
            event.subject = r.get("AppName", 0).to_string();
            event.version = r.get("AppVersion", 1).to_string();
            event.path = r.get("ExeFileName", 5).to_string();
            event.parameters = r.get("HangType", 9).to_string();
        }
        ("MsiInstaller", 1033 | 1034) => {
            // Product name, version, language, status, manufacturer.
            let failed = r.get("", 3).trim().parse::<i64>().is_ok_and(|status| status != 0);
            event.category = "install";
            event.kind = match (r.event_id, failed) {
                (1033, false) => "installed",
                (1033, true) => "install_failed",
                (_, false) => "removed",
                (_, true) => "remove_failed",
            };
            event.severity = if failed { "warning" } else { "info" };
            event.subject = r.get("", 0).to_string();
            event.version = r.get("", 1).to_string();
            event.publisher = r.get("", 4).to_string();
            if failed {
                event.code = r.get("", 3).trim().to_string();
            }
        }
        ("MsiInstaller", 11707 | 11724) => {
            // "Product: Contoso Notes -- Installation completed successfully."
            let text = r.get("", 0);
            let product = text
                .split_once("Product:")
                .map(|(_, rest)| rest.split(" -- ").next().unwrap_or(rest).trim())
                .unwrap_or("");
            event.category = "install";
            event.kind = if r.event_id == 11707 { "installed" } else { "removed" };
            event.severity = "info";
            event.subject = product.to_string();
        }
        _ => return None,
    }
    Some(event)
}

/// A Diagnostics-Performance boot record (event 100).
pub fn boot_from_xml(xml: &str) -> Option<Boot> {
    let record = Record::parse(xml)?;
    if record.event_id != 100 {
        return None;
    }
    let ms = |name: &str| record.get(name, usize::MAX).trim().parse::<u64>().unwrap_or(0);
    let boot_ms = ms("BootTime");
    (boot_ms > 0).then(|| Boot {
        time_ms: record.time_ms,
        time: local_time(record.time_ms),
        boot_ms,
        main_path_ms: ms("MainPathBootTime"),
        post_boot_ms: ms("BootPostBootTime"),
    })
}

// ------------------------------------------------------------------------------ summary

/// Sorts, drops the records that repeat another record of the same incident, groups the programs,
/// counts the categories and draws the hints.
pub fn summarize(mut events: Vec<ReliabilityEvent>, days: u32, since_ms: i64, read_ms: i64) -> Reliability {
    events.retain(|e| e.time_ms >= since_ms);
    events.sort_by(|a, b| b.time_ms.cmp(&a.time_ms).then(b.record_id.cmp(&a.record_id)));
    let events = drop_repeats(events);
    let mut counts: BTreeMap<&'static str, usize> = CATEGORIES.iter().map(|c| (*c, 0)).collect();
    for event in &events {
        *counts.entry(event.category).or_default() += 1;
    }
    let crashing_apps = group_apps(&events, "app_crash");
    let hanging_apps = group_apps(&events, "app_hang");
    let hints = hints(&events, &crashing_apps);
    Reliability {
        days,
        since_ms,
        read_ms,
        events,
        counts,
        crashing_apps,
        hanging_apps,
        hints,
        ..Reliability::default()
    }
}

/// One incident is often logged twice: a blue screen by BugCheck 1001 and by Kernel-Power 41, an
/// unexpected shutdown by Kernel-Power 41 and by EventLog 6008, an MSI install by 1033 and 11707.
/// The more detailed record stays.
fn drop_repeats(events: Vec<ReliabilityEvent>) -> Vec<ReliabilityEvent> {
    let near = |a: &ReliabilityEvent, b: &ReliabilityEvent, window: i64| (a.time_ms - b.time_ms).abs() <= window;
    let keep: Vec<bool> = events
        .iter()
        .map(|event| match (event.category, event.kind) {
            ("bluescreen", "kernel_power") => !events
                .iter()
                .any(|o| o.kind == "bugcheck" && near(o, event, SAME_INCIDENT_MS)),
            ("shutdown", "unexpected") => !events.iter().any(|o| {
                (o.category == "bluescreen" || (o.category == "shutdown" && o.kind != "unexpected"))
                    && near(o, event, SAME_INCIDENT_MS)
            }),
            ("install", _) if matches!(event.event_id, 11707 | 11724) => !events.iter().any(|o| {
                matches!(o.event_id, 1033 | 1034)
                    && o.kind
                        .starts_with(if event.kind == "installed" { "install" } else { "remove" })
                    && near(o, event, 120_000)
                    && (event.subject.is_empty() || o.subject.eq_ignore_ascii_case(&event.subject))
            }),
            _ => true,
        })
        .collect();
    events
        .into_iter()
        .zip(keep)
        .filter_map(|(event, keep)| keep.then_some(event))
        .collect()
}

fn group_apps(events: &[ReliabilityEvent], category: &str) -> Vec<AppGroup> {
    let mut groups: Vec<AppGroup> = Vec::new();
    let mut modules: Vec<HashMap<String, (String, usize)>> = Vec::new();
    // `events` is newest first, so the first event of a group is its latest.
    for event in events.iter().filter(|e| e.category == category) {
        let key = event.subject.to_lowercase();
        let index = match groups.iter().position(|g| g.key == key) {
            Some(index) => index,
            None => {
                groups.push(AppGroup {
                    key: key.clone(),
                    name: event.subject.clone(),
                    last_ms: event.time_ms,
                    ..AppGroup::default()
                });
                modules.push(HashMap::new());
                groups.len() - 1
            }
        };
        let group = &mut groups[index];
        group.count += 1;
        group.first_ms = event.time_ms;
        if group.path.is_empty() {
            group.path = event.path.clone();
        }
        if !event.version.is_empty() && !group.versions.contains(&event.version) && group.versions.len() < 5 {
            group.versions.push(event.version.clone());
        }
        group.events.push(event.id.clone());
        if !event.module.is_empty() {
            let entry = modules[index]
                .entry(event.module.to_lowercase())
                .or_insert_with(|| (event.module.clone(), 0));
            entry.1 += 1;
        }
    }
    for (group, found) in groups.iter_mut().zip(&modules) {
        if let Some((name, count)) = found
            .values()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.to_lowercase().cmp(&a.0.to_lowercase())))
        {
            group.top_module = name.clone();
            group.top_module_count = *count;
        }
    }
    groups.sort_by(|a, b| b.count.cmp(&a.count).then(b.last_ms.cmp(&a.last_ms)));
    groups
}

fn hint(code: &'static str, severity: &'static str, subject: &str, events: &[&ReliabilityEvent]) -> Hint {
    Hint {
        code,
        severity,
        subject: subject.to_string(),
        count: events.len(),
        detail: String::new(),
        events: events.iter().take(50).map(|e| e.id.clone()).collect(),
        ..Hint::default()
    }
}

/// Plain-language pointers, most useful first. They only say what the logs show; none of them is
/// a diagnosis.
pub fn hints(events: &[ReliabilityEvent], crashing_apps: &[AppGroup]) -> Vec<Hint> {
    let mut out = Vec::new();
    let of = |category: &'static str| events.iter().filter(move |e| e.category == category);
    let family = |e: &ReliabilityEvent| {
        parse_code(&e.code, false)
            .map(stop_code)
            .map_or("", |(_, family)| family)
    };
    let stops: Vec<&ReliabilityEvent> = of("bluescreen").collect();

    // Hardware: machine-check and other WHEA errors, or the stop code they cause.
    let fatal: Vec<&ReliabilityEvent> = of("hardware").filter(|e| e.kind == "fatal").collect();
    let corrected: Vec<&ReliabilityEvent> = of("hardware").filter(|e| e.kind == "corrected").collect();
    let whea_stops: Vec<&ReliabilityEvent> = stops.iter().copied().filter(|e| family(e) == "hardware").collect();
    if !fatal.is_empty() || !whea_stops.is_empty() || corrected.len() >= 3 {
        let all: Vec<&ReliabilityEvent> = events
            .iter()
            .filter(|e| e.category == "hardware" || (e.category == "bluescreen" && family(e) == "hardware"))
            .collect();
        let severity = if fatal.is_empty() && whea_stops.is_empty() {
            "info"
        } else {
            "warn"
        };
        out.push(hint("hardware_errors", severity, "", &all));
    }

    // Graphics driver: display stop codes, or programs crashing inside the driver's modules.
    let graphics: Vec<&ReliabilityEvent> = events
        .iter()
        .filter(|e| {
            (e.category == "bluescreen" && family(e) == "graphics")
                || (e.category == "app_crash" && is_gpu_module(&e.module))
        })
        .collect();
    if let Some(first) = graphics.first() {
        let subject = if first.category == "bluescreen" {
            &first.subject
        } else {
            &first.module
        };
        out.push(hint("graphics_driver", "warn", subject, &graphics));
    }

    // Memory: stop codes that faulty memory (or a driver corrupting it) causes.
    let memory: Vec<&ReliabilityEvent> = stops.iter().copied().filter(|e| family(e) == "memory").collect();
    if let Some(first) = memory.first() {
        out.push(hint("memory_stop_codes", "warn", &first.subject, &memory));
    }

    // Disks: read and write errors, file system damage, or the stop codes they cause.
    let disk: Vec<&ReliabilityEvent> = events
        .iter()
        .filter(|e| {
            (e.category == "disk" && e.kind != "retried") || (e.category == "bluescreen" && family(e) == "storage")
        })
        .collect();
    if let Some(first) = disk.first() {
        out.push(hint("disk_errors", "warn", &first.subject, &disk));
    } else {
        let retried: Vec<&ReliabilityEvent> = of("disk").filter(|e| e.kind == "retried").collect();
        if retried.len() >= 5 {
            let subject = most_common(retried.iter().map(|e| e.subject.as_str()));
            out.push(hint("disk_retries", "info", &subject, &retried));
        }
    }

    // The same stop code again and again (families above already have their own hint).
    let mut by_code: BTreeMap<String, Vec<&ReliabilityEvent>> = BTreeMap::new();
    for stop in &stops {
        if matches!(family(stop), "" | "driver" | "system") {
            by_code.entry(stop.code.clone()).or_default().push(stop);
        }
    }
    let mut repeated: Vec<Vec<&ReliabilityEvent>> = by_code.into_values().filter(|list| list.len() >= 2).collect();
    repeated.sort_by_key(|list| std::cmp::Reverse(list.len()));
    for list in repeated.into_iter().take(2) {
        let mut found = hint("repeated_stop_code", "warn", &list[0].subject, &list);
        found.detail = list[0].code.clone();
        out.push(found);
    }

    let manual: Vec<&ReliabilityEvent> = stops.iter().copied().filter(|e| family(e) == "manual").collect();
    if !manual.is_empty() {
        out.push(hint("manual_crash", "info", &manual[0].subject, &manual));
    }

    // Shutdowns without a blue screen.
    let lost: Vec<&ReliabilityEvent> = of("shutdown").filter(|e| e.kind == "power_loss").collect();
    if !lost.is_empty() {
        out.push(hint("power_loss", "info", "", &lost));
    }
    let pressed: Vec<&ReliabilityEvent> = of("shutdown").filter(|e| e.kind == "power_button").collect();
    if !pressed.is_empty() {
        out.push(hint("power_button", "info", "", &pressed));
    }

    // A module (not the program itself, not one every crash passes through) that several programs
    // crash in.
    let mut module_apps: BTreeMap<String, (String, Vec<String>, Vec<&ReliabilityEvent>)> = BTreeMap::new();
    for crash in of("app_crash") {
        let module = crash.module.to_lowercase();
        if generic_module(&module) || is_gpu_module(&module) || module == crash.subject.to_lowercase() {
            continue;
        }
        let entry = module_apps
            .entry(module)
            .or_insert_with(|| (crash.module.clone(), Vec::new(), Vec::new()));
        let app = crash.subject.to_lowercase();
        if !entry.1.contains(&app) {
            entry.1.push(app);
        }
        entry.2.push(crash);
    }
    let mut shared: Vec<_> = module_apps
        .into_values()
        .filter(|(_, apps, _)| apps.len() >= 2)
        .collect();
    shared.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(b.2.len().cmp(&a.2.len())));
    if let Some((module, apps, list)) = shared.first() {
        let mut found = hint("shared_module", "warn", module, list);
        found.detail = apps.len().to_string();
        out.push(found);
    }

    // Programs that crash again and again.
    for group in crashing_apps.iter().filter(|g| g.count >= 3).take(2) {
        let list: Vec<&ReliabilityEvent> = of("app_crash")
            .filter(|e| e.subject.eq_ignore_ascii_case(&group.name))
            .collect();
        out.push(hint("app_repeat", "info", &group.name, &list));
    }

    // An update that keeps failing.
    let mut updates: BTreeMap<String, Vec<&ReliabilityEvent>> = BTreeMap::new();
    for failure in of("update") {
        updates.entry(failure.subject.to_lowercase()).or_default().push(failure);
    }
    let mut failing: Vec<Vec<&ReliabilityEvent>> = updates.into_values().filter(|l| l.len() >= 3).collect();
    failing.sort_by_key(|list| std::cmp::Reverse(list.len()));
    if let Some(list) = failing.first() {
        let mut found = hint("update_repeat", "info", &list[0].subject, list);
        found.detail = list[0].code.clone();
        out.push(found);
    }

    // A service that keeps crashing.
    let mut services: BTreeMap<String, Vec<&ReliabilityEvent>> = BTreeMap::new();
    for crash in of("service").filter(|e| e.kind == "crashed") {
        services.entry(crash.subject.to_lowercase()).or_default().push(crash);
    }
    let mut crashing: Vec<Vec<&ReliabilityEvent>> = services.into_values().filter(|l| l.len() >= 3).collect();
    crashing.sort_by_key(|list| std::cmp::Reverse(list.len()));
    if let Some(list) = crashing.first() {
        out.push(hint("service_repeat", "info", &list[0].subject, list));
    }
    out
}

fn most_common<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for value in values {
        *counts.entry(value).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(a.0)))
        .map(|(value, _)| value.to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = "xmlns='http://schemas.microsoft.com/win/2004/08/events/event'";

    /// A rendered event with the given System fields and EventData.
    fn xml(provider: &str, id: u32, level: u8, time: &str, record: u64, channel: &str, data: &str) -> String {
        format!(
            "<Event {NS}><System><Provider Name='{provider}' Guid='{{00000000-0000-0000-0000-000000000000}}'/>\
             <EventID Qualifiers='16384'>{id}</EventID><Version>0</Version><Level>{level}</Level><Task>0</Task>\
             <TimeCreated SystemTime='{time}'/><EventRecordID>{record}</EventRecordID><Correlation/>\
             <Execution ProcessID='4' ThreadID='8'/><Channel>{channel}</Channel><Computer>PC-VICTIM</Computer>\
             <Security/></System><EventData>{data}</EventData></Event>"
        )
    }

    fn named(pairs: &[(&str, &str)]) -> String {
        pairs
            .iter()
            .map(|(n, v)| format!("<Data Name='{n}'>{v}</Data>"))
            .collect()
    }

    fn unnamed(values: &[&str]) -> String {
        values.iter().map(|v| format!("<Data>{v}</Data>")).collect()
    }

    fn bugcheck(time: &str, record: u64, code: &str) -> String {
        xml(
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            2,
            time,
            record,
            "System",
            &named(&[
                (
                    "param1",
                    &format!("{code} (0x0000000000000003, 0xffffc40c3d5a4060, 0x0, 0x0)"),
                ),
                ("param2", r"C:\Windows\Minidump\010126-12345-01.dmp"),
                ("param3", "00000000-0000-0000-0000-000000000000"),
            ]),
        )
    }

    fn kernel_power(time: &str, record: u64, code: u32, button: &str) -> String {
        xml(
            "Microsoft-Windows-Kernel-Power",
            41,
            1,
            time,
            record,
            "System",
            &named(&[
                ("BugcheckCode", &code.to_string()),
                ("BugcheckParameter1", "0x3"),
                ("BugcheckParameter2", "0x0"),
                ("BugcheckParameter3", "0x0"),
                ("BugcheckParameter4", "0x0"),
                ("SleepInProgress", "0"),
                ("PowerButtonTimestamp", button),
                ("LongPowerButtonPressDetected", "false"),
            ]),
        )
    }

    fn app_crash(time: &str, record: u64, app: &str, module: &str, code: &str) -> String {
        xml(
            "Application Error",
            1000,
            2,
            time,
            record,
            "Application",
            &named(&[
                ("AppName", app),
                ("AppVersion", "1.2.3.4"),
                ("AppTimeStamp", "6b0208b7"),
                ("ModuleName", module),
                ("ModuleVersion", "10.0.1.0"),
                ("ModuleTimeStamp", "00000000"),
                ("ExceptionCode", code),
                ("FaultingOffset", "000000000000c628"),
                ("ProcessId", "0x1a2b"),
                ("ProcessCreationTime", "0x1dd79fcf9109503"),
                ("AppPath", &format!(r"C:\Program Files\Contoso\{app}")),
                ("ModulePath", &format!(r"C:\Program Files\Contoso\{module}")),
                ("IntegratorReportId", "00000000-0000-0000-0000-000000000000"),
                ("PackageFullName", ""),
                ("PackageRelativeAppId", ""),
            ]),
        )
    }

    fn parse(xml: &str) -> ReliabilityEvent {
        event_from_xml(xml, "").expect("an event of a kind read here")
    }

    #[test]
    fn times_parse_as_utc() {
        assert_eq!(iso_utc_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(iso_utc_ms("2026-03-01T10:11:12.1234567Z"), Some(1_772_359_872_123));
        assert_eq!(iso_utc_ms("2024-02-29T23:59:59.9Z"), Some(1_709_251_199_900));
        assert_eq!(iso_utc_ms("2026-13-01T00:00:00Z"), None);
        assert_eq!(iso_utc_ms("yesterday"), None);
    }

    #[test]
    fn stop_codes_have_names_and_families() {
        assert_eq!(stop_code(0x7E), ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "driver"));
        assert_eq!(
            stop_code(0x1000_007E),
            ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "driver")
        );
        assert_eq!(stop_code(0x116), ("VIDEO_TDR_FAILURE", "graphics"));
        assert_eq!(stop_code(0x124), ("WHEA_UNCORRECTABLE_ERROR", "hardware"));
        assert_eq!(stop_code(0x1A), ("MEMORY_MANAGEMENT", "memory"));
        assert_eq!(stop_code(0xDEAD_DEAD), ("MANUALLY_INITIATED_CRASH1", "manual"));
        assert_eq!(stop_code(0x1234), ("", ""));
        assert_eq!(exception_name(0xC000_0005), "ACCESS_VIOLATION");
        assert_eq!(exception_name(0x1234), "");
        assert_eq!(parse_code("159", true), Some(0x9F));
        assert_eq!(parse_code("0x0000009f", false), Some(0x9F));
        assert_eq!(parse_code("c0000005", false), Some(0xC000_0005));
        assert!(is_gpu_module("nvlddmkm.sys") && is_gpu_module("AMDKMDAG.SYS") && !is_gpu_module("ntdll.dll"));
    }

    #[test]
    fn blue_screens_are_read_from_bugcheck_and_kernel_power() {
        let event = parse(&bugcheck("2026-01-01T10:00:00.0000000Z", 10, "0x0000007e"));
        assert_eq!(
            (event.category, event.kind, event.severity),
            ("bluescreen", "bugcheck", "critical")
        );
        assert_eq!(event.code, "0x0000007E");
        assert_eq!(event.code_name, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED");
        assert_eq!(event.subject, event.code_name);
        assert!(event.parameters.starts_with("0x0000000000000003, "));
        assert!(event.path.ends_with(".dmp"));
        assert_eq!(event.id, "System:10");

        let crash = parse(&kernel_power("2026-01-01T09:58:00Z", 9, 0x116, "0"));
        assert_eq!((crash.category, crash.kind), ("bluescreen", "kernel_power"));
        assert_eq!(crash.code_name, "VIDEO_TDR_FAILURE");
        assert_eq!(crash.parameters, "0x3, 0x0, 0x0, 0x0");

        let cut = parse(&kernel_power("2026-01-02T08:00:00Z", 20, 0, "0"));
        assert_eq!(
            (cut.category, cut.kind, cut.severity),
            ("shutdown", "power_loss", "error")
        );
        let held = parse(&kernel_power("2026-01-02T09:00:00Z", 21, 0, "133000000000000000"));
        assert_eq!(held.kind, "power_button");
    }

    #[test]
    fn programs_services_disks_updates_and_installs() {
        let crash = parse(&app_crash(
            "2026-01-03T12:00:00Z",
            5,
            "notes.exe",
            "contoso.dll",
            "c0000005",
        ));
        assert_eq!((crash.category, crash.subject.as_str()), ("app_crash", "notes.exe"));
        assert_eq!(
            (crash.module.as_str(), crash.code.as_str()),
            ("contoso.dll", "0xC0000005")
        );
        assert_eq!(crash.code_name, "ACCESS_VIOLATION");
        assert_eq!(crash.path, r"C:\Program Files\Contoso\notes.exe");

        // Older Windows writes the same fields without names, by position.
        let old = xml(
            "Application Error",
            1000,
            2,
            "2026-01-03T12:00:00Z",
            6,
            "Application",
            &unnamed(&["notes.exe", "1.0", "0", "contoso.dll", "2.0", "0", "c0000409", "00ff"]),
        );
        let old = parse(&old);
        assert_eq!(
            (old.module.as_str(), old.code_name.as_str()),
            ("contoso.dll", "STACK_BUFFER_OVERRUN")
        );

        let hang = xml(
            "Application Hang",
            1002,
            2,
            "2026-01-03T13:00:00Z",
            7,
            "Application",
            &named(&[
                ("AppName", "notes.exe"),
                ("AppVersion", "1.0"),
                ("ExeFileName", r"C:\Program Files\Contoso\notes.exe"),
                ("HangType", "Quiesce"),
            ]),
        );
        let hang = parse(&hang);
        assert_eq!((hang.category, hang.parameters.as_str()), ("app_hang", "Quiesce"));

        let service = xml(
            "Service Control Manager",
            7031,
            2,
            "2026-01-03T14:00:00Z",
            30,
            "System",
            &named(&[
                ("param1", "Contoso Updater"),
                ("param2", "2"),
                ("param3", "60000"),
                ("param4", "1"),
                ("param5", "Restart the service"),
            ]),
        );
        let service = parse(&service);
        assert_eq!(
            (service.kind, service.subject.as_str(), service.count),
            ("crashed", "Contoso Updater", 2)
        );
        let failed = parse(&xml(
            "Service Control Manager",
            7023,
            2,
            "2026-01-03T14:00:00Z",
            31,
            "System",
            &named(&[("param1", "Contoso Sync"), ("param2", "%%1053")]),
        ));
        assert_eq!((failed.kind, failed.code.as_str()), ("stopped_with_error", "1053"));
        let timeout = parse(&xml(
            "Service Control Manager",
            7009,
            2,
            "2026-01-03T14:00:00Z",
            32,
            "System",
            &named(&[("param1", "30000"), ("param2", "Contoso Sync")]),
        ));
        assert_eq!(
            (timeout.kind, timeout.subject.as_str()),
            ("start_timeout", "Contoso Sync")
        );

        let disk = parse(&xml(
            "disk",
            153,
            3,
            "2026-01-04T00:00:00Z",
            40,
            "System",
            &unnamed(&[r"\Device\Harddisk2\DR3", "0x0", "2", r"\Device\0000054c"]),
        ));
        assert_eq!(
            (disk.category, disk.kind, disk.severity),
            ("disk", "retried", "warning")
        );
        assert_eq!(disk.subject, r"\Device\Harddisk2\DR3");

        // A healthy volume (information) is not a problem.
        let healthy = xml(
            "Microsoft-Windows-Ntfs",
            98,
            4,
            "2026-01-04T00:00:00Z",
            41,
            "System",
            &named(&[
                ("DriveName", "C:"),
                ("DeviceName", r"\Device\HarddiskVolume3"),
                ("CorruptionActionState", "0"),
            ]),
        );
        assert!(event_from_xml(&healthy, "").is_none());
        let damaged = parse(&healthy.replace("<Level>4</Level>", "<Level>3</Level>"));
        assert_eq!((damaged.kind, damaged.subject.as_str()), ("needs_repair", "C:"));

        let update = parse(&xml(
            "Microsoft-Windows-WindowsUpdateClient",
            20,
            2,
            "2026-01-05T00:00:00Z",
            50,
            "System",
            &named(&[
                ("errorCode", "0x80073d02"),
                ("updateTitle", "Contoso Notes 1.2"),
                ("updateGuid", "{0}"),
            ]),
        ));
        assert_eq!((update.category, update.code.as_str()), ("update", "0x80073D02"));
        assert_eq!(update.subject, "Contoso Notes 1.2");

        let installed = parse(&xml(
            "MsiInstaller",
            1033,
            4,
            "2026-01-06T00:00:00Z",
            60,
            "Application",
            &unnamed(&["Contoso Notes", "1.2.0", "1033", "0", "Contoso Ltd.", "(NULL)"]),
        ));
        assert_eq!((installed.kind, installed.severity), ("installed", "info"));
        assert_eq!(
            (installed.subject.as_str(), installed.publisher.as_str()),
            ("Contoso Notes", "Contoso Ltd.")
        );
        let failed_remove = parse(&xml(
            "MsiInstaller",
            1034,
            4,
            "2026-01-06T00:00:00Z",
            61,
            "Application",
            &unnamed(&["Contoso Notes", "1.2.0", "1033", "1603", "Contoso Ltd.", "(NULL)"]),
        ));
        assert_eq!(
            (failed_remove.kind, failed_remove.code.as_str()),
            ("remove_failed", "1603")
        );
        let done = parse(&xml(
            "MsiInstaller",
            11707,
            4,
            "2026-01-06T00:00:00Z",
            62,
            "Application",
            &unnamed(&[
                "Product: Contoso Notes -- Installation completed successfully.",
                "(NULL)",
            ]),
        ));
        assert_eq!((done.kind, done.subject.as_str()), ("installed", "Contoso Notes"));

        // Anything else is not read.
        assert!(event_from_xml(&xml("Contoso", 1, 2, "2026-01-01T00:00:00Z", 1, "Application", ""), "").is_none());
        assert!(event_from_xml("<Event><System></System></Event>", "").is_none());
        assert!(event_from_xml("", "").is_none());
    }

    #[test]
    fn boots_and_messages() {
        let boot = xml(
            "Microsoft-Windows-Diagnostics-Performance",
            100,
            2,
            "2026-01-07T07:00:00Z",
            70,
            "Microsoft-Windows-Diagnostics-Performance/Operational",
            &named(&[
                ("BootTime", "31500"),
                ("MainPathBootTime", "12000"),
                ("BootPostBootTime", "19500"),
            ]),
        );
        let boot = boot_from_xml(&boot).expect("a boot");
        assert_eq!(
            (boot.boot_ms, boot.main_path_ms, boot.post_boot_ms),
            (31_500, 12_000, 19_500)
        );
        assert_eq!(
            clean_message("The previous system shutdown at \u{200E}10:05 was unexpected.\r\n\r\n\r\n\r\nDone.  "),
            "The previous system shutdown at 10:05 was unexpected.\n\nDone."
        );
        assert_eq!(clean_message(&"x".repeat(3000)).chars().count(), MAX_MESSAGE + 1);
    }

    #[test]
    fn incidents_are_counted_once_and_programs_grouped() {
        let events: Vec<ReliabilityEvent> = [
            bugcheck("2026-01-01T10:02:00Z", 11, "0x0000007e"),
            kernel_power("2026-01-01T10:00:30Z", 10, 0x7E, "0"),
            xml(
                "EventLog",
                6008,
                2,
                "2026-01-01T10:00:20Z",
                9,
                "System",
                &unnamed(&["10:00", "01/01/2026"]),
            ),
            kernel_power("2026-01-05T08:00:00Z", 30, 0, "0"),
            xml(
                "EventLog",
                6008,
                2,
                "2026-01-05T08:00:05Z",
                31,
                "System",
                &unnamed(&["07:59", "05/01/2026"]),
            ),
            xml(
                "EventLog",
                6008,
                2,
                "2026-01-08T08:00:05Z",
                40,
                "System",
                &unnamed(&["07:59", "08/01/2026"]),
            ),
            app_crash("2026-01-02T10:00:00Z", 1, "notes.exe", "contoso.dll", "c0000005"),
            app_crash("2026-01-03T10:00:00Z", 2, "Notes.exe", "contoso.dll", "c0000005"),
            app_crash("2026-01-04T10:00:00Z", 3, "notes.exe", "ntdll.dll", "c0000374"),
            app_crash("2026-01-04T11:00:00Z", 4, "paint.exe", "contoso.dll", "c0000005"),
        ]
        .iter()
        .map(|x| parse(x))
        .collect();
        let since = iso_utc_ms("2025-12-31T00:00:00Z").unwrap_or(0);
        let summary = summarize(events, 30, since, since + 30 * DAY_MS);
        // The blue screen once (BugCheck kept), the power loss once (Kernel-Power kept), and the
        // lone 6008 on its own.
        assert_eq!(summary.counts["bluescreen"], 1);
        assert_eq!(
            summary
                .events
                .iter()
                .find(|e| e.category == "bluescreen")
                .map(|e| e.kind),
            Some("bugcheck")
        );
        assert_eq!(summary.counts["shutdown"], 2);
        assert_eq!(summary.counts["app_crash"], 4);
        assert_eq!(summary.counts.len(), CATEGORIES.len());
        assert!(summary.events.windows(2).all(|w| w[0].time_ms >= w[1].time_ms));

        let notes = &summary.crashing_apps[0];
        assert_eq!((notes.key.as_str(), notes.count), ("notes.exe", 3));
        assert_eq!((notes.top_module.as_str(), notes.top_module_count), ("contoso.dll", 2));
        assert_eq!(notes.name, "notes.exe", "the newest spelling names the group");
        assert_eq!(notes.events.first().map(String::as_str), Some("Application:3"));
        assert!(notes.last_ms > notes.first_ms);

        let codes: Vec<&str> = summary.hints.iter().map(|h| h.code).collect();
        assert!(codes.contains(&"shared_module"), "{codes:?}");
        assert!(codes.contains(&"app_repeat"), "{codes:?}");
        assert!(codes.contains(&"power_loss"), "{codes:?}");
        let shared = summary.hints.iter().find(|h| h.code == "shared_module");
        assert_eq!(
            shared.map(|h| (h.subject.as_str(), h.detail.as_str())),
            Some(("contoso.dll", "2"))
        );

        // Events before the window are left out.
        let late = summarize(
            summary.events.clone(),
            1,
            iso_utc_ms("2026-01-08T00:00:00Z").unwrap_or(0),
            0,
        );
        assert_eq!(late.events.len(), 1);
    }

    #[test]
    fn hints_point_to_hardware_graphics_memory_and_disks() {
        let whea = |record: u64, level: u8| {
            xml(
                "Microsoft-Windows-WHEA-Logger",
                17,
                level,
                "2026-01-02T00:00:00Z",
                record,
                "System",
                &named(&[("ErrorSource", "4")]),
            )
        };
        let events: Vec<ReliabilityEvent> = [
            whea(1, 3),
            whea(2, 3),
            app_crash("2026-01-03T00:00:00Z", 3, "game.exe", "nvwgf2umx.dll", "c0000005"),
            bugcheck("2026-01-04T00:00:00Z", 4, "0x0000001a"),
            xml(
                "disk",
                7,
                2,
                "2026-01-05T00:00:00Z",
                5,
                "System",
                &unnamed(&[r"\Device\Harddisk1\DR1"]),
            ),
            bugcheck("2026-01-06T00:00:00Z", 6, "0x000000d1"),
            bugcheck("2026-01-07T00:00:00Z", 7, "0x000000d1"),
            bugcheck("2026-01-08T00:00:00Z", 8, "0x000000e2"),
        ]
        .iter()
        .map(|x| parse(x))
        .collect();
        let summary = summarize(events, 30, 0, 0);
        let find = |code: &str| summary.hints.iter().find(|h| h.code == code).cloned();
        // Two corrected errors are not enough to point at the hardware; a third would be.
        assert!(find("hardware_errors").is_none());
        let graphics = find("graphics_driver").expect("graphics");
        assert_eq!((graphics.subject.as_str(), graphics.count), ("nvwgf2umx.dll", 1));
        assert_eq!(
            find("memory_stop_codes").map(|h| h.subject),
            Some("MEMORY_MANAGEMENT".into())
        );
        assert_eq!(
            find("disk_errors").map(|h| h.subject),
            Some(r"\Device\Harddisk1\DR1".into())
        );
        let repeated = find("repeated_stop_code").expect("repeated");
        assert_eq!(
            (repeated.subject.as_str(), repeated.count, repeated.detail.as_str()),
            ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", 2, "0x000000D1")
        );
        assert_eq!(find("manual_crash").map(|h| h.severity), Some("info"));

        let fatal = summarize(vec![parse(&whea(9, 2))], 30, 0, 0);
        assert_eq!(
            fatal.hints.first().map(|h| (h.code, h.severity)),
            Some(("hardware_errors", "warn"))
        );
        let quiet = summarize(Vec::new(), 30, 0, 0);
        assert!(quiet.hints.is_empty() && quiet.crashing_apps.is_empty());
    }

    /// Reads the live logs (read-only) and prints counts only. Run by hand:
    /// `cargo test -p vigil-sys reliability::tests::live -- --ignored --nocapture`
    #[test]
    #[ignore = "reads this computer's event logs"]
    fn live() {
        let started = std::time::Instant::now();
        let result = read(30, Duration::from_secs(60)).expect("the event logs answer");
        let counts: Vec<String> = result.counts.iter().map(|(k, v)| format!("{k}={v}")).collect();
        println!(
            "{} events in {:?}: {}; {} crashing apps, {} hanging apps, {} boots, {} hints {:?}; unread {:?}; truncated {}",
            result.events.len(),
            started.elapsed(),
            counts.join(" "),
            result.crashing_apps.len(),
            result.hanging_apps.len(),
            result.boots.len(),
            result.hints.len(),
            result.hints.iter().map(|h| h.code).collect::<Vec<_>>(),
            result.unread_logs.len(),
            result.truncated
        );
        let with_message = result.events.iter().filter(|e| !e.message.is_empty()).count();
        println!("{with_message} events with a message");
    }
}
