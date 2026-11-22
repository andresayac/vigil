//! Inventory collection. Everything here is READ-ONLY: nothing in this module changes the system.
//!
//! The PowerShell collectors are embedded in the binary and handed to PowerShell through its
//! standard input, their results read back from its standard output: nothing they run or produce
//! ever sits in a folder the user can write (the scan usually runs elevated). The rest (startup
//! entries, programs, browser extensions, configuration) is read directly from the registry and
//! the file system.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use chrono::Local;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::lenient::{Get, as_integral, eq_num, last, list, lower, round_to, rx, skip, strip, take, truthy};
use crate::ntpath::{WINDIR, basename, dirname, isabs, join};
use crate::winreg::{self, Hive, RegData, View};
use vigil_i18n::{tl, tr};

// --------------------------------------------------------------------------- earlier collectors' folder

/// Where earlier versions ran the collectors from (`%TEMP%\vigil-scan`). Nothing is written there
/// any more; events.ps1 still uses it to leave out those versions' own PowerShell activity, which
/// the event logs keep for weeks.
pub(crate) fn scan_root() -> PathBuf {
    std::env::temp_dir().join("vigil-scan")
}

// --------------------------------------------------------------------------- PowerShell collectors

const SCRIPTS: &[(&str, &str)] = &[
    ("_common", include_str!("../ps/_common.ps1")),
    ("events", include_str!("../ps/events.ps1")),
    ("network", include_str!("../ps/network.ps1")),
    ("processes", include_str!("../ps/processes.ps1")),
    ("services", include_str!("../ps/services.ps1")),
    ("signatures", include_str!("../ps/signatures.ps1")),
    ("system", include_str!("../ps/system.ps1")),
    ("tasks", include_str!("../ps/tasks.ps1")),
];

/// The line each collector uses to load the shared helpers; replaced by the helpers themselves.
const INCLUDE_LINE: &str = ". \"$PSScriptRoot\\_common.ps1\"";
/// Separates the script from its input on PowerShell's standard input.
const INPUT_SEPARATOR: &str = "<#VIGIL-INPUT#>";
/// The marker in front of a collector's result on its standard output.
const RESULT_MARKER: &[u8] = b"VIGIL-JSON:";

/// A mark on the collectors' own command line and scripts (`VigilCollector-<hash of the
/// scripts>`): events.ps1 leaves PowerShell activity that carries it out of the findings.
pub(crate) fn self_mark() -> String {
    static MARK: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    MARK.get_or_init(|| {
        let mut digest = Sha256::new();
        for (name, body) in SCRIPTS {
            digest.update(name.as_bytes());
            digest.update(body.as_bytes());
        }
        let tag: String = digest.finalize().iter().take(6).map(|b| format!("{b:02x}")).collect();
        format!("VigilCollector-{tag}")
    })
    .clone()
}

/// The text of one collector with the shared helpers in place of its include line.
fn collector_text(script: &str) -> Result<String, String> {
    let body = SCRIPTS
        .iter()
        .find(|(name, _)| *name == script)
        .map(|(_, body)| *body)
        .ok_or_else(|| tr!("could not prepare the collectors: {0}", script))?;
    let common = SCRIPTS
        .iter()
        .find(|(name, _)| *name == "_common")
        .map(|(_, body)| *body)
        .unwrap_or_default();
    if !body.contains(INCLUDE_LINE) {
        return Err(tr!("could not prepare the collectors: {0}", script));
    }
    Ok(format!("# {}\n{}", self_mark(), body.replacen(INCLUDE_LINE, common, 1)))
}

/// The `-Command` that runs a collector from standard input: the script (ASCII), then optionally
/// its input lines (base64 of UTF-8, so no code page can alter a path). Named values arrive as
/// `PC_ARG_<name>` environment variables and become the script's parameters. Single quotes only:
/// the text travels as one command-line argument.
fn bootstrap() -> String {
    format!(
        "$VigilMark='{mark}';$t=[Console]::In.ReadToEnd();$k=$t.IndexOf('{sep}');$global:VigilInput=@();\
         if($k -ge 0){{$b=$t.Substring($k+{len}).Trim();if($b){{$global:VigilInput=@([Text.Encoding]::UTF8.\
         GetString([Convert]::FromBase64String($b)).Split([char]10)|Where-Object {{$_}})}};$t=$t.Substring(0,$k)}};\
         $a=@{{}};Get-ChildItem Env:PC_ARG_* | ForEach-Object {{$a[$_.Name.Substring(7)]=$_.Value}};\
         $null=& ([scriptblock]::Create($t)) @a",
        mark = self_mark(),
        sep = INPUT_SEPARATOR,
        len = INPUT_SEPARATOR.len(),
    )
}

/// The JSON after the last result marker on a collector's standard output.
fn result_json(stdout: &[u8]) -> Option<&[u8]> {
    let start = stdout.windows(RESULT_MARKER.len()).rposition(|w| w == RESULT_MARKER)? + RESULT_MARKER.len();
    let rest = &stdout[start..];
    let end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
    let json = &rest[..end];
    Some(json.strip_suffix(b"\r").unwrap_or(json))
}

/// Absolute path of Windows PowerShell (never resolved through PATH or the current directory).
pub(crate) fn powershell_path() -> PathBuf {
    // A 32-bit process on 64-bit Windows would see the 32-bit PowerShell and a redirected System32.
    let sysnative = Path::new(&*WINDIR).join("Sysnative");
    let native = if cfg!(target_pointer_width = "32") && sysnative.is_dir() {
        "Sysnative"
    } else {
        "System32"
    };
    Path::new(&*WINDIR)
        .join(native)
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub(crate) fn hide_window(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = (command, CREATE_NO_WINDOW);
}

/// Output of a finished child process.
pub(crate) struct Finished {
    pub(crate) code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

/// Why a child process did not finish.
pub(crate) enum ChildError {
    Spawn(std::io::Error),
    Timeout,
    Cancelled,
}

/// How long the pipe readers may take to finish once the child has exited or been killed. A
/// grandchild that kept the pipes open (and escaped the job) cannot hold the caller forever.
const READER_GRACE: Duration = Duration::from_secs(10);

/// A Windows job object holding a child and everything it starts. Ending it (or dropping it, as
/// the job kills its processes when its last handle closes) ends the whole tree: a `.cmd` shim
/// that starts `node`, which starts the real agent, is stopped as one.
struct ProcessTree {
    #[cfg(windows)]
    job: Option<windows::Win32::Foundation::HANDLE>,
}

impl ProcessTree {
    #[cfg(windows)]
    fn adopt(child: &std::process::Child) -> Self {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
        };
        // SAFETY: an unnamed job with default security; the handle is owned by the returned value.
        let Ok(job) = (unsafe { CreateJobObjectW(None, None) }) else {
            return Self { job: None };
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` is a valid JOBOBJECT_EXTENDED_LIMIT_INFORMATION of the size passed.
        let set = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        // SAFETY: the child's process handle stays valid while `child` is alive (it is borrowed).
        let assigned = set.is_ok() && unsafe { AssignProcessToJobObject(job, HANDLE(child.as_raw_handle())) }.is_ok();
        if !assigned {
            // SAFETY: `job` came from CreateJobObjectW above and is closed once.
            unsafe {
                let _ = CloseHandle(job);
            }
            return Self { job: None };
        }
        Self { job: Some(job) }
    }

    #[cfg(not(windows))]
    fn adopt(_: &std::process::Child) -> Self {
        Self {}
    }

    /// Ends every process in the tree.
    fn kill(&self) {
        #[cfg(windows)]
        if let Some(job) = self.job {
            // SAFETY: `job` is the open job handle this value owns.
            unsafe {
                let _ = windows::Win32::System::JobObjects::TerminateJobObject(job, 1);
            }
        }
    }
}

impl Drop for ProcessTree {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(job) = self.job.take() {
            // SAFETY: closes the job handle this value owns, once; KILL_ON_JOB_CLOSE ends any process
            // of the tree that is still running.
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(job);
            }
        }
    }
}

/// Runs a command with an optional stdin text, a timeout and cancellation. The child and every
/// process it starts run in one job: on timeout or cancellation the whole tree is ended, and once
/// the child exits anything it left running is ended too. Reading its output never waits more
/// than [`READER_GRACE`] after that.
pub(crate) fn run_child(
    mut command: Command,
    input: Option<&str>,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<Finished, ChildError> {
    command
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    hide_window(&mut command);
    let mut child = command.spawn().map_err(ChildError::Spawn)?;
    let tree = ProcessTree::adopt(&child);
    let writer = input.zip(child.stdin.take()).map(|(text, mut stdin)| {
        let text = text.to_string();
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = stdin.write_all(text.as_bytes());
        })
    });
    let read_all = |pipe: Option<Box<dyn Read + Send>>| {
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let mut out = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut out);
            }
            let _ = send.send(out);
        });
        receive
    };
    let stdout = read_all(child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
    let stderr = read_all(child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {}
            Err(error) => break Err(ChildError::Spawn(error)),
        }
        if cancel.load(Ordering::Relaxed) {
            break Err(ChildError::Cancelled);
        }
        if Instant::now() >= deadline {
            break Err(ChildError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if status.is_err() {
        tree.kill();
        let _ = child.kill();
        let _ = child.wait();
    }
    // Whatever the child left running (it exited, or was ended above) goes with the job, so the
    // pipes close and the readers finish.
    tree.kill();
    drop(tree);
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let stdout = stdout.recv_timeout(READER_GRACE).unwrap_or_default();
    let stderr = stderr.recv_timeout(READER_GRACE).unwrap_or_default();
    let status = status?;
    Ok(Finished {
        code: status.code(),
        stdout,
        stderr,
    })
}

/// Text of a UTF-8 file without its byte-order mark.
pub(crate) fn read_text(path: &Path) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// Runs one collector and returns the JSON it prints. The script and its input go through
/// PowerShell's standard input and the result comes back on its standard output, so nothing is
/// written to a folder: an elevated scan runs exactly the script built into Vigil, and its result
/// cannot be swapped on the way. `params` become the script's named parameters (through
/// environment variables, never inside the script text).
fn run_collector(
    script: &str,
    params: &[(&str, String)],
    input: Option<&str>,
    timeout: u64,
    cancel: &AtomicBool,
) -> Result<Value, String> {
    use base64::Engine;
    let mut payload = collector_text(script)?;
    if let Some(input) = input {
        payload.push('\n');
        payload.push_str(INPUT_SEPARATOR);
        payload.push('\n');
        payload.push_str(&base64::engine::general_purpose::STANDARD.encode(input.as_bytes()));
        payload.push('\n');
    }
    let mut command = Command::new(powershell_path());
    // -ExecutionPolicy only affects this child process: without it, the "Restricted" policy
    // prevents loading the Windows modules the collectors use.
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
        ])
        .arg(bootstrap());
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().to_uppercase().starts_with("PC_ARG_") {
            command.env_remove(name);
        }
    }
    for (name, value) in params {
        command.env(format!("PC_ARG_{name}"), value);
    }
    // Windows' own module folder and folders: a module in the user's Documents could otherwise
    // replace the cmdlets the collectors call.
    #[cfg(windows)]
    for (name, value) in vigil_sys::paths::powershell_env() {
        command.env(name, value);
    }
    let finished = match run_child(command, Some(&payload), Duration::from_secs(timeout), cancel) {
        Ok(finished) => finished,
        Err(ChildError::Timeout) => return Err(tr!("{0}: timed out after {1}s", script, timeout)),
        Err(ChildError::Cancelled) => return Err(format!("{script}: cancelled")),
        Err(ChildError::Spawn(error)) => return Err(tr!("{0}: could not run PowerShell ({1})", script, error)),
    };
    let Some(json) = result_json(&finished.stdout) else {
        let detail = if finished.stderr.is_empty() {
            &finished.stdout
        } else {
            &finished.stderr
        };
        let detail = String::from_utf8_lossy(detail);
        let code = finished.code.map_or_else(|| "None".to_string(), |c| c.to_string());
        return Err(tr!(
            "{0}: no output (exit code {1}). {2}",
            script,
            code,
            last(strip(&detail), 600)
        ));
    };
    let text = String::from_utf8_lossy(json);
    serde_json::from_str(&text).map_err(|e| tr!("{0}: invalid JSON ({1})", script, e))
}

// --------------------------------------------------------------------------- startup entries (registry)

const RUN_KEYS: &[(Hive, &str, View, Option<&str>)] = &[
    (
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        View::V64,
        Some("Run"),
    ),
    (
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        View::V32,
        Some("Run32"),
    ),
    (
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        View::V64,
        None,
    ),
    (
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        View::V32,
        None,
    ),
    (
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        View::V64,
        None,
    ),
    (
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        View::V32,
        None,
    ),
    (
        Hive::Hkcu,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        View::V64,
        Some("Run"),
    ),
    (
        Hive::Hkcu,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        View::V64,
        None,
    ),
    (
        Hive::Hkcu,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        View::V64,
        None,
    ),
    (
        Hive::Hkcu,
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        View::V64,
        Some("Run32"),
    ),
];
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
const NT_WINDOWS: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
const IFEO: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const SILENT_EXIT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
const ACTIVE_SETUP: &str = r"SOFTWARE\Microsoft\Active Setup\Installed Components";

fn entry(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn text_of(data: Option<&RegData>) -> String {
    data.map(RegData::as_text).unwrap_or_default()
}

/// Enabled/disabled state set from Task Manager (Startup apps tab).
fn approved_state(hive: Hive, kind: &str) -> Vec<(String, bool)> {
    winreg::values(hive, &format!("{APPROVED}\\{kind}"), View::V64)
        .into_iter()
        .filter_map(|(name, data)| match data {
            // 02/06 = enabled, 03/07 = disabled
            RegData::Bytes(bytes) if !bytes.is_empty() => Some((lower(&name), bytes[0] % 2 == 0)),
            _ => None,
        })
        .collect()
}

fn lookup(state: &[(String, bool)], name: &str) -> bool {
    state
        .iter()
        .rev()
        .find(|(n, _)| n == name)
        .is_none_or(|(_, enabled)| *enabled)
}

pub(crate) fn startup_folders() -> Vec<String> {
    // From Windows, not the environment: a redirected `%ProgramData%` would hide the computer's
    // Startup folder from an elevated scan.
    let mut folders = Vec::new();
    let bases = [
        vigil_sys::paths::roaming_app_data(),
        Some(vigil_sys::paths::program_data()),
    ];
    for base in bases.into_iter().flatten() {
        folders.push(join(
            &base.to_string_lossy(),
            &[r"Microsoft\Windows\Start Menu\Programs\Startup"],
        ));
    }
    folders
}

pub(crate) fn list_startup_files() -> Vec<String> {
    let mut files = Vec::new();
    for folder in startup_folders() {
        let Ok(entries) = fs::read_dir(&folder) else { continue };
        for item in entries.flatten() {
            let name = item.file_name().to_string_lossy().into_owned();
            let full = join(&folder, &[&name]);
            if Path::new(&full).is_file() && lower(&name) != "desktop.ini" {
                files.push(full);
            }
        }
    }
    files
}

fn list_values(data: Option<RegData>) -> Vec<RegData> {
    match data {
        Some(RegData::Multi(items)) => items.into_iter().map(RegData::Str).collect(),
        Some(other) if other.truthy() => vec![other],
        _ => Vec::new(),
    }
}

pub(crate) fn collect_autoruns() -> Vec<Value> {
    let mut entries = Vec::new();

    for &(hive, key, view, approved_kind) in RUN_KEYS {
        let approved = approved_kind.map(|kind| approved_state(hive, kind)).unwrap_or_default();
        let location = winreg::display(hive, key, view);
        for (name, data) in winreg::values(hive, key, view) {
            let command = strip(&data.as_text()).to_string();
            if command.is_empty() {
                continue;
            }
            let enabled = lookup(&approved, &lower(&name));
            entries.push(entry(vec![
                ("source", json!("run")),
                ("location", json!(location)),
                ("name", json!(name)),
                ("command", json!(command)),
                ("enabled", json!(enabled)),
            ]));
        }
    }

    // Winlogon: Shell and Userinit decide what starts at logon.
    for hive in [Hive::Hklm, Hive::Hkcu] {
        let values = winreg::values(hive, WINLOGON, View::V64);
        for name in ["Shell", "Userinit", "Taskman", "AppSetup", "VmApplet"] {
            let command = strip(&text_of(winreg::get(&values, name))).to_string();
            if !command.is_empty() {
                entries.push(entry(vec![
                    ("source", json!("winlogon")),
                    ("location", json!(format!("{}\\{WINLOGON}", hive.short()))),
                    ("name", json!(name)),
                    ("command", json!(command)),
                    ("enabled", json!(true)),
                ]));
            }
        }
    }

    for view in [View::V64, View::V32] {
        let values = winreg::values(Hive::Hklm, NT_WINDOWS, view);
        let dlls = strip(&text_of(winreg::get(&values, "AppInit_DLLs"))).to_string();
        if !dlls.is_empty() {
            entries.push(entry(vec![
                ("source", json!("appinit_dlls")),
                ("location", json!(winreg::display(Hive::Hklm, NT_WINDOWS, view))),
                ("name", json!("AppInit_DLLs")),
                ("command", json!(dlls)),
                (
                    "enabled",
                    json!(winreg::get(&values, "LoadAppInit_DLLs").is_some_and(RegData::truthy)),
                ),
            ]));
        }
    }

    let legacy = winreg::values(
        Hive::Hkcu,
        r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
        View::V64,
    );
    for name in ["Load", "Run"] {
        let command = strip(&text_of(winreg::get(&legacy, name))).to_string();
        if !command.is_empty() {
            entries.push(entry(vec![
                ("source", json!("legacy_load")),
                ("name", json!(name)),
                ("command", json!(command)),
                ("enabled", json!(true)),
                (
                    "location",
                    json!(r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows"),
                ),
            ]));
        }
    }

    let script = strip(&text_of(
        winreg::value(Hive::Hkcu, "Environment", "UserInitMprLogonScript", View::V64).as_ref(),
    ))
    .to_string();
    if !script.is_empty() {
        entries.push(entry(vec![
            ("source", json!("logon_script")),
            ("location", json!(r"HKCU\Environment")),
            ("name", json!("UserInitMprLogonScript")),
            ("command", json!(script)),
            ("enabled", json!(true)),
        ]));
    }

    // Debuggers hooked onto programs: they run instead of the original program.
    for view in [View::V64, View::V32] {
        for sub in winreg::subkeys(Hive::Hklm, IFEO, view) {
            let key = format!("{IFEO}\\{sub}");
            let debugger = strip(&text_of(winreg::value(Hive::Hklm, &key, "Debugger", view).as_ref())).to_string();
            if !debugger.is_empty() {
                entries.push(entry(vec![
                    ("source", json!("ifeo_debugger")),
                    ("location", json!(winreg::display(Hive::Hklm, &key, view))),
                    ("name", json!(sub)),
                    ("command", json!(debugger)),
                    ("enabled", json!(true)),
                ]));
            }
        }
    }
    for sub in winreg::subkeys(Hive::Hklm, SILENT_EXIT, View::V64) {
        let key = format!("{SILENT_EXIT}\\{sub}");
        let monitor = strip(&text_of(
            winreg::value(Hive::Hklm, &key, "MonitorProcess", View::V64).as_ref(),
        ))
        .to_string();
        if !monitor.is_empty() {
            entries.push(entry(vec![
                ("source", json!("ifeo_debugger")),
                ("location", json!(format!("HKLM\\{key}"))),
                ("name", json!(sub)),
                ("command", json!(monitor)),
                ("enabled", json!(true)),
            ]));
        }
    }

    let session = r"SYSTEM\CurrentControlSet\Control\Session Manager";
    for name in crate::hooks::BOOT_VALUES {
        for line in list_values(winreg::value(Hive::Hklm, session, name, View::V64)) {
            let line = strip(&line.as_text()).to_string();
            if !line.is_empty() {
                entries.push(entry(vec![
                    ("source", json!("boot_execute")),
                    ("location", json!(format!("HKLM\\{session}"))),
                    ("name", json!(name)),
                    ("command", json!(line)),
                    ("enabled", json!(true)),
                ]));
            }
        }
    }
    for (name, data) in winreg::values(Hive::Hklm, &format!("{session}\\AppCertDlls"), View::V64) {
        entries.push(entry(vec![
            ("source", json!("appcert_dlls")),
            ("location", json!(format!("HKLM\\{session}\\AppCertDlls"))),
            ("name", json!(name)),
            ("command", json!(data.as_text())),
            ("enabled", json!(true)),
        ]));
    }

    let lsa = r"SYSTEM\CurrentControlSet\Control\Lsa";
    let lsa_values = winreg::values(Hive::Hklm, lsa, View::V64);
    for name in ["Authentication Packages", "Notification Packages", "Security Packages"] {
        for package in list_values(winreg::get(&lsa_values, name).cloned()) {
            let package = strip(&package.as_text()).trim_matches('"').to_string();
            if !package.is_empty() {
                entries.push(entry(vec![
                    ("source", json!("lsa_package")),
                    ("location", json!(format!("HKLM\\{lsa}"))),
                    ("name", json!(name)),
                    ("command", json!(package)),
                    ("enabled", json!(true)),
                ]));
            }
        }
    }

    for view in [View::V64, View::V32] {
        for sub in winreg::subkeys(Hive::Hklm, ACTIVE_SETUP, view) {
            let key = format!("{ACTIVE_SETUP}\\{sub}");
            let values = winreg::values(Hive::Hklm, &key, view);
            let stub = strip(&text_of(winreg::get(&values, "StubPath"))).to_string();
            if !stub.is_empty() {
                let default = text_of(winreg::get(&values, ""));
                let installed = winreg::get(&values, "IsInstalled").is_none_or(|d| !d.eq_int(0));
                entries.push(entry(vec![
                    ("source", json!("active_setup")),
                    ("name", json!(if default.is_empty() { sub.clone() } else { default })),
                    ("location", json!(winreg::display(Hive::Hklm, &key, view))),
                    ("command", json!(stub)),
                    ("enabled", json!(installed)),
                ]));
            }
        }
    }

    let mut approved_folder = approved_state(Hive::Hklm, "StartupFolder");
    approved_folder.extend(approved_state(Hive::Hkcu, "StartupFolder"));
    for full in list_startup_files() {
        let name = basename(&full).to_string();
        let enabled = lookup(&approved_folder, &lower(&name));
        entries.push(entry(vec![
            ("source", json!("startup_folder")),
            ("location", json!(dirname(&full))),
            ("name", json!(name)),
            ("command", json!(format!("\"{full}\""))),
            ("file", json!(full)),
            ("enabled", json!(enabled)),
        ]));
    }
    entries.extend(crate::hooks::collect_autoruns());
    entries.extend(crate::persist::collect_autoruns());
    entries.extend(crate::amsi::collect_autoruns());
    entries.extend(crate::com::collect().0);
    entries.extend(crate::shellext::collect().0);
    entries
}

// --------------------------------------------------------------------------- installed programs

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
rx!(EIGHT_DIGITS, r"^\d{8}$");

pub(crate) fn collect_programs() -> Vec<Value> {
    let mut programs: Vec<((String, String), Value)> = Vec::new();
    for (hive, view, label) in [
        (Hive::Hklm, View::V64, "machine"),
        (Hive::Hklm, View::V32, "machine (32-bit)"),
        (Hive::Hkcu, View::V64, "user"),
    ] {
        for sub in winreg::subkeys(hive, UNINSTALL, view) {
            let key = format!("{UNINSTALL}\\{sub}");
            let values = winreg::values(hive, &key, view);
            let get = |name: &str| strip(&text_of(winreg::get(&values, name))).to_string();
            let name = get("DisplayName");
            if name.is_empty() || winreg::get(&values, "ParentKeyName").is_some_and(RegData::truthy) {
                continue;
            }
            let publisher = get("Publisher");
            let hidden = winreg::get(&values, "SystemComponent").is_some_and(|d| d.eq_int(1));
            if hidden && lower(&publisher).contains("microsoft") {
                continue; // internal Microsoft components
            }
            let date = get("InstallDate");
            let installed = if EIGHT_DIGITS.is_match(&date) {
                json!(format!(
                    "{}-{}-{}",
                    take(&date, 4),
                    take(skip(&date, 4), 2),
                    take(skip(&date, 6), 2)
                ))
            } else {
                Value::Null
            };
            let version = get("DisplayVersion");
            let id = (lower(&name), version.clone());
            if programs.iter().any(|(k, _)| *k == id) {
                continue;
            }
            let record = entry(vec![
                ("name", json!(name)),
                ("publisher", json!(publisher)),
                ("version", json!(version)),
                ("installed", installed),
                ("location", json!(get("InstallLocation"))),
                ("uninstall", json!(get("UninstallString"))),
                ("hidden", json!(hidden)),
                ("scope", json!(label)),
                ("key", json!(winreg::display(hive, &key, view))),
            ]);
            programs.push((id, record));
        }
    }
    let mut programs: Vec<Value> = programs.into_iter().map(|(_, v)| v).collect();
    programs.sort_by_cached_key(|p| lower(p.at("name").as_str().unwrap_or("")));
    programs
}

// --------------------------------------------------------------------------- browser extensions

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

fn chromium_roots() -> Vec<(&'static str, String)> {
    let local = env("LOCALAPPDATA");
    let roaming = env("APPDATA");
    vec![
        ("Chrome", join(&local, &[r"Google\Chrome\User Data"])),
        ("Edge", join(&local, &[r"Microsoft\Edge\User Data"])),
        ("Brave", join(&local, &[r"BraveSoftware\Brave-Browser\User Data"])),
        ("Vivaldi", join(&local, &[r"Vivaldi\User Data"])),
        ("Chromium", join(&local, &[r"Chromium\User Data"])),
        ("Opera", join(&roaming, &[r"Opera Software\Opera Stable"])),
        ("Opera GX", join(&roaming, &[r"Opera Software\Opera GX Stable"])),
    ]
}

pub(crate) fn read_json(path: &str, max_bytes: u64) -> Option<Value> {
    let metadata = fs::metadata(path).ok()?;
    if metadata.len() > max_bytes {
        return None;
    }
    serde_json::from_str(&read_text(Path::new(path)).ok()?).ok()
}

rx!(MSG_RE, r"^__MSG_(.+)__$");
rx!(CHROME_ID, r"^[a-p]{32}$");

/// Resolves `__MSG_key__` names using the extension's `_locales` files.
pub(crate) fn localized(manifest: &Map<String, Value>, ext_dir: &str, value: &str) -> String {
    let Some(caps) = MSG_RE.captures(value) else {
        return value.to_string();
    };
    let key = lower(caps.get(1).map_or("", |m| m.as_str()));
    let default_locale = manifest
        .get("default_locale")
        .filter(|v| truthy(v))
        .map(crate::lenient::str_of);
    for locale in [
        default_locale,
        Some("en".into()),
        Some("en_US".into()),
        Some("es".into()),
    ]
    .into_iter()
    .flatten()
    {
        let path = join(ext_dir, &["_locales", &locale, "messages.json"]);
        if let Some(Value::Object(messages)) = read_json(&path, 4 * 1024 * 1024) {
            for (name, entry) in &messages {
                if lower(name) == key && entry.is_object() && truthy(entry.at("message")) {
                    return crate::lenient::str_of(entry.at("message"));
                }
            }
        }
    }
    value.to_string()
}

/// Chromium's ManifestLocation enum: 7 = external policy download, 8 = command line, 9 = external policy.
/// posture.rs matches the policy, unpacked and external values by prefix: keep both sides in sync.
fn chrome_location(location: &Value) -> String {
    let label = match as_integral(location) {
        Some(1) => tl!("store"),
        Some(2) => tl!("external (preferences)"),
        Some(3) => tl!("external (registry)"),
        Some(4) => tl!("unpacked (developer mode)"),
        Some(5) => tl!("browser component"),
        Some(6) => tl!("external (download)"),
        Some(7 | 9) => tl!("forced by policy"),
        Some(8) => tl!("command line"),
        Some(10) => tl!("browser component (external)"),
        _ if location.is_null() => tl!("extensions folder"),
        _ => tl!("unknown"),
    };
    label.to_string()
}

fn strings(value: &Value) -> Vec<String> {
    list(value)
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// Entries of a folder (not starting with a dot), as full paths.
fn folder_entries(folder: &str) -> Vec<String> {
    let Ok(entries) = fs::read_dir(folder) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with('.'))
        .map(|name| join(folder, &[&name]))
        .collect()
}

fn chromium_profile(browser: &str, profile_dir: &str) -> Vec<Value> {
    let mut settings: Vec<(String, Map<String, Value>)> = Vec::new();
    for prefs_name in ["Secure Preferences", "Preferences"] {
        let prefs = read_json(&join(profile_dir, &[prefs_name]), 64 * 1024 * 1024);
        if let Some(Value::Object(found)) = prefs.as_ref().map(|p| p.at("extensions").at("settings"))
            && prefs.as_ref().is_some_and(Value::is_object)
        {
            for (ext_id, info) in found {
                if let Value::Object(info) = info {
                    match settings.iter_mut().find(|(id, _)| id == ext_id) {
                        Some((_, existing)) => existing.extend(info.clone()),
                        None => settings.push((ext_id.clone(), info.clone())),
                    }
                }
            }
        }
    }

    let ext_root = join(profile_dir, &["Extensions"]);
    let mut ids: BTreeSet<String> = settings.iter().map(|(id, _)| id.clone()).collect();
    if let Ok(entries) = fs::read_dir(&ext_root) {
        ids.extend(entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()));
    }

    let empty = Map::new();
    let mut out = Vec::new();
    for ext_id in ids {
        if !CHROME_ID.is_match(&ext_id) {
            continue;
        }
        let info = settings
            .iter()
            .find(|(id, _)| *id == ext_id)
            .map_or(&empty, |(_, info)| info);
        let location = info.at("location");
        if eq_num(location, 5.0) || eq_num(location, 10.0) {
            continue; // internal browser components
        }
        let mut versions = folder_entries(&join(&ext_root, &[&ext_id]));
        versions.sort();
        let ext_dir = match versions.pop() {
            Some(newest) => Some(newest),
            None => info.at("path").as_str().filter(|p| isabs(p)).map(str::to_string),
        };
        let manifest = ext_dir
            .as_deref()
            .and_then(|dir| read_json(&join(dir, &["manifest.json"]), 4 * 1024 * 1024));
        let manifest = match manifest {
            Some(Value::Object(m)) => m,
            _ => info.at("manifest").as_object().cloned().unwrap_or_default(),
        };
        if manifest.is_empty() && location.is_null() {
            continue; // leftovers of an extension already uninstalled: nothing to analyze
        }
        let all_permissions = strings(manifest.at("permissions"));
        let mut hosts = strings(manifest.at("host_permissions"));
        hosts.extend(
            all_permissions
                .iter()
                .filter(|p| p.contains("://") || *p == "<all_urls>")
                .cloned(),
        );
        let permissions: BTreeSet<String> = all_permissions
            .into_iter()
            .filter(|p| !p.contains("://") && p != "<all_urls>")
            .collect();
        for script in list(manifest.at("content_scripts")) {
            if script.is_object() {
                hosts.extend(strings(script.at("matches")));
            }
        }
        let disabled = truthy(info.at("disable_reasons")) || eq_num(info.at("state"), 0.0);
        let dir = ext_dir.clone().unwrap_or_default();
        let name = localized(&manifest, &dir, &crate::lenient::text(manifest.at("name")));
        let description = localized(&manifest, &dir, &crate::lenient::text(manifest.at("description")));
        let hosts: Vec<String> = hosts
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(25)
            .collect();
        out.push(entry(vec![
            ("browser", json!(browser)),
            ("profile", json!(basename(profile_dir))),
            ("id", json!(ext_id)),
            ("name", json!(if name.is_empty() { ext_id.clone() } else { name })),
            ("version", json!(crate::lenient::text(manifest.at("version")))),
            ("description", json!(take(&description, 300))),
            ("enabled", json!(!disabled)),
            ("origin", json!(chrome_location(location))),
            ("from_webstore", info.at("from_webstore").clone()),
            ("update_url", manifest.at("update_url").clone()),
            ("permissions", json!(permissions.into_iter().collect::<Vec<_>>())),
            ("hosts", json!(hosts)),
            ("path", json!(ext_dir)),
        ]));
    }
    out
}

fn firefox_extensions() -> Vec<Value> {
    let mut out = Vec::new();
    let root = join(&env("APPDATA"), &[r"Mozilla\Firefox\Profiles"]);
    for profile_dir in folder_entries(&root) {
        let Some(data @ Value::Object(_)) = read_json(&join(&profile_dir, &["extensions.json"]), 64 * 1024 * 1024)
        else {
            continue;
        };
        for addon in list(data.at("addons")) {
            if !addon.is_object() || addon.at("type").as_str() != Some("extension") {
                continue;
            }
            let location = addon.get("location").map(crate::lenient::str_of).unwrap_or_default();
            if location.starts_with("app-") && addon.at("location").as_str() != Some("app-profile") {
                continue; // extensions built into Firefox
            }
            let locale = addon.at("defaultLocale");
            let perms = addon.at("userPermissions");
            let signed = addon.at("signedState");
            let id = crate::lenient::text(addon.at("id"));
            let name = {
                let n = crate::lenient::text(locale.at("name"));
                if n.is_empty() { id.clone() } else { n }
            };
            let mut permissions = strings(perms.at("permissions"));
            permissions.sort();
            let mut hosts = strings(perms.at("origins"));
            hosts.sort();
            hosts.truncate(25);
            let signed_ok = signed.as_i64().is_some_and(|s| s > 0);
            out.push(entry(vec![
                ("browser", json!("Firefox")),
                ("profile", json!(basename(&profile_dir))),
                ("id", json!(id)),
                ("name", json!(name)),
                ("version", json!(crate::lenient::text(addon.at("version")))),
                (
                    "description",
                    json!(take(&crate::lenient::text(locale.at("description")), 300)),
                ),
                (
                    "enabled",
                    json!(truthy(addon.at("active")) && !truthy(addon.at("userDisabled"))),
                ),
                // posture.rs compares against the unsigned value: keep both sides in sync.
                (
                    "origin",
                    json!(if signed_ok {
                        tl!("signed by Mozilla")
                    } else {
                        tl!("not signed by Mozilla")
                    }),
                ),
                ("from_webstore", Value::Null),
                ("update_url", addon.at("sourceURI").clone()),
                ("permissions", json!(permissions)),
                ("hosts", json!(hosts)),
                ("path", addon.at("path").clone()),
            ]));
        }
    }
    out
}

pub(crate) fn collect_extensions() -> Vec<Value> {
    let mut out = Vec::new();
    for (browser, root) in chromium_roots() {
        if !Path::new(&root).is_dir() {
            continue;
        }
        let mut profiles = Vec::new();
        if Path::new(&join(&root, &["Preferences"])).is_file() {
            profiles.push(root.clone());
        }
        let mut names: Vec<String> = folder_entries(&root)
            .iter()
            .map(|p| basename(p).to_string())
            .filter(|name| lower(name).starts_with("profile "))
            .collect();
        names.sort();
        for name in std::iter::once("Default".to_string()).chain(names) {
            let candidate = join(&root, &[&name]);
            if Path::new(&candidate).is_dir() {
                profiles.push(candidate);
            }
        }
        for profile_dir in profiles {
            out.extend(chromium_profile(browser, &profile_dir));
        }
    }
    out.extend(firefox_extensions());
    out
}

// --------------------------------------------------------------------------- system configuration

const POLICY_KEYS: &[(&str, &str)] = &[
    ("Chrome", r"SOFTWARE\Policies\Google\Chrome"),
    ("Edge", r"SOFTWARE\Policies\Microsoft\Edge"),
    ("Brave", r"SOFTWARE\Policies\BraveSoftware\Brave"),
    ("Firefox", r"SOFTWARE\Policies\Mozilla\Firefox"),
];

fn policy_tree(hive: Hive, key: &str, depth: usize) -> Map<String, Value> {
    let mut tree: Map<String, Value> = winreg::values(hive, key, View::V64)
        .into_iter()
        .map(|(name, data)| (name, json!(take(&data.as_text(), 400))))
        .collect();
    if depth < 2 {
        for sub in winreg::subkeys(hive, key, View::V64).into_iter().take(40) {
            let child = policy_tree(hive, &format!("{key}\\{sub}"), depth + 1);
            if !child.is_empty() {
                tree.insert(format!("{sub}\\"), Value::Object(child));
            }
        }
    }
    tree
}

fn reg_json(hive: Hive, key: &str, name: &str) -> Value {
    winreg::value(hive, key, name, View::V64).map_or(Value::Null, |d| d.to_value())
}

pub(crate) fn collect_sysconfig() -> Value {
    let mut cfg = Map::new();

    let hosts_path = join(&WINDIR, &[r"System32\drivers\etc\hosts"]);
    let mut hosts = Vec::new();
    match fs::read(&hosts_path) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes)
                .replace("\r\n", "\n")
                .replace('\r', "\n");
            for line in text.split_inclusive('\n') {
                let line = strip(line.split('#').next().unwrap_or(""));
                let parts = crate::lenient::split_ws(line);
                if parts.len() >= 2 {
                    hosts.push(json!({"ip": parts[0], "names": parts[1..]}));
                }
            }
        }
        Err(error) => {
            cfg.insert("hosts_error".into(), json!(error.to_string()));
        }
    }
    cfg.insert("hosts".into(), json!(hosts));

    let inet = winreg::values(
        Hive::Hkcu,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        View::V64,
    );
    cfg.insert(
        "proxy".into(),
        json!({
            "enabled": winreg::get(&inet, "ProxyEnable").is_some_and(RegData::truthy),
            "server": text_of(winreg::get(&inet, "ProxyServer")),
            "pac_url": text_of(winreg::get(&inet, "AutoConfigURL")),
        }),
    );

    let policy = winreg::values(
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        View::V64,
    );
    let as_json = |data: Option<&RegData>| data.map_or(Value::Null, RegData::to_value);
    cfg.insert(
        "uac".into(),
        json!({
            "enabled": winreg::get(&policy, "EnableLUA").is_none_or(|d| !d.eq_int(0)),
            "admin_prompt": as_json(winreg::get(&policy, "ConsentPromptBehaviorAdmin")),
            "secure_desktop": as_json(winreg::get(&policy, "PromptOnSecureDesktop")),
        }),
    );

    // Group policy wins over the local setting (Remote Desktop can be turned on by policy alone).
    let ts_policy = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
    let ts = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
    let rdp_tcp = format!(r"{ts}\WinStations\RDP-Tcp");
    let deny = winreg::value(Hive::Hklm, ts_policy, "fDenyTSConnections", View::V64)
        .or_else(|| winreg::value(Hive::Hklm, ts, "fDenyTSConnections", View::V64))
        .unwrap_or(RegData::Int(1));
    let nla = match reg_json(Hive::Hklm, ts_policy, "UserAuthentication") {
        Value::Null => reg_json(Hive::Hklm, &rdp_tcp, "UserAuthentication"),
        set => set,
    };
    cfg.insert(
        "rdp".into(),
        json!({
            "enabled": deny.eq_int(0),
            "nla": nla,
            "port": reg_json(Hive::Hklm, &rdp_tcp, "PortNumber"),
        }),
    );

    let mut policies = Map::new();
    for (browser, key) in POLICY_KEYS {
        for hive in [Hive::Hklm, Hive::Hkcu] {
            let tree = policy_tree(hive, key, 0);
            if !tree.is_empty() {
                policies.insert(format!("{browser} ({})", hive.short()), Value::Object(tree));
            }
        }
    }
    cfg.insert("browser_policies".into(), Value::Object(policies));

    let mut defender_policy = Map::new();
    let base = r"SOFTWARE\Policies\Microsoft\Windows Defender";
    for sub in [
        "",
        r"\Real-Time Protection",
        r"\Spynet",
        r"\Exclusions\Paths",
        r"\Exclusions\Processes",
        r"\Exclusions\Extensions",
    ] {
        let values = winreg::values(Hive::Hklm, &format!("{base}{sub}"), View::V64);
        if !values.is_empty() {
            let name = sub.trim_start_matches('\\');
            let entries: Map<String, Value> = values
                .into_iter()
                .map(|(k, v)| (k, json!(take(&v.as_text(), 300))))
                .collect();
            defender_policy.insert(
                if name.is_empty() {
                    "(root)".into()
                } else {
                    name.to_string()
                },
                Value::Object(entries),
            );
        }
    }
    cfg.insert("defender_policy".into(), Value::Object(defender_policy));

    let update: Map<String, Value> = winreg::values(
        Hive::Hklm,
        r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        View::V64,
    )
    .into_iter()
    .map(|(k, v)| (k, json!(v.as_text())))
    .collect();
    cfg.insert("windows_update_policy".into(), Value::Object(update));
    cfg.insert(
        "wdigest_cleartext".into(),
        json!(
            winreg::value(
                Hive::Hklm,
                r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                "UseLogonCredential",
                View::V64
            )
            .is_some_and(|d| d.eq_int(1))
        ),
    );
    cfg.insert(
        "smartscreen".into(),
        json!(text_of(
            winreg::value(
                Hive::Hklm,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
                "SmartScreenEnabled",
                View::V64
            )
            .as_ref()
        )),
    );
    cfg.insert(
        "smartscreen_policy".into(),
        reg_json(
            Hive::Hklm,
            r"SOFTWARE\Policies\Microsoft\Windows\System",
            "EnableSmartScreen",
        ),
    );
    cfg.insert("hooks".into(), crate::hooks::collect_config());
    cfg.insert("evasion".into(), crate::hooks::collect_evasion());
    cfg.insert("persistence".into(), crate::persist::collect_config());
    cfg.insert("firewall_rules".into(), crate::firewall::collect());
    cfg.insert(crate::svcsec::SECTION.into(), crate::svcsec::collect(is_admin()));
    cfg.insert(crate::secrets::SECTION.into(), crate::secrets::collect(is_admin()));
    cfg.insert(crate::netcfg::SECTION.into(), crate::netcfg::collect());
    cfg.insert("com_classes".into(), crate::com::collect().1);
    cfg.insert(crate::shellext::SECTION.into(), crate::shellext::collect().1);
    cfg.insert("remote_agents".into(), crate::rmm::collect_config());
    cfg.insert(crate::certs::SECTION.into(), crate::certs::collect());
    cfg.insert(crate::amsi::SECTION.into(), crate::amsi::collect_config());
    cfg.insert(crate::bits::SECTION.into(), crate::bits::collect(is_admin()));
    Value::Object(cfg)
}

// --------------------------------------------------------------------------- signatures

/// Signature and version information for each path. Result key: the lower-cased path.
pub(crate) fn collect_signatures(paths: &[String], cancel: &AtomicBool) -> Result<Map<String, Value>, String> {
    let unique: Vec<&String> = paths
        .iter()
        .filter(|p| !p.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if unique.is_empty() {
        return Ok(Map::new());
    }
    // One PowerShell per 40 files, at most 4: measured on a 16-thread machine, 8 instances were
    // slower than 4 (catalog lookups contend), so the cache, not more instances, is what helps.
    let workers = (unique.len() / 40 + 1).clamp(1, 4);
    let chunks: Vec<Vec<&String>> = (0..workers)
        .map(|i| unique.iter().skip(i).step_by(workers).copied().collect())
        .collect();
    let outcomes: Vec<Result<Value, String>> = std::thread::scope(|scope| {
        let handles: Vec<_> = chunks
            .iter()
            .map(|chunk| {
                scope.spawn(move || {
                    // The paths go with the script, never through a file a user could change.
                    let text = chunk.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n");
                    run_collector("signatures", &[], Some(&text), 900, cancel)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(tr!("signatures: the collector failed")))
            })
            .collect()
    });
    let mut results = Map::new();
    for outcome in outcomes {
        let data = outcome?;
        for info in list(data.at("files")) {
            let key = lower(&info.get("path").map(crate::lenient::str_of).unwrap_or_default());
            results.insert(key, info.clone());
        }
    }
    Ok(results)
}

// --------------------------------------------------------------------------- process paths and privileges

#[cfg(windows)]
mod native {
    use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
    use windows::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};
    use windows::Win32::UI::Shell::IsUserAnAdmin;
    use windows::core::PCWSTR;

    const SYSTEM_PROCESS_ID_INFORMATION: i32 = 0x58;

    #[repr(C)]
    struct RawUnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: usize,
    }

    #[repr(C)]
    struct ProcessIdInformation {
        process_id: usize,
        image_name: RawUnicodeString,
    }

    pub(crate) fn is_admin() -> bool {
        // SAFETY: no arguments; returns a BOOL.
        unsafe { IsUserAnAdmin() }.as_bool()
    }

    /// Gets the image path of any process by PID without opening it. Win32_Process does not give a
    /// non-privileged user the path of SYSTEM or elevated processes; this kernel query does.
    pub(crate) struct PathResolver {
        devices: Vec<(String, String)>,
    }

    impl PathResolver {
        pub(crate) fn new() -> Self {
            let mut drives = vec![0u16; 1024];
            // SAFETY: the buffer is writable for its whole length.
            let length = unsafe { GetLogicalDriveStringsW(Some(&mut drives)) } as usize;
            let mut devices = Vec::new();
            for drive in drives[..length.min(drives.len())].split(|&u| u == 0) {
                let drive = String::from_utf16_lossy(drive);
                let letter = drive.trim_end_matches('\\');
                if letter.is_empty() {
                    continue;
                }
                let name: Vec<u16> = letter.encode_utf16().chain(std::iter::once(0)).collect();
                let mut target = vec![0u16; 1024];
                // SAFETY: `name` is NUL-terminated; `target` is writable for its whole length.
                let written = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut target)) };
                if written > 0 {
                    let end = target.iter().position(|&u| u == 0).unwrap_or(target.len());
                    devices.push((
                        format!("{}\\", String::from_utf16_lossy(&target[..end]).to_lowercase()),
                        format!("{letter}\\"),
                    ));
                }
            }
            Self { devices }
        }

        pub(crate) fn path_for(&self, pid: i64) -> Option<String> {
            if pid <= 4 {
                return None;
            }
            let mut units = vec![0u16; 0x7FFF];
            let mut info = ProcessIdInformation {
                process_id: usize::try_from(pid).ok()?,
                image_name: RawUnicodeString {
                    length: 0,
                    maximum_length: 0xFFFE,
                    buffer: units.as_mut_ptr() as usize,
                },
            };
            // SAFETY: `info` is a valid SYSTEM_PROCESS_ID_INFORMATION whose name buffer (`units`,
            // 0xFFFE bytes) stays alive and writable for the duration of the call.
            let status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS(SYSTEM_PROCESS_ID_INFORMATION),
                    (&mut info as *mut ProcessIdInformation).cast(),
                    size_of::<ProcessIdInformation>() as u32,
                    std::ptr::null_mut(),
                )
            };
            let length = (info.image_name.length as usize / 2).min(units.len());
            if status.0 < 0 || length == 0 {
                return None;
            }
            let nt_path = String::from_utf16_lossy(&units[..length]);
            let low = nt_path.to_lowercase();
            for (device, letter) in &self.devices {
                if low.starts_with(device.as_str()) {
                    return Some(format!(
                        "{letter}{}",
                        crate::lenient::skip(&nt_path, device.chars().count())
                    ));
                }
            }
            // Processes without a file (Registry, Memory Compression...) or volumes without a drive letter.
            nt_path.starts_with('\\').then_some(nt_path)
        }
    }
}

#[cfg(not(windows))]
mod native {
    pub(crate) fn is_admin() -> bool {
        false
    }
    pub(crate) struct PathResolver;
    impl PathResolver {
        pub(crate) fn new() -> Self {
            Self
        }
        pub(crate) fn path_for(&self, _pid: i64) -> Option<String> {
            None
        }
    }
}

pub(crate) use native::is_admin;

/// Fills in the path of processes that WMI hides from a non-privileged user.
fn fill_process_paths(processes: &mut [Value]) -> usize {
    let resolver = native::PathResolver::new();
    let mut filled = 0;
    for proc in processes.iter_mut() {
        if truthy(proc.at("path")) {
            continue;
        }
        let pid = crate::lenient::int_of(proc.at("pid"));
        if let Some(path) = resolver.path_for(pid).filter(|p| !p.starts_with('\\'))
            && let Some(map) = proc.as_object_mut()
        {
            map.insert("path".into(), json!(path));
            map.insert("path_source".into(), json!("kernel"));
            filled += 1;
        }
    }
    filled
}

// --------------------------------------------------------------------------- orchestration

/// What a job may need besides the days: the shortcuts of the Startup folders (system.ps1 reads
/// their targets).
pub(crate) struct JobInput {
    pub(crate) shortcuts: String,
}

type Job = fn(&JobInput, u32, &AtomicBool) -> Result<Value, String>;

fn job_label(name: &str) -> &'static str {
    match name {
        "processes" => tl!("processes"),
        "services" => tl!("services and drivers"),
        "tasks" => tl!("scheduled tasks"),
        "network" => tl!("network"),
        "system" => tl!("security state"),
        "events" => tl!("event logs"),
        "autoruns" => tl!("startup entries"),
        "programs" => tl!("installed programs"),
        "extensions" => tl!("browser extensions"),
        "vulnerable_drivers" => tl!("vulnerable drivers"),
        _ => tl!("configuration"),
    }
}

fn jobs() -> Vec<(&'static str, Job)> {
    vec![
        ("processes", |_, _, cancel| {
            run_collector("processes", &[], None, 300, cancel)
        }),
        ("services", |_, _, cancel| {
            run_collector("services", &[], None, 300, cancel)
        }),
        ("tasks", |_, _, cancel| run_collector("tasks", &[], None, 300, cancel)),
        ("network", |_, _, cancel| {
            run_collector("network", &[], None, 300, cancel)
        }),
        ("system", |input, _, cancel| {
            run_collector("system", &[], Some(&input.shortcuts), 300, cancel)
        }),
        ("events", |_, days, cancel| {
            // The collectors' own PowerShell activity is left out: SelfMark is on this version's
            // command line and scripts, SelfDir where earlier versions ran them from.
            let params = [
                ("Days", days.to_string()),
                ("SelfDir", scan_root().display().to_string()),
                ("SelfMark", self_mark()),
            ];
            run_collector("events", &params, None, 600, cancel)
        }),
        ("autoruns", |_, _, _| Ok(Value::Array(collect_autoruns()))),
        ("programs", |_, _, _| Ok(Value::Array(collect_programs()))),
        ("extensions", |_, _, _| Ok(Value::Array(collect_extensions()))),
        ("sysconfig", |_, _, _| Ok(collect_sysconfig())),
        // Hashes every driver file: its own job, so it runs next to the others.
        ("vulnerable_drivers", |_, days, _| Ok(crate::vulndrv::collect(days))),
    ]
}

/// Runs every collector in parallel and returns the raw inventory.
pub(crate) fn collect_all(days: u32, progress: &dyn Fn(&str), cancel: &AtomicBool) -> Value {
    let days = days.max(1);
    let started = Local::now();
    let lnk: Vec<String> = list_startup_files()
        .into_iter()
        .filter(|f| lower(f).ends_with(".lnk"))
        .collect();
    let input = JobInput {
        shortcuts: lnk.join("\n"),
    };
    let input = &input;

    let jobs = jobs();
    let next = AtomicUsize::new(0);
    type Slot = Option<(Result<Value, String>, f64)>;
    let results: Mutex<Vec<Slot>> = Mutex::new((0..jobs.len()).map(|_| None).collect());
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::scope(|scope| {
        for _ in 0..6.min(jobs.len()) {
            let tx = tx.clone();
            let (jobs, next, results) = (&jobs, &next, &results);
            scope.spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some((name, job)) = jobs.get(index) else { break };
                    let t0 = Instant::now();
                    let outcome = if cancel.load(Ordering::Relaxed) {
                        Err("cancelled".to_string())
                    } else {
                        job(input, days, cancel)
                    };
                    let seconds = t0.elapsed().as_secs_f64();
                    let message = match &outcome {
                        Ok(_) => tr!("  ok {0} ({1}s)", tr!(job_label(name)), format!("{seconds:.1}")),
                        Err(error) => format!("  ! {}: {error}", tr!(job_label(name))),
                    };
                    if let Ok(mut slots) = results.lock() {
                        slots[index] = Some((outcome, seconds));
                    }
                    let _ = tx.send(message);
                }
            });
        }
        drop(tx);
        for message in rx {
            progress(&message);
        }
    });

    let mut notes: Vec<Value> = Vec::new();
    let mut timings = Map::new();
    let mut data: Map<String, Value> = Map::new();
    let slots = results.into_inner().unwrap_or_default();
    for ((name, _), slot) in jobs.iter().zip(slots) {
        let Some((outcome, seconds)) = slot else { continue };
        timings.insert(name.to_string(), json!(round_to(seconds, 1)));
        match outcome {
            Ok(value) => {
                data.insert(name.to_string(), value);
            }
            Err(error) => {
                notes.push(json!({"area": tr!(job_label(name)), "message": tr!("could not be collected: {0}", error)}));
            }
        }
    }

    for name in ["processes", "services", "tasks", "network", "system", "events"] {
        if let Some(Value::Object(section)) = data.get(name) {
            notes.extend(list(section.at("notes")).iter().cloned());
        }
    }
    if let Some(config) = data.get("sysconfig") {
        notes.extend(list(config.at(crate::svcsec::SECTION).at("notes")).iter().cloned());
        notes.extend(list(config.at(crate::secrets::SECTION).at("notes")).iter().cloned());
        notes.extend(list(config.at(crate::certs::SECTION).at("notes")).iter().cloned());
        notes.extend(list(config.at(crate::bits::SECTION).at("notes")).iter().cloned());
    }
    if let Some(section) = data.get("vulnerable_drivers") {
        notes.extend(list(section.at("notes")).iter().cloned());
    }
    if let Some(config) = data.get("sysconfig") {
        if truthy(config.at(crate::shellext::SECTION).at("capped")) {
            notes.push(json!({
                "area": tr!("Explorer extensions"),
                "message": tr!("only the first {0} Explorer extensions were checked", crate::shellext::MAX_ENTRIES),
            }));
        }
        if truthy(config.at("com_classes").at("capped")) {
            notes.push(json!({
                "area": tr!("COM classes"),
                "message": tr!("only the first {0} per-user COM classes were checked", crate::com::MAX_KEYS),
            }));
        }
    }
    let section = |name: &str, key: &str| -> Value {
        match data.get(name) {
            Some(Value::Object(map)) if truthy(map.at(key)) => map.at(key).clone(),
            _ => json!([]),
        }
    };
    let whole = |name: &str, empty: Value| -> Value {
        match data.get(name) {
            Some(value) if truthy(value) => value.clone(),
            _ => empty,
        }
    };

    // The vulnerable driver check runs as its own job but belongs with the configuration.
    let mut sysconfig = whole("sysconfig", json!({}));
    if let (Some(map), Some(section)) = (sysconfig.as_object_mut(), data.get("vulnerable_drivers")) {
        map.insert(crate::vulndrv::SECTION.into(), section.clone());
    }
    let mut processes = section("processes", "processes");
    let filled = processes.as_array_mut().map_or(0, |list| fill_process_paths(list));
    let system = whole("system", json!({}));
    let is_admin_value = match system.get("is_admin") {
        Some(value) => truthy(value),
        None => is_admin(),
    };

    json!({
        "meta": {
            "tool_version": env!("CARGO_PKG_VERSION"),
            "started": started.format("%Y-%m-%dT%H:%M:%S").to_string(),
            "is_admin": is_admin_value,
            "user": env("USERNAME"),
            "computer": env("COMPUTERNAME"),
            "userprofile": env("USERPROFILE"),
            "days": days,
            "timings": timings,
            "paths_filled_from_kernel": filled,
            "self_pid": std::process::id(),
            "language": vigil_i18n::language(),
        },
        "processes": processes,
        "services": section("services", "services"),
        "drivers": section("services", "drivers"),
        "tasks": section("tasks", "tasks"),
        "network": whole("network", json!({})),
        "system": system,
        "events": whole("events", json!({})),
        "autoruns": whole("autoruns", json!([])),
        "programs": whole("programs", json!([])),
        "extensions": whole("extensions", json!([])),
        "sysconfig": sysconfig,
        "files": {},
        "notes": notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cmd /c "start /b ping -n 47 … & …"`: cmd starts a grandchild that inherits the output
    /// pipes and outlives it. Without the job, reading the output would wait ~47 s.
    #[cfg(windows)]
    fn shim_with_grandchild(tail: &str) -> Command {
        let system =
            PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join("System32");
        let mut command = Command::new(system.join("cmd.exe"));
        command.args([
            "/d",
            "/c",
            &format!(
                "start /b {} -n 47 127.0.0.1 >nul & {tail}",
                system.join("PING.EXE").display()
            ),
        ]);
        command
    }

    #[cfg(windows)]
    #[test]
    fn cancelling_ends_the_whole_process_tree() {
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&cancel);
        let stopper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(800));
            flag.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        let ping = shim_with_grandchild("ping -n 47 127.0.0.1 >nul");
        let result = run_child(ping, None, Duration::from_secs(120), &cancel);
        let _ = stopper.join();
        assert!(matches!(result, Err(ChildError::Cancelled)));
        assert!(started.elapsed() < Duration::from_secs(8), "{:?}", started.elapsed());
    }

    #[cfg(windows)]
    #[test]
    fn a_grandchild_left_running_does_not_hold_the_output() {
        let started = Instant::now();
        let shim = shim_with_grandchild("echo finished");
        let finished = run_child(shim, None, Duration::from_secs(120), &AtomicBool::new(false));
        assert!(started.elapsed() < Duration::from_secs(8), "{:?}", started.elapsed());
        let finished = finished.ok().expect("ran");
        assert!(String::from_utf8_lossy(&finished.stdout).contains("finished"));
    }

    #[cfg(windows)]
    #[test]
    fn a_timeout_ends_the_whole_process_tree() {
        let started = Instant::now();
        let shim = shim_with_grandchild("ping -n 47 127.0.0.1 >nul");
        let result = run_child(shim, None, Duration::from_millis(800), &AtomicBool::new(false));
        assert!(matches!(result, Err(ChildError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(8), "{:?}", started.elapsed());
    }
    use crate::lenient::{is_false, obj};

    #[test]
    fn collector_scripts_are_ascii() {
        // Windows PowerShell 5.1 reads scripts without a BOM using the ANSI code page.
        for (name, body) in SCRIPTS {
            assert!(body.is_ascii(), "{name}.ps1 must stay pure ASCII");
        }
    }

    #[test]
    fn collectors_are_composed_with_their_helpers_and_the_mark() {
        for (name, _) in SCRIPTS.iter().filter(|(name, _)| *name != "_common") {
            let text = collector_text(name).expect("composed");
            assert!(text.starts_with(&format!("# {}", self_mark())), "{name}");
            assert!(text.contains("function Write-Result"), "{name}");
            assert!(!text.contains(INCLUDE_LINE), "{name}");
            assert!(text.is_ascii(), "{name}");
        }
        assert!(collector_text("nope").is_err());
        let boot = bootstrap();
        assert!(boot.contains(&self_mark()));
        assert!(!boot.contains('"'), "one command-line argument: no double quotes");
    }

    #[test]
    fn the_result_is_the_last_marked_line() {
        let out = b"WARNING: something\r\nVIGIL-JSON:{\"a\":1}\r\nnoise\nVIGIL-JSON:{\"b\":2}\n";
        assert_eq!(result_json(out), Some(&b"{\"b\":2}"[..]));
        assert_eq!(result_json(b"no marker here"), None);
        assert_eq!(result_json(b"VIGIL-JSON:[1]"), Some(&b"[1]"[..]));
    }

    #[test]
    #[ignore = "a real read-only scan: run by hand"]
    fn every_collector_runs_and_answers() {
        let cancel = AtomicBool::new(false);
        let lines = Mutex::new(Vec::new());
        let progress = |line: &str| {
            if let Ok(mut lines) = lines.lock() {
                lines.push(line.to_string());
            }
        };
        let raw = collect_all(7, &progress, &cancel);
        let lines = lines.into_inner().unwrap_or_default();
        // Counts only: no data from this computer is printed.
        for (name, _) in jobs() {
            let ok = lines
                .iter()
                .any(|l| l.trim_start().starts_with("ok ") && l.contains(job_label(name)));
            println!("{name:<20} {}", if ok { "ok" } else { "FAILED" });
        }
        let failed: Vec<&String> = lines.iter().filter(|l| l.trim_start().starts_with('!')).collect();
        assert!(failed.is_empty(), "{failed:?}");
        assert!(!list(raw.at("processes")).is_empty());
        assert!(raw.at("events").is_object());
        // The collectors' own PowerShell (this run's included) never shows up as a finding.
        let mark = self_mark();
        let events = raw.at("events");
        for entry in list(events.at("ps_commands"))
            .iter()
            .chain(list(events.at("ps_scriptblocks")).iter())
        {
            let text = entry.to_string();
            assert!(!text.contains(&mark), "own activity listed");
            assert!(!text.contains("VIGIL-INPUT"), "own activity listed");
        }
    }

    #[test]
    #[ignore = "starts PowerShell: run by hand"]
    fn a_collector_runs_from_standard_input_with_its_input() {
        let cancel = AtomicBool::new(false);
        let paths = format!(
            "{}\n{}",
            vigil_sys::paths::system_dir().join("notepad.exe").display(),
            std::env::temp_dir().join("vigil-\u{e9}t\u{e9}-missing.exe").display()
        );
        let data = run_collector("signatures", &[], Some(&paths), 120, &cancel).expect("runs");
        let files = list(data.at("files"));
        assert_eq!(files.len(), 2, "{data}");
        assert!(
            files
                .iter()
                .any(|f| f.at("path").as_str().is_some_and(|p| p.contains('\u{e9}')))
        );
        let processes = run_collector("processes", &[], None, 120, &cancel).expect("runs");
        assert!(!list(processes.at("processes")).is_empty());
    }

    #[test]
    fn locations_and_flags() {
        assert_eq!(chrome_location(&json!(7)), "forced by policy");
        assert_eq!(chrome_location(&Value::Null), "extensions folder");
        assert_eq!(chrome_location(&json!(42)), "unknown");
        assert!(is_false(&json!(false)));
        assert!(MSG_RE.is_valid() && CHROME_ID.is_valid() && EIGHT_DIGITS.is_valid());
        assert_eq!(obj(&json!({})).len(), 0);
    }
}
