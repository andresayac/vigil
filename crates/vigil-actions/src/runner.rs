//! Running Windows tools: always by absolute path, with argument lists (never through a shell),
//! and with values for PowerShell passed in `PC_*` environment variables, never in the script text.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::thread;
use std::time::{Duration, Instant};

use windows::Win32::Globalization::{CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS, MultiByteToWideChar};

use crate::error::{ActionError, Result};
use vigil_i18n::tr;

pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// What a tool printed and returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolResult {
    pub code: i32,
    pub out: String,
    pub err: String,
}

impl ToolResult {
    pub fn new(code: i32, out: impl Into<String>, err: impl Into<String>) -> Self {
        Self {
            code,
            out: out.into(),
            err: err.into(),
        }
    }

    /// The error output, or the normal output when there is none.
    pub fn text(&self) -> String {
        let err = self.err.trim();
        if err.is_empty() {
            self.out.trim().to_string()
        } else {
            err.to_string()
        }
    }
}

/// Runs a tool. The app uses [`SystemRunner`]; tests install a fake one with [`set_runner`].
pub trait Runner {
    fn run(&self, args: &[String], timeout: Duration, env: Option<&BTreeMap<String, String>>) -> Result<ToolResult>;
}

/// Starts the real process without a window and waits for it (up to `timeout`).
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, args: &[String], timeout: Duration, env: Option<&BTreeMap<String, String>>) -> Result<ToolResult> {
        let Some(program) = args.first() else {
            return Err(ActionError::new(tr!("no program to run")));
        };
        let name = basename(program);
        let mut command = Command::new(program);
        command
            .args(&args[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW);
        if let Some(env) = env {
            command.env_clear().envs(env);
        }
        let mut child = command
            .spawn()
            .map_err(|e| ActionError::new(tr!("could not run {0}: {1}", name, crate::error::io_text(&e))))?;
        let out = child.stdout.take().map(reader);
        let err = child.stderr.take().map(reader);
        let deadline = Instant::now() + timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ActionError::new(tr!(
                        "{0} did not finish within {1} seconds",
                        name,
                        timeout.as_secs()
                    )));
                }
                Ok(None) => thread::sleep(Duration::from_millis(15)),
                Err(e) => return Err(ActionError::new(tr!("could not run {0}: {1}", name, e))),
            }
        };
        let collect = |handle: Option<thread::JoinHandle<Vec<u8>>>| {
            handle
                .and_then(|h| h.join().ok())
                .map(|bytes| decode(&bytes))
                .unwrap_or_default()
        };
        Ok(ToolResult {
            code: status.code().unwrap_or(-1),
            out: collect(out),
            err: collect(err),
        })
    }
}

fn reader<R: Read + Send + 'static>(mut source: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = source.read_to_end(&mut buffer);
        buffer
    })
}

/// Tool output: UTF-16 (reg.exe, some PowerShell output), UTF-8, or the console's OEM code page.
pub(crate) fn decode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let utf16 = data.starts_with(&[0xFF, 0xFE]) || (data.len() > 3 && data[1] == 0 && data[3] == 0);
    if utf16 {
        let body = if data.starts_with(&[0xFF, 0xFE]) {
            &data[2..]
        } else {
            data
        };
        let units: Vec<u16> = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    match std::str::from_utf8(data) {
        Ok(text) => text.to_string(),
        Err(_) => oem_to_string(data),
    }
}

fn oem_to_string(data: &[u8]) -> String {
    // SAFETY: first call only measures; `data` is a valid slice.
    let needed = unsafe { MultiByteToWideChar(CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), data, None) };
    if needed <= 0 {
        return String::from_utf8_lossy(data).into_owned();
    }
    let mut wide = vec![0u16; needed as usize];
    // SAFETY: `wide` has room for `needed` UTF-16 units.
    let written = unsafe { MultiByteToWideChar(CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), data, Some(&mut wide)) };
    String::from_utf16_lossy(&wide[..written.max(0) as usize])
}

thread_local! {
    static OVERRIDE: RefCell<Option<Rc<dyn Runner>>> = const { RefCell::new(None) };
}

/// Replaces the tool runner for the current thread (tests use a fake one); `None` restores the real one.
pub fn set_runner(runner: Option<Rc<dyn Runner>>) {
    OVERRIDE.with(|slot| *slot.borrow_mut() = runner);
}

fn current() -> Option<Rc<dyn Runner>> {
    OVERRIDE.with(|slot| slot.borrow().clone())
}

/// Runs a tool through the current runner (the fake one in tests).
pub(crate) fn run(args: Vec<String>, timeout_secs: u64) -> Result<ToolResult> {
    run_with_env(&args, timeout_secs, None)
}

fn run_with_env(args: &[String], timeout_secs: u64, env: Option<&BTreeMap<String, String>>) -> Result<ToolResult> {
    let timeout = Duration::from_secs(timeout_secs);
    match current() {
        Some(runner) => runner.run(args, timeout, env),
        None => SystemRunner.run(args, timeout, env),
    }
}

/// Runs a tool with the real runner, whatever a test installed (data-folder lock-down, signatures).
pub(crate) fn run_system(
    args: &[String],
    timeout_secs: u64,
    env: Option<&BTreeMap<String, String>>,
) -> Result<ToolResult> {
    SystemRunner.run(args, Duration::from_secs(timeout_secs), env)
}

pub fn windir() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()))
}

pub fn system32() -> PathBuf {
    windir().join("System32")
}

/// Absolute path of a tool in System32.
pub fn tool(name: &str) -> String {
    system32().join(name).to_string_lossy().into_owned()
}

/// Windows PowerShell by absolute path (a 32-bit process would see the 32-bit one otherwise).
pub fn powershell_path() -> String {
    let native = if cfg!(target_pointer_width = "32") && windir().join("Sysnative").is_dir() {
        "Sysnative"
    } else {
        "System32"
    };
    windir()
        .join(native)
        .join(r"WindowsPowerShell\v1.0\powershell.exe")
        .to_string_lossy()
        .into_owned()
}

/// The arguments and environment of a PowerShell snippet. Values become `$env:PC_<NAME>`.
pub(crate) fn ps_command(script: &str, values: &[(&str, &str)]) -> (Vec<String>, BTreeMap<String, String>) {
    let mut env: BTreeMap<String, String> = std::env::vars()
        .filter(|(key, _)| !key.to_uppercase().starts_with("PC_"))
        .collect();
    for (name, value) in values {
        env.insert(format!("PC_{}", name.to_uppercase()), (*value).to_string());
    }
    let full = format!(
        "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; \
         [Console]::OutputEncoding = [Text.Encoding]::UTF8; {script}"
    );
    let args = [
        powershell_path().as_str(),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        full.as_str(),
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    (args, env)
}

/// Runs a PowerShell snippet through the current runner.
pub(crate) fn ps(script: &str, timeout_secs: u64, values: &[(&str, &str)]) -> Result<ToolResult> {
    let (args, env) = ps_command(script, values);
    run_with_env(&args, timeout_secs, Some(&env))
}

/// Runs a PowerShell snippet and returns its trimmed output, or an error that names `what`.
pub(crate) fn ps_ok(script: &str, what: &str, timeout_secs: u64, values: &[(&str, &str)]) -> Result<String> {
    let result = ps(script, timeout_secs, values)?;
    if result.code != 0 {
        let line = first_line(&result.text());
        let detail = if line.is_empty() {
            tr!("exit code {0}", result.code)
        } else {
            line
        };
        return Err(ActionError::new(format!("{what} failed: {detail}")));
    }
    Ok(result.out.trim().to_string())
}

/// The meaningful part of a tool's error output (sc.exe and others split it over two lines).
pub fn first_line(text: &str) -> String {
    let mut lines: Vec<&str> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty()
            || ["At line:", "+ ", "CategoryInfo", "FullyQualifiedErrorId"]
                .iter()
                .any(|p| line.starts_with(p))
        {
            continue;
        }
        lines.push(line);
        if lines.len() == 2 || !line.ends_with(':') {
            break;
        }
    }
    lines.join(" ").chars().take(400).collect()
}

pub(crate) fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Starts a program and returns at once (uninstallers, Explorer, consoles).
pub(crate) fn launch(program: &str, args: &[&str]) -> Result<()> {
    const DETACHED: u32 = 0x0000_0008 | 0x0000_0200; // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED)
        .spawn()
        .map(|_| ())
        .map_err(|e| {
            ActionError::new(tr!(
                "could not start {0}: {1}",
                basename(program),
                crate::error::io_text(&e)
            ))
        })
}

/// Like [`launch`], with the arguments passed exactly as written (an uninstaller's own command line).
pub(crate) fn launch_raw(program: &str, raw_args: &str) -> Result<()> {
    const DETACHED: u32 = 0x0000_0008 | 0x0000_0200;
    let mut command = Command::new(program);
    if !raw_args.trim().is_empty() {
        command.raw_arg(raw_args.trim());
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED)
        .spawn()
        .map(|_| ())
        .map_err(|e| {
            ActionError::new(tr!(
                "could not start {0}: {1}",
                basename(program),
                crate::error::io_text(&e)
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_line_joins_split_messages() {
        assert_eq!(
            first_line("[SC] OpenService FAILED 5:\n\nAccess is denied.\n"),
            "[SC] OpenService FAILED 5: Access is denied."
        );
        assert_eq!(first_line("At line:1 char:1\nsomething broke\nmore"), "something broke");
    }

    #[test]
    fn decode_handles_utf16_and_utf8() {
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("hé".encode_utf16().flat_map(|u| u.to_le_bytes()))
            .collect();
        assert_eq!(decode(&utf16), "hé");
        assert_eq!(decode("ok ü".as_bytes()), "ok ü");
    }

    #[test]
    fn powershell_values_travel_in_the_environment() {
        let evil = "C:\\x'; Remove-Item C:\\ -Recurse; '";
        let (args, env) = ps_command("Remove-MpPreference -ExclusionPath $env:PC_VALUE", &[("value", evil)]);
        assert!(!args.join(" ").contains("Remove-Item"));
        assert_eq!(env.get("PC_VALUE").map(String::as_str), Some(evil));
    }
}
