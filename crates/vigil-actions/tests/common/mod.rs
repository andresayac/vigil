//! Helpers shared by the integration tests. Nothing here changes the computer: temporary folders,
//! a scratch registry key under HKCU\Software\VigilTests (deleted afterwards), a fake tool runner
//! and child processes that the tests start and always end.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use regex::Regex;
use vigil_actions::{ActionError, Runner, Store, ToolResult};

pub const TEST_ROOT: &str = r"Software\VigilTests";

/// A folder in %TEMP%, deleted when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(prefix: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!("{prefix}{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&path).expect("temp folder");
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A store in a temporary folder, with every seam reset (and elevation pretended) for this thread.
pub struct Fixture {
    pub tmp: TempDir,
    pub store: Store,
}

impl Fixture {
    pub fn new() -> Fixture {
        vigil_actions::testing::reset();
        vigil_actions::testing::set_admin(Some(true));
        let tmp = TempDir::new("vigil-test-");
        let store = Store::open(&tmp.path().join("data")).expect("store");
        Fixture { tmp, store }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        vigil_actions::testing::reset();
    }
}

/// One recorded tool call.
#[derive(Debug, Clone)]
pub struct Call {
    pub args: Vec<String>,
    pub env: Option<BTreeMap<String, String>>,
}

/// Records the tool calls and answers from a table of (regex on the command line -> result).
#[derive(Default)]
pub struct FakeRunner {
    pub calls: RefCell<Vec<Call>>,
    answers: Vec<(Regex, ToolResult)>,
}

impl FakeRunner {
    pub fn install(answers: &[(&str, ToolResult)]) -> Rc<FakeRunner> {
        let runner = Rc::new(FakeRunner {
            calls: RefCell::new(Vec::new()),
            answers: answers
                .iter()
                .map(|(pattern, result)| (Regex::new(&format!("(?i){pattern}")).expect("pattern"), result.clone()))
                .collect(),
        });
        vigil_actions::set_runner(Some(runner.clone()));
        runner
    }

    fn line(args: &[String]) -> String {
        let program = args
            .first()
            .map(|p| p.rsplit('\\').next().unwrap_or(p).to_lowercase())
            .unwrap_or_default();
        std::iter::once(program)
            .chain(args.iter().skip(1).cloned())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The calls as "tool.exe arg arg".
    pub fn lines(&self) -> Vec<String> {
        self.calls.borrow().iter().map(|c| Self::line(&c.args)).collect()
    }

    /// The `PC_*` values PowerShell calls received.
    pub fn ps_values(&self, name: &str) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .filter_map(|c| c.env.as_ref()?.get(name).cloned())
            .collect()
    }
}

impl Runner for FakeRunner {
    fn run(
        &self,
        args: &[String],
        _timeout: Duration,
        env: Option<&BTreeMap<String, String>>,
    ) -> Result<ToolResult, ActionError> {
        self.calls.borrow_mut().push(Call {
            args: args.to_vec(),
            env: env.cloned(),
        });
        let line = Self::line(args);
        Ok(self
            .answers
            .iter()
            .find(|(pattern, _)| pattern.is_match(&line))
            .map(|(_, result)| result.clone())
            .unwrap_or_default())
    }
}

/// Registry tests run one at a time and remove HKCU\Software\VigilTests when they end.
pub struct ScratchKey {
    pub sub: String,
    pub key: String,
    _lock: MutexGuard<'static, ()>,
}

static REGISTRY_LOCK: Mutex<()> = Mutex::new(());

impl ScratchKey {
    pub fn new(name: &str) -> ScratchKey {
        let lock = REGISTRY_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let sub = format!("{TEST_ROOT}\\{name}");
        let _ = vigil_actions::testing::delete_scratch_key(&sub);
        ScratchKey {
            key: format!("HKCU\\{sub}"),
            sub,
            _lock: lock,
        }
    }
}

impl Drop for ScratchKey {
    fn drop(&mut self) {
        let _ = vigil_actions::testing::delete_scratch_key(TEST_ROOT);
    }
}

/// A child process the test owns (`ping` waits ~30 s); always ended, whatever the test does.
pub struct ChildProcess(pub std::process::Child);

impl ChildProcess {
    pub fn start() -> ChildProcess {
        let ping = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join(r"System32\PING.EXE");
        let child = Command::new(ping)
            .args(["-n", "30", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .spawn()
            .expect("child process");
        std::thread::sleep(Duration::from_millis(300));
        ChildProcess(child)
    }

    pub fn pid(&self) -> u32 {
        self.0.id()
    }

    /// Waits up to `seconds` for it to end; true if it ended.
    pub fn wait_exit(&mut self, seconds: u64) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
        while std::time::Instant::now() < deadline {
            if let Ok(Some(_)) = self.0.try_wait() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs Windows PowerShell with values passed in `PC_*` environment variables (test set-up only).
pub fn powershell(script: &str, values: &[(&str, &str)]) -> std::process::Output {
    let exe = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut command = Command::new(exe);
    command
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(0x0800_0000);
    for (name, value) in values {
        command.env(format!("PC_{}", name.to_uppercase()), value);
    }
    command.output().expect("powershell")
}

/// Creates a directory junction `link` -> `target`.
pub fn junction(link: &Path, target: &Path) {
    let out = powershell(
        "New-Item -ItemType Junction -Path $env:PC_LINK -Target $env:PC_TARGET | Out-Null",
        &[("link", &link.to_string_lossy()), ("target", &target.to_string_lossy())],
    );
    assert!(
        out.status.success(),
        "junction: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The SID of the account running the tests (read at run time, never stored).
pub fn current_user_sid() -> String {
    let whoami = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
        .join(r"System32\whoami.exe");
    let out = Command::new(whoami)
        .args(["/user", "/fo", "csv", "/nh"])
        .creation_flags(0x0800_0000)
        .output()
        .expect("whoami");
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim()
        .rsplit(',')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .to_string()
}
