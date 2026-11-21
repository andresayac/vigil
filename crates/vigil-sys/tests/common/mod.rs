//! Helpers shared by the integration tests: child processes that are always killed, and
//! independent sources (Toolhelp, GetProcessTimes) to check the sampler against.
#![allow(dead_code)]

use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const PROCESS_SUSPEND_RESUME: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0800);

/// A child process that is killed when the guard is dropped (also when a test fails).
pub struct ChildGuard(pub std::process::Child);

impl ChildGuard {
    pub fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn system32(file: &str) -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    PathBuf::from(root).join("System32").join(file)
}

pub fn spawn(program: PathBuf, args: &[&str]) -> ChildGuard {
    let child = Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("child process");
    ChildGuard(child)
}

/// A child that waits quietly for about 30 seconds.
pub fn idle_child() -> ChildGuard {
    spawn(system32("PING.EXE"), &["-n", "30", "127.0.0.1"])
}

/// A child that keeps one processor busy.
pub fn busy_child() -> ChildGuard {
    spawn(
        system32(r"WindowsPowerShell\v1.0\powershell.exe"),
        &["-NoProfile", "-NonInteractive", "-Command", "while($true){}"],
    )
}

pub struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by the test and is closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub fn open(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> OwnedHandle {
    // SAFETY: plain call; the handle is owned by the guard.
    OwnedHandle(unsafe { OpenProcess(access, false, pid) }.expect("open process"))
}

fn filetime(time: FILETIME) -> i64 {
    ((time.dwHighDateTime as i64) << 32) | time.dwLowDateTime as i64
}

/// (creation time in Unix ms, user + kernel CPU time in 100 ns units) of a process.
pub fn process_times(pid: u32) -> (i64, i64) {
    let handle = open(pid, PROCESS_QUERY_LIMITED_INFORMATION);
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: four writable FILETIMEs and a valid handle.
    unsafe { GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) }.expect("process times");
    (
        (filetime(created) - 116_444_736_000_000_000) / 10_000,
        filetime(kernel) + filetime(user),
    )
}

/// (parent pid, thread count) of a process according to Toolhelp, an independent source.
pub fn toolhelp(pid: u32) -> Option<(u32, u32)> {
    // SAFETY: the snapshot handle is closed by the guard.
    let snapshot = OwnedHandle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.ok()?);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: `entry` is writable with its size set.
    let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) }.is_ok();
    while more {
        if entry.th32ProcessID == pid {
            return Some((entry.th32ParentProcessID, entry.cntThreads));
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot.0, &mut entry) }.is_ok();
    }
    None
}

/// Waits until `check` holds or `timeout` passes; returns whether it held.
pub fn wait_until(timeout: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    check()
}
