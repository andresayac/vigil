//! The process sampler against independent sources and real child processes.

mod common;

use std::collections::HashSet;
use std::thread::sleep;
use std::time::Duration;

use common::{PROCESS_SUSPEND_RESUME, busy_child, idle_child, open, process_times, toolhelp, wait_until};
use vigil_sys::process::{ProcessRow, ProcessSampler, ProcessStatus};
use windows::Win32::Foundation::{HANDLE, NTSTATUS};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSuspendProcess(process: HANDLE) -> NTSTATUS;
    fn NtResumeProcess(process: HANDLE) -> NTSTATUS;
}

fn find(rows: &[ProcessRow], pid: u32) -> Option<&ProcessRow> {
    rows.iter().find(|r| r.pid == pid)
}

#[test]
fn own_process_matches_independent_sources() {
    let mut sampler = ProcessSampler::new().expect("sampler");
    let rows = sampler.snapshot().expect("snapshot");
    let pid = std::process::id();
    let me = find(&rows, pid).expect("own process");
    let exe = std::env::current_exe().expect("exe");
    assert!(
        me.exe.eq_ignore_ascii_case(&exe.to_string_lossy()),
        "{} vs {}",
        me.exe,
        exe.display()
    );
    assert!(!me.user.is_empty());
    assert!(!me.cmdline.is_empty());
    assert_eq!(me.status, ProcessStatus::Running);
    let (ppid, threads) = toolhelp(pid).expect("toolhelp");
    assert_eq!(me.ppid, ppid);
    // The test harness starts and stops threads while it runs: allow a little drift.
    assert!(me.threads.abs_diff(threads) <= 8, "{} vs {threads}", me.threads);
    let (created_ms, _) = process_times(pid);
    assert!(
        (me.created_ms - created_ms).abs() < 1_000,
        "{} vs {created_ms}",
        me.created_ms
    );
    assert!(me.private_bytes > 0 && me.working_set > 0);
}

#[test]
fn snapshot_keys_are_unique_and_system_is_present() {
    let mut sampler = ProcessSampler::new().expect("sampler");
    let rows = sampler.snapshot().expect("snapshot");
    let keys: HashSet<(u32, i64)> = rows.iter().map(|r| (r.pid, r.created_ms)).collect();
    assert_eq!(keys.len(), rows.len());
    let system = find(&rows, 4).expect("System");
    assert!(!system.user.is_empty());
    assert!(
        rows.iter().all(|r| r.cpu == 0.0),
        "the first snapshot has no CPU rate yet"
    );
}

#[test]
fn child_process_is_named_and_parented() {
    let child = idle_child();
    let mut sampler = ProcessSampler::new().expect("sampler");
    let mut row = None;
    assert!(wait_until(Duration::from_secs(5), || {
        row = sampler
            .snapshot()
            .ok()
            .and_then(|rows| find(&rows, child.pid()).cloned());
        row.is_some()
    }));
    let row = row.expect("child row");
    assert_eq!(row.ppid, std::process::id());
    assert!(row.name.eq_ignore_ascii_case("PING.EXE"));
    assert!(row.exe.to_ascii_lowercase().ends_with(r"\system32\ping.exe"));
    assert!(row.cmdline.contains("127.0.0.1"));
}

#[test]
fn suspended_processes_are_detected() {
    let child = idle_child();
    let mut sampler = ProcessSampler::new().expect("sampler");
    assert!(wait_until(Duration::from_secs(5), || sampler
        .snapshot()
        .is_ok_and(|rows| find(&rows, child.pid()).is_some())));
    let handle = open(child.pid(), PROCESS_SUSPEND_RESUME);
    // SAFETY: valid handle with PROCESS_SUSPEND_RESUME access to our own child.
    assert!(unsafe { NtSuspendProcess(handle.0) }.is_ok());
    let suspended = wait_until(Duration::from_secs(5), || {
        sampler
            .snapshot()
            .is_ok_and(|rows| find(&rows, child.pid()).is_some_and(|r| r.status == ProcessStatus::Suspended))
    });
    // SAFETY: as above.
    assert!(unsafe { NtResumeProcess(handle.0) }.is_ok());
    assert!(suspended, "the suspended child was not reported as suspended");
    assert!(wait_until(Duration::from_secs(5), || {
        sampler
            .snapshot()
            .is_ok_and(|rows| find(&rows, child.pid()).is_some_and(|r| r.status == ProcessStatus::Running))
    }));
}

#[test]
fn cpu_is_measured_between_snapshots() {
    let child = busy_child();
    // PowerShell can take a while to start: wait until the loop really burns CPU.
    assert!(wait_until(Duration::from_secs(20), || process_times(child.pid()).1 > 2_000_000));
    let mut sampler = ProcessSampler::new().expect("sampler");
    let first = sampler.snapshot().expect("snapshot");
    assert_eq!(find(&first, child.pid()).expect("child").cpu, 0.0);
    sleep(Duration::from_millis(1_000));
    let second = sampler.snapshot().expect("snapshot");
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get()) as f32;
    let one_core = 100.0 / cores;
    let cpu = find(&second, child.pid()).expect("child").cpu;
    assert!(cpu > one_core / 3.0, "busy child at {cpu}% (one core = {one_core}%)");
    assert!(
        cpu <= one_core * 1.5 + 0.5,
        "busy child at {cpu}% (one core = {one_core}%)"
    );
}

#[test]
fn rows_serialize_in_camel_case() {
    let mut sampler = ProcessSampler::new().expect("sampler");
    let rows = sampler.snapshot().expect("snapshot");
    let json = serde_json::to_value(find(&rows, std::process::id()).expect("own process")).expect("json");
    for key in [
        "pid",
        "ppid",
        "privateBytes",
        "workingSet",
        "createdMs",
        "ioBps",
        "status",
    ] {
        assert!(json.get(key).is_some(), "missing {key}");
    }
    assert_eq!(json["status"], "running");
}
