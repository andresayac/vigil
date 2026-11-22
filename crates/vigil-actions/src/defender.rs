//! Microsoft Defender actions of the Protection page: quick and full scans that Vigil follows (with
//! cancel), the Microsoft Defender Offline scan, turning protection settings on, and removing the
//! active threats. Nothing here turns protection off: the only way back is History's undo of a
//! setting Vigil turned on, which restores the value it had.
//!
//! A scan runs as `MpCmdRun -Scan` in the background and the action returns at once, so the window
//! and other actions are never blocked for the hour a full scan can take. The app follows the
//! scan with [`scan_status`] / [`wait_running`] and reports its progress.

use std::cell::RefCell;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::sync::{Condvar, LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Value, json};

use crate::engine::{Builtin, Outcome, run_fn, undo_fn};
use crate::error::{ActionError, Result, fail};
use crate::params::Params;
use crate::runner::{first_line, ps_ok, run};
use crate::store::Store;
use vigil_i18n::tr;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Where Microsoft Defender's command-line tool lives (not checked: see `ops::mpcmdrun`).
pub(crate) fn mpcmdrun_path() -> String {
    let base = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
    format!("{base}\\Windows Defender\\MpCmdRun.exe")
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

// --------------------------------------------------------------------------- scans Vigil follows

/// A scan process Vigil started.
pub trait ScanProcess: Send {
    /// The exit code once the process ended; `None` while it runs.
    fn try_wait(&mut self) -> Option<i32>;
}

/// Starts the scan tool with these arguments (the first one is the program).
pub type ScanStarter = Rc<dyn Fn(&[String]) -> Result<Box<dyn ScanProcess>>>;

thread_local! {
    static STARTER: RefCell<Option<ScanStarter>> = const { RefCell::new(None) };
}

/// Replaces how scans are started, for the calling thread (tests record the call and hand back a
/// fake process); `None` starts the real tool again.
#[doc(hidden)]
pub fn set_scan_starter(starter: Option<ScanStarter>) {
    STARTER.with(|slot| *slot.borrow_mut() = starter);
}

struct SystemScan(Child);

impl ScanProcess for SystemScan {
    fn try_wait(&mut self) -> Option<i32> {
        match self.0.try_wait() {
            Ok(Some(status)) => Some(status.code().unwrap_or(-1)),
            Ok(None) => None,
            Err(_) => Some(-1),
        }
    }
}

fn start_process(args: &[String]) -> Result<Box<dyn ScanProcess>> {
    if let Some(starter) = STARTER.with(|slot| slot.borrow().clone()) {
        return starter(args);
    }
    let Some(program) = args.first() else {
        return fail(tr!("no program to run"));
    };
    if !Path::new(program).is_file() {
        return fail(tr!("Microsoft Defender's command-line tool was not found"));
    }
    let child = Command::new(program)
        .args(&args[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| ActionError::new(tr!("could not run {0}: {1}", "MpCmdRun.exe", crate::error::io_text(&e))))?;
    Ok(Box::new(SystemScan(child)))
}

/// What Vigil knows about the last scan it started.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanStatus {
    /// Counts the scans Vigil started in this session.
    pub id: u64,
    /// "quick" or "full".
    pub kind: String,
    pub started_ms: i64,
    pub running: bool,
    /// When Vigil saw it end (Unix ms; 0 while running).
    pub finished_ms: i64,
    /// MpCmdRun's exit code: 0 nothing needs attention, 2 a threat was found and not remediated
    /// or the scan hit an error.
    pub code: Option<i32>,
    /// Vigil asked Defender to stop it.
    pub cancelled: bool,
}

struct Job {
    status: ScanStatus,
    process: Option<Box<dyn ScanProcess>>,
}

#[derive(Default)]
struct Jobs {
    job: Option<Job>,
    next_id: u64,
}

static JOBS: LazyLock<(Mutex<Jobs>, Condvar)> = LazyLock::new(|| (Mutex::new(Jobs::default()), Condvar::new()));

fn jobs() -> MutexGuard<'static, Jobs> {
    JOBS.0.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Checks whether the process ended and returns the job's status.
fn refresh(jobs: &mut Jobs) -> Option<ScanStatus> {
    let job = jobs.job.as_mut()?;
    if job.status.running
        && let Some(process) = job.process.as_mut()
        && let Some(code) = process.try_wait()
    {
        job.status.running = false;
        job.status.code = Some(code);
        job.status.finished_ms = now_ms();
        job.process = None;
    }
    Some(job.status.clone())
}

/// The last scan Vigil started in this session, if any.
pub fn scan_status() -> Option<ScanStatus> {
    refresh(&mut jobs())
}

/// Waits until a scan Vigil started is running (at most `timeout`) and returns its status.
pub fn wait_running(timeout: Duration) -> Option<ScanStatus> {
    let (lock, ready) = &*JOBS;
    let guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut guard, _) = ready
        .wait_timeout_while(guard, timeout, |jobs| {
            !jobs.job.as_ref().is_some_and(|job| job.status.running)
        })
        .unwrap_or_else(PoisonError::into_inner);
    refresh(&mut guard).filter(|status| status.running)
}

/// Forgets the last scan (tests).
#[doc(hidden)]
pub fn reset_scan() {
    jobs().job = None;
}

/// Starts a quick or full scan in the background. Shared by `defender.quick_scan` and
/// `defender.full_scan`.
pub(crate) fn start_scan(kind: &str) -> Result<Outcome> {
    let scan_type = match kind {
        "quick" => "1",
        "full" => "2",
        _ => return fail(tr!("unknown scan type")),
    };
    let mut guard = jobs();
    if refresh(&mut guard).is_some_and(|status| status.running) {
        return fail(tr!("A Microsoft Defender scan Vigil started is still running."));
    }
    let args = [mpcmdrun_path(), "-Scan".into(), "-ScanType".into(), scan_type.into()];
    let process = start_process(&args)?;
    guard.next_id += 1;
    guard.job = Some(Job {
        status: ScanStatus {
            id: guard.next_id,
            kind: kind.to_string(),
            started_ms: now_ms(),
            running: true,
            ..ScanStatus::default()
        },
        process: Some(process),
    });
    drop(guard);
    JOBS.1.notify_all();
    Ok(Outcome::done(if kind == "quick" {
        tr!("started a quick Microsoft Defender scan; the Protection page shows its progress")
    } else {
        tr!(
            "started a full Microsoft Defender scan; it can take an hour or more. The Protection page shows its progress"
        )
    }))
}

fn op_quick_scan(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    start_scan("quick")
}

fn op_cancel_scan(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let result = run(vec![mpcmdrun_path(), "-Scan".into(), "-Cancel".into()], 120)?;
    if result.code != 0 {
        return fail(tr!(
            "Microsoft Defender did not stop the scan (code {0}): {1}",
            result.code,
            first_line(&result.text())
        ));
    }
    if let Some(job) = jobs().job.as_mut().filter(|job| job.status.running) {
        job.status.cancelled = true;
    }
    Ok(Outcome::done(tr!("asked Microsoft Defender to stop the scan")))
}

// --------------------------------------------------------------------------- offline scan

fn op_offline_scan(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    ps_ok(
        "Start-MpWDOScan",
        &tr!("starting the Microsoft Defender Offline scan"),
        300,
        &[],
    )?;
    Ok(Outcome::done(tr!(
        "Windows is restarting to run the Microsoft Defender Offline scan"
    )))
}

// --------------------------------------------------------------------------- settings

/// The settings that can be turned on: (key, Set-MpPreference parameter, value for "on", values
/// that already count as on).
const PREFERENCES: [(&str, &str, i64, &[i64]); 3] = [
    ("pua", "PUAProtection", 1, &[1]),
    ("cloud", "MAPSReporting", 2, &[1, 2]),
    ("samples", "SubmitSamplesConsent", 1, &[1, 3]),
];

/// Reads the setting, sets it unless it already counts as on (`PC_ON`, empty to always set),
/// and reads it again: Defender ignores changes that tamper protection or a policy manages.
const SET_PREFERENCE: &str = r#"
$name = "$env:PC_NAME"
$want = [int]$env:PC_VALUE
$was = [int]((Get-MpPreference).$name)
if ($env:PC_ON -and (@($env:PC_ON -split ',') -contains "$was")) {
    [pscustomobject]@{ status = 'already'; was = $was; now = $was } | ConvertTo-Json -Compress
    return
}
$set = @{ $name = $want }
Set-MpPreference @set
$now = [int]((Get-MpPreference).$name)
$status = if ($now -eq $want) { 'ok' } else { 'refused' }
[pscustomobject]@{ status = $status; was = $was; now = $now } | ConvertTo-Json -Compress
"#;

/// The setting's name in messages.
fn setting_name(key: &str) -> String {
    match key {
        "pua" => tr!("potentially unwanted app blocking"),
        "cloud" => tr!("cloud-delivered protection"),
        _ => tr!("automatic sample submission"),
    }
}

fn set_preference(name: &str, value: i64, on: &[i64], what: &str) -> Result<Value> {
    let on = on.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
    let value = value.to_string();
    let out = ps_ok(
        SET_PREFERENCE,
        what,
        180,
        &[("name", name), ("value", &value), ("on", &on)],
    )?;
    out.lines()
        .rev()
        .map(str::trim)
        .find(|line| line.starts_with('{'))
        .and_then(|line| serde_json::from_str::<Value>(line).ok())
        .ok_or_else(|| ActionError::new(tr!("{0} failed: unexpected answer from PowerShell", what)))
}

fn refused(key: &str) -> ActionError {
    ActionError::new(tr!(
        "Windows did not accept the change to {0}. Tamper protection or an organization's policy may manage it; use Windows Security.",
        setting_name(key)
    ))
}

fn op_preference_on(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let key = p.req_str("setting")?;
    let Some((key, name, value, on)) = PREFERENCES.iter().find(|(k, ..)| *k == key) else {
        return fail(tr!("Unknown Microsoft Defender setting: {0}", key));
    };
    let answer = set_preference(name, *value, on, &tr!("turning on {0}", setting_name(key)))?;
    let was = answer.get("was").and_then(Value::as_i64).unwrap_or(0);
    match answer.get("status").and_then(Value::as_str).unwrap_or("") {
        "already" => Ok(Outcome::done(tr!("{0} was already on", setting_name(key)))),
        "ok" => Ok(Outcome::new(
            tr!("turned on {0}", setting_name(key)),
            Some(json!({ "setting": key, "previous": was })),
        )),
        _ => Err(refused(key)),
    }
}

fn undo_preference(u: Params<'_>, _store: &Store) -> Result<String> {
    let key = u.req_str("setting")?;
    let Some((key, name, ..)) = PREFERENCES.iter().find(|(k, ..)| *k == key) else {
        return fail(tr!("Unknown Microsoft Defender setting: {0}", key));
    };
    let previous = u.get("previous").as_i64().unwrap_or(-1);
    if !(0..=4).contains(&previous) {
        return fail(tr!("The saved value is not valid."));
    }
    let answer = set_preference(name, previous, &[], &tr!("restoring {0}", setting_name(key)))?;
    if answer.get("status").and_then(Value::as_str) != Some("ok") {
        return Err(refused(key));
    }
    Ok(tr!("set {0} back to its previous value", setting_name(key)))
}

// --------------------------------------------------------------------------- threats

/// Defender's default action for every active threat, then how many are still active.
const REMOVE_THREATS: &str = r#"
Remove-MpThreat
@(Get-MpThreat | Where-Object { $_.IsActive }).Count
"#;

fn op_remove_threats(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let out = ps_ok(REMOVE_THREATS, &tr!("removing the active threats"), 900, &[])?;
    let left: u32 = out.lines().rev().find_map(|line| line.trim().parse().ok()).unwrap_or(0);
    if left > 0 {
        return Ok(Outcome::done(tr!(
            "Microsoft Defender acted on the active threats, but {0} still need attention; see Windows Security → Protection history",
            left
        )));
    }
    Ok(Outcome::done(tr!(
        "Microsoft Defender removed or quarantined the active threats"
    )))
}

pub(crate) fn builtin() -> Vec<Builtin> {
    vec![
        ("defender.quick_scan", run_fn(op_quick_scan), None, true),
        ("defender.cancel_scan", run_fn(op_cancel_scan), None, true),
        ("defender.offline_scan", run_fn(op_offline_scan), None, false),
        (
            "defender.preference_on",
            run_fn(op_preference_on),
            Some(undo_fn(undo_preference)),
            false,
        ),
        ("defender.remove_threats", run_fn(op_remove_threats), None, false),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every script these actions run is valid PowerShell (only parsed, never run).
    #[test]
    fn the_scripts_parse() {
        crate::testing::reset();
        let check = "$errors = $null; \
             [void][System.Management.Automation.Language.Parser]::ParseInput($env:PC_SCRIPT, [ref]$null, [ref]$errors); \
             ($errors | ForEach-Object { $_.Message }) -join ' / '";
        for script in [SET_PREFERENCE, REMOVE_THREATS] {
            let out = ps_ok(check, "parse", 120, &[("script", script)]).expect("powershell");
            assert_eq!(out, "", "{script}");
        }
    }
}
