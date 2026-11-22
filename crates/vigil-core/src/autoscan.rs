//! Automatic scans: the background watch runs a scan on a schedule (daily or weekly, at a time)
//! and turns what is new since the previous scan into alerts.
//!
//! - Off by default. The schedule lives with the watch settings in `watch.json`, so the copy in the
//!   tray and a window see the same one. Only the copy that owns the watch runs it.
//! - Local rules only: the AI is never used and VirusTotal is off. The scan runs on its own thread
//!   in background mode (lower CPU, disk and memory priority, efficiency mode where Windows has it),
//!   and the programs it starts run at below-normal priority.
//! - It waits while the computer runs on battery, a full-screen program or presentation runs, or
//!   the processor is busy; a missed time is caught up as soon as those are over, or at the next
//!   start. Slots from before the schedule was set are never run.
//! - Without administrator rights (the copy started in the tray at sign-in) the scan sees less;
//!   the report says so, and so do the alerts and the notification.
//! - Reports are saved like a normal scan (`scan-YYYYMMDD-HHMMSS-auto-report.json` in the data
//!   folder's `scans`), written under a temporary name and renamed, so a scan stopped halfway leaves
//!   nothing that looks like a report. At most [`KEEP`] automatic reports are kept: older ones are
//!   deleted by exact name, inside that folder, never through a link. Nothing else is changed.
//! - One automatic scan at a time on the computer (a named mutex), and the watch's per-minute checks
//!   never wait for it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use chrono::{Datelike, Duration as Span, Local, NaiveDateTime, NaiveTime, TimeZone};
use serde::{Deserialize, Serialize};
use serde_json::json;
use vigil_i18n::tr;
use vigil_scan::diff::ScanDiff;
use vigil_scan::model::{Analysis, Item};

use crate::watch::{Alert, WatchHost, WatchSettings, Watcher, alert, in_language, now_ms};

/// The most automatic reports kept in the scans folder.
pub const KEEP: usize = 10;
/// The most alerts one automatic scan adds (the rest are counted in one more alert).
const MAX_SCAN_ALERTS: usize = 8;
/// The processor counts as busy at this average use (percent) since the last check.
pub const BUSY_PERCENT: u64 = 60;
/// A processor sample older than this is not used (the next check takes a fresh one).
const SAMPLE_AGE: std::time::Duration = std::time::Duration::from_secs(180);
/// A last run further than this in the future (the clock was set back a long way) is ignored.
const FUTURE_SLACK_HOURS: i64 = 26;
/// Temporary files of a scan that was stopped are deleted after this long.
const STALE_TEMP_HOURS: u64 = 24;
const TEMP_PREFIX: &str = ".autoscan-";

/// Set when Vigil quits: the running scan stops at its next step.
static CANCEL: AtomicBool = AtomicBool::new(false);

/// Asks a running automatic scan to stop (Vigil is quitting).
pub fn cancel() {
    CANCEL.store(true, Ordering::Release);
}

// ------------------------------------------------------------------------------------ schedule

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schedule {
    Off,
    /// Every day at this minute of the day.
    Daily {
        minute: u32,
    },
    /// Every week on `day` (1 = Monday … 7 = Sunday) at this minute of the day.
    Weekly {
        day: u32,
        minute: u32,
    },
}

/// "13:05" -> 785. Invalid times are `None`.
pub fn parse_time(text: &str) -> Option<u32> {
    let (hours, minutes) = text.trim().split_once(':')?;
    let hours: u32 = hours.trim().parse().ok()?;
    let minutes: u32 = minutes.trim().parse().ok()?;
    (hours < 24 && minutes < 60).then_some(hours * 60 + minutes)
}

/// The time used when the saved one cannot be read.
pub const DEFAULT_MINUTE: u32 = 12 * 60 + 30;

impl Schedule {
    pub fn from_settings(settings: &WatchSettings) -> Self {
        let minute = parse_time(&settings.scan_time).unwrap_or(DEFAULT_MINUTE);
        match settings.scan_schedule.as_str() {
            "daily" => Self::Daily { minute },
            "weekly" => Self::Weekly {
                day: u32::from(settings.scan_day).clamp(1, 7),
                minute,
            },
            _ => Self::Off,
        }
    }

    /// A short text that changes whenever the schedule does ("weekly 3 13:05").
    pub fn key(&self) -> String {
        match self {
            Self::Off => "off".into(),
            Self::Daily { minute } => format!("daily {:02}:{:02}", minute / 60, minute % 60),
            Self::Weekly { day, minute } => format!("weekly {day} {:02}:{:02}", minute / 60, minute % 60),
        }
    }
}

fn at_minute(date: chrono::NaiveDate, minute: u32) -> Option<NaiveDateTime> {
    NaiveTime::from_hms_opt(minute / 60, minute % 60, 0).map(|time| date.and_time(time))
}

/// The newest scheduled moment at or before `now`, in local wall-clock time. Wall-clock time keeps
/// the schedule right across daylight saving changes: a time skipped in spring is run just after
/// the jump, and a time repeated in autumn runs once.
pub fn latest_slot(schedule: Schedule, now: NaiveDateTime) -> Option<NaiveDateTime> {
    match schedule {
        Schedule::Off => None,
        Schedule::Daily { minute } => {
            let today = at_minute(now.date(), minute)?;
            Some(if today <= now { today } else { today - Span::days(1) })
        }
        Schedule::Weekly { day, minute } => {
            let weekday = now.date().weekday().number_from_monday();
            let back = (weekday + 7 - day) % 7;
            let slot = at_minute(now.date() - Span::days(i64::from(back)), minute)?;
            Some(if slot <= now { slot } else { slot - Span::days(7) })
        }
    }
}

/// The next scheduled moment after `now` (shown in Settings and on the card).
pub fn next_slot(schedule: Schedule, now: NaiveDateTime) -> Option<NaiveDateTime> {
    let latest = latest_slot(schedule, now)?;
    Some(match schedule {
        Schedule::Weekly { .. } => latest + Span::days(7),
        _ => latest + Span::days(1),
    })
}

/// Whether a scan is due at `now`: the newest slot came after the last run and after the moment
/// the schedule was set. Times are local wall-clock times. A last run or arming time far in the
/// future (the clock was set back a long way) is ignored, so the schedule does not stall.
pub fn is_due(
    schedule: Schedule,
    now: NaiveDateTime,
    last_run: Option<NaiveDateTime>,
    armed: Option<NaiveDateTime>,
) -> bool {
    let Some(slot) = latest_slot(schedule, now) else {
        return false;
    };
    let plausible = |time: &NaiveDateTime| *time <= now + Span::hours(FUTURE_SLACK_HOURS);
    if armed.filter(plausible).is_some_and(|armed| armed > slot) {
        return false;
    }
    last_run.filter(plausible).is_none_or(|last| last < slot)
}

/// Milliseconds since 1970 as local wall-clock time.
pub fn local(ms: i64) -> Option<NaiveDateTime> {
    Local.timestamp_millis_opt(ms).single().map(|time| time.naive_local())
}

/// Local wall-clock time as milliseconds since 1970 (a time skipped by daylight saving moves on).
pub fn local_ms(time: NaiveDateTime) -> Option<i64> {
    Local
        .from_local_datetime(&time)
        .earliest()
        .or_else(|| Local.from_local_datetime(&(time + Span::hours(1))).earliest())
        .map(|time| time.timestamp_millis())
}

// ------------------------------------------------------------------------------------ saved state

/// What the watch remembers about automatic scans (in `watch.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct AutoScanState {
    /// The schedule the times below belong to ([`Schedule::key`]).
    pub schedule_key: String,
    /// When that schedule was set (ms since 1970): earlier slots are never run.
    pub armed: Option<i64>,
    /// When the last automatic scan ended, done or failed (ms since 1970).
    pub last_run: Option<i64>,
    /// "", "running", "done", "failed", "interrupted" or "postponed:<reason>" (battery,
    /// fullscreen, busy, other).
    pub status: String,
    /// The last report saved (empty when none).
    pub report: String,
    /// Findings of the last scan that deserve a look (new or changed, rated Remove or Disable).
    pub found: u32,
    /// The last scan ran without administrator rights.
    pub partial: bool,
    /// Why the last scan failed.
    pub error: String,
}

/// What the UI shows about automatic scans.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AutoScanView {
    /// "off", "daily" or "weekly".
    pub schedule: String,
    /// The next scheduled time (ms since 1970).
    pub next: Option<i64>,
    pub last_run: Option<i64>,
    pub status: String,
    pub found: u32,
    pub partial: bool,
    /// A report of the last automatic scan can be opened.
    pub report: bool,
    pub running: bool,
}

pub fn view(settings: &WatchSettings, state: &AutoScanState, running: bool) -> AutoScanView {
    let schedule = Schedule::from_settings(settings);
    let next = local(now_ms())
        .and_then(|now| next_slot(schedule, now))
        .and_then(local_ms);
    AutoScanView {
        schedule: match schedule {
            Schedule::Off => "off",
            Schedule::Daily { .. } => "daily",
            Schedule::Weekly { .. } => "weekly",
        }
        .into(),
        next,
        last_run: state.last_run,
        status: if running {
            "running".into()
        } else {
            state.status.clone()
        },
        found: state.found,
        partial: state.partial,
        report: !state.report.is_empty(),
        running,
    }
}

// ------------------------------------------------------------------------------------ waiting

/// What makes an automatic scan wait.
pub trait Conditions {
    /// Running on battery.
    fn on_battery(&self) -> bool;
    /// A full-screen program, a presentation or "do not disturb" is on.
    fn full_screen(&self) -> bool;
    /// The processor is busy (or not measured yet).
    fn busy(&self) -> bool;
}

/// Why a due scan waits: "battery", "fullscreen" or "busy"; `None` when it can run.
pub fn postpone_reason(conditions: &dyn Conditions) -> Option<&'static str> {
    if conditions.on_battery() {
        Some("battery")
    } else if conditions.full_screen() {
        Some("fullscreen")
    } else if conditions.busy() {
        Some("busy")
    } else {
        None
    }
}

/// Processor use between two samples of `GetSystemTimes` (idle, kernel + user), in percent.
pub fn cpu_percent(before: (u64, u64), after: (u64, u64)) -> Option<u64> {
    let idle = after.0.checked_sub(before.0)?;
    let total = after.1.checked_sub(before.1)?;
    (total > 0).then(|| 100 - (idle.min(total) * 100 / total))
}

/// The real conditions of this computer.
#[derive(Default)]
pub struct SystemConditions {
    /// The last processor sample and when it was taken.
    sample: Mutex<Option<(Instant, (u64, u64))>>,
}

fn filetime(time: windows::Win32::Foundation::FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

fn system_times() -> Option<(u64, u64)> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetSystemTimes;
    let (mut idle, mut kernel, mut user) = (FILETIME::default(), FILETIME::default(), FILETIME::default());
    // SAFETY: three valid out pointers to FILETIME values on the stack.
    unsafe { GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)) }.ok()?;
    // Kernel time includes the idle time.
    Some((filetime(idle), filetime(kernel) + filetime(user)))
}

impl SystemConditions {
    /// Takes a processor sample (each watch check, so a due scan has a recent one to compare with).
    pub fn sample(&self) {
        let _ = self.measure();
    }

    /// The use since the previous sample, and keeps the new one.
    fn measure(&self) -> Option<u64> {
        let now = system_times()?;
        let mut sample = self.sample.lock().unwrap_or_else(PoisonError::into_inner);
        let previous = sample.replace((Instant::now(), now));
        let (taken, before) = previous?;
        if taken.elapsed() > SAMPLE_AGE {
            return None;
        }
        cpu_percent(before, now)
    }
}

impl Conditions for SystemConditions {
    fn on_battery(&self) -> bool {
        use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
        let mut status = SYSTEM_POWER_STATUS::default();
        // SAFETY: a valid out pointer to a SYSTEM_POWER_STATUS on the stack.
        if unsafe { GetSystemPowerStatus(&mut status) }.is_err() {
            return false;
        }
        // 0: on battery; 1: plugged in; 255: unknown (desktops).
        status.ACLineStatus == 0
    }

    fn full_screen(&self) -> bool {
        use windows::Win32::UI::Shell::{
            QUNS_BUSY, QUNS_PRESENTATION_MODE, QUNS_RUNNING_D3D_FULL_SCREEN, SHQueryUserNotificationState,
        };
        // SAFETY: no arguments; it returns the state of the signed-in user's session.
        match unsafe { SHQueryUserNotificationState() } {
            Ok(state) => [QUNS_BUSY, QUNS_RUNNING_D3D_FULL_SCREEN, QUNS_PRESENTATION_MODE].contains(&state),
            Err(_) => false,
        }
    }

    fn busy(&self) -> bool {
        // No recent sample yet: wait for the next check, which will have one.
        self.measure().is_none_or(|percent| percent >= BUSY_PERCENT)
    }
}

// ------------------------------------------------------------------------------------ files

/// `scan-YYYYMMDD-HHMMSS-auto` from one of its files' names (report, HTML report, inventory).
pub fn auto_stem(name: &str) -> Option<&str> {
    let stem = ["-report.json", "-report.html", "-inventory.json"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))?;
    let rest = stem.strip_prefix("scan-")?.strip_suffix("-auto")?;
    let (date, time) = rest.split_once('-')?;
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    (digits(date, 8) && digits(time, 6)).then_some(stem)
}

/// Whether `name` is the report file of an automatic scan.
pub fn is_auto_report(name: &str) -> bool {
    name.ends_with("-report.json") && auto_stem(name).is_some()
}

fn is_plain(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const REPARSE: u32 = 0x400; // FILE_ATTRIBUTE_REPARSE_POINT
    meta.file_attributes() & REPARSE == 0
}

/// A plain folder (not a junction or a link).
fn plain_folder(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir() && is_plain(&meta))
}

/// Deletes the files of all but the newest `keep` automatic scans in `dir`, and temporary files a
/// stopped scan left behind. Only files named like Vigil's own automatic reports, directly in
/// `dir`, never through a link (a folder that is a link is left alone). Returns how many files
/// were deleted.
pub fn prune(dir: &Path, keep: usize) -> usize {
    if !plain_folder(dir) {
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    let mut stale: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !meta.is_file() || !is_plain(&meta) {
            continue;
        }
        if let Some(stem) = auto_stem(&name) {
            files.push((stem.to_string(), entry.path()));
        } else if name.starts_with(TEMP_PREFIX)
            && meta
                .modified()
                .ok()
                .and_then(|m| m.elapsed().ok())
                .is_some_and(|age| age.as_secs() > STALE_TEMP_HOURS * 3600)
        {
            stale.push(entry.path());
        }
    }
    let mut stems: Vec<&String> = files.iter().map(|(stem, _)| stem).collect();
    stems.sort();
    stems.dedup();
    let cut = stems.len().saturating_sub(keep);
    let old: Vec<String> = stems.into_iter().take(cut).cloned().collect();
    let mut deleted = 0;
    for path in files
        .iter()
        .filter(|(stem, _)| old.contains(stem))
        .map(|(_, path)| path)
        .chain(stale.iter())
    {
        if std::fs::remove_file(path).is_ok() {
            deleted += 1;
        }
    }
    deleted
}

/// The report of an automatic scan may be opened from `path`: the right name, directly in one of
/// `folders`, a plain file in a plain folder. The path comes from Vigil's own saved state, which
/// lives in the user's folder, so it is checked before an elevated window reads it.
pub fn check_report_path(path: &Path, folders: &[PathBuf]) -> Result<(), String> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let parent = path.parent().unwrap_or(Path::new(""));
    let same = |a: &Path, b: &Path| a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase();
    let known = folders.iter().any(|folder| same(parent, folder));
    let plain_file = std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && is_plain(&meta));
    if is_auto_report(name) && known && plain_folder(parent) && plain_file {
        Ok(())
    } else {
        Err(tr!("The report of the last automatic scan is no longer there."))
    }
}

// ------------------------------------------------------------------------------------ alerts

/// Alerts for an automatic scan: the findings rated Remove or Disable that are new or changed since
/// the previous scan (all of them for a first scan), and security settings that changed. `ignored`
/// says which findings the user chose to ignore. Returns the alerts and how many findings deserve a
/// look.
pub fn scan_alerts(analysis: &Analysis, diff: Option<&ScanDiff>, ignored: &dyn Fn(&Item) -> bool) -> (Vec<Alert>, u32) {
    let worth = |item: &&Item| matches!(item.verdict.as_str(), "remove" | "disable") && !ignored(item);
    let mut alerts = Vec::new();
    let Some(diff) = diff else {
        let count = analysis.items.iter().filter(worth).count();
        if count > 0 {
            alerts.push(alert(
                "scan",
                "warning",
                "findings",
                tr!("First automatic scan: {0} findings to look at", count),
                tr!("There is no earlier scan to compare with; open the report to see them."),
            ));
        }
        return (alerts, u32::try_from(count).unwrap_or(u32::MAX));
    };
    let changed: std::collections::BTreeMap<&str, &Vec<String>> =
        diff.changed.iter().map(|c| (c.id.as_str(), &c.what)).collect();
    let flagged: Vec<&Item> = analysis
        .items
        .iter()
        .filter(worth)
        .filter(|item| diff.new.contains(&item.id) || changed.contains_key(item.id.as_str()))
        .collect();
    for item in flagged.iter().take(MAX_SCAN_ALERTS) {
        let severity = if item.verdict == "remove" {
            "critical"
        } else {
            "warning"
        };
        let (title, detail) = match changed.get(item.id.as_str()) {
            Some(what) => (
                tr!("Changed since the last scan: {0}", item.title),
                shorten(&what.join(" "), 300),
            ),
            None => (
                tr!("New since the last scan: {0}", item.title),
                shorten(
                    if item.reason.is_empty() {
                        &item.what
                    } else {
                        &item.reason
                    },
                    300,
                ),
            ),
        };
        alerts.push(alert("scan", severity, "findings", title, detail));
    }
    if flagged.len() > MAX_SCAN_ALERTS {
        alerts.push(alert(
            "scan",
            "info",
            "findings",
            tr!(
                "{0} more findings in the automatic scan",
                flagged.len() - MAX_SCAN_ALERTS
            ),
            tr!("Open the report to see them all."),
        ));
    }
    if !diff.posture.is_empty() {
        alerts.push(alert(
            "scan",
            "warning",
            "findings",
            tr!("Security settings changed since the last scan"),
            shorten(&diff.posture.join("; "), 300),
        ));
    }
    (alerts, u32::try_from(flagged.len()).unwrap_or(u32::MAX))
}

fn shorten(text: &str, max: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        format!("{}…", flat.chars().take(max).collect::<String>())
    }
}

/// The notification for a scan that found something: (title, body). Says when coverage was partial.
pub fn toast(alerts: &[Alert], found: u32, partial: bool) -> (String, String) {
    let title = if found > 0 {
        tr!("Automatic scan: {0} findings to look at", found)
    } else {
        tr!("Automatic scan: security settings changed")
    };
    let mut lines: Vec<String> = alerts
        .iter()
        .filter(|a| a.severity != "info")
        .take(3)
        .map(|a| a.title.clone())
        .collect();
    if partial {
        lines.push(tr!(
            "Vigil ran without administrator rights, so some places were not checked."
        ));
    }
    (title, lines.join("\n"))
}

// ------------------------------------------------------------------------------------ running

/// One automatic scan at a time on this computer, whichever copy of Vigil runs it.
struct ScanLock(windows::Win32::Foundation::HANDLE);

impl ScanLock {
    fn take(name: &str) -> Option<Self> {
        use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError};
        use windows::Win32::System::Threading::CreateMutexW;
        let name = windows::core::HSTRING::from(name);
        // SAFETY: plain Win32 call with a valid name; the handle is owned by the returned value.
        let handle = unsafe { CreateMutexW(None, true, &name) }.ok()?;
        // SAFETY: reads this thread's last error, set by CreateMutexW just above.
        if handle.is_invalid() || unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            if !handle.is_invalid() {
                // SAFETY: the handle was just returned and is not used again.
                let _ = unsafe { CloseHandle(handle) };
            }
            return None;
        }
        Some(Self(handle))
    }
}

impl Drop for ScanLock {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::ReleaseMutex;
        // SAFETY: this value owns the mutex (created as its initial owner) and its handle.
        unsafe {
            let _ = ReleaseMutex(self.0);
            let _ = CloseHandle(self.0);
        }
    }
}

const LOCK_NAME: &str = "Local\\Vigil.AutoScan";

/// Lower priority for the scan: this thread goes to background mode (and efficiency mode where
/// Windows has it), and the process runs below normal while the scan lasts, so the programs the
/// collectors start do too. Restores the process priority when dropped.
struct Background {
    restore: bool,
}

impl Background {
    fn begin() -> Self {
        use windows::Win32::System::Threading::{
            BELOW_NORMAL_PRIORITY_CLASS, GetCurrentProcess, GetCurrentThread, GetPriorityClass, NORMAL_PRIORITY_CLASS,
            SetPriorityClass, SetThreadInformation, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN,
            THREAD_POWER_THROTTLING_CURRENT_VERSION, THREAD_POWER_THROTTLING_EXECUTION_SPEED,
            THREAD_POWER_THROTTLING_STATE, ThreadPowerThrottling,
        };
        // SAFETY: pseudo-handles of the current thread and process; the throttling state is a
        // valid struct on the stack whose size is passed along.
        unsafe {
            let _ = SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
            let state = THREAD_POWER_THROTTLING_STATE {
                Version: THREAD_POWER_THROTTLING_CURRENT_VERSION,
                ControlMask: THREAD_POWER_THROTTLING_EXECUTION_SPEED,
                StateMask: THREAD_POWER_THROTTLING_EXECUTION_SPEED,
            };
            let _ = SetThreadInformation(
                GetCurrentThread(),
                ThreadPowerThrottling,
                std::ptr::from_ref(&state).cast(),
                u32::try_from(std::mem::size_of::<THREAD_POWER_THROTTLING_STATE>()).unwrap_or(0),
            );
            let process = GetCurrentProcess();
            let restore = GetPriorityClass(process) == NORMAL_PRIORITY_CLASS.0
                && SetPriorityClass(process, BELOW_NORMAL_PRIORITY_CLASS).is_ok();
            Self { restore }
        }
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        use windows::Win32::System::Threading::{
            GetCurrentProcess, GetCurrentThread, NORMAL_PRIORITY_CLASS, SetPriorityClass, SetThreadPriority,
            THREAD_MODE_BACKGROUND_END,
        };
        // SAFETY: pseudo-handles of the current thread and process.
        unsafe {
            let _ = SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
            if self.restore {
                let _ = SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
            }
        }
    }
}

/// What a finished automatic scan produced.
pub struct Outcome {
    pub report: PathBuf,
    pub analysis: Analysis,
    pub diff: Option<ScanDiff>,
    pub partial: bool,
}

/// Why a scan did not run or did not finish.
pub enum Failure {
    /// Another automatic scan runs (in this or another copy of Vigil).
    Busy,
    Failed(String),
}

/// Runs one automatic scan into `dir` (the data folder's `scans`) and saves its report.
pub fn run_scan(dir: &Path) -> Result<Outcome, Failure> {
    let Some(_lock) = ScanLock::take(LOCK_NAME) else {
        return Err(Failure::Busy);
    };
    let _background = Background::begin();
    let root = dir.parent().unwrap_or(dir);
    let days = crate::settings::Stored::load(&root.join("settings.json"))
        .days
        .clamp(1, 365);
    let quiet = |_: &str| {};
    let (_, mut analysis) =
        vigil_scan::collect_and_analyze(days, None, &quiet, &CANCEL).map_err(|e| Failure::Failed(e.to_string()))?;
    if CANCEL.load(Ordering::Acquire) {
        return Err(Failure::Failed(tr!("Vigil was closed during the scan")));
    }
    let mut ai = serde_json::Map::new();
    ai.insert("reason".into(), json!(tr!("automatic scans use the local rules only")));
    analysis.ai = ai;
    analysis.meta.insert("trigger".into(), json!("automatic"));
    let partial = !vigil_actions::is_admin();
    std::fs::create_dir_all(dir).map_err(|e| Failure::Failed(e.to_string()))?;
    let stamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
    let base = dir.join(format!("scan-{stamp}-auto"));
    let diff = vigil_scan::pipeline::attach_changes(&mut analysis, &base);
    let report = save(&analysis, dir, &stamp).map_err(Failure::Failed)?;
    prune(dir, KEEP);
    Ok(Outcome {
        report,
        analysis,
        diff,
        partial,
    })
}

/// Saves the report under a temporary name, then renames it, so a scan stopped halfway never leaves
/// a file that looks like a report.
fn save(analysis: &Analysis, dir: &Path, stamp: &str) -> Result<PathBuf, String> {
    let temp = dir.join(format!("{TEMP_PREFIX}{stamp}"));
    let (written, _) = vigil_scan::pipeline::save_report(analysis, &temp, false).map_err(|e| e.to_string())?;
    let report = dir.join(format!("scan-{stamp}-auto-report.json"));
    if let Err(error) = std::fs::rename(&written, &report) {
        let _ = std::fs::remove_file(&written);
        return Err(error.to_string());
    }
    Ok(report)
}

/// Brings the saved state up to date before a check: a schedule that changed is armed now (its
/// earlier slots are never run) and forgets that it was waiting; a scan saved as running that this
/// copy no longer runs (Vigil was closed during it) becomes "interrupted".
pub fn arm(auto: &mut AutoScanState, key: &str, now: i64, running: bool) {
    if auto.schedule_key != key {
        auto.schedule_key = key.to_string();
        auto.armed = Some(now);
        if auto.status.starts_with("postponed") {
            auto.status.clear();
        }
    }
    if auto.status == "running" && !running {
        auto.status = "interrupted".into();
    }
}

/// Called after each watch check by the copy that owns the watch: arms a changed schedule, and
/// starts the scan when it is due and nothing makes it wait. The scan runs on its own thread.
pub fn tick(watcher: &Arc<Watcher>, host: &Arc<dyn WatchHost>) {
    watcher.conditions.sample();
    let Some(dir) = watcher.scans.get().cloned() else {
        return;
    };
    let settings = watcher.settings();
    let schedule = Schedule::from_settings(&settings);
    let now = now_ms();
    let running = watcher.scan_running.load(Ordering::Acquire);
    let key = schedule.key();
    let state = watcher.store.update(|file| {
        arm(&mut file.auto_scan, &key, now, running);
        file.auto_scan.clone()
    });
    let Ok(state) = state else {
        return;
    };
    if running || schedule == Schedule::Off {
        return;
    }
    let (Some(now_local), last, armed) = (local(now), state.last_run.and_then(local), state.armed.and_then(local))
    else {
        return;
    };
    if !is_due(schedule, now_local, last, armed) {
        return;
    }
    if let Some(reason) = postpone_reason(&watcher.conditions) {
        let status = format!("postponed:{reason}");
        let _ = watcher.store.update(|file| file.auto_scan.status = status);
        return;
    }
    start(watcher, host, dir);
}

fn start(watcher: &Arc<Watcher>, host: &Arc<dyn WatchHost>, dir: PathBuf) {
    if watcher.scan_running.swap(true, Ordering::AcqRel) {
        return;
    }
    let _ = watcher.store.update(|file| file.auto_scan.status = "running".into());
    host.changed(&watcher.status());
    let worker = Arc::clone(watcher);
    let host = Arc::clone(host);
    let spawned = std::thread::Builder::new()
        .name("vigil-autoscan".into())
        .spawn(move || {
            crate::notify::init_thread();
            let language = worker.language();
            in_language(&language, || finish(&worker, &*host, run_scan(&dir)));
            worker.scan_running.store(false, Ordering::Release);
            host.changed(&worker.status());
        });
    if spawned.is_err() {
        watcher.scan_running.store(false, Ordering::Release);
        let _ = watcher.store.update(|file| file.auto_scan.status = "failed".into());
    }
}

/// Records the result: alerts for what deserves a look, the state, and one notification.
fn finish(watcher: &Watcher, host: &dyn WatchHost, result: Result<Outcome, Failure>) {
    let now = now_ms();
    match result {
        Ok(outcome) => {
            let root = outcome.report.parent().and_then(Path::parent).map(Path::to_path_buf);
            let ignored = root.map(|root| crate::settings::Ignored::load(root.join("ignored.json")));
            let is_ignored = |item: &Item| {
                ignored.as_ref().is_some_and(|list| {
                    list.contains(&crate::settings::item_key(
                        &item.kind,
                        item.path.as_deref(),
                        &item.title,
                    ))
                })
            };
            let (alerts, found) = scan_alerts(&outcome.analysis, outcome.diff.as_ref(), &is_ignored);
            let report = outcome.report.display().to_string();
            let saved = watcher.store.update(|file| {
                let added = file.add_alerts(alerts, now);
                file.auto_scan.last_run = Some(now);
                file.auto_scan.status = "done".into();
                file.auto_scan.report = report;
                file.auto_scan.found = found;
                file.auto_scan.partial = outcome.partial;
                file.auto_scan.error.clear();
                (added, file.notifications_paused(now))
            });
            if let Ok((added, paused)) = saved
                && !added.is_empty()
                && !paused
            {
                let (title, body) = toast(&added, found, outcome.partial);
                host.notify(&title, &body, "alerts");
            }
        }
        Err(Failure::Busy) => {
            let _ = watcher
                .store
                .update(|file| file.auto_scan.status = "postponed:other".into());
        }
        Err(Failure::Failed(error)) => {
            let _ = watcher.store.update(|file| {
                file.auto_scan.last_run = Some(now);
                file.auto_scan.status = "failed".into();
                file.auto_scan.error = shorten(&error, 300);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, mo, d)
            .and_then(|date| date.and_hms_opt(h, mi, 0))
            .expect("valid date")
    }

    const DAILY: Schedule = Schedule::Daily { minute: 12 * 60 + 30 };

    #[test]
    fn times_are_parsed_and_checked() {
        assert_eq!(parse_time("12:30"), Some(750));
        assert_eq!(parse_time(" 0:05 "), Some(5));
        assert_eq!(parse_time("23:59"), Some(1439));
        for bad in ["24:00", "12:60", "noon", "", "12"] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
        let mut settings = WatchSettings::default();
        assert_eq!(Schedule::from_settings(&settings), Schedule::Off, "off by default");
        settings.scan_schedule = "weekly".into();
        settings.scan_day = 9;
        settings.scan_time = "bad".into();
        assert_eq!(
            Schedule::from_settings(&settings),
            Schedule::Weekly {
                day: 7,
                minute: DEFAULT_MINUTE
            }
        );
        assert_eq!(Schedule::from_settings(&settings).key(), "weekly 7 12:30");
    }

    #[test]
    fn daily_slots() {
        assert_eq!(
            latest_slot(DAILY, at(2026, 11, 20, 13, 0)),
            Some(at(2026, 11, 20, 12, 30))
        );
        assert_eq!(
            latest_slot(DAILY, at(2026, 11, 20, 12, 30)),
            Some(at(2026, 11, 20, 12, 30))
        );
        assert_eq!(
            latest_slot(DAILY, at(2026, 11, 20, 9, 0)),
            Some(at(2026, 11, 19, 12, 30))
        );
        assert_eq!(
            next_slot(DAILY, at(2026, 11, 20, 13, 0)),
            Some(at(2026, 11, 21, 12, 30))
        );
        assert_eq!(latest_slot(Schedule::Off, at(2026, 11, 20, 13, 0)), None);
    }

    #[test]
    fn weekly_slots() {
        // 2026-11-20 is a Friday (5); Monday (1) at 08:00.
        let monday = Schedule::Weekly { day: 1, minute: 8 * 60 };
        assert_eq!(
            latest_slot(monday, at(2026, 11, 20, 13, 0)),
            Some(at(2026, 11, 16, 8, 0))
        );
        assert_eq!(
            latest_slot(monday, at(2026, 11, 23, 7, 59)),
            Some(at(2026, 11, 16, 8, 0))
        );
        assert_eq!(
            latest_slot(monday, at(2026, 11, 23, 8, 0)),
            Some(at(2026, 11, 23, 8, 0))
        );
        assert_eq!(next_slot(monday, at(2026, 11, 20, 13, 0)), Some(at(2026, 11, 23, 8, 0)));
        let friday = Schedule::Weekly {
            day: 5,
            minute: 14 * 60,
        };
        assert_eq!(
            latest_slot(friday, at(2026, 11, 20, 13, 0)),
            Some(at(2026, 11, 13, 14, 0))
        );
        assert_eq!(
            latest_slot(friday, at(2026, 11, 20, 15, 0)),
            Some(at(2026, 11, 20, 14, 0))
        );
    }

    #[test]
    fn due_runs_once_per_slot_and_catches_up() {
        let armed = Some(at(2026, 11, 1, 9, 0));
        // Never ran: the newest slot is due.
        assert!(is_due(DAILY, at(2026, 11, 20, 13, 0), None, armed));
        // Ran after the slot: not again until the next one.
        let ran = Some(at(2026, 11, 20, 12, 40));
        assert!(!is_due(DAILY, at(2026, 11, 20, 23, 0), ran, armed));
        assert!(!is_due(DAILY, at(2026, 11, 21, 12, 29), ran, armed));
        assert!(is_due(DAILY, at(2026, 11, 21, 12, 30), ran, armed));
        // The computer was off for days: one catch-up scan at the next chance, not one per day.
        assert!(is_due(DAILY, at(2026, 11, 25, 8, 0), ran, armed));
        let caught_up = Some(at(2026, 11, 25, 8, 1));
        assert!(!is_due(DAILY, at(2026, 11, 25, 9, 0), caught_up, armed));
        // Before the first slot: nothing.
        assert!(!is_due(Schedule::Off, at(2026, 11, 20, 13, 0), None, armed));
    }

    #[test]
    fn a_new_schedule_waits_for_its_first_slot() {
        // Set at 15:00 for 12:30: today's slot is gone, the first one is tomorrow.
        let armed = Some(at(2026, 11, 20, 15, 0));
        assert!(!is_due(DAILY, at(2026, 11, 20, 15, 1), None, armed));
        assert!(!is_due(DAILY, at(2026, 11, 21, 12, 29), None, armed));
        assert!(is_due(DAILY, at(2026, 11, 21, 12, 30), None, armed));
    }

    #[test]
    fn clock_changes_do_not_stall_or_repeat() {
        let armed = Some(at(2026, 11, 1, 9, 0));
        // Set back by an hour right after a scan: the run looks one hour ahead; no second scan.
        let ran = Some(at(2026, 11, 20, 12, 31));
        assert!(!is_due(DAILY, at(2026, 11, 20, 11, 45), ran, armed));
        // A last run far in the future (the clock was wrong): it no longer blocks the schedule.
        let wrong = Some(at(2027, 6, 1, 12, 0));
        assert!(is_due(DAILY, at(2026, 11, 20, 13, 0), wrong, armed));
        // The same for an arming time far in the future.
        assert!(is_due(DAILY, at(2026, 11, 20, 13, 0), None, Some(at(2027, 6, 1, 0, 0))));
    }

    #[test]
    fn daylight_saving_changes() {
        // Spring forward (02:00 -> 03:00): a 02:30 slot never shows on the clock; it is run just
        // after the jump, once.
        let night = Schedule::Daily { minute: 2 * 60 + 30 };
        let armed = Some(at(2026, 3, 1, 0, 0));
        let before = Some(at(2026, 3, 28, 2, 31));
        assert!(is_due(night, at(2026, 3, 29, 3, 0), before, armed));
        assert!(!is_due(
            night,
            at(2026, 3, 29, 3, 5),
            Some(at(2026, 3, 29, 3, 1)),
            armed
        ));
        // Fall back (03:00 -> 02:00): 02:30 shows twice; the scan run at the first one is not
        // repeated at the second.
        let first = Some(at(2026, 10, 25, 2, 31));
        assert!(!is_due(night, at(2026, 10, 25, 2, 10), first, armed));
        assert!(!is_due(night, at(2026, 10, 25, 2, 40), first, armed));
    }

    struct Fake {
        battery: bool,
        full: bool,
        busy: bool,
    }

    impl Conditions for Fake {
        fn on_battery(&self) -> bool {
            self.battery
        }
        fn full_screen(&self) -> bool {
            self.full
        }
        fn busy(&self) -> bool {
            self.busy
        }
    }

    #[test]
    fn postpone_rules() {
        let calm = Fake {
            battery: false,
            full: false,
            busy: false,
        };
        assert_eq!(postpone_reason(&calm), None);
        assert_eq!(postpone_reason(&Fake { battery: true, ..calm }), Some("battery"));
        assert_eq!(postpone_reason(&Fake { full: true, ..calm }), Some("fullscreen"));
        assert_eq!(postpone_reason(&Fake { busy: true, ..calm }), Some("busy"));
        assert_eq!(
            postpone_reason(&Fake {
                battery: true,
                full: true,
                busy: true
            }),
            Some("battery")
        );
    }

    #[test]
    fn processor_use() {
        // 1000 ticks, 250 idle: 75 % used.
        assert_eq!(cpu_percent((100, 1000), (350, 2000)), Some(75));
        assert_eq!(cpu_percent((100, 1000), (1100, 2000)), Some(0));
        assert_eq!(cpu_percent((100, 1000), (100, 1000)), None, "no time passed");
        assert_eq!(cpu_percent((500, 2000), (100, 1000)), None, "counters went back");
        // A first measurement has nothing to compare with: busy, wait for the next check.
        let conditions = SystemConditions::default();
        assert!(conditions.busy());
    }

    #[test]
    fn report_names() {
        assert_eq!(
            auto_stem("scan-20261120-123000-auto-report.json"),
            Some("scan-20261120-123000-auto")
        );
        assert_eq!(
            auto_stem("scan-20261120-123000-auto-inventory.json"),
            Some("scan-20261120-123000-auto")
        );
        assert!(is_auto_report("scan-20261120-123000-auto-report.json"));
        for other in [
            "scan-20261120-123000-report.json",
            "scan-20261120-12300-auto-report.json",
            "scan-2026112a-123000-auto-report.json",
            "scan-20261120-123000-auto-report.json.bak",
            "notes-20261120-123000-auto-report.json",
            "scan-20261120-123000-auto-inventory.json.txt",
        ] {
            assert!(!is_auto_report(other), "{other}");
        }
        assert!(!is_auto_report("scan-20261120-123000-auto-inventory.json"));
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("vigil-autoscan-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("temp folder");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn prune_keeps_the_newest_and_touches_nothing_else() {
        let dir = TempDir::new("prune");
        let write = |name: &str| std::fs::write(dir.0.join(name), b"{}").expect("write");
        for day in 10..=14 {
            write(&format!("scan-202611{day}-120000-auto-report.json"));
        }
        write("scan-20261110-120000-auto-inventory.json");
        write("scan-20261101-090000-report.json"); // a scan the user ran: never touched
        write("notes.txt");
        write("scan-20261101-090000-auto-report.json.keep");
        let deleted = prune(&dir.0, 3);
        assert_eq!(deleted, 3, "two oldest reports and the inventory of the oldest");
        let mut left: Vec<String> = std::fs::read_dir(&dir.0)
            .expect("list")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "notes.txt",
                "scan-20261101-090000-auto-report.json.keep",
                "scan-20261101-090000-report.json",
                "scan-20261112-120000-auto-report.json",
                "scan-20261113-120000-auto-report.json",
                "scan-20261114-120000-auto-report.json",
            ]
        );
    }

    #[test]
    fn prune_never_follows_links() {
        let outside = TempDir::new("outside");
        std::fs::write(outside.0.join("scan-20261101-120000-auto-report.json"), b"{}").expect("write");
        let dir = TempDir::new("linked");
        let link = dir.0.join("scans");
        // A junction needs no privilege (unlike a symbolic link).
        let mklink = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join(r"System32\cmd.exe");
        let made = std::process::Command::new(mklink)
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside.0)
            .output()
            .is_ok_and(|o| o.status.success());
        if made {
            assert_eq!(prune(&link, 0), 0, "a folder that is a link is left alone");
            assert!(outside.0.join("scan-20261101-120000-auto-report.json").exists());
            let _ = std::fs::remove_dir(&link);
        }
        // A missing folder: nothing to do.
        assert_eq!(prune(&dir.0.join("missing"), 0), 0);
    }

    #[test]
    fn only_a_checked_path_opens() {
        let dir = TempDir::new("open");
        let report = dir.0.join("scan-20261120-123000-auto-report.json");
        std::fs::write(&report, b"{}").expect("write");
        let folders = vec![dir.0.clone()];
        assert!(check_report_path(&report, &folders).is_ok());
        assert!(
            check_report_path(&report, &[std::env::temp_dir()]).is_err(),
            "another folder"
        );
        let other = dir.0.join("scan-20261120-123000-report.json");
        std::fs::write(&other, b"{}").expect("write");
        assert!(check_report_path(&other, &folders).is_err(), "not an automatic report");
        assert!(
            check_report_path(&dir.0.join("scan-20261121-123000-auto-report.json"), &folders).is_err(),
            "missing"
        );
    }

    #[test]
    fn one_scan_at_a_time() {
        let name = format!("Local\\Vigil.AutoScan.Test.{}", std::process::id());
        let first = ScanLock::take(&name);
        assert!(first.is_some());
        assert!(ScanLock::take(&name).is_none(), "taken");
        drop(first);
        assert!(ScanLock::take(&name).is_some(), "free again");
    }

    fn item(id: &str, verdict: &str, title: &str) -> Item {
        let mut item = Analysis::from_value(&json!({"items": [{"id": id, "title": title, "kind": "file"}]}))
            .items
            .remove(0);
        item.verdict = verdict.into();
        item.reason = format!("why {title}");
        item
    }

    fn analysis(items: Vec<Item>) -> Analysis {
        let mut analysis = Analysis::from_value(&json!({"items": []}));
        analysis.items = items;
        analysis
    }

    #[test]
    fn new_and_changed_findings_become_alerts() {
        let current = analysis(vec![
            item("1", "remove", "winupd.exe"),
            item("2", "disable", "helper.exe"),
            item("3", "review", "tool.exe"),
            item("4", "remove", "old.exe"),
            item("5", "remove", "ignored.exe"),
        ]);
        let diff = ScanDiff {
            new: vec!["1".into(), "3".into(), "5".into()],
            changed: vec![vigil_scan::diff::Changed {
                id: "2".into(),
                what: vec!["The verdict went from Review to Disable.".into()],
            }],
            posture: vec!["Real-time protection: on → off".into()],
            ..ScanDiff::default()
        };
        let ignored = |item: &Item| item.title == "ignored.exe";
        let (alerts, found) = scan_alerts(&current, Some(&diff), &ignored);
        assert_eq!(found, 2, "Remove and Disable only; unchanged and ignored ones left out");
        assert!(alerts.iter().all(|a| a.kind == "scan" && a.target == "findings"));
        let titles: Vec<&str> = alerts.iter().map(|a| a.title.as_str()).collect();
        assert!(
            titles[0].contains("winupd.exe") && alerts[0].severity == "critical",
            "{titles:?}"
        );
        assert!(
            titles[1].contains("helper.exe") && alerts[1].severity == "warning",
            "{titles:?}"
        );
        assert_eq!(alerts[1].detail, "The verdict went from Review to Disable.");
        assert!(alerts[2].detail.contains("Real-time protection"), "{:?}", alerts[2]);
        assert_eq!(alerts.len(), 3);
        // Nothing new: no alert.
        let (none, zero) = scan_alerts(&current, Some(&ScanDiff::default()), &|_| false);
        assert!(none.is_empty() && zero == 0);
    }

    #[test]
    fn many_findings_are_capped_and_a_first_scan_is_summed_up() {
        let items: Vec<Item> = (0..12)
            .map(|i| item(&i.to_string(), "remove", &format!("bad{i}.exe")))
            .collect();
        let diff = ScanDiff {
            new: (0..12).map(|i| i.to_string()).collect(),
            ..ScanDiff::default()
        };
        let current = analysis(items);
        let (alerts, found) = scan_alerts(&current, Some(&diff), &|_| false);
        assert_eq!(found, 12);
        assert_eq!(alerts.len(), MAX_SCAN_ALERTS + 1);
        assert!(
            alerts
                .last()
                .is_some_and(|a| a.severity == "info" && a.title.contains('4'))
        );
        let (first, count) = scan_alerts(&current, None, &|_| false);
        assert_eq!((first.len(), count), (1, 12));
        let (title, body) = toast(&alerts, found, true);
        assert!(title.contains("12"));
        assert_eq!(body.lines().count(), 4, "three findings and the coverage line: {body}");
    }

    #[test]
    fn a_changed_schedule_is_armed_and_a_lost_scan_is_interrupted() {
        let mut auto = AutoScanState {
            schedule_key: "daily 12:30".into(),
            armed: Some(1),
            status: "postponed:battery".into(),
            ..AutoScanState::default()
        };
        arm(&mut auto, "daily 12:30", 50, false);
        assert_eq!(
            (auto.armed, auto.status.as_str()),
            (Some(1), "postponed:battery"),
            "same schedule"
        );
        arm(&mut auto, "weekly 1 08:00", 100, false);
        assert_eq!((auto.armed, auto.status.as_str()), (Some(100), ""), "new schedule");
        auto.status = "running".into();
        arm(&mut auto, "weekly 1 08:00", 200, true);
        assert_eq!(auto.status, "running", "this copy runs it");
        arm(&mut auto, "weekly 1 08:00", 300, false);
        assert_eq!(auto.status, "interrupted");
        // An older watch.json without the section reads as the defaults.
        let old: crate::watch::WatchFile = serde_json::from_str(r#"{"alerts": []}"#).expect("old state");
        assert_eq!(old.auto_scan, AutoScanState::default());
        assert_eq!(old.settings.scan_schedule, "off");
    }

    #[test]
    #[ignore = "runs a real read-only scan; by hand: cargo test -p vigil-core autoscan -- --ignored"]
    fn live_scan_into_a_temp_folder() {
        let dir = TempDir::new("live");
        let scans = dir.0.join("scans");
        match run_scan(&scans) {
            Ok(outcome) => {
                let (alerts, found) = scan_alerts(&outcome.analysis, outcome.diff.as_ref(), &|_| false);
                println!(
                    "items {} found {found} alerts {} partial {} report {}",
                    outcome.analysis.items.len(),
                    alerts.len(),
                    outcome.partial,
                    outcome.report.exists()
                );
            }
            Err(Failure::Busy) => println!("another automatic scan runs"),
            Err(Failure::Failed(error)) => println!("failed: {error}"),
        }
    }
}
