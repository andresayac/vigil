//! Background Intelligent Transfer Service (BITS) jobs. READ-ONLY: the BITS COM API, nothing is
//! created, changed or cancelled.
//!
//! BITS downloads and uploads files in the background for Windows Update, the Store, browsers and
//! other programs. A job can also name a program to run when it finishes or fails (its "notify
//! command line"): malware uses that to start again, since BITS keeps a job for days and retries it
//! after restarts. The scan judges that program like any startup entry, and the background watch
//! reports a new job that has one.
//!
//! A standard user sees only their own jobs; an administrator can list every account's
//! (`BG_JOB_ENUM_ALL_USERS`). The reader runs on its own COM thread and gives up after a timeout.

use std::sync::mpsc;
use std::time::Duration;

use serde::Serialize;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Networking::BackgroundIntelligentTransferService::{
    BG_JOB_ENUM_ALL_USERS, BG_JOB_STATE, BG_JOB_STATE_ACKNOWLEDGED, BG_JOB_STATE_CANCELLED, BG_JOB_STATE_CONNECTING,
    BG_JOB_STATE_ERROR, BG_JOB_STATE_QUEUED, BG_JOB_STATE_SUSPENDED, BG_JOB_STATE_TRANSFERRED,
    BG_JOB_STATE_TRANSFERRING, BG_JOB_STATE_TRANSIENT_ERROR, BG_JOB_TIMES, BG_JOB_TYPE_DOWNLOAD, BG_JOB_TYPE_UPLOAD,
    BackgroundCopyManager, IBackgroundCopyFile, IBackgroundCopyJob, IBackgroundCopyJob2, IBackgroundCopyManager,
};
use windows::Win32::System::Com::{
    CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows::core::{Interface, PWSTR};

use crate::error::SysError;
use crate::util::filetime_to_unix_ms;

/// How long BITS may take to list its jobs.
const TIMEOUT: Duration = Duration::from_secs(20);
/// Jobs read at most (a computer normally has a handful).
pub const MAX_JOBS: usize = 500;
/// Files read at most per job.
pub const MAX_FILES: usize = 20;

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BitsFile {
    /// Where it is downloaded from (or uploaded to): a URL or a UNC path.
    pub remote: String,
    /// The local file.
    pub local: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BitsJob {
    /// The job's GUID, `{...}` in upper case.
    pub id: String,
    pub name: String,
    /// The owner's SID.
    pub owner: String,
    /// "queued", "connecting", "transferring", "suspended", "error", "transient_error",
    /// "transferred", "acknowledged", "cancelled" or "unknown".
    pub state: String,
    /// "download", "upload" or "upload_reply".
    pub kind: String,
    /// Milliseconds since 1970 (0 when unknown).
    pub created: i64,
    pub modified: i64,
    /// The first [`MAX_FILES`] files.
    pub files: Vec<BitsFile>,
    /// How many files the job has in all.
    pub file_count: usize,
    /// The program BITS runs when the job finishes or fails ("" when none).
    pub notify_program: String,
    pub notify_parameters: String,
}

/// What [`list`] found.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BitsJobs {
    pub jobs: Vec<BitsJob>,
    /// Every account's jobs were listed (only possible as administrator).
    pub all_users: bool,
    /// More than [`MAX_JOBS`] jobs: the rest was not read.
    pub capped: bool,
}

/// Whether the BITS service runs now (`None` when its state cannot be read). Creating the BITS
/// object starts the service when it is stopped, so the background watch asks this first and
/// lists jobs only while BITS already runs: it never starts a service.
pub fn service_running() -> Option<bool> {
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
        SERVICE_RUNNING, SERVICE_STATUS,
    };
    use windows::core::w;
    // SAFETY: plain SCM calls; every handle opened here is closed before returning.
    unsafe {
        let manager = OpenSCManagerW(None, None, SC_MANAGER_CONNECT).ok()?;
        let result = match OpenServiceW(manager, w!("BITS"), SERVICE_QUERY_STATUS) {
            Ok(service) => {
                let mut status = SERVICE_STATUS::default();
                let read = QueryServiceStatus(service, &mut status).is_ok();
                let _ = CloseServiceHandle(service);
                read.then_some(status.dwCurrentState == SERVICE_RUNNING)
            }
            Err(_) => None,
        };
        let _ = CloseServiceHandle(manager);
        result
    }
}

/// The BITS jobs this account may see: every account's when `all_users` (needs administrator
/// rights; falls back to this account's jobs when refused), otherwise this account's.
pub fn list(all_users: bool) -> Result<BitsJobs, SysError> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("vigil-bits".into())
        .spawn(move || {
            // SAFETY: COM for this worker thread only; balanced below when it succeeded.
            let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
            let result = read_all(all_users);
            if initialized {
                // SAFETY: balances the successful CoInitializeEx above; every interface was released.
                unsafe { CoUninitialize() };
            }
            let _ = tx.send(result);
        })
        .map_err(|e| SysError::new(format!("could not start reading BITS jobs: {e}"), 0))?;
    match rx.recv_timeout(TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SysError::new("BITS did not answer in time", 0)),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SysError::new("reading BITS jobs failed", 0)),
    }
}

fn read_all(all_users: bool) -> Result<BitsJobs, SysError> {
    // SAFETY: creates the BITS manager (an out-of-process COM server); released when dropped.
    let manager: IBackgroundCopyManager =
        unsafe { CoCreateInstance(&BackgroundCopyManager, None, CLSCTX_LOCAL_SERVER) }
            .map_err(|e| SysError::from_windows("BITS is not available", &e))?;
    // SAFETY: plain call on a valid interface; every account's jobs needs administrator rights.
    let (jobs, everyone) = match all_users.then(|| unsafe { manager.EnumJobs(BG_JOB_ENUM_ALL_USERS) }) {
        Some(Ok(jobs)) => (jobs, true),
        // SAFETY: as above, this account's jobs only.
        _ => (
            unsafe { manager.EnumJobs(0) }.map_err(|e| SysError::from_windows("could not list BITS jobs", &e))?,
            false,
        ),
    };
    let mut out = BitsJobs {
        all_users: everyone,
        ..BitsJobs::default()
    };
    loop {
        let mut batch: [Option<IBackgroundCopyJob>; 1] = [None];
        let mut fetched = 0u32;
        // SAFETY: valid enumerator; the slice and counter outlive the call.
        if unsafe { jobs.Next(&mut batch, &mut fetched) }.is_err() || fetched == 0 {
            break;
        }
        let Some(job) = batch[0].take() else { break };
        if out.jobs.len() >= MAX_JOBS {
            out.capped = true;
            break;
        }
        out.jobs.push(read_job(&job));
    }
    out.jobs
        .sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.id.cmp(&b.id)));
    Ok(out)
}

/// Copies a string BITS allocated and frees it.
fn take(text: PWSTR) -> String {
    if text.is_null() {
        return String::new();
    }
    // SAFETY: BITS returned a NUL-terminated string allocated with CoTaskMemAlloc.
    let value = unsafe { text.to_string() }.unwrap_or_default();
    // SAFETY: frees the memory BITS allocated, exactly once.
    unsafe { CoTaskMemFree(Some(text.0 as *const _)) };
    value
}

fn filetime_ms(time: FILETIME) -> i64 {
    filetime_to_unix_ms((i64::from(time.dwHighDateTime) << 32) | i64::from(time.dwLowDateTime))
}

fn state_name(state: BG_JOB_STATE) -> &'static str {
    match state {
        BG_JOB_STATE_QUEUED => "queued",
        BG_JOB_STATE_CONNECTING => "connecting",
        BG_JOB_STATE_TRANSFERRING => "transferring",
        BG_JOB_STATE_SUSPENDED => "suspended",
        BG_JOB_STATE_ERROR => "error",
        BG_JOB_STATE_TRANSIENT_ERROR => "transient_error",
        BG_JOB_STATE_TRANSFERRED => "transferred",
        BG_JOB_STATE_ACKNOWLEDGED => "acknowledged",
        BG_JOB_STATE_CANCELLED => "cancelled",
        _ => "unknown",
    }
}

fn read_job(job: &IBackgroundCopyJob) -> BitsJob {
    let mut out = BitsJob::default();
    // SAFETY: plain property reads on a valid interface; returned strings are freed by `take`.
    unsafe {
        if let Ok(id) = job.GetId() {
            out.id = format!("{{{id:?}}}").to_uppercase();
        }
        if let Ok(name) = job.GetDisplayName() {
            out.name = take(name);
        }
        if let Ok(owner) = job.GetOwner() {
            out.owner = take(owner);
        }
        if let Ok(state) = job.GetState() {
            out.state = state_name(state).to_string();
        }
        out.kind = match job.GetType() {
            Ok(BG_JOB_TYPE_DOWNLOAD) => "download",
            Ok(BG_JOB_TYPE_UPLOAD) => "upload",
            Ok(_) => "upload_reply",
            Err(_) => "",
        }
        .to_string();
        let mut times = BG_JOB_TIMES::default();
        if job.GetTimes(&mut times).is_ok() {
            out.created = filetime_ms(times.CreationTime);
            out.modified = filetime_ms(times.ModificationTime);
        }
        if let Ok(files) = job.EnumFiles() {
            loop {
                let mut batch: [Option<IBackgroundCopyFile>; 1] = [None];
                let mut fetched = 0u32;
                if files.Next(&mut batch, &mut fetched).is_err() || fetched == 0 {
                    break;
                }
                let Some(file) = batch[0].take() else { break };
                out.file_count += 1;
                if out.files.len() < MAX_FILES {
                    out.files.push(BitsFile {
                        remote: file.GetRemoteName().map(take).unwrap_or_default(),
                        local: file.GetLocalName().map(take).unwrap_or_default(),
                    });
                }
            }
        }
        if let Ok(job2) = job.cast::<IBackgroundCopyJob2>() {
            let mut program = PWSTR::null();
            let mut parameters = PWSTR::null();
            if job2.GetNotifyCmdLine(&mut program, &mut parameters).is_ok() {
                out.notify_program = take(program);
                out.notify_parameters = take(parameters);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_and_times_are_named() {
        assert_eq!(state_name(BG_JOB_STATE_TRANSFERRED), "transferred");
        assert_eq!(state_name(BG_JOB_STATE(42)), "unknown");
        let zero = FILETIME::default();
        assert_eq!(filetime_ms(zero), 0);
        let epoch = crate::util::EPOCH_AS_FILETIME + 10_000_000;
        let time = FILETIME {
            dwLowDateTime: epoch as u32,
            dwHighDateTime: (epoch >> 32) as u32,
        };
        assert_eq!(filetime_ms(time), 1_000);
    }

    /// Lists this account's jobs (read-only); prints counts and timings only.
    #[test]
    #[ignore = "reads the real BITS jobs"]
    fn live_counts() {
        let started = std::time::Instant::now();
        let running = service_running();
        let status_time = started.elapsed();
        let started = std::time::Instant::now();
        let found = list(false).expect("BITS");
        println!(
            "service running {running:?} ({status_time:?}); listed in {:?}",
            started.elapsed()
        );
        let with_notify = found.jobs.iter().filter(|j| !j.notify_program.is_empty()).count();
        println!(
            "jobs {} (all users {}), with a notify command {}, files {}",
            found.jobs.len(),
            found.all_users,
            with_notify,
            found.jobs.iter().map(|j| j.file_count).sum::<usize>()
        );
    }
}
