//! Live sampling for the Performance, Processes and Overview pages.
//!
//! One background thread samples the whole system and the process list once a second, but only
//! while the UI says a live page is open (`set_live(true)`); otherwise it sleeps on a condition
//! variable and costs nothing.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use vigil_sys::metrics::{Snapshot, SystemMonitor};
use vigil_sys::process::{ProcessRow, ProcessSampler};

const INTERVAL: Duration = Duration::from_millis(1000);

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Payload {
    snapshot: Option<Snapshot>,
    processes: Option<Vec<ProcessRow>>,
    error: Option<String>,
}

type Shared = Arc<(Mutex<bool>, Condvar)>;

pub struct Live {
    active: Shared,
}

impl Live {
    pub fn start(app: AppHandle) -> Self {
        let active: Shared = Arc::new((Mutex::new(false), Condvar::new()));
        let worker = Arc::clone(&active);
        if let Err(error) = thread::Builder::new()
            .name("vigil-live".into())
            .spawn(move || sample_forever(&app, &worker))
        {
            eprintln!("could not start the live sampler: {error}");
        }
        Self { active }
    }

    pub fn set_active(&self, value: bool) {
        let (lock, wake) = &*self.active;
        *lock_ignoring_poison(lock) = value;
        wake.notify_all();
    }
}

fn lock_ignoring_poison(lock: &Mutex<bool>) -> MutexGuard<'_, bool> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

fn wait_until_active(shared: &Shared) {
    let (lock, wake) = &**shared;
    let mut active = lock_ignoring_poison(lock);
    while !*active {
        active = wake.wait(active).unwrap_or_else(PoisonError::into_inner);
    }
}

fn sample_forever(app: &AppHandle, shared: &Shared) {
    let mut monitor: Option<SystemMonitor> = None;
    let mut sampler: Option<ProcessSampler> = None;
    loop {
        wait_until_active(shared);
        let started = Instant::now();
        let mut errors: Vec<String> = Vec::new();

        // Created lazily on this thread: PDH and DXGI take a moment to initialise.
        if monitor.is_none() {
            match SystemMonitor::new() {
                Ok(created) => monitor = Some(created),
                Err(error) => errors.push(format!("system counters: {error}")),
            }
        }
        if sampler.is_none() {
            match ProcessSampler::new() {
                Ok(created) => sampler = Some(created),
                Err(error) => errors.push(format!("process list: {error}")),
            }
        }
        let snapshot = match monitor.as_mut().map(SystemMonitor::sample) {
            Some(Ok(snap)) => Some(snap),
            Some(Err(error)) => {
                errors.push(format!("system counters: {error}"));
                None
            }
            None => None,
        };
        let processes = match sampler.as_mut().map(ProcessSampler::snapshot) {
            Some(Ok(rows)) => Some(rows),
            Some(Err(error)) => {
                errors.push(format!("process list: {error}"));
                None
            }
            None => None,
        };

        let payload = Payload {
            snapshot,
            processes,
            error: (!errors.is_empty()).then(|| errors.join("; ")),
        };
        if app.emit("live", payload).is_err() {
            return; // the app is closing
        }
        thread::sleep(INTERVAL.saturating_sub(started.elapsed()));
    }
}
