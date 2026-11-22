//! Live sampling for the live pages (Overview, Processes, Performance, Optimize, System): one background
//! thread samples the whole system and the process list once a second (one
//! NtQuerySystemInformation call, PDH counters), but only while a live page is open; otherwise it
//! sleeps on a condition variable and costs nothing. Samples reach the UI thread through a
//! channel and are kept in a [`Live`] entity that the pages observe.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use futures::channel::mpsc::{UnboundedSender, unbounded};
use gpui_kit::{App, AppContext, Context, Entity};
use vigil_sys::metrics::{Snapshot, SystemMonitor};
use vigil_sys::process::{ProcessRow, ProcessSampler};

const INTERVAL: Duration = Duration::from_millis(1000);
/// Seconds of history the charts keep: the longest range they show (5 minutes).
pub const HISTORY: usize = 300;

pub struct Sample {
    pub snapshot: Option<Snapshot>,
    pub processes: Option<Vec<ProcessRow>>,
    pub error: Option<String>,
}

/// What the live pages read.
#[derive(Default)]
pub struct Live {
    pub snapshot: Option<Snapshot>,
    pub processes: Vec<ProcessRow>,
    pub error: Option<String>,
    /// Whole-computer CPU and memory use (0-100), oldest first.
    pub cpu: VecDeque<f32>,
    pub memory: VecDeque<f32>,
    /// Every resource's history, oldest first, by key: "disk:{key}" (active %), "disk:{key}:read"
    /// and ":write" (bytes/s), "net:{name}:recv" and ":sent" (bytes/s), "gpu:{luid}" (%),
    /// "vram:{luid}" (% of the dedicated memory).
    pub series: HashMap<String, VecDeque<f64>>,
    /// Samples received, so pages can tell a new sample from a re-render.
    pub generation: u64,
    switch: Option<Switch>,
    /// A live page is open.
    page: bool,
    /// The window is hidden in the tray.
    hidden: bool,
}

/// Turns the sampler thread on and off.
#[derive(Clone)]
pub struct Switch(Arc<(Mutex<bool>, Condvar)>);

impl Switch {
    fn new() -> Self {
        Self(Arc::new((Mutex::new(false), Condvar::new())))
    }

    fn set(&self, on: bool) {
        let (lock, wake) = &*self.0;
        *lock_ignoring_poison(lock) = on;
        wake.notify_all();
    }

    pub(crate) fn wait_until_on(&self) {
        let (lock, wake) = &*self.0;
        let mut on = lock_ignoring_poison(lock);
        while !*on {
            on = wake.wait(on).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

fn lock_ignoring_poison(lock: &Mutex<bool>) -> MutexGuard<'_, bool> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Live {
    /// Starts the sampler thread (idle until a live page opens) and the task that receives its
    /// samples. `demo`: fictitious data instead of this computer's.
    pub fn start(demo: bool, cx: &mut App) -> Entity<Live> {
        let switch = Switch::new();
        let (tx, mut rx) = unbounded::<Sample>();
        let worker = switch.clone();
        let spawned = thread::Builder::new().name("vigil-live".into()).spawn(move || {
            if demo {
                crate::demo::sample_forever(&tx, &worker, INTERVAL);
            } else {
                sample_forever(&tx, &worker);
            }
        });
        let live = cx.new(|_| Live {
            switch: Some(switch),
            error: spawned.err().map(|e| format!("could not start the live sampler: {e}")),
            ..Default::default()
        });
        let weak = live.downgrade();
        cx.spawn(async move |cx| {
            while let Some(sample) = rx.next().await {
                let Ok(()) = weak.update(cx, |live, cx| {
                    live.push(sample);
                    cx.notify();
                }) else {
                    break;
                };
            }
        })
        .detach();
        live
    }

    /// A live page opened (true) or the last one closed (false).
    pub fn set_active(&mut self, active: bool, _cx: &mut Context<Self>) {
        self.page = active;
        self.apply();
    }

    /// The window was shown (true) or hidden in the tray (false): a hidden window samples nothing.
    pub fn set_visible(&mut self, visible: bool, _cx: &mut Context<Self>) {
        self.hidden = !visible;
        self.apply();
    }

    fn apply(&self) {
        if let Some(switch) = &self.switch {
            switch.set(self.page && !self.hidden);
        }
    }

    fn record(&mut self, key: String, value: f64) {
        let series = self.series.entry(key).or_default();
        if series.len() == HISTORY {
            series.pop_front();
        }
        series.push_back(value);
    }

    fn push(&mut self, sample: Sample) {
        self.generation += 1;
        self.error = sample.error;
        if let Some(rows) = sample.processes {
            self.processes = rows;
        }
        if let Some(snapshot) = sample.snapshot {
            let memory = if snapshot.memory.total > 0 {
                (snapshot.memory.used as f64 / snapshot.memory.total as f64 * 100.0) as f32
            } else {
                0.0
            };
            for (series, value) in [(&mut self.cpu, snapshot.cpu), (&mut self.memory, memory)] {
                if series.len() == HISTORY {
                    series.pop_front();
                }
                series.push_back(value);
            }
            for disk in &snapshot.disks {
                self.record(format!("disk:{}", disk.key), f64::from(disk.active));
                self.record(format!("disk:{}:read", disk.key), disk.read_bps);
                self.record(format!("disk:{}:write", disk.key), disk.write_bps);
            }
            for net in &snapshot.nets {
                self.record(format!("net:{}:recv", net.name), net.recv_bps);
                self.record(format!("net:{}:sent", net.name), net.sent_bps);
            }
            for gpu in &snapshot.gpus {
                self.record(format!("gpu:{}", gpu.luid), f64::from(gpu.utilization));
                let vram = if gpu.dedicated_total > 0 {
                    gpu.dedicated_used as f64 / gpu.dedicated_total as f64 * 100.0
                } else {
                    0.0
                };
                self.record(format!("vram:{}", gpu.luid), vram);
            }
            self.snapshot = Some(snapshot);
        }
    }
}

fn sample_forever(tx: &UnboundedSender<Sample>, switch: &Switch) {
    let mut monitor: Option<SystemMonitor> = None;
    let mut sampler: Option<ProcessSampler> = None;
    loop {
        switch.wait_until_on();
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
        let sample = Sample {
            snapshot,
            processes,
            error: (!errors.is_empty()).then(|| errors.join("; ")),
        };
        if tx.unbounded_send(sample).is_err() {
            return; // the app is closing
        }
        thread::sleep(INTERVAL.saturating_sub(started.elapsed()));
    }
}
