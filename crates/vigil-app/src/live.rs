//! Live sampling for the live pages (Overview, Processes, Performance, Optimize, System): one background
//! thread samples the whole system and the process list once a second (one
//! NtQuerySystemInformation call, PDH counters), but only while a live page is open and the window
//! can be seen; otherwise it sleeps on a condition variable and costs nothing. Pages that show no
//! process list (Overview, Optimize, System) get it only every [`SLOW_PROCESSES`] samples, which
//! keeps the search palette's processes recent. Samples reach the UI thread through a channel and
//! are kept in a [`Live`] entity that the pages observe.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use futures::channel::mpsc::{UnboundedSender, unbounded};
use gpui_kit::{App, AppContext, Context, Entity};
use vigil_sys::metrics::{Snapshot, SystemMonitor};
use vigil_sys::process::{ProcessRow, ProcessSampler};

const INTERVAL: Duration = Duration::from_millis(1000);
/// While the open page shows no process list, the list is read on one sample in this many.
pub const SLOW_PROCESSES: u64 = 10;

/// Whether sample number `tick` (counted from 0 since sampling resumed) reads the process list.
/// The first sample after a pause always does, so a page that needs it never waits.
pub fn reads_processes(needed: bool, tick: u64) -> bool {
    needed || tick.is_multiple_of(SLOW_PROCESSES)
}

/// Whether the sampler runs: a live page is open and the window can be seen (not hidden in the
/// tray, not minimized).
pub fn sampling(page: bool, hidden: bool, minimized: bool) -> bool {
    page && !hidden && !minimized
}
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
    /// The window is minimized.
    minimized: bool,
}

/// Turns the sampler thread on and off, and tells it whether the open page shows processes.
#[derive(Clone)]
pub struct Switch {
    state: Arc<(Mutex<bool>, Condvar)>,
    processes: Arc<AtomicBool>,
}

impl Switch {
    fn new() -> Self {
        Self {
            state: Arc::new((Mutex::new(false), Condvar::new())),
            processes: Arc::new(AtomicBool::new(true)),
        }
    }

    fn set(&self, on: bool) {
        let (lock, wake) = &*self.state;
        *lock_ignoring_poison(lock) = on;
        wake.notify_all();
    }

    fn set_processes(&self, needed: bool) {
        self.processes.store(needed, Ordering::Relaxed);
    }

    fn processes_needed(&self) -> bool {
        self.processes.load(Ordering::Relaxed)
    }

    fn is_on(&self) -> bool {
        *lock_ignoring_poison(&self.state.0)
    }

    pub(crate) fn wait_until_on(&self) {
        let (lock, wake) = &*self.state;
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

    /// A live page opened (true) or the last one closed (false); `processes`: the page shows the
    /// process list (Processes, Performance), so it is read on every sample.
    pub fn set_active(&mut self, active: bool, processes: bool, _cx: &mut Context<Self>) {
        self.page = active;
        if let Some(switch) = &self.switch {
            switch.set_processes(processes);
        }
        self.apply();
    }

    /// The window was shown (true) or hidden in the tray (false): a hidden window samples nothing.
    pub fn set_visible(&mut self, visible: bool, _cx: &mut Context<Self>) {
        self.hidden = !visible;
        self.apply();
    }

    /// The window was minimized (true) or restored (false): a minimized window samples nothing.
    pub fn set_minimized(&mut self, minimized: bool, _cx: &mut Context<Self>) {
        if self.minimized != minimized {
            self.minimized = minimized;
            self.apply();
        }
    }

    fn apply(&self) {
        if let Some(switch) = &self.switch {
            switch.set(sampling(self.page, self.hidden, self.minimized));
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
    // Samples since sampling (re)started: the first one reads the process list.
    let mut tick: u64 = 0;
    loop {
        if !switch.is_on() {
            tick = 0;
        }
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
        let processes = if reads_processes(switch.processes_needed(), tick) {
            match sampler.as_mut().map(ProcessSampler::snapshot) {
                Some(Ok(rows)) => Some(rows),
                Some(Err(error)) => {
                    errors.push(format!("process list: {error}"));
                    None
                }
                None => None,
            }
        } else {
            None
        };
        tick = tick.wrapping_add(1);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_without_a_process_list_read_it_now_and_then() {
        // Processes and Performance: every sample.
        assert!((0..30).all(|tick| reads_processes(true, tick)));
        // Other live pages: the first sample after a pause, then one in SLOW_PROCESSES.
        let read: Vec<u64> = (0..30).filter(|&tick| reads_processes(false, tick)).collect();
        assert_eq!(read, vec![0, SLOW_PROCESSES, 2 * SLOW_PROCESSES]);
    }

    #[test]
    fn the_sampler_runs_only_for_a_live_page_in_a_window_that_can_be_seen() {
        assert!(sampling(true, false, false));
        assert!(!sampling(false, false, false), "no live page open");
        assert!(!sampling(true, true, false), "hidden in the tray");
        assert!(!sampling(true, false, true), "minimized");
        assert!(!sampling(true, true, true));
    }

    #[test]
    fn the_switch_carries_whether_processes_are_needed() {
        let switch = Switch::new();
        assert!(switch.processes_needed(), "needed until a page says otherwise");
        assert!(!switch.is_on());
        switch.set_processes(false);
        switch.set(true);
        assert!(!switch.processes_needed());
        assert!(switch.is_on());
    }
}
