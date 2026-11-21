//! Timings of the samplers on this computer. Prints counts and timings only.
//!
//!     cargo run --release -p vigil-sys --example sys_bench

use std::time::{Duration, Instant};

use vigil_sys::metrics::SystemMonitor;
use vigil_sys::net::connections;
use vigil_sys::process::ProcessSampler;

fn ms(duration: Duration) -> String {
    format!("{:7.2} ms", duration.as_secs_f64() * 1000.0)
}

fn main() -> Result<(), vigil_sys::SysError> {
    let start = Instant::now();
    let mut sampler = ProcessSampler::new()?;
    let rows = sampler.snapshot()?;
    println!(
        "process snapshot, cold  {} ({} processes)",
        ms(start.elapsed()),
        rows.len()
    );
    for round in 1..=5 {
        std::thread::sleep(Duration::from_millis(200));
        let start = Instant::now();
        let rows = sampler.snapshot()?;
        println!(
            "process snapshot, warm  {} ({} processes, round {round})",
            ms(start.elapsed()),
            rows.len()
        );
    }

    let start = Instant::now();
    let mut monitor = SystemMonitor::new()?;
    println!(
        "system monitor, create  {} ({} GPUs)",
        ms(start.elapsed()),
        monitor.adapters().len()
    );
    for round in 0..=5 {
        std::thread::sleep(Duration::from_millis(200));
        let start = Instant::now();
        let snap = monitor.sample()?;
        let label = if round == 0 { "cold" } else { "warm" };
        println!(
            "metrics sample, {label}    {} ({} cores, {} GPUs, {} disks, {} networks, {} GPU processes)",
            ms(start.elapsed()),
            snap.per_core.len(),
            snap.gpus.len(),
            snap.disks.len(),
            snap.nets.len(),
            snap.gpu_by_pid.len()
        );
    }
    println!("missing counters: {:?}", monitor.missing_counters());

    let start = Instant::now();
    let list = connections()?;
    println!(
        "connections             {} ({} endpoints)",
        ms(start.elapsed()),
        list.len()
    );
    println!("elevated: {}", vigil_sys::elevation::is_elevated());
    Ok(())
}
