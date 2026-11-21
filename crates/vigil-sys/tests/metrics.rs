//! System metrics: shape and sanity of real samples.

use std::thread::sleep;
use std::time::Duration;

use vigil_sys::metrics::{SystemMonitor, adapters, cpu_name};

fn luid_is_well_formed(luid: &str) -> bool {
    let bytes = luid.as_bytes();
    luid.len() == 21
        && luid.starts_with("0x")
        && bytes[10] == b'_'
        && luid[2..10].chars().all(|c| c.is_ascii_hexdigit())
        && luid[13..].chars().all(|c| c.is_ascii_hexdigit())
}

#[test]
fn samples_are_consistent() {
    let mut monitor = SystemMonitor::new().expect("monitor");
    let first = monitor.sample().expect("first sample");
    assert!(first.per_core.iter().all(|&c| c == 0.0), "no rate on the first sample");
    sleep(Duration::from_millis(600));
    let snap = monitor.sample().expect("second sample");

    assert!((0.0..=100.0).contains(&snap.cpu));
    assert!(!snap.per_core.is_empty());
    assert!(snap.per_core.iter().all(|c| (0.0..=100.0).contains(c)));
    assert!(snap.base_mhz > 0.0 && snap.freq_mhz > 0.0);
    assert!(snap.processes > 0 && snap.threads > 0 && snap.handles > 0);
    assert!(snap.uptime_s > 0.0);
    assert!(snap.time_ms > 1_600_000_000_000);

    let m = &snap.memory;
    assert!(m.total > 0);
    for part in [
        m.available,
        m.used,
        m.standby,
        m.modified,
        m.free,
        m.compressed,
        m.paged_pool,
        m.nonpaged_pool,
    ] {
        assert!(part <= m.total, "{part} > {}", m.total);
    }
    assert!(m.commit <= m.commit_limit);

    for disk in &snap.disks {
        assert!(disk.read_bps >= 0.0 && disk.write_bps >= 0.0 && disk.queue >= 0.0);
        assert!((0.0..=100.0).contains(&disk.active));
        assert!(disk.label.starts_with("Disk "));
    }
    for net in &snap.nets {
        assert!(net.sent_bps >= 0.0 && net.recv_bps >= 0.0 && net.link_bps >= 0.0);
        assert!(!net.name.is_empty());
    }
    for gpu in &snap.gpus {
        assert!(luid_is_well_formed(&gpu.luid), "{}", gpu.luid);
        assert!((0.0..=100.0).contains(&gpu.utilization));
        assert!(gpu.engines.iter().all(|(_, v)| (0.0..=100.0).contains(v)));
    }
    assert!(snap.gpu_by_pid.iter().all(|g| (0.0..=100.0).contains(&g.utilization)));
}

#[test]
fn adapters_have_luids() {
    for adapter in adapters() {
        assert!(luid_is_well_formed(&adapter.luid), "{}", adapter.luid);
        assert!(!adapter.name.is_empty());
    }
    let monitor = SystemMonitor::new().expect("monitor");
    assert!(monitor.adapters().iter().all(|a| !a.software));
}

#[test]
fn processor_name_is_known() {
    assert!(!cpu_name().is_empty());
}

#[test]
fn snapshot_serializes_in_camel_case() {
    let mut monitor = SystemMonitor::new().expect("monitor");
    let json = serde_json::to_value(monitor.sample().expect("sample")).expect("json");
    for key in [
        "timeMs", "cpu", "perCore", "freqMhz", "baseMhz", "uptimeS", "memory", "gpus", "disks", "nets", "gpuByPid",
    ] {
        assert!(json.get(key).is_some(), "missing {key}");
    }
    assert!(json["memory"].get("commitLimit").is_some());
}
