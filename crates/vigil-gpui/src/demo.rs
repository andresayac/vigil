//! `--demo`: fictitious data in place of this computer's, for screenshots and for looking at the
//! interface without reading the system (the native counterpart of the web UI's `mock.ts`).
//! Nothing here touches the computer: no data folder, no process list, no counters, no actions.

use std::time::Duration;

use futures::channel::mpsc::UnboundedSender;
use vigil_sys::metrics::{DiskState, GpuState, GpuUse, MemoryState, NetState, Snapshot};
use vigil_sys::process::{ProcessRow, ProcessStatus};

use crate::live::{Sample, Switch};

const GB: u64 = 1 << 30;
const MB: u64 = 1 << 20;

/// (pid, ppid, name, exe, description, user, window, base CPU %, private MB)
#[rustfmt::skip]
type Spec = (u32, u32, &'static str, &'static str, &'static str, &'static str, bool, f32, u64);

const SYSTEM: &str = r"NT AUTHORITY\SYSTEM";
const USER: &str = r"PC-VICTIM\jdoe";
const SERVICE: &str = r"NT AUTHORITY\LOCAL SERVICE";

// One process per line, as a table.
#[rustfmt::skip]
const PROCESSES: &[Spec] = &[
    (4, 0, "System", "", "", SYSTEM, false, 0.4, 0),
    (120, 4, "Registry", "", "", SYSTEM, false, 0.0, 12),
    (640, 4, "smss.exe", r"C:\Windows\System32\smss.exe", "Windows Session Manager", SYSTEM, false, 0.0, 1),
    (812, 640, "csrss.exe", r"C:\Windows\System32\csrss.exe", "Client Server Runtime Process", SYSTEM, false, 0.1, 2),
    (900, 640, "wininit.exe", r"C:\Windows\System32\wininit.exe", "Windows Start-Up Application", SYSTEM, false, 0.0, 1),
    (1004, 900, "services.exe", r"C:\Windows\System32\services.exe", "Services and Controller app", SYSTEM, false, 0.1, 6),
    (1016, 900, "lsass.exe", r"C:\Windows\System32\lsass.exe", "Local Security Authority Process", SYSTEM, false, 0.1, 9),
    (1180, 1004, "svchost.exe", r"C:\Windows\System32\svchost.exe", "Host Process for Windows Services", SYSTEM, false, 0.3, 24),
    (1236, 1004, "svchost.exe", r"C:\Windows\System32\svchost.exe", "Host Process for Windows Services", SERVICE, false, 0.1, 11),
    (1312, 1004, "svchost.exe", r"C:\Windows\System32\svchost.exe", "Host Process for Windows Services", SYSTEM, false, 0.0, 7),
    (1408, 1004, "svchost.exe", r"C:\Windows\System32\svchost.exe", "Host Process for Windows Services", SERVICE, false, 0.2, 15),
    (1520, 812, "dwm.exe", r"C:\Windows\System32\dwm.exe", "Desktop Window Manager", r"Window Manager\DWM-1", false, 1.8, 96),
    (2210, 1004, "MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2601.4-0\MsMpEng.exe", "Antimalware Service Executable", SYSTEM, false, 0.6, 210),
    (2390, 1004, "spoolsv.exe", r"C:\Windows\System32\spoolsv.exe", "Spooler SubSystem App", SYSTEM, false, 0.0, 6),
    (2640, 1004, "ContosoSyncService.exe", r"C:\Program Files\Contoso\Sync\ContosoSyncService.exe", "Contoso Sync Service", SYSTEM, false, 0.2, 38),
    (2712, 1004, "FabrikamUpdater.exe", r"C:\Program Files (x86)\Fabrikam\Updater\FabrikamUpdater.exe", "Fabrikam Updater", SYSTEM, false, 0.0, 9),
    (3180, 2960, "explorer.exe", r"C:\Windows\explorer.exe", "Windows Explorer", USER, true, 0.9, 142),
    (3404, 3180, "SecurityHealthSystray.exe", r"C:\Windows\System32\SecurityHealthSystray.exe", "Windows Security notification icon", USER, false, 0.0, 2),
    (3512, 3180, "ContosoMail.exe", r"C:\Program Files\Contoso\Mail\ContosoMail.exe", "Contoso Mail", USER, true, 1.2, 312),
    (3540, 3512, "ContosoMail.exe", r"C:\Program Files\Contoso\Mail\ContosoMail.exe", "Contoso Mail", USER, false, 0.4, 96),
    (3541, 3512, "ContosoMail.exe", r"C:\Program Files\Contoso\Mail\ContosoMail.exe", "Contoso Mail", USER, false, 0.1, 54),
    (3820, 3180, "Edgeview.exe", r"C:\Program Files\Woodgrove\Edgeview\Application\Edgeview.exe", "Woodgrove Browser", USER, true, 3.4, 524),
    (3850, 3820, "Edgeview.exe", r"C:\Program Files\Woodgrove\Edgeview\Application\Edgeview.exe", "Woodgrove Browser", USER, false, 2.1, 388),
    (3851, 3820, "Edgeview.exe", r"C:\Program Files\Woodgrove\Edgeview\Application\Edgeview.exe", "Woodgrove Browser", USER, false, 0.8, 201),
    (3852, 3820, "Edgeview.exe", r"C:\Program Files\Woodgrove\Edgeview\Application\Edgeview.exe", "Woodgrove Browser", USER, false, 0.3, 122),
    (3853, 3820, "Edgeview.exe", r"C:\Program Files\Woodgrove\Edgeview\Application\Edgeview.exe", "Woodgrove Browser", USER, false, 0.1, 64),
    (4012, 3180, "Notepad.exe", r"C:\Windows\System32\notepad.exe", "Notepad", USER, true, 0.0, 18),
    (4100, 3180, "Terminal.exe", r"C:\Program Files\Contoso\Terminal\Terminal.exe", "Terminal", USER, true, 0.5, 86),
    (4130, 4100, "pwsh.exe", r"C:\Program Files\PowerShell\7\pwsh.exe", "PowerShell 7", USER, false, 0.1, 64),
    (4240, 3180, "OneSync.exe", r"C:\Users\jdoe\AppData\Local\Contoso\OneSync\OneSync.exe", "Contoso OneSync", USER, false, 0.2, 72),
    (4388, 3180, "updater.exe", r"C:\Users\jdoe\AppData\Roaming\Microsft\updater.exe", "", USER, false, 1.5, 33),
    (4410, 1004, "TailspinVPN.exe", r"C:\Program Files\Tailspin\VPN\TailspinVPN.exe", "Tailspin VPN", SYSTEM, false, 0.1, 27),
    (4520, 1180, "RuntimeBroker.exe", r"C:\Windows\System32\RuntimeBroker.exe", "Runtime Broker", USER, false, 0.0, 8),
    (4600, 1180, "SearchHost.exe", r"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe", "Search", USER, false, 0.0, 64),
    (4710, 1180, "StartMenuExperienceHost.exe", r"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe", "Start", USER, false, 0.0, 41),
    (4820, 1004, "ContosoPrintAgent.exe", r"C:\Program Files\Contoso\Print\ContosoPrintAgent.exe", "Contoso Print Agent", SYSTEM, false, 0.0, 5),
    (5004, 3180, "Paint.exe", r"C:\Program Files\Contoso\Paint\Paint.exe", "Paint", USER, true, 0.2, 77),
    (5120, 1180, "audiodg.exe", r"C:\Windows\System32\audiodg.exe", "Windows Audio Device Graph Isolation", SERVICE, false, 0.3, 9),
    (5230, 1004, "WmiPrvSE.exe", r"C:\Windows\System32\wbem\WmiPrvSE.exe", "WMI Provider Host", SYSTEM, false, 0.1, 14),
    (5310, 3180, "Fabrikam.Chat.exe", r"C:\Users\jdoe\AppData\Local\Fabrikam\Chat\Fabrikam.Chat.exe", "Fabrikam Chat", USER, true, 0.7, 260),
    (5311, 5310, "Fabrikam.Chat.exe", r"C:\Users\jdoe\AppData\Local\Fabrikam\Chat\Fabrikam.Chat.exe", "Fabrikam Chat", USER, false, 0.4, 140),
];

/// A small deterministic wobble, so the demo looks alive without randomness.
fn wobble(seed: u32, tick: u64) -> f32 {
    let x = (seed as f32 * 12.9898 + tick as f32 * 0.731).sin() * 43_758.547;
    x - x.floor()
}

/// The fictitious process list at second `tick`; `started_ms` (when the demo began) anchors the
/// start times, so each process keeps the same identity (pid + start time) from sample to sample.
pub fn processes(tick: u64, started_ms: i64) -> Vec<ProcessRow> {
    PROCESSES
        .iter()
        .map(|&(pid, ppid, name, exe, description, user, window, cpu, mb)| {
            let w = wobble(pid, tick);
            ProcessRow {
                pid,
                ppid,
                name: name.into(),
                exe: exe.into(),
                user: user.into(),
                cmdline: if exe.is_empty() {
                    String::new()
                } else {
                    format!("\"{exe}\"")
                },
                cpu: (cpu * (0.6 + w * 0.8)).min(100.0),
                private_bytes: mb * MB + u64::from(pid % 97) * 4096,
                working_set: mb * MB * 3 / 2,
                threads: 4 + pid % 40,
                handles: 120 + pid % 900,
                session: u32::from(user == USER),
                created_ms: started_ms - i64::from(pid) * 9_000 - 3_600_000,
                io_bps: f64::from(cpu * w) * 180_000.0,
                status: if pid == 4012 {
                    ProcessStatus::Suspended
                } else {
                    ProcessStatus::Running
                },
                window,
                description: description.into(),
            }
        })
        .collect()
}

/// The fictitious whole-computer state at second `tick`.
pub fn snapshot(tick: u64, now_ms: i64, rows: &[ProcessRow]) -> Snapshot {
    let cpu: f32 = rows.iter().map(|r| r.cpu).sum::<f32>() + 6.0 + wobble(7, tick) * 9.0;
    let total = 32 * GB;
    let used = 14 * GB + (wobble(11, tick) * 600.0) as u64 * MB;
    Snapshot {
        time_ms: now_ms,
        cpu: cpu.min(100.0),
        per_core: (0..16).map(|c| (cpu * (0.5 + wobble(c, tick))).min(100.0)).collect(),
        freq_mhz: 3_900.0 + wobble(3, tick) * 500.0,
        base_mhz: 3_600.0,
        processes: rows.len() as u32,
        threads: rows.iter().map(|r| r.threads).sum(),
        handles: rows.iter().map(|r| r.handles).sum(),
        uptime_s: 93_784.0 + tick as f64,
        memory: MemoryState {
            total,
            available: total - used,
            used,
            commit: used + 3 * GB,
            commit_limit: total + 8 * GB,
            standby: 9 * GB,
            modified: 300 * MB,
            free: total - used - 9 * GB,
            compressed: 420 * MB,
            paged_pool: 900 * MB,
            nonpaged_pool: 400 * MB,
        },
        gpus: vec![GpuState {
            luid: "demo".into(),
            name: "Contoso Graphics 780".into(),
            utilization: 4.0 + wobble(5, tick) * 6.0,
            engines: vec![("3D".into(), 4.0)],
            dedicated_used: 1_200 * MB,
            dedicated_total: 8 * GB,
            shared_used: 300 * MB,
            shared_total: 16 * GB,
        }],
        disks: vec![DiskState {
            key: "0".into(),
            label: "C:".into(),
            read_bps: 2.0e6 * f64::from(wobble(9, tick)),
            write_bps: 0.8e6 * f64::from(wobble(10, tick)),
            active: 3.0 + wobble(12, tick) * 8.0,
            queue: 0.0,
        }],
        nets: vec![NetState {
            name: "Ethernet".into(),
            sent_bps: 40_000.0,
            recv_bps: 250_000.0 * f64::from(wobble(13, tick)),
            link_bps: 1.0e9,
        }],
        gpu_by_pid: vec![
            GpuUse {
                pid: 3850,
                utilization: 3.0,
                dedicated: 410 * MB,
            },
            GpuUse {
                pid: 1520,
                utilization: 1.5,
                dedicated: 220 * MB,
            },
        ],
    }
}

/// The demo's sampler thread: the same rhythm and switch as the real one.
pub fn sample_forever(tx: &UnboundedSender<Sample>, switch: &Switch, interval: Duration) {
    let mut tick = 0u64;
    let started = crate::format::now_ms();
    loop {
        switch.wait_until_on();
        let now = crate::format::now_ms();
        let rows = processes(tick, started);
        let snap = snapshot(tick, now, &rows);
        let sample = Sample {
            snapshot: Some(snap),
            processes: Some(rows),
            error: None,
        };
        if tx.unbounded_send(sample).is_err() {
            return;
        }
        tick += 1;
        std::thread::sleep(interval);
    }
}
