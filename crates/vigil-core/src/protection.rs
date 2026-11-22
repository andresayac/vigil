//! The Protection page: Microsoft Defender's live state (read-only), the scans Vigil follows, and
//! the requests that scan, update or turn protection on. Every request is checked against a fresh
//! read; the texts of the confirmation come from here, never from the page. Nothing offered here
//! turns protection off.

use std::time::Duration;

use serde::Serialize;
use serde_json::json;
use vigil_actions::defender::{ScanStatus, scan_status, wait_running};
use vigil_i18n::tr;
use vigil_sys::defender::Protection;

use crate::planner::{SpecExt, spec};
use crate::requests::Plan;

/// The page's view: Defender's state and the last scan Vigil started.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionView {
    #[serde(flatten)]
    pub state: Protection,
    pub scan: Option<ScanStatus>,
}

/// One progress event of a scan Vigil started (`defender-scan`).
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanEvent {
    #[serde(flatten)]
    status: ScanStatus,
    elapsed_secs: u64,
    /// Threats Defender recorded since the scan started (once it ended).
    found: Option<usize>,
}

/// Microsoft Defender's state (read-only; slow, call it off the UI thread). Changes go through
/// the action service (`Request::Defender`).
pub fn view() -> ProtectionView {
    ProtectionView {
        state: vigil_sys::defender::read(),
        scan: scan_status(),
    }
}

fn event(status: &ScanStatus, found: Option<usize>) -> ScanEvent {
    let end = if status.running {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    } else {
        status.finished_ms
    };
    ScanEvent {
        status: status.clone(),
        elapsed_secs: u64::try_from((end - status.started_ms).max(0) / 1000).unwrap_or(0),
        found,
    }
}

/// Follows the scans Vigil starts: once a second while one runs (`emit` gets each event), then
/// once more with what Defender found. Idle, the thread only waits.
pub fn start_monitor(emit: impl Fn(ScanEvent) + Send + 'static) {
    let _ = std::thread::Builder::new()
        .name("vigil-defender-scan".into())
        .spawn(move || {
            loop {
                let Some(mut status) = wait_running(Duration::from_secs(3600)) else {
                    continue;
                };
                while status.running {
                    emit(event(&status, None));
                    std::thread::sleep(Duration::from_secs(1));
                    match scan_status() {
                        Some(next) if next.id == status.id => status = next,
                        _ => break,
                    }
                }
                let since = status.started_ms - 5_000;
                let found = vigil_sys::defender::read()
                    .threats
                    .iter()
                    .filter(|t| t.detected_ms >= since)
                    .count();
                emit(event(&status, Some(found)));
            }
        });
}

/// The settings the page may turn on: (key, name in messages).
fn setting_name(key: &str) -> Option<String> {
    Some(match key {
        "realtime" => tr!("real-time protection"),
        "pua" => tr!("potentially unwanted app blocking"),
        "cloud" => tr!("cloud-delivered protection"),
        "samples" => tr!("automatic sample submission"),
        _ => return None,
    })
}

fn switch_state<'a>(state: &'a Protection, key: &str) -> &'a str {
    state
        .switches
        .iter()
        .find(|s| s.key == key)
        .map_or("unknown", |s| s.state.as_str())
}

/// A request of the Protection page, checked against a fresh read of Defender.
pub fn plan(op: &str, setting: &str, list: &str, value: &str, state: &Protection) -> Result<Plan, String> {
    if !state.available {
        return Err(tr!("Microsoft Defender is not available on this computer."));
    }
    let defender = tr!("Microsoft Defender");
    let vigil_scan = scan_status().is_some_and(|s| s.running);
    let built = match op {
        "quick-scan" | "full-scan" => {
            if vigil_scan {
                return Err(tr!("A Microsoft Defender scan Vigil started is still running."));
            }
            if !state.service_enabled {
                return Err(tr!("Microsoft Defender's antivirus is off, so it cannot scan."));
            }
            if op == "quick-scan" {
                spec(
                    "defender.quick_scan",
                    tr!("Run a quick scan"),
                    defender,
                    tr!(
                        "Microsoft Defender checks the places malware usually hides: running programs, startup locations, the registry and system folders. It usually takes a few minutes and runs in the background; you can keep working and stop it at any time."
                    ),
                )
            } else {
                spec(
                    "defender.full_scan",
                    tr!("Run a full scan"),
                    defender,
                    tr!(
                        "Microsoft Defender checks every file and running program on the computer's drives. It can take an hour or more and slows the computer down while it runs; it runs in the background and you can stop it at any time."
                    ),
                )
            }
            .group("fix")
            .irreversible()
            .no_admin()
        }
        "cancel-scan" => {
            if !vigil_scan && state.running_scan.is_none() {
                return Err(tr!("No Microsoft Defender scan is running."));
            }
            spec(
                "defender.cancel_scan",
                tr!("Stop the scan"),
                defender,
                tr!("Asks Microsoft Defender to stop the quick or full scan that is running. What it already found stays in the threat history."),
            )
            .group("fix")
            .irreversible()
            .no_admin()
        }
        "offline-scan" => spec(
            "defender.offline_scan",
            tr!("Run a Microsoft Defender Offline scan"),
            defender,
            tr!(
                "Windows restarts right away into a separate environment where Microsoft Defender scans the computer before Windows, and any malware, can start. It takes about 15 minutes; then Windows starts again. Save your work and close your programs first."
            ),
        )
        .warning(&tr!("The computer restarts as soon as you confirm. Unsaved work is lost."))
        .group("fix")
        .irreversible(),
        "update" => spec(
            "defender.update",
            tr!("Update security intelligence"),
            defender,
            tr!("Downloads the latest Defender definitions."),
        )
        .group("fix")
        .irreversible(),
        "turn-on" => {
            let name = setting_name(setting).ok_or(tr!("This setting is not changed from Vigil. Use Windows Security."))?;
            match switch_state(state, setting) {
                "on" => return Err(tr!("This is already on: {0}.", name)),
                "unknown" => return Err(tr!("Vigil could not read {0}. Refresh the page.", name)),
                _ => {}
            }
            if setting == "realtime" {
                if state.mode == "passive" {
                    return Err(tr!(
                        "Another antivirus protects this computer, so Microsoft Defender runs in passive mode and its real-time protection stays off. To use Defender instead, turn off or uninstall the other antivirus."
                    ));
                }
                spec(
                    "defender.realtime_on",
                    tr!("Turn real-time protection on"),
                    defender,
                    tr!("Turns real-time protection back on."),
                )
                .group("fix")
                .irreversible()
            } else {
                let explain = match setting {
                    "pua" => tr!(
                        "Microsoft Defender blocks potentially unwanted apps: programs that are not quite malware but install adware, cryptocurrency miners or other software you did not ask for."
                    ),
                    "cloud" => tr!(
                        "Microsoft Defender asks Microsoft's cloud service about new and suspicious files, which stops new threats much sooner. Information about those files is sent to Microsoft."
                    ),
                    _ => tr!(
                        "When a file may be malware, Microsoft Defender sends it to Microsoft for analysis without asking. Files that are likely to contain personal information are not sent without asking."
                    ),
                };
                spec(
                    "defender.preference_on",
                    tr!("Turn on {0}", name),
                    defender,
                    explain,
                )
                .params(json!({ "setting": setting }))
                .group("fix")
            }
        }
        "remove-exclusion" => {
            if state.exclusions_hidden {
                return Err(tr!("Only administrators can see and change Microsoft Defender's exclusions."));
            }
            let exclusion = state
                .exclusions
                .iter()
                .find(|e| e.kind == list && e.value.trim().eq_ignore_ascii_case(value.trim()))
                .ok_or(tr!("The exclusion is no longer there. Refresh the page."))?;
            spec(
                "defender.remove_exclusion",
                tr!("Remove exclusion {0}", format!("\"{}\"", exclusion.value)),
                exclusion.value.clone(),
                tr!("Lets Defender scan it again."),
            )
            .params(json!({ "kind": exclusion.kind, "value": exclusion.value }))
            .group("fix")
        }
        "remove-threats" => {
            let active: Vec<&str> = state
                .threats
                .iter()
                .filter(|t| t.active)
                .map(|t| t.name.as_str())
                .collect();
            if active.is_empty() {
                return Err(tr!("Microsoft Defender has no active threats to remove."));
            }
            spec(
                "defender.remove_threats",
                tr!("Remove active threats"),
                active.join(", "),
                tr!(
                    "Microsoft Defender applies its recommended action to every threat it detected and has not dealt with yet: usually it quarantines or deletes the files involved."
                ),
            )
            .group("remove")
            .destructive()
            .irreversible()
        }
        _ => return Err(tr!("Unknown request: {0}", op)),
    };
    Ok(Plan::Run {
        spec: built,
        item: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_sys::defender::{Exclusion, Switch, Threat};

    fn state() -> Protection {
        let switch = |key: &str, state: &str| Switch {
            key: key.into(),
            state: state.into(),
        };
        Protection {
            available: true,
            service_enabled: true,
            antivirus_enabled: true,
            mode: "normal".into(),
            switches: vec![
                switch("realtime", "on"),
                switch("cloud", "off"),
                switch("samples", "on"),
                switch("pua", "audit"),
                switch("tamper", "off"),
            ],
            exclusions: vec![Exclusion {
                kind: "path".into(),
                value: r"C:\Users\jdoe\Downloads".into(),
                flags: vec!["writable".into()],
            }],
            threats: vec![
                Threat {
                    name: "Trojan:Win32/Example.A".into(),
                    active: true,
                    ..Threat::default()
                },
                Threat {
                    name: "PUA:Win32/Example".into(),
                    ..Threat::default()
                },
            ],
            ..Protection::default()
        }
    }

    fn run(
        op: &str,
        setting: &str,
        list: &str,
        value: &str,
        s: &Protection,
    ) -> Result<vigil_actions::ActionSpec, String> {
        match plan(op, setting, list, value, s)? {
            Plan::Run { spec, .. } => Ok(spec),
            _ => Err("not a run plan".into()),
        }
    }

    #[test]
    fn scans_and_updates() {
        vigil_actions::defender::reset_scan();
        let s = state();
        let quick = run("quick-scan", "", "", "", &s).expect("quick");
        assert_eq!(quick.op, "defender.quick_scan");
        assert!(!quick.admin && !quick.destructive && !quick.reversible);
        let full = run("full-scan", "", "", "", &s).expect("full");
        assert_eq!(full.op, "defender.full_scan");
        assert!(!full.admin);
        let offline = run("offline-scan", "", "", "", &s).expect("offline");
        assert_eq!(offline.op, "defender.offline_scan");
        assert!(offline.admin && !offline.destructive && !offline.reversible && !offline.warning.is_empty());
        assert_eq!(run("update", "", "", "", &s).expect("update").op, "defender.update");
        // Nothing is running, so there is nothing to stop.
        assert!(run("cancel-scan", "", "", "", &s).is_err());
        let mut running = state();
        running.running_scan = Some(vigil_sys::defender::RunningScan {
            kind: "full".into(),
            start_ms: 1,
        });
        assert_eq!(
            run("cancel-scan", "", "", "", &running).expect("cancel").op,
            "defender.cancel_scan"
        );
        let mut off = state();
        off.service_enabled = false;
        assert!(run("quick-scan", "", "", "", &off).is_err());
        let mut missing = state();
        missing.available = false;
        assert!(run("update", "", "", "", &missing).is_err());
    }

    #[test]
    fn only_turning_on_is_offered() {
        let s = state();
        let cloud = run("turn-on", "cloud", "", "", &s).expect("cloud");
        assert_eq!(cloud.op, "defender.preference_on");
        assert_eq!(cloud.params, json!({"setting": "cloud"}));
        assert!(cloud.reversible && cloud.admin);
        // Audit mode is not on: blocking can be turned on.
        assert_eq!(
            run("turn-on", "pua", "", "", &s).expect("pua").op,
            "defender.preference_on"
        );
        // Already on, or not a setting Vigil changes.
        assert!(run("turn-on", "samples", "", "", &s).is_err());
        assert!(run("turn-on", "realtime", "", "", &s).is_err());
        assert!(run("turn-on", "tamper", "", "", &s).is_err());
        assert!(run("turn-on", "network", "", "", &s).is_err());
        assert!(run("turn-off", "cloud", "", "", &s).is_err());
        let mut passive = state();
        passive.mode = "passive".into();
        passive.switches[0].state = "off".into();
        assert!(run("turn-on", "realtime", "", "", &passive).is_err());
        let mut normal_off = state();
        normal_off.switches[0].state = "off".into();
        assert_eq!(
            run("turn-on", "realtime", "", "", &normal_off).expect("realtime").op,
            "defender.realtime_on"
        );
    }

    #[test]
    fn exclusions_and_threats_come_from_the_live_read() {
        let s = state();
        let removed = run("remove-exclusion", "", "path", r"c:\users\jdoe\downloads", &s).expect("exclusion");
        assert_eq!(removed.op, "defender.remove_exclusion");
        // The value comes from the live list, not from the request.
        assert_eq!(
            removed.params,
            json!({"kind": "path", "value": r"C:\Users\jdoe\Downloads"})
        );
        assert!(run("remove-exclusion", "", "process", r"C:\Users\jdoe\Downloads", &s).is_err());
        assert!(run("remove-exclusion", "", "path", r"C:\Windows", &s).is_err());
        let mut hidden = state();
        hidden.exclusions_hidden = true;
        hidden.exclusions.clear();
        assert!(run("remove-exclusion", "", "path", r"C:\Users\jdoe\Downloads", &hidden).is_err());
        let threats = run("remove-threats", "", "", "", &s).expect("threats");
        assert_eq!(threats.op, "defender.remove_threats");
        assert_eq!(threats.target, "Trojan:Win32/Example.A");
        assert!(threats.destructive && !threats.reversible);
        let mut clean = state();
        clean.threats.retain(|t| !t.active);
        assert!(run("remove-threats", "", "", "", &clean).is_err());
        assert!(run("allow-threat", "", "", "", &s).is_err());
    }
}
