//! Microsoft Defender actions, with a fake runner and a fake scan starter: no scan, update or
//! setting change ever reaches the real Defender.

mod common;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use common::{FakeRunner, Fixture};
use serde_json::{Value, json};
use vigil_actions::defender::{ScanProcess, reset_scan, scan_status, set_scan_starter};
use vigil_actions::{ActionSpec, ToolResult, execute, undo};

fn spec(op: &str, params: Value) -> ActionSpec {
    ActionSpec::new(op, op, "Microsoft Defender", "", params)
}

fn ok(out: &str) -> ToolResult {
    ToolResult::new(0, out, "")
}

const RUNNING: i32 = i32::MIN;

/// A scan process whose exit code the test sets.
struct FakeScan(Arc<AtomicI32>);

impl ScanProcess for FakeScan {
    fn try_wait(&mut self) -> Option<i32> {
        let code = self.0.load(Ordering::SeqCst);
        (code != RUNNING).then_some(code)
    }
}

/// Installs a starter that records the arguments and hands out processes driven by `exit`.
fn fake_starter(exit: &Arc<AtomicI32>) -> Rc<RefCell<Vec<Vec<String>>>> {
    let calls: Rc<RefCell<Vec<Vec<String>>>> = Rc::new(RefCell::new(Vec::new()));
    let (seen, exit) = (Rc::clone(&calls), Arc::clone(exit));
    set_scan_starter(Some(Rc::new(move |args: &[String]| {
        seen.borrow_mut().push(args.to_vec());
        exit.store(RUNNING, Ordering::SeqCst);
        Ok(Box::new(FakeScan(Arc::clone(&exit))) as Box<dyn ScanProcess>)
    })));
    calls
}

fn tail(args: &[String]) -> String {
    args.iter().skip(1).cloned().collect::<Vec<_>>().join(" ")
}

/// One test for the whole scan life cycle: the scan Vigil follows is shared by the process.
#[test]
fn scans_start_in_the_background_are_followed_and_can_be_stopped() {
    let fx = Fixture::new();
    reset_scan();
    let exit = Arc::new(AtomicI32::new(RUNNING));
    let starts = fake_starter(&exit);
    let runner = FakeRunner::install(&[(r"mpcmdrun\.exe -Scan -Cancel", ok("Scan cancelled"))]);

    let quick = execute(&spec("defender.quick_scan", json!({})), &fx.store, None, "");
    assert!(quick.ok(), "{}", quick.message());
    assert_eq!(tail(&starts.borrow()[0]), "-Scan -ScanType 1");
    assert!(
        starts.borrow()[0][0]
            .to_lowercase()
            .ends_with(r"\windows defender\mpcmdrun.exe")
    );
    let status = scan_status().expect("status");
    assert!(status.running && status.kind == "quick" && !status.cancelled);

    // One scan at a time, whichever kind.
    let again = execute(&spec("defender.full_scan", json!({})), &fx.store, None, "");
    assert!(!again.ok());
    assert_eq!(starts.borrow().len(), 1);

    let cancel = execute(&spec("defender.cancel_scan", json!({})), &fx.store, None, "");
    assert!(cancel.ok(), "{}", cancel.message());
    assert_eq!(runner.lines(), ["mpcmdrun.exe -Scan -Cancel"]);
    assert!(scan_status().expect("status").cancelled);

    // The process ends: Vigil records its exit code.
    exit.store(0, Ordering::SeqCst);
    let ended = scan_status().expect("status");
    assert!(!ended.running && ended.code == Some(0) && ended.finished_ms >= ended.started_ms);

    // The findings' full scan uses the same mechanism.
    let full = execute(&spec("defender.full_scan", json!({})), &fx.store, None, "");
    assert!(full.ok(), "{}", full.message());
    assert_eq!(tail(&starts.borrow()[1]), "-Scan -ScanType 2");
    let status = scan_status().expect("status");
    assert!(status.running && status.kind == "full" && status.id == ended.id + 1);
    exit.store(2, Ordering::SeqCst);
    assert_eq!(scan_status().expect("status").code, Some(2));

    // Defender refusing to stop is an error.
    let runner = FakeRunner::install(&[(r"mpcmdrun\.exe -Scan -Cancel", ToolResult::new(2, "", "no scan"))]);
    let refused = execute(&spec("defender.cancel_scan", json!({})), &fx.store, None, "");
    assert!(!refused.ok());
    assert_eq!(runner.lines().len(), 1);
    set_scan_starter(None);
    reset_scan();
}

#[test]
fn turning_a_setting_on_records_the_previous_value_and_undo_restores_it() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[("Set-MpPreference", ok(r#"{"status":"ok","was":0,"now":1}"#))]);
    let record = execute(
        &spec("defender.preference_on", json!({"setting": "pua"})),
        &fx.store,
        None,
        "",
    );
    assert!(record.ok(), "{}", record.message());
    assert_eq!(record.undo_data(), Some(&json!({"setting": "pua", "previous": 0})));
    // Values travel as environment variables; the parameter name comes from Vigil's own table.
    assert_eq!(runner.ps_values("PC_NAME"), ["PUAProtection"]);
    assert_eq!(runner.ps_values("PC_VALUE"), ["1"]);
    assert_eq!(runner.ps_values("PC_ON"), ["1"]);

    let runner = FakeRunner::install(&[("Set-MpPreference", ok(r#"{"status":"ok","was":1,"now":0}"#))]);
    let message = undo(record.id(), &fx.store).expect("undo");
    assert!(message.undo_message().is_some());
    assert_eq!(runner.ps_values("PC_VALUE"), ["0"]);
    assert_eq!(runner.ps_values("PC_ON"), [""]);
}

#[test]
fn cloud_and_samples_use_their_own_values() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[("Set-MpPreference", ok(r#"{"status":"ok","was":0,"now":2}"#))]);
    assert!(
        execute(
            &spec("defender.preference_on", json!({"setting": "cloud"})),
            &fx.store,
            None,
            ""
        )
        .ok()
    );
    assert_eq!(runner.ps_values("PC_NAME"), ["MAPSReporting"]);
    assert_eq!(runner.ps_values("PC_VALUE"), ["2"]);
    assert_eq!(runner.ps_values("PC_ON"), ["1,2"]);
    let runner = FakeRunner::install(&[("Set-MpPreference", ok(r#"{"status":"ok","was":2,"now":1}"#))]);
    assert!(
        execute(
            &spec("defender.preference_on", json!({"setting": "samples"})),
            &fx.store,
            None,
            ""
        )
        .ok()
    );
    assert_eq!(runner.ps_values("PC_NAME"), ["SubmitSamplesConsent"]);
    assert_eq!(runner.ps_values("PC_VALUE"), ["1"]);
    assert_eq!(runner.ps_values("PC_ON"), ["1,3"]);
}

#[test]
fn a_setting_already_on_or_refused_is_not_recorded_as_changed() {
    let fx = Fixture::new();
    FakeRunner::install(&[("Set-MpPreference", ok(r#"{"status":"already","was":2,"now":2}"#))]);
    let already = execute(
        &spec("defender.preference_on", json!({"setting": "cloud"})),
        &fx.store,
        None,
        "",
    );
    assert!(already.ok());
    assert_eq!(already.undo_data(), None);

    FakeRunner::install(&[("Set-MpPreference", ok(r#"{"status":"refused","was":0,"now":0}"#))]);
    let refused = execute(
        &spec("defender.preference_on", json!({"setting": "pua"})),
        &fx.store,
        None,
        "",
    );
    assert!(!refused.ok());
    assert!(refused.message().contains("Windows Security"), "{}", refused.message());

    // Only the three known settings: nothing reaches PowerShell for anything else.
    let runner = FakeRunner::install(&[]);
    for setting in ["realtime", "DisableRealtimeMonitoring", "network", ""] {
        let record = execute(
            &spec("defender.preference_on", json!({"setting": setting})),
            &fx.store,
            None,
            "",
        );
        assert!(!record.ok(), "{setting}");
    }
    assert!(runner.lines().is_empty());
}

#[test]
fn removing_threats_and_the_offline_scan() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[("Remove-MpThreat", ok("0"))]);
    let removed = execute(&spec("defender.remove_threats", json!({})), &fx.store, None, "");
    assert!(removed.ok(), "{}", removed.message());
    assert_eq!(runner.lines().len(), 1);

    FakeRunner::install(&[("Remove-MpThreat", ok("2"))]);
    let left = execute(&spec("defender.remove_threats", json!({})), &fx.store, None, "");
    assert!(left.ok());
    assert!(left.message().contains('2'), "{}", left.message());

    let runner = FakeRunner::install(&[("Start-MpWDOScan", ok(""))]);
    let offline = execute(&spec("defender.offline_scan", json!({})), &fx.store, None, "");
    assert!(offline.ok(), "{}", offline.message());
    assert!(runner.lines()[0].contains("Start-MpWDOScan"));
    assert_eq!(offline.undo_data(), None);
}
