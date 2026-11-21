//! Optimization operations (disk cleanup lives in the app, next to the storage layer). Process changes act on a child process the test starts, registry changes on a scratch
//! key, and Windows tools (powercfg, sc, PowerShell) are replaced by a fake runner.

mod common;

use common::{ChildProcess, FakeRunner, Fixture, ScratchKey};
use serde_json::{Value, json};
use vigil_actions::{ActionSpec, Record, ToolResult, can_undo, execute, testing};

const BALANCED: &str = "381b4222-f694-41f0-9685-ff5bb260df2e";
const HIGH: &str = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";

fn run_spec(fx: &Fixture, op: &str, params: Value, admin: bool) -> Record {
    let mut spec = ActionSpec::new(op, op, "target", "", params);
    spec.admin = admin;
    execute(&spec, &fx.store, None, "")
}

fn child_params(child: &ChildProcess, extra: Value) -> Value {
    let created = vigil_actions::Proc::get(i64::from(child.pid()))
        .ok()
        .and_then(|p| p.create_time());
    let mut params = json!({"pid": child.pid(), "create_time": created});
    if let (Some(map), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        map.extend(extra.clone());
    }
    params
}

fn priority_of(pid: u32) -> String {
    let out = common::powershell(
        "(Get-Process -Id ([int]$env:PC_PID)).PriorityClass.ToString()",
        &[("pid", &pid.to_string())],
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// How the app names a priority class reported by PowerShell.
fn priority_label(class: &str) -> &str {
    match class {
        "Idle" => "Low",
        "BelowNormal" => "Below normal",
        "AboveNormal" => "Above normal",
        other => other,
    }
}

// The child inherits the test runner's priority class (Normal on a desktop, Below normal on some CI
// machines), so the tests compare with what it started with instead of assuming Normal.
#[test]
fn priority_is_set_and_undone() {
    let fx = Fixture::new();
    testing::set_admin(Some(false));
    let child = ChildProcess::start();
    let before = priority_of(child.pid());
    let record = run_spec(
        &fx,
        "process.priority",
        child_params(&child, json!({"priority": "idle"})),
        false,
    );
    assert!(record.ok(), "{}", record.message());
    assert_eq!(
        record.message(),
        format!(
            "PING.EXE (PID {}) now runs at Low priority (it was {})",
            child.pid(),
            priority_label(&before)
        )
    );
    assert_eq!(priority_of(child.pid()), "Idle");
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(priority_of(child.pid()), before);
}

#[test]
fn efficiency_mode_lowers_priority_and_is_undone() {
    let fx = Fixture::new();
    testing::set_admin(Some(false));
    let child = ChildProcess::start();
    let before = priority_of(child.pid());
    let record = run_spec(&fx, "process.efficiency", child_params(&child, json!({})), false);
    assert!(record.ok(), "{}", record.message());
    assert_eq!(priority_of(child.pid()), "Idle");
    let undone = vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(priority_of(child.pid()), before);
    assert!(
        undone
            .undo_message()
            .is_some_and(|m| m.ends_with("left efficiency mode"))
    );
}

#[test]
fn background_lowers_disk_and_memory_priority_and_is_undone() {
    let fx = Fixture::new();
    testing::set_admin(Some(false));
    let child = ChildProcess::start();
    let before = vigil_actions::io_memory_priority(child.pid()).expect("read priorities");
    let record = run_spec(&fx, "process.background", child_params(&child, json!({})), false);
    assert!(record.ok(), "{}", record.message());
    let (io, memory) = vigil_actions::io_memory_priority(child.pid()).expect("read priorities");
    assert!(io <= 1 && memory <= 2, "io {io}, memory {memory}");
    assert!(can_undo(&record));
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(
        vigil_actions::io_memory_priority(child.pid()).expect("read priorities"),
        before
    );
}

#[test]
fn trim_reports_memory() {
    let fx = Fixture::new();
    let child = ChildProcess::start();
    let record = run_spec(&fx, "process.trim", child_params(&child, json!({})), false);
    assert!(record.ok(), "{}", record.message());
    assert!(record.message().contains("of RAM now"), "{}", record.message());
    assert!(!can_undo(&record));
}

#[test]
fn own_process_and_reused_pid_are_refused() {
    let fx = Fixture::new();
    let record = run_spec(
        &fx,
        "process.priority",
        json!({"pid": std::process::id(), "priority": "idle"}),
        false,
    );
    assert!(!record.ok());
    assert!(record.message().contains("Vigil itself"), "{}", record.message());
    let child = ChildProcess::start();
    let mut params = child_params(&child, json!({"priority": "idle"}));
    params["create_time"] = json!(params["create_time"].as_f64().unwrap_or(0.0) - 100.0);
    let record = run_spec(&fx, "process.priority", params, false);
    assert!(!record.ok());
    assert!(record.message().contains("exited"), "{}", record.message());
}

#[test]
fn no_admin_needed_for_own_processes() {
    let fx = Fixture::new();
    testing::set_admin(Some(false));
    FakeRunner::install(&[]);
    let needs_admin = |op: &str| {
        let record = run_spec(&fx, op, json!({}), true);
        record.message() == "this action needs Vigil to run as administrator"
    };
    for op in [
        "process.priority",
        "process.efficiency",
        "process.trim",
        "power.plan",
        "gpu.preference",
        "gaming.game_mode",
    ] {
        assert!(!needs_admin(op), "{op}");
    }
    for op in [
        "memory.purge_standby",
        "memory.trim_all",
        "power.hibernate",
        "gaming.hags",
        "disk.optimize",
    ] {
        assert!(needs_admin(op), "{op}");
    }
}

#[test]
fn switching_plan_remembers_the_previous_one() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[(
        "getactivescheme",
        ToolResult::new(0, format!("Power Scheme GUID: {BALANCED}  (Balanced)"), ""),
    )]);
    let params = json!({"guid": HIGH, "name": "High performance", "previous_name": "Balanced"});
    let record = run_spec(&fx, "power.plan", params, false);
    assert!(record.ok(), "{}", record.message());
    assert!(runner.lines().contains(&format!("powercfg.exe /setactive {HIGH}")));
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(
        runner.lines().last(),
        Some(&format!("powercfg.exe /setactive {BALANCED}"))
    );
}

#[test]
fn plan_identifier_is_validated() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[]);
    let record = run_spec(
        &fx,
        "power.plan",
        json!({"guid": "SCHEME_MIN & calc", "name": "x"}),
        false,
    );
    assert!(!record.ok());
    assert!(!runner.lines().iter().any(|line| line.contains("/setactive")));
}

#[test]
fn hibernation_off_is_undone_with_on() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[]);
    let record = run_spec(&fx, "power.hibernate", json!({"on": false}), true);
    assert!(record.ok(), "{}", record.message());
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(
        runner.lines(),
        ["powercfg.exe /hibernate off", "powercfg.exe /hibernate on"]
    );
}

#[test]
fn ultimate_plan_is_added_and_removed() {
    let fx = Fixture::new();
    let new = "11111111-2222-3333-4444-555555555555";
    let runner = FakeRunner::install(&[
        (
            "duplicatescheme",
            ToolResult::new(0, format!("Power Scheme GUID: {new}  (Ultimate)"), ""),
        ),
        (
            "getactivescheme",
            ToolResult::new(0, format!("Power Scheme GUID: {new}"), ""),
        ),
    ]);
    let record = run_spec(&fx, "power.ultimate", json!({}), true);
    assert!(record.ok(), "{}", record.message());
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert!(runner.lines().contains(&format!("powercfg.exe /setactive {BALANCED}")));
    assert_eq!(runner.lines().last(), Some(&format!("powercfg.exe /delete {new}")));
}

#[test]
fn gpu_preference_keeps_other_fields_and_is_undone() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("Tuning");
    testing::redirect_setting("gpu", &scratch.key);
    let exe = std::env::current_exe().expect("exe").to_string_lossy().into_owned();
    vigil_actions::reg_write(
        &scratch.key,
        &exe,
        &json!({"type": "REG_SZ", "data": "SwapEffectUpgradeEnable=1;"}),
    )
    .expect("write");
    let record = run_spec(&fx, "gpu.preference", json!({"exe": exe, "preference": 2}), false);
    assert!(record.ok(), "{}", record.message());
    let read = vigil_actions::reg_read(&scratch.key, &exe)
        .expect("read")
        .expect("value");
    assert_eq!(read["data"], "SwapEffectUpgradeEnable=1;GpuPreference=2;");
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    let read = vigil_actions::reg_read(&scratch.key, &exe)
        .expect("read")
        .expect("value");
    assert_eq!(read["data"], "SwapEffectUpgradeEnable=1;");
}

#[test]
fn gpu_preference_needs_an_existing_exe() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("Tuning");
    testing::redirect_setting("gpu", &scratch.key);
    let record = run_spec(
        &fx,
        "gpu.preference",
        json!({"exe": "C:\\nope\\missing.exe", "preference": 2}),
        false,
    );
    assert!(!record.ok());
}

#[test]
fn game_mode_toggle_is_undone() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("Tuning");
    testing::redirect_setting("game_mode", &scratch.key);
    let record = run_spec(&fx, "gaming.game_mode", json!({"on": false}), false);
    assert!(record.ok(), "{}", record.message());
    let read = vigil_actions::reg_read(&scratch.key, "AutoGameModeEnabled")
        .expect("read")
        .expect("value");
    assert_eq!(read["data"], 0);
    let undone = vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(undone.undo_message(), Some("restored Tuning\\AutoGameModeEnabled"));
    // It did not exist before.
    assert_eq!(
        vigil_actions::reg_read(&scratch.key, "AutoGameModeEnabled").expect("read"),
        None
    );
}

fn fake_service(start: i64, delayed: bool) {
    let mut map = serde_json::Map::new();
    map.insert("Start".into(), json!(start));
    map.insert("DelayedAutostart".into(), json!(i64::from(delayed)));
    testing::set_service_reg(Some(std::rc::Rc::new(move |_: &str| Ok(map.clone()))));
}

#[test]
fn service_manual_and_undo() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[]);
    fake_service(2, true);
    let record = run_spec(&fx, "service.manual", json!({"name": "AcmeUpdater"}), true);
    assert!(record.ok(), "{}", record.message());
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(
        runner.lines(),
        [
            "sc.exe config AcmeUpdater start= demand",
            "sc.exe config AcmeUpdater start= delayed-auto"
        ]
    );
}

#[test]
fn boot_drivers_are_not_changed() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[]);
    fake_service(0, false);
    let record = run_spec(&fx, "service.manual", json!({"name": "acmedrv"}), true);
    assert!(!record.ok());
    assert!(runner.calls.borrow().is_empty());
}

#[test]
fn drive_optimize_uses_trim_for_ssd_and_validates_the_letter() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[]);
    let ok = run_spec(&fx, "disk.optimize", json!({"drive": "C:", "media": "SSD"}), true);
    let bad = run_spec(
        &fx,
        "disk.optimize",
        json!({"drive": "C; Remove-Item", "media": "SSD"}),
        true,
    );
    assert!(ok.ok(), "{}", ok.message());
    assert_eq!(ok.message(), "C: was trimmed (the SSD now knows which blocks are free)");
    let calls = runner.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0]
            .args
            .last()
            .is_some_and(|script| script.ends_with("-DriveLetter $env:PC_DRIVE -ReTrim"))
    );
    assert_eq!(runner.ps_values("PC_DRIVE"), ["C"]);
    assert!(!bad.ok());
}

#[test]
fn component_cleanup_accepts_restart_needed() {
    let fx = Fixture::new();
    FakeRunner::install(&[("dism", ToolResult::new(3010, "", ""))]);
    let record = run_spec(&fx, "disk.component_cleanup", json!({}), true);
    assert!(record.ok(), "{}", record.message());
}
