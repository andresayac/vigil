//! The action layer: guards, journal, quarantine, undo and every operation, without changing the machine.

mod common;

use std::cell::Cell;
use std::fs;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use common::{ChildProcess, FakeRunner, Fixture, ScratchKey, TempDir};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vigil_actions::{
    ActionSpec, Outcome, Record, SignatureInfo, Store, ToolResult, can_undo, execute, execute_plan, testing,
};

fn spec(op: &str, params: Value) -> ActionSpec {
    ActionSpec::new(op, op, "target", "", params)
}

fn victim(fx: &Fixture, name: &str, data: &[u8]) -> String {
    let folder = fx.tmp.path().join("victim");
    fs::create_dir_all(&folder).expect("folder");
    let path = folder.join(name);
    fs::write(&path, data).expect("file");
    path.to_string_lossy().into_owned()
}

fn signed_by_microsoft() -> SignatureInfo {
    SignatureInfo {
        exists: Some(true),
        sig_status: Some("Valid".into()),
        signer: Some("Microsoft Corporation".into()),
        issuer: Some("Microsoft Code Signing PCA 2011".into()),
        ..SignatureInfo::default()
    }
}

fn no_signature() {
    testing::set_signature(Some(Rc::new(|_: &str| None)));
}

// --------------------------------------------------------------------------- quarantine

#[test]
fn quarantine_and_restore_round_trip() {
    let fx = Fixture::new();
    let original: Vec<u8> = b"MZ".iter().copied().chain((0..9000).flat_map(|_| 0u8..=255)).collect();
    let path = victim(&fx, "evil.exe", &original);
    let outcome = vigil_actions::quarantine_file(&path, &fx.store, "test", false, false).expect("quarantine");
    assert!(!fs::exists(&path).unwrap_or(true));
    let qid = outcome
        .undo
        .as_ref()
        .and_then(|u| u["quarantine_id"].as_str())
        .expect("id")
        .to_string();
    let blob = fs::read(fx.store.quarantine_dir().join(format!("{qid}.bin"))).expect("blob");
    assert_eq!(blob.len(), original.len());
    assert_ne!(blob, original);
    assert!(!blob[..16].windows(5).any(|w| w == b"MZ\x00\x01\x02"));
    let entries = fx.store.quarantined();
    assert_eq!(entries[0].original_path, path);
    assert_eq!(entries[0].sha256, format!("{:x}", Sha256::digest(&original)));
    assert!(entries[0].present);
    vigil_actions::restore_quarantined(&qid, &fx.store).expect("restore");
    assert_eq!(fs::read(&path).expect("restored"), original);
    assert!(fx.store.quarantined().is_empty());
    assert!(vigil_actions::restore_quarantined(&qid, &fx.store).is_err());
}

#[test]
fn restore_refuses_to_overwrite_and_detects_damage() {
    let fx = Fixture::new();
    let path = victim(&fx, "evil.exe", &b"payload".repeat(100));
    let outcome = vigil_actions::quarantine_file(&path, &fx.store, "", false, false).expect("quarantine");
    let qid = outcome
        .undo
        .as_ref()
        .and_then(|u| u["quarantine_id"].as_str())
        .expect("id")
        .to_string();
    fs::write(&path, b"new file").expect("write");
    let refused = vigil_actions::restore_quarantined(&qid, &fx.store).expect_err("overwrite");
    assert!(refused.message().contains("already exists"), "{refused}");
    fs::remove_file(&path).expect("remove");
    let blob = fx.store.quarantine_dir().join(format!("{qid}.bin"));
    let mut data = fs::read(&blob).expect("blob");
    data[0] ^= 0xFF;
    fs::write(&blob, data).expect("damage");
    let damaged = vigil_actions::restore_quarantined(&qid, &fx.store).expect_err("damaged");
    assert!(damaged.message().contains("hash mismatch"), "{damaged}");
    assert!(!fs::exists(&path).unwrap_or(true));
    assert!(!fs::exists(format!("{path}.pc-restore")).unwrap_or(true));
}

#[test]
fn execute_journals_and_undo_restores() {
    let fx = Fixture::new();
    no_signature();
    let path = victim(&fx, "evil.exe", &b"abc".repeat(1000));
    let record = execute(
        &spec("file.quarantine", json!({"path": path, "kill": false})),
        &fx.store,
        None,
        "",
    );
    assert!(record.ok(), "{}", record.message());
    assert!(can_undo(&record));
    assert_eq!(fx.store.records()[0].id(), record.id());
    let keys: Vec<&String> = record.0.keys().collect();
    assert_eq!(
        keys,
        [
            "id", "batch", "time", "op", "label", "target", "item", "params", "ok", "message", "undo", "undone"
        ]
    );
    let undone = vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert!(fs::exists(&path).unwrap_or(false));
    assert!(undone.undone());
    assert!(
        fx.store
            .find(record.id())
            .is_some_and(|r| r.undone() && r.undo_message().is_some())
    );
    assert!(vigil_actions::undo(record.id(), &fx.store).is_err());
}

#[test]
fn delete_quarantined_names_the_file() {
    let fx = Fixture::new();
    let path = victim(&fx, "tool.exe", b"xyz");
    let outcome = vigil_actions::quarantine_file(&path, &fx.store, "", false, false).expect("quarantine");
    let qid = outcome
        .undo
        .as_ref()
        .and_then(|u| u["quarantine_id"].as_str())
        .expect("id")
        .to_string();
    assert_eq!(
        vigil_actions::delete_quarantined(&qid, &fx.store).ok().as_deref(),
        Some("permanently deleted tool.exe")
    );
    assert!(fx.store.quarantined().is_empty());
    assert!(vigil_actions::restore_quarantined("..\\..\\x", &fx.store).is_err());
}

#[test]
fn guards() {
    let fx = Fixture::new();
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let own = std::env::current_exe().expect("exe").to_string_lossy().into_owned();
    for path in [
        format!(r"{windir}\System32\notepad.exe"),
        own,
        r"relative\file.exe".to_string(),
    ] {
        assert!(vigil_actions::guard_file(&path, false).is_err(), "{path}");
    }
    assert!(vigil_actions::guard_file(&format!(r"{windir}\Temp\x.exe"), false).is_ok());
    testing::set_signature(Some(Rc::new(|_: &str| Some(signed_by_microsoft()))));
    let signed = victim(&fx, "signed.exe", b"MZ");
    assert!(vigil_actions::guard_file(&signed, true).is_err());
}

// --------------------------------------------------------------------------- registry

#[test]
fn registry_values_round_trip() {
    let _fx = Fixture::new();
    let scratch = ScratchKey::new("roundtrip");
    for (name, snapshot) in [
        ("sz", json!({"type": "REG_SZ", "data": "C:\\x.exe --y"})),
        ("expand", json!({"type": "REG_EXPAND_SZ", "data": "%APPDATA%\\x.exe"})),
        ("dword", json!({"type": "REG_DWORD", "data": 7})),
        ("qword", json!({"type": "REG_QWORD", "data": 1u64 << 40})),
        ("multi", json!({"type": "REG_MULTI_SZ", "data": ["a", "b"]})),
        ("bin", json!({"type": "REG_BINARY", "data": {"hex": "0300000001"}})),
        ("numeric", json!({"type": 4, "data": 9})),
    ] {
        vigil_actions::reg_write(&scratch.key, name, &snapshot).expect("write");
        let read = vigil_actions::reg_read(&scratch.key, name)
            .expect("read")
            .expect("value");
        if name == "numeric" {
            assert_eq!(read, json!({"type": "REG_DWORD", "data": 9}));
        } else {
            assert_eq!(read, snapshot, "{name}");
        }
        vigil_actions::reg_delete(&scratch.key, name).expect("delete");
        assert_eq!(vigil_actions::reg_read(&scratch.key, name).expect("read"), None);
    }
    assert!(vigil_actions::reg_delete(&scratch.key, "missing").is_ok());
    assert!(vigil_actions::reg_write(&scratch.key, "x", &json!({"type": "REG_NOPE", "data": 1})).is_err());
}

#[test]
fn only_startup_locations_are_editable() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("editable");
    for (key, value) in [
        (r"HKLM\SYSTEM\CurrentControlSet\Services\x", "ImagePath"),
        (
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\a.exe",
            "GlobalFlag",
        ),
        (
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\..\..\Policies",
            "x",
        ),
        (scratch.key.as_str(), "x"),
    ] {
        let record = execute(
            &spec("registry.delete", json!({"key": key, "value": value})),
            &fx.store,
            None,
            "",
        );
        assert!(!record.ok(), "{key}");
        assert!(
            record.message().contains("only edits startup locations"),
            "{}",
            record.message()
        );
    }
}

fn scratch_run_keys(scratch: &ScratchKey) -> (String, String) {
    let run_key = format!("{}\\Run", scratch.key);
    let approved = format!("{}\\Approved", scratch.key);
    testing::allow_editable_key(&run_key);
    let mapped = approved.clone();
    testing::set_approved_location(Some(Rc::new(move |_: &str| Some(mapped.clone()))));
    (run_key, approved)
}

#[test]
fn disable_startup_entry_and_undo() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("startup");
    let (run_key, approved) = scratch_run_keys(&scratch);
    vigil_actions::reg_write(
        &run_key,
        "Updater",
        &json!({"type": "REG_SZ", "data": "C:\\x\\updater.exe"}),
    )
    .expect("w");
    let disable = spec("startup.disable", json!({"key": run_key, "value": "Updater"}));
    let record = execute(&disable, &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    let blob = vigil_actions::reg_read(&approved, "Updater")
        .expect("read")
        .expect("blob");
    assert_eq!(blob["type"], "REG_BINARY");
    let hex = blob["data"]["hex"].as_str().expect("hex");
    assert_eq!(hex.len(), 24);
    assert!(hex.starts_with("03000000"));
    assert!(
        vigil_actions::reg_read(&run_key, "Updater").expect("read").is_some(),
        "the entry itself stays"
    );
    let again = execute(&disable, &fx.store, None, "");
    assert!(again.message().contains("already"), "{}", again.message());
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(vigil_actions::reg_read(&approved, "Updater").expect("read"), None);
}

#[test]
fn enable_startup_entry_and_undo() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("enable");
    let (run_key, approved) = scratch_run_keys(&scratch);
    vigil_actions::reg_write(
        &run_key,
        "Updater",
        &json!({"type": "REG_SZ", "data": "C:\\x\\updater.exe"}),
    )
    .expect("w");
    let enable = spec("startup.enable", json!({"key": run_key, "value": "Updater"}));
    let first = execute(&enable, &fx.store, None, "");
    assert!(
        first.ok() && first.message().contains("already"),
        "no switch value means on: {}",
        first.message()
    );
    let off = json!({"type": "REG_BINARY", "data": {"hex": "030000000080e2c0f87adc01"}});
    vigil_actions::reg_write(&approved, "Updater", &off).expect("w");
    let record = execute(&enable, &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    let blob = vigil_actions::reg_read(&approved, "Updater")
        .expect("read")
        .expect("blob");
    assert_eq!(blob["data"]["hex"], "020000000000000000000000");
    let again = execute(&enable, &fx.store, None, "");
    assert!(again.message().contains("already"), "{}", again.message());
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(
        vigil_actions::reg_read(&approved, "Updater").expect("read"),
        Some(off),
        "undo restores the previous bytes"
    );
    let gone = execute(
        &spec("startup.enable", json!({"key": run_key, "value": "Missing"})),
        &fx.store,
        None,
        "",
    );
    assert!(!gone.ok(), "an entry that is gone is refused");
}

#[test]
fn delete_startup_entry_and_undo() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("delete");
    let (run_key, _approved) = scratch_run_keys(&scratch);
    let snapshot = json!({"type": "REG_EXPAND_SZ", "data": "%APPDATA%\\x\\y.exe -silent"});
    vigil_actions::reg_write(&run_key, "Thing", &snapshot).expect("write");
    let record = execute(
        &spec("registry.delete", json!({"key": run_key, "value": "Thing"})),
        &fx.store,
        None,
        "",
    );
    assert!(record.ok(), "{}", record.message());
    assert_eq!(vigil_actions::reg_read(&run_key, "Thing").expect("read"), None);
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(
        vigil_actions::reg_read(&run_key, "Thing").expect("read"),
        Some(snapshot)
    );
}

// --------------------------------------------------------------------------- services and tasks

#[test]
fn essential_and_microsoft_services_are_refused() {
    let _fx = Fixture::new();
    assert!(vigil_actions::guard_service("WinDefend", &serde_json::Map::new()).is_err());
    let checks = Rc::new(Cell::new(0));
    let counter = checks.clone();
    testing::set_signature(Some(Rc::new(move |_: &str| {
        counter.set(counter.get() + 1);
        Some(signed_by_microsoft())
    })));
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut values = serde_json::Map::new();
    values.insert(
        "ImagePath".into(),
        json!(format!(r"{windir}\System32\svchost.exe -k netsvcs")),
    );
    values.insert("ServiceDll".into(), json!(format!(r"{windir}\System32\x.dll")));
    assert!(vigil_actions::guard_service("SomeWindowsService", &values).is_err());
    // A third-party DLL hosted in svchost is not protected by svchost's signature.
    checks.set(0);
    values.insert("ServiceDll".into(), json!(r"C:\ProgramData\evil\evil.dll"));
    assert!(vigil_actions::guard_service("EvilService", &values).is_ok());
    assert_eq!(checks.get(), 0);
}

fn fake_service(values: Value, states: &[&str]) {
    let map = values.as_object().cloned().unwrap_or_default();
    testing::set_service_reg(Some(Rc::new(move |_: &str| Ok(map.clone()))));
    let states = Rc::new(std::cell::RefCell::new(
        states.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
    ));
    testing::set_service_status(Some(Rc::new(move |_: &str| {
        let mut states = states.borrow_mut();
        Some(if states.is_empty() {
            "stopped".to_string()
        } else {
            states.remove(0)
        })
    })));
    testing::set_no_sleep(true);
    no_signature();
}

#[test]
fn disable_service_stops_it_and_undo_restores() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[]);
    fake_service(
        json!({"Start": 2, "DelayedAutostart": 1, "ImagePath": "C:\\x\\svc.exe"}),
        &["running", "running", "stopped", "stopped"],
    );
    let record = execute(
        &spec("service.disable", json!({"name": "Evil Svc"})),
        &fx.store,
        None,
        "",
    );
    assert!(record.ok(), "{}", record.message());
    assert!(runner.lines().contains(&"sc.exe stop Evil Svc".to_string()));
    assert!(
        runner
            .lines()
            .contains(&"sc.exe config Evil Svc start= disabled".to_string())
    );
    assert_eq!(
        record.undo_data(),
        Some(&json!({"name": "Evil Svc", "start": 2, "delayed": true, "was_running": true}))
    );
    assert_eq!(
        record.message(),
        "disabled \"Evil Svc\" (it was set to delayed-auto start) and stopped it"
    );
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert!(
        runner
            .lines()
            .contains(&"sc.exe config Evil Svc start= delayed-auto".to_string())
    );
    assert!(runner.lines().contains(&"sc.exe start Evil Svc".to_string()));
}

#[test]
fn start_restart_and_start_type_go_through_sc_and_the_guards() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[]);
    fake_service(
        json!({"Start": 3, "ImagePath": "C:\\x\\svc.exe"}),
        &["stopped", "running"],
    );
    let started = execute(&spec("service.start", json!({"name": "Evil Svc"})), &fx.store, None, "");
    assert!(started.ok(), "{}", started.message());
    assert!(runner.lines().contains(&"sc.exe start Evil Svc".to_string()));
    assert!(!can_undo(&started), "starting is not undone");

    fake_service(
        json!({"Start": 3, "ImagePath": "C:\\x\\svc.exe"}),
        &["running", "stopped", "running"],
    );
    let restarted = execute(
        &spec("service.restart", json!({"name": "Evil Svc"})),
        &fx.store,
        None,
        "",
    );
    assert!(restarted.ok(), "{}", restarted.message());
    let lines = runner.lines();
    let stop = lines
        .iter()
        .rposition(|l| l == "sc.exe stop Evil Svc")
        .expect("stopped");
    let start = lines
        .iter()
        .rposition(|l| l == "sc.exe start Evil Svc")
        .expect("started");
    assert!(stop < start, "stop before start: {lines:?}");

    fake_service(
        json!({"Start": 2, "DelayedAutostart": 1, "ImagePath": "C:\\x\\svc.exe"}),
        &["running"],
    );
    let changed = execute(
        &spec(
            "service.start_type",
            json!({"name": "Evil Svc", "start_type": "demand"}),
        ),
        &fx.store,
        None,
        "",
    );
    assert!(changed.ok(), "{}", changed.message());
    assert!(
        runner
            .lines()
            .contains(&"sc.exe config Evil Svc start= demand".to_string())
    );
    assert_eq!(
        changed.undo_data(),
        Some(&json!({"name": "Evil Svc", "start": 2, "delayed": true, "was_running": false}))
    );
    vigil_actions::undo(changed.id(), &fx.store).expect("undo");
    assert!(
        runner
            .lines()
            .contains(&"sc.exe config Evil Svc start= delayed-auto".to_string()),
        "undo restores the previous startup type"
    );
}

#[test]
fn start_type_refuses_unknown_values_disabled_services_and_essential_ones() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[]);
    fake_service(json!({"Start": 3, "ImagePath": "C:\\x\\svc.exe"}), &["stopped"]);
    let odd = execute(
        &spec("service.start_type", json!({"name": "Evil Svc", "start_type": "boot"})),
        &fx.store,
        None,
        "",
    );
    assert!(
        !odd.ok() && odd.message().contains("unknown startup type"),
        "{}",
        odd.message()
    );
    fake_service(json!({"Start": 4, "ImagePath": "C:\\x\\svc.exe"}), &["stopped"]);
    let disabled = execute(&spec("service.start", json!({"name": "Evil Svc"})), &fx.store, None, "");
    assert!(
        !disabled.ok() && disabled.message().contains("disabled"),
        "{}",
        disabled.message()
    );
    fake_service(json!({"Start": 2}), &["running"]);
    let essential = execute(
        &spec("service.restart", json!({"name": "WinDefend"})),
        &fx.store,
        None,
        "",
    );
    assert!(!essential.ok(), "essential services are refused");
    assert!(
        runner.lines().iter().all(|l| !l.starts_with("sc.exe")),
        "{:?}",
        runner.lines()
    );
}

#[test]
fn failed_tool_is_reported_not_raised() {
    let fx = Fixture::new();
    FakeRunner::install(&[(
        r"sc\.exe config",
        ToolResult::new(5, "[SC] OpenService FAILED 5:\nAccess is denied.", ""),
    )]);
    fake_service(json!({"Start": 3}), &["stopped"]);
    let record = execute(&spec("service.disable", json!({"name": "x"})), &fx.store, None, "");
    assert!(!record.ok());
    assert!(record.message().contains("Access is denied"), "{}", record.message());
    assert!(!can_undo(&record));
}

#[test]
fn service_delete_backs_up_the_key_with_the_record_id() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[]);
    fake_service(json!({"Start": 3}), &["stopped"]);
    // reg.exe is faked and writes no backup file, so the service must not be deleted.
    let backups = fx.store.backup_dir();
    let record = execute(
        &spec("service.delete", json!({"name": "Evil Svc"})),
        &fx.store,
        None,
        "",
    );
    assert!(!record.ok());
    assert!(
        record.message().starts_with("could not back up"),
        "{}",
        record.message()
    );
    assert!(!runner.lines().iter().any(|l| l.starts_with("sc.exe delete")));
    let export = runner
        .lines()
        .into_iter()
        .find(|l| l.starts_with("reg.exe export"))
        .expect("export");
    assert!(export.contains(&format!("{}.reg", record.id())), "{export}");
    assert!(export.contains(&backups.to_string_lossy().into_owned()));
}

const ENABLED_TASK: &str =
    r#"<?xml version="1.0" encoding="UTF-16"?><Task><Settings><Enabled>true</Enabled></Settings></Task>"#;

#[test]
fn task_disable_delete_and_undo() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[(r"/Query", ToolResult::new(0, ENABLED_TASK, ""))]);
    let params = json!({"path": "\\Vendor\\", "name": "Updater Task"});
    let record = execute(&spec("task.disable", params.clone()), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert!(
        runner
            .lines()
            .contains(&r"schtasks.exe /Change /TN \Vendor\Updater Task /DISABLE".to_string())
    );
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert!(
        runner
            .lines()
            .contains(&r"schtasks.exe /Change /TN \Vendor\Updater Task /ENABLE".to_string())
    );

    let deleted = execute(&spec("task.delete", params), &fx.store, None, "");
    assert!(deleted.ok(), "{}", deleted.message());
    let backup = deleted
        .undo_data()
        .and_then(|u| u["backup"].as_str())
        .expect("backup")
        .to_string();
    assert!(backup.ends_with(&format!("{}.xml", deleted.id())));
    let bytes = fs::read(&backup).expect("backup file");
    assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
    let units: Vec<u16> = bytes[2..].chunks(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
    assert!(String::from_utf16_lossy(&units).starts_with("<?xml"));
    vigil_actions::undo(deleted.id(), &fx.store).expect("undo");
    assert!(
        runner
            .lines()
            .contains(&format!(r"schtasks.exe /Create /TN \Vendor\Updater Task /XML {backup}"))
    );
}

#[test]
fn microsoft_tasks_are_refused() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[]);
    let params = json!({"path": "\\Microsoft\\Windows\\Defrag\\", "name": "ScheduledDefrag"});
    let record = execute(&spec("task.disable", params), &fx.store, None, "");
    assert!(!record.ok());
    assert!(runner.calls.borrow().is_empty());
}

#[test]
fn powershell_values_travel_in_the_environment() {
    let _fx = Fixture::new();
    let runner = FakeRunner::install(&[]);
    let evil = "C:\\x'; Remove-Item C:\\ -Recurse; '";
    vigil_actions::run_powershell("Remove-MpPreference -ExclusionPath $env:PC_VALUE", &[("value", evil)]).expect("run");
    assert!(!runner.calls.borrow()[0].args.join(" ").contains("Remove-Item"));
    assert_eq!(runner.ps_values("PC_VALUE"), [evil]);
}

#[test]
fn firewall_rules_and_defender_exclusions_use_environment_values() {
    let fx = Fixture::new();
    no_signature();
    let runner = FakeRunner::install(&[]);
    let exe = victim(&fx, "net tool.exe", b"MZ");
    let record = execute(&spec("firewall.block", json!({"path": exe})), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    let rules: Vec<String> = record
        .undo_data()
        .and_then(|u| u["rules"].as_array())
        .expect("rules")
        .iter()
        .map(|r| r.to_string())
        .collect();
    assert_eq!(rules.len(), 2);
    assert_eq!(runner.ps_values("PC_PATH"), std::slice::from_ref(&exe));
    assert_eq!(runner.ps_values("PC_LABEL"), ["net tool.exe"]);
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    let removed = runner.ps_values("PC_NAME");
    assert_eq!(removed.len(), 2);
    assert!(removed[0].starts_with("Vigil-") && removed[0].ends_with("-out"));

    let record = execute(
        &spec("defender.remove_exclusion", json!({"value": "C:\\Games"})),
        &fx.store,
        None,
        "",
    );
    assert!(record.ok(), "{}", record.message());
    assert_eq!(
        record.undo_data(),
        Some(&json!({"kind": "ExclusionPath", "value": "C:\\Games"}))
    );
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    let scripts: Vec<String> = runner
        .calls
        .borrow()
        .iter()
        .filter_map(|c| c.args.last().cloned())
        .collect();
    assert!(
        scripts
            .iter()
            .any(|s| s.ends_with("Add-MpPreference -ExclusionPath $env:PC_VALUE"))
    );
}

// --------------------------------------------------------------------------- processes

#[test]
fn terminate_child_process() {
    let fx = Fixture::new();
    testing::set_admin(Some(false));
    let mut child = ChildProcess::start();
    let mut terminate = spec(
        "process.terminate",
        json!({"pids": [child.pid()], "names": ["PING.EXE"]}),
    );
    terminate.admin = false;
    let record = execute(&terminate, &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert!(record.message().starts_with("ended PING.EXE"), "{}", record.message());
    assert!(child.wait_exit(10));
}

#[test]
fn terminate_a_group_only_ends_the_confirmed_instances() {
    let fx = Fixture::new();
    testing::set_admin(Some(false));
    let mut first = ChildProcess::start();
    let second = ChildProcess::start();
    let started = |pid: u32| {
        vigil_actions::Proc::get(i64::from(pid))
            .ok()
            .and_then(|p| p.create_time())
    };
    let mut terminate = spec(
        "process.terminate",
        json!({
            "pids": [first.pid(), second.pid()],
            "names": ["PING.EXE"],
            "instances": [
                {"pid": first.pid(), "create_time": started(first.pid())},
                // Recorded before the PID was reused: left alone.
                {"pid": second.pid(), "create_time": started(second.pid()).unwrap_or(0.0) - 100.0},
            ],
        }),
    );
    terminate.admin = false;
    let record = execute(&terminate, &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert_eq!(record.message(), format!("ended PING.EXE (PID {})", first.pid()));
    assert!(first.wait_exit(10));
    assert!(
        vigil_actions::Proc::get(i64::from(second.pid())).is_ok(),
        "the other instance still runs"
    );
}

#[test]
fn suspend_and_resume_a_child_process() {
    let fx = Fixture::new();
    testing::set_admin(Some(false));
    let child = ChildProcess::start();
    let mut suspend = spec("process.suspend", json!({"pid": child.pid()}));
    suspend.admin = true; // a no-admin operation: works without elevation anyway
    let record = execute(&suspend, &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert!(record.undo_data().is_some_and(|u| u["create_time"].as_f64().is_some()));
    let undone = vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(
        undone.undo_message(),
        Some(format!("resumed PING.EXE (PID {})", child.pid()).as_str())
    );
}

#[test]
fn never_ends_itself_or_the_kernel() {
    let fx = Fixture::new();
    let own = vigil_actions::Proc::get(i64::from(std::process::id())).expect("own process");
    assert!(vigil_actions::process_protection(&own).is_some());
    let record = execute(
        &spec("process.terminate", json!({"pids": [std::process::id(), 4]})),
        &fx.store,
        None,
        "",
    );
    assert!(!record.ok());
    assert!(record.message().contains("Vigil itself"), "{}", record.message());
    assert!(record.message().contains("Windows kernel"), "{}", record.message());
}

#[test]
fn stale_pid_from_an_old_scan_is_ignored() {
    let exe = std::env::current_exe().expect("exe");
    let name = exe.file_name().expect("name").to_string_lossy().into_owned();
    let pid = i64::from(std::process::id());
    let found = vigil_actions::find_processes(None, &[pid], std::slice::from_ref(&name), Some("2000-01-01T00:00:00"));
    assert!(found.is_empty());
    let found = vigil_actions::find_processes(None, &[pid], &[name], None);
    assert_eq!(found.len(), 1);
}

// --------------------------------------------------------------------------- journal

#[test]
fn unknown_action_is_recorded_as_failed() {
    let fx = Fixture::new();
    let record = execute(&spec("nope", json!({})), &fx.store, None, "");
    assert!(!record.ok());
    assert_eq!(record.message(), "unknown action nope");
    assert_eq!(fx.store.records().len(), 1);
}

#[test]
fn admin_actions_refuse_without_elevation() {
    let fx = Fixture::new();
    testing::set_admin(Some(false));
    let record = execute(&spec("rdp.disable", json!({})), &fx.store, None, "");
    assert!(!record.ok());
    assert!(record.message().contains("administrator"));
}

#[test]
fn batch_undo_runs_in_reverse_order() {
    let fx = Fixture::new();
    let order: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    for name in ["a", "b"] {
        let log = order.clone();
        vigil_actions::register(
            &format!("test.batch_{name}"),
            Arc::new(move |_: &Value, _: &Store, _: &str| Ok(Outcome::new(name, Some(json!({"n": name}))))),
            Some(Arc::new(move |undo: &Value, _: &Store| {
                log.lock()
                    .expect("log")
                    .push(undo["n"].as_str().unwrap_or("").to_string());
                Ok(format!("undid {name}"))
            })),
            true,
        );
    }
    let mut plan = spec("plan.remove", json!({}));
    plan.steps = vec![spec("test.batch_a", json!({})), spec("test.batch_b", json!({}))];
    let labels = std::cell::RefCell::new(Vec::new());
    let records = execute_plan(&plan, &fx.store, "item", &|label| {
        labels.borrow_mut().push(label.to_string())
    });
    assert_eq!(*labels.borrow(), ["test.batch_a", "test.batch_b"]);
    let batch = records[0].batch().expect("batch").to_string();
    assert!(
        records
            .iter()
            .all(|r| r.batch() == Some(batch.as_str()) && r.item() == "item")
    );
    let results = vigil_actions::undo_batch(&batch, &fx.store);
    assert!(results.iter().all(|(_, error)| error.is_none()));
    assert_eq!(*order.lock().expect("log"), ["b", "a"]);
}

#[test]
fn register_keeps_an_earlier_undo_handler() {
    let fx = Fixture::new();
    let run = |message: &'static str| -> vigil_actions::RunFn {
        Arc::new(move |_: &Value, _: &Store, _: &str| Ok(Outcome::new(message, Some(json!({})))))
    };
    vigil_actions::register(
        "test.keep",
        run("first"),
        Some(Arc::new(|_: &Value, _: &Store| Ok("undone".into()))),
        false,
    );
    vigil_actions::register("test.keep", run("second"), None, false);
    let record = execute(&spec("test.keep", json!({})), &fx.store, None, "");
    assert_eq!(record.message(), "second");
    assert!(can_undo(&record));
}

#[test]
fn undo_data_is_dropped_for_operations_without_undo() {
    let fx = Fixture::new();
    vigil_actions::register(
        "test.no_undo",
        Arc::new(|_: &Value, _: &Store, _: &str| Ok(Outcome::new("done", Some(json!({"x": 1}))))),
        None,
        true,
    );
    let record = execute(&spec("test.no_undo", json!({})), &fx.store, None, "");
    assert!(record.ok());
    assert_eq!(record.get("undo"), Some(&Value::Null));
}

#[test]
fn a_panicking_handler_is_reported_not_propagated() {
    let fx = Fixture::new();
    vigil_actions::register(
        "test.panics",
        Arc::new(|_: &Value, _: &Store, _: &str| -> Result<Outcome, vigil_actions::ActionError> { panic!("boom") }),
        None,
        true,
    );
    let record = execute(&spec("test.panics", json!({})), &fx.store, None, "");
    assert!(!record.ok());
    assert_eq!(record.message(), "unexpected error: boom");
}

#[test]
fn store_rewrite_keeps_other_records() {
    let fx = Fixture::new();
    for index in 0..3 {
        let mut map = serde_json::Map::new();
        map.insert("id".into(), json!(index.to_string()));
        map.insert("ok".into(), json!(true));
        fx.store.append(&Record(map)).expect("append");
    }
    let mut changed = serde_json::Map::new();
    changed.insert("id".into(), json!("1"));
    changed.insert("ok".into(), json!(false));
    fx.store.update(&Record(changed)).expect("update");
    let oks: Vec<bool> = fx.store.records().iter().map(Record::ok).collect();
    assert_eq!(oks, [true, false, true]);
    let text = fs::read_to_string(fx.store.journal_path()).expect("journal");
    assert_eq!(text.lines().next(), Some(r#"{"id": "0", "ok": true}"#));
}

#[test]
fn invalid_journal_lines_are_skipped() {
    let fx = Fixture::new();
    fs::write(
        fx.store.journal_path(),
        "{\"id\": \"1\"}\nnot json\n[1, 2]\n\n{\"id\": \"2\"}\n",
    )
    .expect("journal");
    let ids: Vec<String> = fx.store.records().iter().map(|r| r.id().to_string()).collect();
    assert_eq!(ids, ["1", "2"]);
}

// --------------------------------------------------------------------------- data folder

#[test]
fn data_folder_files_stay_usable_across_restarts() {
    let sid = common::current_user_sid();
    assert!(sid.starts_with("S-1-"), "{sid}");
    let tmp = TempDir::new("vigil-data-");
    let root = tmp.path().join("Vigil");
    let start = || {
        let warning = testing::prepare_private_dir_as(&root, &sid, &[&sid, "S-1-5-18"]).expect("prepare");
        assert_eq!(warning, "");
    };
    start();
    let settings = root.join("settings.json");
    let nested = root.join("scans").join("scan-report.json");
    fs::create_dir_all(nested.parent().expect("parent")).expect("mkdir");
    fs::write(&settings, "{}").expect("write");
    fs::write(&nested, "{}").expect("write");
    start();
    start();
    fs::write(&settings, r#"{"days": 7}"#).expect("rewrite after restarts");
    fs::write(&nested, "[]").expect("rewrite nested");
    assert_eq!(fs::read_to_string(&settings).expect("read"), r#"{"days": 7}"#);
    let probes = fs::read_dir(&root)
        .expect("list")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(".write-test"))
        .count();
    assert_eq!(probes, 0);
}

#[test]
fn junction_inside_the_data_folder_is_refused() {
    let tmp = TempDir::new("vigil-data-");
    let root = tmp.path().join("Vigil");
    fs::create_dir_all(&root).expect("root");
    let target = tmp.path().join("elsewhere");
    fs::create_dir_all(&target).expect("target");
    common::junction(&root.join("backups"), &target);
    let error = testing::prepare_private_dir_as(&root, "S-1-5-32-544", &["S-1-5-32-544"]).expect_err("refused");
    assert!(
        error
            .message()
            .contains("junction or symbolic link inside the data folder"),
        "{error}"
    );
    fs::remove_dir(root.join("backups")).expect("remove the junction only");
    assert!(target.is_dir());

    let linked = tmp.path().join("LinkedVigil");
    common::junction(&linked, &target);
    let error = testing::prepare_private_dir_as(&linked, "S-1-5-32-544", &["S-1-5-32-544"]).expect_err("refused");
    assert!(
        error.message().contains("is a junction or symbolic link. Remove it"),
        "{error}"
    );
    fs::remove_dir(&linked).expect("remove the junction only");
}
