//! Stored formats: a journal, a quarantined file and a task backup recorded by an earlier session
//! (tests/data/formats) must still be read, undone and restored byte for byte.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{FakeRunner, Fixture, ScratchKey};
use serde_json::{Value, json};
use vigil_actions::{can_undo, testing};

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(r"tests\data\formats")
}

fn expected() -> Value {
    serde_json::from_str(&fs::read_to_string(data_dir().join("expected.json")).expect("expected.json")).expect("json")
}

fn name(key: &str) -> String {
    expected()["names"][key].as_str().expect("name").to_string()
}

/// A path as it appears inside a JSON string.
fn json_text(path: &Path) -> String {
    let quoted = serde_json::to_string(&path.to_string_lossy()).expect("json");
    quoted[1..quoted.len() - 1].to_string()
}

/// Puts the recorded data folder in the fixture's store; returns (folder of the quarantined file, journal lines).
fn install_fixture(fx: &Fixture) -> (PathBuf, Vec<String>) {
    let files = fx.tmp.path().join("files");
    fs::create_dir_all(&files).expect("files");
    let root = fx.store.root().to_path_buf();
    let fill = |text: &str| {
        text.replace("{{ROOT}}", &json_text(&root))
            .replace("{{FILES}}", &json_text(&files))
    };
    let journal = fill(&fs::read_to_string(data_dir().join("journal.jsonl")).expect("journal"));
    fs::write(fx.store.journal_path(), &journal).expect("write journal");
    for entry in fs::read_dir(data_dir().join("quarantine")).expect("quarantine") {
        let path = entry.expect("entry").path();
        let target = fx.store.quarantine_dir().join(path.file_name().expect("name"));
        if path.extension().is_some_and(|e| e == "json") {
            fs::write(target, fill(&fs::read_to_string(&path).expect("meta"))).expect("meta");
        } else {
            fs::copy(&path, target).expect("blob");
        }
    }
    for entry in fs::read_dir(data_dir().join("backups")).expect("backups") {
        let path = entry.expect("entry").path();
        fs::copy(&path, fx.store.backup_dir().join(path.file_name().expect("name"))).expect("backup");
    }
    (files, journal.lines().map(str::to_string).collect())
}

#[test]
fn stored_journal_is_read_and_undo_flags_agree() {
    let fx = Fixture::new();
    install_fixture(&fx);
    let expected = expected();
    let records = fx.store.records();
    assert_eq!(records.len() as u64, expected["count"].as_u64().expect("count"));
    for record in &records {
        assert_eq!(
            Some(can_undo(record)),
            expected["can_undo"][record.id()].as_bool(),
            "{}",
            record.op()
        );
        assert_ne!(vigil_actions::op_label(record.op()), "", "{}", record.op());
    }
    assert_eq!(vigil_actions::op_label("file.quarantine"), "Quarantine file");
}

#[test]
fn stored_quarantine_is_restored_byte_identical() {
    let fx = Fixture::new();
    let (files, _) = install_fixture(&fx);
    let entries = fx.store.quarantined();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert!(entry.present);
    assert_eq!(entry.size, 10251);
    assert_eq!(entry.state.as_deref(), Some("removed"));
    assert_eq!(Path::new(&entry.original_path), files.join("evil.exe"));
    let undone = vigil_actions::undo(&name("quarantine"), &fx.store).expect("undo");
    assert_eq!(
        undone.undo_message(),
        Some(format!("restored evil.exe to {}", entry.original_path).as_str())
    );
    let original = fs::read(data_dir().join("original.bin")).expect("original");
    assert_eq!(fs::read(files.join("evil.exe")).expect("restored"), original);
    let modified = fs::metadata(files.join("evil.exe"))
        .and_then(|m| m.modified())
        .expect("mtime");
    let seconds = modified
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_secs_f64();
    assert!((seconds - entry.modified.unwrap_or(0.0)).abs() < 0.01, "{seconds}");
    assert!(fx.store.quarantined().is_empty());
}

#[test]
fn stored_registry_records_are_undone() {
    let fx = Fixture::new();
    install_fixture(&fx);
    let scratch = ScratchKey::new("v2fixture");
    let approved = format!("{}\\Approved", scratch.key);
    let run_key = format!("{}\\Run", scratch.key);
    // The state the recorded session left: the entry switched off, the other value deleted.
    vigil_actions::reg_write(
        &approved,
        "Updater",
        &json!({"type": "REG_BINARY", "data": {"hex": "030000000102030405060708"}}),
    )
    .expect("write");
    vigil_actions::reg_write(
        &run_key,
        "Updater",
        &json!({"type": "REG_SZ", "data": "C:\\Vendor\\updater.exe"}),
    )
    .expect("w");
    vigil_actions::undo(&name("startup"), &fx.store).expect("undo startup");
    assert_eq!(
        vigil_actions::reg_read(&approved, "Updater").expect("read"),
        Some(json!({"type": "REG_BINARY", "data": {"hex": "020000000000000000000000"}}))
    );
    vigil_actions::undo(&name("registry"), &fx.store).expect("undo registry");
    assert_eq!(
        vigil_actions::reg_read(&run_key, "Thing").expect("read"),
        Some(json!({"type": "REG_EXPAND_SZ", "data": "%APPDATA%\\x\\y.exe -silent"}))
    );
}

#[test]
fn stored_tool_records_are_undone_with_the_same_commands() {
    let fx = Fixture::new();
    install_fixture(&fx);
    let runner = FakeRunner::install(&[]);
    let mut service = serde_json::Map::new();
    service.insert("Start".into(), json!(4));
    testing::set_service_reg(Some(std::rc::Rc::new(move |_: &str| Ok(service.clone()))));

    vigil_actions::undo(&name("service"), &fx.store).expect("service");
    assert!(
        runner
            .lines()
            .contains(&"sc.exe config Evil Svc start= delayed-auto".to_string())
    );
    assert!(runner.lines().contains(&"sc.exe start Evil Svc".to_string()));

    let backup = fx.store.backup_dir().join(format!("{}.xml", name("task")));
    vigil_actions::undo(&name("task"), &fx.store).expect("task");
    let create = format!(
        r"schtasks.exe /Create /TN \Vendor\Updater Task /XML {}",
        backup.display()
    );
    assert!(runner.lines().contains(&create), "{:?}", runner.lines());
    assert_eq!(&fs::read(&backup).expect("backup")[..2], &[0xFF, 0xFE]);

    vigil_actions::undo(&name("firewall"), &fx.store).expect("firewall");
    assert_eq!(
        runner.ps_values("PC_NAME"),
        ["Vigil-e9f4283a57c3-out", "Vigil-e9f4283a57c3-in"]
    );

    vigil_actions::undo(&name("power"), &fx.store).expect("power");
    assert_eq!(
        runner.lines().last(),
        Some(&"powercfg.exe /setactive 381b4222-f694-41f0-9685-ff5bb260df2e".to_string())
    );
    let refused = vigil_actions::undo(&name("power_undone"), &fx.store).expect_err("already undone");
    assert_eq!(refused.message(), "that action cannot be undone");

    let results = vigil_actions::undo_batch(&name("batch"), &fx.store);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0.id(), name("batch_ok"));
    assert_eq!(results[0].1, None);
    assert_eq!(runner.ps_values("PC_PROFILES"), ["Private,Public"]);
    let still: Vec<String> = fx
        .store
        .records()
        .iter()
        .filter(|r| can_undo(r))
        .map(|r| r.id().to_string())
        .collect();
    assert_eq!(
        still,
        [name("quarantine"), name("startup"), name("registry")],
        "the others are undone now"
    );
}

#[test]
fn rewritten_lines_stay_byte_identical() {
    let fx = Fixture::new();
    let (_, original) = install_fixture(&fx);
    FakeRunner::install(&[]);
    let power = name("power");
    vigil_actions::undo(&power, &fx.store).expect("undo");
    let text = fs::read_to_string(fx.store.journal_path()).expect("journal");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), original.len());
    for (line, before) in lines.iter().zip(&original) {
        if before.contains(&power) {
            let kept = before.trim_end_matches("\"undone\": false}");
            assert!(
                line.starts_with(&format!("{kept}\"undone\": true, \"undone_at\": \"")),
                "{line}"
            );
            assert!(
                line.ends_with("\"undo_message\": \"restored the power plan \\\"Balanced\\\"\"}"),
                "{line}"
            );
        } else {
            assert_eq!(line, before);
        }
    }
}
