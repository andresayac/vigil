//! Removing leftover entries of installed programs. Every entry lives under the scratch key
//! HKCU\Software\VigilTests (the real Uninstall keys are never read for changes nor touched).

mod common;

use std::path::Path;

use common::{Fixture, ScratchKey};
use serde_json::{Value, json};
use vigil_actions::{ActionSpec, execute, reg_read, reg_write, testing};

fn spec(key: &str) -> ActionSpec {
    ActionSpec::new(
        "program.remove_entry",
        "Remove leftover entry",
        key,
        "",
        json!({ "key": key }),
    )
}

fn text(key: &str, value: &str, data: &str) {
    reg_write(key, value, &json!({"type": "REG_SZ", "data": data})).expect("write the scratch value");
}

fn display_name(key: &str) -> Option<String> {
    reg_read(key, "DisplayName")
        .expect("read")
        .and_then(|v| v["data"].as_str().map(str::to_string))
}

/// An entry whose uninstaller and install folder (under `gone`) do not exist.
fn leftover(root: &str, name: &str, publisher: &str, gone: &Path) -> String {
    let key = format!("{root}\\{name}");
    text(&key, "DisplayName", name);
    text(&key, "Publisher", publisher);
    text(
        &key,
        "UninstallString",
        &format!("\"{}\" /SILENT", gone.join("unins000.exe").display()),
    );
    text(&key, "InstallLocation", &gone.display().to_string());
    key
}

#[test]
fn a_leftover_entry_is_removed_and_restored() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("programs-remove");
    let root = format!("{}\\Uninstall", scratch.key);
    testing::set_uninstall_root(Some(&root));
    let gone = fx.tmp.path().join("Fabrikam Viewer");
    let key = leftover(&root, "Fabrikam Viewer", "Fabrikam, Inc.", &gone);
    text(&key, "DisplayVersion", "2.0");

    let record = execute(&spec(&key), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert!(record.message().contains("Fabrikam Viewer"), "{}", record.message());
    assert_eq!(display_name(&key), None, "the entry is gone");
    let undo: Value = record.undo_data().cloned().unwrap_or(Value::Null);
    let backup = undo["backup"].as_str().unwrap_or_default();
    assert!(Path::new(backup).is_file(), "the key was exported first: {undo}");
    assert_eq!(undo["key"], key);

    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(display_name(&key).as_deref(), Some("Fabrikam Viewer"));
    let version = reg_read(&key, "DisplayVersion").expect("read").expect("restored value");
    assert_eq!(version["data"], "2.0", "every value comes back");
}

#[test]
fn entries_that_are_not_leftovers_are_refused() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("programs-refused");
    let root = format!("{}\\Uninstall", scratch.key);
    testing::set_uninstall_root(Some(&root));
    let gone = fx.tmp.path().join("gone");

    let refused = |key: &str, words: &str| {
        let record = execute(&spec(key), &fx.store, None, "");
        assert!(!record.ok(), "{key}");
        assert!(record.message().contains(words), "{key}: {}", record.message());
    };

    // Microsoft's own entries stay, even when nothing else is left of them.
    let microsoft = leftover(&root, "Contoso Runtime", "Microsoft Corporation", &gone);
    refused(&microsoft, "Microsoft");
    assert!(display_name(&microsoft).is_some());

    // Its uninstaller is still there: uninstall it instead.
    let folder = fx.tmp.path().join("Woodgrove");
    std::fs::create_dir_all(&folder).expect("folder");
    let uninstaller = folder.join("uninstall.exe");
    std::fs::write(&uninstaller, b"MZ").expect("file");
    let installed = format!("{root}\\Woodgrove");
    text(&installed, "DisplayName", "Woodgrove Tools");
    text(&installed, "UninstallString", &format!("\"{}\"", uninstaller.display()));
    refused(&installed, "still there");
    assert!(display_name(&installed).is_some());

    // Gone already, nested deeper, or outside the Uninstall keys.
    refused(&format!("{root}\\Nothing"), "no longer");
    let nested = leftover(&format!("{root}\\Northwind"), "Agent", "Northwind", &gone);
    refused(&nested, "only removes entries");
    refused(&format!("{}\\Other\\Contoso", scratch.key), "only removes entries");
    refused(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Contoso",
        "only removes entries",
    );
    refused(
        r"HKLM\SYSTEM\CurrentControlSet\Services\Contoso",
        "only removes entries",
    );
    assert!(display_name(&nested).is_some());
}

#[test]
fn outside_the_tests_the_real_uninstall_keys_are_the_only_ones() {
    let fx = Fixture::new();
    for key in [
        r"HKCU\Software\VigilTests\Uninstall\Contoso",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Contoso",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ] {
        let record = execute(&spec(key), &fx.store, None, "");
        assert!(!record.ok(), "{key}");
        assert!(
            record.message().contains("only removes entries"),
            "{}",
            record.message()
        );
    }
    // A scratch root outside HKCU\Software\VigilTests is ignored.
    testing::set_uninstall_root(Some(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall"));
    let record = execute(
        &spec(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Vigil Tests Nothing"),
        &fx.store,
        None,
        "",
    );
    assert!(!record.ok());
    assert!(record.message().contains("no longer"), "{}", record.message());
}
