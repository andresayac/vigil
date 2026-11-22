//! Removing browser policies. Every policy lives under the scratch key HKCU\Software\VigilTests,
//! which stands in for HKCU\SOFTWARE\Policies; the real policy keys are never touched.

mod common;

use common::{Fixture, ScratchKey};
use serde_json::{Value, json};
use vigil_actions::{ActionSpec, execute, reg_read, reg_write, testing};

fn spec(key: &str, value: &str) -> ActionSpec {
    ActionSpec::new(
        "browser.policy_remove",
        "Remove browser policy",
        key,
        "",
        json!({ "key": key, "value": value, "browser": "Chrome", "name": value }),
    )
}

fn set(key: &str, value: &str, snapshot: Value) {
    reg_write(key, value, &snapshot).expect("write the scratch value");
}

fn exists(key: &str, value: &str) -> bool {
    reg_read(key, value).expect("read").is_some()
}

#[test]
fn a_forced_extension_is_removed_and_put_back() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("browser-policies");
    let root = format!(r"{}\Policies", scratch.key);
    testing::set_policy_root(Some(&root));
    let list = format!(r"{root}\Google\Chrome\ExtensionInstallForcelist");
    let forced = "ppppoooonnnnmmmmllllkkkkjjjjiiii;https://updates.fabrikam.example/crx";
    set(&list, "1", json!({"type": "REG_SZ", "data": forced}));
    set(
        &list,
        "2",
        json!({"type": "REG_SZ", "data": "aaaabbbbccccddddeeeeffffgggghhhh"}),
    );

    let record = execute(&spec(&list, "1"), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert!(record.message().contains("restarts"), "{}", record.message());
    assert!(!exists(&list, "1"), "the value is gone");
    assert!(exists(&list, "2"), "the other entries stay");
    let undo = record.undo_data().cloned().unwrap_or(Value::Null);
    assert_eq!(undo["snapshot"]["data"], forced);

    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    let back = reg_read(&list, "1").expect("read").expect("restored");
    assert_eq!(back["data"], forced);
}

#[test]
fn a_hijacked_home_page_and_safe_browsing_off_are_removed() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("browser-home");
    let root = format!(r"{}\Policies", scratch.key);
    testing::set_policy_root(Some(&root));
    let edge = format!(r"{root}\Microsoft\Edge");
    set(
        &edge,
        "HomepageLocation",
        json!({"type": "REG_SZ", "data": "https://start.fabrikam.example"}),
    );
    set(&edge, "SmartScreenEnabled", json!({"type": "REG_DWORD", "data": 0}));
    for value in ["HomepageLocation", "SmartScreenEnabled"] {
        let record = execute(&spec(&edge, value), &fx.store, None, "");
        assert!(record.ok(), "{value}: {}", record.message());
        assert!(!exists(&edge, value));
        vigil_actions::undo(record.id(), &fx.store).expect("undo");
        assert!(exists(&edge, value));
    }
    let smartscreen = reg_read(&edge, "SmartScreenEnabled").expect("read").expect("value");
    assert_eq!(
        smartscreen,
        json!({"type": "REG_DWORD", "data": 0}),
        "the DWORD comes back as it was"
    );
}

#[test]
fn policies_that_keep_protection_on_or_are_unknown_stay() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("browser-refused");
    let root = format!(r"{}\Policies", scratch.key);
    testing::set_policy_root(Some(&root));
    let chrome = format!(r"{root}\Google\Chrome");
    set(&chrome, "SafeBrowsingEnabled", json!({"type": "REG_DWORD", "data": 1}));
    set(
        &chrome,
        "PasswordManagerEnabled",
        json!({"type": "REG_DWORD", "data": 0}),
    );
    set(
        &chrome,
        "ExtensionSettings",
        json!({"type": "REG_SZ", "data": r#"{"*":{"installation_mode":"blocked"}}"#}),
    );
    set(
        &format!(r"{chrome}\ExtensionInstallAllowlist"),
        "1",
        json!({"type": "REG_SZ", "data": "aaaabbbbccccddddeeeeffffgggghhhh"}),
    );

    let refused = |key: &str, value: &str, words: &str| {
        let record = execute(&spec(key, value), &fx.store, None, "");
        assert!(!record.ok(), "{key} {value}");
        assert!(record.message().contains(words), "{key} {value}: {}", record.message());
    };
    refused(&chrome, "SafeBrowsingEnabled", "protection on");
    refused(&chrome, "ExtensionSettings", "protection on");
    refused(&chrome, "PasswordManagerEnabled", "only removes browser policies");
    refused(
        &format!(r"{chrome}\ExtensionInstallAllowlist"),
        "1",
        "only removes browser policies",
    );
    refused(&chrome, "HomepageLocation", "no longer set");
    refused(
        &format!(r"{}\Other\Google\Chrome", scratch.key),
        "HomepageLocation",
        "only removes browser policies",
    );
    // With the scratch root in place, the real policy keys are refused too.
    refused(
        r"HKCU\SOFTWARE\Policies\Google\Chrome",
        "HomepageLocation",
        "only removes browser policies",
    );
    assert!(exists(&chrome, "SafeBrowsingEnabled") && exists(&chrome, "PasswordManagerEnabled"));
}

#[test]
fn machine_policies_need_administrator_rights() {
    let fx = Fixture::new();
    testing::set_admin(Some(false));
    // Refused before anything is read or written.
    let record = execute(
        &spec(r"HKLM\SOFTWARE\Policies\Google\Chrome", "HomepageLocation"),
        &fx.store,
        None,
        "",
    );
    assert!(!record.ok());
    assert!(record.message().contains("administrator"), "{}", record.message());
    // Outside the tests' scratch root, keys that are not browser policies are refused.
    testing::set_admin(Some(true));
    for (key, value) in [
        (
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
            "DisableAntiSpyware",
        ),
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HomepageLocation",
        ),
        (r"HKCU\Software\VigilTests\Google\Chrome", "HomepageLocation"),
    ] {
        let record = execute(&spec(key, value), &fx.store, None, "");
        assert!(!record.ok(), "{key}");
        assert!(
            record.message().contains("only removes browser policies"),
            "{}",
            record.message()
        );
    }
}
