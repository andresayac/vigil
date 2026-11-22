//! The Security posture actions, on scratch keys under HKCU\Software\VigilTests and with a fake
//! tool runner and service: no real setting, service or Windows feature is ever changed.

mod common;

use std::cell::Cell;
use std::rc::Rc;

use common::{FakeRunner, Fixture, ScratchKey};
use serde_json::{Map, Value, json};
use vigil_actions::testing::{redirect_setting, set_no_sleep, set_service_reg, set_service_status};
use vigil_actions::{ActionSpec, ToolResult, execute, reg_read, reg_write, undo};

fn spec(op: &str) -> ActionSpec {
    ActionSpec::new(op, op, "Security posture", "", json!({}))
}

fn dword(key: &str, value: &str) -> Option<i64> {
    reg_read(key, value)
        .expect("read")
        .and_then(|s| s.get("data").and_then(Value::as_i64))
}

fn set(key: &str, value: &str, data: u32) {
    reg_write(key, value, &json!({ "type": "REG_DWORD", "data": data })).expect("write");
}

#[test]
fn uac_goes_back_to_the_default_and_undo_restores_the_exact_values() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("posture-uac");
    let key = format!(r"{}\System", scratch.key);
    redirect_setting("posture.uac", &key);
    // "Never notify", with PromptOnSecureDesktop missing.
    set(&key, "EnableLUA", 1);
    set(&key, "ConsentPromptBehaviorAdmin", 0);

    let record = execute(&spec("posture.uac_default"), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert_eq!(dword(&key, "EnableLUA"), Some(1));
    assert_eq!(dword(&key, "ConsentPromptBehaviorAdmin"), Some(5));
    // Missing means on (1); only what was below the default changed.
    assert_eq!(dword(&key, "PromptOnSecureDesktop"), None);

    undo(record.id(), &fx.store).expect("undo");
    assert_eq!(dword(&key, "ConsentPromptBehaviorAdmin"), Some(0));
    assert_eq!(dword(&key, "PromptOnSecureDesktop"), None);

    // At the default or stricter: nothing to do, nothing to undo.
    set(&key, "ConsentPromptBehaviorAdmin", 2);
    set(&key, "PromptOnSecureDesktop", 0);
    let record = execute(&spec("posture.uac_default"), &fx.store, None, "");
    assert!(record.ok() && record.undo_data().is_none(), "{}", record.message());
    assert_eq!(dword(&key, "PromptOnSecureDesktop"), Some(0));

    // UAC off altogether: turned back on (a restart finishes it).
    set(&key, "EnableLUA", 0);
    set(&key, "ConsentPromptBehaviorAdmin", 5);
    let record = execute(&spec("posture.uac_default"), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert_eq!(dword(&key, "EnableLUA"), Some(1));
    undo(record.id(), &fx.store).expect("undo");
    assert_eq!(dword(&key, "EnableLUA"), Some(0));
}

#[test]
fn registry_settings_are_raised_and_undone() {
    let fx = Fixture::new();
    let scratch = ScratchKey::new("posture-registry");
    let k = |name: &str| format!(r"{}\{name}", scratch.key);
    for (which, name) in [
        ("posture.rdp", "Rdp"),
        ("posture.rdp_policy", "RdpPolicy"),
        ("posture.autorun", "Explorer"),
        ("posture.ci", "Ci"),
        ("posture.lsa", "Lsa"),
        ("posture.version", "Version"),
    ] {
        redirect_setting(which, &k(name));
    }
    reg_write(
        &k("Version"),
        "CurrentBuildNumber",
        &json!({ "type": "REG_SZ", "data": "26100" }),
    )
    .expect("build");
    set(&k("Rdp"), "UserAuthentication", 0);
    set(&k("Explorer"), "NoDriveTypeAutoRun", 0x91);

    for (op, key, value, wanted) in [
        ("posture.rdp_nla", k("Rdp"), "UserAuthentication", 1),
        ("posture.autorun_off", k("Explorer"), "NoDriveTypeAutoRun", 0xFF),
        (
            "posture.driver_blocklist_on",
            k("Ci"),
            "VulnerableDriverBlocklistEnable",
            1,
        ),
        ("posture.lsa_on", k("Lsa"), "RunAsPPL", 2),
    ] {
        let before = dword(&key, value);
        let record = execute(&spec(op), &fx.store, None, "");
        assert!(record.ok(), "{op}: {}", record.message());
        assert_eq!(dword(&key, value), Some(wanted), "{op}");
        undo(record.id(), &fx.store).expect("undo");
        assert_eq!(dword(&key, value), before, "{op} undone");
        // Already as recommended: nothing to change.
        set(&key, value, u32::try_from(wanted).expect("u32"));
        let again = execute(&spec(op), &fx.store, None, "");
        assert!(again.ok() && again.undo_data().is_none(), "{op}: {}", again.message());
    }

    // A policy that turns NLA off wins over the local value: refused.
    set(&k("Rdp"), "UserAuthentication", 0);
    set(&k("RdpPolicy"), "UserAuthentication", 0);
    let refused = execute(&spec("posture.rdp_nla"), &fx.store, None, "");
    assert!(!refused.ok());
    assert_eq!(dword(&k("Rdp"), "UserAuthentication"), Some(0));

    // Before the Windows 11 2022 Update LSA protection would lock itself in the firmware.
    reg_write(
        &k("Version"),
        "CurrentBuildNumber",
        &json!({ "type": "REG_SZ", "data": "19045" }),
    )
    .expect("build");
    reg_write(&k("Lsa"), "RunAsPPL", &json!({ "type": "REG_DWORD", "data": 0 })).expect("lsa");
    let refused = execute(&spec("posture.lsa_on"), &fx.store, None, "");
    assert!(!refused.ok());
    assert_eq!(dword(&k("Lsa"), "RunAsPPL"), Some(0));
}

#[test]
fn remote_registry_is_stopped_disabled_and_restored() {
    let fx = Fixture::new();
    set_no_sleep(true);
    let mut values = Map::new();
    values.insert("Start".into(), json!(3));
    set_service_reg(Some(Rc::new(move |name: &str| {
        assert_eq!(name, "RemoteRegistry");
        Ok(values.clone())
    })));
    // Running for the first two questions, stopped once sc.exe was asked to stop it.
    let asked = Rc::new(Cell::new(0));
    let seen = Rc::clone(&asked);
    set_service_status(Some(Rc::new(move |_| {
        seen.set(seen.get() + 1);
        Some(if seen.get() <= 2 { "running" } else { "stopped" }.to_string())
    })));
    let runner = FakeRunner::install(&[]);

    let record = execute(&spec("posture.remote_registry_off"), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert_eq!(
        runner.lines(),
        [
            "sc.exe stop RemoteRegistry",
            "sc.exe config RemoteRegistry start= disabled"
        ]
    );
    undo(record.id(), &fx.store).expect("undo");
    assert_eq!(
        runner.lines()[2..],
        [
            "sc.exe config RemoteRegistry start= demand",
            "sc.exe start RemoteRegistry"
        ]
    );
}

const FEATURES: &str = "Feature Name                                | State\n\
                        ------------------------------------------- | --------\n\
                        SMB1Protocol                                | Enabled\n\
                        SMB1Protocol-Client                         | Enabled\n\
                        SMB1Protocol-Server                         | Disabled\n\
                        MicrosoftWindowsPowerShellV2Root            | Enabled\n\
                        MicrosoftWindowsPowerShellV2                | Enabled\n";

#[test]
fn optional_features_are_turned_off_with_dism_and_back_on() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[
        (r"dism\.exe .*/Get-Features", ToolResult::new(0, FEATURES, "")),
        (r"dism\.exe .*/Disable-Feature", ToolResult::new(3010, "", "")),
        (r"dism\.exe .*/Enable-Feature", ToolResult::new(0, "", "")),
    ]);

    let record = execute(&spec("posture.smb1_off"), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    let lines = runner.lines();
    assert_eq!(lines[0], "dism.exe /English /Online /Get-Features /Format:Table");
    // Only what was on, children first.
    assert_eq!(
        lines[1],
        "dism.exe /English /Online /Disable-Feature /FeatureName:SMB1Protocol-Client /FeatureName:SMB1Protocol /NoRestart"
    );
    undo(record.id(), &fx.store).expect("undo");
    assert_eq!(
        runner.lines()[2],
        "dism.exe /English /Online /Enable-Feature /FeatureName:SMB1Protocol /FeatureName:SMB1Protocol-Client /NoRestart"
    );

    let record = execute(&spec("posture.ps2_off"), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert_eq!(
        runner.lines()[4],
        "dism.exe /English /Online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2 /FeatureName:MicrosoftWindowsPowerShellV2Root /NoRestart"
    );
}

#[test]
fn features_already_off_are_left_alone_and_dism_errors_are_reported() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[(
        r"dism\.exe .*/Get-Features",
        ToolResult::new(
            0,
            "SMB1Protocol | Disabled\nMicrosoftWindowsPowerShellV2Root | Disabled with Payload Removed\n",
            "",
        ),
    )]);
    let record = execute(&spec("posture.smb1_off"), &fx.store, None, "");
    assert!(record.ok() && record.undo_data().is_none(), "{}", record.message());
    assert_eq!(runner.lines().len(), 1);

    FakeRunner::install(&[(
        r"dism\.exe",
        ToolResult::new(740, "", "Elevated permissions are required"),
    )]);
    let record = execute(&spec("posture.ps2_off"), &fx.store, None, "");
    assert!(!record.ok());
    assert!(
        record.message().contains("Elevated permissions"),
        "{}",
        record.message()
    );
}
