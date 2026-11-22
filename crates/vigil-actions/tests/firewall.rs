//! Firewall rule actions, with a fake runner: no rule on this computer is changed.

mod common;

use common::{FakeRunner, Fixture};
use serde_json::{Value, json};
use vigil_actions::{ActionSpec, ToolResult, execute};

const SET_STATE: &str = r"\$was = ";
const RESTORE_STATE: &str = r"if \(\$r\.Count -ne 1\)";
const DELETE: &str = "Remove-NetFirewallRule";
const RECREATE: &str = "New-NetFirewallRule";

fn spec(op: &str, params: Value) -> ActionSpec {
    ActionSpec::new(op, op, "target", "", params)
}

fn rule(name: &str) -> Value {
    json!({
        "name": name,
        "direction": "in",
        "program": r"c:\users\jdoe\appdata\local\contoso\sync.exe",
        "service": "",
        "protocol": "6",
        "localPorts": "8080",
        "remotePorts": "",
        "label": "Contoso Sync",
    })
}

fn ok(out: &str) -> ToolResult {
    ToolResult::new(0, out, "")
}

fn scripts(runner: &FakeRunner) -> Vec<String> {
    runner.calls.borrow().iter().map(|c| c.args.join(" ")).collect()
}

#[test]
fn turning_a_rule_off_records_its_state_and_undo_restores_it() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[
        (SET_STATE, ok(r#"{"status":"ok","id":"{3F2A-77}","was":true}"#)),
        (RESTORE_STATE, ok(r#"{"status":"ok"}"#)),
    ]);
    let name = "Contoso Sync'; Remove-NetFirewallRule -All; '";
    let record = execute(&spec("firewall.rule_disable", rule(name)), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert!(record.message().contains("Contoso Sync"), "{}", record.message());
    assert_eq!(
        record.undo_data(),
        Some(&json!({"id": "{3F2A-77}", "enabled": true, "label": "Contoso Sync"}))
    );
    // Values travel as environment variables, never inside the script.
    assert_eq!(runner.ps_values("PC_NAME"), [name]);
    assert_eq!(runner.ps_values("PC_ENABLE"), ["0"]);
    assert_eq!(runner.ps_values("PC_DIRECTION"), ["in"]);
    assert_eq!(runner.ps_values("PC_LOCALPORTS"), ["8080"]);
    assert_eq!(
        runner.ps_values("PC_PROGRAM"),
        [r"c:\users\jdoe\appdata\local\contoso\sync.exe"]
    );
    assert!(!scripts(&runner)[0].contains("Contoso"));
    assert!(scripts(&runner)[0].contains("Disable-NetFirewallRule"));

    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(runner.ps_values("PC_ID"), ["{3F2A-77}"]);
    assert_eq!(runner.ps_values("PC_ENABLE"), ["0", "1"]);
}

#[test]
fn turning_a_rule_on_is_undone_by_turning_it_off_again() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[
        (SET_STATE, ok(r#"{"status":"ok","id":"rule-1","was":false}"#)),
        (RESTORE_STATE, ok(r#"{"status":"ok"}"#)),
    ]);
    let record = execute(&spec("firewall.rule_enable", rule("Contoso Sync")), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert_eq!(runner.ps_values("PC_ENABLE"), ["1"]);
    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(runner.ps_values("PC_ENABLE"), ["1", "0"]);
}

#[test]
fn a_rule_that_is_gone_or_ambiguous_is_not_touched() {
    let fx = Fixture::new();
    let _runner = FakeRunner::install(&[(SET_STATE, ok(r#"{"status":"missing"}"#))]);
    let record = execute(
        &spec("firewall.rule_disable", rule("Contoso Sync")),
        &fx.store,
        None,
        "",
    );
    assert!(!record.ok());
    assert!(record.message().contains("no longer there"), "{}", record.message());

    let _runner = FakeRunner::install(&[(SET_STATE, ok(r#"{"status":"ambiguous"}"#))]);
    let record = execute(
        &spec("firewall.rule_disable", rule("Contoso Sync")),
        &fx.store,
        None,
        "",
    );
    assert!(!record.ok());
    assert!(
        record.message().contains("Several firewall rules"),
        "{}",
        record.message()
    );

    let _runner = FakeRunner::install(&[(SET_STATE, ok(r#"{"status":"policy"}"#))]);
    let record = execute(
        &spec("firewall.rule_disable", rule("Contoso Sync")),
        &fx.store,
        None,
        "",
    );
    assert!(!record.ok());
    assert!(record.message().contains("Group Policy"), "{}", record.message());

    let _runner = FakeRunner::install(&[(SET_STATE, ok("garbage"))]);
    let record = execute(
        &spec("firewall.rule_disable", rule("Contoso Sync")),
        &fx.store,
        None,
        "",
    );
    assert!(!record.ok());
}

#[test]
fn invalid_rule_fields_are_refused_before_powershell_runs() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[]);
    for (field, value) in [
        ("direction", "sideways"),
        ("protocol", "6; Remove-Item"),
        ("protocol", ""),
        ("name", ""),
    ] {
        let mut params = rule("Contoso Sync");
        params[field] = json!(value);
        let record = execute(&spec("firewall.rule_delete", params), &fx.store, None, "");
        assert!(!record.ok(), "{field}={value} must be refused");
    }
    assert!(runner.calls.borrow().is_empty());
}

#[test]
fn rules_of_windows_groups_are_never_deleted() {
    let fx = Fixture::new();
    let runner = FakeRunner::install(&[(DELETE, ok(r#"{"status":"builtin"}"#))]);
    let record = execute(
        &spec("firewall.rule_delete", rule("Remote Desktop")),
        &fx.store,
        None,
        "",
    );
    assert!(!record.ok());
    assert!(record.message().contains("not deleted"), "{}", record.message());
    // The script checks the group before it removes anything.
    let script = &scripts(&runner)[0];
    assert!(script.find("'builtin'") < script.find("Remove-NetFirewallRule"));
}

#[test]
fn a_deleted_rule_keeps_its_definition_and_undo_recreates_it() {
    let fx = Fixture::new();
    let saved = json!({
        "Name": "{9C1D-02}",
        "DisplayName": "Contoso Sync",
        "Direction": "Inbound",
        "Action": "Allow",
        "Enabled": "True",
        "Profile": "Private, Public",
        "Program": r"%LOCALAPPDATA%\Contoso\sync.exe",
        "Protocol": "TCP",
        "LocalPort": ["8080"],
        "RemoteAddress": ["203.0.113.0/255.255.255.0"],
    });
    let runner = FakeRunner::install(&[
        (DELETE, ok(&json!({"status": "ok", "rule": saved}).to_string())),
        (RECREATE, ok(r#"{"status":"ok"}"#)),
    ]);
    let record = execute(&spec("firewall.rule_delete", rule("Contoso Sync")), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    assert_eq!(
        record.undo_data(),
        Some(&json!({"rule": saved, "label": "Contoso Sync"}))
    );

    vigil_actions::undo(record.id(), &fx.store).expect("undo");
    assert_eq!(runner.ps_values("PC_ID"), ["{9C1D-02}"]);
    let sent: Value = serde_json::from_str(&runner.ps_values("PC_RULE")[0]).expect("json");
    assert_eq!(sent, saved);
    assert!(!scripts(&runner)[1].contains("Contoso"));
}

#[test]
fn undo_does_not_overwrite_a_rule_recreated_meanwhile() {
    let fx = Fixture::new();
    let saved = json!({"Name": "{9C1D-02}", "DisplayName": "Contoso Sync", "Direction": "Inbound"});
    let _runner = FakeRunner::install(&[
        (DELETE, ok(&json!({"status": "ok", "rule": saved}).to_string())),
        (RECREATE, ok(r#"{"status":"exists"}"#)),
    ]);
    let record = execute(&spec("firewall.rule_delete", rule("Contoso Sync")), &fx.store, None, "");
    assert!(record.ok(), "{}", record.message());
    let error = vigil_actions::undo(record.id(), &fx.store).expect_err("refused");
    assert!(error.message().contains("already exists"), "{}", error.message());
}
