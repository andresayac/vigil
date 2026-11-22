//! The actions of the Security posture page. Each one only raises security, re-reads the live
//! value first, and saves exactly what it changes so History can put it back: UAC back to the
//! Windows default, Network Level Authentication for Remote Desktop, AutoRun off for every drive,
//! the vulnerable driver blocklist and LSA protection on, the Remote Registry service off, and the
//! SMBv1 and Windows PowerShell 2.0 optional features off.
//!
//! The registry keys can be pointed at a scratch key by the tests (`testing::redirect_setting`
//! with the names below); DISM and sc.exe go through the tool runner, which the tests replace.

use serde_json::{Map, Value, json};

use crate::engine::{Builtin, Outcome, run_fn, undo_fn};
use crate::error::{ActionError, Result, fail};
use crate::ops::{service_reg, service_start, service_status, stop_service, undo_service_disable};
use crate::params::Params;
use crate::registry::{reg_read, reg_write, restore_value};
use crate::runner::{first_line, run, tool};
use crate::store::Store;
use vigil_i18n::tr;

const UAC_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const RDP_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
const RDP_POLICY_KEY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
const AUTORUN_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
const CI_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config";
const LSA_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
const VERSION_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const REMOTE_REGISTRY: &str = "RemoteRegistry";
/// Windows 11 2022 Update: LSA protection can be on without locking it in the firmware.
const BUILD_22H2: i64 = 22_621;

/// The key an operation works on: the real one, or the test's scratch key.
fn key(which: &str, real: &str) -> String {
    crate::testing::setting_key(which).unwrap_or_else(|| real.to_string())
}

fn dword(key: &str, value: &str) -> Result<Option<i64>> {
    Ok(reg_read(key, value)?.and_then(|s| s.get("data").and_then(Value::as_i64)))
}

/// Sets DWORD values, saving what each one was (or that it did not exist) for undo. If a write
/// fails, the values already written are put back before the error is returned.
fn set_dwords(key: &str, values: &[(&str, u32)]) -> Result<Value> {
    let mut saved = Map::new();
    for (name, _) in values {
        saved.insert((*name).to_string(), reg_read(key, name)?.unwrap_or(Value::Null));
    }
    for (index, (name, data)) in values.iter().enumerate() {
        if let Err(error) = reg_write(key, name, &json!({ "type": "REG_DWORD", "data": data })) {
            for (done, _) in &values[..index] {
                let _ = restore_value(key, done, saved.get(*done));
            }
            return Err(error);
        }
    }
    Ok(json!({ "key": key, "values": saved }))
}

fn undo_values(u: Params<'_>, _store: &Store) -> Result<String> {
    let key = u.req_str("key")?;
    if let Some(values) = u.object("values") {
        for (name, snapshot) in values {
            restore_value(&key, name, Some(snapshot))?;
        }
    }
    Ok(tr!("restored the previous settings"))
}

// --------------------------------------------------------------------------- registry settings

fn op_uac_default(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let key = key("posture.uac", UAC_KEY);
    let lua = dword(&key, "EnableLUA")?.unwrap_or(1);
    let consent = dword(&key, "ConsentPromptBehaviorAdmin")?.unwrap_or(5);
    let secure = dword(&key, "PromptOnSecureDesktop")?.unwrap_or(1);
    let mut changes: Vec<(&str, u32)> = Vec::new();
    if lua == 0 {
        changes.push(("EnableLUA", 1));
    }
    if consent == 0 {
        changes.push(("ConsentPromptBehaviorAdmin", 5));
    }
    // 1 and 2 always prompt on the secure desktop; the others follow PromptOnSecureDesktop.
    if secure == 0 && !matches!(consent, 1 | 2) {
        changes.push(("PromptOnSecureDesktop", 1));
    }
    if changes.is_empty() {
        return Ok(Outcome::done(tr!(
            "User Account Control was already at the Windows default or stricter"
        )));
    }
    let undo = set_dwords(&key, &changes)?;
    Ok(Outcome::new(
        if lua == 0 {
            tr!("User Account Control is back to the Windows default; restart the computer to finish")
        } else {
            tr!("User Account Control is back to the Windows default")
        },
        Some(undo),
    ))
}

fn op_rdp_nla(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let policy = key("posture.rdp_policy", RDP_POLICY_KEY);
    if dword(&policy, "UserAuthentication")? == Some(0) {
        return fail(tr!(
            "a group policy turns Network Level Authentication off; it has to be changed there"
        ));
    }
    let key = key("posture.rdp", RDP_KEY);
    if dword(&key, "UserAuthentication")? == Some(1) {
        return Ok(Outcome::done(tr!(
            "Remote Desktop already required Network Level Authentication"
        )));
    }
    let undo = set_dwords(&key, &[("UserAuthentication", 1)])?;
    Ok(Outcome::new(
        tr!("Remote Desktop now requires Network Level Authentication"),
        Some(undo),
    ))
}

fn op_autorun_off(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let key = key("posture.autorun", AUTORUN_KEY);
    if dword(&key, "NoDriveTypeAutoRun")?.is_some_and(|v| v & 0xFF == 0xFF) {
        return Ok(Outcome::done(tr!("AutoRun was already off for every drive")));
    }
    let undo = set_dwords(&key, &[("NoDriveTypeAutoRun", 0xFF)])?;
    Ok(Outcome::new(tr!("AutoRun is off for every drive"), Some(undo)))
}

fn op_driver_blocklist_on(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let key = key("posture.ci", CI_KEY);
    if dword(&key, "VulnerableDriverBlocklistEnable")? == Some(1) {
        return Ok(Outcome::done(tr!("the vulnerable driver blocklist was already on")));
    }
    let undo = set_dwords(&key, &[("VulnerableDriverBlocklistEnable", 1)])?;
    Ok(Outcome::new(
        tr!("the vulnerable driver blocklist is on; it takes effect after a restart"),
        Some(undo),
    ))
}

fn op_lsa_on(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let version = key("posture.version", VERSION_KEY);
    let build = reg_read(&version, "CurrentBuildNumber")?
        .and_then(|s| {
            s.get("data")
                .and_then(Value::as_str)
                .and_then(|t| t.trim().parse::<i64>().ok())
        })
        .unwrap_or(0);
    // Earlier versions lock LSA protection in the firmware, where History could not undo it.
    if build < BUILD_22H2 {
        return fail(tr!(
            "on this version of Windows, LSA protection is turned on by your organization's policy, not from Vigil"
        ));
    }
    let key = key("posture.lsa", LSA_KEY);
    if matches!(dword(&key, "RunAsPPL")?, Some(1 | 2)) {
        return Ok(Outcome::done(tr!("LSA protection was already on")));
    }
    // 2: on, without the UEFI lock (so it can be turned off again).
    let undo = set_dwords(&key, &[("RunAsPPL", 2)])?;
    Ok(Outcome::new(
        tr!("LSA protection is on; it takes effect after a restart"),
        Some(undo),
    ))
}

// --------------------------------------------------------------------------- Remote Registry

fn op_remote_registry_off(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let values = service_reg(REMOTE_REGISTRY)?;
    let (start, delayed) = service_start(&values)?;
    let running = service_status(REMOTE_REGISTRY).as_deref() == Some("running");
    if start == 4 && !running {
        return Ok(Outcome::done(tr!("Remote Registry was already disabled")));
    }
    let was_running = stop_service(REMOTE_REGISTRY)?;
    if start != 4 {
        crate::ops::sc(
            &["config", REMOTE_REGISTRY, "start=", "disabled"],
            &tr!("disabling Remote Registry"),
        )?;
    }
    Ok(Outcome::new(
        tr!("Remote Registry is stopped and disabled"),
        Some(json!({ "name": REMOTE_REGISTRY, "start": start, "delayed": delayed, "was_running": was_running })),
    ))
}

// --------------------------------------------------------------------------- optional features

/// The features of SMBv1 and of Windows PowerShell 2.0, children before parents.
const SMB1_FEATURES: [&str; 4] = [
    "SMB1Protocol-Deprecation",
    "SMB1Protocol-Client",
    "SMB1Protocol-Server",
    "SMB1Protocol",
];
const PS2_FEATURES: [&str; 2] = ["MicrosoftWindowsPowerShellV2", "MicrosoftWindowsPowerShellV2Root"];

fn dism() -> String {
    tool("Dism.exe")
}

/// The state of every optional feature, from `dism /Get-Features /Format:Table` (in English).
pub fn parse_features(table: &str) -> Vec<(String, String)> {
    table
        .lines()
        .filter_map(|line| {
            let (name, state) = line.split_once('|')?;
            let (name, state) = (name.trim(), state.trim());
            // A feature name starts with a letter or digit (the table's rules are dashes).
            let valid = name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
            (valid && name != "Feature Name").then(|| (name.to_string(), state.to_string()))
        })
        .collect()
}

fn is_enabled(state: &str) -> bool {
    state.eq_ignore_ascii_case("Enabled") || state.eq_ignore_ascii_case("Enable Pending")
}

fn features() -> Result<Vec<(String, String)>> {
    let result = run(
        vec![
            dism(),
            "/English".into(),
            "/Online".into(),
            "/Get-Features".into(),
            "/Format:Table".into(),
        ],
        300,
    )?;
    if result.code != 0 {
        return fail(tr!(
            "DISM could not list the Windows features: {0}",
            first_line(&result.text())
        ));
    }
    Ok(parse_features(&result.out))
}

/// Runs `dism /Enable-Feature` or `/Disable-Feature` for these features. 3010 means a restart
/// finishes the change.
fn dism_change(verb: &str, names: &[String]) -> Result<bool> {
    let mut args = vec![dism(), "/English".into(), "/Online".into(), format!("/{verb}")];
    args.extend(names.iter().map(|n| format!("/FeatureName:{n}")));
    args.push("/NoRestart".into());
    let result = run(args, 1800)?;
    match result.code {
        0 => Ok(false),
        3010 => Ok(true),
        code => fail(tr!(
            "DISM could not change the Windows features (code {0}): {1}",
            code,
            first_line(&result.text())
        )),
    }
}

fn features_off(family: &[&str]) -> Result<(Vec<String>, bool)> {
    let states = features()?;
    let enabled: Vec<String> = family
        .iter()
        .filter(|name| {
            states
                .iter()
                .any(|(n, s)| n.eq_ignore_ascii_case(name) && is_enabled(s))
        })
        .map(|n| (*n).to_string())
        .collect();
    if enabled.is_empty() {
        return Ok((enabled, false));
    }
    let restart = dism_change("Disable-Feature", &enabled)?;
    Ok((enabled, restart))
}

fn op_smb1_off(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let (turned_off, _) = features_off(&SMB1_FEATURES)?;
    if turned_off.is_empty() {
        return Ok(Outcome::done(tr!("SMBv1 was already off")));
    }
    Ok(Outcome::new(
        tr!("SMBv1 is off; restart the computer to finish"),
        Some(json!({ "features": turned_off })),
    ))
}

fn op_ps2_off(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let (turned_off, _) = features_off(&PS2_FEATURES)?;
    if turned_off.is_empty() {
        return Ok(Outcome::done(tr!("Windows PowerShell 2.0 was already off")));
    }
    Ok(Outcome::new(
        tr!("Windows PowerShell 2.0 is off; Windows PowerShell 5.1 stays. A restart may be needed to finish"),
        Some(json!({ "features": turned_off })),
    ))
}

fn undo_features(u: Params<'_>, _store: &Store) -> Result<String> {
    let known: Vec<&str> = SMB1_FEATURES.iter().chain(PS2_FEATURES.iter()).copied().collect();
    // Parents before children when turning them back on.
    let mut names: Vec<String> = u
        .list("features")
        .into_iter()
        .filter_map(|v| v.as_str())
        .filter(|n| known.contains(n))
        .map(str::to_string)
        .collect();
    names.reverse();
    if names.is_empty() {
        return Err(ActionError::new(tr!("nothing was saved to undo")));
    }
    let restart = dism_change("Enable-Feature", &names)?;
    Ok(if restart {
        tr!("turned the Windows features back on; restart the computer to finish")
    } else {
        tr!("turned the Windows features back on")
    })
}

// --------------------------------------------------------------------------- table

pub(crate) fn builtin() -> Vec<Builtin> {
    vec![
        (
            "posture.uac_default",
            run_fn(op_uac_default),
            Some(undo_fn(undo_values)),
            false,
        ),
        ("posture.rdp_nla", run_fn(op_rdp_nla), Some(undo_fn(undo_values)), false),
        (
            "posture.autorun_off",
            run_fn(op_autorun_off),
            Some(undo_fn(undo_values)),
            false,
        ),
        (
            "posture.driver_blocklist_on",
            run_fn(op_driver_blocklist_on),
            Some(undo_fn(undo_values)),
            false,
        ),
        ("posture.lsa_on", run_fn(op_lsa_on), Some(undo_fn(undo_values)), false),
        (
            "posture.remote_registry_off",
            run_fn(op_remote_registry_off),
            Some(undo_fn(undo_service_disable)),
            false,
        ),
        (
            "posture.smb1_off",
            run_fn(op_smb1_off),
            Some(undo_fn(undo_features)),
            false,
        ),
        (
            "posture.ps2_off",
            run_fn(op_ps2_off),
            Some(undo_fn(undo_features)),
            false,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dism_feature_table() {
        let table = "\nDeployment Image Servicing and Management tool\nVersion: 10.0.26100.1\n\n\
                     ------------------------------------------- | --------\n\
                     Feature Name                                | State\n\
                     ------------------------------------------- | --------\n\
                     SMB1Protocol                                | Disabled\n\
                     SMB1Protocol-Client                         | Enabled\n\
                     MicrosoftWindowsPowerShellV2Root            | Disabled with Payload Removed\n\
                     \nThe operation completed successfully.\n";
        let rows = parse_features(table);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1], ("SMB1Protocol-Client".to_string(), "Enabled".to_string()));
        assert!(is_enabled("Enable Pending") && !is_enabled("Disabled with Payload Removed"));
    }
}
