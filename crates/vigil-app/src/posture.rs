//! The Security posture page: the Windows settings that protect the computer as a whole, read live
//! (read-only), and the requests that raise one of them. Every request is checked against a fresh
//! read: an action is offered only for a setting that is below the recommendation and that Vigil
//! can safely change. Nothing offered here lowers security.

use vigil_i18n::tr;
use vigil_sys::posture::{Check, Posture};

use crate::planner::{SpecExt, spec};
use crate::requests::Plan;

pub async fn read_async() -> Result<Posture, String> {
    let elevated = vigil_sys::elevation::is_elevated();
    tauri::async_runtime::spawn_blocking(move || vigil_sys::posture::read(elevated))
        .await
        .map_err(|e| e.to_string())
}

/// The security posture (read-only); changes go through run_action ({ kind: "posture" }).
#[tauri::command]
pub async fn posture_state() -> Result<Posture, String> {
    read_async().await
}

/// The check that offers `op` in this read.
fn offering<'a>(state: &'a Posture, op: &str) -> Option<&'a Check> {
    state.checks.iter().find(|c| c.fixes.iter().any(|f| f == op))
}

/// A request of the Security posture page, checked against a fresh read.
pub fn plan(op: &str, state: &Posture) -> Result<Plan, String> {
    let Some(check) = offering(state, op) else {
        return Err(tr!(
            "This setting is already as recommended, or Vigil does not change it. Refresh the page."
        ));
    };
    let restart = tr!("Restart the computer to finish.");
    let built = match op {
        "uac-default" => {
            let built = spec(
                "posture.uac_default",
                tr!("Set User Account Control to the Windows default"),
                tr!("User Account Control"),
                tr!(
                    "Windows asks for your confirmation on the dimmed secure desktop before a program makes changes that need administrator rights. Only the values below the Windows default change, and History can put them back."
                ),
            );
            if check.detail == "disabled" { built.warning(&restart) } else { built }
        }
        "rdp-nla" => spec(
            "posture.rdp_nla",
            tr!("Require Network Level Authentication"),
            tr!("Remote Desktop"),
            tr!(
                "People connecting with Remote Desktop must sign in before Windows creates a session for them, which keeps password guessing and some attacks away from this computer's sign-in screen."
            ),
        )
        .warning(&tr!("Very old Remote Desktop clients that cannot do this will no longer connect.")),
        "rdp-off" => spec(
            "rdp.disable",
            tr!("Turn Remote Desktop off"),
            tr!("Remote Desktop"),
            tr!(
                "Nobody can connect to this computer with Remote Desktop any more. Other remote-control programs are not affected."
            ),
        )
        .warning(&tr!(
            "If you use this computer through Remote Desktop, you will not be able to connect to it again until it is turned back on."
        )),
        "smb1-off" => spec(
            "posture.smb1_off",
            tr!("Turn SMBv1 off"),
            tr!("SMBv1"),
            tr!(
                "Turns off the Windows feature for SMB version 1, the old file-sharing protocol that WannaCry and other worms spread through. File sharing between current computers uses SMB 2 and 3 and keeps working. Restart the computer to finish."
            ),
        )
        .warning(&tr!(
            "Very old devices, such as some network drives and printers, may no longer share files with this computer."
        )),
        "ps2-off" => spec(
            "posture.ps2_off",
            tr!("Turn Windows PowerShell 2.0 off"),
            tr!("Windows PowerShell 2.0"),
            tr!(
                "Turns off the Windows feature for Windows PowerShell 2.0, an old version attackers use to get around the logging and protections of newer PowerShell. Windows PowerShell 5.1 stays. A restart may be needed to finish."
            ),
        ),
        "autorun-off" => spec(
            "posture.autorun_off",
            tr!("Turn AutoRun off for every drive"),
            tr!("AutoRun"),
            tr!(
                "CDs, DVDs and other drives can no longer start a program by themselves when they are inserted. AutoPlay still asks what to do with them."
            ),
        ),
        "driver-blocklist-on" => spec(
            "posture.driver_blocklist_on",
            tr!("Turn on the vulnerable driver blocklist"),
            tr!("Microsoft Vulnerable Driver Blocklist"),
            tr!(
                "Windows refuses to load drivers that Microsoft knows have flaws attackers use to take over a computer. It takes effect after a restart."
            ),
        )
        .warning(&tr!("In rare cases a driver of an old program is on the list and stops loading.")),
        "lsa-on" => spec(
            "posture.lsa_on",
            tr!("Turn on LSA protection"),
            tr!("Local Security Authority protection"),
            tr!(
                "Windows protects the process that keeps your sign-in secrets, so other programs cannot read passwords and tokens from its memory. It takes effect after a restart."
            ),
        )
        .warning(&tr!(
            "Some old smart card, password or security add-ins that are not signed for it stop loading. If something stops working after the restart, undo this from History."
        )),
        "remote-registry-off" => spec(
            "posture.remote_registry_off",
            tr!("Turn Remote Registry off"),
            tr!("Remote Registry service"),
            tr!(
                "Stops the Remote Registry service and sets it to Disabled, the Windows default, so this computer's registry cannot be read or changed over the network."
            ),
        )
        .warning(&tr!("Some management tools that organizations use need it.")),
        _ => return Err(tr!("Unknown request: {0}", op)),
    };
    Ok(Plan::Run {
        spec: built.group("fix"),
        item: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_sys::posture::{Raw, evaluate};

    fn weak() -> Posture {
        evaluate(&Raw {
            edition: "Professional".into(),
            build: 26_100,
            enable_lua: Some(1),
            consent_admin: Some(0),
            rdp_deny: Some(0),
            rdp_nla: Some(0),
            smb1_feature: Some(1),
            ps2_feature: Some(1),
            driver_blocklist: Some(0),
            remote_registry_start: Some(2),
            ..Raw::default()
        })
    }

    fn run_spec(plan: Plan) -> vigil_actions::ActionSpec {
        match plan {
            Plan::Run { spec, item } => {
                assert!(item.is_none());
                spec
            }
            other => panic!("not a run plan: {other:?}"),
        }
    }

    #[test]
    fn offered_fixes_become_admin_actions_that_can_be_undone() {
        let state = weak();
        for (op, engine_op) in [
            ("uac-default", "posture.uac_default"),
            ("rdp-nla", "posture.rdp_nla"),
            ("rdp-off", "rdp.disable"),
            ("smb1-off", "posture.smb1_off"),
            ("ps2-off", "posture.ps2_off"),
            ("autorun-off", "posture.autorun_off"),
            ("driver-blocklist-on", "posture.driver_blocklist_on"),
            ("lsa-on", "posture.lsa_on"),
            ("remote-registry-off", "posture.remote_registry_off"),
        ] {
            let spec = run_spec(plan(op, &state).expect(op));
            assert_eq!(spec.op, engine_op);
            assert!(spec.admin && spec.reversible && !spec.destructive, "{op}");
            assert!(!spec.explain.is_empty() && spec.params == serde_json::json!({}), "{op}");
            assert!(vigil_actions::known_ops().contains(&spec.op), "{op} is not registered");
        }
    }

    #[test]
    fn the_page_request_is_understood() {
        let request: crate::requests::Request =
            serde_json::from_value(serde_json::json!({"kind": "posture", "op": "smb1-off"})).expect("request");
        assert!(matches!(request, crate::requests::Request::Posture { ref op } if op == "smb1-off"));
        assert!(serde_json::from_value::<crate::requests::Request>(serde_json::json!({"kind": "posture"})).is_err());
    }

    #[test]
    fn only_what_the_fresh_read_offers_is_planned() {
        let good = evaluate(&Raw {
            edition: "Professional".into(),
            build: 26_100,
            rdp_deny: Some(1),
            smb1_feature: Some(2),
            ps2_feature: Some(3),
            driver_blocklist: Some(1),
            run_as_ppl: Some(2),
            autorun_machine: Some(255),
            remote_registry_start: Some(4),
            ..Raw::default()
        });
        for op in [
            "uac-default",
            "rdp-nla",
            "rdp-off",
            "smb1-off",
            "ps2-off",
            "autorun-off",
            "driver-blocklist-on",
            "lsa-on",
            "remote-registry-off",
        ] {
            assert!(
                plan(op, &good).is_err(),
                "{op} offered on a computer that does not need it"
            );
        }
        // Never anything that lowers protection, whatever the page asks for.
        for op in ["uac-off", "rdp-on", "smb1-on", "defender-off", "", "exec"] {
            assert!(plan(op, &weak()).is_err(), "{op}");
        }
        // LSA protection before the Windows 11 2022 Update: explained, not offered.
        let old = evaluate(&Raw {
            build: 19_045,
            ..Raw::default()
        });
        assert!(plan("lsa-on", &old).is_err());
    }
}
