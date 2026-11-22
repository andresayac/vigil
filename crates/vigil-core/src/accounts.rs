//! The Accounts and sign-ins page: local accounts, the members of Administrators and Remote
//! Desktop Users, the sessions signed in now and the sign-in history from the event logs
//! (read-only); and the requests that disable an account, remove a member from one of the two
//! groups or sign out a session.
//!
//! A request names an account, a member or a session; Rust reads the accounts again, applies the
//! same guards as the action engine and writes every text of the confirmation from what it finds.

use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use vigil_actions::Record;
use vigil_actions::accounts::{check_disable, check_group_remove, check_logoff, member_label};
use vigil_i18n::tr;
use vigil_sys::accounts::{ADMINISTRATORS, REMOTE_DESKTOP_USERS, Snapshot};
use vigil_sys::signins::{DEFAULT_DAYS, MAX_DAYS, Signins, Warning};

use crate::planner::{SpecExt, spec};
use crate::requests::Plan;

const READ_TIMEOUT: Duration = Duration::from_secs(45);

/// A change Vigil made that is still in place (History can undo it): an account it disabled, or a
/// member it removed from a group.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VigilChange {
    pub record_id: String,
    pub time: String,
    /// The account (or member).
    pub sid: String,
    pub name: String,
    /// Group changes: the group.
    pub group_sid: String,
    pub group_name: String,
}

/// Everything the page shows.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountsView {
    #[serde(flatten)]
    pub snapshot: Snapshot,
    /// The sign-in history (`None` when the event logs could not be read at all).
    pub signins: Option<Signins>,
    pub signins_error: String,
    pub warnings: Vec<Warning>,
    pub disabled_by_vigil: Vec<VigilChange>,
    pub removed_by_vigil: Vec<VigilChange>,
}

/// The page's data (read-only): accounts, groups, sessions and the last `days` days of sign-ins
/// (`None`: the default; clamped to what the reader allows). `records` is the journal, for the
/// changes Vigil made. Slow: call it off the UI thread.
pub fn read(days: Option<u32>, records: &[Record]) -> AccountsView {
    load(days.unwrap_or(DEFAULT_DAYS).clamp(1, MAX_DAYS), records)
}

fn load(days: u32, records: &[Record]) -> AccountsView {
    let snapshot = vigil_sys::accounts::read();
    let (signins, signins_error) = match vigil_sys::signins::read(days, READ_TIMEOUT, vigil_scan::is_public_address) {
        Ok(signins) => (Some(signins), String::new()),
        Err(error) => (None, tr!("Could not read the event logs: {0}", error)),
    };
    let warnings = vigil_sys::signins::warnings(&snapshot, signins.as_ref().unwrap_or(&Signins::default()));
    let (disabled_by_vigil, removed_by_vigil) = vigil_changes(&snapshot, records);
    AccountsView {
        snapshot,
        signins,
        signins_error,
        warnings,
        disabled_by_vigil,
        removed_by_vigil,
    }
}

fn undo_text(record: &Record, key: &str) -> String {
    record
        .undo_data()
        .and_then(|u| u.get(key))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// The accounts Vigil disabled that are still disabled, and the members it removed that are still
/// out of their group; the newest record of each, when History can still undo it.
pub fn vigil_changes(snapshot: &Snapshot, records: &[Record]) -> (Vec<VigilChange>, Vec<VigilChange>) {
    let mut disabled: Vec<VigilChange> = Vec::new();
    let mut removed: Vec<VigilChange> = Vec::new();
    for record in records.iter().filter(|r| vigil_actions::can_undo(r)) {
        match record.op() {
            "account.disable" => {
                let (sid, name) = (undo_text(record, "sid"), undo_text(record, "name"));
                let guest = undo_text(record, "sid_suffix") == "-501";
                let Some(account) = snapshot.accounts.iter().find(|a| {
                    (!sid.is_empty() && a.sid.eq_ignore_ascii_case(&sid))
                        || (sid.is_empty() && !name.is_empty() && a.name.eq_ignore_ascii_case(&name))
                        || (guest && a.rid == 501)
                }) else {
                    continue;
                };
                if account.enabled {
                    continue;
                }
                disabled.retain(|c| !c.sid.eq_ignore_ascii_case(&account.sid));
                disabled.push(VigilChange {
                    record_id: record.id().to_string(),
                    time: record.time().to_string(),
                    sid: account.sid.clone(),
                    name: account.name.clone(),
                    ..VigilChange::default()
                });
            }
            "account.group_remove" => {
                let (group_sid, member_sid) = (undo_text(record, "group_sid"), undo_text(record, "member_sid"));
                let group = if group_sid.eq_ignore_ascii_case(ADMINISTRATORS) {
                    &snapshot.administrators
                } else if group_sid.eq_ignore_ascii_case(REMOTE_DESKTOP_USERS) {
                    &snapshot.remote_desktop_users
                } else {
                    continue;
                };
                if group.members.iter().any(|m| m.sid.eq_ignore_ascii_case(&member_sid)) {
                    continue;
                }
                removed.retain(|c| !(c.sid.eq_ignore_ascii_case(&member_sid) && c.group_sid == group.sid));
                removed.push(VigilChange {
                    record_id: record.id().to_string(),
                    time: record.time().to_string(),
                    sid: member_sid,
                    name: undo_text(record, "member_name"),
                    group_sid: group.sid.clone(),
                    group_name: group.name.clone(),
                });
            }
            _ => {}
        }
    }
    (disabled, removed)
}

// ------------------------------------------------------------------------------------ requests

/// A refusal from the action engine's guards, as a sentence for the page.
fn sentence(error: vigil_actions::ActionError) -> String {
    let text = error.message().to_string();
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => format!("{}{}.", first.to_uppercase(), chars.as_str().trim_end_matches('.')),
        None => text,
    }
}

/// The group a request names: "administrators" or "remote_desktop_users".
fn group_sid(group: &str) -> Result<&'static str, String> {
    match group {
        "administrators" => Ok(ADMINISTRATORS),
        "remote_desktop_users" => Ok(REMOTE_DESKTOP_USERS),
        _ => Err(tr!("Unknown group.")),
    }
}

/// A request about an account, a group member or a session, checked against a fresh read.
pub fn plan(op: &str, sid: &str, group: &str, session: u32) -> Result<Plan, String> {
    let snapshot = vigil_sys::accounts::read();
    plan_for(
        op,
        sid,
        group,
        session,
        &snapshot,
        vigil_sys::accounts::current_session_id(),
    )
}

pub(crate) fn plan_for(
    op: &str,
    sid: &str,
    group: &str,
    session: u32,
    snapshot: &Snapshot,
    current_session: u32,
) -> Result<Plan, String> {
    let built = match op {
        "disable" => {
            let account = check_disable(snapshot, sid.trim()).map_err(sentence)?;
            let quoted = format!("\"{}\"", account.name);
            let mut built = spec(
                "account.disable",
                tr!("Disable the account {0}", quoted),
                tr!("local account {0}", account.name),
                tr!(
                    "Nobody can sign in with this account until it is enabled again; its files and settings stay. Programs running as this account keep running until it signs out. You can enable it again from History or from this page."
                ),
            )
            .params(json!({ "sid": account.sid, "name": account.name }))
            .group("fix")
            .destructive();
            if account.admin {
                built = built.warning(&tr!(
                    "{0} is an administrator. Make sure you know the password of another administrator account first.",
                    quoted
                ));
            }
            built
        }
        "remove_member" => {
            let group_sid = group_sid(group)?;
            let member = check_group_remove(snapshot, group_sid, sid.trim()).map_err(sentence)?;
            let label = member_label(member);
            let group_name = if group_sid == ADMINISTRATORS {
                &snapshot.administrators.name
            } else {
                &snapshot.remote_desktop_users.name
            };
            let explain = if group_sid == ADMINISTRATORS {
                tr!(
                    "The account stays, but it loses administrator rights: from its next sign-in it can no longer change system settings or install programs for everyone without an administrator's password. You can add it back from History."
                )
            } else {
                tr!(
                    "The account can no longer sign in to this computer with Remote Desktop (administrators still can, if Remote Desktop is on). You can add it back from History."
                )
            };
            spec(
                "account.group_remove",
                tr!("Remove {0} from {1}", label, group_name),
                label.clone(),
                explain,
            )
            .params(json!({ "group_sid": group_sid, "member_sid": member.sid, "member_name": label }))
            .group("fix")
            .destructive()
        }
        "logoff" => {
            let target = check_logoff(snapshot, session, current_session).map_err(sentence)?;
            let what = if target.protocol == "rdp" && !target.client_address.is_empty() {
                tr!("{0}, connected from {1}", target.user, target.client_address)
            } else {
                target.user.clone()
            };
            spec(
                "account.logoff",
                tr!("Sign out {0}", target.user),
                what,
                tr!(
                    "Ends the session: every program open in it closes. This cannot be undone; the person can sign in again."
                ),
            )
            .params(json!({ "session": target.id, "user": target.user }))
            .warning(&tr!("Work that was not saved in that session is lost."))
            .group("fix")
            .destructive()
            .irreversible()
        }
        _ => return Err(tr!("Unknown request: {0}", op)),
    };
    Ok(Plan::Run {
        spec: built,
        item: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requests::Request;
    use vigil_sys::accounts::{Group, GroupMember, LocalAccount, Session, link};

    const MACHINE: &str = "S-1-5-21-1111111111-2222222222-3333333333";

    fn sid(rid: u32) -> String {
        format!("{MACHINE}-{rid}")
    }

    fn snapshot() -> Snapshot {
        let account = |name: &str, rid: u32, enabled: bool| LocalAccount {
            sid: sid(rid),
            rid,
            name: name.into(),
            enabled,
            builtin: vigil_sys::accounts::builtin_role(rid).into(),
            ..LocalAccount::default()
        };
        let member = |rid: u32, name: &str| GroupMember {
            sid: sid(rid),
            name: format!(r"PC-VICTIM\{name}"),
            kind: "user".into(),
            ..GroupMember::default()
        };
        let mut s = Snapshot {
            machine_sid: MACHINE.into(),
            current_sids: vec![sid(1001)],
            accounts: vec![
                account("Guest", 501, false),
                account("jdoe", 1001, true),
                account("helper", 1002, true),
                account("old", 1004, false),
            ],
            administrators: Group {
                sid: ADMINISTRATORS.into(),
                name: "Administrators".into(),
                members: vec![member(1001, "jdoe"), member(1002, "helper")],
                ..Group::default()
            },
            remote_desktop_users: Group {
                sid: REMOTE_DESKTOP_USERS.into(),
                name: "Remote Desktop Users".into(),
                members: vec![member(1002, "helper")],
                ..Group::default()
            },
            sessions: vec![
                Session {
                    id: 1,
                    user: r"PC-VICTIM\jdoe".into(),
                    state: "active".into(),
                    protocol: "console".into(),
                    current: true,
                    ..Session::default()
                },
                Session {
                    id: 2,
                    user: r"PC-VICTIM\helper".into(),
                    state: "active".into(),
                    protocol: "rdp".into(),
                    client_address: "203.0.113.4".into(),
                    ..Session::default()
                },
            ],
            ..Snapshot::default()
        };
        link(&mut s);
        s
    }

    fn run_spec(plan: Result<Plan, String>) -> vigil_actions::ActionSpec {
        match plan {
            Ok(Plan::Run { spec, .. }) => spec,
            other => panic!("a confirmed action, got {other:?}"),
        }
    }

    #[test]
    fn disabling_is_planned_from_the_live_account() {
        let s = snapshot();
        let spec = run_spec(plan_for("disable", &sid(1002), "", 0, &s, 1));
        assert_eq!(spec.op, "account.disable");
        assert_eq!(spec.params["sid"], sid(1002));
        assert_eq!(
            spec.params["name"], "helper",
            "the name comes from Windows, not from the page"
        );
        assert!(spec.destructive && spec.reversible && spec.admin);
        assert!(!spec.warning.is_empty(), "an administrator");

        let error = plan_for("disable", &sid(1001), "", 0, &s, 1).expect_err("in use");
        assert!(error.starts_with("You cannot disable"), "{error}");
        assert!(error.ends_with('.'));
        assert!(
            plan_for("disable", &sid(1004), "", 0, &s, 1).is_err(),
            "already disabled"
        );
        assert!(plan_for("disable", "S-1-5-18", "", 0, &s, 1).is_err());
        assert!(plan_for("format", &sid(1002), "", 0, &s, 1).is_err());
    }

    #[test]
    fn members_are_removed_from_the_two_groups_only() {
        let s = snapshot();
        let spec = run_spec(plan_for("remove_member", &sid(1002), "remote_desktop_users", 0, &s, 1));
        assert_eq!(spec.op, "account.group_remove");
        assert_eq!(spec.params["group_sid"], REMOTE_DESKTOP_USERS);
        assert_eq!(spec.params["member_name"], r"PC-VICTIM\helper");
        assert!(spec.label.contains("Remote Desktop Users"));
        let admin = run_spec(plan_for("remove_member", &sid(1002), "administrators", 0, &s, 1));
        assert_eq!(admin.params["group_sid"], ADMINISTRATORS);
        assert!(
            plan_for("remove_member", &sid(1001), "administrators", 0, &s, 1).is_err(),
            "in use"
        );
        assert!(plan_for("remove_member", &sid(1002), "users", 0, &s, 1).is_err());
        assert!(
            plan_for("remove_member", &sid(1004), "administrators", 0, &s, 1).is_err(),
            "not a member"
        );
    }

    #[test]
    fn sessions_are_signed_out_with_a_warning() {
        let s = snapshot();
        let spec = run_spec(plan_for("logoff", "", "", 2, &s, 1));
        assert_eq!(spec.op, "account.logoff");
        assert_eq!(spec.params["session"], 2);
        assert!(spec.target.contains("203.0.113.4"));
        assert!(!spec.reversible && spec.destructive && !spec.warning.is_empty());
        assert!(plan_for("logoff", "", "", 1, &s, 1).is_err(), "Vigil's own session");
        assert!(plan_for("logoff", "", "", 9, &s, 1).is_err());
    }

    #[test]
    fn the_request_kind_is_account() {
        let parsed: Request = serde_json::from_value(
            json!({"kind": "account", "op": "remove_member", "sid": "S-1-5-21-1-2-3-1002", "group": "administrators"}),
        )
        .expect("request");
        assert!(
            matches!(parsed, Request::Account { ref op, ref group, .. } if op == "remove_member" && group == "administrators")
        );
        let logoff: Request =
            serde_json::from_value(json!({"kind": "account", "op": "logoff", "session": 3})).expect("logoff");
        assert!(matches!(logoff, Request::Account { session: 3, .. }));
    }

    #[test]
    fn changes_vigil_made_are_found_in_the_journal() {
        let mut s = snapshot();
        // helper was disabled by Vigil and then removed from Remote Desktop Users.
        s.accounts[2].enabled = false;
        s.remote_desktop_users.members.clear();
        let record = |id: &str, op: &str, undo: Value, undone: bool| {
            let value = json!({
                "id": id, "batch": null, "time": "2026-11-20T10:00:00", "op": op, "label": op, "target": "",
                "item": "", "params": {}, "ok": true, "message": "", "undo": undo, "undone": undone
            });
            serde_json::from_value::<Record>(value).expect("record")
        };
        let records = vec![
            record(
                "a1",
                "account.disable",
                json!({"name": "helper", "sid": sid(1002)}),
                false,
            ),
            record("a2", "account.disable", json!({"name": "old"}), false),
            record(
                "a3",
                "account.disable",
                json!({"name": "jdoe", "sid": sid(1001)}),
                false,
            ),
            record(
                "g1",
                "account.group_remove",
                json!({"group_sid": REMOTE_DESKTOP_USERS, "member_sid": sid(1002), "member_name": "PC-VICTIM\\helper"}),
                false,
            ),
            record(
                "g2",
                "account.group_remove",
                json!({"group_sid": ADMINISTRATORS, "member_sid": sid(1002), "member_name": "x"}),
                false,
            ),
            record(
                "u1",
                "account.disable",
                json!({"sid_suffix": "-501", "name": "Guest"}),
                true,
            ),
        ];
        let (disabled, removed) = vigil_changes(&s, &records);
        let ids: Vec<&str> = disabled.iter().map(|c| c.record_id.as_str()).collect();
        assert_eq!(
            ids,
            ["a1", "a2"],
            "jdoe is enabled again; the undone Guest record is not offered"
        );
        assert_eq!(disabled[1].sid, sid(1004), "an old record found by name");
        assert_eq!(removed.len(), 1, "helper is still in Administrators");
        assert_eq!(
            (removed[0].record_id.as_str(), removed[0].group_name.as_str()),
            ("g1", "Remote Desktop Users")
        );
    }
}
