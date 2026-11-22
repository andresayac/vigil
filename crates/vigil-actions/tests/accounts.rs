//! Account actions through the engine, with a fake account backend that records the calls: no real
//! account, group or session is ever touched.

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use common::Fixture;
use serde_json::{Value, json};
use vigil_actions::accounts::AccountBackend;
use vigil_actions::{ActionSpec, execute, undo};
use vigil_sys::accounts::{
    ADMINISTRATORS, Group, GroupMember, LocalAccount, REMOTE_DESKTOP_USERS, Session, Snapshot, link,
};

const MACHINE: &str = "S-1-5-21-1111111111-2222222222-3333333333";

fn sid(rid: u32) -> String {
    format!("{MACHINE}-{rid}")
}

/// A computer with jdoe (signed in, administrator), helper (administrator) and a remote user.
fn computer() -> Snapshot {
    let account = |name: &str, rid: u32| LocalAccount {
        sid: sid(rid),
        rid,
        name: name.into(),
        enabled: true,
        password_required: true,
        ..LocalAccount::default()
    };
    let member = |rid: u32, name: &str| GroupMember {
        sid: sid(rid),
        name: format!(r"PC-VICTIM\{name}"),
        kind: "user".into(),
        ..GroupMember::default()
    };
    let mut snapshot = Snapshot {
        machine_sid: MACHINE.into(),
        current_sids: vec![sid(1001)],
        accounts: vec![account("jdoe", 1001), account("helper", 1002), account("remote", 1003)],
        administrators: Group {
            sid: ADMINISTRATORS.into(),
            name: "Administrators".into(),
            members: vec![member(1001, "jdoe"), member(1002, "helper")],
            ..Group::default()
        },
        remote_desktop_users: Group {
            sid: REMOTE_DESKTOP_USERS.into(),
            name: "Remote Desktop Users".into(),
            members: vec![member(1003, "remote")],
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
                id: 3,
                user: r"PC-VICTIM\remote".into(),
                state: "active".into(),
                protocol: "rdp".into(),
                client_address: "203.0.113.4".into(),
                ..Session::default()
            },
        ],
        ..Snapshot::default()
    };
    link(&mut snapshot);
    snapshot
}

/// Keeps a computer in memory and records every change asked of it.
struct FakeAccounts {
    state: RefCell<Snapshot>,
    calls: RefCell<Vec<String>>,
}

impl FakeAccounts {
    fn install() -> Rc<FakeAccounts> {
        let fake = Rc::new(FakeAccounts {
            state: RefCell::new(computer()),
            calls: RefCell::new(Vec::new()),
        });
        vigil_actions::testing::set_account_backend(Some(Rc::clone(&fake) as Rc<dyn AccountBackend>));
        fake
    }

    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    fn group<'s>(state: &'s mut Snapshot, group_sid: &str) -> &'s mut Group {
        if group_sid == ADMINISTRATORS {
            &mut state.administrators
        } else {
            &mut state.remote_desktop_users
        }
    }
}

impl AccountBackend for FakeAccounts {
    fn snapshot(&self) -> Snapshot {
        let mut state = self.state.borrow().clone();
        link(&mut state);
        state
    }

    fn current_session(&self) -> u32 {
        1
    }

    fn set_enabled(&self, name: &str, enabled: bool) -> Result<(), vigil_actions::ActionError> {
        self.calls.borrow_mut().push(format!("set_enabled {name} {enabled}"));
        for account in self.state.borrow_mut().accounts.iter_mut().filter(|a| a.name == name) {
            account.enabled = enabled;
        }
        Ok(())
    }

    fn add_member(&self, group_sid: &str, member_sid: &str) -> Result<(), vigil_actions::ActionError> {
        self.calls.borrow_mut().push(format!("add {group_sid} {member_sid}"));
        let mut state = self.state.borrow_mut();
        Self::group(&mut state, group_sid).members.push(GroupMember {
            sid: member_sid.into(),
            kind: "user".into(),
            ..GroupMember::default()
        });
        Ok(())
    }

    fn remove_member(&self, group_sid: &str, member_sid: &str) -> Result<(), vigil_actions::ActionError> {
        self.calls.borrow_mut().push(format!("remove {group_sid} {member_sid}"));
        let mut state = self.state.borrow_mut();
        Self::group(&mut state, group_sid)
            .members
            .retain(|m| m.sid != member_sid);
        Ok(())
    }

    fn logoff(&self, session: u32) -> Result<(), vigil_actions::ActionError> {
        self.calls.borrow_mut().push(format!("logoff {session}"));
        self.state.borrow_mut().sessions.retain(|s| s.id != session);
        Ok(())
    }
}

fn spec(op: &str, params: Value) -> ActionSpec {
    ActionSpec::new(op, op, "account", "", params)
}

#[test]
fn an_account_is_disabled_by_sid_and_enabled_again_by_undo() {
    let fx = Fixture::new();
    let fake = FakeAccounts::install();
    let record = execute(
        &spec("account.disable", json!({ "sid": sid(1002), "name": "helper" })),
        &fx.store,
        None,
        "",
    );
    assert!(record.ok(), "{}", record.message());
    assert_eq!(fake.calls(), ["set_enabled helper false"]);
    assert_eq!(record.undo_data().expect("undo")["sid"], sid(1002));

    // Renamed meanwhile: undo finds it by its SID.
    fake.state.borrow_mut().accounts[1].name = "helper2".into();
    let undone = undo(record.id(), &fx.store).expect("undo");
    assert!(undone.undone());
    assert_eq!(fake.calls()[1], "set_enabled helper2 true");
}

#[test]
fn the_account_in_use_and_the_last_administrator_stay() {
    let fx = Fixture::new();
    let fake = FakeAccounts::install();
    let mine = execute(
        &spec("account.disable", json!({ "sid": sid(1001) })),
        &fx.store,
        None,
        "",
    );
    assert!(
        !mine.ok() && mine.message().contains("you are using"),
        "{}",
        mine.message()
    );

    // helper is disabled; jdoe is then the last enabled administrator, signed in elsewhere.
    let first = execute(
        &spec("account.disable", json!({ "sid": sid(1002) })),
        &fx.store,
        None,
        "",
    );
    assert!(first.ok(), "{}", first.message());
    fake.state.borrow_mut().current_sids = vec![sid(1003)];
    let last = execute(
        &spec("account.disable", json!({ "sid": sid(1001) })),
        &fx.store,
        None,
        "",
    );
    assert!(
        !last.ok() && last.message().contains("last enabled administrator"),
        "{}",
        last.message()
    );
    let demote = execute(
        &spec(
            "account.group_remove",
            json!({ "group_sid": ADMINISTRATORS, "member_sid": sid(1001) }),
        ),
        &fx.store,
        None,
        "",
    );
    assert!(!demote.ok() && demote.message().contains("last enabled administrator"));
    assert_eq!(fake.calls(), ["set_enabled helper false"], "nothing else was changed");
}

#[test]
fn a_member_is_removed_and_added_back_by_undo() {
    let fx = Fixture::new();
    let fake = FakeAccounts::install();
    let record = execute(
        &spec(
            "account.group_remove",
            json!({ "group_sid": REMOTE_DESKTOP_USERS, "member_sid": sid(1003) }),
        ),
        &fx.store,
        None,
        "",
    );
    assert!(record.ok(), "{}", record.message());
    assert_eq!(fake.calls(), [format!("remove {REMOTE_DESKTOP_USERS} {}", sid(1003))]);
    assert!(fake.snapshot().remote_desktop_users.members.is_empty());
    let undone = undo(record.id(), &fx.store).expect("undo");
    assert!(undone.undone(), "{:?}", undone.undo_message());
    assert_eq!(fake.calls()[1], format!("add {REMOTE_DESKTOP_USERS} {}", sid(1003)));

    let other_group = execute(
        &spec(
            "account.group_remove",
            json!({ "group_sid": "S-1-5-32-545", "member_sid": sid(1003) }),
        ),
        &fx.store,
        None,
        "",
    );
    assert!(!other_group.ok());
    assert_eq!(fake.calls().len(), 2);
}

#[test]
fn only_another_persons_remote_session_is_signed_out() {
    let fx = Fixture::new();
    let fake = FakeAccounts::install();
    let mine = execute(&spec("account.logoff", json!({ "session": 1 })), &fx.store, None, "");
    assert!(
        !mine.ok() && mine.message().contains("Vigil runs in"),
        "{}",
        mine.message()
    );
    let missing = execute(&spec("account.logoff", json!({ "session": 7 })), &fx.store, None, "");
    assert!(!missing.ok());
    let remote = execute(&spec("account.logoff", json!({ "session": 3 })), &fx.store, None, "");
    assert!(remote.ok(), "{}", remote.message());
    assert!(remote.undo_data().is_none(), "signing out cannot be undone");
    assert_eq!(fake.calls(), ["logoff 3"]);
}
