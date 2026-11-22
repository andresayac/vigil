//! Changes to local accounts: disable an account (undo enables it), remove a member from
//! Administrators or Remote Desktop Users (undo adds it back), and sign out a session.
//!
//! Every handler reads the accounts again and applies the guards before changing anything:
//! - the account running Vigil (or signed in to its session) is never disabled, removed or signed out;
//! - the last enabled local administrator is never disabled or removed from Administrators;
//! - Windows' own accounts (SYSTEM, services, built-in groups...) and the accounts Windows manages
//!   itself (DefaultAccount, WDAGUtilityAccount) are left alone, and so are groups as members;
//! - an unresolved SID is only removed when it is an account of this computer (a deleted account).
//!
//! The changes go through [`AccountBackend`]; the tests inject a fake one, so they never touch a
//! real account or group.

use std::rc::Rc;

use serde_json::json;
use vigil_i18n::tr;
use vigil_sys::accounts::{
    ADMINISTRATORS, GroupMember, LocalAccount, REMOTE_DESKTOP_USERS, Session, Snapshot, enabled_local_admins,
    is_person_sid, rid_of,
};
use windows::Win32::Foundation::{HLOCAL, LocalFree, WIN32_ERROR};
use windows::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_MEMBERS_INFO_0, NERR_Success, NetApiBufferFree, NetLocalGroupAddMembers, NetLocalGroupDelMembers,
    NetUserGetInfo, NetUserSetInfo, UF_ACCOUNTDISABLE, USER_ACCOUNT_FLAGS, USER_INFO_1, USER_INFO_1008,
};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::PSID;
use windows::Win32::System::RemoteDesktop::WTSLogoffSession;
use windows::core::HSTRING;

use crate::engine::{Builtin, Outcome, run_fn, undo_fn};
use crate::error::{ActionError, Result, fail};
use crate::params::Params;
use crate::registry::win32_text;
use crate::store::Store;

/// Reads the accounts and makes the changes. [`Live`] uses Windows; the tests inject a fake one
/// with [`crate::testing::set_account_backend`].
pub trait AccountBackend {
    /// Accounts, groups and sessions, read now.
    fn snapshot(&self) -> Snapshot;
    /// The session Vigil runs in.
    fn current_session(&self) -> u32;
    fn set_enabled(&self, name: &str, enabled: bool) -> Result<()>;
    fn add_member(&self, group_sid: &str, member_sid: &str) -> Result<()>;
    fn remove_member(&self, group_sid: &str, member_sid: &str) -> Result<()>;
    fn logoff(&self, session: u32) -> Result<()>;
}

fn backend() -> Rc<dyn AccountBackend> {
    crate::testing::account_backend().unwrap_or_else(|| Rc::new(Live))
}

// ------------------------------------------------------------------------------------ guards

fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn is_current(snapshot: &Snapshot, sid: &str) -> bool {
    snapshot.current_sids.iter().any(|c| same(c, sid))
}

/// The groups members can be removed from, with their names for messages.
fn group_of<'s>(snapshot: &'s Snapshot, group_sid: &str) -> Option<&'s vigil_sys::accounts::Group> {
    if same(group_sid, ADMINISTRATORS) {
        Some(&snapshot.administrators)
    } else if same(group_sid, REMOTE_DESKTOP_USERS) {
        Some(&snapshot.remote_desktop_users)
    } else {
        None
    }
}

/// The name to show for a member: its name, or its SID when it has none.
pub fn member_label(member: &GroupMember) -> String {
    if member.name.is_empty() {
        member.sid.clone()
    } else {
        member.name.clone()
    }
}

/// Whether the local account `sid` may be disabled; the account when it may.
pub fn check_disable<'s>(snapshot: &'s Snapshot, sid: &str) -> Result<&'s LocalAccount> {
    let account = snapshot
        .accounts
        .iter()
        .find(|a| same(&a.sid, sid))
        .ok_or_else(|| ActionError::new(tr!("the account is no longer on this computer")))?;
    let quoted = format!("\"{}\"", account.name);
    if is_current(snapshot, &account.sid) {
        return fail(tr!("you cannot disable the account you are using"));
    }
    if matches!(account.builtin.as_str(), "default" | "wdag") {
        return fail(tr!(
            "{0} is an account Windows manages itself; Vigil leaves it alone",
            quoted
        ));
    }
    if !account.enabled {
        return fail(tr!("the account {0} is already disabled", quoted));
    }
    let admins = enabled_local_admins(snapshot);
    if account.admin && admins.len() <= 1 {
        return fail(tr!(
            "{0} is the last enabled administrator account; without it nobody could manage this computer",
            quoted
        ));
    }
    Ok(account)
}

/// Whether `member_sid` may be removed from the group `group_sid` (Administrators or Remote Desktop
/// Users); the member when it may.
pub fn check_group_remove<'s>(snapshot: &'s Snapshot, group_sid: &str, member_sid: &str) -> Result<&'s GroupMember> {
    let group = group_of(snapshot, group_sid).ok_or_else(|| {
        ActionError::new(tr!(
            "only members of Administrators and Remote Desktop Users are removed here"
        ))
    })?;
    let member = group
        .members
        .iter()
        .find(|m| same(&m.sid, member_sid))
        .ok_or_else(|| ActionError::new(tr!("that member is no longer in {0}", group.name)))?;
    let label = member_label(member);
    if !is_person_sid(&member.sid) {
        return fail(tr!("{0} belongs to Windows itself; Vigil leaves it alone", label));
    }
    if matches!(member.kind.as_str(), "group" | "alias" | "well_known") {
        return fail(tr!("{0} is a group; Vigil only removes accounts", label));
    }
    if matches!(member.kind.as_str(), "deleted" | "unknown" | "other") && !member.local {
        return fail(tr!(
            "{0} cannot be identified and is not an account of this computer; Vigil leaves it alone",
            label
        ));
    }
    if is_current(snapshot, &member.sid) {
        return fail(tr!("you cannot remove the account you are using"));
    }
    if same(group_sid, ADMINISTRATORS) {
        if member.local && rid_of(&member.sid) == 500 {
            return fail(tr!(
                "the built-in Administrator account stays in Administrators; disable it instead"
            ));
        }
        let admins = enabled_local_admins(snapshot);
        if member.enabled == Some(true) && admins.len() <= 1 {
            return fail(tr!(
                "{0} is the last enabled administrator account; without it nobody could manage this computer",
                label
            ));
        }
    }
    Ok(member)
}

/// Whether the session `id` may be signed out: another person's session that is disconnected or
/// comes over Remote Desktop, never the one Vigil runs in.
pub fn check_logoff(snapshot: &Snapshot, id: u32, current_session: u32) -> Result<&Session> {
    let session = snapshot
        .sessions
        .iter()
        .find(|s| s.id == id)
        .ok_or_else(|| ActionError::new(tr!("the session is no longer there")))?;
    let current_user = snapshot
        .sessions
        .iter()
        .find(|s| s.id == current_session)
        .map(|s| s.user.as_str());
    if id == current_session || session.current {
        return fail(tr!("you cannot sign out the session Vigil runs in"));
    }
    if session.user.is_empty() {
        return fail(tr!("nobody is signed in to that session"));
    }
    if current_user.is_some_and(|user| same(user, &session.user)) {
        return fail(tr!("that session is yours; sign out from it directly"));
    }
    if session.state != "disconnected" && session.protocol != "rdp" {
        return fail(tr!(
            "only disconnected sessions and Remote Desktop sessions are signed out here"
        ));
    }
    Ok(session)
}

// ------------------------------------------------------------------------------------ handlers

/// `account.disable` for an account named by its SID (the Accounts page).
pub(crate) fn disable_by_sid(p: &Params<'_>) -> Result<Outcome> {
    let sid = p.req_str("sid")?;
    let backend = backend();
    let snapshot = backend.snapshot();
    let account = check_disable(&snapshot, &sid)?;
    backend.set_enabled(&account.name, false)?;
    Ok(Outcome::new(
        tr!("disabled the local account \"{0}\"", account.name),
        Some(json!({ "name": account.name, "sid": account.sid })),
    ))
}

/// `account.disable` by name (the scan's findings): the same guards when the account is found.
pub(crate) fn guard_disable_by_name(name: &str) -> Result<()> {
    let snapshot = backend().snapshot();
    match snapshot.accounts.iter().find(|a| same(&a.name, name)) {
        Some(account) if !account.enabled => Ok(()),
        Some(account) => check_disable(&snapshot, &account.sid).map(|_| ()),
        None => Ok(()),
    }
}

/// Undo of `account.disable` recorded with a SID: enables the account again (by its current name).
pub(crate) fn enable_by_sid(u: &Params<'_>) -> Result<String> {
    let sid = u.req_str("sid")?;
    let backend = backend();
    let snapshot = backend.snapshot();
    let account = snapshot
        .accounts
        .iter()
        .find(|a| same(&a.sid, &sid))
        .ok_or_else(|| ActionError::new(tr!("the account is no longer on this computer")))?;
    if !account.enabled {
        backend.set_enabled(&account.name, true)?;
    }
    Ok(tr!("enabled the account \"{0}\" again", account.name))
}

fn op_group_remove(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let group_sid = p.req_str("group_sid")?;
    let member_sid = p.req_str("member_sid")?;
    let backend = backend();
    let snapshot = backend.snapshot();
    let member = check_group_remove(&snapshot, &group_sid, &member_sid)?;
    let group = group_of(&snapshot, &group_sid)
        .map(|g| g.name.clone())
        .unwrap_or_default();
    let label = member_label(member);
    backend.remove_member(&group_sid, &member.sid)?;
    Ok(Outcome::new(
        tr!("removed {0} from {1}", label, group),
        Some(json!({ "group_sid": group_sid, "member_sid": member.sid, "member_name": label, "group_name": group })),
    ))
}

fn undo_group_remove(u: Params<'_>, _store: &Store) -> Result<String> {
    let group_sid = u.req_str("group_sid")?;
    let member_sid = u.req_str("member_sid")?;
    if !same(&group_sid, ADMINISTRATORS) && !same(&group_sid, REMOTE_DESKTOP_USERS) {
        return fail(tr!(
            "only members of Administrators and Remote Desktop Users are removed here"
        ));
    }
    backend().add_member(&group_sid, &member_sid)?;
    let label = u.str_or_empty("member_name");
    let group = u.str_or_empty("group_name");
    Ok(tr!(
        "added {0} back to {1}",
        if label.is_empty() { member_sid } else { label },
        group
    ))
}

fn op_logoff(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let id =
        u32::try_from(p.req_int("session")?).map_err(|_| ActionError::new(tr!("the session is no longer there")))?;
    let backend = backend();
    let snapshot = backend.snapshot();
    let session = check_logoff(&snapshot, id, backend.current_session())?;
    let user = session.user.clone();
    backend.logoff(id)?;
    Ok(Outcome::done(tr!("signed out the session of {0}", user)))
}

pub(crate) fn builtin() -> Vec<Builtin> {
    vec![
        (
            "account.group_remove",
            run_fn(op_group_remove),
            Some(undo_fn(undo_group_remove)),
            false,
        ),
        ("account.logoff", run_fn(op_logoff), None, false),
    ]
}

// ------------------------------------------------------------------------------------ Windows

/// The real accounts (NetApi32, Remote Desktop Services).
pub struct Live;

/// A NetApi32 status as a message for the user.
fn net_error(status: u32) -> ActionError {
    match status {
        5 => ActionError::new(tr!("this needs administrator rights")),
        1371 => ActionError::new(tr!("Windows does not allow this change to a built-in account or group")),
        1377 | 1387 => ActionError::new(tr!("that member is not in the group")),
        2221 => ActionError::new(tr!("the account is no longer on this computer")),
        _ => ActionError::new(win32_text(WIN32_ERROR(status))),
    }
}

/// A SID from its text, freed when dropped.
struct OwnedSid(PSID);

impl OwnedSid {
    fn parse(sid: &str) -> Result<Self> {
        let mut psid = PSID::default();
        // SAFETY: the HSTRING is NUL-terminated; `psid` receives a LocalAlloc'd SID owned by Self.
        unsafe { ConvertStringSidToSidW(&HSTRING::from(sid), &mut psid) }
            .map_err(|_| ActionError::new(tr!("not a valid account identifier: {0}", sid)))?;
        Ok(OwnedSid(psid))
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        // SAFETY: the SID was allocated by ConvertStringSidToSidW and is freed once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

impl Live {
    fn group_members(&self, group_sid: &str, member_sid: &str, add: bool) -> Result<()> {
        let group = vigil_sys::accounts::group_name(group_sid)
            .ok_or_else(|| ActionError::new(tr!("the group {0} was not found", group_sid)))?;
        let member = OwnedSid::parse(member_sid)?;
        let entry = LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: member.0 };
        let name = HSTRING::from(group.as_str());
        let buffer = (&entry as *const LOCALGROUP_MEMBERS_INFO_0).cast::<u8>();
        // SAFETY: `entry` points to a valid SID that outlives the call; one entry at level 0.
        let status = unsafe {
            if add {
                NetLocalGroupAddMembers(None, &name, 0, buffer, 1)
            } else {
                NetLocalGroupDelMembers(None, &name, 0, buffer, 1)
            }
        };
        // Adding a member that is already there leaves things as they should be.
        if status == NERR_Success || (add && status == 1378) {
            Ok(())
        } else {
            Err(net_error(status))
        }
    }
}

impl AccountBackend for Live {
    fn snapshot(&self) -> Snapshot {
        vigil_sys::accounts::read()
    }

    fn current_session(&self) -> u32 {
        vigil_sys::accounts::current_session_id()
    }

    fn set_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        let user = HSTRING::from(name);
        let mut buffer: *mut u8 = std::ptr::null_mut();
        // SAFETY: level 1 fills `buffer` with one USER_INFO_1, freed below.
        let status = unsafe { NetUserGetInfo(None, &user, 1, &mut buffer) };
        if status != NERR_Success || buffer.is_null() {
            return Err(net_error(status));
        }
        // SAFETY: on success the buffer holds one USER_INFO_1.
        let flags = unsafe { (*buffer.cast::<USER_INFO_1>()).usri1_flags.0 };
        // SAFETY: the buffer was allocated by NetUserGetInfo and is freed once.
        unsafe {
            let _ = NetApiBufferFree(Some(buffer.cast_const().cast()));
        }
        let flags = if enabled {
            flags & !UF_ACCOUNTDISABLE.0
        } else {
            flags | UF_ACCOUNTDISABLE.0
        };
        let info = USER_INFO_1008 {
            usri1008_flags: USER_ACCOUNT_FLAGS(flags),
        };
        // SAFETY: `info` is a valid USER_INFO_1008 for level 1008 and outlives the call.
        let status = unsafe { NetUserSetInfo(None, &user, 1008, (&info as *const USER_INFO_1008).cast(), None) };
        if status == NERR_Success {
            Ok(())
        } else {
            Err(net_error(status))
        }
    }

    fn add_member(&self, group_sid: &str, member_sid: &str) -> Result<()> {
        self.group_members(group_sid, member_sid, true)
    }

    fn remove_member(&self, group_sid: &str, member_sid: &str) -> Result<()> {
        self.group_members(group_sid, member_sid, false)
    }

    fn logoff(&self, session: u32) -> Result<()> {
        // SAFETY: plain call on the local server; Windows checks the rights.
        unsafe { WTSLogoffSession(None, session, false) }
            .map_err(|e| ActionError::new(tr!("could not sign out the session: {0}", e.message())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_sys::accounts::Group;

    const MACHINE: &str = "S-1-5-21-1111111111-2222222222-3333333333";

    fn sid(rid: u32) -> String {
        format!("{MACHINE}-{rid}")
    }

    fn account(name: &str, rid: u32, enabled: bool, admin: bool) -> LocalAccount {
        LocalAccount {
            sid: sid(rid),
            rid,
            name: name.into(),
            enabled,
            admin,
            builtin: vigil_sys::accounts::builtin_role(rid).into(),
            ..LocalAccount::default()
        }
    }

    fn member(sid: &str, name: &str, kind: &str, local: bool, enabled: Option<bool>) -> GroupMember {
        GroupMember {
            sid: sid.into(),
            name: name.into(),
            kind: kind.into(),
            local,
            enabled,
            ..GroupMember::default()
        }
    }

    pub(crate) fn snapshot() -> Snapshot {
        Snapshot {
            machine_sid: MACHINE.into(),
            current_sids: vec![sid(1001)],
            accounts: vec![
                account("Administrator", 500, false, true),
                account("jdoe", 1001, true, true),
                account("helper", 1002, true, true),
                account("guest-ish", 1003, true, false),
                account("WDAGUtilityAccount", 504, true, false),
            ],
            administrators: Group {
                sid: ADMINISTRATORS.into(),
                name: "Administrators".into(),
                members: vec![
                    member(&sid(500), r"PC-VICTIM\Administrator", "user", true, Some(false)),
                    member(&sid(1001), r"PC-VICTIM\jdoe", "user", true, Some(true)),
                    member(&sid(1002), r"PC-VICTIM\helper", "user", true, Some(true)),
                    member("S-1-5-21-9-9-9-512", r"CONTOSO\Domain Admins", "group", false, None),
                    member(&sid(1009), "", "deleted", true, None),
                    member("S-1-12-1-1-2-3-4", "", "unknown", false, None),
                    member("S-1-5-4", r"NT AUTHORITY\INTERACTIVE", "well_known", false, None),
                ],
                ..Group::default()
            },
            remote_desktop_users: Group {
                sid: REMOTE_DESKTOP_USERS.into(),
                name: "Remote Desktop Users".into(),
                members: vec![member(&sid(1003), r"PC-VICTIM\guest-ish", "user", true, Some(true))],
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
                    state: "disconnected".into(),
                    protocol: "console".into(),
                    ..Session::default()
                },
                Session {
                    id: 3,
                    user: r"PC-VICTIM\guest-ish".into(),
                    state: "active".into(),
                    protocol: "rdp".into(),
                    client_address: "203.0.113.4".into(),
                    ..Session::default()
                },
                Session {
                    id: 4,
                    user: r"PC-VICTIM\helper".into(),
                    state: "active".into(),
                    protocol: "console".into(),
                    ..Session::default()
                },
            ],
            ..Snapshot::default()
        }
    }

    fn refused<T: std::fmt::Debug>(result: Result<T>, words: &str) {
        let error = result.expect_err("refused");
        assert!(error.message().contains(words), "{}", error.message());
    }

    #[test]
    fn disabling_keeps_the_current_and_the_last_administrator() {
        let s = snapshot();
        assert_eq!(check_disable(&s, &sid(1002)).expect("helper").name, "helper");
        assert!(check_disable(&s, &sid(1003)).is_ok());
        refused(check_disable(&s, &sid(1001)), "you are using");
        refused(check_disable(&s, &sid(500)), "already disabled");
        refused(check_disable(&s, &sid(504)), "Windows manages itself");
        refused(check_disable(&s, &sid(1999)), "no longer");

        // With jdoe the only other enabled administrator, helper cannot go either.
        let mut alone = snapshot();
        alone.current_sids = vec![sid(1003)];
        alone.accounts.retain(|a| a.rid != 1001);
        refused(check_disable(&alone, &sid(1002)), "last enabled administrator");
    }

    #[test]
    fn removing_members_follows_the_guards() {
        let s = snapshot();
        assert!(check_group_remove(&s, ADMINISTRATORS, &sid(1002)).is_ok());
        assert!(
            check_group_remove(&s, ADMINISTRATORS, &sid(1009)).is_ok(),
            "a deleted account of this computer"
        );
        assert!(check_group_remove(&s, REMOTE_DESKTOP_USERS, &sid(1003)).is_ok());
        refused(check_group_remove(&s, ADMINISTRATORS, &sid(1001)), "you are using");
        refused(
            check_group_remove(&s, ADMINISTRATORS, &sid(500)),
            "built-in Administrator",
        );
        refused(
            check_group_remove(&s, ADMINISTRATORS, "S-1-5-21-9-9-9-512"),
            "is a group",
        );
        refused(
            check_group_remove(&s, ADMINISTRATORS, "S-1-12-1-1-2-3-4"),
            "cannot be identified",
        );
        refused(check_group_remove(&s, ADMINISTRATORS, "S-1-5-4"), "Windows itself");
        refused(check_group_remove(&s, "S-1-5-32-545", &sid(1002)), "only members");
        refused(check_group_remove(&s, REMOTE_DESKTOP_USERS, &sid(1002)), "no longer in");

        let mut alone = snapshot();
        alone.current_sids = vec![sid(1003)];
        alone.accounts.retain(|a| a.rid != 1001);
        alone.administrators.members.retain(|m| m.sid != sid(1001));
        refused(
            check_group_remove(&alone, ADMINISTRATORS, &sid(1002)),
            "last enabled administrator",
        );
    }

    #[test]
    fn only_other_peoples_remote_or_disconnected_sessions_are_signed_out() {
        let s = snapshot();
        assert_eq!(check_logoff(&s, 2, 1).expect("disconnected").user, r"PC-VICTIM\helper");
        assert!(check_logoff(&s, 3, 1).is_ok(), "a Remote Desktop session");
        refused(check_logoff(&s, 1, 1), "Vigil runs in");
        refused(check_logoff(&s, 4, 1), "only disconnected");
        refused(check_logoff(&s, 9, 1), "no longer there");
        let mut mine = snapshot();
        mine.sessions[1].user = r"PC-VICTIM\jdoe".into();
        refused(check_logoff(&mine, 2, 1), "is yours");
    }
}
