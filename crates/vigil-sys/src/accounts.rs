//! Local accounts, the members of the Administrators and Remote Desktop Users groups, and the
//! sessions signed in now. Read-only (NetApi32 and the Remote Desktop Services API, no PowerShell);
//! changes go through the action engine.
//!
//! Groups are found by their well-known SID, never by name: Windows translates group names
//! ("Administradores", "Administrateurs"...). The built-in Administrator and Guest accounts are
//! recognized by their RID (500, 501) for the same reason; they can also be renamed.

use std::path::PathBuf;

use serde::Serialize;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::NetworkManagement::NetManagement::{
    FILTER_NORMAL_ACCOUNT, LOCALGROUP_MEMBERS_INFO_2, MAX_PREFERRED_LENGTH, NERR_Success, NETSETUP_JOIN_STATUS,
    NetApiBufferFree, NetGetJoinInformation, NetLocalGroupGetMembers, NetSetupDomainName, NetUserEnum, NetUserGetInfo,
    UF_ACCOUNTDISABLE, UF_DONT_EXPIRE_PASSWD, UF_LOCKOUT, UF_PASSWD_NOTREQD, USER_INFO_0, USER_INFO_4, USER_INFO_24,
};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, LookupAccountSidW, PSID, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_CLIENT_ADDRESS, WTS_CONNECTSTATE_CLASS, WTS_INFO_CLASS, WTS_SESSION_INFOW,
    WTSClientAddress, WTSClientName, WTSClientProtocolType, WTSEnumerateSessionsW, WTSFreeMemory, WTSINFOW,
    WTSQuerySessionInformationW, WTSSessionInfo,
};
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcessToken};
use windows::core::{PCWSTR, PWSTR};

use crate::reliability::local_time;
use crate::util::{filetime_to_unix_ms, from_wide, now_unix_ms, wide};

/// BUILTIN\Administrators.
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
/// BUILTIN\Remote Desktop Users.
pub const REMOTE_DESKTOP_USERS: &str = "S-1-5-32-555";

/// A local account of this computer.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalAccount {
    pub sid: String,
    /// The last part of the SID: 500 is the built-in Administrator, 501 Guest.
    pub rid: u32,
    pub name: String,
    pub full_name: String,
    pub comment: String,
    pub enabled: bool,
    /// Locked out after too many wrong passwords.
    pub locked: bool,
    /// False when the account may have an empty password (the PASSWD_NOTREQD flag).
    pub password_required: bool,
    /// False when the password never expires.
    pub password_expires: bool,
    /// When the password was last set (local ISO time; "" when unknown).
    pub password_set: String,
    /// The last sign-in Windows recorded for it (local ISO time; "" when never).
    pub last_logon: String,
    pub last_logon_ms: i64,
    /// Sign-ins counted by Windows (0 when not kept).
    pub logons: u32,
    /// Wrong passwords since the last good one.
    pub bad_passwords: u32,
    /// A direct member of Administrators.
    pub admin: bool,
    /// A direct member of Remote Desktop Users.
    pub remote_desktop: bool,
    /// "administrator" (RID 500), "guest" (501), "default" (503), "wdag" (504) or "".
    pub builtin: String,
    /// Signed in with a Microsoft account: its provider and sign-in name ("" for a local password).
    pub online_provider: String,
    pub online_name: String,
    /// The account running Vigil (or signed in to this session).
    pub current: bool,
}

/// A member of a local group.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    pub sid: String,
    /// "DOMAIN\name", or "" when the SID no longer resolves.
    pub name: String,
    /// "user", "group" (a domain group), "alias" (a local group), "well_known", "deleted", "unknown"
    /// or "other".
    pub kind: String,
    /// An account or group of this computer (its SID is under the computer's own SID).
    pub local: bool,
    /// For local accounts: whether it is enabled.
    pub enabled: Option<bool>,
    pub current: bool,
}

/// A local group read by its well-known SID.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub sid: String,
    /// Its name in this Windows language.
    pub name: String,
    pub members: Vec<GroupMember>,
    /// Why the members could not be read ("" when they were).
    pub error: String,
}

/// A session on this computer (console or Remote Desktop).
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: u32,
    /// "Console", "RDP-Tcp#3"...
    pub station: String,
    /// "active", "connected", "disconnected", "idle" or "other".
    pub state: String,
    /// "DOMAIN\user".
    pub user: String,
    /// "console", "rdp" or "other".
    pub protocol: String,
    /// The address of a Remote Desktop client ("" otherwise).
    pub client_address: String,
    pub client_name: String,
    pub logon_time: String,
    pub disconnect_time: String,
    /// The session Vigil runs in.
    pub current: bool,
}

/// Accounts, groups and sessions, read now.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// The computer's own SID (local accounts are this plus a RID).
    pub machine_sid: String,
    /// The account running Vigil and the one signed in to its session (usually the same).
    pub current_sids: Vec<String>,
    pub accounts: Vec<LocalAccount>,
    pub administrators: Group,
    pub remote_desktop_users: Group,
    pub sessions: Vec<Session>,
    /// Joined to a domain (its accounts and groups may appear as members).
    pub domain_joined: bool,
    /// Local Users and Groups (lusrmgr.msc) is installed (not on Home editions).
    pub lusrmgr: bool,
    /// Parts that could not be read.
    pub errors: Vec<String>,
}

// ------------------------------------------------------------------------------ pure helpers

/// The built-in account a RID stands for ("" for ordinary accounts).
pub fn builtin_role(rid: u32) -> &'static str {
    match rid {
        500 => "administrator",
        501 => "guest",
        503 => "default",
        504 => "wdag",
        _ => "",
    }
}

/// The RID of a SID (its last part), 0 when there is none.
pub fn rid_of(sid: &str) -> u32 {
    sid.rsplit('-').next().and_then(|r| r.parse().ok()).unwrap_or(0)
}

/// The computer's SID from one of its accounts' SIDs (the account's RID removed).
pub fn domain_of(sid: &str) -> String {
    match sid.rsplit_once('-') {
        Some((domain, rid)) if sid.starts_with("S-1-5-21-") && rid.parse::<u32>().is_ok() => domain.to_string(),
        _ => String::new(),
    }
}

/// An account of this computer: its SID is the computer's SID plus a RID.
pub fn is_local_sid(sid: &str, machine_sid: &str) -> bool {
    !machine_sid.is_empty() && domain_of(sid).eq_ignore_ascii_case(machine_sid)
}

/// A SID that names a person's account rather than Windows itself: a local, domain or Microsoft
/// Entra (Azure AD) account. Everything else (SYSTEM, LOCAL SERVICE, NT SERVICE\..., BUILTIN
/// groups, Everyone...) is Windows' own.
pub fn is_person_sid(sid: &str) -> bool {
    sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-")
}

/// `SID_NAME_USE` as a word.
pub fn kind_name(usage: i32) -> &'static str {
    match usage {
        1 => "user",
        2 => "group",
        4 => "alias",
        5 => "well_known",
        6 => "deleted",
        8 => "unknown",
        _ => "other",
    }
}

/// The state of a session as a word.
pub fn session_state(state: i32) -> &'static str {
    match state {
        0 => "active",
        1 => "connected",
        4 => "disconnected",
        5 => "idle",
        _ => "other",
    }
}

/// Marks group membership and the current account on the accounts, and the local accounts' state
/// on the group members.
pub fn link(snapshot: &mut Snapshot) {
    let in_group = |group: &Group, sid: &str| group.members.iter().any(|m| m.sid.eq_ignore_ascii_case(sid));
    let current = snapshot.current_sids.clone();
    let is_current = |sid: &str| current.iter().any(|c| c.eq_ignore_ascii_case(sid));
    for account in &mut snapshot.accounts {
        account.admin = in_group(&snapshot.administrators, &account.sid);
        account.remote_desktop = in_group(&snapshot.remote_desktop_users, &account.sid);
        account.current = is_current(&account.sid);
    }
    let machine = snapshot.machine_sid.clone();
    let accounts = snapshot.accounts.clone();
    for group in [&mut snapshot.administrators, &mut snapshot.remote_desktop_users] {
        for member in &mut group.members {
            member.local = is_local_sid(&member.sid, &machine);
            member.current = is_current(&member.sid);
            member.enabled = accounts
                .iter()
                .find(|a| a.sid.eq_ignore_ascii_case(&member.sid))
                .map(|a| a.enabled);
        }
    }
}

/// The enabled local accounts that are direct members of Administrators.
pub fn enabled_local_admins(snapshot: &Snapshot) -> Vec<&LocalAccount> {
    snapshot.accounts.iter().filter(|a| a.admin && a.enabled).collect()
}

// ------------------------------------------------------------------------------ reading

/// Reads accounts, the two groups and the sessions now.
pub fn read() -> Snapshot {
    let mut snapshot = Snapshot::default();
    match read_accounts() {
        Ok(accounts) => snapshot.accounts = accounts,
        Err(error) => snapshot.errors.push(error),
    }
    snapshot.machine_sid = snapshot
        .accounts
        .iter()
        .map(|a| domain_of(&a.sid))
        .find(|d| !d.is_empty())
        .unwrap_or_default();
    snapshot.administrators = read_group(ADMINISTRATORS);
    snapshot.remote_desktop_users = read_group(REMOTE_DESKTOP_USERS);
    for group in [&snapshot.administrators, &snapshot.remote_desktop_users] {
        if !group.error.is_empty() {
            snapshot.errors.push(group.error.clone());
        }
    }
    let current_session = current_session_id();
    match read_sessions(current_session) {
        Ok(sessions) => snapshot.sessions = sessions,
        Err(error) => snapshot.errors.push(error),
    }
    let mut current = Vec::new();
    if let Some(sid) = token_user_sid() {
        current.push(sid);
    }
    if let Some(session) = snapshot.sessions.iter().find(|s| s.current)
        && let Some(sid) = sid_of_name(&session.user)
        && !current.iter().any(|c: &String| c.eq_ignore_ascii_case(&sid))
    {
        current.push(sid);
    }
    snapshot.current_sids = current;
    snapshot.domain_joined = domain_joined();
    snapshot.lusrmgr = system32().join("lusrmgr.msc").is_file();
    link(&mut snapshot);
    snapshot
}

fn system32() -> PathBuf {
    crate::paths::system_dir()
}

/// A NetApi32 buffer freed when dropped.
struct NetBuffer(*mut u8);

impl Drop for NetBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the buffer was allocated by a NetApi32 call and is freed once.
            unsafe {
                let _ = NetApiBufferFree(Some(self.0.cast_const().cast()));
            }
        }
    }
}

/// A NUL-terminated wide string from a pointer owned by Windows ("" when null).
fn pwstr(text: PWSTR) -> String {
    if text.is_null() {
        return String::new();
    }
    // SAFETY: Windows returned a valid NUL-terminated string that lives as long as its buffer.
    unsafe { text.to_string() }.unwrap_or_default()
}

/// The string form of a SID ("" when it cannot be converted).
fn sid_text(sid: PSID) -> String {
    if sid.is_invalid() {
        return String::new();
    }
    let mut text = PWSTR::null();
    // SAFETY: `sid` is valid for the call; `text` receives a LocalAlloc'd string freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) }.is_err() {
        return String::new();
    }
    let out = pwstr(text);
    // SAFETY: `text` was allocated by ConvertSidToStringSidW and is freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
    }
    out
}

/// The name of a SID: (name, domain, SID_NAME_USE), or `None` when it does not resolve.
fn lookup_sid(sid: PSID) -> Option<(String, String, i32)> {
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut usage = SID_NAME_USE::default();
    // SAFETY: both buffers are writable for the lengths passed; `sid` is valid for the call.
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut usage,
        )
    }
    .ok()?;
    Some((from_wide(&name), from_wide(&domain), usage.0))
}

/// The SID of an account name ("DOMAIN\name"), or `None`.
pub fn sid_of_name(account: &str) -> Option<String> {
    if account.trim().is_empty() {
        return None;
    }
    let name = wide(account);
    let mut sid = vec![0u8; 128];
    let mut sid_len = sid.len() as u32;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut usage = SID_NAME_USE::default();
    // SAFETY: the name is NUL-terminated; the SID and domain buffers are writable for the lengths passed.
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            Some(PSID(sid.as_mut_ptr().cast())),
            &mut sid_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut usage,
        )
    }
    .ok()?;
    let text = sid_text(PSID(sid.as_mut_ptr().cast()));
    (!text.is_empty()).then_some(text)
}

/// The SID of the account running this process.
pub fn token_user_sid() -> Option<String> {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo-handle of this process; `token` receives a handle closed below.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.ok()?;
    let mut buffer = vec![0u64; 32];
    let mut out = None;
    for _ in 0..2 {
        let mut needed = 0u32;
        let length = (buffer.len() * 8) as u32;
        // SAFETY: the buffer is writable for `length` bytes and 8-byte aligned.
        let result =
            unsafe { GetTokenInformation(token, TokenUser, Some(buffer.as_mut_ptr().cast()), length, &mut needed) };
        if result.is_ok() {
            // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points inside it.
            let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
            out = Some(sid_text(sid));
            break;
        }
        if needed as usize <= buffer.len() * 8 {
            break;
        }
        buffer = vec![0u64; (needed as usize).div_ceil(8)];
    }
    // SAFETY: `token` was opened above and is closed once.
    unsafe {
        let _ = CloseHandle(token);
    }
    out.filter(|s| !s.is_empty())
}

/// Seconds since 1970 (as NetApi32 keeps them) to (local ISO time, Unix ms); 0 is "never".
fn net_time(seconds: u32) -> (String, i64) {
    if seconds == 0 || seconds == u32::MAX {
        return (String::new(), 0);
    }
    let ms = i64::from(seconds) * 1000;
    (local_time(ms), ms)
}

fn read_accounts() -> Result<Vec<LocalAccount>, String> {
    let mut buffer: *mut u8 = std::ptr::null_mut();
    let (mut read, mut total) = (0u32, 0u32);
    // SAFETY: level 0 fills `buffer` with an array of USER_INFO_0, freed by NetBuffer.
    let status = unsafe {
        NetUserEnum(
            PCWSTR::null(),
            0,
            FILTER_NORMAL_ACCOUNT,
            &mut buffer,
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
            None,
        )
    };
    let buffer = NetBuffer(buffer);
    if status != NERR_Success || buffer.0.is_null() {
        return Err(format!("could not list the local accounts (error {status})"));
    }
    // SAFETY: on success the buffer holds `read` USER_INFO_0 entries.
    let names: Vec<String> = unsafe { std::slice::from_raw_parts(buffer.0.cast::<USER_INFO_0>(), read as usize) }
        .iter()
        .map(|u| pwstr(u.usri0_name))
        .filter(|n| !n.is_empty())
        .collect();
    drop(buffer);
    let now = now_unix_ms();
    Ok(names.iter().filter_map(|name| read_account(name, now)).collect())
}

fn read_account(name: &str, now: i64) -> Option<LocalAccount> {
    let user = wide(name);
    let mut buffer: *mut u8 = std::ptr::null_mut();
    // SAFETY: level 4 fills `buffer` with one USER_INFO_4, freed by NetBuffer.
    let status = unsafe { NetUserGetInfo(PCWSTR::null(), PCWSTR(user.as_ptr()), 4, &mut buffer) };
    let buffer = NetBuffer(buffer);
    if status != NERR_Success || buffer.0.is_null() {
        return None;
    }
    // SAFETY: on success the buffer holds one USER_INFO_4.
    let info = unsafe { &*buffer.0.cast::<USER_INFO_4>() };
    let sid = sid_text(info.usri4_user_sid);
    let flags = info.usri4_flags.0;
    let has = |flag: u32| flags & flag != 0;
    let rid = rid_of(&sid);
    let (last_logon, last_logon_ms) = net_time(info.usri4_last_logon);
    let password_set = if info.usri4_password_age == 0 {
        String::new()
    } else {
        local_time(now - i64::from(info.usri4_password_age) * 1000)
    };
    let mut account = LocalAccount {
        rid,
        builtin: builtin_role(rid).to_string(),
        name: pwstr(info.usri4_name),
        full_name: pwstr(info.usri4_full_name),
        comment: pwstr(info.usri4_comment),
        enabled: !has(UF_ACCOUNTDISABLE.0),
        locked: has(UF_LOCKOUT.0),
        password_required: !has(UF_PASSWD_NOTREQD.0),
        password_expires: !has(UF_DONT_EXPIRE_PASSWD.0),
        password_set,
        last_logon,
        last_logon_ms,
        logons: info.usri4_num_logons,
        bad_passwords: info.usri4_bad_pw_count,
        sid,
        ..LocalAccount::default()
    };
    drop(buffer);
    // Level 24 says whether the account signs in with a Microsoft account (Windows 8 and later).
    let mut online: *mut u8 = std::ptr::null_mut();
    // SAFETY: level 24 fills `online` with one USER_INFO_24, freed by NetBuffer.
    let status = unsafe { NetUserGetInfo(PCWSTR::null(), PCWSTR(user.as_ptr()), 24, &mut online) };
    let online = NetBuffer(online);
    if status == NERR_Success && !online.0.is_null() {
        // SAFETY: on success the buffer holds one USER_INFO_24.
        let info = unsafe { &*online.0.cast::<USER_INFO_24>() };
        if info.usri24_internet_identity.as_bool() {
            account.online_provider = pwstr(info.usri24_internet_provider_name);
            account.online_name = pwstr(info.usri24_internet_principal_name);
        }
    }
    Some(account)
}

/// The name of a SID given as text: (name, domain, SID_NAME_USE), or `None`.
pub fn lookup_sid_text(sid: &str) -> Option<(String, String, i32)> {
    let text = wide(sid);
    let mut psid = PSID::default();
    // SAFETY: `text` is NUL-terminated; `psid` receives a LocalAlloc'd SID freed below.
    unsafe { ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &mut psid) }.ok()?;
    let found = lookup_sid(psid);
    // SAFETY: the SID was allocated by ConvertStringSidToSidW and is freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(psid.0)));
    }
    found
}

/// The name of a local group in this Windows language ("Administrators", "Administradores"...).
pub fn group_name(sid: &str) -> Option<String> {
    lookup_sid_text(sid).map(|(name, _, _)| name).filter(|n| !n.is_empty())
}

fn read_group(sid: &str) -> Group {
    let mut group = Group {
        sid: sid.to_string(),
        ..Group::default()
    };
    let Some(name) = group_name(sid) else {
        group.error = format!("the group {sid} does not exist");
        return group;
    };
    group.name = name.clone();
    let name = wide(&name);
    let mut buffer: *mut u8 = std::ptr::null_mut();
    let (mut read, mut total) = (0u32, 0u32);
    // SAFETY: level 2 fills `buffer` with LOCALGROUP_MEMBERS_INFO_2 entries, freed by NetBuffer.
    let status = unsafe {
        NetLocalGroupGetMembers(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            2,
            &mut buffer,
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
            None,
        )
    };
    let buffer = NetBuffer(buffer);
    if status != NERR_Success {
        group.error = format!("could not read the members of {} (error {status})", group.name);
        return group;
    }
    if buffer.0.is_null() {
        return group;
    }
    // SAFETY: on success the buffer holds `read` LOCALGROUP_MEMBERS_INFO_2 entries.
    let entries = unsafe { std::slice::from_raw_parts(buffer.0.cast::<LOCALGROUP_MEMBERS_INFO_2>(), read as usize) };
    for entry in entries {
        let sid = sid_text(entry.lgrmi2_sid);
        let kind = kind_name(entry.lgrmi2_sidusage.0);
        let mut name = pwstr(entry.lgrmi2_domainandname);
        // An unresolved SID comes back as its own string form: no name.
        if matches!(kind, "deleted" | "unknown") || name.eq_ignore_ascii_case(&sid) {
            name = String::new();
        }
        group.members.push(GroupMember {
            sid,
            name,
            kind: kind.to_string(),
            ..GroupMember::default()
        });
    }
    group
}

/// The session this process runs in (`u32::MAX` when unknown).
pub fn current_session_id() -> u32 {
    let mut session = u32::MAX;
    // SAFETY: plain query for this process; `session` is writable.
    if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) }.is_err() {
        return u32::MAX;
    }
    session
}

/// A buffer from WTSQuerySessionInformationW, freed when dropped.
struct WtsBuffer(PWSTR, u32);

impl Drop for WtsBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the buffer was allocated by the Remote Desktop Services API and is freed once.
            unsafe { WTSFreeMemory(self.0.0.cast()) };
        }
    }
}

fn query_session(id: u32, class: WTS_INFO_CLASS) -> Option<WtsBuffer> {
    let mut buffer = PWSTR::null();
    let mut bytes = 0u32;
    // SAFETY: `buffer` receives memory owned by WtsBuffer; `bytes` its size.
    unsafe { WTSQuerySessionInformationW(None, id, class, &mut buffer, &mut bytes) }.ok()?;
    Some(WtsBuffer(buffer, bytes))
}

/// The client address of a Remote Desktop session ("" when there is none).
pub fn client_address(family: u32, address: &[u8; 20]) -> String {
    match family {
        // AF_INET: the address starts at the third byte.
        2 => {
            let ip = std::net::Ipv4Addr::new(address[2], address[3], address[4], address[5]);
            if ip.is_unspecified() {
                String::new()
            } else {
                ip.to_string()
            }
        }
        // AF_INET6.
        23 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&address[2..18]);
            let ip = std::net::Ipv6Addr::from(bytes);
            if ip.is_unspecified() {
                String::new()
            } else {
                ip.to_string()
            }
        }
        _ => String::new(),
    }
}

fn read_sessions(current: u32) -> Result<Vec<Session>, String> {
    let mut list: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: `list` receives an array of `count` WTS_SESSION_INFOW freed with WTSFreeMemory.
    unsafe { WTSEnumerateSessionsW(None, 0, 1, &mut list, &mut count) }
        .map_err(|e| format!("could not list the sessions: {}", e.message()))?;
    let _owned = WtsBuffer(PWSTR(list.cast()), 0);
    if list.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: on success `list` holds `count` entries that live until `_owned` is dropped.
    let entries = unsafe { std::slice::from_raw_parts(list, count as usize) };
    let mut out = Vec::new();
    for entry in entries {
        let id = entry.SessionId;
        let mut session = Session {
            id,
            station: pwstr(entry.pWinStationName),
            state: session_state(entry.State.0).to_string(),
            current: id == current,
            ..Session::default()
        };
        if let Some(info) = query_session(id, WTSSessionInfo)
            && info.1 as usize >= std::mem::size_of::<WTSINFOW>()
        {
            // SAFETY: the buffer holds one WTSINFOW (its size was checked).
            let info = unsafe { &*info.0.0.cast::<WTSINFOW>() };
            let user = from_wide(&info.UserName);
            let domain = from_wide(&info.Domain);
            session.user = match (domain.is_empty(), user.is_empty()) {
                (_, true) => String::new(),
                (true, false) => user,
                (false, false) => format!("{domain}\\{user}"),
            };
            session.logon_time = local_time(filetime_to_unix_ms(info.LogonTime));
            if WTS_CONNECTSTATE_CLASS(entry.State.0) == WTS_CONNECTSTATE_CLASS(4) {
                session.disconnect_time = local_time(filetime_to_unix_ms(info.DisconnectTime));
            }
        }
        if session.user.is_empty() {
            // Listeners and the services session: nobody is signed in there.
            continue;
        }
        if let Some(protocol) = query_session(id, WTSClientProtocolType)
            && protocol.1 >= 2
        {
            // SAFETY: the buffer holds one USHORT.
            let value = unsafe { *protocol.0.0.cast::<u16>() };
            session.protocol = match value {
                0 => "console",
                2 => "rdp",
                _ => "other",
            }
            .to_string();
        }
        if session.protocol == "rdp" {
            if let Some(address) = query_session(id, WTSClientAddress)
                && address.1 as usize >= std::mem::size_of::<WTS_CLIENT_ADDRESS>()
            {
                // SAFETY: the buffer holds one WTS_CLIENT_ADDRESS (its size was checked).
                let address = unsafe { &*address.0.0.cast::<WTS_CLIENT_ADDRESS>() };
                session.client_address = client_address(address.AddressFamily, &address.Address);
            }
            if let Some(name) = query_session(id, WTSClientName) {
                session.client_name = pwstr(name.0);
            }
        }
        out.push(session);
    }
    Ok(out)
}

fn domain_joined() -> bool {
    let mut name = PWSTR::null();
    let mut status = NETSETUP_JOIN_STATUS::default();
    // SAFETY: `name` receives a NetApi32 buffer freed below.
    let result = unsafe { NetGetJoinInformation(PCWSTR::null(), &mut name, &mut status) };
    if !name.is_null() {
        // SAFETY: the buffer was allocated by NetGetJoinInformation and is freed once.
        unsafe {
            let _ = NetApiBufferFree(Some(name.0.cast_const().cast()));
        }
    }
    result == NERR_Success && status == NetSetupDomainName
}

#[cfg(test)]
mod tests {
    use super::*;

    const MACHINE: &str = "S-1-5-21-1111111111-2222222222-3333333333";

    fn account(name: &str, rid: u32, enabled: bool) -> LocalAccount {
        LocalAccount {
            sid: format!("{MACHINE}-{rid}"),
            rid,
            name: name.into(),
            enabled,
            builtin: builtin_role(rid).into(),
            ..LocalAccount::default()
        }
    }

    fn member(sid: &str, kind: &str) -> GroupMember {
        GroupMember {
            sid: sid.into(),
            kind: kind.into(),
            ..GroupMember::default()
        }
    }

    #[test]
    fn sids_are_classified() {
        assert_eq!(rid_of(&format!("{MACHINE}-1001")), 1001);
        assert_eq!(rid_of("S-1-5-18"), 18);
        assert_eq!(rid_of(""), 0);
        assert_eq!(domain_of(&format!("{MACHINE}-500")), MACHINE);
        assert_eq!(domain_of("S-1-5-32-544"), "", "BUILTIN is not an account domain");
        assert!(is_local_sid(&format!("{MACHINE}-1002"), MACHINE));
        assert!(!is_local_sid("S-1-5-21-9-9-9-1002", MACHINE), "another domain");
        assert!(!is_local_sid(&format!("{MACHINE}-1002"), ""));
        assert!(is_person_sid("S-1-12-1-1-2-3-4"), "Microsoft Entra accounts");
        assert!(!is_person_sid("S-1-5-18") && !is_person_sid("S-1-5-32-544") && !is_person_sid("S-1-5-80-1-2"));
        assert_eq!(builtin_role(500), "administrator");
        assert_eq!(builtin_role(501), "guest");
        assert_eq!(builtin_role(1001), "");
        assert_eq!(kind_name(1), "user");
        assert_eq!(kind_name(6), "deleted");
        assert_eq!(session_state(4), "disconnected");
        assert_eq!(session_state(6), "other");
    }

    #[test]
    fn client_addresses_are_read() {
        let mut v4 = [0u8; 20];
        v4[2..6].copy_from_slice(&[203, 0, 113, 7]);
        assert_eq!(client_address(2, &v4), "203.0.113.7");
        assert_eq!(client_address(2, &[0u8; 20]), "");
        let mut v6 = [0u8; 20];
        v6[2] = 0x20;
        v6[3] = 0x01;
        v6[4] = 0x0d;
        v6[5] = 0xb8;
        v6[17] = 1;
        assert_eq!(client_address(23, &v6), "2001:db8::1");
        assert_eq!(client_address(99, &v4), "");
    }

    #[test]
    fn membership_and_the_current_account_are_linked() {
        let mut snapshot = Snapshot {
            machine_sid: MACHINE.into(),
            current_sids: vec![format!("{MACHINE}-1001")],
            accounts: vec![
                account("Administrator", 500, false),
                account("jdoe", 1001, true),
                account("helper", 1002, true),
            ],
            administrators: Group {
                sid: ADMINISTRATORS.into(),
                members: vec![
                    member(&format!("{MACHINE}-500"), "user"),
                    member(&format!("{MACHINE}-1001"), "user"),
                    member("S-1-5-21-9-9-9-512", "group"),
                    member(&format!("{MACHINE}-1005"), "deleted"),
                ],
                ..Group::default()
            },
            remote_desktop_users: Group {
                sid: REMOTE_DESKTOP_USERS.into(),
                members: vec![member(&format!("{MACHINE}-1002"), "user")],
                ..Group::default()
            },
            ..Snapshot::default()
        };
        link(&mut snapshot);
        let by_name = |name: &str| {
            snapshot
                .accounts
                .iter()
                .find(|a| a.name == name)
                .expect("account")
                .clone()
        };
        assert!(by_name("jdoe").admin && by_name("jdoe").current && !by_name("jdoe").remote_desktop);
        assert!(by_name("helper").remote_desktop && !by_name("helper").admin);
        assert!(by_name("Administrator").admin && !by_name("Administrator").enabled);
        let members = &snapshot.administrators.members;
        assert_eq!(members[1].enabled, Some(true));
        assert!(members[1].current && members[1].local);
        assert!(!members[2].local, "a domain group");
        assert!(
            members[3].local && members[3].enabled.is_none(),
            "a deleted local account"
        );
        let admins: Vec<&str> = enabled_local_admins(&snapshot)
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(admins, ["jdoe"]);
    }

    /// Reads this computer (read-only) and prints counts only.
    #[test]
    #[ignore = "reads this computer's accounts; run by hand"]
    fn live_read_prints_counts() {
        let started = std::time::Instant::now();
        let s = read();
        println!(
            "accounts {} (enabled {}), admins {}, rdp users {}, sessions {}, current sids {}, domain {}, lusrmgr {}, errors {} in {:?}",
            s.accounts.len(),
            s.accounts.iter().filter(|a| a.enabled).count(),
            s.administrators.members.len(),
            s.remote_desktop_users.members.len(),
            s.sessions.len(),
            s.current_sids.len(),
            s.domain_joined,
            s.lusrmgr,
            s.errors.len(),
            started.elapsed()
        );
    }
}
