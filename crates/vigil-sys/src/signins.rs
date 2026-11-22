//! Sign-in history from the event logs: successful and failed sign-ins, lockouts, accounts created
//! or deleted, group changes, a cleared security log, and Remote Desktop connections. Read-only,
//! through the Event Log API (the same reader as the Reliability page).
//!
//! The Security log needs administrator rights; the Remote Desktop logs can often be read without
//! them. Everything is aggregated here (per day, per source address, per account) and turned into
//! warnings with a code; the app words them. Addresses are classified by a function the caller
//! passes, so this crate needs no address tables.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::mpsc;
use std::time::Duration;

use serde::Serialize;

use crate::SysError;
use crate::accounts::{ADMINISTRATORS, Snapshot};
use crate::reliability::{ERROR_EVT_CHANNEL_NOT_FOUND, LogReader, Record, local_time};
use crate::util::now_unix_ms;

pub const DEFAULT_DAYS: u32 = 30;
pub const MAX_DAYS: u32 = 90;
const DAY_MS: i64 = 86_400_000;
/// Events kept in the answer (the newest); the counts use every event read.
const MAX_EVENTS: usize = 2000;
/// Failures from one address before it counts as password guessing.
pub const GUESSING_FAILURES: u32 = 10;
/// Different account names tried before it counts as guessing names.
pub const GUESSING_NAMES: usize = 5;
/// Events of one Remote Desktop sign-in (authentication, sign-in, session) this close are one sign-in.
const SAME_SIGNIN_MS: i64 = 2 * 60 * 1000;

pub const SECURITY_LOG: &str = "Security";
pub const RDP_AUTH_LOG: &str = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
pub const RDP_SESSION_LOG: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

/// One sign-in event.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SigninEvent {
    /// "<log>:<record id>".
    pub id: String,
    /// Local ISO time.
    pub time: String,
    pub time_ms: i64,
    /// "success", "failure", "lockout", "created", "deleted", "member_added", "member_removed",
    /// "log_cleared", "remote_auth" (1149), "remote_logon" (21), "remote_reconnect" (25) or
    /// "session_logon" (21 at this computer).
    pub kind: String,
    pub event_id: u32,
    pub log: String,
    /// The account signed in (or tried, or changed): "DOMAIN\name" as recorded.
    pub account: String,
    pub sid: String,
    /// The Windows logon type (2 interactive, 3 network, 10 Remote Desktop...); 0 when none.
    pub logon_type: u32,
    /// "interactive", "network", "unlock", "remote", "cached", "batch", "service" or "other".
    pub logon: String,
    /// The source address ("" when the event names none, as for sign-ins at this computer).
    pub address: String,
    /// The address is on the internet (not a local or private network).
    pub public: bool,
    pub workstation: String,
    pub process: String,
    /// Failures: "bad_password", "no_such_user", "locked", "disabled", "expired",
    /// "password_expired", "must_change", "not_allowed", "clock" or "other".
    pub reason: String,
    /// The NTSTATUS code of a failure (`0xC000006A`).
    pub status: String,
    /// Group changes: the group and the member.
    pub group: String,
    pub group_sid: String,
    pub member: String,
    pub member_sid: String,
    /// Who made a change (account created or deleted, group change, log cleared).
    pub by: String,
}

/// Successful and failed sign-ins of one day.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Day {
    /// `YYYY-MM-DD` (local).
    pub date: String,
    pub success: u32,
    pub failure: u32,
}

/// Failed sign-ins from one address ("" for this computer).
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub address: String,
    pub public: bool,
    pub count: u32,
    /// The account names tried most, up to five.
    pub accounts: Vec<String>,
    pub account_count: u32,
    pub first: String,
    pub last: String,
}

/// Failed sign-ins for one account name.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountFailures {
    pub account: String,
    pub count: u32,
    pub sources: u32,
    pub last: String,
}

/// One sign-in from another computer (its events merged).
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RemoteSignin {
    pub time: String,
    pub time_ms: i64,
    pub account: String,
    pub address: String,
    pub public: bool,
    /// "remote_desktop" or "network".
    pub how: String,
    pub events: Vec<String>,
}

/// Something worth a look, with a code the app words.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Warning {
    /// "guessing_address", "guessing_names", "internet_signin", "log_cleared", "admin_added",
    /// "account_created", "lockouts", "no_password_required", "guest_enabled",
    /// "builtin_admin_enabled" or "unknown_admin".
    pub code: String,
    /// "bad", "warn" or "info".
    pub severity: String,
    /// An address, an account or a member, depending on the code.
    pub subject: String,
    pub detail: String,
    pub count: u32,
    /// The events behind it (ids), to show them.
    pub events: Vec<String>,
}

/// The sign-in history of the last `days` days.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Signins {
    pub days: u32,
    /// Unix ms of the read.
    pub read_ms: i64,
    /// Newest first, at most [`MAX_EVENTS`].
    pub events: Vec<SigninEvent>,
    pub daily: Vec<Day>,
    pub success: u32,
    pub failure: u32,
    pub sources: Vec<Source>,
    pub failed_accounts: Vec<AccountFailures>,
    pub remote: Vec<RemoteSignin>,
    /// The Security log could be read (it needs administrator rights).
    pub security_readable: bool,
    /// Logs that exist but could not be read.
    pub unread_logs: Vec<String>,
    /// A log had more events than are read.
    pub truncated: bool,
}

// ------------------------------------------------------------------------------ parsing

/// The words for a Windows logon type.
pub fn logon_name(logon_type: u32) -> &'static str {
    match logon_type {
        2 => "interactive",
        3 | 8 => "network",
        4 => "batch",
        5 => "service",
        7 => "unlock",
        10 | 12 => "remote",
        11 | 13 => "cached",
        _ => "other",
    }
}

/// The reason of a failed sign-in from its status (and sub-status when the status is the generic one).
pub fn failure_reason(status: &str, sub_status: &str) -> &'static str {
    let code = |text: &str| u32::from_str_radix(text.trim().trim_start_matches("0x").trim_start_matches("0X"), 16).ok();
    let main = code(status);
    let detail = code(sub_status).filter(|c| *c != 0);
    let pick = match (main, detail) {
        (Some(0xC000_006D), Some(sub)) | (None, Some(sub)) => sub,
        (Some(main), _) => main,
        (None, None) => return "other",
    };
    match pick {
        0xC000_006A => "bad_password",
        0xC000_0064 => "no_such_user",
        0xC000_0234 => "locked",
        0xC000_0072 => "disabled",
        0xC000_0193 => "expired",
        0xC000_0071 => "password_expired",
        0xC000_0224 => "must_change",
        0xC000_006F | 0xC000_0070 | 0xC000_015B | 0xC000_0413 => "not_allowed",
        0xC000_0133 => "clock",
        _ => "other",
    }
}

/// `-`, empty and loopback addresses mean "this computer".
fn clean_address(text: &str) -> String {
    let text = text.trim();
    if matches!(text, "" | "-" | "::1" | "127.0.0.1" | "LOCAL") || text.eq_ignore_ascii_case("local") {
        return String::new();
    }
    text.trim_start_matches("::ffff:").to_string()
}

fn join_account(domain: &str, name: &str) -> String {
    let (domain, name) = (domain.trim(), name.trim());
    match (domain.is_empty() || domain == "-", name.is_empty() || name == "-") {
        (_, true) => String::new(),
        (true, false) => name.to_string(),
        (false, false) => format!("{domain}\\{name}"),
    }
}

/// Accounts that are Windows itself, not a person: SYSTEM, the service accounts, Window Manager and
/// Font Driver Host sessions, and computer accounts (ending in `$`).
fn machine_account(sid: &str, name: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-5-7")
        || sid.starts_with("S-1-5-90-")
        || sid.starts_with("S-1-5-96-")
        || name.trim().ends_with('$')
        || name.trim().eq_ignore_ascii_case("ANONYMOUS LOGON")
}

/// A rendered event (`EvtRenderEventXml`) interpreted; `None` for events that are not sign-ins, or
/// are Windows signing in to itself.
pub fn event_from_xml(xml: &str, is_public: fn(&str) -> bool) -> Option<SigninEvent> {
    let r = Record::parse(xml)?;
    let get = |name: &str| r.get(name, usize::MAX).trim().to_string();
    let mut event = SigninEvent {
        id: format!("{}:{}", if r.log.is_empty() { "Log" } else { &r.log }, r.record_id),
        time: local_time(r.time_ms),
        time_ms: r.time_ms,
        event_id: r.event_id,
        log: r.log.clone(),
        ..SigninEvent::default()
    };
    let subject = || join_account(&get("SubjectDomainName"), &get("SubjectUserName"));
    match (r.provider.as_str(), r.event_id) {
        ("Microsoft-Windows-Security-Auditing", 4624 | 4625) => {
            let name = get("TargetUserName");
            let sid = get("TargetUserSid");
            if machine_account(&sid, &name) {
                return None;
            }
            event.kind = if r.event_id == 4624 { "success" } else { "failure" }.into();
            event.account = join_account(&get("TargetDomainName"), &name);
            event.sid = if sid == "S-1-0-0" { String::new() } else { sid };
            event.logon_type = get("LogonType").parse().unwrap_or(0);
            event.logon = logon_name(event.logon_type).into();
            if event.kind == "success" && matches!(event.logon.as_str(), "service" | "batch") {
                return None;
            }
            event.address = clean_address(&get("IpAddress"));
            event.workstation = get("WorkstationName").trim_matches('-').to_string();
            event.process = get("ProcessName").trim_matches('-').to_string();
            // Network sign-ins from this computer itself (shares, services) are not sign-ins of a person.
            if event.kind == "success" && event.logon == "network" && event.address.is_empty() {
                return None;
            }
            if event.kind == "failure" {
                let status = get("Status");
                let sub = get("SubStatus");
                event.reason = failure_reason(&status, &sub).into();
                event.status = if status.eq_ignore_ascii_case("0xc000006d") && !sub.is_empty() && sub != "0x0" {
                    sub
                } else {
                    status
                };
            }
        }
        ("Microsoft-Windows-Security-Auditing", 4740) => {
            event.kind = "lockout".into();
            event.account = get("TargetUserName");
            event.sid = get("TargetSid");
            // In this event TargetDomainName is the computer the attempts came from.
            event.workstation = get("TargetDomainName");
        }
        ("Microsoft-Windows-Security-Auditing", 4720 | 4726) => {
            event.kind = if r.event_id == 4720 { "created" } else { "deleted" }.into();
            event.account = join_account(&get("TargetDomainName"), &get("TargetUserName"));
            event.sid = get("TargetSid");
            event.by = subject();
        }
        ("Microsoft-Windows-Security-Auditing", 4732 | 4733) => {
            event.kind = if r.event_id == 4732 {
                "member_added"
            } else {
                "member_removed"
            }
            .into();
            event.group = join_account(&get("TargetDomainName"), &get("TargetUserName"));
            event.group_sid = get("TargetSid");
            event.member_sid = get("MemberSid");
            let member = get("MemberName");
            event.member = if member == "-" { String::new() } else { member };
            event.account = event.member.clone();
            event.sid = event.member_sid.clone();
            event.by = subject();
        }
        ("Microsoft-Windows-Eventlog", 1102) => {
            event.kind = "log_cleared".into();
            event.by = subject();
            event.account = event.by.clone();
            event.sid = get("SubjectUserSid");
        }
        ("Microsoft-Windows-TerminalServices-RemoteConnectionManager", 1149) => {
            event.kind = "remote_auth".into();
            event.account = join_account(&get("Param2"), &get("Param1"));
            event.address = clean_address(&get("Param3"));
            event.logon = "remote".into();
            if event.address.is_empty() {
                return None;
            }
        }
        ("Microsoft-Windows-TerminalServices-LocalSessionManager", 21 | 25) => {
            event.account = get("User");
            event.address = clean_address(&get("Address"));
            event.logon = if event.address.is_empty() {
                "interactive"
            } else {
                "remote"
            }
            .into();
            event.kind = match (r.event_id, event.address.is_empty()) {
                (21, true) => "session_logon",
                (21, false) => "remote_logon",
                (_, false) => "remote_reconnect",
                (_, true) => return None,
            }
            .into();
        }
        _ => return None,
    }
    event.public = !event.address.is_empty() && is_public(&event.address);
    Some(event)
}

// ------------------------------------------------------------------------------ summary

/// The account name without its domain, lower case (to group "PC\jdoe" with "jdoe").
fn bare_name(account: &str) -> String {
    account.rsplit('\\').next().unwrap_or(account).trim().to_lowercase()
}

/// The same successful sign-in recorded twice (an administrator gets two linked sign-ins).
fn drop_twins(events: Vec<SigninEvent>) -> Vec<SigninEvent> {
    let mut last: HashMap<(String, u32, String), i64> = HashMap::new();
    let mut out = Vec::with_capacity(events.len());
    for event in events {
        if event.kind == "success" {
            let key = (bare_name(&event.account), event.logon_type, event.address.clone());
            if let Some(&seen) = last.get(&key)
                && (seen - event.time_ms).abs() <= 5000
            {
                continue;
            }
            last.insert(key, event.time_ms);
        }
        out.push(event);
    }
    out
}

/// The local dates of the window, oldest first.
fn window_days(days: u32, now_ms: i64) -> Vec<String> {
    let mut out: Vec<String> = (0..i64::from(days))
        .rev()
        .map(|i| local_time(now_ms - i * DAY_MS).get(..10).unwrap_or("").to_string())
        .filter(|d| !d.is_empty())
        .collect();
    out.dedup();
    out
}

/// Remote sign-ins: Remote Desktop and network sign-ins from another computer, the events of one
/// sign-in merged.
fn remote_signins(events: &[SigninEvent]) -> Vec<RemoteSignin> {
    let mut out: Vec<RemoteSignin> = Vec::new();
    let mut ordered: Vec<&SigninEvent> = events
        .iter()
        .filter(|e| {
            !e.address.is_empty()
                && (matches!(e.kind.as_str(), "remote_auth" | "remote_logon" | "remote_reconnect")
                    || (e.kind == "success" && matches!(e.logon.as_str(), "remote" | "network" | "cached")))
        })
        .collect();
    ordered.sort_by_key(|e| e.time_ms);
    for event in ordered {
        let how = if event.logon == "network" {
            "network"
        } else {
            "remote_desktop"
        };
        let name = bare_name(&event.account);
        if let Some(found) = out.iter_mut().rev().find(|r| {
            r.address == event.address
                && r.how == how
                && (bare_name(&r.account) == name || r.account.is_empty() || name.is_empty())
                && (event.time_ms - r.time_ms).abs() <= SAME_SIGNIN_MS
        }) {
            found.events.push(event.id.clone());
            if found.account.is_empty() || event.kind == "success" {
                found.account = event.account.clone();
            }
            continue;
        }
        out.push(RemoteSignin {
            time: event.time.clone(),
            time_ms: event.time_ms,
            account: event.account.clone(),
            address: event.address.clone(),
            public: event.public,
            how: how.into(),
            events: vec![event.id.clone()],
        });
    }
    out.reverse();
    out
}

/// Counts and groups the events of the last `days` days (`events` in any order).
pub fn summarize(events: Vec<SigninEvent>, days: u32, now_ms: i64, security_readable: bool) -> Signins {
    let mut events = events;
    events.sort_by(|a, b| b.time_ms.cmp(&a.time_ms).then_with(|| b.id.cmp(&a.id)));
    let events = drop_twins(events);
    // Without the Security log, the Remote Desktop logs are the only record of sign-ins.
    let counts_as_success = |e: &SigninEvent| {
        if security_readable {
            e.kind == "success"
        } else {
            matches!(e.kind.as_str(), "session_logon" | "remote_logon" | "remote_reconnect")
        }
    };
    let mut by_day: BTreeMap<String, Day> = window_days(days, now_ms)
        .into_iter()
        .map(|date| (date.clone(), Day { date, ..Day::default() }))
        .collect();
    let (mut success, mut failure) = (0u32, 0u32);
    for event in &events {
        let date = event.time.get(..10).unwrap_or("").to_string();
        let ok = counts_as_success(event);
        let failed = event.kind == "failure";
        success += u32::from(ok);
        failure += u32::from(failed);
        if let Some(day) = by_day.get_mut(&date) {
            day.success += u32::from(ok);
            day.failure += u32::from(failed);
        }
    }

    // Failures per source address (newest first, so `last` is the first seen).
    let mut sources: Vec<Source> = Vec::new();
    let mut tried: HashMap<String, HashMap<String, u32>> = HashMap::new();
    let mut per_account: Vec<AccountFailures> = Vec::new();
    let mut account_sources: HashMap<String, HashSet<String>> = HashMap::new();
    for event in events.iter().filter(|e| e.kind == "failure") {
        let source = match sources.iter_mut().find(|s| s.address == event.address) {
            Some(found) => found,
            None => {
                sources.push(Source {
                    address: event.address.clone(),
                    public: event.public,
                    last: event.time.clone(),
                    ..Source::default()
                });
                sources.last_mut().expect("just pushed")
            }
        };
        source.count += 1;
        source.first = event.time.clone();
        let name = bare_name(&event.account);
        *tried
            .entry(event.address.clone())
            .or_default()
            .entry(name.clone())
            .or_default() += 1;
        match per_account.iter_mut().find(|a| bare_name(&a.account) == name) {
            Some(found) => found.count += 1,
            None => per_account.push(AccountFailures {
                account: if event.account.is_empty() {
                    name.clone()
                } else {
                    event.account.clone()
                },
                count: 1,
                last: event.time.clone(),
                ..AccountFailures::default()
            }),
        }
        account_sources.entry(name).or_default().insert(event.address.clone());
    }
    for source in &mut sources {
        let names = tried.remove(&source.address).unwrap_or_default();
        source.account_count = names.len() as u32;
        let mut names: Vec<(String, u32)> = names.into_iter().collect();
        names.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        source.accounts = names.into_iter().take(5).map(|(n, _)| n).collect();
    }
    sources.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.address.cmp(&b.address)));
    for account in &mut per_account {
        account.sources = account_sources
            .get(&bare_name(&account.account))
            .map_or(0, |s| s.len() as u32);
    }
    per_account.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.account.cmp(&b.account)));

    let remote = remote_signins(&events);
    let mut kept = events;
    kept.truncate(MAX_EVENTS);
    Signins {
        days,
        read_ms: now_ms,
        events: kept,
        daily: by_day.into_values().collect(),
        success,
        failure,
        sources,
        failed_accounts: per_account,
        remote,
        security_readable,
        unread_logs: Vec::new(),
        truncated: false,
    }
}

fn warning(code: &str, severity: &str, subject: &str, detail: &str, count: u32, events: Vec<String>) -> Warning {
    Warning {
        code: code.into(),
        severity: severity.into(),
        subject: subject.into(),
        detail: detail.into(),
        count,
        events: events.into_iter().take(500).collect(),
    }
}

/// What deserves a look in the accounts and the sign-in history, most serious first.
pub fn warnings(snapshot: &Snapshot, signins: &Signins) -> Vec<Warning> {
    let mut out = Vec::new();
    let ids = |pred: &dyn Fn(&SigninEvent) -> bool| -> Vec<String> {
        signins
            .events
            .iter()
            .filter(|e| pred(e))
            .map(|e| e.id.clone())
            .collect()
    };

    // The accounts as they are now.
    for account in snapshot.accounts.iter().filter(|a| a.enabled) {
        if !account.password_required {
            out.push(warning("no_password_required", "bad", &account.name, "", 1, Vec::new()));
        }
        match account.builtin.as_str() {
            "guest" => out.push(warning("guest_enabled", "warn", &account.name, "", 1, Vec::new())),
            "administrator" => out.push(warning(
                "builtin_admin_enabled",
                "info",
                &account.name,
                "",
                1,
                Vec::new(),
            )),
            _ => {}
        }
    }
    let unknown: Vec<&str> = snapshot
        .administrators
        .members
        .iter()
        .filter(|m| m.local && matches!(m.kind.as_str(), "deleted" | "unknown"))
        .map(|m| m.sid.as_str())
        .collect();
    if !unknown.is_empty() {
        out.push(warning(
            "unknown_admin",
            "info",
            unknown[0],
            "",
            unknown.len() as u32,
            Vec::new(),
        ));
    }

    // The history.
    for source in &signins.sources {
        if source.count >= GUESSING_FAILURES {
            let severity = if source.public { "bad" } else { "warn" };
            let address = source.address.clone();
            out.push(warning(
                "guessing_address",
                severity,
                &source.address,
                &source.account_count.to_string(),
                source.count,
                ids(&|e| e.kind == "failure" && e.address == address),
            ));
        }
    }
    let names: HashSet<String> = signins
        .events
        .iter()
        .filter(|e| e.kind == "failure")
        .map(|e| bare_name(&e.account))
        .filter(|n| !n.is_empty())
        .collect();
    if names.len() >= GUESSING_NAMES && signins.failure >= GUESSING_FAILURES {
        out.push(warning(
            "guessing_names",
            "warn",
            "",
            &names.len().to_string(),
            signins.failure,
            ids(&|e| e.kind == "failure"),
        ));
    }
    let mut public_seen: Vec<&str> = Vec::new();
    for remote in signins.remote.iter().filter(|r| r.public) {
        if public_seen.contains(&remote.address.as_str()) {
            continue;
        }
        public_seen.push(&remote.address);
        let from: Vec<&RemoteSignin> = signins.remote.iter().filter(|r| r.address == remote.address).collect();
        out.push(warning(
            "internet_signin",
            "bad",
            &remote.address,
            &remote.account,
            from.len() as u32,
            from.iter().flat_map(|r| r.events.clone()).collect(),
        ));
    }
    let cleared = ids(&|e| e.kind == "log_cleared");
    if let Some(first) = signins.events.iter().find(|e| e.kind == "log_cleared") {
        out.push(warning(
            "log_cleared",
            "bad",
            &first.by,
            "",
            cleared.len() as u32,
            cleared,
        ));
    }
    for event in signins
        .events
        .iter()
        .filter(|e| e.kind == "member_added" && e.group_sid.eq_ignore_ascii_case(ADMINISTRATORS))
    {
        let subject = if event.member.is_empty() {
            &event.member_sid
        } else {
            &event.member
        };
        out.push(warning(
            "admin_added",
            "warn",
            subject,
            &event.by,
            1,
            vec![event.id.clone()],
        ));
    }
    for event in signins.events.iter().filter(|e| e.kind == "created") {
        out.push(warning(
            "account_created",
            "info",
            &event.account,
            &event.by,
            1,
            vec![event.id.clone()],
        ));
    }
    let lockouts = ids(&|e| e.kind == "lockout");
    if let Some(first) = signins.events.iter().find(|e| e.kind == "lockout") {
        out.push(warning(
            "lockouts",
            "warn",
            &first.account,
            "",
            lockouts.len() as u32,
            lockouts,
        ));
    }
    let rank = |s: &str| match s {
        "bad" => 0,
        "warn" => 1,
        _ => 2,
    };
    out.sort_by_key(|w| rank(&w.severity));
    out
}

// ------------------------------------------------------------------------------ reading

/// Reads the sign-in history of the last `days` days on a worker thread that gives up after
/// `timeout`. `is_public` says whether an address is on the internet.
pub fn read(days: u32, timeout: Duration, is_public: fn(&str) -> bool) -> Result<Signins, SysError> {
    let days = days.clamp(1, MAX_DAYS);
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("vigil-signins".into())
        .spawn(move || {
            let _ = tx.send(read_now(days, is_public));
        })
        .map_err(|e| SysError::new(format!("could not start reading the event logs: {e}"), 0))?;
    match rx.recv_timeout(timeout) {
        Ok(result) => Ok(result),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SysError::new("the event logs did not answer in time", 0)),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SysError::new("reading the event logs failed", 0)),
    }
}

/// Successful sign-ins of people: at the computer, unlocks, Remote Desktop, cached credentials, and
/// network sign-ins that came from another address.
const SUCCESS_SELECT: &str = "Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' \
or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11' or Data[@Name='LogonType']='12' \
or Data[@Name='LogonType']='13' or (Data[@Name='LogonType']='3' and Data[@Name='IpAddress']!='-' \
and Data[@Name='IpAddress']!='127.0.0.1' and Data[@Name='IpAddress']!='::1')";

/// The queries: (log, XPath filter inside `System[...]`, extra filter on the event, Security).
fn queries(window_ms: i64) -> Vec<(&'static str, String, bool)> {
    let time = format!("TimeCreated[timediff(@SystemTime) <= {window_ms}]");
    vec![
        (
            SECURITY_LOG,
            format!("*[System[EventID=4624 and {time}] and EventData[{SUCCESS_SELECT}]]"),
            true,
        ),
        (SECURITY_LOG, format!("*[System[EventID=4625 and {time}]]"), true),
        (
            SECURITY_LOG,
            format!(
                "*[System[(EventID=4740 or EventID=4720 or EventID=4726 or EventID=4732 or EventID=4733 or EventID=1102) and {time}]]"
            ),
            true,
        ),
        (RDP_AUTH_LOG, format!("*[System[EventID=1149 and {time}]]"), false),
        (
            RDP_SESSION_LOG,
            format!("*[System[(EventID=21 or EventID=25) and {time}]]"),
            false,
        ),
    ]
}

fn read_now(days: u32, is_public: fn(&str) -> bool) -> Signins {
    let window_ms = i64::from(days) * DAY_MS;
    let mut reader = LogReader::default();
    let mut events = Vec::new();
    let mut unread: Vec<String> = Vec::new();
    let mut truncated = false;
    let mut security_readable = true;
    for (log, query, security) in queries(window_ms) {
        match reader.query(log, &query, false) {
            Ok((records, cut)) => {
                truncated |= cut;
                events.extend(records.iter().filter_map(|(xml, _)| event_from_xml(xml, is_public)));
            }
            Err(error) => {
                if security {
                    security_readable = false;
                }
                // A log that does not exist is simply not there; anything else (access denied) is said.
                if error.code() != ERROR_EVT_CHANNEL_NOT_FOUND && !unread.iter().any(|l| l == log) {
                    unread.push(log.to_string());
                }
            }
        }
    }
    let mut result = summarize(events, days, now_unix_ms(), security_readable);
    result.unread_logs = unread;
    result.truncated = truncated;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{Group, GroupMember, LocalAccount, REMOTE_DESKTOP_USERS};

    const MACHINE: &str = "S-1-5-21-1111111111-2222222222-3333333333";

    /// Treats the documentation ranges as the internet, as real public addresses would be.
    fn public(address: &str) -> bool {
        address.starts_with("203.0.113.") || address.starts_with("198.51.100.")
    }

    fn security(id: u32, record: u64, time: &str, data: &[(&str, &str)]) -> String {
        let fields: String = data
            .iter()
            .map(|(k, v)| format!("<Data Name='{k}'>{v}</Data>"))
            .collect();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'/>\
             <EventID>{id}</EventID><Level>0</Level><TimeCreated SystemTime='{time}'/>\
             <EventRecordID>{record}</EventRecordID><Channel>Security</Channel><Computer>PC-VICTIM</Computer></System>\
             <EventData>{fields}</EventData></Event>"
        )
    }

    fn user_data(provider: &str, channel: &str, id: u32, record: u64, time: &str, body: &str) -> String {
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='{provider}'/>\
             <EventID>{id}</EventID><TimeCreated SystemTime='{time}'/><EventRecordID>{record}</EventRecordID>\
             <Channel>{channel}</Channel></System><UserData>{body}</UserData></Event>"
        )
    }

    fn success(record: u64, time: &str, user: &str, logon_type: &str, ip: &str) -> String {
        security(
            4624,
            record,
            time,
            &[
                ("SubjectUserSid", "S-1-5-18"),
                ("TargetUserSid", &format!("{MACHINE}-1001")),
                ("TargetUserName", user),
                ("TargetDomainName", "PC-VICTIM"),
                ("LogonType", logon_type),
                ("WorkstationName", "PC-VICTIM"),
                ("ProcessName", r"C:\Windows\System32\svchost.exe"),
                ("IpAddress", ip),
            ],
        )
    }

    fn failure(record: u64, time: &str, user: &str, ip: &str, sub: &str) -> String {
        security(
            4625,
            record,
            time,
            &[
                ("TargetUserSid", "S-1-0-0"),
                ("TargetUserName", user),
                ("TargetDomainName", ""),
                ("Status", "0xc000006d"),
                ("SubStatus", sub),
                ("LogonType", "3"),
                ("WorkstationName", "-"),
                ("IpAddress", ip),
            ],
        )
    }

    fn parse(xml: &str) -> SigninEvent {
        event_from_xml(xml, public).expect("a sign-in event")
    }

    #[test]
    fn successful_and_failed_sign_ins_are_read() {
        let local = parse(&success(10, "2026-11-20T08:00:00.000Z", "jdoe", "2", "127.0.0.1"));
        assert_eq!(local.kind, "success");
        assert_eq!(local.account, r"PC-VICTIM\jdoe");
        assert_eq!(local.logon, "interactive");
        assert_eq!(local.address, "", "loopback is this computer");
        assert_eq!(local.id, "Security:10");
        assert!(!local.public);

        let rdp = parse(&success(11, "2026-11-20T09:00:00.000Z", "jdoe", "10", "203.0.113.50"));
        assert_eq!(
            (rdp.logon.as_str(), rdp.address.as_str(), rdp.public),
            ("remote", "203.0.113.50", true)
        );

        let bad = parse(&failure(
            12,
            "2026-11-20T10:00:00.000Z",
            "admin",
            "198.51.100.7",
            "0xc000006a",
        ));
        assert_eq!(bad.kind, "failure");
        assert_eq!(bad.reason, "bad_password");
        assert_eq!(bad.status, "0xc000006a", "the sub-status explains the generic status");
        assert_eq!(bad.sid, "", "S-1-0-0 is no account");
        let unknown = parse(&failure(
            13,
            "2026-11-20T10:00:01.000Z",
            "test",
            "198.51.100.7",
            "0xc0000064",
        ));
        assert_eq!(unknown.reason, "no_such_user");

        // Windows signing in to itself is not a sign-in.
        let system = security(
            4624,
            14,
            "2026-11-20T10:00:00.000Z",
            &[
                ("TargetUserSid", "S-1-5-18"),
                ("TargetUserName", "SYSTEM"),
                ("LogonType", "5"),
            ],
        );
        assert!(event_from_xml(&system, public).is_none());
        let dwm = security(
            4624,
            15,
            "2026-11-20T10:00:00.000Z",
            &[
                ("TargetUserSid", "S-1-5-90-0-1"),
                ("TargetUserName", "DWM-1"),
                ("LogonType", "2"),
            ],
        );
        assert!(event_from_xml(&dwm, public).is_none());
        let share = success(16, "2026-11-20T10:00:00.000Z", "jdoe", "3", "-");
        assert!(
            event_from_xml(&share, public).is_none(),
            "a network sign-in from this computer"
        );
        assert!(event_from_xml("<Event><System></System></Event>", public).is_none());
    }

    #[test]
    fn failure_reasons_follow_the_status() {
        assert_eq!(failure_reason("0xC000006D", "0xC000006A"), "bad_password");
        assert_eq!(failure_reason("0xC000006D", "0x0"), "other");
        assert_eq!(failure_reason("0xC0000234", "0x0"), "locked");
        assert_eq!(failure_reason("0xc0000072", ""), "disabled");
        assert_eq!(failure_reason("0xC000006D", "0xC0000071"), "password_expired");
        assert_eq!(failure_reason("0xC000006D", "0xC0000070"), "not_allowed");
        assert_eq!(failure_reason("", ""), "other");
        assert_eq!(logon_name(10), "remote");
        assert_eq!(logon_name(7), "unlock");
        assert_eq!(logon_name(99), "other");
    }

    #[test]
    fn account_and_group_changes_are_read() {
        let added = parse(&security(
            4732,
            20,
            "2026-11-19T12:00:00.000Z",
            &[
                ("MemberName", "-"),
                ("MemberSid", &format!("{MACHINE}-1003")),
                ("TargetUserName", "Administrators"),
                ("TargetDomainName", "Builtin"),
                ("TargetSid", "S-1-5-32-544"),
                ("SubjectUserName", "jdoe"),
                ("SubjectDomainName", "PC-VICTIM"),
            ],
        ));
        assert_eq!(added.kind, "member_added");
        assert_eq!(added.group, r"Builtin\Administrators");
        assert_eq!(added.group_sid, ADMINISTRATORS);
        assert_eq!(added.member, "", "a local member has no distinguished name");
        assert_eq!(added.member_sid, format!("{MACHINE}-1003"));
        assert_eq!(added.by, r"PC-VICTIM\jdoe");

        let created = parse(&security(
            4720,
            21,
            "2026-11-19T11:59:00.000Z",
            &[
                ("TargetUserName", "support"),
                ("TargetDomainName", "PC-VICTIM"),
                ("TargetSid", &format!("{MACHINE}-1003")),
                ("SubjectUserName", "jdoe"),
                ("SubjectDomainName", "PC-VICTIM"),
            ],
        ));
        assert_eq!(
            (created.kind.as_str(), created.account.as_str()),
            ("created", r"PC-VICTIM\support")
        );

        let lockout = parse(&security(
            4740,
            22,
            "2026-11-19T13:00:00.000Z",
            &[
                ("TargetUserName", "jdoe"),
                ("TargetDomainName", "DESKTOP-ABC123"),
                ("TargetSid", "x"),
            ],
        ));
        assert_eq!(
            (lockout.kind.as_str(), lockout.workstation.as_str()),
            ("lockout", "DESKTOP-ABC123")
        );

        let cleared = user_data(
            "Microsoft-Windows-Eventlog",
            "Security",
            1102,
            23,
            "2026-11-19T14:00:00.000Z",
            "<LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>\
             <SubjectUserSid>S-1-5-21-1-2-3-1001</SubjectUserSid><SubjectUserName>jdoe</SubjectUserName>\
             <SubjectDomainName>PC-VICTIM</SubjectDomainName></LogFileCleared>",
        );
        let cleared = parse(&cleared);
        assert_eq!(
            (cleared.kind.as_str(), cleared.by.as_str()),
            ("log_cleared", r"PC-VICTIM\jdoe")
        );
    }

    #[test]
    fn remote_desktop_logs_are_read() {
        let auth = parse(&user_data(
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
            RDP_AUTH_LOG,
            1149,
            30,
            "2026-11-18T20:00:00.000Z",
            "<EventXML xmlns='Event_NS'><Param1>jdoe</Param1><Param2>PC-VICTIM</Param2><Param3>203.0.113.9</Param3></EventXML>",
        ));
        assert_eq!(
            (
                auth.kind.as_str(),
                auth.account.as_str(),
                auth.address.as_str(),
                auth.public
            ),
            ("remote_auth", r"PC-VICTIM\jdoe", "203.0.113.9", true)
        );
        let session = |id: u32, record: u64, address: &str| {
            user_data(
                "Microsoft-Windows-TerminalServices-LocalSessionManager",
                RDP_SESSION_LOG,
                id,
                record,
                "2026-11-18T20:00:05.000Z",
                &format!(
                    "<EventXML xmlns='Event_NS'><User>PC-VICTIM\\jdoe</User><SessionID>2</SessionID><Address>{address}</Address></EventXML>"
                ),
            )
        };
        assert_eq!(parse(&session(21, 31, "203.0.113.9")).kind, "remote_logon");
        assert_eq!(parse(&session(25, 32, "203.0.113.9")).kind, "remote_reconnect");
        assert_eq!(parse(&session(21, 33, "LOCAL")).kind, "session_logon");
        assert!(event_from_xml(&session(25, 34, "LOCAL"), public).is_none());
    }

    fn history() -> Vec<SigninEvent> {
        let mut xml = vec![
            success(1, "2026-11-20T08:00:00.000Z", "jdoe", "2", "-"),
            // The linked second sign-in of an administrator: the same sign-in.
            success(2, "2026-11-20T08:00:01.000Z", "jdoe", "2", "-"),
            success(3, "2026-11-20T21:00:00.000Z", "jdoe", "10", "203.0.113.50"),
            success(4, "2026-11-19T09:00:00.000Z", "jdoe", "3", "192.168.1.20"),
        ];
        for i in 0..12 {
            let user = ["admin", "administrator", "test", "user", "backup", "scanner"][i % 6];
            xml.push(failure(
                100 + i as u64,
                &format!("2026-11-19T03:{:02}:00.000Z", i),
                user,
                "198.51.100.7",
                "0xc0000064",
            ));
        }
        xml.push(failure(200, "2026-11-20T07:59:00.000Z", "jdoe", "-", "0xc000006a"));
        xml.push(user_data(
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
            RDP_AUTH_LOG,
            1149,
            300,
            "2026-11-20T20:59:58.000Z",
            "<EventXML><Param1>jdoe</Param1><Param2>PC-VICTIM</Param2><Param3>203.0.113.50</Param3></EventXML>",
        ));
        xml.push(security(
            4732,
            400,
            "2026-11-19T12:00:00.000Z",
            &[
                ("MemberName", "-"),
                ("MemberSid", &format!("{MACHINE}-1003")),
                ("TargetUserName", "Administrators"),
                ("TargetDomainName", "Builtin"),
                ("TargetSid", "S-1-5-32-544"),
                ("SubjectUserName", "jdoe"),
                ("SubjectDomainName", "PC-VICTIM"),
            ],
        ));
        xml.push(user_data(
            "Microsoft-Windows-Eventlog",
            "Security",
            1102,
            401,
            "2026-11-19T14:00:00.000Z",
            "<LogFileCleared><SubjectUserName>jdoe</SubjectUserName><SubjectDomainName>PC-VICTIM</SubjectDomainName></LogFileCleared>",
        ));
        xml.iter().filter_map(|x| event_from_xml(x, public)).collect()
    }

    /// 2026-11-21 12:00 UTC.
    fn now() -> i64 {
        crate::reliability::iso_utc_ms("2026-11-21T12:00:00.000Z").expect("time")
    }

    #[test]
    fn the_history_is_counted_and_grouped() {
        let s = summarize(history(), 7, now(), true);
        assert_eq!(s.success, 3, "the linked twin is one sign-in");
        assert_eq!(s.failure, 13);
        assert_eq!(s.daily.len(), 7);
        assert_eq!(s.daily.iter().map(|d| d.failure).sum::<u32>(), 13);
        assert!(
            s.events.windows(2).all(|w| w[0].time_ms >= w[1].time_ms),
            "newest first"
        );

        let top = &s.sources[0];
        assert_eq!(
            (top.address.as_str(), top.count, top.account_count, top.public),
            ("198.51.100.7", 12, 6, true)
        );
        assert_eq!(top.accounts.len(), 5);
        assert_eq!(
            top.first,
            local_time(crate::reliability::iso_utc_ms("2026-11-19T03:00:00.000Z").expect("time"))
        );
        let here = s.sources.iter().find(|x| x.address.is_empty()).expect("this computer");
        assert_eq!(here.count, 1);
        assert_eq!(
            s.failed_accounts[0].count, 2,
            "admin, administrator, test... tried twice each"
        );
        assert!(s.failed_accounts.iter().any(|a| a.account == "jdoe" && a.sources == 1));

        // The Remote Desktop authentication and the sign-in two seconds later are one sign-in.
        assert_eq!(s.remote.len(), 2, "{:?}", s.remote);
        let rdp = s.remote.iter().find(|r| r.how == "remote_desktop").expect("rdp");
        assert_eq!(
            (rdp.address.as_str(), rdp.public, rdp.events.len()),
            ("203.0.113.50", true, 2)
        );
        assert_eq!(rdp.account, r"PC-VICTIM\jdoe");
        let lan = s.remote.iter().find(|r| r.how == "network").expect("network");
        assert!(!lan.public);
    }

    #[test]
    fn without_the_security_log_the_session_logs_count() {
        let events = vec![
            parse(&user_data(
                "Microsoft-Windows-TerminalServices-LocalSessionManager",
                RDP_SESSION_LOG,
                21,
                1,
                "2026-11-20T08:00:00.000Z",
                "<EventXML><User>PC-VICTIM\\jdoe</User><SessionID>1</SessionID><Address>LOCAL</Address></EventXML>",
            )),
            parse(&success(2, "2026-11-20T09:00:00.000Z", "jdoe", "2", "-")),
        ];
        assert_eq!(summarize(events.clone(), 7, now(), false).success, 1);
        assert_eq!(summarize(events, 7, now(), true).success, 1);
    }

    fn snapshot() -> Snapshot {
        let account = |name: &str, rid: u32, enabled: bool, password_required: bool| LocalAccount {
            sid: format!("{MACHINE}-{rid}"),
            rid,
            name: name.into(),
            enabled,
            password_required,
            builtin: crate::accounts::builtin_role(rid).into(),
            ..LocalAccount::default()
        };
        Snapshot {
            machine_sid: MACHINE.into(),
            accounts: vec![
                account("Administrator", 500, true, true),
                account("Guest", 501, true, false),
                account("jdoe", 1001, true, true),
                account("old", 1002, false, false),
            ],
            administrators: Group {
                sid: ADMINISTRATORS.into(),
                members: vec![GroupMember {
                    sid: format!("{MACHINE}-1009"),
                    kind: "deleted".into(),
                    local: true,
                    ..GroupMember::default()
                }],
                ..Group::default()
            },
            remote_desktop_users: Group {
                sid: REMOTE_DESKTOP_USERS.into(),
                ..Group::default()
            },
            ..Snapshot::default()
        }
    }

    #[test]
    fn warnings_name_what_deserves_a_look() {
        let s = summarize(history(), 7, now(), true);
        let list = warnings(&snapshot(), &s);
        let codes: Vec<&str> = list.iter().map(|w| w.code.as_str()).collect();
        for code in [
            "no_password_required",
            "guest_enabled",
            "builtin_admin_enabled",
            "unknown_admin",
            "guessing_address",
            "guessing_names",
            "internet_signin",
            "log_cleared",
            "admin_added",
        ] {
            assert!(codes.contains(&code), "{code} in {codes:?}");
        }
        assert!(!codes.contains(&"lockouts") && !codes.contains(&"account_created"));
        let rank = |w: &Warning| match w.severity.as_str() {
            "bad" => 0,
            "warn" => 1,
            _ => 2,
        };
        assert!(
            list.windows(2).all(|w| rank(&w[0]) <= rank(&w[1])),
            "most serious first"
        );

        let guess = list.iter().find(|w| w.code == "guessing_address").expect("guessing");
        assert_eq!(
            (guess.severity.as_str(), guess.subject.as_str(), guess.count),
            ("bad", "198.51.100.7", 12)
        );
        assert_eq!(guess.detail, "6");
        assert_eq!(guess.events.len(), 12);
        let internet = list.iter().find(|w| w.code == "internet_signin").expect("internet");
        assert_eq!(
            (internet.subject.as_str(), internet.detail.as_str()),
            ("203.0.113.50", r"PC-VICTIM\jdoe")
        );
        let blank = list.iter().find(|w| w.code == "no_password_required").expect("blank");
        assert_eq!(blank.subject, "Guest", "only enabled accounts");
        let added = list.iter().find(|w| w.code == "admin_added").expect("admin");
        assert_eq!(added.subject, format!("{MACHINE}-1003"));

        let quiet = summarize(Vec::new(), 7, now(), true);
        let calm = Snapshot {
            accounts: vec![LocalAccount {
                enabled: true,
                password_required: true,
                ..LocalAccount::default()
            }],
            ..Snapshot::default()
        };
        assert!(warnings(&calm, &quiet).is_empty());
    }

    #[test]
    fn the_queries_are_valid() {
        // The Security log needs administrator rights, so the filters are checked against a log
        // every account can read: a filter Windows does not understand fails right away.
        let mut reader = LogReader::default();
        for (_, query, _) in queries(DAY_MS) {
            let result = reader.query("Application", &query, false);
            assert!(result.is_ok(), "{query}: {:?}", result.err());
        }
    }

    /// Reads this computer's logs (read-only) and prints counts only.
    #[test]
    #[ignore = "reads this computer's event logs; run by hand"]
    fn live_read_prints_counts() {
        let started = std::time::Instant::now();
        let s = read(30, Duration::from_secs(60), |a| {
            !a.starts_with("192.168.") && !a.starts_with("10.")
        })
        .expect("read");
        println!(
            "events {} success {} failure {} sources {} remote {} security {} unread {} truncated {} in {:?}",
            s.events.len(),
            s.success,
            s.failure,
            s.sources.len(),
            s.remote.len(),
            s.security_readable,
            s.unread_logs.len(),
            s.truncated,
            started.elapsed()
        );
    }
}
