//! Context tools for the AI: a digest of the whole scan, the findings related to one finding, the
//! recent events of a program and the history of a file.
//!
//! Like the rest of the registry they only read: the loaded report, the saved reports, the event
//! logs (through vigil-sys, no PowerShell), Microsoft Defender's threat history, the scheduled
//! tasks, the background watch's alerts and one file's metadata. Results go through the same caps
//! and anonymization as every other tool (see [`super::registry::call`]).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use vigil_scan::ai::agent::ToolDef;
use vigil_scan::model::{Analysis, Item};
use vigil_scan::privacy::clip;

use super::registry::{
    Context, MAX_LIMIT, READ_TIMEOUT, arg_str, arg_usize, compact, def, finding_line, limit, limit_prop, local_path,
    pick, report, saved_reports, schema, to_value, verdict_rank,
};

/// Saved reports `get_file_history` reads at most (newest first).
const HISTORY_REPORTS: usize = 12;
/// Largest saved report `get_file_history` opens.
const MAX_REPORT_BYTES: u64 = vigil_scan::limits::MAX_REPORT_BYTES;
/// Events read per log for `get_process_events`, before matching.
const EVENTS_PER_LOG: usize = 400;
/// Most findings `get_related` returns.
const MAX_RELATED: usize = 20;
const FIREWALL_LOG: &str = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall";

/// The four context tools, in the order an investigation is suggested to use them.
pub fn definitions() -> Vec<ToolDef> {
    vec![
        def(
            "get_scan_summary",
            "A compact digest of the whole latest scan: findings per verdict and kind, the 10 most serious findings with a one-line reason, the security settings that need attention, what changed since the previous scan, coverage notes and the next steps Vigil's own remedies suggest. Read this first.",
            schema(json!({}), &[]),
        ),
        def(
            "get_related",
            "Other findings of the latest scan that share something with one finding: the same file, the same signer (not Microsoft), the same folder, the same parent process, or the same network endpoint.",
            schema(
                json!({
                    "id": {"type": "string", "maxLength": 200, "description": "The finding's id, from list_findings."},
                    "limit": limit_prop(),
                }),
                &["id"],
            ),
        ),
        def(
            "get_process_events",
            "Recent events about one program, newest first: crashes and hangs, Microsoft Defender detections, services installed or failing, scheduled tasks created, firewall rule changes and background-watch alerts that name it. Give its path (best), its PID or its file name.",
            schema(
                json!({
                    "path": {"type": "string", "maxLength": 400, "description": "Absolute local path of the program."},
                    "pid": {"type": "integer", "minimum": 1, "description": "A running process; its program path is used."},
                    "name": {"type": "string", "maxLength": 120, "description": "Only a file name such as updater.exe (weaker: other programs may share it)."},
                    "days": {"type": "integer", "minimum": 1, "maximum": 90, "description": "Days to look back (default 30)."},
                    "limit": limit_prop(),
                }),
                &[],
            ),
        ),
        def(
            "get_file_history",
            "The history of one local file: created, modified and last-access times; where it was downloaded from (Mark of the Web); its signer; when Vigil's saved scans first and last saw it and in which roles (startup, service, task...); background-watch alerts that named it; and whether Windows recorded it running (Prefetch, administrator only). Never returns the file's content.",
            schema(
                json!({"path": {"type": "string", "maxLength": 400, "description": "Absolute local path, e.g. C:\\Users\\Public\\app.exe."}}),
                &["path"],
            ),
        ),
    ]
}

/// Runs one of the context tools (the registry adds coverage and anonymization).
pub fn call(ctx: &Context, name: &str, input: &Value) -> Result<Value, String> {
    match name {
        "get_scan_summary" => scan_summary(report(ctx)?),
        "get_related" => related(report(ctx)?, input),
        "get_process_events" => process_events(input),
        "get_file_history" => file_history(input),
        other => Err(format!("unknown tool {other:?}")),
    }
}

// ------------------------------------------------------------------------------------ helpers

/// `2026-11-20T10:00:00Z` for ms since 1970 ("" when unknown).
fn iso(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

fn ms_of(time: std::io::Result<SystemTime>) -> i64 {
    time.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

fn lower(text: &str) -> String {
    text.to_lowercase()
}

/// The lower-case file name of a path ("" when none).
fn file_name(path: &str) -> String {
    let path = path.trim().trim_matches('"');
    lower(path.rsplit(['\\', '/']).next().unwrap_or(""))
}

/// The lower-case folder of a path ("" when none).
fn folder_of(path: &str) -> String {
    let path = path.trim().trim_matches('"');
    path.rfind(['\\', '/']).map_or_else(String::new, |i| lower(&path[..i]))
}

// ------------------------------------------------------------------------------------ summary

/// Kinds that hold the security settings and events the scan judged.
const SETTING_KINDS: [&str; 2] = ["config", "event"];

fn scan_summary(analysis: &Analysis) -> Result<Value, String> {
    let mut by_verdict = Map::new();
    for verdict in vigil_scan::model::VERDICTS {
        let n = analysis.items.iter().filter(|i| i.verdict == verdict).count();
        by_verdict.insert(verdict.to_string(), json!(n));
    }
    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    for item in &analysis.items {
        *by_kind.entry(item.kind.as_str()).or_default() += 1;
    }
    let mut ranked: Vec<&Item> = analysis.items.iter().collect();
    ranked.sort_by(|a, b| {
        verdict_rank(&a.verdict)
            .cmp(&verdict_rank(&b.verdict))
            .then(b.score.cmp(&a.score))
    });
    let serious = |i: &&&Item| matches!(i.verdict.as_str(), "remove" | "disable" | "review");
    let top: Vec<Value> = ranked
        .iter()
        .filter(serious)
        .take(10)
        .map(|item| {
            let mut line = finding_line(item);
            if let Some(map) = line.as_object_mut() {
                map.insert("reason".into(), json!(clip(&item.reason, 200)));
            }
            line
        })
        .collect();
    let settings: Vec<Value> = ranked
        .iter()
        .filter(|i| SETTING_KINDS.contains(&i.kind.as_str()))
        .filter(serious)
        .take(15)
        .map(|i| json!({"id": i.id, "title": i.title, "verdict": i.verdict, "score": i.score}))
        .collect();
    let next_steps: Vec<Value> = ranked
        .iter()
        .filter(|i| matches!(i.verdict.as_str(), "remove" | "disable"))
        .take(5)
        .map(|item| {
            let steps: Vec<Value> = item
                .remediation
                .iter()
                .filter_map(|s| s.get("title").cloned())
                .take(3)
                .collect();
            json!({"id": item.id, "title": item.title, "action": clip(&item.action, 200), "steps": steps})
        })
        .collect();
    let meta = pick(
        &Value::Object(analysis.meta.clone()),
        &["started", "finished", "elevated", "version", "trigger"],
    );
    Ok(compact(
        &json!({
            "scan": meta,
            "findings": analysis.items.len(),
            "by_verdict": by_verdict,
            "by_kind": by_kind,
            "most_serious": top,
            "security_settings_needing_attention": settings,
            "changes_since_previous_scan": analysis.changes.as_ref().map(|c| pick(c, &["counts", "summary", "previous"])),
            "coverage_notes": analysis.notes,
            "next_steps": next_steps,
        }),
        15,
    ))
}

// ------------------------------------------------------------------------------------ related

/// Folders too common to relate two findings by themselves.
const GENERIC_FOLDERS: [&str; 7] = [
    "c:\\windows",
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\program files",
    "c:\\program files (x86)",
    "c:\\programdata",
    "c:\\users",
];

/// What one finding can share with another.
#[derive(Default)]
struct Keys {
    path: String,
    folder: String,
    signer: String,
    file: String,
    parents: BTreeSet<String>,
    endpoints: BTreeSet<String>,
}

fn keys(item: &Item) -> Keys {
    let path = item.path.as_deref().map(lower).unwrap_or_default();
    let folder = item
        .path
        .as_deref()
        .map(folder_of)
        .filter(|f| !f.is_empty() && !GENERIC_FOLDERS.contains(&f.as_str()))
        .unwrap_or_default();
    let signer = item
        .file
        .as_ref()
        .and_then(|f| f.get("signer"))
        .and_then(Value::as_str)
        .map(|s| lower(s.trim()))
        .filter(|s| !s.is_empty() && !s.starts_with("microsoft"))
        .unwrap_or_default();
    let parents = item
        .roles
        .iter()
        .filter(|r| r.kind == "process")
        .filter_map(|r| r.detail.get("parents").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .map(lower)
        .filter(|p| !p.is_empty())
        .collect();
    let endpoints = item
        .network
        .get("remote")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                // "203.0.113.5:443" -> "203.0.113.5"; "[2001:db8::1]:443" -> "[2001:db8::1]".
                .map(|e| e.rsplit_once(':').map_or(e, |(host, _)| host).to_string())
                .filter(|h| !h.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Keys {
        file: item.path.as_deref().map(file_name).unwrap_or_default(),
        path,
        folder,
        signer,
        parents,
        endpoints,
    }
}

/// Why `a` and `b` are related ("" entries never appear).
fn shared(a: &Keys, b: &Keys) -> Vec<String> {
    let mut out = Vec::new();
    if !a.path.is_empty() && a.path == b.path {
        out.push("same file".to_string());
    } else if !a.folder.is_empty() && a.folder == b.folder {
        out.push("same folder".to_string());
    }
    if !a.signer.is_empty() && a.signer == b.signer {
        out.push("same signer".to_string());
    }
    if a.parents.intersection(&b.parents).next().is_some() {
        out.push("same parent process".to_string());
    }
    if (!b.file.is_empty() && a.parents.contains(&b.file)) || (!a.file.is_empty() && b.parents.contains(&a.file)) {
        out.push("one starts the other".to_string());
    }
    if a.endpoints.intersection(&b.endpoints).next().is_some() {
        out.push("same network endpoint".to_string());
    }
    out
}

fn related(analysis: &Analysis, input: &Value) -> Result<Value, String> {
    let id = arg_str(input, "id");
    let item = analysis
        .items
        .iter()
        .find(|i| i.id == id)
        .ok_or_else(|| format!("No finding has the id {:?}; use list_findings.", clip(id, 80)))?;
    let mine = keys(item);
    let mut found: Vec<(Vec<String>, &Item)> = analysis
        .items
        .iter()
        .filter(|other| other.id != item.id)
        .filter_map(|other| {
            let why = shared(&mine, &keys(other));
            (!why.is_empty()).then_some((why, other))
        })
        .collect();
    found.sort_by(|(wa, a), (wb, b)| wb.len().cmp(&wa.len()).then(b.score.cmp(&a.score)));
    let total = found.len();
    let items: Vec<Value> = found
        .into_iter()
        .take(limit(input).min(MAX_RELATED))
        .map(|(why, other)| {
            let mut line = finding_line(other);
            if let Some(map) = line.as_object_mut() {
                map.insert("shared".into(), json!(why));
            }
            line
        })
        .collect();
    Ok(compact(
        &json!({"finding": finding_line(item), "total": total, "related": items}),
        MAX_LIMIT,
    ))
}

// ------------------------------------------------------------------------------------ events

/// What `get_process_events` looks for: a full path (preferred) or only a file name.
struct Target {
    /// Lower-case full path; `None` when only a name was given.
    path: Option<String>,
    /// Lower-case file name.
    name: String,
    shown: String,
}

impl Target {
    fn from_input(input: &Value) -> Result<Self, String> {
        let path = arg_str(input, "path");
        if !path.is_empty() {
            let path = local_path(path)?;
            let text = path.to_string_lossy().into_owned();
            return Ok(Self {
                name: file_name(&text),
                path: Some(lower(&text)),
                shown: text,
            });
        }
        if let Some(pid) = input.get("pid").and_then(Value::as_u64) {
            let pid = u32::try_from(pid).map_err(|_| "pid is out of range".to_string())?;
            let rows = vigil_sys::process::ProcessSampler::new()
                .and_then(|mut s| s.snapshot())
                .map_err(|e| e.to_string())?;
            let row = rows
                .iter()
                .find(|r| r.pid == pid)
                .ok_or_else(|| format!("No running process has the PID {pid}."))?;
            return Ok(if row.exe.is_empty() {
                Self {
                    path: None,
                    name: lower(&row.name),
                    shown: row.name.clone(),
                }
            } else {
                Self {
                    path: Some(lower(&row.exe)),
                    name: file_name(&row.exe),
                    shown: row.exe.clone(),
                }
            });
        }
        let name = arg_str(input, "name");
        if name.is_empty() || name.contains(['\\', '/', ':', '\n', '\r', '\0']) || name.chars().count() > 120 {
            return Err(
                "Give the program's absolute path (best), a running PID or a file name such as updater.exe.".into(),
            );
        }
        Ok(Self {
            path: None,
            name: lower(name),
            shown: name.to_string(),
        })
    }

    /// How `text` names the target: by full path, by file name (only when no path is known), or not.
    fn matched(&self, text: &str) -> Option<&'static str> {
        let text = lower(text);
        match &self.path {
            Some(path) if text.contains(path.as_str()) => Some("path"),
            Some(_) => None,
            None if !self.name.is_empty() && text.contains(self.name.as_str()) => Some("name"),
            None => None,
        }
    }
}

struct Event {
    time_ms: i64,
    value: Value,
}

fn event(time_ms: i64, source: &str, what: &str, detail: &str, how: &str) -> Event {
    Event {
        time_ms,
        value: json!({
            "time": iso(time_ms),
            "source": source,
            "what": clip(what, 200),
            "detail": clip(detail, 300),
            "matched_by": how,
        }),
    }
}

/// Events of one log that name the target; an unreadable log becomes a note.
fn log_events(
    target: &Target,
    log: &str,
    ids: &[u32],
    days: u32,
    source: &str,
    notes: &mut Vec<String>,
    describe: impl Fn(&vigil_sys::watchlog::LogEvent) -> (String, String),
) -> Vec<Event> {
    match vigil_sys::watchlog::read_recent(log, ids, days, EVENTS_PER_LOG) {
        Ok(list) => list
            .iter()
            .filter_map(|e| {
                let text: Vec<&str> = e.data.iter().map(|(_, v)| v.as_str()).collect();
                let how = target.matched(&text.join("\n"))?;
                let (what, detail) = describe(e);
                Some(event(e.time_ms, source, &what, &detail, how))
            })
            .collect(),
        Err(error) => {
            notes.push(format!("{log}: {error}"));
            Vec::new()
        }
    }
}

fn process_events(input: &Value) -> Result<Value, String> {
    let target = Target::from_input(input)?;
    let days = u32::try_from(arg_usize(input, "days", 30, 90).max(1)).unwrap_or(30);
    let mut notes: Vec<String> = Vec::new();
    let mut events: Vec<Event> = Vec::new();

    // Crashes, hangs, service failures and the rest of the reliability records.
    match vigil_sys::reliability::read(days, READ_TIMEOUT) {
        Ok(data) => events.extend(data.events.iter().filter_map(|e| {
            let how = target.matched(&format!("{}\n{}\n{}", e.path, e.subject, e.message))?;
            let what = format!("{} / {}: {}", e.category, e.kind, e.subject);
            Some(event(e.time_ms, "reliability", &what, &e.message, how))
        })),
        Err(error) => notes.push(format!("reliability: {error}")),
    }
    // Microsoft Defender's threat history, by the resources it names.
    let since = chrono::Utc::now().timestamp_millis() - i64::from(days) * 86_400_000;
    let defender = vigil_sys::defender::read();
    events.extend(
        defender
            .threats
            .iter()
            .filter(|t| t.detected_ms >= since)
            .filter_map(|t| {
                let how = target.matched(&t.resources.join("\n"))?;
                let detail = format!("{} ({}), active: {}", t.status, t.severity, t.active);
                Some(event(t.detected_ms, "defender", &t.name, &detail, how))
            }),
    );
    // Services installed (System 7045).
    events.extend(log_events(
        &target,
        "System",
        &[7045],
        days,
        "service_installed",
        &mut notes,
        |e| (e.get("ServiceName").to_string(), e.get("ImagePath").to_string()),
    ));
    // Scheduled tasks created (Security 4698; the Security log needs administrator rights).
    events.extend(log_events(
        &target,
        "Security",
        &[4698],
        days,
        "task_created",
        &mut notes,
        |e| (e.get("TaskName").to_string(), e.get("SubjectUserName").to_string()),
    ));
    // Firewall rules added, changed or deleted.
    events.extend(log_events(
        &target,
        FIREWALL_LOG,
        &[2004, 2005, 2006, 2052, 2097, 2099],
        days,
        "firewall_rule",
        &mut notes,
        |e| {
            let what = match e.event_id {
                2004 | 2097 => "rule added",
                2006 | 2052 => "rule deleted",
                _ => "rule changed",
            };
            (
                format!("{what}: {}", e.get("RuleName")),
                e.get("ModifyingApplication").to_string(),
            )
        },
    ));
    // Background-watch alerts that name it.
    if let Some(store) = crate::watch::Store::in_profile().filter(|s| s.path().exists()) {
        let since_alerts = since;
        events.extend(
            store
                .load()
                .alerts
                .iter()
                .filter(|a| a.time >= since_alerts)
                .filter_map(|a| {
                    let how = target.matched(&format!("{}\n{}", a.title, a.detail))?;
                    Some(event(a.time, "watch_alert", &a.title, &a.detail, how))
                }),
        );
    }
    // Scheduled tasks that run it now (with when they were registered).
    let tasks: Vec<Value> = match vigil_sys::tasks::list() {
        Ok(list) => list
            .iter()
            .filter(|t| target.matched(&t.program).is_some())
            .take(10)
            .map(|t| json!({"task": t.path, "created": t.created, "enabled": t.enabled}))
            .collect(),
        Err(error) => {
            notes.push(format!("scheduled tasks: {error}"));
            Vec::new()
        }
    };

    events.sort_by_key(|e| std::cmp::Reverse(e.time_ms));
    let total = events.len();
    let items: Vec<Value> = events.into_iter().take(limit(input)).map(|e| e.value).collect();
    Ok(compact(
        &json!({
            "target": target.shown,
            "matched_by": if target.path.is_some() { "full path" } else { "file name only (other programs may share it)" },
            "days": days,
            "total": total,
            "events": items,
            "scheduled_tasks_running_it": tasks,
            "unreadable_sources": notes,
        }),
        MAX_LIMIT,
    ))
}

// ------------------------------------------------------------------------------------ history

/// A download address as the Mark of the Web keeps it, without user names or passwords and
/// with the query cut (it can hold tokens).
pub fn clean_url(url: &str) -> String {
    let url = url.trim();
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), url),
    };
    let rest = rest.split('#').next().unwrap_or("");
    let (before_query, query) = match rest.split_once('?') {
        Some((before, _)) => (before, "?…"),
        None => (rest, ""),
    };
    let (authority, path) = match before_query.find('/') {
        Some(i) => before_query.split_at(i),
        None => (before_query, ""),
    };
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    clip(&format!("{scheme}{authority}{path}{query}"), 300)
}

/// The Zone.Identifier stream of a file (the Mark of the Web), at most 4 KB of it.
fn mark_of_the_web(path: &Path) -> Value {
    let stream = PathBuf::from(format!("{}:Zone.Identifier", path.display()));
    let Ok(file) = std::fs::File::open(&stream) else {
        return json!({"present": false});
    };
    let mut text = String::new();
    if file.take(4096).read_to_string(&mut text).is_err() {
        return json!({"present": true, "note": "the stream could not be read as text"});
    }
    let field = |key: &str| {
        text.lines()
            .find_map(|line| {
                let (k, v) = line.split_once('=')?;
                k.trim().eq_ignore_ascii_case(key).then(|| v.trim().to_string())
            })
            .unwrap_or_default()
    };
    let zone = field("ZoneId");
    let zone_name = match zone.as_str() {
        "0" => "this computer",
        "1" => "local intranet",
        "2" => "trusted sites",
        "3" => "internet",
        "4" => "restricted sites",
        _ => "",
    };
    json!({
        "present": true,
        "zone_id": zone,
        "zone": zone_name,
        "host_url": clean_url(&field("HostUrl")),
        "referrer_url": clean_url(&field("ReferrerUrl")),
    })
}

/// When Vigil's saved scans saw `path` (the newest [`HISTORY_REPORTS`] reports).
fn seen_in_scans(path: &str) -> Value {
    let wanted = lower(path);
    let name = file_name(path);
    let reports = saved_reports();
    let checked: Vec<&PathBuf> = reports.iter().rev().take(HISTORY_REPORTS).collect();
    let mut sightings: Vec<Value> = Vec::new();
    for report_path in &checked {
        // A cheap look first: a report that does not even hold the file name is skipped unopened.
        let holds_name = vigil_scan::limits::read_capped(report_path, MAX_REPORT_BYTES)
            .is_ok_and(|bytes| name.is_empty() || lower(&String::from_utf8_lossy(&bytes)).contains(&name));
        if !holds_name {
            continue;
        }
        let Ok(analysis) = vigil_scan::pipeline::load_report(report_path) else {
            continue;
        };
        if let Some(item) = analysis
            .items
            .iter()
            .find(|i| i.path.as_deref().is_some_and(|p| lower(p) == wanted))
        {
            let roles: Vec<&str> = item.roles.iter().take(4).map(|r| r.label.as_str()).collect();
            sightings.push(json!({
                "report": report_path.file_name().map(|n| n.to_string_lossy().into_owned()),
                "scanned": analysis.meta.get("started").cloned().unwrap_or(Value::Null),
                "verdict": item.verdict,
                "score": item.score,
                "roles": roles,
            }));
        }
    }
    // `checked` runs newest first: the last sighting is the oldest.
    json!({
        "reports_checked": checked.len(),
        "seen_in": sightings.len(),
        "first_seen": sightings.last().and_then(|s| s.get("scanned").cloned()),
        "last_seen": sightings.first().and_then(|s| s.get("scanned").cloned()),
        "sightings": sightings.into_iter().take(6).collect::<Vec<_>>(),
    })
}

/// Background-watch alerts that name `path`: how many, the first and the last.
fn watch_mentions(path: &str) -> Value {
    let Some(store) = crate::watch::Store::in_profile().filter(|s| s.path().exists()) else {
        return json!({"count": 0});
    };
    let wanted = lower(path);
    let mut times: Vec<(i64, String)> = store
        .load()
        .alerts
        .iter()
        .filter(|a| lower(&a.detail).contains(&wanted) || lower(&a.title).contains(&wanted))
        .map(|a| (a.time, a.title.clone()))
        .collect();
    times.sort_by_key(|(t, _)| *t);
    json!({
        "count": times.len(),
        "first": times.first().map(|(t, title)| json!({"time": iso(*t), "title": title})),
        "last": times.last().map(|(t, title)| json!({"time": iso(*t), "title": title})),
    })
}

/// Whether Windows' Prefetch folder holds files for this program (it needs administrator
/// rights). Only names and times are read, never the files themselves.
fn prefetch(path: &str) -> Value {
    let name = file_name(path).to_uppercase();
    if name.is_empty() {
        return json!({"readable": false});
    }
    let root = vigil_sys::paths::windows_dir();
    let Ok(entries) = std::fs::read_dir(root.join("Prefetch")) else {
        return json!({"readable": false, "note": "the Prefetch folder needs administrator rights"});
    };
    let prefix = format!("{name}-");
    let mut newest = 0i64;
    let mut files = 0usize;
    for entry in entries.flatten() {
        let file = entry.file_name().to_string_lossy().to_uppercase();
        if file.starts_with(&prefix) && file.ends_with(".PF") {
            files += 1;
            newest = newest.max(ms_of(entry.metadata().and_then(|m| m.modified())));
        }
    }
    json!({
        "readable": true,
        "files": files,
        "last_run_hint": iso(newest),
        "note": "the Prefetch file's time, which is roughly the last time Windows saw the program start",
    })
}

fn file_history(input: &Value) -> Result<Value, String> {
    let (path, metadata) = super::registry::local_file(arg_str(input, "path"))?;
    let text = path.to_string_lossy().into_owned();
    let signature = vigil_actions::verify_signature(&path).ok().map(|s| {
        let mut value = pick(
            &to_value(&s),
            &[
                "sigStatus",
                "signer",
                "issuer",
                "certNotAfter",
                "osBinary",
                "company",
                "version",
            ],
        );
        if let Some(map) = value.as_object_mut() {
            map.insert(
                "signed_when".into(),
                json!("not available: the signing time is not read"),
            );
        }
        value
    });
    Ok(compact(
        &json!({
            "path": text,
            "size": metadata.len(),
            "created": iso(ms_of(metadata.created())),
            "modified": iso(ms_of(metadata.modified())),
            "last_access": iso(ms_of(metadata.accessed())),
            "mark_of_the_web": mark_of_the_web(&path),
            "signature": signature,
            "vigil_scans": seen_in_scans(&text),
            "watch_alerts": watch_mentions(&text),
            "prefetch": prefetch(&text),
        }),
        10,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::registry::call as registry_call;
    use vigil_scan::model::Role;
    use vigil_scan::privacy::Redactor;

    fn item(id: &str, verdict: &str, score: i64, path: &str) -> Item {
        let mut item = Item::new("executable", file_name(path), path);
        item.id = id.into();
        item.verdict = verdict.into();
        item.score = score;
        item.path = Some(path.into());
        item.reason = format!("reason of {id}");
        item.action = format!("action of {id}");
        item
    }

    fn with_signer(mut item: Item, signer: &str) -> Item {
        let mut file = Map::new();
        file.insert("signer".into(), json!(signer));
        item.file = Some(file);
        item
    }

    fn with_parent(mut item: Item, parent: &str) -> Item {
        let mut detail = Map::new();
        detail.insert("parents".into(), json!([parent]));
        item.roles
            .push(Role::new("process", "1 running process".to_string(), detail));
        item
    }

    fn with_remote(mut item: Item, remote: &str) -> Item {
        item.network.insert("remote".into(), json!([remote]));
        item
    }

    fn analysis() -> Analysis {
        let mut a = Analysis::default();
        a.meta.insert("started".into(), json!("2026-11-20T10:00:00"));
        a.meta.insert("computer".into(), json!("PC-VICTIM"));
        let mut setting = Item::new("config", "Remote Desktop is on", "");
        setting.id = "s1".into();
        setting.verdict = "review".into();
        setting.score = 25;
        let mut updater = with_remote(
            with_signer(
                item("u1", "remove", 85, r"C:\Users\jdoe\AppData\Roaming\Contoso\updater.exe"),
                "Contoso Ltd",
            ),
            "203.0.113.5:443",
        );
        updater.remediation = vec![
            json!({"title": "End the process"}),
            json!({"title": "Quarantine the file"}),
        ];
        a.items = vec![
            updater,
            with_signer(
                item("u2", "review", 40, r"C:\Users\jdoe\AppData\Roaming\Contoso\helper.exe"),
                "Contoso Ltd",
            ),
            with_parent(item("u3", "disable", 55, r"C:\Users\Public\child.exe"), "updater.exe"),
            with_remote(
                item("u4", "review", 30, r"C:\Tools\Fabrikam\sync.exe"),
                "203.0.113.5:8443",
            ),
            with_signer(
                item("m1", "trusted", 0, r"C:\Windows\System32\a.exe"),
                "Microsoft Windows",
            ),
            with_signer(
                item("m2", "trusted", 0, r"C:\Windows\System32\b.exe"),
                "Microsoft Windows",
            ),
            setting,
            item("x9", "safe", 0, r"C:\Program Files\Woodgrove\w.exe"),
        ];
        a
    }

    fn ctx(anonymize: bool) -> Context {
        Context {
            report: Some(analysis()),
            report_path: Some(PathBuf::from("scan-20261120-100000-report.json")),
            redactor: Redactor::new("jdoe", "PC-VICTIM", anonymize),
            anonymized: anonymize,
            elevated: false,
        }
    }

    #[test]
    fn the_summary_ranks_findings_lists_settings_and_next_steps() {
        let out = registry_call(&ctx(false), "get_scan_summary", &json!({})).expect("summary");
        assert_eq!(out["findings"], 8);
        assert_eq!(out["by_verdict"]["remove"], 1);
        assert_eq!(out["by_kind"]["executable"], 7);
        let top: Vec<&str> = out["most_serious"]
            .as_array()
            .expect("top")
            .iter()
            .map(|i| i["id"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(top.first(), Some(&"u1"), "remove first");
        assert!(!top.contains(&"m1") && !top.contains(&"x9"), "only serious findings");
        assert_eq!(out["most_serious"][0]["reason"], "reason of u1");
        assert_eq!(out["security_settings_needing_attention"][0]["id"], "s1");
        assert_eq!(out["next_steps"][0]["steps"][1], "Quarantine the file");
        assert_eq!(out["coverage"], "standard user");
    }

    #[test]
    fn related_findings_share_a_folder_signer_parent_or_endpoint() {
        let out = registry_call(&ctx(false), "get_related", &json!({"id": "u1"})).expect("related");
        let by_id: BTreeMap<String, Vec<String>> = out["related"]
            .as_array()
            .expect("related")
            .iter()
            .map(|r| {
                let why: Vec<String> = r["shared"]
                    .as_array()
                    .map(|l| l.iter().filter_map(Value::as_str).map(str::to_string).collect())
                    .unwrap_or_default();
                (r["id"].as_str().unwrap_or("").to_string(), why)
            })
            .collect();
        assert_eq!(by_id["u2"], ["same folder", "same signer"]);
        assert_eq!(by_id["u3"], ["one starts the other"]);
        assert_eq!(by_id["u4"], ["same network endpoint"]);
        assert!(!by_id.contains_key("x9"), "nothing in common");
        // Microsoft's signer and the System32 folder relate nothing by themselves.
        let windows = registry_call(&ctx(false), "get_related", &json!({"id": "m1"})).expect("related");
        assert_eq!(windows["total"], 0);
        assert!(registry_call(&ctx(false), "get_related", &json!({"id": "nope"})).is_err());
        let one = registry_call(&ctx(false), "get_related", &json!({"id": "u1", "limit": 1})).expect("capped");
        assert_eq!(one["related"].as_array().map(Vec::len), Some(1));
        assert_eq!(one["total"], 3);
    }

    #[test]
    fn context_results_are_anonymized() {
        let out = registry_call(&ctx(true), "get_related", &json!({"id": "u1"})).expect("related");
        let text = serde_json::to_string(&out).unwrap_or_default();
        assert!(!text.contains("jdoe"), "{text}");
        let summary = registry_call(&ctx(true), "get_scan_summary", &json!({})).expect("summary");
        assert!(!serde_json::to_string(&summary).unwrap_or_default().contains("jdoe"));
    }

    #[test]
    fn urls_lose_user_info_queries_and_fragments() {
        assert_eq!(
            clean_url("https://jdoe:hunter2@dl.contoso.example/files/setup.exe?token=abc123#x"),
            "https://dl.contoso.example/files/setup.exe?…"
        );
        assert_eq!(
            clean_url("http://203.0.113.5:8080/a.exe"),
            "http://203.0.113.5:8080/a.exe"
        );
        assert_eq!(clean_url("about:internet"), "about:internet");
        assert_eq!(clean_url(""), "");
        let long = format!("https://x.example/{}", "a".repeat(2000));
        assert!(clean_url(&long).chars().count() < 400);
    }

    #[test]
    fn targets_take_a_local_path_a_pid_or_a_bare_name() {
        for bad in [
            json!({}),
            json!({"path": "\\\\server\\share\\a.exe"}),
            json!({"path": "relative\\a.exe"}),
            json!({"name": "C:\\a.exe"}),
            json!({"name": "..\\a.exe"}),
        ] {
            assert!(Target::from_input(&bad).is_err(), "{bad}");
        }
        let by_path = Target::from_input(&json!({"path": r"C:\Users\Public\Child.exe"})).expect("path");
        assert_eq!(by_path.name, "child.exe");
        assert_eq!(
            by_path.matched(r"ImagePath C:\USERS\PUBLIC\CHILD.EXE /svc"),
            Some("path")
        );
        assert_eq!(
            by_path.matched("child.exe crashed"),
            None,
            "a known path never matches by name"
        );
        let by_name = Target::from_input(&json!({"name": "Updater.exe"})).expect("name");
        assert_eq!(by_name.matched(r"C:\Other\updater.exe"), Some("name"));
        let me = std::process::id();
        let by_pid = Target::from_input(&json!({"pid": me})).expect("pid");
        assert!(by_pid.path.is_some() || !by_pid.name.is_empty());
    }

    #[test]
    fn file_history_reads_times_and_the_mark_of_the_web() {
        assert!(registry_call(&ctx(false), "get_file_history", &json!({"path": "relative.exe"})).is_err());
        let dir = std::env::temp_dir().join(format!("vigil-history-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        assert!(
            registry_call(&ctx(false), "get_file_history", &json!({"path": dir.to_string_lossy()})).is_err(),
            "a folder is refused"
        );
        let file = dir.join("setup.exe");
        std::fs::write(&file, b"not a real program").expect("file");
        // The Mark of the Web, as a browser writes it (an NTFS alternate stream).
        let zone = PathBuf::from(format!("{}:Zone.Identifier", file.display()));
        let wrote_zone = std::fs::write(
            &zone,
            "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://jdoe:pw@dl.contoso.example/setup.exe?sig=SECRET\r\n",
        )
        .is_ok();
        let out = registry_call(
            &ctx(false),
            "get_file_history",
            &json!({"path": file.to_string_lossy()}),
        )
        .expect("history");
        assert_eq!(out["size"], 18);
        assert!(!out["created"].as_str().unwrap_or("").is_empty());
        if wrote_zone {
            assert_eq!(out["mark_of_the_web"]["zone"], "internet");
            assert_eq!(
                out["mark_of_the_web"]["host_url"],
                "https://dl.contoso.example/setup.exe?…"
            );
            let text = serde_json::to_string(&out).unwrap_or_default();
            assert!(!text.contains("SECRET") && !text.contains(":pw@"), "{text}");
        }
        assert!(out["prefetch"].get("readable").is_some());
        assert!(out["vigil_scans"].get("reports_checked").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tiny OpenAI-compatible server on 127.0.0.1 that answers with `script` in order (the last
    /// reply repeats) and records each request body. Nothing goes to any real AI service.
    fn fake_model(script: Vec<Value>) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let base = format!("http://127.0.0.1:{}/v1", listener.local_addr().expect("addr").port());
        let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = std::sync::Arc::clone(&bodies);
        std::thread::spawn(move || {
            for (n, stream) in listener.incoming().flatten().enumerate() {
                let Ok(clone) = stream.try_clone() else { continue };
                let mut reader = BufReader::new(clone);
                let mut length = 0usize;
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|read| read > 0) {
                    let header = line.trim_end().to_string();
                    line.clear();
                    if header.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = header.split_once(':')
                        && k.trim().eq_ignore_ascii_case("content-length")
                    {
                        length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; length];
                let _ = std::io::Read::read_exact(&mut reader, &mut body);
                if let Ok(mut l) = log.lock() {
                    l.push(String::from_utf8_lossy(&body).into_owned());
                }
                let reply = script[n.min(script.len() - 1)].to_string();
                let mut stream = stream;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
            }
        });
        (base, bodies)
    }

    fn tool_call(id: &str, name: &str, arguments: &str) -> Value {
        json!({"choices": [{"index": 0, "finish_reason": "tool_calls", "message": {"role": "assistant", "content": null,
            "tool_calls": [{"id": id, "type": "function", "function": {"name": name, "arguments": arguments}}]}}]})
    }

    #[test]
    fn the_investigation_loop_calls_the_context_tools() {
        use std::sync::atomic::AtomicBool;
        use vigil_scan::ai::Provider;
        use vigil_scan::ai::agent::{Limits, ToolCall, investigate};
        let answer = json!({"choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant",
            "content": "{\"verdict\": \"remove\"}"}}]});
        let (base, bodies) = fake_model(vec![
            tool_call("c1", "get_scan_summary", "{}"),
            tool_call("c2", "get_related", "{\"id\": \"u1\"}"),
            answer,
        ]);
        let ctx = ctx(true);
        let host = crate::mcp::registry::Host { ctx: &ctx, skip: &[] };
        let provider = Provider::openai_compatible("test-model", None, &base).with_retries(0);
        let outcome = investigate(
            &provider,
            "system",
            "user",
            &json!({"type": "object", "properties": {"verdict": {"type": "string"}}, "required": ["verdict"]}),
            &host,
            None,
            &Limits::default(),
            &AtomicBool::new(false),
            &|_: &ToolCall| {},
        )
        .expect("answer");
        assert_eq!(outcome.answer["verdict"], "remove");
        let names: Vec<&str> = outcome.calls.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["get_scan_summary", "get_related"]);
        assert!(outcome.calls.iter().all(|c| c.ok));
        let bodies = bodies.lock().map(|b| b.clone()).unwrap_or_default();
        // The model saw the new tools offered, and the related findings came back anonymized.
        assert!(bodies[0].contains("\"get_file_history\"") && bodies[0].contains("\"get_process_events\""));
        assert!(bodies[2].contains("same signer") && !bodies[2].contains("jdoe"));
    }

    #[test]
    fn process_events_answer_for_a_path_and_name_their_unreadable_sources() {
        let exe = std::env::current_exe().expect("test program");
        let out = registry_call(
            &ctx(false),
            "get_process_events",
            &json!({"path": exe.to_string_lossy(), "days": 7, "limit": 5}),
        )
        .expect("events");
        assert_eq!(out["matched_by"], "full path");
        assert!(out["events"].as_array().is_none_or(|e| e.len() <= 5));
        assert!(out.get("total").is_some());
    }
}
