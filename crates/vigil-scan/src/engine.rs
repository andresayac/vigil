//! Orchestrates the local analysis: from the raw inventory to the set of findings.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use serde_json::{Map, Value, json};

use crate::analyze::{self, Files};
use crate::lenient::{Get, list, lower, obj, str_of, truthy};
use crate::model::{Analysis, Item, kind_prefix, verdict_rank};
use crate::posture;
use crate::remedy::build_remediation;
use crate::vt;
use vigil_i18n::tr;

/// Provisional verdict from the heuristics (the AI may replace it later).
pub fn local_verdict(item: &mut Item) {
    if item.trusted {
        item.verdict = "trusted".into();
        item.verdict_source = "automatic".into();
        return;
    }
    item.verdict_source = "heuristic".into();
    let mut flags: Vec<_> = item.flags.iter().collect();
    flags.sort_by_key(|f| -f.weight);
    let reasons: Vec<&str> = flags.iter().filter(|f| f.weight > 0).map(|f| f.text.as_str()).collect();
    if item.score >= 15 {
        item.verdict = "review".into();
        item.reason = tr!(
            "Local signals: {0}.",
            reasons.iter().take(4).copied().collect::<Vec<_>>().join("; ")
        );
        if item.score >= 70 {
            item.action = tr!("High priority: find out what this is before you keep using the computer as usual.");
        } else if item.score >= 40 {
            item.action = tr!("Check whether you recognize this item and, if you do not, investigate it.");
        }
    } else {
        item.verdict = "no_signals".into();
        item.reason = if reasons.is_empty() {
            String::new()
        } else {
            tr!(
                "Minor signal: {0}.",
                reasons.iter().take(2).copied().collect::<Vec<_>>().join("; ")
            )
        };
    }
}

fn assign_ids(items: &mut [Item]) {
    let mut counters: Vec<(&'static str, usize)> = Vec::new();
    for item in items.iter_mut() {
        let prefix = kind_prefix(&item.kind);
        let n = match counters.iter_mut().find(|(p, _)| *p == prefix) {
            Some((_, n)) => {
                *n += 1;
                *n
            }
            None => {
                counters.push((prefix, 1));
                1
            }
        };
        item.id = format!("{prefix}{n}");
    }
}

/// Final order: by verdict severity and, within each verdict, by score.
pub fn sort_for_report(analysis: &mut Analysis) {
    analysis
        .items
        .sort_by_cached_key(|i| (verdict_rank(&i.verdict), -i.score, i.kind.clone(), lower(&i.title)));
}

/// Options of a live analysis (the system is examined: signatures, hashes, VirusTotal).
pub(crate) struct Live<'a> {
    pub(crate) workdir: Option<&'a std::path::Path>,
    pub(crate) vt_key: Option<&'a str>,
    pub(crate) vt_limit: usize,
    pub(crate) progress: &'a dyn Fn(&str),
    pub(crate) cancel: &'a AtomicBool,
    /// The signature cache of the data folder (`sigcache.rs`); `None` verifies every file.
    pub(crate) cache: Option<&'a std::path::Path>,
}

/// Evaluates the inventory. `live = None` does not touch the system (saved or test inventories).
pub(crate) fn analyze(raw: &mut Value, live: Option<&Live>) -> Analysis {
    let say = |msg: &str| {
        if let Some(live) = live {
            (live.progress)(msg);
        }
    };
    let cancelled = || live.is_some_and(|l| l.cancel.load(Ordering::Relaxed));
    // Seconds per analysis phase, kept in `meta.timings` next to the collectors' (live scans only).
    let mut phases: Vec<(&str, f64)> = Vec::new();
    let mut clock = Instant::now();
    let mut lap = |name: &'static str, phases: &mut Vec<(&str, f64)>| {
        phases.push((name, clock.elapsed().as_secs_f64()));
        clock = Instant::now();
    };
    let (refs, aux) = analyze::build_references(raw);
    let mut files: Files = obj(raw.at("files")).clone();
    // The accessibility programs are checked even when nothing references them: a copy of cmd.exe
    // in their place keeps Microsoft's signature, only its version data tells (posture.rs).
    let mut missing: Vec<String> = analyze::needed_paths(&refs)
        .into_iter()
        .chain(crate::hooks::accessibility_paths())
        .filter(|p| !files.contains_key(&lower(p)))
        .collect();
    missing.sort_by_key(|p| lower(p));
    missing.dedup_by_key(|p| lower(p));
    if let Some(live) = live
        && !missing.is_empty()
        && !cancelled()
    {
        // Files verified recently and unchanged since (same content) come from the cache, in an
        // elevated copy only.
        let mut cache = live.cache.and_then(crate::sigcache::SigCache::open);
        if let Some(cache) = cache.as_mut() {
            let hits = cache.get_many(&missing);
            let mut still = Vec::with_capacity(missing.len());
            for (path, hit) in missing.into_iter().zip(hits) {
                match hit {
                    Some(info) => {
                        files.insert(lower(&path), info);
                    }
                    None => still.push(path),
                }
            }
            missing = still;
        }
        if !missing.is_empty() {
            say(&tr!("  verifying the digital signature of {0} files...", missing.len()));
        }
        let own_dir;
        let workdir = match live.workdir {
            Some(dir) => Some(dir.to_path_buf()),
            None => {
                own_dir = crate::collect::WorkDir::create().ok();
                own_dir.as_ref().map(|d| d.path().to_path_buf())
            }
        };
        match workdir {
            _ if missing.is_empty() => {}
            Some(dir) => match crate::collect::collect_signatures(&missing, &dir, live.cancel) {
                Ok(found) => {
                    if let Some(cache) = cache.as_mut() {
                        cache.put_many(found.values());
                    }
                    files.extend(found);
                }
                Err(error) => push_note(raw, "signatures", &tr!("could not be verified: {0}", error)),
            },
            None => push_note(raw, "signatures", &tr!("could not be verified: no temporary folder")),
        }
        if let Some(cache) = cache
            && !live.cancel.load(Ordering::Relaxed)
        {
            cache.save();
        }
        files = in_path_order(files);
    }
    if let Some(map) = raw.as_object_mut() {
        map.insert("files".into(), Value::Object(files.clone()));
    }
    lap("analysis_signatures", &mut phases);

    let mut items = analyze::evaluate_entities(raw, refs, &files);
    items.extend(posture::program_items(raw));
    items.extend(posture::extension_items(raw));
    items.extend(posture::event_items(raw));
    let (config, state) = posture::config_items(raw, &aux);
    items.extend(config);
    lap("analysis_rules", &mut phases);

    let mut vt_note = None;
    if let Some(live) = live
        && !cancelled()
    {
        let hashed = analyze::add_hashes(&mut items);
        say(&tr!(
            "  SHA-256 hash computed for {0} unsigned or flagged files",
            hashed
        ));
        if let Some(key) = live.vt_key.filter(|k| !k.is_empty()) {
            say(&tr!(
                "  querying VirusTotal (hashes only; 4 lookups per minute with a free key)..."
            ));
            let (checked, note) = vt::enrich_with(
                &mut items,
                key,
                live.vt_limit,
                15.5,
                vt::API_BASE,
                live.progress,
                live.cancel,
            );
            vt_note = note;
            say(&tr!("  VirusTotal: {0} files looked up", checked));
        }
    }
    lap("analysis_hashes", &mut phases);

    for item in items.iter_mut() {
        local_verdict(item);
    }
    items.sort_by_cached_key(|i| (i.trusted, -i.score, i.kind.clone(), lower(&i.title)));
    assign_ids(&mut items);
    for item in items.iter_mut() {
        if !item.trusted {
            item.remediation = build_remediation(item);
        }
    }

    lap("analysis_finish", &mut phases);
    if live.is_some()
        && let Some(Value::Object(timings)) = raw.get_mut("meta").and_then(|m| m.get_mut("timings"))
    {
        for (name, seconds) in phases {
            timings.insert(name.to_string(), json!((seconds * 10.0).round() / 10.0));
        }
    }
    let meta = obj(raw.at("meta")).clone();
    let mut notes: Vec<Value> = list(raw.at("notes")).to_vec();
    if !truthy(meta.at("is_admin")) {
        // The event collector reports the same thing with this prefix; keep a single, fuller note.
        notes.retain(|n| {
            !n.get("message")
                .map(str_of)
                .unwrap_or_default()
                .starts_with("Security log:")
        });
        notes.insert(
            0,
            json!({"area": "coverage", "message":
                tr!("The scan ran without administrator privileges: the Security event log (logons, created accounts), the Defender exclusions and the command lines of system processes could not be read. Run it as administrator for full coverage.")}),
        );
    }
    if aux.unresolved_com != 0 {
        notes.push(json!({"area": "tasks", "message":
            tr!("{0} Microsoft tasks use COM objects whose file could not be resolved.", aux.unresolved_com)}));
    }
    if let Some(note) = vt_note {
        notes.push(json!({"area": "VirusTotal", "message": note}));
    }

    let pending: Vec<&Item> = items.iter().filter(|i| !i.trusted).collect();
    let mut by_level = Map::new();
    let mut by_kind = Map::new();
    for item in &pending {
        bump(&mut by_level, item.level());
        bump(&mut by_kind, &item.kind);
    }
    let count = |key: &str| json!(list(raw.at(key)).len());
    let stats: Map<String, Value> = [
        ("processes", count("processes")),
        ("services", count("services")),
        ("drivers", count("drivers")),
        ("tasks", count("tasks")),
        ("autoruns", count("autoruns")),
        ("programs", count("programs")),
        ("extensions", count("extensions")),
        ("files_verified", json!(files.len())),
        ("elements", json!(items.len())),
        ("auto_trusted", json!(items.len() - pending.len())),
        ("to_analyze", json!(pending.len())),
        ("by_level", Value::Object(by_level)),
        ("by_kind", Value::Object(by_kind)),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    Analysis {
        meta,
        items,
        posture: state,
        notes,
        stats,
        summary: None,
        ai: Map::new(),
        changes: None,
    }
}

/// The verified files ordered by path: results come from the cache and from several collectors
/// finishing in any order, and the inventory must read the same whatever that order was.
fn in_path_order(files: Files) -> Files {
    let mut entries: Vec<(String, Value)> = files.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries.into_iter().collect()
}

fn bump(counter: &mut Map<String, Value>, key: &str) {
    let n = counter.get(key).and_then(Value::as_u64).unwrap_or(0);
    counter.insert(key.to_string(), json!(n + 1));
}

fn push_note(raw: &mut Value, area: &str, message: &str) {
    if let Some(map) = raw.as_object_mut() {
        let notes = map.entry("notes").or_insert_with(|| json!([]));
        if !notes.is_array() {
            *notes = json!([]);
        }
        if let Some(list) = notes.as_array_mut() {
            list.push(json!({"area": area, "message": message}));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_files_read_the_same_whatever_order_they_arrived_in() {
        let entry = |path: &str| {
            (
                lower(path),
                json!({"path": path, "exists": true, "sig_status": "Valid"}),
            )
        };
        let paths = [r"C:\b.exe", r"C:\a.dll", r"D:\z\c.sys", r"C:\Windows\x.exe"];
        let forward: Files = paths.iter().map(|p| entry(p)).collect();
        let backward: Files = paths.iter().rev().map(|p| entry(p)).collect();
        // Cache hits first, then the collectors' results, in another split.
        let mixed: Files = [paths[2], paths[0], paths[3], paths[1]]
            .iter()
            .map(|p| entry(p))
            .collect();
        let a = serde_json::to_string(&in_path_order(forward)).expect("json");
        assert_eq!(a, serde_json::to_string(&in_path_order(backward)).expect("json"));
        assert_eq!(a, serde_json::to_string(&in_path_order(mixed)).expect("json"));
        assert!(a.find("a.dll").expect("a") < a.find("b.exe").expect("b"));
    }
}
