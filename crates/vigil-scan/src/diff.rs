//! What changed since the previous scan: items that appeared, items that went away, items whose
//! verdict, risk, signature, file or ways of starting changed, and security settings that flipped.
//!
//! Items are matched by a stable identity (kind plus the lower-cased path, or the setting topic, the
//! event category or the title), so ids, scores and wording can differ between scans. The texts are
//! written in the current language; the result is stored in the report under `changes`.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Map, Value};
use vigil_i18n::{tl, tr};

use crate::lenient::{Get, list, obj, str_of, text};
use crate::model::{Analysis, Item, Role};

/// The scan the current one is compared with.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Previous {
    pub started: String,
    pub path: String,
}

/// An item of the previous scan that is no longer there.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Gone {
    pub title: String,
    pub kind: String,
    pub path: Option<String>,
    pub verdict: String,
}

/// An item present in both scans, with what changed (localized sentences).
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Changed {
    pub id: String,
    pub what: Vec<String>,
}

/// The differences between two scans of the same computer.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct ScanDiff {
    pub previous: Previous,
    /// Ids (in the current scan) of items that were not there before.
    pub new: Vec<String>,
    pub gone: Vec<Gone>,
    pub changed: Vec<Changed>,
    /// Security settings that changed (localized sentences).
    pub posture: Vec<String>,
}

impl ScanDiff {
    pub fn is_empty(&self) -> bool {
        self.new.is_empty() && self.gone.is_empty() && self.changed.is_empty() && self.posture.is_empty()
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// The identity of an item across scans.
pub fn identity(item: &Item) -> String {
    let facts = |key: &str| item.facts.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    let base = match item.kind.as_str() {
        "config" if !facts("topic").is_empty() => facts("topic"),
        "event" if !facts("category").is_empty() => facts("category"),
        _ => item
            .path
            .clone()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| item.title.clone()),
    };
    format!("{}|{}", item.kind, base.to_lowercase())
}

/// Detail keys that change from one run to the next without meaning anything.
const VOLATILE: [&str; 4] = ["pids", "count", "names", "started"];

/// A role's identity: its kind and the stable part of its details. Running instances only count
/// as "running", since their process ids change every time.
fn role_identity(role: &Role) -> String {
    if role.kind == "process" {
        return "process".into();
    }
    let stable: BTreeMap<&String, &Value> = role
        .detail
        .iter()
        .filter(|(k, _)| !VOLATILE.contains(&k.as_str()))
        .collect();
    format!(
        "{}|{}",
        role.kind,
        serde_json::to_string(&stable).unwrap_or_default().to_lowercase()
    )
}

fn verdict_name(verdict: &str) -> String {
    let template = match verdict {
        "remove" => tl!("Remove"),
        "disable" => tl!("Disable"),
        "review" => tl!("Review"),
        "no_signals" => tl!("No signals"),
        "safe" => tl!("Safe"),
        "trusted" => tl!("Trusted"),
        other => return other.to_string(),
    };
    tr!(template)
}

fn level_name(level: &str) -> String {
    let template = match level {
        "critical" => tl!("critical"),
        "suspicious" => tl!("suspicious"),
        "attention" => tl!("attention"),
        "no_signals" => tl!("no signals"),
        _ => tl!("trusted"),
    };
    tr!(template)
}

/// The Authenticode status in words (unknown statuses are shown as they are).
fn signature_name(status: &str) -> String {
    let template = match status {
        "Valid" => tl!("Valid"),
        "NotSigned" => tl!("Not signed"),
        "HashMismatch" => tl!("Modified after signing"),
        "NotTrusted" => tl!("Untrusted certificate"),
        "UnknownError" => tl!("Unknown"),
        other => return other.to_string(),
    };
    tr!(template)
}

fn file_text(item: &Item, key: &str) -> String {
    item.file
        .as_ref()
        .and_then(|f| f.get(key))
        .map(str_of)
        .unwrap_or_default()
}

fn endpoints(item: &Item) -> BTreeSet<String> {
    ["listen", "remote"]
        .iter()
        .flat_map(|key| list(item.network.at(key)).iter().map(str_of).collect::<Vec<_>>())
        .filter(|e| !e.is_empty())
        .collect()
}

/// What changed in one item (empty when nothing that matters did).
fn item_changes(before: &Item, after: &Item) -> Vec<String> {
    let mut what = Vec::new();
    if !before.verdict.is_empty() && !after.verdict.is_empty() && before.verdict != after.verdict {
        what.push(tr!(
            "Verdict: {0} → {1}",
            verdict_name(&before.verdict),
            verdict_name(&after.verdict)
        ));
    }
    if before.level() != after.level() {
        what.push(tr!(
            "Risk level: {0} → {1}",
            level_name(before.level()),
            level_name(after.level())
        ));
    }
    let (sig_before, sig_after) = (file_text(before, "sig_status"), file_text(after, "sig_status"));
    if !sig_before.is_empty() && !sig_after.is_empty() && sig_before != sig_after {
        what.push(tr!(
            "Signature: {0} → {1}",
            signature_name(&sig_before),
            signature_name(&sig_after)
        ));
    }
    let (signer_before, signer_after) = (file_text(before, "signer"), file_text(after, "signer"));
    if !signer_before.is_empty() && !signer_after.is_empty() && signer_before != signer_after {
        what.push(tr!("Signer: {0} → {1}", signer_before, signer_after));
    }
    if let (Some(a), Some(b)) = (&before.sha256, &after.sha256)
        && !a.is_empty()
        && !b.is_empty()
        && !a.eq_ignore_ascii_case(b)
    {
        what.push(tr!("The file's contents changed (new SHA-256)."));
    }
    let roles_before: BTreeMap<String, &Role> = before.roles.iter().map(|r| (role_identity(r), r)).collect();
    let roles_after: BTreeMap<String, &Role> = after.roles.iter().map(|r| (role_identity(r), r)).collect();
    for (key, role) in &roles_after {
        if !roles_before.contains_key(key) {
            what.push(if role.kind == "process" {
                tr!("It is running now.")
            } else {
                tr!("New: {0}", role.label)
            });
        }
    }
    for (key, role) in &roles_before {
        if !roles_after.contains_key(key) {
            what.push(if role.kind == "process" {
                tr!("It is no longer running.")
            } else {
                tr!("No longer: {0}", role.label)
            });
        }
    }
    let new_endpoints: Vec<String> = endpoints(after).difference(&endpoints(before)).cloned().collect();
    if !new_endpoints.is_empty() {
        what.push(tr!("New network activity: {0}", new_endpoints.join(", ")));
    }
    what
}

fn on_off(value: bool) -> String {
    if value { tr!("on") } else { tr!("off") }
}

fn strings(value: &Value) -> BTreeSet<String> {
    list(value).iter().map(str_of).filter(|s| !s.is_empty()).collect()
}

/// Security settings that changed between the two postures.
fn posture_changes(before: &Map<String, Value>, after: &Map<String, Value>) -> Vec<String> {
    let mut out = Vec::new();
    let realtime = |p: &Map<String, Value>| p.at("defender").at("realtime_protection").as_bool();
    if let (Some(a), Some(b)) = (realtime(before), realtime(after))
        && a != b
    {
        out.push(tr!(
            "Microsoft Defender real-time protection: {0} → {1}",
            on_off(a),
            on_off(b)
        ));
    }
    let firewall_before = obj(before.at("firewall"));
    for (profile, state) in obj(after.at("firewall")) {
        if let (Some(a), Some(b)) = (firewall_before.get(profile).and_then(Value::as_bool), state.as_bool())
            && a != b
        {
            out.push(tr!("Firewall ({0} profile): {1} → {2}", profile, on_off(a), on_off(b)));
        }
    }
    for (key, template) in [
        ("uac", tl!("User Account Control: {0} → {1}")),
        ("remote_desktop", tl!("Remote Desktop: {0} → {1}")),
    ] {
        let (a, b) = (text(before.at(key)), text(after.at(key)));
        if !a.is_empty() && !b.is_empty() && a != b {
            out.push(tr!(template, a, b));
        }
    }
    let exclusions = |p: &Map<String, Value>| -> BTreeSet<String> {
        obj(p.at("defender_exclusions"))
            .values()
            .flat_map(|v| strings(v).into_iter())
            .collect()
    };
    for added in exclusions(after).difference(&exclusions(before)) {
        out.push(tr!("New Microsoft Defender exclusion: {0}", added));
    }
    let (admins_before, admins_after) = (
        strings(before.at("administrators")),
        strings(after.at("administrators")),
    );
    for added in admins_after.difference(&admins_before) {
        out.push(tr!("New administrator account: {0}", added));
    }
    for removed in admins_before.difference(&admins_after) {
        out.push(tr!("No longer an administrator: {0}", removed));
    }
    let (accounts_before, accounts_after) = (
        strings(before.at("local_accounts")),
        strings(after.at("local_accounts")),
    );
    for added in accounts_after.difference(&accounts_before) {
        out.push(tr!("New local account: {0}", added));
    }
    out
}

/// Compares the current analysis with the previous one (`previous_path` is where it was read).
pub fn diff(previous: &Analysis, previous_path: &str, current: &Analysis) -> ScanDiff {
    let before: BTreeMap<String, &Item> = previous.items.iter().map(|i| (identity(i), i)).collect();
    let after: BTreeMap<String, &Item> = current.items.iter().map(|i| (identity(i), i)).collect();
    let mut result = ScanDiff {
        previous: Previous {
            started: text(previous.meta.at("started")),
            path: previous_path.to_string(),
        },
        ..ScanDiff::default()
    };
    for item in &current.items {
        match before.get(&identity(item)) {
            None => result.new.push(item.id.clone()),
            Some(old) => {
                let what = item_changes(old, item);
                if !what.is_empty() {
                    result.changed.push(Changed {
                        id: item.id.clone(),
                        what,
                    });
                }
            }
        }
    }
    for item in &previous.items {
        if !after.contains_key(&identity(item)) {
            result.gone.push(Gone {
                title: item.title.clone(),
                kind: item.kind.clone(),
                path: item.path.clone(),
                verdict: item.verdict.clone(),
            });
        }
    }
    result.posture = posture_changes(&previous.posture, &current.posture);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reference() -> Analysis {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/fixture-analysis.json");
        let text = std::fs::read_to_string(path).unwrap_or_default();
        Analysis::from_value(&serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    #[test]
    fn identical_scans_have_no_changes() {
        let a = reference();
        let d = diff(&a, "previous.json", &a);
        assert!(d.is_empty(), "{d:?}");
        assert_eq!(d.previous.path, "previous.json");
        assert!(!d.previous.started.is_empty());
    }

    #[test]
    fn new_gone_changed_and_posture_are_found() {
        vigil_i18n::with_language("en", || {
            let before = reference();
            let mut after = before.clone();
            // A new startup entry for an existing file, and a signature that changed.
            let b1 = after.items.iter_mut().find(|i| i.id == "B1").expect("B1");
            let mut detail = Map::new();
            detail.insert("source".into(), json!("run"));
            detail.insert(
                "reg_key".into(),
                json!(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"),
            );
            detail.insert("value".into(), json!("Helper2"));
            b1.roles.push(Role::new("startup", "startup entry \"Helper2\"", detail));
            if let Some(file) = b1.file.as_mut() {
                file.insert("sig_status".into(), json!("HashMismatch"));
            }
            // One item removed, one item added.
            let removed = after.items.iter().position(|i| i.id == "B2").expect("B2");
            let gone = after.items.remove(removed);
            let mut fresh = Item::new("executable", "dropper.exe", "");
            fresh.id = "B9".into();
            fresh.path = Some(r"C:\Users\jdoe\AppData\Local\Temp\dropper.exe".into());
            after.items.push(fresh);
            // The firewall comes back on for the public profile.
            after.posture.insert("firewall".into(), json!({"Public": true}));

            let d = diff(&before, "old-report.json", &after);
            assert_eq!(d.new, vec!["B9".to_string()]);
            assert_eq!(d.gone.len(), 1);
            assert_eq!(d.gone[0].title, gone.title);
            let changed = d.changed.iter().find(|c| c.id == "B1").expect("B1 changed");
            assert!(
                changed
                    .what
                    .iter()
                    .any(|w| w.contains("Not signed → Modified after signing")),
                "{changed:?}"
            );
            assert!(
                changed.what.iter().any(|w| w.starts_with("New: startup entry")),
                "{changed:?}"
            );
            assert!(
                d.posture.iter().any(|p| p.contains("Public") && p.contains("off → on")),
                "{:?}",
                d.posture
            );
        });
    }

    #[test]
    fn running_instances_and_ids_do_not_count_as_changes() {
        let before = reference();
        let mut after = before.clone();
        for item in &mut after.items {
            item.id = format!("{}x", item.id);
            for role in &mut item.roles {
                role.detail.insert("pids".into(), json!([4242]));
            }
        }
        let d = diff(&before, "p", &after);
        assert!(d.new.is_empty() && d.gone.is_empty() && d.changed.is_empty(), "{d:?}");
    }

    #[test]
    fn changes_travel_with_the_report_and_render_escaped() {
        let before = reference();
        let mut after = before.clone();
        let mut fresh = Item::new("executable", "<script>alert(1)</script>.exe", "");
        fresh.id = "B9".into();
        fresh.path = Some(r"C:\Users\jdoe\x.exe".into());
        after.items.push(fresh);
        after.changes = Some(diff(&before, "p", &after).to_value());
        let round = Analysis::from_value(&after.to_value());
        assert_eq!(round.changes, after.changes);
        assert!(before.to_value().get("changes").is_none(), "no key for a first scan");
        let html = vigil_i18n::with_language("en", || crate::report::render_html(&after));
        assert!(html.contains("Changes since the last scan"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;.exe"));
        assert!(!html.contains("<script>alert(1)"));
    }

    #[test]
    fn the_previous_report_in_the_folder_is_found() {
        let dir = std::env::temp_dir().join(format!("vigil-diff-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).ok();
        let before = reference();
        let old_base = dir.join("scan-20260101-100000");
        crate::pipeline::save_report(&before, &old_base, false).expect("save");
        std::fs::write(dir.join("scan-20260101-110000-report.json"), "not json").ok();
        let mut current = before.clone();
        current.posture.insert("remote_desktop".into(), json!("disabled"));
        let found = crate::pipeline::attach_changes(&mut current, &dir.join("scan-20260102-090000")).expect("previous");
        assert!(
            found.previous.path.ends_with("scan-20260101-100000-report.json"),
            "{}",
            found.previous.path
        );
        assert!(current.changes.is_some());
        let mut first = before.clone();
        assert!(crate::pipeline::attach_changes(&mut first, &dir.join("scan-20250101-000000")).is_none());
        assert!(first.changes.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn texts_follow_the_language() {
        let before = reference();
        let mut after = before.clone();
        after.posture.insert("uac".into(), json!("ENABLED"));
        let d = vigil_i18n::with_language("es", || diff(&before, "p", &after));
        assert!(
            d.posture.iter().any(|p| p.contains("DISABLED → ENABLED")),
            "{:?}",
            d.posture
        );
        assert!(!d.posture[0].starts_with("User Account Control"), "{:?}", d.posture);
    }
}
