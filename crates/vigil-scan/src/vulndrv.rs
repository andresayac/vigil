//! Drivers on Microsoft's vulnerable driver blocklist, and drivers code integrity blocked.
//!
//! READ-ONLY: the data comes from `vigil_sys::drvblock`, which reads the blocklist Windows keeps
//! (`System32\CodeIntegrity\driversipolicy.p7b`) offline, hashes the driver files the service
//! database names (Authenticode, as code integrity does) and reads the code integrity log.
//!
//! The list is used only when its signature chains, offline, to one of Microsoft's product roots.
//! A list that is not signed by Microsoft (or cannot be verified) never accuses a driver: it is
//! reported as a coverage note and a configuration item instead.
//!
//! How it is judged:
//! - a registered driver whose file the list names gets the `vulnerable_driver` flag on its file
//!   item, so it is offered the usual "disable the driver" action (with undo); by hash it is
//!   certain, by original file name it is likely (only rules that deny every version count);
//! - a driver seen loaded without a service entry becomes its own config item;
//! - drivers Windows refused to load are reported once, as information: the protection worked.

use std::collections::HashMap;

use serde_json::{Map, Value, json};
use vigil_i18n::tr;

use crate::lenient::{Get, list, lower, text};
use crate::model::{Flag, Item};

pub(crate) const SECTION: &str = "vulnerable_drivers";
pub(crate) const FLAG: &str = "vulnerable_driver";

/// The blocklist check of this computer's drivers, with coverage notes.
#[cfg(windows)]
pub(crate) fn collect(days: u32) -> Value {
    let report = vigil_sys::drvblock::scan(days);
    let mut value = serde_json::to_value(&report).unwrap_or_else(|_| json!({}));
    let mut notes: Vec<Value> = Vec::new();
    let area = tr!("vulnerable drivers");
    if report.policy.is_none() {
        let message = if report.policy_error == "missing" {
            tr!("Windows keeps no vulnerable driver blocklist on this computer")
        } else {
            tr!(
                "the vulnerable driver blocklist could not be read: {0}",
                report.policy_error
            )
        };
        notes.push(json!({"area": area, "message": message}));
    } else if report.policy.as_ref().is_some_and(|p| !p.used) {
        notes.push(json!({
            "area": area,
            "message": tr!(
                "Windows' vulnerable driver list on this computer is not signed by Microsoft, or its signature could not be verified offline, so Vigil did not use it"
            ),
        }));
    } else if report.unreadable > 0 {
        notes.push(json!({
            "area": area,
            "message": tr!("{0} driver files could not be read and were not checked", report.unreadable),
        }));
    }
    if let Some(map) = value.as_object_mut() {
        map.insert("notes".into(), Value::Array(notes));
    }
    value
}

#[cfg(not(windows))]
pub(crate) fn collect(_days: u32) -> Value {
    json!({})
}

/// Whether the section's list may accuse drivers: not when the scan says it did not use it
/// (its signature is not Microsoft's). Reports from before that field existed count as used.
fn list_used(section: &Value) -> bool {
    section.at("policy").at("used").as_bool() != Some(false)
}

/// The matches by lower-case file path (for the file items' flag).
pub(crate) fn matches_by_path(raw: &Value) -> HashMap<String, Value> {
    let section = raw.at("sysconfig").at(SECTION);
    if !list_used(section) {
        return HashMap::new();
    }
    list(section.at("matches"))
        .iter()
        .map(|m| (lower(&text(m.at("path"))), m.clone()))
        .filter(|(path, _)| !path.is_empty())
        .collect()
}

/// Whether a match is running now or starts with Windows (then it is critical).
fn active(m: &Value) -> bool {
    m.at("loaded").as_bool() == Some(true) || matches!(lower(&text(m.at("start"))).as_str(), "boot" | "system" | "auto")
}

/// The flag for a driver file the blocklist names.
pub(crate) fn flag(m: &Value) -> Flag {
    let by_hash = text(m.at("rule")) == "hash";
    let weight = match (by_hash, active(m)) {
        (true, true) => 90,
        (true, false) => 50,
        (false, true) => 60,
        (false, false) => 30,
    };
    let message = if by_hash {
        tr!("on Microsoft's list of vulnerable drivers: attackers load this exact file to switch off security software")
    } else {
        tr!("its original file name is on Microsoft's list of vulnerable drivers for every version of it")
    };
    Flag::new(FLAG, weight, message)
}

fn facts(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn item(topic: &str, title: String, score: i64, summary: String, facts: Map<String, Value>) -> Item {
    let mut item = Item::new("config", title, summary.clone());
    let mut all = Map::new();
    all.insert("topic".into(), json!(topic));
    all.extend(facts);
    item.facts = all;
    item.add_flag(Flag::new(topic, score, summary));
    item.rescore();
    item
}

/// Config items: loaded drivers on the list that no service names, and drivers Windows blocked.
pub(crate) fn items(raw: &Value) -> Vec<Item> {
    let section = raw.at("sysconfig").at(SECTION);
    if section.as_object().is_none_or(|m| m.is_empty()) {
        return Vec::new();
    }
    let mut out = Vec::new();
    // A list Vigil did not use because its signature is not Microsoft's (or not verifiable).
    let policy = section.at("policy");
    if policy.at("used").as_bool() == Some(false) {
        let state = text(policy.at("signature").at("state"));
        let reason = text(policy.at("signature").at("reason"));
        // A signature that does not verify at all points to a replaced file; one that verifies but
        // cannot be traced to Microsoft offline is only a coverage gap.
        let score = if state == "invalid" { 40 } else { 10 };
        out.push(item(
            "vulnerable_driver_list_unverified",
            tr!("Windows' vulnerable driver list could not be verified"),
            score,
            tr!(
                "Windows' vulnerable driver list on this computer is not signed by Microsoft, or its signature could not be verified offline ({0}), so Vigil did not use it to judge drivers. If Windows Security shows the vulnerable driver blocklist as on, Windows itself still applies its own copy; a list file that does not verify may have been replaced.",
                if reason.is_empty() { state.clone() } else { reason.clone() }
            ),
            facts(vec![
                ("path", policy.at("path").clone()),
                ("signature", json!(state)),
                ("reason", json!(reason)),
            ]),
        ));
    }
    let matches = if list_used(section) {
        list(section.at("matches"))
    } else {
        &[]
    };
    for m in matches {
        // A registered driver is judged on its own file item (with its actions).
        if !text(m.at("service")).is_empty() {
            continue;
        }
        let path = text(m.at("path"));
        let found = flag(m);
        out.push(item(
            "vulnerable_driver_loaded",
            tr!("Vulnerable driver loaded: {0}", path),
            found.weight,
            tr!(
                "{0} is loaded but no driver service names it, and it is on Microsoft's list of drivers that attackers load to switch off security software. A program loaded it directly; find it and uninstall it, then restart.",
                path
            ),
            facts(vec![
                ("path", json!(path)),
                ("rule", m.at("rule").clone()),
                ("sha256", m.at("sha256").clone()),
            ]),
        ));
    }
    let events = list(section.at("events"));
    let blocked: Vec<&Value> = events
        .iter()
        .filter(|e| e.at("audit").as_bool() != Some(true))
        .collect();
    if !blocked.is_empty() {
        let files: Vec<String> = blocked.iter().take(5).map(|e| text(e.at("file"))).collect();
        out.push(item(
            "vulnerable_driver_blocked",
            tr!("Windows blocked {0} drivers from loading", blocked.len()),
            0,
            tr!(
                "Code integrity refused to load drivers its policies block, such as the vulnerable driver blocklist: the protection worked. Something tried to load them; the program that installed them may still be on the computer. Last ones: {0}",
                files.join("; ")
            ),
            facts(vec![("files", json!(files)), ("count", json!(blocked.len()))]),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(matches: Value, events: Value) -> Value {
        json!({"sysconfig": {SECTION: {
            "policy": {"version": "10.0.1.0"},
            "matches": matches,
            "events": events,
        }}})
    }

    #[test]
    fn severity_follows_the_rule_and_whether_it_runs() {
        vigil_i18n::with_language("en", || {
            let weight = |rule: &str, start: &str, loaded: Value| {
                flag(&json!({"rule": rule, "start": start, "loaded": loaded})).weight
            };
            assert_eq!(weight("hash", "system", Value::Null), 90);
            assert_eq!(weight("hash", "demand", json!(true)), 90);
            assert_eq!(weight("hash", "demand", json!(false)), 50);
            assert_eq!(weight("hash", "disabled", Value::Null), 50);
            assert_eq!(weight("name", "auto", Value::Null), 60);
            assert_eq!(weight("name", "demand", Value::Null), 30);
        });
    }

    #[test]
    fn registered_drivers_are_flagged_on_their_file_and_loaded_ones_get_an_item() {
        vigil_i18n::with_language("en", || {
            let data = raw(
                json!([
                    {"path": r"C:\Windows\System32\drivers\contoso.sys", "service": "contoso", "start": "system", "rule": "hash"},
                    {"path": r"C:\Users\jdoe\AppData\Local\Temp\fabrikam.sys", "service": "", "loaded": true, "rule": "hash"},
                ]),
                json!([]),
            );
            let by_path = matches_by_path(&data);
            assert!(by_path.contains_key(r"c:\windows\system32\drivers\contoso.sys"));
            let found = items(&data);
            assert_eq!(found.len(), 1);
            assert_eq!(text(found[0].facts.at("topic")), "vulnerable_driver_loaded");
            assert!(found[0].score >= 70, "{}", found[0].score);
        });
    }

    #[test]
    fn a_list_vigil_did_not_use_accuses_nothing_and_is_reported() {
        vigil_i18n::with_language("en", || {
            let mut data = raw(
                json!([
                    {"path": r"C:\Program Files\Contoso\agent.sys", "service": "contoso", "start": "boot", "rule": "name"},
                    {"path": r"C:\Users\jdoe\fabrikam.sys", "service": "", "loaded": true, "rule": "hash"},
                ]),
                json!([]),
            );
            data["sysconfig"][SECTION]["policy"] = json!({
                "path": r"C:\Windows\System32\CodeIntegrity\driversipolicy.p7b",
                "used": false,
                "signature": {"state": "intact", "reason": "the certificate chain does not end at a Microsoft product root"},
            });
            assert!(matches_by_path(&data).is_empty(), "no flag from an unverified list");
            let found = items(&data);
            assert_eq!(found.len(), 1);
            assert_eq!(text(found[0].facts.at("topic")), "vulnerable_driver_list_unverified");
            assert_eq!(found[0].score, 10);
            data["sysconfig"][SECTION]["policy"]["signature"]["state"] = json!("invalid");
            assert_eq!(
                items(&data)[0].score,
                40,
                "a list whose signature fails stands out more"
            );
        });
    }

    #[test]
    fn blocked_drivers_are_information() {
        vigil_i18n::with_language("en", || {
            let data = raw(
                json!([]),
                json!([
                    {"event_id": 3077, "file": r"\Device\HarddiskVolume3\Users\jdoe\Downloads\RTCore64.sys", "audit": false},
                    {"event_id": 3076, "file": r"\Device\HarddiskVolume3\Temp\gdrv.sys", "audit": true},
                ]),
            );
            let found = items(&data);
            assert_eq!(found.len(), 1);
            assert_eq!(text(found[0].facts.at("topic")), "vulnerable_driver_blocked");
            assert_eq!(found[0].score, 0);
            assert_eq!(found[0].facts.at("count").as_u64(), Some(1));
            assert!(items(&json!({})).is_empty());
        });
    }
}
