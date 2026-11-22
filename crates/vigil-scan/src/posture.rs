//! Items that are not executables: programs, extensions, events and security configuration.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{Local, NaiveDate, NaiveDateTime};
use serde_json::{Map, Value, json};

use crate::analyze::Aux;
use crate::cmdline::parse_command;
use crate::ip;
use crate::lenient::{
    Get, Rx, as_int, as_integral, as_number, eq_num, int_of, is_false, list, literal_of, lower, max_of, obj, or_empty,
    rx, str_of, strip, take, text, truthy,
};
use crate::model::{Flag, Item};
use crate::privacy::{clip, scrub_secrets};
use crate::rules::{OBSOLETE_SOFTWARE, label_flags, location_flags, scan_command, scan_text};
use vigil_i18n::{tl, tr};

fn days_since(iso: &Value) -> Option<i64> {
    let text = iso.as_str().filter(|s| !s.is_empty())?;
    let head = take(text, 19);
    let parsed = NaiveDateTime::parse_from_str(head, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(head, "%Y-%m-%d %H:%M:%S"))
        .or_else(|_| NaiveDateTime::parse_from_str(head, "%Y-%m-%dT%H:%M"))
        .or_else(|_| NaiveDateTime::parse_from_str(head, "%Y-%m-%d %H:%M"))
        .ok()
        .or_else(|| {
            NaiveDate::parse_from_str(head, "%Y-%m-%d")
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
        })?;
    let seconds = (Local::now().naive_local() - parsed).num_seconds();
    Some(seconds.div_euclid(86_400))
}

/// A count with its noun in the right number: "1 time", "3 times".
/// "1 time" / "3 times": both forms are whole templates (`tl!`), so each language places the number.
fn count(number: &Value, one: &'static str, many: &'static str) -> String {
    let n = str_of(number);
    if eq_num(number, 1.0) { tr!(one, n) } else { tr!(many, n) }
}

fn count_n(number: usize, one: &'static str, many: &'static str) -> String {
    count(&json!(number), one, many)
}

fn finish(mut item: Item, flags: Vec<Flag>) -> Item {
    for flag in flags {
        item.add_flag(flag);
    }
    item.rescore();
    item
}

fn config(
    topic: &str,
    title: impl AsRef<str>,
    score: i64,
    text: impl AsRef<str>,
    detail: Option<&Map<String, Value>>,
    extra: Vec<Flag>,
) -> Item {
    let mut facts = Map::new();
    facts.insert("topic".into(), json!(topic));
    if let Some(detail) = detail {
        for (k, v) in detail {
            facts.insert(k.clone(), v.clone());
        }
    }
    let (title, text) = (title.as_ref(), text.as_ref());
    let mut item = Item::new("config", title, text);
    item.facts = facts;
    let mut flags = vec![Flag::new(topic, score, text)];
    flags.extend(extra);
    finish(item, flags)
}

fn facts(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn sorted_strings<'a>(values: impl IntoIterator<Item = &'a Value>) -> Vec<String> {
    values
        .into_iter()
        .map(str_of)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

// --------------------------------------------------------------------------- programs

rx!(CN_RE, r"CN=([^,]+)");

pub(crate) fn program_items(raw: &Value) -> Vec<Item> {
    let mut items = Vec::new();
    for prog in list(raw.at("programs")) {
        if truthy(prog.at("hidden")) {
            continue; // installer subcomponents (they do not appear in "Installed apps")
        }
        let name = text(prog.at("name"));
        let publisher = text(prog.at("publisher"));
        let version = text(prog.at("version"));
        let mut flags = label_flags(&[&name, &publisher]);
        if OBSOLETE_SOFTWARE.is_match(&name) {
            flags.push(Flag::new(
                "outdated_software",
                25,
                tr!("unsupported software or software with known security flaws"),
            ));
        }
        let installed = text(prog.at("installed"));
        let version_text = if version.is_empty() {
            String::new()
        } else {
            format!("v{version}")
        };
        let subtitle = [publisher.as_str(), version_text.as_str(), installed.as_str()]
            .into_iter()
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
            .join(" · ");
        let mut item = Item::new("program", name, subtitle);
        let uninstall = scrub_secrets(&text(prog.at("uninstall")));
        item.facts = facts(vec![
            ("publisher", or_empty(prog.at("publisher"))),
            ("version", or_empty(prog.at("version"))),
            ("installed", prog.at("installed").clone()),
            ("folder", prog.at("location").clone()),
            ("scope", prog.at("scope").clone()),
            ("origin", json!(tr!("classic installer"))),
            ("uninstall", json!(uninstall)),
            ("registry_key", prog.at("key").clone()),
        ]);
        let no_flags = flags.is_empty();
        let mut item = finish(item, flags);
        if no_flags && lower(&publisher).starts_with("microsoft") {
            item.trusted = true;
            item.what = tr!("Microsoft program");
        }
        items.push(item);
    }

    for app in list(raw.at("system").at("appx")) {
        let name = text(app.at("name"));
        let publisher_raw = text(app.at("publisher"));
        let publisher = CN_RE
            .captures(&publisher_raw)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            .unwrap_or_else(|| publisher_raw.clone());
        let kind = text(app.at("kind"));
        let origin = match kind.as_str() {
            "Store" => tr!("Microsoft Store"),
            "Developer" => tr!("MSIX package installed outside the Store"),
            "Enterprise" => tr!("enterprise package"),
            "None" => tr!("unsigned package"),
            "" => "package".to_string(),
            other => other.to_string(),
        };
        let mut flags = label_flags(&[&name]);
        if kind == "None" {
            flags.push(Flag::new(
                "unsigned_package",
                30,
                tr!("packaged app without a signature (developer mode)"),
            ));
        }
        let mut item = Item::new(
            "program",
            name,
            format!("{publisher} · v{} · {origin}", str_of(app.at("version"))),
        );
        item.facts = facts(vec![
            ("publisher", json!(publisher)),
            ("version", app.at("version").clone()),
            ("folder", app.at("location").clone()),
            ("origin", json!(origin)),
        ]);
        items.push(finish(item, flags));
    }
    items
}

// --------------------------------------------------------------------------- extensions

const BROAD_HOSTS: &[&str] = &["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/"];
const RISKY_PERMISSIONS: &[&str] = &["proxy", "debugger", "nativeMessaging", "management"];
// Update URLs of the official stores (Edge and Opera do not count as the Chrome "webstore").
rx!(
    STORE_UPDATE,
    r"(?i)clients2\.google\.com|edge\.microsoft\.com/extensionwebstorebase|extension-updates\.opera\.com|addons\.opera\.com|update\.vivaldi\.com"
);

pub(crate) fn extension_items(raw: &Value) -> Vec<Item> {
    // (browser, id) -> merged entry, in order of first appearance.
    type Merged = ((String, String), Map<String, Value>, Vec<Value>);
    let mut merged: Vec<Merged> = Vec::new();
    for ext in list(raw.at("extensions")) {
        let key = (text(ext.at("browser")), text(ext.at("id")));
        let position = match merged.iter().position(|(k, _, _)| *k == key) {
            Some(p) => p,
            None => {
                let mut entry = obj(ext).clone();
                entry.insert("profiles".into(), json!([]));
                merged.push((key, entry, Vec::new()));
                merged.len() - 1
            }
        };
        let (_, entry, profiles) = &mut merged[position];
        profiles.push(ext.at("profile").clone());
        let enabled = truthy(entry.at("enabled")) || truthy(ext.at("enabled"));
        entry.insert("enabled".into(), json!(enabled));
    }

    let mut items = Vec::new();
    for ((browser, ext_id), ext, profiles) in merged {
        let name = {
            let n = text(ext.at("name"));
            if n.is_empty() { ext_id.clone() } else { n }
        };
        let origin = text(ext.at("origin"));
        let permissions = if truthy(ext.at("permissions")) {
            ext.at("permissions").clone()
        } else {
            json!([])
        };
        let hosts = if truthy(ext.at("hosts")) {
            ext.at("hosts").clone()
        } else {
            json!([])
        };
        let enabled = truthy(ext.at("enabled"));
        let from_store = truthy(ext.at("from_webstore")) || STORE_UPDATE.is_match(&text(ext.at("update_url")));
        let mut flags = label_flags(&[&name]);
        // The literals compared against `origin` are the origin labels written by the collector
        // (CHROME_LOCATIONS and the Firefox add-on reader): both sides must change together.
        if origin.starts_with("forced by policy") {
            flags.push(Flag::new(
                "forced_extension",
                30,
                tr!("force-installed by a browser policy"),
            ));
        } else if origin.starts_with("unpacked") {
            flags.push(Flag::new(
                "unpacked_extension",
                20,
                tr!("loaded unpacked (developer mode)"),
            ));
        } else if origin.starts_with("external") && !from_store {
            flags.push(Flag::new(
                "external_extension",
                20,
                tr!("installed by an external program, not by the browser store"),
            ));
        } else if origin == "not signed by Mozilla" {
            flags.push(Flag::new("unsigned_extension", 25, tr!("not signed by Mozilla")));
        } else if is_false(ext.at("from_webstore")) && !from_store {
            flags.push(Flag::new(
                "off_store_extension",
                20,
                tr!("does not come from the official browser store"),
            ));
        }
        if list(&hosts)
            .iter()
            .any(|h| h.as_str().is_some_and(|h| BROAD_HOSTS.iter().any(|b| h.starts_with(b))))
        {
            flags.push(Flag::new(
                "all_sites_access",
                10,
                tr!("can read and modify every page you visit"),
            ));
        }
        let risky: Vec<String> = list(&permissions)
            .iter()
            .filter_map(|p| p.as_str())
            .filter(|p| RISKY_PERMISSIONS.contains(p))
            .map(str::to_string)
            .collect();
        if !risky.is_empty() {
            flags.push(Flag::new(
                "high_risk_permissions",
                10,
                tr!("high-risk permissions: {0}", risky.join(", ")),
            ));
        }
        if !enabled {
            flags = flags
                .into_iter()
                .map(|f| Flag::new(f.code, f.weight.div_euclid(2), f.text))
                .collect();
        }

        // The collector's origin labels stay in English for the comparisons above; people see them translated.
        let origin = tr!(origin.as_str());
        let subtitle = format!(
            "{browser} · v{} · {origin}{}",
            str_of(ext.at("version")),
            if enabled { String::new() } else { tr!(" · disabled") }
        );
        let profiles = sorted_strings(profiles.iter().filter(|p| truthy(p)));
        let mut item = Item::new("extension", name, subtitle);
        item.facts = facts(vec![
            ("browser", json!(browser)),
            ("ext_id", json!(ext_id)),
            ("version", ext.at("version").clone()),
            ("origin", json!(origin)),
            ("active", json!(enabled)),
            ("profiles", json!(profiles)),
            ("description", ext.at("description").clone()),
            ("permissions", permissions),
            ("sites", hosts),
            ("updates_from", ext.at("update_url").clone()),
            ("folder", ext.at("path").clone()),
        ]);
        let mut item = finish(item, flags);
        if !enabled && item.score == 0 {
            item.trusted = true;
            item.what = tr!("Disabled extension with no risk signals");
        }
        items.push(item);
    }
    items
}

// --------------------------------------------------------------------------- events

fn event(title: String, subtitle: String, flags: Vec<Flag>, facts: Map<String, Value>) -> Item {
    let mut item = Item::new("event", title, subtitle);
    item.facts = facts;
    finish(item, flags)
}

fn with_fields(mut base: Map<String, Value>, extra: &Value) -> Map<String, Value> {
    for (k, v) in obj(extra) {
        base.insert(k.clone(), v.clone());
    }
    base
}

fn weight_sum(flags: &[Flag]) -> i64 {
    flags.iter().map(|f| f.weight).sum()
}

/// Stable sort by descending score, then the first `n`.
fn top(mut items: Vec<Item>, n: usize) -> Vec<Item> {
    items.sort_by_key(|i| -i.score);
    items.truncate(n);
    items
}

pub(crate) fn event_items(raw: &Value) -> Vec<Item> {
    let events = raw.at("events");
    let days = {
        let d = events.at("days");
        if truthy(d) {
            d.clone()
        } else if truthy(raw.at("meta").at("days")) {
            raw.at("meta").at("days").clone()
        } else {
            json!(30)
        }
    };
    let days = str_of(&days);
    // The event stores the display name of the service, so it is compared against both names.
    let mut current_services: BTreeSet<String> = BTreeSet::new();
    for entry in list(raw.at("services")).iter().chain(list(raw.at("drivers"))) {
        current_services.insert(lower(&text(entry.at("name"))));
        current_services.insert(lower(&text(entry.at("display"))));
    }
    let mut items = Vec::new();

    // Recently installed services (the event remains even when the service has since been deleted).
    let mut installs: Vec<(String, &Value, i64, Vec<String>)> = Vec::new();
    for ev in list(events.at("service_installs")) {
        let key = lower(&text(ev.at("service")));
        let position = match installs.iter().position(|(k, ..)| *k == key) {
            Some(p) => p,
            None => {
                installs.push((key, ev, 0, Vec::new()));
                installs.len() - 1
            }
        };
        let entry = &mut installs[position];
        entry.2 += 1;
        let image = text(ev.at("image"));
        if !image.is_empty() && !entry.3.contains(&image) {
            entry.3.push(image);
        }
    }
    let mut candidates = Vec::new();
    for (name_l, ev, n, images) in installs {
        let joined = images.join("\n");
        let service = text(ev.at("service"));
        let mut flags = scan_text(&joined);
        flags.extend(label_flags(&[&service, &joined]));
        for image in images.iter().take(3) {
            flags.extend(location_flags(parse_command(image, None).target().unwrap_or("")));
        }
        let gone = !current_services.contains(&name_l);
        if gone {
            flags.push(Flag::new(
                "ephemeral_service",
                10,
                tr!("service that was installed and no longer exists"),
            ));
        } else if !flags.iter().any(|f| f.weight != 0) {
            continue; // still installed and no signals: it is already evaluated as an executable
        }
        candidates.push(event(
            tr!("Service installed: {0}", str_of(ev.at("service"))),
            tr!(
                "installed {0} in the last {1} days",
                count_n(usize::try_from(n).unwrap_or(0), tl!("{0} time"), tl!("{0} times")),
                days
            ),
            flags,
            facts(vec![
                ("category", json!("service_installed")),
                (
                    "commands",
                    json!(
                        images
                            .iter()
                            .take(3)
                            .map(|i| clip(&scrub_secrets(i), 500))
                            .collect::<Vec<_>>()
                    ),
                ),
                ("account", ev.at("account").clone()),
                ("last_seen", ev.at("time").clone()),
                ("times", json!(n)),
                ("still_installed", json!(!gone)),
            ]),
        ));
    }
    items.extend(top(candidates, 15));

    let cleared = list(events.at("log_cleared"));
    if !cleared.is_empty() {
        let logs = sorted_strings(cleared.iter().map(|e| e.at("log")));
        items.push(event(
            tr!("Event logs cleared"),
            tr!(
                "cleared {0}: {1}",
                count_n(cleared.len(), tl!("{0} time"), tl!("{0} times")),
                logs.join(", ")
            ),
            vec![Flag::new(
                "event_log_cleared",
                50,
                tr!("event logs were cleared (possibly to hide activity)"),
            )],
            facts(vec![
                ("category", json!("event_log_cleared")),
                ("logs", json!(logs)),
                ("last_seen", cleared[0].at("time").clone()),
                ("times", json!(cleared.len())),
            ]),
        ));
    }

    items.extend(defender_items(raw, events, &days));

    // PowerShell: command-line history.
    let mut candidates = Vec::new();
    for entry in list(events.at("ps_commands")) {
        let command = text(entry.at("cmd"));
        let parsed = parse_command(&command, None);
        let mut flags = scan_command(&[Some(&command), parsed.inline.as_deref(), parsed.decoded.as_deref()]);
        if parsed.hidden {
            flags.push(Flag::new("hidden_window", 15, tr!("ran with a hidden window")));
        }
        let decoded = parsed.decoded.as_deref().filter(|d| !d.is_empty());
        if decoded.is_some() {
            flags.push(Flag::new("encoded_powershell", 20, tr!("command encoded in Base64")));
        }
        if weight_sum(&flags) < 30 {
            continue;
        }
        let mut f = facts(vec![
            ("category", json!("powershell_history")),
            ("command", json!(clip(&scrub_secrets(&command), 700))),
            ("last_seen", entry.at("last").clone()),
            ("times", entry.at("n").clone()),
        ]);
        if let Some(decoded) = decoded {
            f.insert("decoded".into(), json!(clip(&scrub_secrets(decoded), 900)));
        }
        candidates.push(event(
            tr!("PowerShell with risk indicators"),
            format!(
                "run {}; last: {}",
                count(entry.at("n"), tl!("{0} time"), tl!("{0} times")),
                str_of(entry.at("last"))
            ),
            flags,
            f,
        ));
    }
    items.extend(top(candidates, 15));

    let mut candidates = Vec::new();
    for block in list(events.at("ps_scriptblocks")) {
        let text_value = text(block.at("text"));
        let flags = scan_text(&text_value);
        if weight_sum(&flags) < 40 {
            continue;
        }
        let file = if truthy(block.at("path")) {
            block.at("path").clone()
        } else {
            json!("(inline)")
        };
        candidates.push(event(
            tr!("PowerShell script flagged as suspicious"),
            tr!("logged by Windows on {0}", str_of(block.at("time"))),
            flags,
            facts(vec![
                ("category", json!("powershell_script")),
                ("file", file),
                ("snippet", json!(clip(&scrub_secrets(&text_value), 900))),
                ("last_seen", block.at("time").clone()),
            ]),
        ));
    }
    items.extend(top(candidates, 10));

    let rdp = list(events.at("rdp_sessions"));
    if !rdp.is_empty() {
        let public = rdp.iter().any(|s| ip::is_public(&text(s.at("address"))));
        let mut flags = vec![Flag::new(
            "remote_session",
            25,
            tr!("there were Remote Desktop sessions to this computer"),
        )];
        if public {
            flags.push(Flag::new(
                "remote_session_internet",
                30,
                tr!("Remote Desktop sessions from Internet addresses"),
            ));
        }
        items.push(event(
            tr!("Remote Desktop sessions received"),
            count_n(rdp.len(), tl!("{0} distinct source"), tl!("{0} distinct sources")),
            flags,
            facts(vec![
                ("category", json!("remote_desktop")),
                ("sessions", json!(rdp.iter().take(20).collect::<Vec<_>>())),
            ]),
        ));
    }

    for group in list(events.at("failed_logons")) {
        let n = int_of(group.at("n"));
        if n < 10 {
            continue;
        }
        let mut flags = vec![Flag::new(
            "failed_logons",
            if n >= 100 { 45 } else { 30 },
            tr!("{0} failed logon attempts from the same source", n),
        )];
        if ip::is_public(&text(group.at("ip"))) {
            flags.push(Flag::new(
                "internet_attack",
                15,
                tr!("the attempts come from an Internet address"),
            ));
        }
        let source = {
            let s = text(group.at("ip"));
            if s.is_empty() { tr!("a local source") } else { s }
        };
        items.push(event(
            tr!("Failed logon attempts"),
            tr!("{0} attempts from {1}", n, source),
            flags,
            with_fields(facts(vec![("category", json!("failed_logons"))]), group),
        ));
    }

    let remote: Vec<&Value> = list(events.at("remote_logons"))
        .iter()
        .filter(|g| str_of(g.at("logon_type")) == "10" || ip::is_public(&text(g.at("ip"))))
        .collect();
    if !remote.is_empty() {
        let mut flags = vec![Flag::new(
            "remote_logon",
            30,
            tr!("successful logons from another computer"),
        )];
        if remote.iter().any(|g| ip::is_public(&text(g.at("ip")))) {
            flags.push(Flag::new(
                "remote_logon_internet",
                25,
                tr!("successful logons from Internet addresses"),
            ));
        }
        items.push(event(
            tr!("Successful remote logons"),
            count_n(remote.len(), tl!("{0} source"), tl!("{0} sources")),
            flags,
            facts(vec![
                ("category", json!("remote_logon")),
                ("logons", json!(remote.iter().take(20).collect::<Vec<_>>())),
            ]),
        ));
    }

    for ev in list(events.at("accounts_created")) {
        items.push(event(
            tr!("User account created: {0}", str_of(ev.at("user"))),
            tr!("on {0}", str_of(ev.at("time"))),
            vec![Flag::new(
                "account_created",
                50,
                tr!("a local user account was created"),
            )],
            with_fields(facts(vec![("category", json!("account_created"))]), ev),
        ));
    }
    for ev in list(events.at("admin_added")) {
        items.push(event(
            tr!("Account added to the Administrators group"),
            tr!("on {0}", str_of(ev.at("time"))),
            vec![Flag::new(
                "admin_added",
                50,
                tr!("administrator privileges were granted to an account"),
            )],
            with_fields(facts(vec![("category", json!("admin_added"))]), ev),
        ));
    }

    for ev in list(events.at("tasks_created")) {
        let content = text(ev.at("content"));
        let flags = scan_text(&content);
        if weight_sum(&flags) >= 30 {
            items.push(event(
                tr!("Scheduled task created: {0}", str_of(ev.at("task"))),
                tr!("on {0}", str_of(ev.at("time"))),
                flags,
                facts(vec![
                    ("category", json!("task_created")),
                    ("task", ev.at("task").clone()),
                    ("created_by", ev.at("by").clone()),
                    ("content", json!(clip(&scrub_secrets(&content), 900))),
                ]),
            ));
        }
    }

    items.extend(firewall_change_items(events, &days));

    let consumers: Vec<&Value> = list(events.at("wmi_consumers"))
        .iter()
        .filter(|e| {
            let joined = format!(
                "{}{}{}",
                str_of(e.at("filter")),
                str_of(e.at("consumer")),
                str_of(e.at("cause"))
            );
            !lower(&joined).contains("scm event log")
        })
        .collect();
    if !consumers.is_empty() {
        items.push(event(
            tr!("Permanent WMI subscription registered"),
            count_n(consumers.len(), tl!("{0} event"), tl!("{0} events")),
            vec![Flag::new(
                "wmi_registered",
                40,
                tr!("a permanent WMI consumer was registered (persistence mechanism)"),
            )],
            facts(vec![
                ("category", json!("wmi")),
                (
                    "detail",
                    json!(
                        consumers
                            .iter()
                            .take(5)
                            .map(|c| clip(&str_of(c.at("cause")), 500))
                            .collect::<Vec<_>>()
                    ),
                ),
            ]),
        ));
    }

    let changes = list(events.at("task_changes"));
    if !changes.is_empty() {
        let names = sorted_strings(changes.iter().map(|c| c.at("task")));
        items.push(event(
            tr!("Scheduled tasks registered or deleted"),
            tr!(
                "{0} in {1} days",
                count_n(names.len(), tl!("{0} task"), tl!("{0} tasks")),
                days
            ),
            vec![Flag::new(
                "tasks_modified",
                10,
                tr!("scheduled tasks were registered or deleted recently"),
            )],
            facts(vec![
                ("category", json!("tasks_modified")),
                ("tasks", json!(names.iter().take(25).collect::<Vec<_>>())),
            ]),
        ));
    }
    items
}

fn severity_label(value: &Value) -> Option<&'static str> {
    match as_integral(value) {
        Some(1) => Some("low"),
        Some(2) => Some("moderate"),
        Some(4) => Some("high"),
        Some(5) => Some("severe"),
        _ => None,
    }
}

#[derive(Default)]
struct Threat {
    n: i64,
    paths: Vec<Value>,
    processes: BTreeSet<String>,
    actions: BTreeSet<String>,
    last: Value,
    active: bool,
    executed: bool,
    severity: Value,
    failed: bool,
    category: Value,
}

fn event_id_in(value: &Value, ids: &[i64]) -> bool {
    as_number(value).is_some_and(|n| ids.iter().any(|&id| n == id as f64))
}

/// Antivirus detections, grouped by threat.
fn defender_items(raw: &Value, events: &Value, days: &str) -> Vec<Item> {
    let mut threats: Vec<(String, Threat)> = Vec::new();
    fn entry_for(threats: &mut Vec<(String, Threat)>, name: String) -> &mut Threat {
        let position = match threats.iter().position(|(n, _)| *n == name) {
            Some(p) => p,
            None => {
                threats.push((name, Threat::default()));
                threats.len() - 1
            }
        };
        &mut threats[position].1
    }

    for det in list(raw.at("system").at("defender_detections")) {
        let name = {
            let n = text(det.at("name"));
            if n.is_empty() {
                tr!("threat {0}", str_of(det.at("threat_id")))
            } else {
                n
            }
        };
        let entry = entry_for(&mut threats, name);
        entry.n += 1;
        entry.last = max_of(&entry.last, det.at("time"));
        entry.active |= truthy(det.at("active"));
        entry.executed |= truthy(det.at("executed"));
        entry.failed |= is_false(det.at("action_success"));
        if let Some(label) = severity_label(det.at("severity")) {
            entry.severity = json!(label);
        }
        if truthy(det.at("process")) {
            entry.processes.insert(str_of(det.at("process")));
        }
        for resource in list(det.at("resources")) {
            if !entry.paths.contains(resource) {
                entry.paths.push(resource.clone());
            }
        }
    }

    for ev in list(events.at("defender_detections")) {
        let name = ev.at("threat");
        if !truthy(name) {
            continue;
        }
        let entry = entry_for(&mut threats, str_of(name));
        if event_id_in(ev.at("id"), &[1006, 1116, 1015]) && entry.paths.is_empty() {
            entry.n += 1;
        }
        entry.last = max_of(&entry.last, ev.at("time"));
        if !truthy(&entry.severity) {
            entry.severity = ev.at("severity").clone();
        }
        if !truthy(&entry.category) {
            entry.category = ev.at("category").clone();
        }
        if truthy(ev.at("action")) {
            entry.actions.insert(str_of(ev.at("action")));
        }
        if event_id_in(ev.at("id"), &[1008, 1118, 1119]) {
            entry.failed = true;
        }
        if truthy(ev.at("process")) {
            entry.processes.insert(str_of(ev.at("process")));
        }
        let path = ev.at("path");
        if truthy(path) && !entry.paths.contains(path) && entry.paths.len() < 12 {
            entry.paths.push(path.clone());
        }
    }

    let mut items = Vec::new();
    for (name, entry) in threats {
        let mut flags = vec![Flag::new(
            "antivirus_detection",
            30,
            tr!("Microsoft Defender detected a threat"),
        )];
        if entry.active {
            flags.push(Flag::new(
                "active_threat",
                40,
                tr!("Defender still considers it active"),
            ));
        }
        if entry.executed {
            flags.push(Flag::new("threat_executed", 15, tr!("the threat managed to run")));
        }
        if entry.failed {
            flags.push(Flag::new("cleanup_failed", 20, tr!("a cleanup action failed")));
        }
        let times = entry.n.max(1);
        items.push(event(
            tr!("Defender detection: {0}", name),
            format!(
                "{}; last: {}",
                count(&json!(times), tl!("{0} detection"), tl!("{0} detections")),
                str_of(&entry.last)
            ),
            flags,
            facts(vec![
                ("category", json!("antivirus_detection")),
                ("threat", json!(name)),
                ("severity", entry.severity.clone()),
                ("type", entry.category.clone()),
                ("times", json!(times)),
                ("last_seen", entry.last.clone()),
                ("actions", json!(entry.actions.iter().collect::<Vec<_>>())),
                ("processes", json!(entry.processes.iter().take(5).collect::<Vec<_>>())),
                (
                    "files",
                    json!(
                        entry
                            .paths
                            .iter()
                            .take(6)
                            .map(|p| clip(&scrub_secrets(&text(p)), 300))
                            .collect::<Vec<_>>()
                    ),
                ),
                ("total_files", json!(entry.paths.len())),
            ]),
        ));
    }

    let disabled = list(events.at("defender_disabled"));
    if !disabled.is_empty() {
        items.push(event(
            tr!("Defender protection was turned off"),
            tr!(
                "{0} in {1} days",
                count_n(disabled.len(), tl!("{0} time"), tl!("{0} times")),
                days
            ),
            vec![Flag::new(
                "antivirus_disabled",
                45,
                tr!("real-time protection or scanning was turned off"),
            )],
            facts(vec![
                ("category", json!("antivirus_disabled")),
                ("last_seen", disabled[0].at("time").clone()),
                ("times", json!(disabled.len())),
            ]),
        ));
    }

    let config_changes = list(events.at("defender_config"));
    let is_exclusion =
        |c: &Value| lower(&format!("{}{}", str_of(c.at("new")), str_of(c.at("old")))).contains("exclusions\\");
    let change = |c: &&Value| json!({"when": c.at("time"), "before": c.at("old"), "after": c.at("new")});
    let exclusions: Vec<&Value> = config_changes.iter().filter(|c| is_exclusion(c)).collect();
    if !exclusions.is_empty() {
        items.push(event(
            tr!("Changes to Defender exclusions"),
            tr!(
                "{0} in {1} days",
                count_n(exclusions.len(), tl!("{0} change"), tl!("{0} changes")),
                days
            ),
            vec![Flag::new(
                "exclusion_changed",
                40,
                tr!("antivirus exclusions were added or removed"),
            )],
            facts(vec![
                ("category", json!("exclusions")),
                (
                    "changes",
                    json!(exclusions.iter().take(15).map(change).collect::<Vec<_>>()),
                ),
            ]),
        ));
    }
    let other: Vec<&Value> = config_changes.iter().filter(|c| !is_exclusion(c)).collect();
    if !other.is_empty() {
        items.push(event(
            tr!("Changes to Defender protection settings"),
            count_n(other.len(), tl!("{0} change"), tl!("{0} changes")),
            vec![Flag::new(
                "antivirus_settings",
                15,
                tr!("an antivirus protection setting changed"),
            )],
            facts(vec![
                ("category", json!("antivirus_settings")),
                ("changes", json!(other.iter().take(10).map(change).collect::<Vec<_>>())),
            ]),
        ));
    }
    items
}

// --------------------------------------------------------------------------- configuration

const KNOWN_DNS: &[&str] = &[
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "1.1.1.2",
    "1.0.0.2",
    "1.1.1.3",
    "1.0.0.3",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "76.76.2.0",
    "76.76.10.0",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2620:fe::fe",
    "2620:fe::9",
];
// Detection data: well-known services, security vendors and banks (including Spanish-language names).
rx!(
    SENSITIVE_HOST,
    r"(?i)(microsoft|windowsupdate|windows\.com|live\.com|office\.|google|gstatic|googleapis|youtube|facebook|instagram|whatsapp|paypal|apple\.com|icloud|amazon|netflix|bank|banco|bancolombia|davivienda|bbva|santander|nequi|binance|coinbase|kaspersky|avast|avg\.com|eset|bitdefender|malwarebytes|norton|symantec|mcafee|sophos|trendmicro|virustotal|defender)"
);
rx!(
    PSEUDO_PROCESSES,
    r"(?i)^(registry|memory compression|secure system|system|system idle process|vmmem.*|memcompression)$"
);
rx!(
    DNS_MINING,
    r"(?i)(xmr|monero|nanopool|minexmr|supportxmr|2miners|nicehash|ethermine|f2pool|hashvault|moneroocean|pool\.hashvault)"
);
rx!(
    DNS_DYNAMIC,
    r"(?i)(duckdns\.org|no-ip\.|ddns\.net|hopto\.org|zapto\.org|serveo\.net|portmap\.io)$"
);
rx!(
    RISKY_POLICIES,
    r"(?i)extensioninstallforcelist|extensionsettings|proxy|homepagelocation|newtabpagelocation|restoreonstartupurls|defaultsearchprovider|nativemessaging|remotedebugging|certificates"
);
rx!(
    BROAD_EXCLUSION,
    r"(?i)^[a-z]:\\?$|\\users\\[^\\]+\\?$|\\temp\\?$|\\appdata|\\downloads|\\programdata\\?$|\\windows\\?$"
);

fn dns_ioc() -> [(&'static Rx, Flag); 2] {
    [
        (
            &DNS_MINING,
            Flag::new("mining_domain", 45, tr!("cryptocurrency mining domains were resolved")),
        ),
        (
            &DNS_DYNAMIC,
            Flag::new(
                "dynamic_dns_domain",
                20,
                tr!("dynamic DNS domains were resolved (common in remote-control malware)"),
            ),
        ),
    ]
}

fn hosts_item(hosts: &[Value]) -> (Option<Item>, Map<String, Value>) {
    let mut counts = facts(vec![
        ("total", json!(hosts.len())),
        ("local", json!(0)),
        ("private", json!(0)),
        ("public", json!(0)),
    ]);
    let mut blocked: Vec<String> = Vec::new();
    let mut redirected: Vec<String> = Vec::new();
    for entry in hosts {
        let class = ip::address_class(&str_of(entry.at("ip")));
        let current = as_int(counts.at(class)).unwrap_or(0);
        counts.insert(class.to_string(), json!(current + 1));
        for name in list(entry.at("names")) {
            let name = str_of(name);
            if matches!(
                lower(&name).as_str(),
                "localhost" | "kubernetes.docker.internal" | "host.docker.internal" | "gateway.docker.internal"
            ) {
                continue;
            }
            if !SENSITIVE_HOST.is_match(&name) {
                continue;
            }
            if class == "local" {
                blocked.push(name);
            } else {
                redirected.push(format!("{name} → {}", str_of(entry.at("ip"))));
            }
        }
    }
    let mut flags = Vec::new();
    if !redirected.is_empty() {
        flags.push(Flag::new(
            "hosts_redirects",
            60,
            tr!("the hosts file redirects well-known domains to another address (possible spoofing)"),
        ));
    }
    if !blocked.is_empty() {
        flags.push(Flag::new(
            "hosts_blocks",
            25,
            tr!("the hosts file blocks domains of well-known or security services"),
        ));
    }
    if flags.is_empty() {
        return (None, counts);
    }
    let total = counts.at("total").clone();
    let mut item = Item::new(
        "config",
        tr!("Hosts file with sensitive entries"),
        tr!("{0} in total", count(&total, tl!("{0} entry"), tl!("{0} entries"))),
    );
    item.facts = facts(vec![
        ("topic", json!("hosts")),
        ("summary", Value::Object(counts.clone())),
        ("redirected", json!(redirected.iter().take(25).collect::<Vec<_>>())),
        ("blocked", json!(blocked.iter().take(40).collect::<Vec<_>>())),
        ("total_blocked", json!(blocked.len())),
    ]);
    (Some(finish(item, flags)), counts)
}

/// Configuration findings and a summary of the security posture.
pub(crate) fn config_items(raw: &Value, aux: &Aux) -> (Vec<Item>, Map<String, Value>) {
    let system = raw.at("system");
    let cfg = raw.at("sysconfig");
    let meta = raw.at("meta");
    let mut items = Vec::new();
    let mut posture = Map::new();
    posture.insert("is_administrator".into(), json!(truthy(meta.at("is_admin"))));

    let os_info = system.at("os");
    if truthy(os_info) {
        posture.insert(
            "system".into(),
            json!(tr!(
                "{0} (build {1}), installed on {2}, last boot {3}",
                str_of(os_info.at("caption")),
                str_of(os_info.at("build")),
                take(&str_of(os_info.at("installed")), 10),
                take(&str_of(os_info.at("last_boot")), 16).replace('T', " ")
            )),
        );
        let build_text = text(os_info.at("build"));
        let build = if !build_text.is_empty() && build_text.chars().all(|c| c.is_ascii_digit()) {
            build_text.parse::<i64>().unwrap_or(0)
        } else {
            0
        };
        let support_ended = NaiveDate::from_ymd_opt(2025, 10, 14).is_some_and(|end| Local::now().date_naive() >= end);
        if 0 < build && build < 22000 && support_ended {
            items.push(config(
                "unsupported_os",
                tr!("Windows without security support"),
                30,
                tr!("this version of Windows no longer receives security patches (unless enrolled in the ESU program)"),
                Some(&facts(vec![
                    ("system", os_info.at("caption").clone()),
                    ("build", os_info.at("build").clone()),
                ])),
                vec![],
            ));
        }
    }
    let computer = system.at("computer");
    if truthy(computer) {
        posture.insert(
            "computer".into(),
            json!(
                strip(&format!(
                    "{} {}",
                    str_of(computer.at("manufacturer")),
                    str_of(computer.at("model"))
                ))
                .to_string()
            ),
        );
    }

    // --- antivirus
    let products = list(system.at("av_products"));
    let other_av_active = products
        .iter()
        .any(|p| !lower(&str_of(p.at("name"))).contains("defender") && int_of(p.at("state")) & 0x1000 != 0);
    posture.insert(
        "registered_antivirus".into(),
        json!(products.iter().map(|p| p.at("name")).collect::<Vec<_>>()),
    );
    let defender = system.at("defender");
    if truthy(defender) {
        let full_age = as_number(defender.at("full_scan_age_days")).unwrap_or(0.0);
        let quick = if truthy(defender.at("quick_scan")) {
            str_of(defender.at("quick_scan"))
        } else {
            "never".into()
        };
        let full = if !truthy(defender.at("full_scan")) || full_age > 100_000.0 {
            "never".to_string()
        } else {
            take(&str_of(defender.at("full_scan")), 10).to_string()
        };
        let state = facts(vec![
            ("realtime_protection", defender.at("realtime").clone()),
            ("tamper_protection", defender.at("tamper").clone()),
            ("signature_age_days", defender.at("sig_age_days").clone()),
            ("last_quick_scan", json!(take(&quick, 10))),
            ("last_full_scan", json!(full)),
            ("mode", defender.at("mode").clone()),
        ]);
        posture.insert("defender".into(), Value::Object(state.clone()));
        if !other_av_active {
            if !truthy(defender.at("realtime")) || !truthy(defender.at("antivirus")) {
                items.push(config(
                    "defender_off",
                    tr!("Real-time protection turned off"),
                    55,
                    tr!("the antivirus is not monitoring in real time and no other antivirus is active"),
                    Some(&state),
                    vec![],
                ));
            }
            let sig_age = defender.at("sig_age_days");
            if let Some(age) = sig_age
                .as_i64()
                .or_else(|| sig_age.as_u64().map(|u| i64::try_from(u).unwrap_or(i64::MAX)))
                && 7 < age
                && age < 100_000
            {
                items.push(config(
                    "outdated_signatures",
                    tr!("Antivirus definitions out of date"),
                    if age > 30 { 40 } else { 25 },
                    tr!("the definitions are {0} days old", age),
                    Some(&facts(vec![("days", json!(age))])),
                    vec![],
                ));
            }
            if is_false(defender.at("tamper")) {
                items.push(config(
                    "tamper_protection_off",
                    tr!("Tamper Protection turned off"),
                    15,
                    tr!("any privileged program can turn Defender off"),
                    None,
                    vec![],
                ));
            }
        }
    } else if !other_av_active {
        items.push(config(
            "unknown_antivirus",
            tr!("Could not check the antivirus"),
            20,
            tr!("it was not possible to query the status of Microsoft Defender"),
            None,
            vec![],
        ));
    }

    let pref = system.at("defender_pref");
    let disabled_prefs: Vec<&str> = [
        "disable_realtime",
        "disable_behavior",
        "disable_ioav",
        "disable_script_scanning",
    ]
    .into_iter()
    .filter(|k| truthy(pref.at(k)))
    .collect();
    if !disabled_prefs.is_empty() && !other_av_active {
        items.push(config(
            "defender_layers_disabled",
            tr!("Defender protection layers turned off"),
            50,
            tr!("some protection modules are turned off in the settings"),
            Some(&facts(vec![("disabled", json!(disabled_prefs))])),
            vec![],
        ));
    }
    let or_list = |v: &Value| if truthy(v) { v.clone() } else { json!([]) };
    let exclusion_lists = facts(vec![
        ("paths", or_list(pref.at("exclusion_path"))),
        ("processes", or_list(pref.at("exclusion_process"))),
        ("extensions", or_list(pref.at("exclusion_extension"))),
    ]);
    let hidden = exclusion_lists
        .values()
        .flat_map(list)
        .any(|v| str_of(v).starts_with("N/A"));
    posture.insert(
        "defender_exclusions".into(),
        if hidden {
            json!(tr!("not visible without administrator rights"))
        } else {
            Value::Object(
                exclusion_lists
                    .iter()
                    .filter(|(_, v)| truthy(v))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            )
        },
    );
    if !hidden && exclusion_lists.values().any(truthy) {
        let broad = list(exclusion_lists.at("paths"))
            .iter()
            .any(|p| BROAD_EXCLUSION.is_match(&str_of(p)))
            || truthy(exclusion_lists.at("extensions"));
        items.push(config(
            "defender_exclusions",
            tr!("Antivirus exclusions"),
            if broad { 60 } else { 30 },
            tr!("Defender does not scan these paths, processes or extensions"),
            Some(&exclusion_lists),
            vec![],
        ));
    }

    let defender_policy = cfg.at("defender_policy");
    if truthy(defender_policy) {
        let policy_text = lower(&str_of(defender_policy));
        let risky = [
            "disableantispyware",
            "disableantivirus",
            "disablerealtimemonitoring",
            "exclusions",
        ]
        .iter()
        .any(|k| policy_text.contains(k));
        items.push(config(
            "defender_disabled_by_policy",
            tr!("Defender configured by registry policies"),
            if risky { 60 } else { 20 },
            tr!("there are policies that change how the antivirus behaves"),
            Some(obj(defender_policy)),
            vec![],
        ));
    }

    // --- firewall, UAC, remote access
    let firewall = list(system.at("firewall"));
    let mut profiles = Map::new();
    for p in firewall {
        profiles.insert(crate::lenient::json_key(p.at("name")), p.at("enabled").clone());
    }
    posture.insert("firewall".into(), Value::Object(profiles));
    let off: Vec<&Value> = firewall
        .iter()
        .filter(|p| is_false(p.at("enabled")))
        .map(|p| p.at("name"))
        .collect();
    if !off.is_empty() {
        items.push(config(
            "firewall_disabled",
            tr!("Windows Firewall turned off"),
            35,
            tr!(
                "profiles without firewall: {0}",
                off.iter().map(|n| str_of(n)).collect::<Vec<_>>().join(", ")
            ),
            Some(&facts(vec![("profiles", json!(off))])),
            vec![],
        ));
    }

    let uac = cfg.at("uac");
    let uac_enabled = uac.get("enabled").is_none_or(truthy);
    posture.insert("uac".into(), json!(if uac_enabled { "enabled" } else { "DISABLED" }));
    if truthy(uac) && !uac_enabled {
        items.push(config(
            "uac_disabled",
            tr!("User Account Control (UAC) turned off"),
            45,
            tr!("programs get administrator privileges without asking for confirmation"),
            None,
            vec![],
        ));
    } else if eq_num(uac.at("admin_prompt"), 0.0) {
        items.push(config(
            "uac_silent",
            tr!("UAC elevates privileges without asking"),
            30,
            tr!("administrators do not see the confirmation prompt"),
            None,
            vec![],
        ));
    }

    let rdp = cfg.at("rdp");
    posture.insert(
        "remote_desktop".into(),
        json!(if truthy(rdp.at("enabled")) {
            "enabled"
        } else {
            "disabled"
        }),
    );
    if truthy(rdp.at("enabled")) {
        let extra = if eq_num(rdp.at("nla"), 0.0) {
            vec![Flag::new(
                "rdp_without_nla",
                10,
                tr!("without Network Level Authentication"),
            )]
        } else {
            vec![]
        };
        let allowed: Vec<&Value> = list(system.at("rdp_users")).iter().map(|u| u.at("name")).collect();
        items.push(config(
            "rdp_enabled",
            tr!("Remote Desktop enabled"),
            20,
            tr!("the computer accepts Remote Desktop connections"),
            Some(&facts(vec![
                ("port", rdp.at("port").clone()),
                ("allowed_users", json!(allowed)),
            ])),
            extra,
        ));
    }
    if lower(&str_of(cfg.at("smartscreen"))) == "off" || eq_num(cfg.at("smartscreen_policy"), 0.0) {
        items.push(config(
            "smartscreen_disabled",
            tr!("SmartScreen turned off"),
            20,
            tr!("Windows does not check the reputation of downloaded programs"),
            None,
            vec![],
        ));
    }
    if truthy(cfg.at("wdigest_cleartext")) {
        items.push(config(
            "wdigest",
            tr!("WDigest keeps passwords in memory"),
            45,
            tr!("setting that leaves passwords in clear text in memory (attackers enable it to steal them)"),
            None,
            vec![],
        ));
    }
    if str_of(cfg.at("windows_update_policy").at("NoAutoUpdate")) == "1" {
        items.push(config(
            "updates_disabled",
            tr!("Automatic updates turned off"),
            20,
            tr!("a policy prevents Windows from updating itself"),
            None,
            vec![],
        ));
    }
    let hotfix = system.at("last_hotfix");
    let age = days_since(hotfix.at("date"));
    let last_update = if truthy(hotfix.at("date")) {
        str_of(hotfix.at("date"))
    } else {
        "unknown".into()
    };
    posture.insert("last_update".into(), json!(take(&last_update, 10)));
    if let Some(age) = age
        && age > 60
    {
        items.push(config(
            "updates_overdue",
            tr!("Windows has not been updated for a long time"),
            if age > 180 { 40 } else { 25 },
            tr!("the last installed update is {0} days old", age),
            Some(&facts(vec![(
                "last",
                if truthy(hotfix) { hotfix.clone() } else { json!({}) },
            )])),
            vec![],
        ));
    }

    // --- network
    let proxy = cfg.at("proxy");
    if truthy(proxy.at("pac_url")) {
        items.push(config(
            "proxy_auto_config",
            tr!("Proxy configuration script"),
            35,
            tr!("web traffic can be diverted according to an external script"),
            Some(&facts(vec![("url", proxy.at("pac_url").clone())])),
            vec![],
        ));
    }
    if truthy(proxy.at("enabled")) && truthy(proxy.at("server")) {
        items.push(config(
            "proxy_enabled",
            tr!("System proxy enabled"),
            25,
            tr!("all web traffic goes through an intermediary"),
            Some(&facts(vec![("server", proxy.at("server").clone())])),
            vec![],
        ));
    }

    let (hosts, hosts_counts) = hosts_item(list(cfg.at("hosts")));
    posture.insert("hosts_file".into(), Value::Object(hosts_counts));
    items.extend(hosts);

    let network_config = crate::netcfg::posture(raw);
    if !network_config.is_null() {
        posture.insert("network_config".into(), network_config);
    }
    items.extend(crate::netcfg::items(raw, Local::now().timestamp_millis()));
    // Servers set by hand are reported by `netcfg` with what is known about them.
    let hand_set_dns = crate::netcfg::hand_set_dns(raw);
    let mut unknown_dns: Vec<(String, BTreeSet<String>)> = Vec::new();
    for iface in list(raw.at("network").at("dns_servers")) {
        for server in list(iface.at("servers")) {
            let server_text = str_of(server);
            if server.as_str().is_some_and(|s| KNOWN_DNS.contains(&s))
                || lower(&server_text).starts_with("fec0:0:0:ffff")
                || hand_set_dns.contains(&server_text)
            {
                continue;
            }
            if ip::address_class(&server_text) == "public" {
                let iface_name = str_of(iface.at("iface"));
                match unknown_dns.iter_mut().find(|(s, _)| *s == server_text) {
                    Some((_, names)) => {
                        names.insert(iface_name);
                    }
                    None => unknown_dns.push((server_text, BTreeSet::from([iface_name]))),
                }
            }
        }
    }
    if !unknown_dns.is_empty() {
        let servers: Map<String, Value> = unknown_dns
            .into_iter()
            .map(|(k, v)| (k, json!(v.into_iter().collect::<Vec<_>>())))
            .collect();
        items.push(config(
            "unrecognized_dns",
            tr!("Unrecognized public DNS servers"),
            15,
            tr!("they may belong to your Internet provider; a malicious DNS server redirects your browsing"),
            Some(&facts(vec![("servers", Value::Object(servers))])),
            vec![],
        ));
    }

    let mut cache_hits: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for name in list(raw.at("network").at("dns_cache")) {
        let name = str_of(name);
        for (pattern, flag) in dns_ioc() {
            if pattern.is_match(&name) {
                cache_hits.entry(flag.code.clone()).or_default().push(name.clone());
            }
        }
    }
    for (_, flag) in dns_ioc() {
        if let Some(hits) = cache_hits.get(&flag.code).filter(|h| !h.is_empty()) {
            let domains: Vec<String> = hits
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .take(20)
                .collect();
            items.push(config(
                &flag.code,
                tr!("Suspicious domains resolved recently"),
                flag.weight,
                &flag.text,
                Some(&facts(vec![("domains", json!(domains))])),
                vec![],
            ));
        }
    }

    // --- accounts
    let current = lower(&text(meta.at("user")));
    let users = list(system.at("users"));
    let builtin = ["-500", "-501", "-503", "-504"];
    posture.insert(
        "local_accounts".into(),
        json!(
            users
                .iter()
                .map(|u| format!(
                    "{}{}",
                    str_of(u.at("name")),
                    if truthy(u.at("enabled")) { "" } else { " (disabled)" }
                ))
                .collect::<Vec<_>>()
        ),
    );
    let extra_users: Vec<&Value> = users
        .iter()
        .filter(|u| {
            truthy(u.at("enabled"))
                && lower(&text(u.at("name"))) != current
                && !builtin.iter().any(|b| str_of(u.at("sid")).ends_with(b))
        })
        .collect();
    if !extra_users.is_empty() {
        let hidden_names = extra_users.iter().any(|u| str_of(u.at("name")).ends_with('$'));
        let accounts: Vec<Value> = extra_users
            .iter()
            .map(|u| {
                json!({
                    "name": u.at("name"), "description": u.at("desc"), "last_logon": u.at("last_logon"),
                    "created_or_changed": u.at("password_set"), "password_required": u.at("password_required"),
                })
            })
            .collect();
        items.push(config(
            "additional_accounts",
            tr!("Other local accounts enabled"),
            if hidden_names { 50 } else { 20 },
            tr!("there are user accounts besides yours: confirm that you recognize them"),
            Some(&facts(vec![("accounts", json!(accounts))])),
            vec![],
        ));
    }
    for user in users {
        if !truthy(user.at("enabled")) {
            continue;
        }
        let sid = str_of(user.at("sid"));
        if sid.ends_with("-501") {
            items.push(config(
                "guest_enabled",
                tr!("Guest account enabled"),
                35,
                tr!("anyone can sign in without a password"),
                None,
                vec![],
            ));
        } else if sid.ends_with("-500") {
            items.push(config(
                "builtin_administrator",
                tr!("Built-in Administrator account enabled"),
                20,
                tr!("account with full privileges and no UAC; a common target of attacks"),
                None,
                vec![],
            ));
        }
    }
    let admins = list(system.at("admins"));
    posture.insert(
        "administrators".into(),
        json!(admins.iter().map(|a| a.at("name")).collect::<Vec<_>>()),
    );
    let extra_admins: Vec<&Value> = admins
        .iter()
        .filter(|a| {
            !str_of(a.at("sid")).ends_with("-500")
                && lower(text(a.at("name")).rsplit('\\').next().unwrap_or("")) != current
        })
        .map(|a| a.at("name"))
        .collect();
    if !extra_admins.is_empty() {
        items.push(config(
            "other_administrators",
            tr!("Other accounts with administrator privileges"),
            30,
            tr!("besides your user there are more administrators on the computer"),
            Some(&facts(vec![("accounts", json!(extra_admins))])),
            vec![],
        ));
    }
    let shares = list(system.at("shares"));
    if !shares.is_empty() {
        let resources: Vec<Value> = shares
            .iter()
            .map(|s| json!({"name": s.at("name"), "path": s.at("path")}))
            .collect();
        items.push(config(
            "shared_folders",
            tr!("Folders shared on the network"),
            15,
            tr!("these folders are reachable from other computers on the network"),
            Some(&facts(vec![("resources", json!(resources))])),
            vec![],
        ));
    }

    // --- browsers
    let policies = cfg.at("browser_policies");
    if truthy(policies) {
        let risky = RISKY_POLICIES.is_match(&literal_of(policies));
        items.push(config(
            "browser_policies",
            tr!("Browser managed by policies"),
            if risky { 40 } else { 15 },
            tr!("there are policies applied to the browser (\"managed by your organization\"); adware uses them to pin search engines, extensions or proxies"),
            Some(obj(policies)),
            vec![],
        ));
    }

    items.extend(hook_items(raw, other_av_active));
    items.extend(crate::svcsec::items(raw));
    items.extend(persistence_items(raw));
    items.extend(crate::secrets::items(raw));
    items.extend(firewall_rule_items(raw));
    items.extend(crate::rmm::items(raw));
    items.extend(crate::certs::items(raw));
    items.extend(crate::amsi::items(raw));
    items.extend(crate::bits::items(raw));

    // --- pathless processes and findings from the registry
    let odd: BTreeSet<&String> = aux
        .pathless
        .iter()
        .map(|(_, name)| name)
        .filter(|name| !PSEUDO_PROCESSES.is_match(name))
        .collect();
    if !odd.is_empty() {
        items.push(config(
            "pathless_processes",
            tr!("Processes whose location could not be determined"),
            20,
            tr!("it was not possible to find out which file they run from"),
            Some(&facts(vec![("processes", json!(odd))])),
            vec![],
        ));
    }
    for finding in &aux.config {
        let scan = text(finding.at("scan"));
        let extra = if scan.is_empty() { vec![] } else { scan_text(&scan) };
        items.push(config(
            &text(finding.at("topic")),
            text(finding.at("title")),
            as_int(finding.at("score")).unwrap_or(0),
            text(finding.at("text")),
            finding.at("detail").as_object(),
            extra,
        ));
    }
    (items, posture)
}

/// Programs whose copy in place of an accessibility program gives a way in without a password.
const BACKDOOR_PROGRAMS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "explorer.exe",
    "taskmgr.exe",
    "regedit.exe",
    "mmc.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
];

/// Persistence tricks and defence-evasion settings (`sysconfig.hooks`, `sysconfig.evasion`, the
/// extra Defender preferences, two services and the accessibility programs). Every check looks
/// for an explicit change: what Windows ships with never scores.
fn hook_items(raw: &Value, other_av_active: bool) -> Vec<Item> {
    let mut items = Vec::new();
    let system = raw.at("system");
    let cfg = raw.at("sysconfig");

    // --- accessibility programs replaced (sticky keys backdoor)
    let files = raw.at("files");
    for (name, originals) in crate::hooks::ACCESSIBILITY {
        let path = crate::ntpath::join(&crate::ntpath::SYSTEM32, &[name]);
        let info = files.at(&lower(&path));
        if !crate::lenient::is_true(info.at("exists")) {
            continue;
        }
        let original = lower(&text(info.at("original")));
        let original = original.trim_end_matches(".mui").to_string();
        let detail = facts(vec![
            ("path", json!(path)),
            ("original_name", json!(original)),
            ("signer", info.at("signer").clone()),
        ]);
        if !original.is_empty() && !originals.contains(&original.as_str()) {
            let shell = BACKDOOR_PROGRAMS.contains(&original.as_str());
            items.push(config(
                "accessibility_replaced",
                tr!("Accessibility program replaced: {0}", name),
                // A shell there is a sign-in screen backdoor; another program is still wrong.
                if shell { 85 } else { 55 },
                tr!(
                    "\"{0}\" is really \"{1}\": Windows starts it from the sign-in screen with SYSTEM rights, so anyone at the computer could use it without a password",
                    name,
                    original
                ),
                Some(&detail),
                vec![],
            ));
        } else if info.at("sig_status").as_str().is_some_and(|s| !s.is_empty())
            && !crate::rules::is_microsoft_signed(info.as_object())
        {
            items.push(config(
                "accessibility_replaced",
                tr!("Accessibility program replaced: {0}", name),
                70,
                tr!(
                    "\"{0}\" is not signed by Microsoft: Windows starts it from the sign-in screen with SYSTEM rights",
                    name
                ),
                Some(&detail),
                vec![],
            ));
        }
    }

    // --- one-value tricks
    let hooks = cfg.at("hooks");
    let overrides = hooks.at("env_override");
    if overrides.as_object().is_some_and(|o| !o.is_empty()) {
        items.push(config(
            "env_override",
            tr!("Windows folder variable redefined for your account"),
            70,
            tr!(
                "%windir% or %SystemRoot% points elsewhere for your account: Windows' own tasks and programs that elevate without asking would run files from there"
            ),
            overrides.as_object(),
            vec![],
        ));
    }
    let shell = strip(&text(hooks.at("alternate_shell"))).to_string();
    if !shell.is_empty() && lower(&shell) != "cmd.exe" {
        items.push(config(
            "safeboot_shell",
            tr!("Safe mode shell changed"),
            60,
            tr!("Safe mode with command prompt starts \"{0}\" instead of cmd.exe", shell),
            Some(&facts(vec![("alternate_shell", json!(shell))])),
            vec![],
        ));
    }
    // Programs register hidden service accounts too; only a hidden administrator is a finding.
    let admins: BTreeSet<String> = list(system.at("admins"))
        .iter()
        .map(|a| lower(text(a.at("name")).rsplit('\\').next().unwrap_or("")))
        .collect();
    let hidden_admins: Vec<String> = list(hooks.at("hidden_accounts"))
        .iter()
        .map(text)
        .filter(|n| admins.contains(&lower(n)))
        .collect();
    if !hidden_admins.is_empty() {
        items.push(config(
            "hidden_administrator",
            tr!("Administrator hidden from the sign-in screen"),
            60,
            tr!("an account with administrator rights does not appear on the sign-in screen: a way back in that is easy to miss"),
            Some(&facts(vec![("accounts", json!(hidden_admins))])),
            vec![],
        ));
    }
    let before = list(hooks.at("path_before_system32"));
    if !before.is_empty() {
        items.push(config(
            "path_hijack",
            tr!("Folders outside Program Files come before System32 in PATH"),
            // Common on developer computers (tool folders at the root of the drive): a minor
            // signal. The folder may still be protected by its own permissions.
            10,
            tr!("if a standard user can write to one of these folders, a program placed there can take the place of a Windows command for every user"),
            Some(&facts(vec![("folders", json!(before))])),
            vec![],
        ));
    }

    // --- logging and protection switched off explicitly
    let evasion = cfg.at("evasion");
    let channels = list(evasion.at("channels_off"));
    if !channels.is_empty() {
        items.push(config(
            "event_channels_off",
            tr!("Security event logs turned off"),
            50,
            tr!("these event logs are turned off, so actions an attacker takes there leave no record"),
            Some(&facts(vec![("logs", json!(channels))])),
            vec![],
        ));
    }
    let loggers = list(evasion.at("autologgers_off"));
    if !loggers.is_empty() {
        items.push(config(
            "event_logging_off",
            tr!("Windows event logging turned off"),
            60,
            tr!("the Security, System or Application log does not start with Windows: nothing is recorded"),
            Some(&facts(vec![("loggers", json!(loggers))])),
            vec![],
        ));
    }
    if eq_num(evasion.at("run_as_ppl"), 0.0) {
        items.push(config(
            "lsa_protection_off",
            tr!("LSA protection turned off explicitly"),
            25,
            tr!("RunAsPPL is set to 0: other programs can read the process that holds sign-in secrets"),
            None,
            vec![],
        ));
    }
    if eq_num(evasion.at("driver_blocklist"), 0.0) {
        items.push(config(
            "driver_blocklist_off",
            tr!("Vulnerable driver blocklist turned off"),
            30,
            tr!("drivers with known flaws, which attackers load to switch security software off, are allowed again"),
            None,
            vec![],
        ));
    }

    // --- event logging service and Defender service
    let services = list(raw.at("services"));
    let find = |name: &str| services.iter().find(|s| text(s.at("name")).eq_ignore_ascii_case(name));
    let stopped =
        |svc: &Value| lower(&text(svc.at("start"))) == "disabled" || lower(&text(svc.at("state"))) == "stopped";
    if let Some(svc) = find("EventLog").filter(|s| stopped(s)) {
        items.push(config(
            "eventlog_stopped",
            tr!("Windows Event Log service stopped"),
            60,
            tr!("no event is recorded while the Windows Event Log service is stopped or disabled"),
            Some(&facts(vec![
                ("state", svc.at("state").clone()),
                ("start", svc.at("start").clone()),
            ])),
            vec![],
        ));
    }

    if other_av_active {
        return items;
    }
    if let Some(svc) = find("WinDefend").filter(|s| stopped(s)) {
        items.push(config(
            "defender_service_stopped",
            tr!("Microsoft Defender service stopped"),
            55,
            tr!("the antivirus service is stopped or disabled and no other antivirus is active"),
            Some(&facts(vec![
                ("state", svc.at("state").clone()),
                ("start", svc.at("start").clone()),
            ])),
            vec![],
        ));
    }
    let pref = system.at("defender_pref");
    let allowed: Vec<Value> = list(pref.at("threat_default_actions"))
        .iter()
        .filter(|t| matches!(as_int(t.at("action")), Some(6 | 9)))
        .cloned()
        .collect();
    if !allowed.is_empty() {
        items.push(config(
            "defender_allowed_threats",
            tr!("Defender told to leave threats alone"),
            55,
            tr!("Defender is set to allow, or to take no action on, specific threats when it finds them"),
            Some(&facts(vec![("threats", json!(allowed))])),
            vec![],
        ));
    }
    if pref.get("maps_reporting").is_some() && eq_num(pref.at("maps_reporting"), 0.0) {
        items.push(config(
            "cloud_protection_off",
            tr!("Cloud-delivered protection turned off"),
            30,
            tr!("Defender does not ask Microsoft's cloud about new files, so new threats are caught later"),
            None,
            vec![],
        ));
    }
    if truthy(pref.at("disable_block_at_first_seen")) {
        items.push(config(
            "block_at_first_seen_off",
            tr!("Block at first sight turned off"),
            20,
            tr!("new suspicious files are not held back while the cloud checks them"),
            None,
            vec![],
        ));
    }
    let ips: Vec<&Value> = list(pref.at("exclusion_ip"))
        .iter()
        .filter(|v| !str_of(v).starts_with("N/A"))
        .collect();
    if !ips.is_empty() {
        items.push(config(
            "defender_ip_exclusions",
            tr!("Network addresses excluded from Defender"),
            30,
            tr!("Defender's network protection does not inspect traffic to these addresses"),
            Some(&facts(vec![("addresses", json!(ips))])),
            vec![],
        ));
    }
    let asr = list(pref.at("asr_disabled"));
    if !asr.is_empty() {
        items.push(config(
            "asr_rules_off",
            tr!("Attack surface reduction rules turned off"),
            15,
            tr!("some attack surface reduction rules are set to off explicitly"),
            Some(&facts(vec![("rules", json!(asr))])),
            vec![],
        ));
    }
    items
}

// --------------------------------------------------------------------------- PowerShell and Office

/// PowerShell profiles, VSTO add-ins, macro files in the Office startup folders and Outlook
/// (`sysconfig.persistence`). A profile is reported only when its text scores like a suspicious
/// script (30, the threshold of the PowerShell history): prompt themes and environment managers that
/// pipe their setup into Invoke-Expression score 20 and stay quiet.
fn persistence_items(raw: &Value) -> Vec<Item> {
    let mut items = Vec::new();
    let cfg = raw.at("sysconfig").at("persistence");
    for profile in list(cfg.at("ps_profiles")) {
        let content = text(profile.at("content"));
        let flags = scan_text(&content);
        if weight_sum(&flags) < 30 {
            continue;
        }
        let path = text(profile.at("path"));
        let everyone = str_of(profile.at("scope")) == "all_users";
        let patterns: Vec<&str> = flags.iter().map(|f| f.text.as_str()).collect();
        let detail = facts(vec![
            ("path", json!(path)),
            ("scope", profile.at("scope").clone()),
            ("patterns", json!(patterns)),
            ("snippet", json!(clip(&scrub_secrets(&content), 900))),
        ]);
        items.push(config(
            "ps_profile",
            tr!(
                "PowerShell profile with suspicious commands: {0}",
                crate::ntpath::basename(&path)
            ),
            if everyone { 20 } else { 15 },
            if everyone {
                tr!("PowerShell runs this script for every user, every time it starts")
            } else {
                tr!("PowerShell runs this script every time it starts")
            },
            Some(&detail),
            flags,
        ));
    }

    let office = cfg.at("office");
    for addin in list(office.at("vsto_addins")) {
        // Add-ins installed from the Office Store or by a vendor's installer in its own folder are
        // normal; one fetched from a web address, or kept where any program can change it, is not.
        let web = truthy(addin.at("web"));
        if !web && !truthy(addin.at("user_writable")) {
            continue;
        }
        let detail = facts(vec![
            ("app", addin.at("app").clone()),
            ("name", addin.at("name").clone()),
            ("manifest", addin.at("manifest").clone()),
            ("key", addin.at("location").clone()),
        ]);
        items.push(config(
            "office_vsto_addin",
            tr!(
                "Office add-in \"{0}\" ({1})",
                str_of(addin.at("name")),
                str_of(addin.at("app"))
            ),
            if web { 20 } else { 10 },
            if web {
                tr!("the add-in is installed and updated from a web address every time the program starts")
            } else {
                tr!("the add-in loads every time the program starts, from a folder any program can change")
            },
            Some(&detail),
            vec![],
        ));
    }
    for file in list(office.at("startup_macros")) {
        let path = text(file.at("file"));
        let app = str_of(file.at("app"));
        items.push(config(
            "office_startup_macros",
            tr!(
                "Office opens a file with macros at start: {0}",
                crate::ntpath::basename(&path)
            ),
            30,
            tr!("{0} opens this file, macros included, every time it starts", app),
            Some(&facts(vec![
                ("path", json!(path)),
                ("folder", file.at("folder").clone()),
                ("app", json!(app)),
                ("size", file.at("size").clone()),
            ])),
            vec![],
        ));
    }
    let outlook = office.at("outlook");
    let vba = outlook.at("vba_project");
    if truthy(vba) {
        items.push(config(
            "outlook_vba",
            tr!("Outlook loads a VBA project at start"),
            25,
            tr!("Outlook runs the macros in VbaProject.OTM whenever it starts; malware uses it to stay on a computer"),
            Some(&facts(vec![
                ("path", vba.at("path").clone()),
                ("size", vba.at("size").clone()),
            ])),
            vec![],
        ));
    }
    for page in list(outlook.at("home_pages")) {
        items.push(config(
            "outlook_home_page",
            tr!("Outlook home page set: {0}", str_of(page.at("url"))),
            60,
            tr!("Outlook shows this web page inside the program, where it can run code: a known way to keep access to a computer"),
            Some(&facts(vec![("key", page.at("key").clone()), ("url", page.at("url").clone())])),
            vec![],
        ));
    }
    items
}

// --------------------------------------------------------------------------- firewall rules

/// Any remote address: empty, "*" or "Any".
fn any_remote(addresses: &str) -> bool {
    let a = lower(addresses.trim());
    a.is_empty() || a == "*" || a == "any"
}

/// The firewall rules the Firewall rules page marks (`sysconfig.firewall_rules`). Rules of Windows'
/// own groups only appear here when flagged; Remote Desktop's group is left to the Remote Desktop
/// setting. A rule for a program that no longer exists is housekeeping: one low summary.
fn firewall_rule_items(raw: &Value) -> Vec<Item> {
    let rules = raw.at("sysconfig").at("firewall_rules");
    let mut candidates = Vec::new();
    let mut missing = Vec::new();
    let mut writable = Vec::new();
    for rule in list(rules.at("flagged")) {
        let codes: Vec<String> = list(rule.at("flags")).iter().map(str_of).collect();
        let has = |code: &str| codes.iter().any(|c| c == code);
        let name = str_of(rule.at("name"));
        let program = text(rule.at("program"));
        if has("missing_program") {
            missing.push(json!({"name": name, "program": program}));
        }
        let public_any = list(rule.at("profiles")).iter().any(|p| str_of(p) == "public")
            && any_remote(&text(rule.at("remote_addresses")));
        let port = as_int(rule.at("port")).unwrap_or(0);
        let mut found: Vec<(String, String, i64, String)> = Vec::new();
        if has("open_public") {
            found.push((
                "firewall_open_public".into(),
                tr!("Firewall rule open to everyone on public networks: {0}", name),
                35,
                tr!("every program on this computer can be reached from any address on public networks (cafés, airports, hotels)"),
            ));
        }
        if has("remote_access") {
            found.push((
                "firewall_remote_access".into(),
                tr!("Firewall rule opens a remote-access port: {0} (port {1})", name, port),
                if public_any { 45 } else { 30 },
                if public_any {
                    tr!("lets any computer, also on public networks, reach port {0}, used to control a computer remotely", port)
                } else {
                    tr!("lets other computers reach port {0}, used to control a computer remotely", port)
                },
            ));
        }
        // Many programs install in the user's folders (and Windows' "allow this app" prompt adds
        // their rule): on its own, that is one summary, not a finding per rule.
        if has("writable_program") && found.is_empty() {
            writable.push(json!({"name": name, "program": program}));
            continue;
        }
        if has("writable_program") {
            found.push((
                "firewall_writable_program".into(),
                tr!("Firewall rule for a program in a folder anyone can change: {0}", name),
                30,
                tr!(
                    "any program could take the place of {0} and receive connections through this rule",
                    program
                ),
            ));
        }
        if found.is_empty() {
            continue;
        }
        found.sort_by_key(|f| std::cmp::Reverse(f.2));
        let (topic, title, score, text_main) = found.remove(0);
        let extra = found
            .into_iter()
            .map(|(code, _, weight, text)| Flag::new(code, weight, text))
            .collect();
        let detail = facts(vec![
            ("rule", json!(name)),
            ("group", rule.at("group").clone()),
            ("program", json!(program)),
            ("service", rule.at("service").clone()),
            ("direction", rule.at("direction").clone()),
            ("profiles", rule.at("profiles").clone()),
            ("protocol", rule.at("protocol").clone()),
            ("local_ports", rule.at("local_ports").clone()),
            ("remote_addresses", rule.at("remote_addresses").clone()),
            ("windows_group", rule.at("builtin").clone()),
        ]);
        candidates.push(config(&topic, title, score, text_main, Some(&detail), extra));
    }
    let mut items = top(candidates, 15);
    if !writable.is_empty() {
        items.push(config(
            "firewall_writable_program",
            tr!("Firewall rules for programs in folders anyone can change"),
            15,
            count_n(
                writable.len(),
                tl!("{0} rule lets in traffic for a program kept where any program could take its place"),
                tl!("{0} rules let in traffic for programs kept where any program could take their place"),
            ),
            Some(&facts(vec![(
                "rules",
                json!(writable.iter().take(30).collect::<Vec<_>>()),
            )])),
            vec![],
        ));
    }
    if !missing.is_empty() {
        items.push(config(
            "firewall_missing_programs",
            tr!("Firewall rules for programs that no longer exist"),
            5,
            count_n(
                // The inventory keeps a capped list; the count covers every rule.
                as_int(rules.at("missing")).map_or(missing.len(), |n| usize::try_from(n).unwrap_or(missing.len())),
                tl!("{0} rule lets in traffic for a program that was removed; a file put at that path would inherit it"),
                tl!("{0} rules let in traffic for programs that were removed; a file put at one of those paths would inherit it"),
            ),
            Some(&facts(vec![("rules", json!(missing.iter().take(30).collect::<Vec<_>>()))])),
            vec![],
        ));
    }
    items
}

/// Programs that change the firewall from a script or a command line.
const SCRIPTED_MODIFIERS: &[&str] = &["netsh.exe", "powershell.exe", "pwsh.exe", "wmiprvse.exe", "cmd.exe"];
/// Remote-access ports (Remote Desktop, SSH, Telnet, VNC, WinRM).
const REMOTE_PORTS: &[&str] = &["3389", "22", "23", "5900", "5985", "5986"];

/// Firewall changes from the Firewall log (`events.firewall_changes`). Windows changes its own
/// rules all the time (Store apps, features, the "allow this app" prompt), so a change made by a
/// Windows program for a Windows program or for no program is never reported. Rules added by
/// command line, rules opening remote-access ports to the network and rules for every program are
/// worth a look; any other rule added for a program outside Windows goes to one low summary.
fn firewall_change_items(events: &Value, days: &str) -> Vec<Item> {
    let mut items = Vec::new();
    let mut added = Vec::new();
    let mut deleted = 0usize;
    for change in list(events.at("firewall_changes")) {
        let id = int_of(change.at("id"));
        let by = text(change.at("by_app"));
        let by_name = lower(crate::ntpath::basename(&by));
        let scripted = SCRIPTED_MODIFIERS.contains(&by_name.as_str());
        let windows_modifier = !scripted && (by.is_empty() || crate::rules::in_windows_dir(&by));
        let program = text(change.at("program"));
        let windows_program = program.is_empty() || crate::rules::in_windows_dir(&program);
        let rule = str_of(change.at("rule"));
        let when = str_of(change.at("time"));
        let detail = facts(vec![
            ("rule", json!(rule)),
            ("program", json!(program)),
            ("changed_by", json!(by)),
            ("time", json!(when)),
            ("local_ports", change.at("local_ports").clone()),
        ]);
        match id {
            2004 | 2097 => {
                if windows_modifier && windows_program {
                    continue;
                }
                // Direction 1 is inbound; action 2 is block (the firewall's own numbering).
                let inbound = str_of(change.at("direction")) == "1";
                let allows = str_of(change.at("action")) != "2";
                let ports = text(change.at("local_ports"));
                let remote_port = ports.split(',').map(str::trim).find(|p| REMOTE_PORTS.contains(p));
                let every_program = program.is_empty() && text(change.at("service")).is_empty();
                let mut flags = Vec::new();
                if inbound && allows {
                    if scripted {
                        flags.push(Flag::new(
                            "firewall_rule_scripted",
                            35,
                            tr!("an inbound rule was added from a command line ({0})", by_name),
                        ));
                    }
                    if let Some(port) = remote_port {
                        flags.push(Flag::new(
                            "firewall_rule_remote_port",
                            35,
                            tr!(
                                "the new rule lets other computers reach port {0}, used to control a computer remotely",
                                port
                            ),
                        ));
                    }
                    if every_program && !windows_modifier {
                        flags.push(Flag::new(
                            "firewall_rule_every_program",
                            30,
                            tr!("the new rule lets in traffic for every program"),
                        ));
                    }
                }
                if flags.is_empty() {
                    if !windows_program {
                        added.push(json!({"rule": rule, "program": program, "by": by, "time": when}));
                    }
                    continue;
                }
                items.push(event(
                    tr!("Firewall rule added: {0}", rule),
                    tr!("on {0}", when),
                    flags,
                    detail,
                ));
            }
            2006 | 2052 => {
                if !windows_modifier {
                    deleted += 1;
                }
            }
            2003 if scripted => items.push(event(
                tr!("Firewall settings changed from a command line"),
                tr!("on {0}", when),
                vec![Flag::new(
                    "firewall_settings_scripted",
                    25,
                    tr!("{0} changed a firewall profile setting", by_name),
                )],
                with_fields(
                    detail,
                    &json!({"setting": change.at("setting"), "value": change.at("value")}),
                ),
            )),
            _ => {}
        }
    }
    if !added.is_empty() || deleted > 0 {
        items.push(event(
            tr!("Firewall rules added for programs"),
            tr!("in the last {0} days", days),
            vec![Flag::new(
                "firewall_rules_added",
                5,
                count_n(
                    added.len(),
                    tl!("{0} rule was added for a program outside Windows"),
                    tl!("{0} rules were added for programs outside Windows"),
                ),
            )],
            facts(vec![
                ("rules", json!(added.iter().take(20).collect::<Vec<_>>())),
                ("deleted_by_programs", json!(deleted)),
            ]),
        ));
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_compile() {
        for rx in [
            &*SENSITIVE_HOST,
            &*PSEUDO_PROCESSES,
            &*DNS_MINING,
            &*DNS_DYNAMIC,
            &*RISKY_POLICIES,
            &*BROAD_EXCLUSION,
            &*CN_RE,
            &*STORE_UPDATE,
        ] {
            assert!(rx.is_valid());
        }
    }

    #[test]
    fn counts_and_dates() {
        assert_eq!(count(&json!(1), tl!("{0} time"), tl!("{0} times")), "1 time");
        assert_eq!(count(&json!(3), tl!("{0} entry"), tl!("{0} entries")), "3 entries");
        assert_eq!(count(&Value::Null, tl!("{0} time"), tl!("{0} times")), "None times");
        assert!(days_since(&json!("2000-01-01")).is_some_and(|d| d > 9000));
        assert_eq!(days_since(&json!("not a date")), None);
    }
}
