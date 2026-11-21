//! Self-contained HTML report (no external resources) and JSON dump.
//!
//! Every piece of text that comes from the scanned machine (or from the AI) is escaped: a
//! malicious file or task name cannot inject markup or scripts into the report.

use std::collections::BTreeSet;

use chrono::Local;
use serde_json::{Map, Value, json};

use crate::analyze::signature_text;
use crate::lenient::{
    Get, as_number, capitalize_first, dumps_pretty, format_grouped, format_grouped_rounded, html_escape, list, obj,
    str_of, strip, take, text, truthy,
};
use crate::model::{Analysis, Item, VERDICTS, kind_label};
use vigil_i18n::{tl, tr};

const CSS: &str = include_str!("report.css");
const JS: &str = include_str!("report.js");
const DASH: &str = "<span class=\"muted\">—</span>";

fn verdict_label(verdict: &str) -> Option<&'static str> {
    Some(match verdict {
        "remove" => tl!("Remove"),
        "disable" => tl!("Disable"),
        "review" => tl!("Review"),
        "no_signals" => tl!("No signals"),
        "safe" => tl!("Safe"),
        "trusted" => tl!("Trusted"),
        _ => return None,
    })
}

fn verdict_help(verdict: &str) -> &'static str {
    match verdict {
        "remove" => tl!("Malicious, unwanted or a leftover worth cleaning up."),
        "disable" => tl!("Legitimate but dispensable: disable or uninstall it if you do not use it."),
        "review" => tl!("Could not be determined: check what is indicated."),
        "no_signals" => tl!("The local rules found nothing (it was not sent to the AI)."),
        "safe" => tl!("Legitimate and expected according to the analysis."),
        "trusted" => tl!("Microsoft components with a valid signature, verified automatically."),
        _ => "",
    }
}

fn level_label(level: &str) -> &'static str {
    match level {
        "critical" => tl!("critical"),
        "suspicious" => tl!("suspicious"),
        "attention" => tl!("attention"),
        "no_signals" => tl!("no signals"),
        _ => tl!("trusted"),
    }
}

fn risk_label(level: &str) -> Option<&'static str> {
    Some(match level {
        "low" => tl!("Low risk"),
        "moderate" => tl!("Moderate risk"),
        "high" => tl!("High risk"),
        "critical" => tl!("Critical risk"),
        _ => return None,
    })
}

/// Labels for the report's own field names when the generic rule is not enough.
fn fact_label(key: &str) -> Option<&'static str> {
    Some(match key {
        "ext_id" => tl!("Extension ID"),
        "sites" => tl!("Sites it can access"),
        "updates_from" => tl!("Updates from"),
        "uninstall" => tl!("Uninstall command"),
        "actions" => tl!("Defender actions"),
        "decoded" => tl!("Decoded content"),
        "msix_package" => tl!("MSIX package"),
        "host" => tl!("Interpreter"),
        "chain" => tl!("Interpreter chain"),
        "running" => tl!("Running components"),
        "topic" => tl!("Rule"),
        "is_administrator" => tl!("Scanned as administrator"),
        "signature_age_days" => tl!("Definition age (days)"),
        "realtime_protection" => tl!("Real-time protection"),
        "tamper_protection" => tl!("Tamper protection"),
        "remote_desktop" => tl!("Remote Desktop"),
        _ => return None,
    })
}

/// Words with a fixed spelling (acronyms and product names) inside a generated label.
fn word_form(word: &str) -> Option<&'static str> {
    Some(match word {
        "id" => "ID",
        "ids" => "IDs",
        "uac" => "UAC",
        "rdp" => "RDP",
        "nla" => "NLA",
        "dns" => "DNS",
        "wmi" => "WMI",
        "pid" => "PID",
        "pids" => "PIDs",
        "sid" => "SID",
        "url" => "URL",
        "urls" => "URLs",
        "ip" => "IP",
        "tcp" => "TCP",
        "udp" => "UDP",
        "os" => "OS",
        "dll" => "DLL",
        "lsa" => "LSA",
        "msix" => "MSIX",
        "appx" => "AppX",
        "sha256" => "SHA-256",
        "ai" => "AI",
        "powershell" => "PowerShell",
        "smartscreen" => "SmartScreen",
        "virustotal" => "VirusTotal",
        "defender" => "Defender",
        "windows" => "Windows",
        "microsoft" => "Microsoft",
        _ => return None,
    })
}

fn esc(text: &str) -> String {
    html_escape(text)
}

/// `esc(value)`: `None` is empty, anything else is `str(value)`.
fn esc_v(value: &Value) -> String {
    if value.is_null() {
        String::new()
    } else {
        html_escape(&str_of(value))
    }
}

/// Readable name of one of the report's own fields (never applied to data from the machine).
fn label(key: &str) -> String {
    if let Some(fixed) = fact_label(key) {
        return tr!(fixed);
    }
    let words: Vec<String> = key
        .replace('_', " ")
        .split(' ')
        .map(|word| word_form(&word.to_lowercase()).map_or_else(|| word.to_string(), str::to_string))
        .collect();
    capitalize_first(&words.join(" "))
}

/// '1 service', '3 services': both forms are whole templates (`tl!`), so each language places the number.
fn count(number: &Value, one: &'static str, many: &'static str) -> String {
    let n = str_of(number);
    if as_number(number) == Some(1.0) {
        tr!(one, n)
    } else {
        tr!(many, n)
    }
}

/// Readable labels for structures whose keys are defined by the scan itself.
fn pretty_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (label(k), pretty_keys(v))).collect()),
        other => other.clone(),
    }
}

fn is_blank(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// Renders nested values (dict/list) as escaped HTML.
fn value_html(value: &Value, depth: usize) -> String {
    match value {
        Value::Null => DASH.into(),
        Value::String(s) if s.is_empty() => DASH.into(),
        Value::Bool(b) => (if *b { "yes" } else { "no" }).into(),
        Value::Object(map) => {
            if depth >= 3 {
                return format!("<pre>{}</pre>", esc(&dumps_pretty(value)));
            }
            let rows: String = map
                .iter()
                .map(|(k, v)| format!("<tr><th>{}</th><td>{}</td></tr>", esc(k), value_html(v, depth + 1)))
                .collect();
            if rows.is_empty() {
                DASH.into()
            } else {
                format!("<table>{rows}</table>")
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                return DASH.into();
            }
            format!(
                "<ul>{}</ul>",
                items
                    .iter()
                    .map(|v| format!("<li>{}</li>", value_html(v, depth + 1)))
                    .collect::<String>()
            )
        }
        other => esc_v(other),
    }
}

fn rows(pairs: &[(&str, Value)]) -> String {
    let body: String = pairs
        .iter()
        .filter(|(_, v)| !is_blank(v))
        .map(|(k, v)| format!("<tr><th>{}</th><td>{}</td></tr>", esc(&tr!(*k)), value_html(v, 0)))
        .collect();
    if body.is_empty() {
        String::new()
    } else {
        format!("<table>{body}</table>")
    }
}

fn file_table(item: &Item) -> String {
    let info = item.file.clone().unwrap_or_default();
    let size = match info.at("size") {
        v @ (Value::Number(_) | Value::Bool(_)) => json!(format!(
            "{} KB",
            format_grouped_rounded(as_number(v).unwrap_or(0.0) / 1024.0)
        )),
        _ => Value::Null,
    };
    let when = |key: &str| json!(text(info.at(key)).replace('T', " "));
    let mut pairs = vec![
        (tl!("Path"), json!(item.path)),
        (tl!("Digital signature"), json!(signature_text(item))),
        (tl!("Description"), info.at("description").clone()),
        (tl!("Publisher"), info.at("company").clone()),
        (tl!("Product"), info.at("product").clone()),
        (tl!("Version"), info.at("version").clone()),
        (tl!("Original name"), info.at("original").clone()),
        (tl!("Size"), size),
        (tl!("Created"), when("created")),
        (tl!("Modified"), when("modified")),
        ("SHA-256", json!(item.sha256)),
    ];
    if let Some(vt) = item.vt.as_ref().filter(|v| !v.is_empty()) {
        pairs.push((tl!("VirusTotal"), vt.at("summary").clone()));
    }
    rows(&pairs)
}

fn steps(item: &Item) -> String {
    if item.remediation.is_empty() {
        return String::new();
    }
    let mut parts = String::new();
    for step in &item.remediation {
        let mut marks = String::new();
        if truthy(step.at("admin")) {
            marks.push_str(&format!(
                " <span class=\"tag\">{}</span>",
                tr!("requires administrator")
            ));
        }
        if truthy(step.at("danger")) {
            marks.push_str(&format!(" <span class=\"tag warn\">{}</span>", tr!("irreversible")));
        }
        let mut body = format!("<div class=\"t\">{}{marks}</div>", esc_v(step.at("title")));
        if truthy(step.at("command")) {
            body.push_str(&format!(
                "<div><pre>{}</pre><button class=\"copy\" type=\"button\">{}</button></div>",
                esc_v(step.at("command")),
                tr!("Copy")
            ));
        }
        if truthy(step.at("url")) {
            let raw_url = str_of(step.at("url"));
            let url = esc(&raw_url);
            // Saved reports can be edited by anyone: only web links become clickable.
            if raw_url.starts_with("https://") {
                body.push_str(&format!(
                    "<div><a href=\"{url}\" target=\"_blank\" rel=\"noopener noreferrer\">{url}</a></div>"
                ));
            } else {
                body.push_str(&format!("<div>{url}</div>"));
            }
        }
        if truthy(step.at("note")) {
            body.push_str(&format!("<div class=\"small muted\">{}</div>", esc_v(step.at("note"))));
        }
        parts.push_str(&format!("<div class=\"step\">{body}</div>"));
    }
    format!(
        "<details><summary>{}</summary>{parts}</details>",
        tr!("How to do it (steps and PowerShell commands)")
    )
}

fn evidence(item: &Item) -> String {
    let mut blocks: Vec<String> = Vec::new();
    if item.kind == "executable" {
        blocks.push(file_table(item));
    }
    if item.kind == "group" {
        let rows: String = item
            .members
            .iter()
            .map(|m| {
                let description = if truthy(m.at("description")) {
                    m.at("description")
                } else {
                    m.at("company")
                };
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc_v(m.at("name")),
                    esc_v(description),
                    value_html(m.at("roles"), 0),
                    esc_v(m.at("path"))
                )
            })
            .collect();
        blocks.push(format!(
            "<table class=\"list\"><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>{rows}</table>",
            tr!("Component"),
            tr!("Description"),
            tr!("Presence"),
            tr!("Path")
        ));
    } else if !item.roles.is_empty() {
        let roles: String = item
            .roles
            .iter()
            .map(|r| format!("<li>{}</li>", esc(&r.label)))
            .collect();
        blocks.push(format!(
            "<b class='small'>{}</b><ul>{roles}</ul>",
            tr!("Presence on the system")
        ));
    }
    if !item.commands.is_empty() {
        let commands: String = item.commands.iter().map(|c| format!("<pre>{}</pre>", esc(c))).collect();
        blocks.push(format!("<b class='small'>{}</b>{commands}", tr!("Command line")));
    }
    if !item.decoded.is_empty() {
        let decoded: String = item
            .decoded
            .iter()
            .map(|d| format!("<pre>{}</pre>", esc(take(d, 4000))))
            .collect();
        blocks.push(format!(
            "<b class='small'>{}</b>{decoded}",
            tr!("Decoded content (Base64)")
        ));
    }
    if !item.network.is_empty() {
        blocks.push(format!(
            "<b class='small'>{}</b>{}",
            tr!("Network"),
            rows(&[
                (tl!("Listening ports"), item.network.at("listen").clone()),
                (tl!("Reachable from the network"), item.network.at("exposed").clone()),
                (tl!("Connections to the internet"), item.network.at("remote").clone()),
            ])
        ));
    }
    // Only top-level keys get a label: nested ones may be data from the machine.
    let facts: Map<String, Value> = item
        .facts
        .iter()
        .filter(|(_, v)| !is_blank(v))
        .map(|(k, v)| (label(k), v.clone()))
        .collect();
    if !facts.is_empty() {
        blocks.push(format!(
            "<b class='small'>{}</b>{}",
            tr!("Details"),
            value_html(&Value::Object(facts), 0)
        ));
    }
    if !item.flags.is_empty() {
        let mut flags: Vec<_> = item.flags.iter().collect();
        flags.sort_by_key(|f| -f.weight);
        let list: String = flags
            .iter()
            .map(|f| format!("<li>{} <span class='muted'>(+{})</span></li>", esc(&f.text), f.weight))
            .collect();
        blocks.push(format!(
            "<b class='small'>{}</b><ul>{list}</ul>",
            tr!("Local signals · score {0}/100", item.score)
        ));
    }
    if blocks.is_empty() {
        return String::new();
    }
    format!(
        "<details><summary>{}</summary>{}</details>",
        tr!("Evidence"),
        blocks.concat()
    )
}

fn search_text(item: &Item) -> String {
    let mut parts: Vec<String> = vec![
        item.id.clone(),
        item.title.clone(),
        item.subtitle.clone(),
        item.path.clone().unwrap_or_default(),
        item.what.clone(),
        item.reason.clone(),
        tr!(kind_label(&item.kind).unwrap_or("")),
    ];
    parts.extend(item.members.iter().map(|m| text(m.at("name"))));
    parts.retain(|p| !p.is_empty());
    parts.join(" ").to_lowercase()
}

fn kind_text(kind: &str) -> String {
    kind_label(kind).map_or_else(|| kind.to_string(), |label| tr!(label))
}

fn card(item: &Item) -> String {
    let verdict = if item.verdict.is_empty() {
        "review"
    } else {
        item.verdict.as_str()
    };
    let mut badges = format!(
        "<span class=\"badge b-{}\">{}</span>",
        esc(verdict),
        esc(&tr!(verdict_label(verdict).unwrap_or(verdict)))
    );
    badges.push_str(&format!("<span class=\"tag\">{}</span>", esc(&kind_text(&item.kind))));
    let level = item.level();
    if matches!(level, "critical" | "suspicious" | "attention") {
        badges.push_str(&format!(
            "<span class=\"tag\">{}</span>",
            tr!("local risk: {0} ({1})", esc(&tr!(level_label(level))), item.score)
        ));
    }
    if !item.confidence.is_empty() {
        badges.push_str(&format!(
            "<span class=\"tag\">{}</span>",
            tr!("AI confidence: {0}", esc(&item.confidence))
        ));
    }
    if item.verdict_source == "heuristic" {
        badges.push_str(&format!("<span class=\"tag\">{}</span>", tr!("no AI analysis")));
    }
    let mut says = String::new();
    for (name, value) in [
        (tl!("What it is"), &item.what),
        (tl!("Why"), &item.reason),
        (tl!("What to do"), &item.action),
    ] {
        if !value.is_empty() {
            says.push_str(&format!("<dt>{}</dt><dd>{}</dd>", tr!(name), esc(value)));
        }
    }
    let actionable = matches!(verdict, "remove" | "disable" | "review");
    format!(
        "<article class=\"item row v-{v}\" id=\"item-{id}\" data-verdict=\"{v}\" data-kind=\"{kind}\" data-text=\"{search}\"><header><h3>{title}</h3>{badges}<span class=\"tag\">{id}</span></header><div class=\"sub\">{subtitle}</div>{says}{steps}{evidence}</article>",
        v = esc(verdict),
        id = esc(&item.id),
        kind = esc(&item.kind),
        search = esc(&search_text(item)),
        title = esc(&item.title),
        subtitle = esc(&item.subtitle),
        says = if says.is_empty() {
            String::new()
        } else {
            format!("<dl class=\"says\">{says}</dl>")
        },
        steps = if actionable { steps(item) } else { String::new() },
        evidence = evidence(item),
    )
}

fn compact_table(items: &[&Item]) -> String {
    let rows: String = items
        .iter()
        .map(|item| {
            let detail = item.path.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| item.subtitle.clone());
            format!(
                "<tr class=\"row\" data-verdict=\"{}\" data-kind=\"{}\" data-text=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class='muted'>{}</td></tr>",
                esc(&item.verdict),
                esc(&item.kind),
                esc(&search_text(item)),
                esc(&item.id),
                esc(&kind_text(&item.kind)),
                esc(&item.title),
                esc(&item.what),
                esc(&detail)
            )
        })
        .collect();
    format!(
        "<table class=\"list\"><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>{rows}</table>",
        tr!("ID"),
        tr!("Type"),
        tr!("Item"),
        tr!("What it is"),
        tr!("Detail")
    )
}

fn summary_panel(analysis: &Analysis) -> String {
    let Some(summary) = analysis.summary.as_ref().filter(|s| truthy(s)) else {
        let reason = text(analysis.ai.at("reason"));
        let reason = capitalize_first(&if reason.is_empty() {
            tr!("it was not requested")
        } else {
            reason
        });
        return format!(
            "<div class=\"panel risk\"><div class=\"level\">{}</div><div class=\"headline\">{}</div><p>{}</p></div>",
            tr!("No AI analysis"),
            tr!("Report based on local rules only"),
            tr!(
                "{0}. Items are sorted by their local risk score; \"Review\" means that a rule found something, not that the item is malicious.",
                esc(&reason)
            )
        );
    };
    let level = summary.get("risk_level").cloned().unwrap_or_else(|| json!(""));
    let summary_text = summary.get("summary").map_or_else(String::new, str_of);
    let paragraphs: String = summary_text
        .split('\n')
        .filter(|p| !strip(p).is_empty())
        .map(|p| format!("<p>{}</p>", esc(p)))
        .collect();
    let mut actions = String::new();
    for action in list(summary.at("priority_actions")) {
        let links: Vec<String> = list(action.at("ids"))
            .iter()
            .map(|i| format!("<a href=\"#item-{0}\">{0}</a>", esc_v(i)))
            .collect();
        let links = links.join(" ");
        actions.push_str(&format!(
            "<li><b>{}</b><br>{}{}</li>",
            esc_v(action.at("title")),
            esc_v(action.at("detail")),
            if links.is_empty() {
                String::new()
            } else {
                format!(" <span class=\"small muted\">{}</span>", tr!("Related: {0}", links))
            }
        ));
    }
    let practices: String = list(summary.at("good_practices"))
        .iter()
        .map(|p| format!("<li>{}</li>", esc_v(p)))
        .collect();
    let level_text = level
        .as_str()
        .and_then(risk_label)
        .map_or_else(|| esc_v(&level), |label| tr!(label));
    format!(
        "<div class=\"panel risk {}\"><div class=\"level\">{}</div><div class=\"headline\">{}</div>{paragraphs}</div>{}{}",
        esc_v(&level),
        level_text,
        esc_v(summary.at("headline")),
        if actions.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"panel\"><h3>{}</h3><ol class=\"actions\">{actions}</ol></div>",
                tr!("What to do first")
            )
        },
        if practices.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"panel\"><h3>{}</h3><ul>{practices}</ul></div>",
                tr!("Recommendations for this computer")
            )
        },
    )
}

fn get_or(map: &Map<String, Value>, key: &str, default: Value) -> Value {
    map.get(key).cloned().unwrap_or(default)
}

/// The report as a self-contained HTML page.
pub fn render_html(analysis: &Analysis) -> String {
    let (meta, stats) = (&analysis.meta, &analysis.stats);
    let mut by_verdict: Vec<(String, Vec<&Item>)> = VERDICTS.iter().map(|v| (v.to_string(), Vec::new())).collect();
    for item in &analysis.items {
        let verdict = if item.verdict.is_empty() {
            "review"
        } else {
            item.verdict.as_str()
        };
        match by_verdict.iter_mut().find(|(v, _)| v == verdict) {
            Some((_, items)) => items.push(item),
            None => by_verdict.push((verdict.to_string(), vec![item])),
        }
    }
    let group = |verdict: &str| {
        by_verdict
            .iter()
            .find(|(v, _)| v == verdict)
            .map(|(_, items)| items.as_slice())
            .unwrap_or(&[])
    };

    let mut chips = String::new();
    for verdict in VERDICTS {
        let n = group(verdict).len();
        if n == 0 {
            continue;
        }
        let pressed = if verdict == "trusted" { "false" } else { "true" };
        chips.push_str(&format!(
            "<button class=\"chip b-{verdict}\" type=\"button\" data-verdict=\"{verdict}\" aria-pressed=\"{pressed}\" title=\"{}\"><span class=\"dot\"></span>{} <b>{n}</b></button>",
            esc(&tr!(verdict_help(verdict))),
            esc(&tr!(verdict_label(verdict).unwrap_or(verdict)))
        ));
    }
    let kinds: BTreeSet<&str> = analysis.items.iter().map(|i| i.kind.as_str()).collect();
    let options = format!(
        "<option value=\"\">{}</option>{}",
        tr!("All types"),
        kinds
            .iter()
            .map(|k| format!("<option value=\"{}\">{}</option>", esc(k), esc(&kind_text(k))))
            .collect::<String>()
    );

    let mut sections = String::new();
    for verdict in ["remove", "disable", "review"] {
        let items = group(verdict);
        if !items.is_empty() {
            sections.push_str(&format!(
                "<section data-section=\"{verdict}\"><h2>{} · {}</h2><p class=\"muted small\">{}</p>{}</section>",
                esc(&tr!(verdict_label(verdict).unwrap_or(verdict))),
                items.len(),
                esc(&tr!(verdict_help(verdict))),
                items.iter().map(|i| card(i)).collect::<String>()
            ));
        }
    }
    for verdict in ["no_signals", "safe", "trusted"] {
        let items = group(verdict);
        if !items.is_empty() {
            sections.push_str(&format!(
                "<section data-section=\"{verdict}\"><h2>{} · {}</h2><p class=\"muted small\">{}</p><div class=\"panel\">{}</div></section>",
                esc(&tr!(verdict_label(verdict).unwrap_or(verdict))),
                items.len(),
                esc(&tr!(verdict_help(verdict))),
                compact_table(items)
            ));
        }
    }

    let ai = &analysis.ai;
    let mut ai_line = tr!("not used");
    if truthy(ai.at("provider")) {
        let usage = obj(ai.at("usage"));
        ai_line = tr!(
            "{0} · {1} of {2} items classified · {3} input tokens, {4} output tokens",
            str_of(ai.at("destination")),
            str_of(&get_or(ai, "with_verdict", json!(0))),
            str_of(&get_or(ai, "sent", json!(0))),
            format_grouped(&get_or(usage, "input_tokens", json!(0))),
            format_grouped(&get_or(usage, "output_tokens", json!(0)))
        );
        if truthy(usage.at("cost_usd")) {
            ai_line.push_str(&tr!(
                " · approximate cost {0} USD",
                format!("{:.2}", as_number(usage.at("cost_usd")).unwrap_or(0.0))
            ));
        }
    }
    let started = str_of(&get_or(meta, "started", json!("")));
    let header_facts: Vec<(&str, Value)> = vec![
        (tl!("Scan date"), json!(started.replace('T', " "))),
        (tl!("Computer"), analysis.posture.at("computer").clone()),
        (tl!("System"), analysis.posture.at("system").clone()),
        (
            tl!("Privileges"),
            json!(if truthy(meta.at("is_admin")) {
                tr!("administrator (full coverage)")
            } else {
                tr!("standard user (partial coverage)")
            }),
        ),
        (
            tl!("Events reviewed"),
            json!(tr!("last {0}", count(meta.at("days"), tl!("{0} day"), tl!("{0} days")))),
        ),
        (tl!("AI analysis"), json!(ai_line)),
        (
            tl!("Inventory"),
            json!(
                [
                    count(stats.at("processes"), tl!("{0} process"), tl!("{0} processes")),
                    count(stats.at("services"), tl!("{0} service"), tl!("{0} services")),
                    count(stats.at("drivers"), tl!("{0} driver"), tl!("{0} drivers")),
                    count(stats.at("tasks"), tl!("{0} task"), tl!("{0} tasks")),
                    count(stats.at("programs"), tl!("{0} program"), tl!("{0} programs")),
                    count(stats.at("extensions"), tl!("{0} extension"), tl!("{0} extensions")),
                ]
                .join(" · ")
            ),
        ),
        (tl!("Files verified"), stats.at("files_verified").clone()),
    ];
    let facts_html: String = header_facts
        .iter()
        .filter(|(_, v)| !(v.is_null() || v.as_str() == Some("")))
        .map(|(k, v)| format!("<div><b>{}</b>{}</div>", esc(&tr!(*k)), esc_v(v)))
        .collect();

    let mut notes: String = analysis
        .notes
        .iter()
        .map(|n| {
            let area = n.get("area").map_or_else(String::new, str_of);
            format!("<li><b>{}:</b> {}</li>", esc(&label(&area)), esc_v(n.at("message")))
        })
        .collect();
    for error in list(ai.at("errors")) {
        notes.push_str(&format!("<li><b>{}</b> {}</li>", tr!("AI:"), esc_v(error)));
    }
    let posture: Map<String, Value> = analysis
        .posture
        .iter()
        .filter(|(k, _)| k.as_str() != "computer" && k.as_str() != "system")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let posture = pretty_keys(&Value::Object(posture));

    let generated = Local::now().format("%Y-%m-%d %H:%M").to_string();
    format!(
        r#"<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>{t_title} · {title_date}</title>
<style>{CSS}</style>
</head>
<body>
<main>
<h1>{t_title}</h1>
<div class="muted">{t_intro}</div>
<div class="panel"><div class="kv">{facts_html}</div></div>
{summary}
<div class="panel small">{t_before}</div>
{notes_block}{changes_block}
<div class="toolbar">
<div class="chips">{chips}</div>
<input id="q" type="search" placeholder="{t_search}" aria-label="{t_search_label}">
<select id="kind" aria-label="{t_type}">{options}</select>
<span class="small muted">{t_showing}</span>
</div>
{sections}
<h2>{t_posture}</h2>
<div class="panel">{posture}</div>
<h2>{t_next}</h2>
<div class="panel"><ul>
<li>{t_next1}</li>
<li>{t_next2}</li>
<li>{t_next3}</li>
<li>{t_next4}</li>
</ul></div>
<footer>{t_footer}</footer>
</main>
<script>{JS}</script>
</body>
</html>
"#,
        title_date = esc(take(&started, 10)),
        lang = vigil_i18n::language_tag(vigil_i18n::language()),
        t_title = tr!("Vigil — security scan report"),
        t_intro = if analysis.summary.as_ref().is_some_and(truthy) {
            tr!("Read-only inventory of this computer, evaluated with local rules and AI.")
        } else {
            tr!("Read-only inventory of this computer, evaluated with local rules.")
        },
        t_before = tr!(
            "<b>Before you change anything:</b> this report is guidance; it does not replace an antivirus or your own judgment.\nVerdicts (the AI's too) can be wrong. Do not delete anything you do not understand; prefer disabling over removing,\nand create a restore point before making changes. The scan did not modify anything on your computer."
        ),
        t_search = tr!("Search by name, path or ID"),
        t_search_label = tr!("Search"),
        t_type = tr!("Type"),
        t_showing = tr!("Showing {0} items", "<span id=\"shown\">0</span>"),
        t_posture = tr!("System security posture"),
        t_next = tr!("Recommended next steps"),
        t_next1 = tr!(
            "This scan covers what <b>runs or starts on its own</b>. It does not examine every file on the disk: complement it with a full\nMicrosoft Defender scan ({0}) or an offline scan from Windows Security.",
            "<code>Start-MpScan -ScanType FullScan</code>"
        ),
        t_next2 = tr!(
            "For unsigned executables, use the VirusTotal link on each card: it looks up the reputation by hash, without uploading the file."
        ),
        t_next3 = tr!(
            "If you confirm an infection, change your passwords from another device and turn on two-step verification."
        ),
        t_next4 =
            tr!("Run the scan again as administrator to cover the Security event log and the antivirus exclusions."),
        t_footer = tr!(
            "Generated on {0} by Vigil v{1}. This file contains sensitive information about your computer: do not publish it.",
            esc(&generated),
            esc_v(meta.at("tool_version"))
        ),
        summary = summary_panel(analysis),
        notes_block = if notes.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"panel small\"><b>{}</b><ul>{notes}</ul></div>",
                tr!("Limitations of this scan")
            )
        },
        posture = value_html(&posture, 0),
        changes_block = changes_panel(analysis),
    )
}

/// "Changes since the last scan": new, gone and changed items and settings (empty for a first scan).
fn changes_panel(analysis: &Analysis) -> String {
    let Some(changes) = analysis.changes.as_ref().filter(|c| c.is_object()) else {
        return String::new();
    };
    let title_of = |id: &str| {
        analysis
            .items
            .iter()
            .find(|i| i.id == id)
            .map(|i| i.title.clone())
            .unwrap_or_else(|| id.to_string())
    };
    let mut lines = String::new();
    for id in list(changes.at("new")) {
        let id = str_of(id);
        let verdict = analysis
            .items
            .iter()
            .find(|i| i.id == id)
            .map(|i| i.verdict.clone())
            .unwrap_or_default();
        let badge = verdict_label(&verdict)
            .map(|l| format!(" <span class=\"muted\">· {}</span>", esc(&tr!(l))))
            .unwrap_or_default();
        lines.push_str(&format!(
            "<li><b>{}</b> {}{badge}</li>",
            esc(&tr!("New:")),
            esc(&title_of(&id))
        ));
    }
    for item in list(changes.at("changed")) {
        let what: Vec<String> = list(item.at("what")).iter().map(|w| esc(&str_of(w))).collect();
        lines.push_str(&format!(
            "<li><b>{}</b> {}<br><span class=\"muted small\">{}</span></li>",
            esc(&tr!("Changed:")),
            esc(&title_of(&str_of(item.at("id")))),
            what.join(" · ")
        ));
    }
    for item in list(changes.at("gone")) {
        lines.push_str(&format!(
            "<li><b>{}</b> {}</li>",
            esc(&tr!("Gone:")),
            esc(&str_of(item.at("title")))
        ));
    }
    for line in list(changes.at("posture")) {
        lines.push_str(&format!(
            "<li><b>{}</b> {}</li>",
            esc(&tr!("Setting:")),
            esc(&str_of(line))
        ));
    }
    if lines.is_empty() {
        lines = format!("<li>{}</li>", esc(&tr!("Nothing changed.")));
    }
    let started = str_of(changes.at("previous").at("started")).replace('T', " ");
    format!(
        "<h2>{}</h2><div class=\"panel\"><p class=\"muted small\">{}</p><ul>{lines}</ul></div>",
        esc(&tr!("Changes since the last scan")),
        esc(&tr!("Compared with the scan of {0}.", take(&started, 16)))
    )
}

/// The `-report.json` content (one-space indent, stable key order).
pub fn render_json(analysis: &Analysis) -> String {
    dumps_pretty(&analysis.to_value())
}
