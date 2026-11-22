//! Findings exported for other people and tools: CSV (one row per finding, for a spreadsheet) and
//! SARIF 2.1.0 (for security tools), next to the existing HTML report.
//!
//! Everything in a report came from the computer, so it is untrusted: CSV cells that a spreadsheet
//! would read as a formula are neutralised, every text goes through the same secret scrubber as
//! the report's excerpts, and the optional anonymization is the AI review's own [`Redactor`].

use serde_json::{Map, Value, json};

use crate::lenient::{Get, list, str_of, text};
use crate::model::{Analysis, Item, verdict_rank};
use crate::privacy::{Redactor, scrub_secrets};

/// What a report can be exported as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Csv,
    Sarif,
    Html,
    Json,
}

impl Format {
    /// `csv`, `sarif`, `html` or `json` (any case).
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "csv" => Some(Self::Csv),
            "sarif" => Some(Self::Sarif),
            "html" => Some(Self::Html),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    /// The file extension, without the dot.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Sarif => "sarif",
            Self::Html => "html",
            Self::Json => "json",
        }
    }
}

/// How the findings are exported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// Replace the user and computer names, the other local account names, the domain and every
    /// profile folder's name, like the AI review does. Off by default: a local file stays useful.
    pub anonymize: bool,
    /// Include the Microsoft components verified automatically (left out by default: there are
    /// hundreds and none needs a look).
    pub include_trusted: bool,
}

/// The analysis as it will be exported: anonymized when asked.
pub fn prepare(analysis: &Analysis, options: Options) -> Analysis {
    if !options.anonymize {
        return analysis.clone();
    }
    let meta = |key: &str| text(analysis.meta.at(key));
    let redactor = Redactor::for_this_computer(&meta("user"), &meta("computer"), true);
    Analysis::from_value(&redactor.apply(&analysis.to_value()))
}

/// The export as bytes, ready to be written to a file.
pub fn render(analysis: &Analysis, format: Format, options: Options) -> Vec<u8> {
    let prepared = prepare(analysis, options);
    match format {
        Format::Csv => csv(&prepared, options).into_bytes(),
        Format::Sarif => sarif(&prepared, options).into_bytes(),
        Format::Html => crate::report::render_html(&prepared).into_bytes(),
        Format::Json => crate::report::render_json(&prepared).into_bytes(),
    }
}

/// How many findings an export with these options holds.
pub fn count(analysis: &Analysis, options: Options) -> usize {
    findings(analysis, options).len()
}

/// The findings to export, most severe first.
fn findings(analysis: &Analysis, options: Options) -> Vec<&Item> {
    let mut items: Vec<&Item> = analysis
        .items
        .iter()
        .filter(|i| options.include_trusted || !(i.trusted || i.verdict == "trusted"))
        .collect();
    items.sort_by(|a, b| {
        verdict_rank(&a.verdict)
            .cmp(&verdict_rank(&b.verdict))
            .then(b.score.cmp(&a.score))
            .then(a.title.cmp(&b.title))
    });
    items
}

/// "new", "changed" or "" for an item, from the report's comparison with the previous scan.
fn since_last_scan(analysis: &Analysis, id: &str) -> &'static str {
    let Some(changes) = analysis.changes.as_ref() else {
        return "";
    };
    if list(changes.at("new")).iter().any(|v| str_of(v) == id) {
        "new"
    } else if list(changes.at("changed")).iter().any(|v| str_of(v.at("id")) == id) {
        "changed"
    } else {
        ""
    }
}

/// A text that may carry raw system data (a command line, the AI's own words), safe to hand out:
/// secrets masked like the report's excerpts, one line, at most `limit` characters.
fn clean(value: &str, limit: usize) -> String {
    flat(&scrub_secrets(value), limit)
}

/// A text Vigil wrote itself from what it found (a title, a path, a role): one line, at most
/// `limit` characters. Not masked, because a generic "password: …" rule would hide the path in
/// "Windows setup file keeps a password: C:\…"; secret values never reach these fields.
fn plain(value: &str, limit: usize) -> String {
    flat(value, limit)
}

/// The name and details of a finding: a command item's title is the command line itself, so it
/// is masked; other titles are Vigil's own.
fn heading(item: &Item, value: &str, limit: usize) -> String {
    if item.kind == "command" {
        clean(value, limit)
    } else {
        plain(value, limit)
    }
}

fn flat(value: &str, limit: usize) -> String {
    let flat: String = value
        .chars()
        .map(|c| if c.is_control() && c != '\t' { ' ' } else { c })
        .collect();
    let flat = flat.trim();
    if flat.chars().count() <= limit {
        flat.to_string()
    } else {
        format!("{}…", flat.chars().take(limit).collect::<String>())
    }
}

fn file_field(item: &Item, key: &str) -> String {
    item.file.as_ref().map(|f| text(f.at(key))).unwrap_or_default()
}

// ------------------------------------------------------------------------------------------- CSV

/// The CSV columns (stable, English: tools read them by name).
pub const CSV_COLUMNS: [&str; 20] = [
    "id",
    "verdict",
    "verdict_source",
    "confidence",
    "score",
    "level",
    "kind",
    "name",
    "details",
    "path",
    "sha256",
    "signer",
    "signature",
    "appears_in",
    "command",
    "flags",
    "signals",
    "reason",
    "recommended_action",
    "since_last_scan",
];

/// Characters that make a spreadsheet read what follows as a formula.
const FORMULA_START: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];
/// Characters a spreadsheet may split cells on: `,`, and `;` in the locales that use a decimal
/// comma (Spanish, French, Portuguese…), where a cell can be cut in two whatever the quoting.
const SPLITS: [char; 5] = [',', ';', '\t', '\r', '\n'];

/// One CSV cell, always quoted (RFC 4180). Every place a spreadsheet could start a cell (the
/// start, and after a `,` or `;`, which some locales split on even inside quotes) is neutralised
/// with a `'` when a formula character follows.
pub fn csv_cell(value: &str) -> String {
    let mut guarded = String::with_capacity(value.len() + 2);
    let mut at_start = true;
    for ch in value.chars() {
        if at_start && FORMULA_START.contains(&ch) {
            guarded.push('\'');
        }
        guarded.push(ch);
        at_start = SPLITS.contains(&ch);
    }
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

/// The findings as CSV: UTF-8 with a byte order mark (so spreadsheets read accents correctly),
/// CRLF line ends, one header row.
pub fn csv(analysis: &Analysis, options: Options) -> String {
    let mut out = String::from('\u{feff}');
    let line = |cells: Vec<String>| cells.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(",") + "\r\n";
    out.push_str(&line(CSV_COLUMNS.iter().map(|c| (*c).to_string()).collect()));
    for item in findings(analysis, options) {
        let roles: Vec<String> = item.roles.iter().map(|r| plain(&r.label, 200)).collect();
        // A role's command, the item's own commands, or the excerpt an event finding keeps (the
        // PowerShell history line): all masked again on the way out.
        let fact_command = text(item.facts.at("command"));
        let command = item
            .roles
            .iter()
            .map(|r| r.command.as_str())
            .chain(item.commands.iter().map(String::as_str))
            .chain(std::iter::once(fact_command.as_str()))
            .find(|c| !c.trim().is_empty())
            .unwrap_or("");
        let row = vec![
            plain(&item.id, 80),
            plain(&item.verdict, 40),
            plain(&item.verdict_source, 40),
            plain(&item.confidence, 40),
            item.score.to_string(),
            item.level().to_string(),
            plain(&item.kind, 40),
            heading(item, &item.title, 300),
            heading(item, &item.subtitle, 300),
            plain(item.path.as_deref().unwrap_or(""), 1000),
            plain(item.sha256.as_deref().unwrap_or(""), 64),
            plain(&file_field(item, "signer"), 200),
            plain(&file_field(item, "sig_status"), 40),
            roles.join("; "),
            clean(command, 1000),
            item.flags
                .iter()
                .map(|f| plain(&f.code, 80))
                .collect::<Vec<_>>()
                .join("; "),
            item.flags
                .iter()
                .map(|f| clean(&f.text, 300))
                .collect::<Vec<_>>()
                .join("; "),
            clean(&item.reason, 1000),
            clean(&item.action, 300),
            since_last_scan(analysis, &item.id).to_string(),
        ];
        out.push_str(&line(row));
    }
    out
}

// ----------------------------------------------------------------------------------------- SARIF

/// A Windows path as a `file:` URI: `C:\a b\x.exe` → `file:///C:/a%20b/x.exe`,
/// `\\host\share\x` → `file://host/share/x`. Anything else (a registry key, a command) is `None`.
pub fn file_uri(path: &str) -> Option<String> {
    let path = path.trim().trim_matches('"');
    let bytes = path.as_bytes();
    let (prefix, rest) = if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
    {
        (format!("file:///{}:", &path[..1]), &path[2..])
    } else if path.starts_with(r"\\") && !path[2..].starts_with(['?', '.']) {
        // A share; `\\?\` and `\\.\` device paths are not files a tool can open.
        ("file://".to_string(), &path[2..])
    } else {
        return None;
    };
    let mut out = prefix;
    for byte in rest.replace('\\', "/").bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    Some(out)
}

/// `error` for remove, `warning` for disable, `note` for review, `none` for the rest.
pub fn sarif_level(verdict: &str) -> &'static str {
    match verdict {
        "remove" => "error",
        "disable" => "warning",
        "review" => "note",
        _ => "none",
    }
}

/// The rule a finding reports: its weightiest signal, or its kind when it has none.
fn rule_of(item: &Item) -> (String, String) {
    match item.flags.iter().max_by_key(|f| f.weight) {
        Some(flag) => (plain(&flag.code, 80), clean(&flag.text, 300)),
        None => {
            let kind = if item.kind.is_empty() {
                "item"
            } else {
                item.kind.as_str()
            };
            // The rule describes the kind (shared by every such finding), not this finding.
            let label = crate::model::kind_label(kind).map_or_else(|| kind.to_string(), |l| vigil_i18n::tr!(l));
            (format!("vigil/{}", plain(kind, 40)), plain(&label, 80))
        }
    }
}

/// The findings as a SARIF 2.1.0 log: one run, Vigil as the tool, one rule per signal.
pub fn sarif(analysis: &Analysis, options: Options) -> String {
    let items = findings(analysis, options);
    let mut rules: Vec<Value> = Vec::new();
    let mut index_of = std::collections::BTreeMap::new();
    let mut results = Vec::new();
    for item in items {
        let (rule, description) = rule_of(item);
        let rule_index = *index_of.entry(rule.clone()).or_insert_with(|| {
            rules.push(json!({
                "id": rule,
                "shortDescription": {"text": if description.is_empty() { rule.clone() } else { description.clone() }},
            }));
            rules.len() - 1
        });
        let summary = [&item.reason, &item.what, &item.subtitle]
            .into_iter()
            .find(|t| !t.trim().is_empty())
            .map(|t| clean(t, 1000))
            .unwrap_or_default();
        let title = heading(item, &item.title, 300);
        let message = if summary.is_empty() {
            title.clone()
        } else {
            format!("{title}: {summary}")
        };
        let mut result = Map::new();
        result.insert("ruleId".into(), json!(rule));
        result.insert("ruleIndex".into(), json!(rule_index));
        result.insert("level".into(), json!(sarif_level(&item.verdict)));
        result.insert("message".into(), json!({"text": message}));
        let location = match item.path.as_deref().and_then(file_uri) {
            Some(uri) => json!({"physicalLocation": {"artifactLocation": {"uri": uri}}}),
            None => json!({"logicalLocations": [{"name": title, "kind": plain(&item.kind, 40)}]}),
        };
        result.insert("locations".into(), json!([location]));
        let mut properties = json!({
            "id": plain(&item.id, 80),
            "verdict": plain(&item.verdict, 40),
            "verdictSource": plain(&item.verdict_source, 40),
            "confidence": plain(&item.confidence, 40),
            "score": item.score,
            "kind": plain(&item.kind, 40),
            "signals": item.flags.iter().map(|f| plain(&f.code, 80)).collect::<Vec<_>>(),
        });
        if let Some(sha) = item.sha256.as_deref().filter(|s| !s.is_empty()) {
            properties["sha256"] = json!(plain(sha, 64));
        }
        let since = since_last_scan(analysis, &item.id);
        if !since.is_empty() {
            properties["sinceLastScan"] = json!(since);
        }
        result.insert("properties".into(), properties);
        results.push(Value::Object(result));
    }
    let log = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Vigil",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules,
            }},
            "results": results,
            "properties": {
                "scanStarted": plain(&text(analysis.meta.at("started")), 40),
                "anonymized": options.anonymize,
            },
        }],
    });
    serde_json::to_string_pretty(&log).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Flag, Role};
    use serde_json::Map;

    const FAKE_AWS: &str = "AKIAEXAMPLEEXAMPLE00";
    const FAKE_PASSWORD: &str = "Summer2026!Example";
    const FAKE_OPENAI: &str = "sk-proj-EXAMPLEexampleEXAMPLE0000";

    fn sample() -> Analysis {
        let mut bad = Item::new("exe", "winupd.exe", "Starts with Windows from the user folder");
        bad.id = "f1".into();
        bad.path = Some(r"C:\Users\jdoe\AppData\Roaming\win upd\winupd.exe".into());
        bad.verdict = "remove".into();
        bad.verdict_source = "ai".into();
        bad.confidence = "high".into();
        bad.reason = "=HYPERLINK(\"http://203.0.113.5\") unsigned, in a user folder".into();
        bad.score = 85;
        bad.sha256 = Some("ab".repeat(32));
        bad.add_flag(Flag::new("no_signature", 85, "no digital signature"));
        let mut file = Map::new();
        file.insert("signer".into(), json!(""));
        file.insert("sig_status".into(), json!("NotSigned"));
        bad.file = Some(file);
        let mut role = Role::new("startup", "startup entry \"winupd\" in HKCU Run", Map::new());
        role.command = format!("winupd.exe --token {FAKE_OPENAI} --user jdoe");
        bad.roles.push(role);

        let mut script = Item::new("command", "PowerShell history", "C:\\Users\\jdoe\\history.txt");
        script.id = "f2".into();
        script.verdict = "review".into();
        script.score = 30;
        script.commands = vec![format!(
            "net user backdoor {FAKE_PASSWORD} /add; $env:AWS_KEY='{FAKE_AWS}'"
        )];
        script.add_flag(Flag::new("history_secret", 30, "a password in the history"));

        let mut setting = Item::new("config", "Remote Desktop is on", "");
        setting.id = "f3".into();
        setting.verdict = "disable".into();
        setting.score = 40;

        let mut trusted = Item::new("exe", "svchost.exe", "");
        trusted.id = "f4".into();
        trusted.verdict = "trusted".into();
        trusted.trusted = true;
        trusted.path = Some(r"C:\Windows\System32\svchost.exe".into());

        let mut meta = Map::new();
        meta.insert("user".into(), json!("jdoe"));
        meta.insert("computer".into(), json!("PC-VICTIM"));
        meta.insert("started".into(), json!("2026-01-01T10:00:00"));
        Analysis {
            meta,
            items: vec![setting, trusted, script, bad],
            changes: Some(json!({"new": ["f1"], "changed": [{"id": "f2", "what": ["signature"]}], "gone": []})),
            ..Analysis::default()
        }
    }

    #[test]
    fn csv_cells_are_quoted_and_formulas_neutralised() {
        assert_eq!(csv_cell("plain"), "\"plain\"", "every cell is quoted");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("two\nlines"), "\"two\nlines\"");
        for formula in ["=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx"] {
            let cell = csv_cell(formula);
            assert!(cell.starts_with("\"'"), "{formula:?} gave {cell:?}");
        }
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
    }

    #[test]
    fn no_cell_starts_a_formula_in_semicolon_locales() {
        // Spanish, French or Portuguese Excel splits on ';' (and a ',' cell may be cut too): every
        // piece a split could start must not begin with a formula character.
        let payloads = [
            r#"C:\x\a;=HYPERLINK(CHAR(104)&"ttp://203.0.113.5","x").exe"#,
            "a,+cmd|' /C calc'!A0",
            "x;@SUM(1)",
            "x;-2+3",
            "x\n=1",
        ];
        for payload in payloads {
            let cell = csv_cell(payload);
            let inner = &cell[1..cell.len() - 1];
            for piece in inner.split([',', ';', '\t', '\n', '\r']) {
                let piece = piece.trim_start_matches('"');
                assert!(
                    !piece.starts_with(['=', '+', '-', '@']),
                    "{payload:?}: a split could start a formula at {piece:?}"
                );
            }
        }
    }

    #[test]
    fn csv_has_a_bom_a_header_and_one_row_per_finding() {
        let out = csv(&sample(), Options::default());
        assert!(out.starts_with('\u{feff}'));
        let body = out.trim_start_matches('\u{feff}');
        let lines: Vec<&str> = body.split("\r\n").filter(|l| !l.is_empty()).collect();
        let header: Vec<String> = CSV_COLUMNS.iter().map(|c| format!("\"{c}\"")).collect();
        assert_eq!(lines[0], header.join(","));
        // Trusted left out by default; most severe first.
        assert_eq!(lines.len(), 4, "{body}");
        assert!(
            lines[1].starts_with(r#""f1","remove","ai","high","85","critical","exe","winupd.exe""#),
            "{}",
            lines[1]
        );
        assert!(lines[2].starts_with(r#""f3","disable""#));
        assert!(lines[3].starts_with(r#""f2","review""#));
        assert!(lines[1].ends_with(r#","new""#));
        assert!(lines[3].ends_with(r#","changed""#));
        // The AI's reason started with "=": neutralised.
        assert!(lines[1].contains("\"'=HYPERLINK("));
        let all = csv(
            &sample(),
            Options {
                include_trusted: true,
                ..Options::default()
            },
        );
        assert!(all.contains("svchost.exe"));
    }

    #[test]
    fn no_secret_value_is_exported() {
        let analysis = sample();
        let options = Options::default();
        for format in [Format::Csv, Format::Sarif] {
            let out = String::from_utf8(render(&analysis, format, options)).unwrap_or_default();
            for value in [FAKE_AWS, FAKE_PASSWORD, FAKE_OPENAI] {
                assert!(!out.contains(value), "{value} left in the {format:?} export");
            }
        }
    }

    #[test]
    fn anonymization_hides_the_user_and_the_computer() {
        let analysis = sample();
        let plain = String::from_utf8(render(&analysis, Format::Csv, Options::default())).unwrap_or_default();
        assert!(plain.contains("jdoe"));
        let options = Options {
            anonymize: true,
            ..Options::default()
        };
        for format in [Format::Csv, Format::Sarif, Format::Html] {
            let out = String::from_utf8(render(&analysis, format, options)).unwrap_or_default();
            assert!(!out.contains("jdoe"), "{format:?} still names the user");
            assert!(!out.contains("PC-VICTIM"), "{format:?} still names the computer");
        }
    }

    #[test]
    fn file_uris_are_encoded() {
        assert_eq!(
            file_uri(r"C:\Users\jdoe\win upd\x#1.exe").as_deref(),
            Some("file:///C:/Users/jdoe/win%20upd/x%231.exe")
        );
        assert_eq!(
            file_uri(r"\\server\share\a.exe").as_deref(),
            Some("file://server/share/a.exe")
        );
        assert_eq!(file_uri(r"C:\Pro\é.exe").as_deref(), Some("file:///C:/Pro/%C3%A9.exe"));
        assert_eq!(file_uri(r"HKCU\Software\Run"), None);
        assert_eq!(file_uri(r"\\?\C:\x"), None);
        assert_eq!(file_uri("powershell -enc AAA"), None);
    }

    /// The parts of the SARIF 2.1.0 schema a consumer relies on, checked by hand:
    /// `version` "2.1.0", `runs[]` with `tool.driver.name`, every rule with an `id`, every result
    /// with `message.text`, a `level` from the enumeration, a `ruleIndex` that points at its
    /// `ruleId`, and locations that are either a `file:` URI or a logical location with a name.
    #[test]
    fn sarif_has_the_required_shape() {
        let log: Value = serde_json::from_str(&sarif(&sample(), Options::default())).unwrap_or_default();
        assert_eq!(log["version"], "2.1.0");
        let runs = log["runs"].as_array().cloned().unwrap_or_default();
        assert_eq!(runs.len(), 1);
        let run = &runs[0];
        assert_eq!(run["tool"]["driver"]["name"], "Vigil");
        assert!(run["tool"]["driver"]["version"].is_string());
        let rules = run["tool"]["driver"]["rules"].as_array().cloned().unwrap_or_default();
        assert!(!rules.is_empty());
        for rule in &rules {
            assert!(rule["id"].as_str().is_some_and(|s| !s.is_empty()));
            assert!(rule["shortDescription"]["text"].is_string());
        }
        let results = run["results"].as_array().cloned().unwrap_or_default();
        assert_eq!(results.len(), 3);
        for result in &results {
            assert!(result["message"]["text"].as_str().is_some_and(|s| !s.is_empty()));
            let level = result["level"].as_str().unwrap_or("");
            assert!(["none", "note", "warning", "error"].contains(&level), "{level}");
            let index = result["ruleIndex"].as_u64().unwrap_or(u64::MAX) as usize;
            assert_eq!(rules[index]["id"], result["ruleId"]);
            for location in result["locations"].as_array().cloned().unwrap_or_default() {
                let uri = location["physicalLocation"]["artifactLocation"]["uri"].as_str();
                let logical = location["logicalLocations"][0]["name"].as_str();
                assert!(uri.is_some_and(|u| u.starts_with("file:")) || logical.is_some());
            }
        }
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[0]["ruleId"], "no_signature");
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(results[1]["ruleId"], "vigil/config");
        assert_eq!(results[2]["level"], "note");
        assert_eq!(results[0]["properties"]["sinceLastScan"], "new");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "file:///C:/Users/jdoe/AppData/Roaming/win%20upd/winupd.exe"
        );
    }

    #[test]
    fn formats_parse() {
        assert_eq!(Format::parse("CSV"), Some(Format::Csv));
        assert_eq!(Format::parse("sarif"), Some(Format::Sarif));
        assert_eq!(Format::parse("html").map(Format::extension), Some("html"));
        assert_eq!(Format::parse("xml"), None);
    }

    /// A CSV read back cell by cell (RFC 4180, byte order mark skipped).
    fn read_csv(text: &str) -> Vec<Vec<String>> {
        let mut rows = Vec::new();
        let mut row = Vec::new();
        let mut cell = String::new();
        let mut quoted = false;
        let mut chars = text.trim_start_matches('\u{FEFF}').chars().peekable();
        while let Some(c) = chars.next() {
            if quoted {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        cell.push('"');
                        chars.next();
                    } else {
                        quoted = false;
                    }
                } else {
                    cell.push(c);
                }
            } else {
                match c {
                    '"' => quoted = true,
                    ',' => row.push(std::mem::take(&mut cell)),
                    '\r' => {}
                    '\n' => {
                        row.push(std::mem::take(&mut cell));
                        rows.push(std::mem::take(&mut row));
                    }
                    _ => cell.push(c),
                }
            }
        }
        if !cell.is_empty() || !row.is_empty() {
            row.push(cell);
            rows.push(row);
        }
        rows
    }

    /// Names, reasons and paths come from the scanned computer: whatever they hold, the CSV keeps
    /// one cell per column, no cell starts a formula, and the SARIF is valid JSON.
    #[test]
    fn any_text_exports_safely() {
        use crate::fuzz::{Rng, check_text};
        let mut rng = Rng::new(27);
        let tokens = &[
            "=",
            "+",
            "-",
            "@",
            "\t",
            "\r",
            "\n",
            ",",
            ";",
            "\"",
            "'",
            "=HYPERLINK(",
            "\u{202E}",
            "C:\\",
            "\\\\server\\",
            "%",
            "#",
            "\u{0}",
            "file:///",
        ];
        for _ in 0..300 {
            let mut analysis = sample();
            for item in &mut analysis.items {
                item.title = rng.text(8, tokens);
                item.reason = rng.text(8, tokens);
                item.path = Some(rng.text(6, tokens));
                item.commands = vec![rng.text(6, tokens)];
            }
            let shown: Vec<&str> = analysis.items.iter().map(|i| i.title.as_str()).collect();
            check_text("export", &shown.join("|"), || {
                let rows = read_csv(&csv(
                    &analysis,
                    Options {
                        include_trusted: true,
                        ..Options::default()
                    },
                ));
                let width = rows[0].len();
                assert!(rows.iter().all(|row| row.len() == width), "one cell per column");
                for cell in rows.iter().flatten() {
                    assert!(!cell.starts_with(['=', '+', '-', '@', '\t', '\r']), "formula: {cell:?}");
                }
                let sarif = sarif(
                    &analysis,
                    Options {
                        include_trusted: true,
                        ..Options::default()
                    },
                );
                assert!(serde_json::from_str::<Value>(&sarif).is_ok(), "valid JSON");
            });
        }
    }
}
