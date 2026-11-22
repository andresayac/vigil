//! The interface's own words, in the five languages.
//!
//! The catalogs use dotted keys, `{name}` placeholders, and plurals as objects chosen by `count`
//! (`{ "one": …, "other": … }`). They live in `locales/<code>.json`; `en.json` is the
//! source and every other catalog must have exactly its keys (tested below). Texts produced by the
//! core (findings, action labels, confirmations) keep coming from `vigil_i18n::tr!`, translated
//! there; the language is the one `vigil_i18n` uses, so both always agree.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::Value;

const SOURCES: [(&str, &str); 5] = [
    ("en", include_str!("../locales/en.json")),
    ("es", include_str!("../locales/es.json")),
    ("fr", include_str!("../locales/fr.json")),
    ("pt", include_str!("../locales/pt.json")),
    ("zh", include_str!("../locales/zh.json")),
];

enum Msg {
    Text(String),
    /// CLDR plural category -> text; "other" is always there.
    Plural(HashMap<String, String>),
}

type Catalog = HashMap<String, Msg>;

fn catalogs() -> &'static HashMap<&'static str, Catalog> {
    static CATALOGS: OnceLock<HashMap<&'static str, Catalog>> = OnceLock::new();
    CATALOGS.get_or_init(|| SOURCES.iter().map(|(code, text)| (*code, parse(text))).collect())
}

fn parse(text: &str) -> Catalog {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text) else {
        return Catalog::new();
    };
    map.into_iter()
        .filter_map(|(key, value)| match value {
            Value::String(text) => Some((key, Msg::Text(text))),
            Value::Object(forms) => {
                let forms: HashMap<String, String> = forms
                    .into_iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                    .collect();
                forms.contains_key("other").then_some((key, Msg::Plural(forms)))
            }
            _ => None,
        })
        .collect()
}

/// The language in use: the core's (`vigil_i18n::set_language`), so the page and the findings agree.
pub fn language() -> &'static str {
    vigil_i18n::language()
}

/// The CLDR plural category of `count` in `code` (cardinal, integers).
fn plural(code: &str, count: u64) -> &'static str {
    match code {
        "zh" => "other",
        // French and Brazilian Portuguese: 0 and 1 are singular.
        "fr" | "pt" if count <= 1 => "one",
        _ if count == 1 => "one",
        _ => "other",
    }
}

fn lookup(code: &str, key: &str, count: u64) -> Option<&'static str> {
    let message = catalogs().get(code)?.get(key)?;
    Some(match message {
        Msg::Text(text) => text.as_str(),
        Msg::Plural(forms) => forms
            .get(plural(code, count))
            .or_else(|| forms.get("other"))
            .map(String::as_str)?,
    })
}

fn message(key: &str, count: u64) -> &'static str {
    let code = language();
    lookup(code, key, count)
        .or_else(|| lookup("en", key, count))
        .unwrap_or("")
}

/// Fills `{name}` placeholders; unknown ones stay as written.
fn fill(template: &str, params: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        match tail.find('}').map(|end| (&tail[..end], end)) {
            Some((name, end)) if params.iter().any(|(n, _)| *n == name) => {
                if let Some((_, value)) = params.iter().find(|(n, _)| *n == name) {
                    out.push_str(value);
                }
                rest = &tail[end + 1..];
            }
            _ => {
                out.push('{');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The catalog has `key`.
pub fn has(key: &str) -> bool {
    lookup("en", key, 0).is_some()
}

/// The text of `key`, or `fallback` when the catalog does not have it (a value from the core).
pub fn t_or(key: &str, fallback: &str) -> String {
    if has(key) { t(key) } else { fallback.to_string() }
}

/// A text without placeholders.
pub fn t(key: &str) -> String {
    message(key, 0).to_string()
}

/// A text with `{name}` placeholders.
pub fn tf(key: &str, params: &[(&str, &str)]) -> String {
    fill(message(key, 0), params)
}

/// A plural text chosen by `count`; `{count}` is the number formatted for the language.
pub fn tn(key: &str, count: u64, params: &[(&str, &str)]) -> String {
    let shown = crate::format::num(count as f64, 0);
    let mut all: Vec<(&str, &str)> = vec![("count", shown.as_str())];
    all.extend_from_slice(params);
    fill(message(key, count), &all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn keys(code: &str) -> BTreeSet<String> {
        catalogs()
            .get(code)
            .map(|c| c.keys().cloned().collect())
            .unwrap_or_default()
    }

    #[test]
    fn every_catalog_has_the_english_keys() {
        let english = keys("en");
        assert!(english.len() > 50, "the English catalog did not load");
        for (code, _) in SOURCES {
            assert_eq!(keys(code), english, "catalog {code} differs from en.json");
        }
    }

    /// The text of every source file of the window.
    fn sources() -> Vec<(std::path::PathBuf, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        let mut stack = vec![dir];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
        files
            .into_iter()
            .map(|file| {
                let text = std::fs::read_to_string(&file).unwrap_or_default();
                (file, text)
            })
            .collect()
    }

    /// The string literals of the sources (a leading "@" marks a key a table translates later).
    fn literals(text: &str) -> impl Iterator<Item = &str> {
        text.split('"').skip(1).step_by(2).map(|l| l.trim_start_matches('@'))
    }

    /// Every key the code names is in the English catalog: a string literal shaped like a key of
    /// one of the catalog's areas ("proc.endTask"), wherever it is (in `t(…)`, a table, a branch).
    #[test]
    fn every_key_used_is_translated() {
        let english = keys("en");
        let areas: BTreeSet<&str> = english.iter().filter_map(|k| k.split('.').next()).collect();
        let mut missing = Vec::new();
        for (file, text) in sources() {
            for literal in literals(&text) {
                let Some((area, name)) = literal.split_once('.') else {
                    continue;
                };
                let file_name = ["msc", "exe", "dll", "json", "ico", "png"].contains(&name);
                let shaped =
                    !file_name && !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.');
                if areas.contains(area) && shaped && !english.contains(literal) {
                    missing.push(format!("{literal} ({})", file.display()));
                }
            }
        }
        assert!(missing.is_empty(), "keys missing from en.json: {missing:#?}");
    }

    /// Every key of the catalogs is used: named as a string literal, or under the literal head of a
    /// `format!("area.{…}")` that builds keys (verdicts, kinds, states).
    #[test]
    fn no_catalog_key_is_stale() {
        let sources = sources();
        let mut named = BTreeSet::new();
        let mut prefixes = BTreeSet::new();
        for (_, text) in &sources {
            named.extend(literals(text).map(str::to_string));
            for rest in text.split("format!(").skip(1) {
                let Some(start) = rest.trim_start().strip_prefix('"') else {
                    continue;
                };
                let literal = start.split('"').next().unwrap_or("");
                if let Some((head, _)) = literal.split_once('{')
                    && head.contains('.')
                {
                    prefixes.insert(head.to_string());
                }
            }
        }
        let stale: Vec<String> = keys("en")
            .into_iter()
            .filter(|key| !named.contains(key) && !prefixes.iter().any(|p| key.starts_with(p.as_str())))
            .collect();
        assert!(stale.is_empty(), "keys no code uses: {stale:#?}");
    }

    #[test]
    fn plurals_follow_the_language() {
        assert_eq!(plural("en", 1), "one");
        assert_eq!(plural("en", 0), "other");
        assert_eq!(plural("fr", 0), "one");
        assert_eq!(plural("pt", 1), "one");
        assert_eq!(plural("es", 2), "other");
        assert_eq!(plural("zh", 1), "other");
    }

    #[test]
    fn placeholders_are_filled() {
        assert_eq!(
            fill("{name} ({count})", &[("name", "Apps"), ("count", "3")]),
            "Apps (3)"
        );
        assert_eq!(fill("{unknown} x", &[]), "{unknown} x");
    }
}
