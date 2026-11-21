//! Every English template written in the workspace (`tr!("...")` and `tl!("...")` in
//! `crates/*/src`) must have a translation in every catalog, and no catalog may keep a template the
//! code no longer uses. A missing entry would silently show English; a stale one is dead weight.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The value of a Rust string literal body (escapes and line continuations resolved).
fn unescape(body: &str) -> String {
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\n') | Some('\r') => {
                while chars.peek().is_some_and(|c| c.is_whitespace()) {
                    chars.next();
                }
            }
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('u') => {
                let hex: String = chars.by_ref().skip(1).take_while(|c| *c != '}').collect();
                if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    out.push(ch);
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// English templates used in the code, with the first file that uses each.
fn templates() -> BTreeMap<String, String> {
    let mut files = Vec::new();
    let Ok(crates) = fs::read_dir(crates_dir()) else {
        return BTreeMap::new();
    };
    for krate in crates.flatten() {
        if krate.file_name() == "vigil-i18n" {
            continue;
        }
        rust_files(&krate.path().join("src"), &mut files);
    }
    files.sort();
    let mut found = BTreeMap::new();
    for file in files {
        let Ok(raw) = fs::read_to_string(&file) else { continue };
        // rustc reads CRLF line ends as LF, so literals spanning lines hold "\n" whatever the checkout uses.
        let text = raw.replace("\r\n", "\n");
        for marker in ["tr!(", "tl!("] {
            let mut from = 0;
            while let Some(pos) = text[from..].find(marker) {
                let start = from + pos;
                from = start + marker.len();
                let before = text[..start].chars().next_back();
                if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    continue;
                }
                let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
                if text[line_start..start].trim_start().starts_with("//") {
                    continue;
                }
                let rest = text[from..].trim_start();
                let Some(body) = rest.strip_prefix('"') else { continue };
                let mut end = None;
                let mut escaped = false;
                for (i, c) in body.char_indices() {
                    if escaped {
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        end = Some(i);
                        break;
                    }
                }
                let Some(end) = end else { continue };
                found
                    .entry(unescape(&body[..end]))
                    .or_insert_with(|| file.display().to_string());
            }
        }
    }
    found
}

#[test]
fn every_template_is_translated_and_no_entry_is_stale() {
    let used = templates();
    assert!(used.len() > 500, "the extraction found only {} templates", used.len());
    let mut problems = Vec::new();
    for code in ["es", "fr", "pt", "zh"] {
        let keys: BTreeSet<String> = vigil_i18n::catalog_keys(code).into_iter().collect();
        for (template, file) in &used {
            if !keys.contains(template) {
                problems.push(format!("{code}: missing {template:?} ({file})"));
            }
        }
        for key in &keys {
            if !used.contains_key(key) {
                problems.push(format!("{code}: stale {key:?}"));
            }
        }
    }
    let shown: Vec<&String> = problems.iter().take(40).collect();
    assert!(problems.is_empty(), "{} catalog problems:\n{shown:#?}", problems.len());
}

#[test]
fn translations_are_not_left_in_english() {
    // A translation identical to English is allowed only for short technical texts (names, units).
    let used = templates();
    let mut same = Vec::new();
    for code in ["es", "fr", "pt", "zh"] {
        for template in used.keys() {
            let translated = vigil_i18n::with_language(code, || vigil_i18n::template(template).to_string());
            let words = template
                .split_whitespace()
                .filter(|w| w.chars().all(char::is_alphabetic))
                .count();
            if translated == *template && words >= 4 {
                same.push(format!("{code}: {template:?}"));
            }
        }
    }
    let shown: Vec<&String> = same.iter().take(30).collect();
    assert!(same.is_empty(), "{} texts left in English:\n{shown:#?}", same.len());
}
