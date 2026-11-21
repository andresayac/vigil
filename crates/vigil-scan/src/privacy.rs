//! Privacy: strips secrets from command lines and anonymizes what is sent to the AI.

use regex::{Captures, NoExpand, Regex};
use serde_json::{Map, Value};

use crate::lenient::{char_len, rx, skip, take};

// Values that follow a parameter name that looks like a credential.
rx!(
    SECRET_ARG,
    r#"(?i)((?:--?|/)(?:password|passwd|pwd|pass|token|secret|api[-_]?key|apikey|access[-_]?key|auth[-_]?token|client[-_]?secret|private[-_]?key|bearer)(?:[=:]|\s+))("[^"]*"|'[^']*'|\S+)"#
);
rx!(
    SECRET_KV,
    r#"(?i)\b((?:password|passwd|pwd|token|secret|api[-_]?key|apikey|access[-_]?key|client[-_]?secret|authorization)\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s&;"']+)"#
);
rx!(URL_CREDS, r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^@\s/]+@");
rx!(BEARER, r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{16,}");
rx!(
    KNOWN_TOKENS,
    r"\b(sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
);
rx!(MACHINE_SID, r"\bS-1-5-21-\d+-\d+-\d+(-\d+)?\b");

/// Hides passwords, tokens and keys that commonly appear in command lines.
pub fn scrub_secrets(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let keep_first = |caps: &Captures| format!("{}<redacted>", &caps[1]);
    let text = SECRET_ARG.replace_all(text, keep_first);
    let text = SECRET_KV.replace_all(&text, keep_first);
    let text = URL_CREDS.replace_all(&text, |caps: &Captures| format!("{}<redacted>@", &caps[1]));
    let text = BEARER.replace_all(&text, keep_first);
    KNOWN_TOKENS.replace_all(&text, NoExpand("<redacted>")).into_owned()
}

/// Cuts a text to `limit` characters, saying how many were left out.
pub fn clip(text: &str, limit: usize) -> String {
    let length = char_len(text);
    if length <= limit {
        text.to_string()
    } else {
        format!("{}… (+{} characters)", take(text, limit), length - limit)
    }
}

/// Replaces the user name, the computer name and the machine SID with markers.
pub struct Redactor {
    enabled: bool,
    computer: Option<Regex>,
    user: Option<Regex>,
}

impl Redactor {
    pub fn new(user: &str, computer: &str, enabled: bool) -> Self {
        let literal = |text: &str| {
            (enabled && char_len(text) >= 3)
                .then(|| Regex::new(&format!("(?i){}", regex::escape(text))).ok())
                .flatten()
        };
        Self {
            enabled,
            computer: literal(computer),
            user: literal(user),
        }
    }

    pub fn text(&self, value: &str) -> String {
        if !self.enabled || value.is_empty() {
            return value.to_string();
        }
        let mut value = value.to_string();
        if let Some(computer) = &self.computer {
            value = computer.replace_all(&value, NoExpand("<computer>")).into_owned();
        }
        if let Some(user) = &self.user {
            value = replace_whole_word(user, &value, "<user>");
        }
        MACHINE_SID
            .replace_all(&value, |caps: &Captures| {
                format!("S-1-5-21-<sid>{}", caps.get(1).map_or("", |m| m.as_str()))
            })
            .into_owned()
    }

    /// Applies the anonymization to strings inside nested structures (keys included).
    pub fn apply(&self, value: &Value) -> Value {
        match value {
            Value::String(s) => Value::String(self.text(s)),
            Value::Array(items) => Value::Array(items.iter().map(|v| self.apply(v)).collect()),
            Value::Object(map) => {
                let mut out = Map::new();
                for (k, v) in map {
                    out.insert(self.text(k), self.apply(v));
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }
}

/// `(?<![A-Za-z0-9])name(?![A-Za-z0-9])` replacement: whole words only, so names inside
/// other words ("jdoe" in "jdoe2") are left alone.
fn replace_whole_word(pattern: &Regex, text: &str, replacement: &str) -> String {
    let alnum = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut start = 0;
    while let Some(found) = pattern.find_at(text, start) {
        let before = text[..found.start()].chars().next_back();
        let after = text[found.end()..].chars().next();
        if !alnum(before) && !alnum(after) && !found.as_str().is_empty() {
            out.push_str(&text[copied..found.start()]);
            out.push_str(replacement);
            copied = found.end();
            start = found.end();
        } else {
            let step = skip(&text[found.start()..], 1);
            start = text.len() - step.len();
            if start <= found.start() {
                break;
            }
        }
    }
    out.push_str(&text[copied..]);
    out
}
