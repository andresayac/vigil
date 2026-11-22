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
    let text = KNOWN_TOKENS.replace_all(&text, NoExpand("<redacted>"));
    // Everything the secrets scanner recognizes too (`net user NAME PASS`, `-AsPlainText`
    // literals, `$dbPassword=`, `*_API_KEY=`, `github_pat_`, `AccountKey=`...), from its own
    // patterns, so an excerpt can never show a value the scanner would report as a secret.
    crate::secrets::mask_values(&text)
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

/// Replaces the user name, the computer name and the machine SID with markers; with
/// [`Redactor::with_accounts`] (or [`Redactor::for_this_computer`]) also the other local account
/// names and the sign-in domain. Every profile folder (`C:\Users\<name>`) other than the shared
/// ones (Public, Default...) loses its name too, whoever it belongs to.
pub struct Redactor {
    enabled: bool,
    computer: Option<Regex>,
    user: Option<Regex>,
    domain: Option<Regex>,
    accounts: Vec<Regex>,
}

/// Account and folder names that identify nobody: Windows' own accounts and shared profiles. A
/// local account with one of these names is left alone, so ordinary words are not replaced.
const NOT_PERSONAL: &[&str] = &[
    "administrator",
    "admin",
    "guest",
    "defaultaccount",
    "wdagutilityaccount",
    "defaultuser0",
    "user",
    "users",
    "owner",
    "test",
    "home",
    "public",
    "default",
    "default user",
    "all users",
    "defaultapppool",
    "system",
    "local service",
    "network service",
    "localservice",
    "networkservice",
    "everyone",
    "service",
    "local",
    "network",
    "workgroup",
    "azuread",
    "nt authority",
    "builtin",
    "nt service",
    "font driver host",
    "window manager",
];

fn personal(name: &str) -> bool {
    let name = name.trim();
    char_len(name) >= 3 && !NOT_PERSONAL.contains(&name.to_lowercase().as_str()) && !name.starts_with('<')
}

/// The names of this computer's local accounts and the sign-in domain, read once.
#[cfg(windows)]
fn this_computer_names() -> &'static (Vec<String>, String) {
    static NAMES: std::sync::OnceLock<(Vec<String>, String)> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| {
        let accounts = vigil_sys::accounts::read()
            .accounts
            .into_iter()
            .flat_map(|a| [a.name, a.full_name])
            .filter(|n| personal(n))
            .collect();
        let domain = std::env::var("USERDOMAIN").unwrap_or_default();
        let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
        let domain = if domain.eq_ignore_ascii_case(&computer) {
            String::new()
        } else {
            domain
        };
        (accounts, domain)
    })
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
            domain: None,
            accounts: Vec::new(),
        }
    }

    /// Also replaces these account names (whole words) with `<account>` and the domain with
    /// `<domain>`. Windows' own names and shared profiles are left alone.
    pub fn with_accounts(mut self, names: &[String], domain: &str) -> Self {
        if !self.enabled {
            return self;
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut names: Vec<&str> = names
            .iter()
            .map(|n| n.trim())
            .filter(|n| personal(n) && seen.insert(n.to_lowercase()))
            .collect();
        // Longer names first: "Ana Lopez" before "ana".
        names.sort_by_key(|n| std::cmp::Reverse(char_len(n)));
        self.accounts = names
            .into_iter()
            .filter_map(|n| Regex::new(&format!("(?i){}", regex::escape(n))).ok())
            .collect();
        self.domain = personal(domain)
            .then(|| Regex::new(&format!("(?i){}", regex::escape(domain.trim()))).ok())
            .flatten();
        self
    }

    /// [`Redactor::new`] plus this computer's local account names and the sign-in domain: what the
    /// AI review and the MCP tools use, so other people's names on the computer are hidden too.
    pub fn for_this_computer(user: &str, computer: &str, enabled: bool) -> Self {
        let redactor = Self::new(user, computer, enabled);
        #[cfg(windows)]
        if enabled {
            let (names, domain) = this_computer_names();
            return redactor.with_accounts(names, domain);
        }
        redactor
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
        if let Some(domain) = &self.domain {
            value = replace_whole_word(domain, &value, "<domain>");
        }
        for account in &self.accounts {
            value = replace_whole_word(account, &value, "<account>");
        }
        value = profile_names(&value);
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

/// `X:\Users\<name>` with the name replaced by `<account>`, unless it is a shared profile (Public,
/// Default...) or already a marker. The name runs to the next `\` (or, with none after it, to the
/// first space or quote), so `C:\Users\John Smith\x` and `C:\Users\jdoe` both lose it.
fn profile_names(text: &str) -> String {
    const NEEDLE: &str = ":\\users\\";
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut from = 0;
    while let Some(found) = lower[from..].find(NEEDLE).map(|i| i + from) {
        let drive_ok = found >= 1 && text.as_bytes()[found - 1].is_ascii_alphabetic();
        let start = found + NEEDLE.len();
        from = start;
        if !drive_ok || start >= text.len() {
            continue;
        }
        let rest = &text[start..];
        let stop = |c: char| {
            matches!(
                c,
                '"' | '\'' | '\r' | '\n' | '\t' | '<' | '>' | '|' | '*' | '?' | ',' | ';'
            )
        };
        let end = match rest.find(|c: char| c == '\\' || c == '/' || stop(c)) {
            Some(at) if rest[at..].starts_with(['\\', '/']) => at,
            other => {
                // No folder after it: the name ends at the first space too.
                let cut = other.unwrap_or(rest.len());
                rest[..cut].find(char::is_whitespace).unwrap_or(cut)
            }
        };
        let name = &rest[..end];
        if name.is_empty() || !personal(name) {
            continue;
        }
        out.push_str(&text[copied..start]);
        out.push_str("<account>");
        copied = start + end;
        from = copied;
    }
    out.push_str(&text[copied..]);
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_profiles_and_accounts_are_hidden_too() {
        let redactor = Redactor::new("jdoe", "PC-VICTIM", true).with_accounts(
            &[
                "ana".into(),
                "support".into(),
                "Administrator".into(),
                "Ana Lopez".into(),
            ],
            "CONTOSO",
        );
        let cases = [
            (r"C:\Users\jdoe\x.exe", r"C:\Users\<user>\x.exe"),
            (r"C:\Users\ana\AppData\x.exe", r"C:\Users\<account>\AppData\x.exe"),
            (
                r"D:\users\Someone Else\Downloads\a.zip",
                r"D:\users\<account>\Downloads\a.zip",
            ),
            (r#""C:\Users\mallory""#, r#""C:\Users\<account>""#),
            (r"C:\Users\mallory and more", r"C:\Users\<account> and more"),
            (r"C:\Users\Public\Desktop\a.lnk", r"C:\Users\Public\Desktop\a.lnk"),
            (r"C:\Users\Default\NTUSER.DAT", r"C:\Users\Default\NTUSER.DAT"),
            (r"PC-VICTIM\support signed in", r"<computer>\<account> signed in"),
            (r"CONTOSO\ana", r"<domain>\<account>"),
            ("Administrator and Guest", "Administrator and Guest"),
            ("Ana Lopez", "<account>"),
            ("supporting text", "supporting text"),
        ];
        for (text, want) in cases {
            assert_eq!(redactor.text(text), want, "{text}");
        }
        // Off: nothing changes.
        let off = Redactor::new("jdoe", "PC-VICTIM", false).with_accounts(&["ana".into()], "CONTOSO");
        assert_eq!(off.text(r"C:\Users\ana\x"), r"C:\Users\ana\x");
    }
}
