//! Translations of the texts Vigil's core shows: findings, action labels and explanations,
//! confirmations, results and insights. The UI has its own catalogs for its chrome.
//!
//! English is the source language and lives in the code itself:
//!
//! ```
//! use vigil_i18n::tr;
//! let label = tr!("Disable service {0}", "\"Updater\"");
//! assert_eq!(label, "Disable service \"Updater\"");
//! ```
//!
//! Each other language has a catalog in `locales/<code>.json` that maps the English template to its
//! translation, with the same `{0}`, `{1}` placeholders. A missing entry falls back to English, so a
//! new string never breaks anything; `cargo test -p vigil-i18n` lists what is missing.

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The languages Vigil speaks, in this order: English, Spanish, French, Portuguese (Brazil), Chinese (Simplified).
pub const LANGUAGES: [&str; 5] = ["en", "es", "fr", "pt", "zh"];

const CATALOG_SOURCES: [(&str, &str); 4] = [
    ("es", include_str!("../locales/es.json")),
    ("fr", include_str!("../locales/fr.json")),
    ("pt", include_str!("../locales/pt.json")),
    ("zh", include_str!("../locales/zh.json")),
];

static CURRENT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// A language for this thread only ([`with_language`]): tests run in parallel and must not see
    /// each other's language.
    static OVERRIDE: Cell<Option<usize>> = const { Cell::new(None) };
}
static CATALOGS: OnceLock<HashMap<&'static str, HashMap<String, String>>> = OnceLock::new();

fn catalogs() -> &'static HashMap<&'static str, HashMap<String, String>> {
    CATALOGS.get_or_init(|| {
        CATALOG_SOURCES
            .iter()
            .map(|(code, text)| {
                (
                    *code,
                    serde_json::from_str::<HashMap<String, String>>(text).unwrap_or_default(),
                )
            })
            .collect()
    })
}

/// The language of the texts produced from now on: "en", "es", "fr", "pt", "zh", or "auto" for the
/// Windows display language. Returns the code in use.
pub fn set_language(code: &str) -> &'static str {
    let wanted = if code == "auto" { detect() } else { code };
    let index = LANGUAGES.iter().position(|l| *l == wanted).unwrap_or(0);
    CURRENT.store(index, Ordering::Relaxed);
    LANGUAGES[index]
}

/// The code of the language in use.
pub fn language() -> &'static str {
    let index = OVERRIDE
        .with(Cell::get)
        .unwrap_or_else(|| CURRENT.load(Ordering::Relaxed));
    LANGUAGES[index.min(LANGUAGES.len() - 1)]
}

/// Runs `f` with another language on this thread only (the global setting is untouched).
pub fn with_language<R>(code: &str, f: impl FnOnce() -> R) -> R {
    let index = LANGUAGES.iter().position(|l| *l == code).unwrap_or(0);
    let previous = OVERRIDE.with(|o| o.replace(Some(index)));
    let result = f();
    OVERRIDE.with(|o| o.set(previous));
    result
}

/// The language's English name, for instructions to an AI model ("Answer in Spanish").
pub fn language_name(code: &str) -> &'static str {
    match code {
        "es" => "Spanish",
        "fr" => "French",
        "pt" => "Brazilian Portuguese",
        "zh" => "Simplified Chinese",
        _ => "English",
    }
}

/// The language as a BCP 47 tag, for the `lang` attribute of HTML pages ("pt-BR", "zh-CN").
pub fn language_tag(code: &str) -> &'static str {
    match code {
        "es" => "es",
        "fr" => "fr",
        "pt" => "pt-BR",
        "zh" => "zh-CN",
        _ => "en",
    }
}

/// The Windows display language mapped to one of [`LANGUAGES`] (English when it is none of them).
pub fn detect() -> &'static str {
    #[cfg(windows)]
    {
        // SAFETY: plain call without arguments.
        let lang_id = unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() };
        // The primary language is the low 10 bits of the LANGID.
        match lang_id & 0x3ff {
            0x0a => "es",
            0x0c => "fr",
            0x16 => "pt",
            0x04 => "zh",
            _ => "en",
        }
    }
    #[cfg(not(windows))]
    {
        "en"
    }
}

/// The template in the current language (English when there is no translation).
pub fn template(english: &str) -> &str {
    let code = language();
    if code == "en" {
        return english;
    }
    catalogs()
        .get(code)
        .and_then(|catalog| catalog.get(english))
        .filter(|t| !t.is_empty())
        .map_or(english, String::as_str)
}

/// Fills `{0}`, `{1}`… in a template. Unknown placeholders stay as written.
pub fn fill(template: &str, args: &[&dyn Display]) -> String {
    if args.is_empty() {
        return template.to_string();
    }
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        match tail
            .find('}')
            .and_then(|end| tail[..end].parse::<usize>().ok().map(|n| (n, end)))
        {
            Some((n, end)) if n < args.len() => {
                out.push_str(&args[n].to_string());
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

/// Translates and fills a template: `tr!("Delete task {0}", name)`.
#[macro_export]
macro_rules! tr {
    ($template:expr) => {
        $crate::template($template).to_string()
    };
    ($template:expr, $($arg:expr),+ $(,)?) => {
        $crate::fill($crate::template($template), &[$(&$arg as &dyn ::std::fmt::Display),+])
    };
}

/// Marks a literal as translatable without translating it yet: for tables of static texts that are
/// translated where they are shown, with `tr!(text)`. It expands to the literal itself.
#[macro_export]
macro_rules! tl {
    ($text:literal) => {
        $text
    };
}

/// Every English template a catalog translates, for tests and tooling.
pub fn catalog_keys(code: &str) -> Vec<String> {
    catalogs()
        .get(code)
        .map(|c| c.keys().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_is_the_source() {
        set_language("en");
        assert_eq!(tr!("Disable service {0}", "\"Updater\""), "Disable service \"Updater\"");
        assert_eq!(tr!("Plain text"), "Plain text");
    }

    #[test]
    fn placeholders_fill_in_any_order() {
        assert_eq!(fill("{1} then {0}", &[&"a", &2]), "2 then a");
        assert_eq!(fill("keep {x} and {9}", &[&"a"]), "keep {x} and {9}");
    }

    #[test]
    fn thread_language_does_not_leak() {
        let inside = with_language("es", language);
        assert_eq!(inside, "es");
        assert_eq!(with_language("zh", || with_language("fr", language)), "fr");
        assert_ne!(language(), "es");
    }

    #[test]
    fn unknown_language_falls_back_to_english() {
        assert_eq!(set_language("xx"), "en");
        assert_eq!(language(), "en");
        assert_eq!(with_language("xx", || tr!("Disable service")), "Disable service");
    }

    #[test]
    fn every_language_translates_and_has_a_tag() {
        let label = |code: &str| with_language(code, || tr!("Disable service"));
        assert_eq!(label("en"), "Disable service");
        assert_eq!(label("es"), "Deshabilitar servicio");
        assert_eq!(label("fr"), "Désactiver le service");
        assert_eq!(label("pt"), "Desabilitar serviço");
        assert_eq!(label("zh"), "禁用服务");
        let tags: Vec<&str> = LANGUAGES.iter().map(|code| language_tag(code)).collect();
        assert_eq!(tags, ["en", "es", "fr", "pt-BR", "zh-CN"]);
        assert_eq!(language_name("pt"), "Brazilian Portuguese");
    }

    #[test]
    fn catalogs_parse_and_keep_placeholders() {
        for (code, text) in CATALOG_SOURCES {
            let parsed: HashMap<String, String> = serde_json::from_str(text).expect(code);
            for (english, translated) in parsed {
                for n in 0..10 {
                    let placeholder = format!("{{{n}}}");
                    assert_eq!(
                        english.contains(&placeholder),
                        translated.contains(&placeholder),
                        "{code}: {english:?} -> {translated:?}"
                    );
                }
            }
        }
    }
}
