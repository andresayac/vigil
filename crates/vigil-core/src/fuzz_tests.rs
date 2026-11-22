//! Robustness of the core's readers of untrusted data: names shown to the user, the saved
//! watch state and settings (files any program the user runs can edit), the hosts file.
//! Random and mutated input must never panic or stall; the sanitizer must never let a hidden or
//! direction-changing character through.

use std::path::PathBuf;

use crate::fuzz::{Rng, check, check_text};

/// The sanitizer's whole job: after it, nothing invisible or direction-changing is left.
#[test]
fn shown_text_never_hides_anything() {
    let mut rng = Rng::new(41);
    let tokens = &[
        "\u{202A}",
        "\u{202B}",
        "\u{202C}",
        "\u{202D}",
        "\u{202E}",
        "\u{2066}",
        "\u{2067}",
        "\u{2068}",
        "\u{2069}",
        "\u{200E}",
        "\u{200F}",
        "\u{061C}",
        "\u{200B}",
        "\u{FEFF}",
        "\u{0085}",
        "\u{009B}",
        "\u{001B}",
        "\t",
        "\r",
        "\n",
        "invoice",
        ".exe",
        "fdp.",
        "⟨U+202E⟩",
    ];
    for _ in 0..5_000 {
        let text = rng.text(16, tokens);
        check_text("display sanitizer", &text, || {
            let shown = crate::display::shown(&text);
            assert!(crate::display::is_plain(&shown), "hidden character left in {shown:?}");
            let line = crate::display::shown_line(&text);
            assert!(crate::display::is_plain(&line), "hidden character left in {line:?}");
            assert!(!line.contains(['\t', '\n', '\r']), "line break left in {line:?}");
            if crate::display::is_plain(&text) {
                assert_eq!(shown, text, "plain text is shown as it is");
            }
        });
    }
}

const JSON_TOKENS: &[&str] = &[
    "{",
    "}",
    "[",
    "]",
    "\"",
    ":",
    ",",
    "null",
    "true",
    "1e999",
    "-1",
    "18446744073709551616",
    "\"alerts\"",
    "\"settings\"",
    "\"fingerprint\"",
    "\"version\"",
    "\"watching\"",
    "\"language\"",
    "\"absent\"",
    "\"update\"",
    "\"provider\"",
    "\"endpoint\"",
    "\"model\"",
    "[[[[[[[[[[",
    "\\u0000",
    "\\ud800",
];

/// A temp folder, removed when dropped.
struct Temp(PathBuf);

impl Temp {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("vigil-fuzz-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        Temp(dir)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `watch.json` is shared by two copies of Vigil and lives where the user's programs can write:
/// a damaged one is set aside and the watch starts again, never a panic.
#[test]
fn any_watch_file_loads_or_is_set_aside() {
    let mut rng = Rng::new(42);
    let temp = Temp::new("watch");
    let dir = temp.0.join("watch");
    let sample = br#"{"settings":{"watching":true,"language":"es","scanSchedule":"daily","scanTime":"03:00"},"alerts":[{"id":1,"kind":"service","severity":"warning","title":"New service","detail":"x","page":"services","timeMs":1}],"nextId":2,"fingerprint":{"version":3,"startup":{},"services":{},"absent":{}},"update":{"lastCheckMs":1}}"#;
    for case in 0..150 {
        let bytes = match case % 3 {
            0 => rng.bytes(600),
            1 => rng.mutate(sample),
            _ => rng.text(40, JSON_TOKENS).into_bytes(),
        };
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("watch.json"), &bytes);
        check("watch file", &bytes, || {
            let store = crate::watch::Store::new(dir.clone());
            let _ = store.load();
            let _ = store.update(|file| file.alerts.len());
        });
    }
}

/// Settings and the ignore list are read at every start.
#[test]
fn any_settings_file_loads_as_defaults() {
    let mut rng = Rng::new(43);
    let temp = Temp::new("settings");
    let settings = temp.0.join("settings.json");
    let ignored = temp.0.join("ignored.json");
    let sample = br#"{"theme":"dark","language":"fr","ai":{"provider":"openai","endpoint":"https://203.0.113.5/v1","model":"x","anonymize":true},"eventDays":30}"#;
    for case in 0..200 {
        let bytes = if case % 2 == 0 {
            rng.bytes(500)
        } else {
            rng.mutate(sample)
        };
        let _ = std::fs::write(&settings, &bytes);
        let _ = std::fs::write(&ignored, &bytes);
        check("settings file", &bytes, || {
            let _ = crate::settings::Stored::load(&settings);
            let _ = crate::settings::Ignored::load(ignored.clone());
        });
    }
}

/// The hosts file is checked every minute; malware writes it.
#[test]
fn any_hosts_file_parses() {
    let mut rng = Rng::new(44);
    let tokens = &[
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "203.0.113.5",
        "localhost",
        "www.contoso.com",
        "wpad",
        " ",
        "\t",
        "#",
        "\r\n",
        "\n",
        "%",
        "\u{202E}",
        "999.999.999.999",
        "fe80::1%eth0",
    ];
    let sample = "# hosts\r\n127.0.0.1 localhost\r\n203.0.113.5 www.contoso.com update.contoso.com # pinned\r\n0.0.0.0 ads.example\r\n";
    for case in 0..3_000 {
        let text = if case % 2 == 0 {
            rng.text(30, tokens)
        } else {
            rng.mutate_text(sample, tokens)
        };
        check_text("hosts file", &text, || {
            let _ = crate::watch::hosts_redirects(&text);
        });
    }
    let long = "203.0.113.5 ".repeat(50_000);
    check_text("long hosts line", &long, || {
        let _ = crate::watch::hosts_redirects(&long);
    });
}
