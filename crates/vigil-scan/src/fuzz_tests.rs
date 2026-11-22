//! Robustness of the scan's readers and judges of untrusted text: command lines, secrets in
//! files and history, paths, saved reports, release answers. Random and mutated input must never
//! panic or stall; the secret scanners also get long adversarial lines.

use std::path::Path;

use serde_json::{Map, Value, json};

use crate::fuzz::{Rng, check, check_text};
use crate::model::Analysis;

const COMMAND_TOKENS: &[&str] = &[
    "\"",
    "'",
    " ",
    "^",
    "%",
    "%TEMP%",
    "%x",
    "!",
    "&",
    "|",
    ">",
    "<",
    "(",
    ")",
    "C:\\",
    "\\\\?\\",
    "\\??\\",
    "\\\\server\\share\\",
    "powershell",
    "-enc ",
    "-EncodedCommand ",
    "-e ",
    "cmd /c ",
    "rundll32.exe ",
    ",#1",
    "regsvr32 /s /i:",
    "mshta ",
    "wscript ",
    "http://203.0.113.5/x",
    "SQBFAFgA",
    "=",
    "==",
    "AAAA",
    "..\\",
    ".exe",
    ".dll",
    ".ps1",
    "\u{202E}",
    "\0",
];

const SECRET_TOKENS: &[&str] = &[
    "password=",
    "Password=",
    "pwd=",
    "secret=",
    "token=",
    "api_key=",
    "OPENAI_API_KEY=",
    "AKIA",
    "ASIA",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "sk-",
    "sk-ant-",
    "Bearer ",
    "AccountKey=",
    "Server=x;Password=",
    "ConvertTo-SecureString \"",
    "\" -AsPlainText -Force",
    "net user ",
    " /add",
    "/p:",
    "-Password ",
    "https://user:pass@",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----END RSA PRIVATE KEY-----",
    "Proc-Type: 4,ENCRYPTED",
    "<Password><Value>",
    "</Value></Password>",
    "cpassword=\"",
    "password 51:b:",
    "\n",
    "\r\n",
    "\"",
    "'",
    "$",
    "{",
    "}",
    "<",
    ">",
    "*",
    "Read-Host",
    "${X}",
    "<your-key>",
    "EXAMPLE",
    "0123456789abcdef",
];

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
    "false",
    "-0",
    "1e999",
    "-1e999",
    "18446744073709551616",
    "0.0000001",
    "\"items\"",
    "\"verdict\"",
    "\"remove\"",
    "\"meta\"",
    "\\u0000",
    "\\ud800",
    "\"\\",
    "[[[[[[[[[[",
];

/// Command lines come from services, tasks, Run keys and processes: anything goes.
#[test]
fn command_lines_parse_anything() {
    let mut rng = Rng::new(21);
    let sample = r#""C:\Program Files\Contoso\upd.exe" -q --token x & powershell -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="#;
    for case in 0..2_500 {
        let line = if case % 2 == 0 {
            rng.text(24, COMMAND_TOKENS)
        } else {
            rng.mutate_text(sample, COMMAND_TOKENS)
        };
        // Resolving a bare program name looks in every PATH folder on disk: one case in four.
        let resolve = case % 4 == 1;
        check_text("command line", &line, || {
            if resolve {
                let _ = crate::cmdline::parse_command(&line, Some(r"C:\Users\jdoe"));
                let _ = crate::cmdline::split_command(&line, None);
            }
            let _ = crate::cmdline::split_args(&line);
            let _ = crate::cmdline::decode_encoded_command(&line);
            let _ = crate::cmdline::expand_env(&line);
            let _ = crate::cmdline::normalize_path(&line);
            let _ = crate::ntpath::normpath(&line);
            let _ = crate::ntpath::splitroot(&line);
            let _ = crate::ntpath::splitext(&line);
            let _ = crate::ntpath::dirname(&line);
            let _ = crate::ntpath::join(&line, &[&line, "x"]);
            let _ = crate::rmm::agent_for(&line);
        });
    }
}

/// Secret scanners read history and configuration files the user's programs write.
#[test]
fn secret_scanners_survive_anything() {
    let mut rng = Rng::new(22);
    let sample = "$cred = ConvertTo-SecureString \"Summer2026!Example\" -AsPlainText -Force\r\nnet user backdoor Summer2026! /add\r\nOPENAI_API_KEY=sk-proj-EXAMPLEexampleEXAMPLE0000\r\n";
    let kinds = [
        crate::secrets::FileKind::Rdp,
        crate::secrets::FileKind::Env,
        crate::secrets::FileKind::Key,
        crate::secrets::FileKind::AwsCredentials,
        crate::secrets::FileKind::GitCredentials,
        crate::secrets::FileKind::Npmrc,
        crate::secrets::FileKind::Pypirc,
        crate::secrets::FileKind::Connections,
        crate::secrets::FileKind::Docker,
        crate::secrets::FileKind::AzureTokens,
        crate::secrets::FileKind::ConfigText,
        crate::secrets::FileKind::PasswordList,
    ];
    for case in 0..2_000 {
        let text = if case % 2 == 0 {
            rng.text(30, SECRET_TOKENS)
        } else {
            rng.mutate_text(sample, SECRET_TOKENS)
        };
        let kind = kinds[rng.below(kinds.len())];
        check_text("secret scanners", &text, || {
            let _ = crate::secrets::line_kinds(&text);
            let _ = crate::secrets::mask_values(&text);
            let _ = crate::secrets::unattend_found(&text);
            let _ = crate::secrets::gpp_found(&text);
            let _ = crate::secrets::private_key_found(&text);
            let _ = crate::secrets::file_found(kind, &text);
            let _ = crate::privacy::scrub_secrets(&text);
            let _ = crate::privacy::clip(&text, 40);
        });
    }
}

/// Long, repetitive lines: a pattern that backtracks or a loop that restarts would take
/// seconds here instead of milliseconds.
#[test]
fn secret_scanners_stay_fast_on_long_adversarial_lines() {
    let pieces = [
        "password=",
        "a",
        "-----BEGIN ",
        "Bearer ",
        "sk-",
        "net user ",
        "https://u:p@",
        "\"",
        "=",
        "$x=\"",
        "AccountKey=",
        "github_pat_",
        "<Password><Value>",
        "cpassword=\"",
        "ConvertTo-SecureString \"",
    ];
    for piece in pieces {
        let line = piece.repeat(50_000 / piece.len().max(1));
        check_text("long secret line", &line, || {
            let _ = crate::secrets::line_kinds(&line);
            let _ = crate::secrets::mask_values(&line);
            let _ = crate::secrets::file_found(crate::secrets::FileKind::ConfigText, &line);
            let _ = crate::privacy::scrub_secrets(&line);
            let _ = crate::cmdline::parse_command(&line, None);
        });
    }
}

/// File contents decoded from other programs' files (UTF-8, UTF-16 with or without a mark).
#[test]
fn decoders_accept_any_bytes() {
    let mut rng = Rng::new(23);
    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(
            "profile line\r\nInvoke-WebRequest x"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        )
        .collect();
    for case in 0..3_000 {
        let bytes = if case % 2 == 0 {
            rng.bytes(400)
        } else {
            rng.mutate(&utf16)
        };
        check("decoders", &bytes, || {
            let _ = crate::persist::decode(&bytes);
            let _ = crate::hooks::packed_path(&bytes);
            let _ = crate::lenient::bytes_literal(&bytes);
        });
    }
}

/// Small helpers on text and numbers from inventories.
#[test]
fn lenient_helpers_survive_extremes() {
    let mut rng = Rng::new(24);
    for _ in 0..3_000 {
        let text = rng.text(
            10,
            &[
                "-",
                "+",
                "0x",
                "9",
                "99999999999999999999",
                " ",
                ".",
                "e",
                "€",
                "\u{202E}",
            ],
        );
        check_text("lenient text", &text, || {
            let _ = crate::lenient::parse_int(&text);
            let _ = crate::lenient::quote_literal(&text);
            let _ = crate::lenient::html_escape(&text);
            let _ = crate::lenient::take(&text, 3);
            let _ = crate::lenient::last(&text, 3);
            let _ = crate::lenient::capitalize_first(&text);
            let _ = crate::persist::manifest_location(&text);
            let _ = crate::browsers::all_sites(&text);
            let _ = crate::browsers::store_update(&text);
            let _ = crate::browsers::installed_by_settings(&text);
            let _ = crate::browsers::classify_chromium(&text, &text, &text, Some(u64::MAX));
            let _ = crate::browsers::classify_firefox(&text, &text, &text, None);
            let _ = crate::release::parse_version(&text);
            let _ = crate::release::valid_release_url_for(&text, &text);
            let _ = crate::export::file_uri(&text);
            let _ = crate::export::csv_cell(&text);
        });
    }
    for value in [i128::MIN, i128::MAX, 0, -1] {
        check("group thousands", &value.to_le_bytes(), || {
            let _ = crate::lenient::group_thousands(value);
        });
    }
    for value in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::MAX,
        f64::MIN_POSITIVE,
        -0.0,
        1e300,
    ] {
        check("float text", &value.to_le_bytes(), || {
            let _ = crate::lenient::float_text(value);
            let _ = crate::lenient::round_to(value, 2);
            let _ = crate::lenient::format_grouped_rounded(value);
            let _ = crate::lenient::format_grouped(&json!(value));
        });
    }
    for mask in [0, 1, u64::MAX, 1 << 63] {
        check("disable reasons", &mask.to_le_bytes(), || {
            let _ = crate::browsers::chromium_disable_reasons(mask);
        });
    }
}

/// The release answer comes from the network: any body is refused or parsed, never a panic.
#[test]
fn release_answers_parse_anything() {
    let mut rng = Rng::new(25);
    let sample = r#"{"tag_name":"v9.9.9","html_url":"https://github.com/andresayac/vigil/releases/tag/v9.9.9","draft":false,"prerelease":false,"assets":[{"name":"Vigil_9.9.9_x64-setup.exe"}]}"#;
    for case in 0..2_000 {
        let body = if case % 2 == 0 {
            rng.text(30, JSON_TOKENS)
        } else {
            rng.mutate_text(sample, JSON_TOKENS)
        };
        check_text("release answer", &body, || {
            let _ = crate::release::parse(&body);
        });
    }
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    check_text("deep release answer", &deep, || {
        let _ = crate::release::parse(&deep);
    });
}

/// A random JSON value: nested objects and arrays, odd numbers and strings.
fn value(rng: &mut Rng, depth: usize) -> Value {
    match if depth == 0 { rng.below(4) } else { rng.below(6) } {
        0 => Value::Null,
        1 => [
            json!(0),
            json!(-1),
            json!(i64::MIN),
            json!(u64::MAX),
            json!(1e308),
            json!(-0.5),
        ][rng.below(6)]
        .clone(),
        2 => Value::String(rng.text(6, &["remove", "review", "trusted", "exe", "C:\\", "\u{202E}", ""])),
        3 => Value::Bool(rng.chance(50)),
        4 => Value::Array((0..rng.below(5)).map(|_| value(rng, depth - 1)).collect()),
        _ => {
            let keys = [
                "items", "verdict", "score", "roles", "flags", "file", "meta", "kind", "name", "path", "facts",
                "commands", "changes", "summary", "posture", "id", "trusted", "level",
            ];
            let mut map = Map::new();
            for _ in 0..rng.below(8) {
                map.insert(keys[rng.below(keys.len())].to_string(), value(rng, depth - 1));
            }
            Value::Object(map)
        }
    }
}

/// Saved reports can be edited by anyone who can write the scans folder; loading one, turning it
/// into a model, comparing, rendering and exporting it must never panic.
#[test]
fn reports_of_any_shape_load_and_render() {
    let mut rng = Rng::new(26);
    for _ in 0..400 {
        let data = value(&mut rng, 5);
        let text = data.to_string();
        check_text("report model", &text, || {
            let analysis = Analysis::from_value(&data);
            let _ = analysis.to_value();
            let _ = crate::export::csv(&analysis, crate::export::Options::default());
            let _ = crate::export::sarif(&analysis, crate::export::Options::default());
            let _ = crate::privacy::Redactor::new("jdoe", "PC-VICTIM", true).apply(&data);
        });
    }
    let dir = std::env::temp_dir().join(format!("vigil-fuzz-reports-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("scan-20260101-100000-report.json");
    for case in 0..120 {
        let bytes = match case % 3 {
            0 => rng.bytes(512),
            1 => rng.text(30, JSON_TOKENS).into_bytes(),
            _ => json!({"items": [value(&mut rng, 4)], "meta": value(&mut rng, 3)})
                .to_string()
                .into_bytes(),
        };
        let _ = std::fs::write(&path, &bytes);
        check("saved report", &bytes, || {
            let _ = crate::pipeline::load_report(Path::new(&path));
        });
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: `\\server\share\…` in a command line made the scan probe the file over SMB,
/// which connects to that server (2.7 s here, and it offers the user's credentials). A remote
/// path is now never opened, checked for a signature or hashed.
#[test]
fn remote_paths_are_never_opened() {
    use crate::cmdline::is_remote_path;
    for remote in [
        r"\\server\share\",
        r"\\203.0.113.5\c$\x.exe",
        r"\\?\UNC\server\share\x.exe",
        r"\\.\pipe\x",
        r"\\?\Volume{00000000-0000-0000-0000-000000000000}\x.exe",
        "//server/share/x.exe",
        r#""\\server\share\x.exe""#,
    ] {
        assert!(is_remote_path(remote), "{remote}");
    }
    for local in [
        r"C:\Windows\System32\cmd.exe",
        r"\\?\C:\Windows\x.exe",
        r"x.exe",
        r"\Windows\x",
        "",
    ] {
        assert!(!is_remote_path(local), "{local}");
    }
    let line = r"\\server\share\";
    let started = std::time::Instant::now();
    let parsed = crate::cmdline::parse_command(line, None);
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "no network lookup"
    );
    let _ = parsed;
    let started = std::time::Instant::now();
    assert!(!crate::cmdline::is_file(r"\\server\share\x.exe"));
    assert!(started.elapsed() < std::time::Duration::from_millis(200));
}
