//! Robustness of what the action engine reads back: registry values, tool output, command lines
//! from service keys, the journal and quarantine records (files in a folder the standard copy's
//! user can write). Random and mutated input must never panic or stall.

use crate::fuzz::{Rng, check, check_text};

/// Registry data of any type and length, and the hex form History stores.
#[test]
fn registry_values_decode_any_data() {
    let mut rng = Rng::new(51);
    for _ in 0..4_000 {
        let kind = [1u32, 2, 3, 4, 5, 6, 7, 11, 0xFFFF_FFFF][rng.below(9)];
        let data = rng.bytes(300);
        let text = String::from_utf8_lossy(&data).into_owned();
        check("registry value", &data, || {
            let value = crate::registry::decode_value(kind, &data);
            let _ = crate::registry::hex(&data);
            let _ = crate::registry::unhex(&text);
            let _ = value.to_string();
            let _ = crate::registry::split_key(&text);
        });
    }
}

/// Output of the tools Vigil runs (UTF-16 with or without a mark, the OEM code page, garbage).
#[test]
fn tool_output_decodes_any_bytes() {
    let mut rng = Rng::new(52);
    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain("SUCCESS: done.\r\n".encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    for case in 0..4_000 {
        let data = if case % 2 == 0 {
            rng.bytes(300)
        } else {
            rng.mutate(&utf16)
        };
        check("tool output", &data, || {
            let _ = crate::runner::decode(&data);
        });
    }
}

/// Command lines from service keys and uninstall entries.
#[test]
fn command_lines_split_anything() {
    let mut rng = Rng::new(53);
    let tokens = &[
        "\"",
        " ",
        "%",
        "%SystemRoot%",
        "%x",
        "^",
        "C:\\",
        "\\\\?\\",
        "\\??\\",
        "\\\\server\\share\\",
        "..\\",
        ".exe",
        "MsiExec.exe /X{",
        "}",
        "/S",
        "\u{202E}",
        "\0",
    ];
    let sample = r#""C:\Program Files\Contoso\uninstall.exe" /S --mode "quiet""#;
    for case in 0..2_500 {
        let line = if case % 2 == 0 {
            rng.text(16, tokens)
        } else {
            rng.mutate_text(sample, tokens)
        };
        // Resolving a bare name looks in the system folders on disk: one case in four.
        let resolve = case % 4 == 1;
        check_text("action command line", &line, || {
            if resolve {
                let _ = crate::cmdline::split_command(&line);
            }
            let _ = crate::cmdline::normalize_path(&line);
            let _ = crate::cmdline::expand_env(&line);
            let _ = crate::cmdline::normpath(&line);
            let _ = crate::cmdline::dirname(&line);
            let _ = crate::cmdline::in_dir(&line, r"C:\Windows");
        });
    }
}

/// Regression: a service ImagePath or uninstall string on a share made the elevated engine
/// probe `\\server\share` over SMB while resolving the program. Remote paths are never opened.
#[test]
fn remote_paths_are_never_probed() {
    use crate::cmdline::is_remote_path;
    for remote in [
        r"\\server\share\x.exe",
        r"\\?\UNC\server\share\x.exe",
        r"\\.\pipe\x",
        "//server/x",
    ] {
        assert!(is_remote_path(remote), "{remote}");
    }
    for local in [r"C:\Windows\System32\svchost.exe", r"\\?\C:\x.exe", "x.exe", ""] {
        assert!(!is_remote_path(local), "{local}");
    }
    let started = std::time::Instant::now();
    let _ = crate::cmdline::split_command(r"\\server\share\x /S");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "no network lookup"
    );
}

/// Journal lines and quarantine records are read back at every start; any content is skipped,
/// never a panic.
#[test]
fn damaged_journal_and_quarantine_records_are_skipped() {
    let mut rng = Rng::new(54);
    let dir = std::env::temp_dir().join(format!("vigil-fuzz-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let Ok(store) = crate::Store::open(&dir) else {
        return;
    };
    let record = br#"{"id":"1","batch":null,"time":"2026-01-01T10:00:00","op":"file.quarantine","label":"Quarantine","target":"C:\\x.exe","ok":true,"message":"done","undo":{"id":"q1","original":"C:\\x.exe"}}"#;
    let quarantine =
        br#"{"id":"q1","original":"C:\\x.exe","sha256":"ab","size":1,"quarantinedAt":"2026-01-01T10:00:00"}"#;
    let _ = std::fs::create_dir_all(store.quarantine_dir());
    for case in 0..150 {
        let journal = match case % 3 {
            0 => rng.bytes(600),
            1 => rng.mutate(record),
            _ => [record.as_slice(), b"\n", &rng.mutate(record), b"\n", &rng.bytes(64)].concat(),
        };
        let meta = if case % 2 == 0 {
            rng.bytes(300)
        } else {
            rng.mutate(quarantine)
        };
        let _ = std::fs::write(store.journal_path(), &journal);
        let _ = std::fs::write(store.quarantine_dir().join("q1.json"), &meta);
        check("journal and quarantine", &journal, || {
            for r in store.records() {
                let _ = (r.op(), r.target(), r.undo_data(), r.batch(), r.undone());
            }
            let _ = store.quarantined();
        });
    }
    let _ = std::fs::remove_dir_all(&dir);
}
