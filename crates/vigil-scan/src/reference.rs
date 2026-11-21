//! The low-level helpers against recorded reference cases (tests/data/helpers.json).

use serde_json::{Value, json};

use crate::cmdline::{normalize_path, parse_command, split_args};
use crate::ntpath;
use crate::privacy::{Redactor, clip, scrub_secrets};
use crate::rules::{in_microsoft_home, is_user_writable, label_flags, location_flags, name_flags, scan_text};
use crate::{ip, lenient};

/// Read at run time (like the inventories, it is kept out of the test executable).
fn golden() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("helpers.json");
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null)
}

/// Golden strings refer to the %SystemRoot% of the machine that made them.
fn local(value: &Value) -> Value {
    let theirs = golden()["windir"].as_str().unwrap_or(r"C:\Windows").to_string();
    match value {
        Value::String(s) => json!(s.replace(&theirs, &ntpath::WINDIR)),
        Value::Array(items) => Value::Array(items.iter().map(local).collect()),
        other => other.clone(),
    }
}

fn rows(key: &str) -> Vec<Value> {
    golden()[key].as_array().cloned().unwrap_or_default()
}

fn codes(flags: Vec<crate::model::Flag>) -> Value {
    json!(flags.into_iter().map(|f| f.code).collect::<Vec<_>>())
}

#[test]
fn golden_data_is_present() {
    assert!(golden().is_object());
}

#[test]
fn paths_match_the_reference() {
    for row in rows("paths") {
        let p = row["path"].as_str().unwrap_or("");
        let (d, r, t) = ntpath::splitroot(p);
        let (root, ext) = ntpath::splitext(p);
        assert_eq!(json!(ntpath::isabs(p)), row["isabs"], "isabs {p:?}");
        assert_eq!(json!([d, r, t]), row["splitroot"], "splitroot {p:?}");
        assert_eq!(json!(ntpath::normpath(p)), row["normpath"], "normpath {p:?}");
        assert_eq!(json!(ntpath::basename(p)), row["basename"], "basename {p:?}");
        assert_eq!(json!(ntpath::dirname(p)), row["dirname"], "dirname {p:?}");
        assert_eq!(json!([root, ext]), row["splitext"], "splitext {p:?}");
        assert_eq!(json!(ntpath::join(p, &["child.txt"])), row["join"], "join {p:?}");
        assert_eq!(
            json!(normalize_path(p)),
            local(&row["normalize"]),
            "normalize_path {p:?}"
        );
    }
}

#[test]
fn command_parsing_matches_the_reference() {
    for row in rows("commands") {
        let command = row["raw"].as_str().unwrap_or("");
        let p = parse_command(command, None);
        let ours = json!({
            "raw": p.raw, "program": p.program, "args": p.args, "host": p.host, "payload": p.payload,
            "payload_url": p.payload_url, "inline": p.inline, "decoded": p.decoded, "hidden": p.hidden,
            "compound": p.compound, "certain": p.certain, "chain": p.chain, "target": p.target(),
        });
        for key in ours
            .as_object()
            .map(|m| m.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
        {
            assert_eq!(ours[&key], local(&row[&key]), "{key} of {command:?}");
        }
    }
    for row in rows("split_args") {
        let args = row["args"].as_str().unwrap_or("");
        assert_eq!(json!(split_args(args)), row["tokens"], "{args:?}");
    }
}

#[test]
fn addresses_match_the_reference() {
    for row in rows("ips") {
        let address = row["ip"].as_str().unwrap_or("");
        assert_eq!(json!(ip::address_class(address)), row["class"], "{address:?}");
        assert_eq!(json!(ip::is_public(address)), row["public"], "{address:?}");
    }
}

#[test]
fn privacy_matches_the_reference() {
    for row in rows("scrub") {
        let text = row["text"].as_str().unwrap_or("");
        assert_eq!(json!(scrub_secrets(text)), row["scrubbed"], "{text:?}");
    }
    let redactor = Redactor::new("jdoe", "DESKTOP-ABC123", true);
    for row in rows("redact") {
        let text = row["text"].as_str().unwrap_or("");
        assert_eq!(json!(redactor.text(text)), row["redacted"], "{text:?}");
    }
    for row in rows("clip") {
        let text = row["text"].as_str().unwrap_or("");
        let limit = row["limit"].as_u64().unwrap_or(0) as usize;
        assert_eq!(json!(clip(text, limit)), row["clipped"], "{text:?}");
    }
}

#[test]
fn rules_match_the_reference() {
    for row in rows("names") {
        let path = row["path"].as_str().unwrap_or("");
        assert_eq!(codes(name_flags(path, false, false)), row["flags"], "{path:?}");
        assert_eq!(codes(name_flags(path, true, true)), row["signed"], "{path:?}");
    }
    for row in rows("locations") {
        let path = row["path"].as_str().unwrap_or("");
        assert_eq!(codes(location_flags(path)), row["flags"], "{path:?}");
        assert_eq!(json!(is_user_writable(path)), row["writable"], "{path:?}");
        assert_eq!(json!(in_microsoft_home(path)), row["ms_home"], "{path:?}");
    }
    for row in rows("scan") {
        let text = row["text"].as_str().unwrap_or("");
        assert_eq!(codes(scan_text(text)), row["flags"], "{text:?}");
    }
    for row in rows("labels") {
        let name = row["name"].as_str().unwrap_or("");
        assert_eq!(codes(label_flags(&[name])), row["flags"], "{name:?}");
    }
    assert!(lenient::truthy(&json!(1)));
}
