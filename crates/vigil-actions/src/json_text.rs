//! The JSON layout of the journal and of quarantine records: `", "` and `": "` separators, non-ASCII text
//! kept as is, and a one-space indent for records. A stable, readable layout keeps the files diffable and
//! lets History rewrite one line without touching the others.

use serde_json::Value;

/// One line: `{"a": 1, "b": [1, 2]}` (separators ", " and ": ").
pub fn dumps(value: &Value) -> String {
    let mut out = String::new();
    write_compact(value, &mut out);
    out
}

/// `json.dumps(value, indent=1)`: one space per level, "," at line ends.
pub fn dumps_indent1(value: &Value) -> String {
    let mut out = String::new();
    write_indented(value, 0, &mut out);
    out
}

fn write_compact(value: &Value, out: &mut String) {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_compact(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_string(key, out);
                out.push_str(": ");
                write_compact(item, out);
            }
            out.push('}');
        }
        other => write_scalar(other, out),
    }
}

fn write_indented(value: &Value, level: usize, out: &mut String) {
    match value {
        Value::Array(items) if !items.is_empty() => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                newline(level + 1, out);
                write_indented(item, level + 1, out);
            }
            newline(level, out);
            out.push(']');
        }
        Value::Object(map) if !map.is_empty() => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                newline(level + 1, out);
                write_string(key, out);
                out.push_str(": ");
                write_indented(item, level + 1, out);
            }
            newline(level, out);
            out.push('}');
        }
        Value::Array(_) => out.push_str("[]"),
        Value::Object(_) => out.push_str("{}"),
        other => write_scalar(other, out),
    }
}

fn newline(level: usize, out: &mut String) {
    out.push('\n');
    out.extend(std::iter::repeat_n(' ', level));
}

fn write_scalar(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => write_string(text, out),
        Value::Array(_) | Value::Object(_) => write_compact(value, out),
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_the_journal_layout() {
        let value = json!({"id": "x", "n": [1, 2.5, null], "s": "C:\\é\n\u{1}", "o": {}, "ok": true});
        assert_eq!(
            dumps(&value),
            r#"{"id": "x", "n": [1, 2.5, null], "s": "C:\\é\n\u0001", "o": {}, "ok": true}"#
        );
        assert_eq!(
            dumps_indent1(&json!({"a": 1, "b": [1], "c": []})),
            "{\n \"a\": 1,\n \"b\": [\n  1\n ],\n \"c\": []\n}"
        );
    }
}
