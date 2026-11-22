//! Lenient helpers over JSON values, used by the collectors and the rules: truthiness, the text and
//! literal forms of values, whitespace stripping, slicing by characters and the stable JSON layout of
//! reports. They matter because their output ends up in labels, report text and the data sent to the AI.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::{Captures, Match, Regex, Replacer};
use serde::Serialize;
use serde_json::{Map, Value};

pub(crate) static NULL: Value = Value::Null;
static EMPTY_MAP: LazyLock<Map<String, Value>> = LazyLock::new(Map::new);

// --------------------------------------------------------------------------- regular expressions

/// A compiled pattern that never panics: an invalid pattern (a bug caught by the tests) matches nothing.
pub(crate) struct Rx(Option<Regex>);

impl Rx {
    pub(crate) fn new(pattern: &str) -> Self {
        Self(Regex::new(pattern).ok())
    }

    #[cfg(test)]
    pub(crate) fn is_valid(&self) -> bool {
        self.0.is_some()
    }

    pub(crate) fn is_match(&self, text: &str) -> bool {
        self.0.as_ref().is_some_and(|re| re.is_match(text))
    }

    pub(crate) fn find<'t>(&self, text: &'t str) -> Option<Match<'t>> {
        self.0.as_ref()?.find(text)
    }

    pub(crate) fn find_at<'t>(&self, text: &'t str, start: usize) -> Option<Match<'t>> {
        self.0.as_ref()?.find_at(text, start)
    }

    pub(crate) fn captures<'t>(&self, text: &'t str) -> Option<Captures<'t>> {
        self.0.as_ref()?.captures(text)
    }

    /// Every match, with its position (none when the pattern did not compile).
    pub(crate) fn matches<'t>(&self, text: &'t str) -> Vec<Match<'t>> {
        match &self.0 {
            Some(re) => re.find_iter(text).collect(),
            None => Vec::new(),
        }
    }

    /// Every match's capture groups (none when the pattern did not compile).
    pub(crate) fn captures_all<'t>(&self, text: &'t str) -> Vec<Captures<'t>> {
        match &self.0 {
            Some(re) => re.captures_iter(text).collect(),
            None => Vec::new(),
        }
    }

    pub(crate) fn find_all<'t>(&self, text: &'t str) -> Vec<&'t str> {
        match &self.0 {
            Some(re) => re.find_iter(text).map(|m| m.as_str()).collect(),
            None => Vec::new(),
        }
    }

    pub(crate) fn replace_all<'t, R: Replacer>(&self, text: &'t str, rep: R) -> Cow<'t, str> {
        match &self.0 {
            Some(re) => re.replace_all(text, rep),
            None => Cow::Borrowed(text),
        }
    }
}

/// `static NAME: LazyLock<Rx>` for a pattern.
macro_rules! rx {
    ($name:ident, $pattern:expr) => {
        static $name: std::sync::LazyLock<$crate::lenient::Rx> =
            std::sync::LazyLock::new(|| $crate::lenient::Rx::new($pattern));
    };
}
pub(crate) use rx;

// --------------------------------------------------------------------------- JSON access

/// `dict.get(key)` that works on any value (missing keys and non-objects give `None`).
pub(crate) trait Get {
    fn at(&self, key: &str) -> &Value;
}

impl Get for Value {
    fn at(&self, key: &str) -> &Value {
        self.get(key).unwrap_or(&NULL)
    }
}

impl Get for Map<String, Value> {
    fn at(&self, key: &str) -> &Value {
        self.get(key).unwrap_or(&NULL)
    }
}

/// Truthiness: `null`, `false`, `0`, `""`, `[]` and `{}` are false.
pub(crate) fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `str(value or "")`.
pub(crate) fn text(value: &Value) -> String {
    if truthy(value) { str_of(value) } else { String::new() }
}

/// `value or ""`, keeping the original value when it is truthy.
pub(crate) fn or_empty(value: &Value) -> Value {
    if truthy(value) {
        value.clone()
    } else {
        Value::String(String::new())
    }
}

/// `value or []` as a slice.
pub(crate) fn list(value: &Value) -> &[Value] {
    match value {
        Value::Array(items) => items,
        _ => &[],
    }
}

/// `value or {}` as a map.
pub(crate) fn obj(value: &Value) -> &Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => &EMPTY_MAP,
    }
}

/// `str(value)` when the value is not `None`.
pub(crate) fn opt_str(value: &Value) -> Option<String> {
    if value.is_null() { None } else { Some(str_of(value)) }
}

/// `value is True`.
pub(crate) fn is_true(value: &Value) -> bool {
    value.as_bool() == Some(true)
}

/// `value is False`.
pub(crate) fn is_false(value: &Value) -> bool {
    value.as_bool() == Some(false)
}

/// The number a value compares equal to (`true == 1`, `1.0 == 1`).
pub(crate) fn as_number(value: &Value) -> Option<f64> {
    match value {
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

/// The integer a value compares equal to (`true == 1`, `5.0 == 5`), if any.
pub(crate) fn as_integral(value: &Value) -> Option<i64> {
    match as_number(value) {
        Some(n) if n.is_finite() && n.fract() == 0.0 && n.abs() < 9.0e15 => Some(n as i64),
        _ => None,
    }
}

/// `value == number`.
pub(crate) fn eq_num(value: &Value, number: f64) -> bool {
    as_number(value) == Some(number)
}

/// Whether the value is an integer (booleans included).
pub(crate) fn as_int(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(b) => Some(i64::from(*b)),
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_u64().map(|u| i64::try_from(u).unwrap_or(i64::MAX))),
        _ => None,
    }
}

/// `int(value)` with 0 for anything that cannot be converted.
pub(crate) fn int_of(value: &Value) -> i64 {
    match value {
        Value::Bool(b) => i64::from(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i
            } else if let Some(u) = n.as_u64() {
                i64::try_from(u).unwrap_or(i64::MAX)
            } else {
                match n.as_f64() {
                    Some(f) if f.is_finite() => f.trunc() as i64,
                    _ => 0,
                }
            }
        }
        Value::String(s) => parse_int(s).unwrap_or(0),
        _ => 0,
    }
}

/// `int(text)`: optional sign, ASCII digits, single underscores between digits, outer whitespace.
pub(crate) fn parse_int(text: &str) -> Option<i64> {
    let s = strip(text);
    let (negative, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let mut value: i64 = 0;
    for c in digits.chars() {
        if c == '_' {
            continue;
        }
        let d = c.to_digit(10)?;
        value = value.checked_mul(10)?.checked_add(i64::from(d))?;
    }
    Some(if negative { -value } else { value })
}

/// The larger of two optional values (strings or numbers), ignoring empty ones.
pub(crate) fn max_of(current: &Value, candidate: &Value) -> Value {
    let values: Vec<&Value> = [current, candidate].into_iter().filter(|v| truthy(v)).collect();
    let mut best: Option<&Value> = None;
    for value in values {
        best = match best {
            None => Some(value),
            Some(b) => {
                let greater = match (b, value) {
                    (Value::String(x), Value::String(y)) => y > x,
                    _ => match (as_number(b), as_number(value)) {
                        (Some(x), Some(y)) => y > x,
                        _ => false,
                    },
                };
                Some(if greater { value } else { b })
            }
        };
    }
    best.cloned().unwrap_or(Value::Null)
}

/// The key `json.dumps` writes for a dict key that is not a string.
pub(crate) fn json_key(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        Value::Bool(true) => "true".into(),
        Value::Bool(false) => "false".into(),
        Value::Number(_) => str_of(value),
        other => str_of(other),
    }
}

// --------------------------------------------------------------------------- str() and repr()

/// `str(value)`.
pub(crate) fn str_of(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => literal_of(other),
    }
}

/// `repr(value)`.
pub(crate) fn literal_of(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                float_text(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => quote_literal(s),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(literal_of).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Object(map) => {
            let inner: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", quote_literal(k), literal_of(v)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// `repr(text)` for a string.
pub(crate) fn quote_literal(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        let code = c as u32;
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if c == quote => {
                out.push('\\');
                out.push(c);
            }
            _ if code < 0x20 || code == 0x7f => out.push_str(&format!("\\x{code:02x}")),
            _ if c.is_ascii() || is_printable(c) => out.push(c),
            _ if code <= 0xff => out.push_str(&format!("\\x{code:02x}")),
            _ if code <= 0xffff => out.push_str(&format!("\\u{code:04x}")),
            _ => out.push_str(&format!("\\U{code:08x}")),
        }
    }
    out.push(quote);
    out
}

/// `repr(bytes)`, used for binary registry values shown as text.
pub(crate) fn bytes_literal(data: &[u8]) -> String {
    let quote = if data.contains(&b'\'') && !data.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::from("b");
    out.push(char::from(quote));
    for &b in data {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ if b == quote => {
                out.push('\\');
                out.push(char::from(b));
            }
            0x20..=0x7e => out.push(char::from(b)),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out.push(char::from(quote));
    out
}

/// `repr(float)`: shortest round-trip digits, exponent below 1e-4 and from 1e16.
pub(crate) fn float_text(value: f64) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let formatted = format!("{value:e}");
    let (mantissa, exponent) = formatted.split_once('e').unwrap_or((formatted.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if negative { "-" } else { "" };
    if (-4..16).contains(&exponent) {
        let point = exponent + 1;
        let body = if point <= 0 {
            format!("0.{}{}", "0".repeat(point.unsigned_abs() as usize), digits)
        } else {
            let point = point as usize;
            if point >= digits.len() {
                format!("{}{}.0", digits, "0".repeat(point - digits.len()))
            } else {
                format!("{}.{}", &digits[..point], &digits[point..])
            }
        };
        format!("{sign}{body}")
    } else {
        let mantissa = if digits.len() == 1 {
            digits.clone()
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        format!("{sign}{mantissa}e{exp_sign}{:02}", exponent.unsigned_abs())
    }
}

/// `str.isprintable()` for one character (Unicode categories Cc, Cf, Co, Zs/Zl/Zp except space;
/// unassigned code points other than noncharacters are treated as printable).
pub(crate) fn is_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    !matches!(c,
        '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' | '\u{890}'..='\u{891}'
        | '\u{8e2}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}'
        | '\u{110bd}' | '\u{110cd}' | '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}'
        | '\u{1d173}'..='\u{1d17a}' | '\u{e0001}' | '\u{e0020}'..='\u{e007f}'
        | '\u{e000}'..='\u{f8ff}' | '\u{f0000}'..='\u{ffffd}' | '\u{100000}'..='\u{10fffd}'
        | '\u{fdd0}'..='\u{fdef}' | '\u{fffe}' | '\u{ffff}')
}

// --------------------------------------------------------------------------- strings

/// `str.isspace()` for one character.
pub(crate) fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()`.
pub(crate) fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// `str.lstrip()`.
pub(crate) fn lstrip(text: &str) -> &str {
    text.trim_start_matches(is_space)
}

/// `str.split()`.
pub(crate) fn split_ws(text: &str) -> Vec<&str> {
    text.split(is_space).filter(|part| !part.is_empty()).collect()
}

/// `text.split(None, 1)`: the first word and the rest (without its leading whitespace).
pub(crate) fn split_ws_once(text: &str) -> (&str, Option<&str>) {
    let text = lstrip(text);
    match text.find(is_space) {
        Some(end) => {
            let rest = lstrip(&text[end..]);
            (&text[..end], if rest.is_empty() { None } else { Some(rest) })
        }
        None => (text, None),
    }
}

/// `text[:n]` (characters).
pub(crate) fn take(text: &str, n: usize) -> &str {
    match text.char_indices().nth(n) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

/// `text[n:]` (characters).
pub(crate) fn skip(text: &str, n: usize) -> &str {
    match text.char_indices().nth(n) {
        Some((index, _)) => &text[index..],
        None => "",
    }
}

/// `text[-n:]` (characters).
pub(crate) fn last(text: &str, n: usize) -> &str {
    let count = char_len(text);
    if count <= n { text } else { skip(text, count - n) }
}

/// `len(text)`.
pub(crate) fn char_len(text: &str) -> usize {
    text.chars().count()
}

/// `text.lower()`.
pub(crate) fn lower(text: &str) -> String {
    text.to_lowercase()
}

/// `text[:1].upper() + text[1:]`.
pub(crate) fn capitalize_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// `html.escape(text, quote=True)`.
pub(crate) fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// `f"{number:,}"` for an integer.
pub(crate) fn group_thousands(number: i128) -> String {
    let digits = number.unsigned_abs().to_string();
    let mut out = String::new();
    for (index, c) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if number < 0 { format!("-{out}") } else { out }
}

/// `f"{value:,}"` for a JSON number (integers grouped; floats keep their decimals).
pub(crate) fn format_grouped(value: &Value) -> String {
    match value {
        Value::Bool(b) => group_thousands(i128::from(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                group_thousands(i128::from(i))
            } else if let Some(u) = n.as_u64() {
                group_thousands(i128::from(u))
            } else {
                let repr = float_text(n.as_f64().unwrap_or(0.0));
                match repr.split_once('.') {
                    Some((whole, frac)) if !repr.contains('e') => {
                        let whole_number: i128 = whole.parse().unwrap_or(0);
                        let sign = if whole.starts_with('-') && whole_number == 0 {
                            "-"
                        } else {
                            ""
                        };
                        format!("{sign}{}.{frac}", group_thousands(whole_number))
                    }
                    _ => repr,
                }
            }
        }
        other => str_of(other),
    }
}

/// `f"{value:,.0f}"`.
pub(crate) fn format_grouped_rounded(value: f64) -> String {
    let rounded = format!("{value:.0}");
    let negative = rounded.starts_with('-');
    let number: i128 = rounded.trim_start_matches('-').parse().unwrap_or(0);
    let grouped = group_thousands(number);
    if negative { format!("-{grouped}") } else { grouped }
}

/// `round(value, digits)` (correctly rounded through the decimal representation).
pub(crate) fn round_to(value: f64, digits: usize) -> f64 {
    format!("{value:.digits$}").parse().unwrap_or(value)
}

// --------------------------------------------------------------------------- json.dumps

/// `json.dumps(value, ensure_ascii=False, indent=1)`.
pub(crate) fn dumps_pretty(value: &Value) -> String {
    dumps(value, true)
}

/// `json.dumps(value, ensure_ascii=False, separators=(",", ":"))`.
pub(crate) fn dumps_compact(value: &Value) -> String {
    dumps(value, false)
}

fn dumps(value: &Value, pretty: bool) -> String {
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(
        &mut out,
        PyFormatter {
            pretty,
            level: 0,
            has_value: false,
        },
    );
    if value.serialize(&mut serializer).is_err() {
        return String::new();
    }
    String::from_utf8(out).unwrap_or_default()
}

/// The JSON layout of reports: an indent of one space and floats in their shortest form.
struct PyFormatter {
    pretty: bool,
    level: usize,
    has_value: bool,
}

impl PyFormatter {
    fn newline<W: ?Sized + std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        if self.pretty {
            writer.write_all(b"\n")?;
            for _ in 0..self.level {
                writer.write_all(b" ")?;
            }
        }
        Ok(())
    }
}

impl serde_json::ser::Formatter for PyFormatter {
    fn write_f64<W: ?Sized + std::io::Write>(&mut self, writer: &mut W, value: f64) -> std::io::Result<()> {
        writer.write_all(float_text(value).as_bytes())
    }

    fn write_f32<W: ?Sized + std::io::Write>(&mut self, writer: &mut W, value: f32) -> std::io::Result<()> {
        writer.write_all(float_text(f64::from(value)).as_bytes())
    }

    fn begin_array<W: ?Sized + std::io::Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        self.level += 1;
        self.has_value = false;
        writer.write_all(b"[")
    }

    fn end_array<W: ?Sized + std::io::Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        self.level -= 1;
        if self.has_value {
            self.newline(writer)?;
        }
        writer.write_all(b"]")
    }

    fn begin_array_value<W: ?Sized + std::io::Write>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()> {
        if !first {
            writer.write_all(b",")?;
        }
        self.newline(writer)
    }

    fn end_array_value<W: ?Sized + std::io::Write>(&mut self, _writer: &mut W) -> std::io::Result<()> {
        self.has_value = true;
        Ok(())
    }

    fn begin_object<W: ?Sized + std::io::Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        self.level += 1;
        self.has_value = false;
        writer.write_all(b"{")
    }

    fn end_object<W: ?Sized + std::io::Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        self.level -= 1;
        if self.has_value {
            self.newline(writer)?;
        }
        writer.write_all(b"}")
    }

    fn begin_object_key<W: ?Sized + std::io::Write>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()> {
        if !first {
            writer.write_all(b",")?;
        }
        self.newline(writer)
    }

    fn begin_object_value<W: ?Sized + std::io::Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(if self.pretty { b": " } else { b":" })
    }

    fn end_object_value<W: ?Sized + std::io::Write>(&mut self, _writer: &mut W) -> std::io::Result<()> {
        self.has_value = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn floats_print_in_shortest_form() {
        assert_eq!(float_text(0.0), "0.0");
        assert_eq!(float_text(45.0), "45.0");
        assert_eq!(float_text(1.5), "1.5");
        assert_eq!(float_text(0.0001), "0.0001");
        assert_eq!(float_text(0.00001), "1e-05");
        assert_eq!(float_text(1e15), "1000000000000000.0");
        assert_eq!(float_text(1e16), "1e+16");
        assert_eq!(float_text(-2.5e-7), "-2.5e-07");
        assert_eq!(float_text(123.456), "123.456");
    }

    #[test]
    fn literals_are_quoted_consistently() {
        assert_eq!(quote_literal("abc"), "'abc'");
        assert_eq!(quote_literal("it's"), "\"it's\"");
        assert_eq!(quote_literal("a\\b\n"), "'a\\\\b\\n'");
        assert_eq!(
            literal_of(&json!({"a": [1, true, null], "b": "x"})),
            "{'a': [1, True, None], 'b': 'x'}"
        );
        assert_eq!(bytes_literal(&[2, 0, b'a']), "b'\\x02\\x00a'");
    }

    #[test]
    fn dumps_matches_the_report_layout() {
        let value = json!({"a": [], "b": {}, "c": [1, {"d": 2.0}]});
        assert_eq!(
            dumps_pretty(&value),
            "{\n \"a\": [],\n \"b\": {},\n \"c\": [\n  1,\n  {\n   \"d\": 2.0\n  }\n ]\n}"
        );
        assert_eq!(dumps_compact(&value), "{\"a\":[],\"b\":{},\"c\":[1,{\"d\":2.0}]}");
    }

    #[test]
    fn numbers_and_strings() {
        assert_eq!(group_thousands(1234567), "1,234,567");
        assert_eq!(group_thousands(-1000), "-1,000");
        assert_eq!(format_grouped_rounded(2048.0 / 1024.0), "2");
        assert_eq!(format_grouped_rounded(12_345_678.0 / 1024.0), "12,056");
        assert_eq!(parse_int(" 12 "), Some(12));
        assert_eq!(parse_int("1_000"), Some(1000));
        assert_eq!(parse_int("1.5"), None);
        assert_eq!(take("héllo", 2), "hé");
        assert_eq!(skip("héllo", 2), "llo");
        assert_eq!(last("héllo", 3), "llo");
        assert_eq!(split_ws_once("  a  b c "), ("a", Some("b c ")));
        assert_eq!(split_ws_once("a   "), ("a", None));
        assert_eq!(
            html_escape("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#x27;&amp;&#x27;&lt;/a&gt;"
        );
        assert_eq!(round_to(0.123456, 4), 0.1235);
    }
}
