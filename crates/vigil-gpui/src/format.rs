//! Numbers, sizes and times in the active language, as the web UI writes them with `Intl`
//! (grouping and decimal separators, the space before "%", unit names from the catalogs).

use crate::i18n::{language, t, tf};

/// (grouping separator, decimal separator, minimum digits before grouping applies).
fn separators(code: &str) -> (&'static str, &'static str, usize) {
    match code {
        // es-ES groups only from five digits on ("1234", "12.345").
        "es" => (".", ",", 5),
        "pt" => (".", ",", 4),
        "fr" => ("\u{202f}", ",", 4),
        _ => (",", ".", 4),
    }
}

/// A number with the language's separators and `digits` decimals.
pub fn num(value: f64, digits: usize) -> String {
    let value = if value.is_finite() { value } else { 0.0 };
    let (group, decimal, min_digits) = separators(language());
    let text = format!("{:.*}", digits, value.abs());
    let (whole, fraction) = text.split_once('.').unwrap_or((text.as_str(), ""));
    let mut out = String::new();
    if value < 0.0 && text.chars().any(|c| c.is_ascii_digit() && c != '0') {
        out.push('-');
    }
    if whole.len() >= min_digits {
        for (i, c) in whole.chars().enumerate() {
            if i > 0 && (whole.len() - i).is_multiple_of(3) {
                out.push_str(group);
            }
            out.push(c);
        }
    } else {
        out.push_str(whole);
    }
    if !fraction.is_empty() {
        out.push_str(decimal);
        out.push_str(fraction);
    }
    out
}

/// A percentage (`value` is 0-100): "12%", "12 %" (Spanish), "12 %" (French).
pub fn pct(value: f64, digits: usize) -> String {
    let n = num(value, digits);
    match language() {
        "es" => format!("{n}\u{a0}%"),
        "fr" => format!("{n}\u{202f}%"),
        _ => format!("{n}%"),
    }
}

/// Bytes in KB, MB, GB or TB (binary multiples, as Windows shows them).
pub fn size(bytes: f64, digits: usize) -> String {
    let mut value = bytes;
    if value.abs() < 1024.0 {
        return tf("unit.bytes", &[("n", &num(value.round(), 0))]);
    }
    let units = ["unit.KB", "unit.MB", "unit.GB", "unit.TB"];
    for (i, unit) in units.iter().enumerate() {
        value /= 1024.0;
        if value.abs() < 1024.0 || i == units.len() - 1 {
            return format!("{} {}", num(value, digits), t(unit));
        }
    }
    String::new()
}

/// How long ago a process started: "12 min", "3.5 h", "2.1 d".
pub fn age(created_ms: i64, now_ms: i64) -> String {
    if created_ms <= 0 {
        return String::new();
    }
    let seconds = ((now_ms - created_ms) as f64 / 1000.0).max(0.0);
    if seconds < 3600.0 {
        tf("time.minutesShort", &[("n", &num((seconds / 60.0).floor(), 0))])
    } else if seconds < 86400.0 {
        tf("time.hoursShort", &[("n", &num(seconds / 3600.0, 1))])
    } else {
        tf("time.daysShort", &[("n", &num(seconds / 86400.0, 1))])
    }
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// The bytes of a base64 `data:` URL (the program icons `vigil-sys` reads as PNG data URLs).
pub fn data_url_bytes(url: &str) -> Option<Vec<u8>> {
    let (_, encoded) = url.split_once(";base64,")?;
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let clean: Vec<u8> = encoded.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * i);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..chunk.len().saturating_sub(1)]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn data_urls_decode() {
        assert_eq!(
            super::data_url_bytes("data:image/png;base64,TWFu").as_deref(),
            Some(&b"Man"[..])
        );
        assert_eq!(
            super::data_url_bytes("data:image/png;base64,TWE=").as_deref(),
            Some(&b"Ma"[..])
        );
        assert_eq!(
            super::data_url_bytes("data:image/png;base64,TQ==").as_deref(),
            Some(&b"M"[..])
        );
        assert_eq!(super::data_url_bytes("data:image/png;base64,T!=="), None);
    }

    use super::*;

    #[test]
    fn numbers_follow_the_language() {
        assert_eq!(vigil_i18n::with_language("en", || num(1234.5, 1)), "1,234.5");
        assert_eq!(vigil_i18n::with_language("es", || num(1234.0, 0)), "1234");
        assert_eq!(vigil_i18n::with_language("es", || num(12345.0, 0)), "12.345");
        assert_eq!(vigil_i18n::with_language("fr", || num(1234.5, 1)), "1\u{202f}234,5");
        assert_eq!(vigil_i18n::with_language("pt", || pct(12.0, 0)), "12%");
        assert_eq!(vigil_i18n::with_language("es", || pct(12.0, 0)), "12\u{a0}%");
        assert_eq!(vigil_i18n::with_language("en", || num(-0.04, 1)), "0.0");
    }

    #[test]
    fn sizes_use_binary_units() {
        assert_eq!(vigil_i18n::with_language("en", || size(1536.0 * 1024.0, 1)), "1.5 MB");
        assert_eq!(vigil_i18n::with_language("en", || size(512.0, 1)), "512 bytes");
    }
}
