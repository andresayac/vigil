//! Text from the computer (file, process, service, task and extension names, paths, registry
//! values) shown to the user, made safe to read.
//!
//! Malware names files with invisible characters that change how text is drawn: a right-to-left
//! override (U+202E) makes `invoice\u{202E}fdp.exe` read as "invoiceexe.pdf", and control
//! characters can hide or break a line. Before such text reaches a confirmation dialog or a label,
//! every such character is replaced by a visible marker (`⟨U+202E⟩`), so what the user reads is what
//! the file is called.

/// Characters that change how surrounding text is drawn, or that cannot be seen.
fn hidden(c: char) -> bool {
    matches!(
        c,
        // Bidirectional embeddings, overrides and isolates; the directional and Arabic marks.
        '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}'
            // C1 controls.
            | '\u{0080}'..='\u{009F}'
            // Zero-width space, word joiner and invisible operators, line and paragraph separators,
            // the byte order mark and interlinear annotation marks.
            | '\u{200B}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
    ) || (c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
}

fn marker(c: char, out: &mut String) {
    out.push_str(&format!("⟨U+{:04X}⟩", u32::from(c)));
}

/// Whether `text` has nothing to mark, line breaks and tabs aside (then it is shown as it is,
/// without a copy).
pub fn is_plain(text: &str) -> bool {
    !text.chars().any(hidden)
}

/// `text` with every hidden or direction-changing character shown as a marker. Line breaks and
/// tabs stay (dialog bodies have several lines).
pub fn shown(text: &str) -> String {
    if !text.chars().any(hidden) {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        if hidden(c) {
            marker(c, &mut out);
        } else {
            out.push(c);
        }
    }
    out
}

/// One line of `text` for a label: like [`shown`], and line breaks and tabs become markers too
/// (a name never has them; a line break could push the rest out of sight).
pub fn shown_line(text: &str) -> String {
    if !text.chars().any(|c| hidden(c) || matches!(c, '\t' | '\n' | '\r')) {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        if hidden(c) || matches!(c, '\t' | '\n' | '\r') {
            marker(c, &mut out);
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_right_to_left_override_is_shown() {
        let name = "C:\\Users\\jdoe\\Downloads\\invoice\u{202E}fdp.exe";
        let shown = shown(name);
        assert_eq!(shown, "C:\\Users\\jdoe\\Downloads\\invoice⟨U+202E⟩fdp.exe");
        assert!(!shown.contains('\u{202E}'));
    }

    #[test]
    fn every_direction_mark_and_control_is_shown() {
        for c in [
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
            '\u{200E}', '\u{200F}', '\u{061C}', '\u{0000}', '\u{0007}', '\u{001B}', '\u{007F}', '\u{0085}', '\u{009B}',
            '\u{200B}', '\u{2028}', '\u{FEFF}',
        ] {
            let text = format!("a{c}b");
            let out = shown(&text);
            assert!(!out.contains(c), "{c:?} survived in {out:?}");
            assert!(out.contains("⟨U+"), "{c:?}: {out:?}");
        }
    }

    #[test]
    fn ordinary_text_is_untouched() {
        for text in [
            "notepad.exe",
            "C:\\Program Files\\Contoso\\app.exe",
            "Привет мир",
            "مرحبا بالعالم",
            "שלום",
            "家庭",
            "👩‍💻 Dev",
            "ZWNJ: می\u{200C}خواهم",
        ] {
            assert_eq!(shown(text), text);
            assert_eq!(shown_line(text), text);
        }
    }

    #[test]
    fn line_breaks_stay_in_bodies_but_not_in_labels() {
        assert_eq!(shown("one\ntwo\tthree"), "one\ntwo\tthree");
        assert_eq!(shown_line("one\ntwo"), "one⟨U+000A⟩two");
    }
}
