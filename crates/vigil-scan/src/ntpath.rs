//! Windows path handling: normalizing, joining, splitting and case folding
//! (`isabs`, `splitroot`, `join`, `normpath`, `split`, `basename`, `splitext`).
//!
//! The rules compare paths as text, so the same input must always give the same string.

use std::sync::LazyLock;

/// `%SystemRoot%` (`C:\Windows` when it is not set).
pub(crate) static WINDIR: LazyLock<String> = LazyLock::new(|| {
    // From Windows itself on Windows: a user's environment can override `%SystemRoot%`.
    #[cfg(windows)]
    {
        vigil_sys::paths::windows_dir().display().to_string()
    }
    #[cfg(not(windows))]
    {
        std::env::var("SystemRoot")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| r"C:\Windows".to_string())
    }
});
pub(crate) static SYSTEM32: LazyLock<String> = LazyLock::new(|| join(&WINDIR, &["System32"]));
pub(crate) static SYSWOW64: LazyLock<String> = LazyLock::new(|| join(&WINDIR, &["SysWOW64"]));

fn is_sep(c: char) -> bool {
    c == '\\' || c == '/'
}

/// Byte offset of the second character, if any.
fn second_char(p: &str) -> Option<usize> {
    p.chars().next().map(char::len_utf8).filter(|&i| i < p.len())
}

/// `(drive, root, tail)`.
pub(crate) fn splitroot(p: &str) -> (&str, &str, &str) {
    let normp: Vec<u8> = p.bytes().map(|b| if b == b'/' { b'\\' } else { b }).collect();
    if normp.first() == Some(&b'\\') {
        if normp.get(1) == Some(&b'\\') {
            let start = if normp.len() >= 8 && normp[..8].eq_ignore_ascii_case(b"\\\\?\\UNC\\") {
                8
            } else {
                2
            };
            let find = |from: usize| normp.iter().skip(from).position(|&b| b == b'\\').map(|i| i + from);
            let Some(index) = find(start) else { return (p, "", "") };
            let Some(index2) = find(index + 1) else {
                return (p, "", "");
            };
            return (&p[..index2], &p[index2..index2 + 1], &p[index2 + 1..]);
        }
        return ("", &p[..1], &p[1..]);
    }
    if let Some(second) = second_char(p)
        && p[second..].starts_with(':')
    {
        let after = second + 1;
        if p[after..].starts_with(is_sep) {
            return (&p[..after], &p[after..after + 1], &p[after + 1..]);
        }
        return (&p[..after], "", &p[after..]);
    }
    ("", "", p)
}

/// Absolute: a drive with a root (`C:\x`), or a UNC/device path (`\\server\share`).
pub(crate) fn isabs(s: &str) -> bool {
    let head: Vec<char> = s.chars().take(3).map(|c| if c == '/' { '\\' } else { c }).collect();
    (head.len() >= 3 && head[1] == ':' && head[2] == '\\') || (head.len() >= 2 && head[0] == '\\' && head[1] == '\\')
}

/// `ntpath.join(path, *paths)`.
pub(crate) fn join(path: &str, paths: &[&str]) -> String {
    let (d, r, t) = splitroot(path);
    let (mut drive, mut root, mut tail) = (d.to_string(), r.to_string(), t.to_string());
    for p in paths {
        let (p_drive, p_root, p_path) = splitroot(p);
        if !p_root.is_empty() {
            if !p_drive.is_empty() || drive.is_empty() {
                drive = p_drive.to_string();
            }
            root = p_root.to_string();
            tail = p_path.to_string();
            continue;
        } else if !p_drive.is_empty() && p_drive != drive {
            if p_drive.to_lowercase() != drive.to_lowercase() {
                drive = p_drive.to_string();
                root = p_root.to_string();
                tail = p_path.to_string();
                continue;
            }
            drive = p_drive.to_string();
        }
        if !tail.is_empty() && !tail.ends_with(is_sep) {
            tail.push('\\');
        }
        tail.push_str(p_path);
    }
    if !tail.is_empty() && root.is_empty() && !drive.is_empty() && !drive.ends_with([':', '\\', '/']) {
        return format!("{drive}\\{tail}");
    }
    format!("{drive}{root}{tail}")
}

/// `ntpath.normpath(path)`.
pub(crate) fn normpath(path: &str) -> String {
    let replaced = path.replace('/', "\\");
    let (drive, root, rest) = splitroot(&replaced);
    let prefix = format!("{drive}{root}");
    let mut comps: Vec<&str> = rest.split('\\').collect();
    let mut i = 0;
    while i < comps.len() {
        if comps[i].is_empty() || comps[i] == "." {
            comps.remove(i);
        } else if comps[i] == ".." {
            if i > 0 && comps[i - 1] != ".." {
                comps.drain(i - 1..=i);
                i -= 1;
            } else if i == 0 && !root.is_empty() {
                comps.remove(i);
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    if prefix.is_empty() && comps.is_empty() {
        comps.push(".");
    }
    format!("{prefix}{}", comps.join("\\"))
}

/// `ntpath.split(path)`.
pub(crate) fn split(p: &str) -> (String, &str) {
    let (d, r, rest) = splitroot(p);
    let i = rest.rfind(is_sep).map_or(0, |i| i + 1);
    let (head, tail) = rest.split_at(i);
    (format!("{d}{r}{}", head.trim_end_matches(is_sep)), tail)
}

/// `ntpath.basename(path)`.
pub(crate) fn basename(p: &str) -> &str {
    split(p).1
}

/// `ntpath.dirname(path)`.
pub(crate) fn dirname(p: &str) -> String {
    split(p).0
}

/// `ntpath.splitext(path)`: `(root, ext)`; a leading dot of the file name is not an extension.
pub(crate) fn splitext(p: &str) -> (&str, &str) {
    let sep_index = p.rfind(is_sep).map(|i| i as isize).unwrap_or(-1);
    if let Some(dot_index) = p.rfind('.')
        && dot_index as isize > sep_index
    {
        let name_start = (sep_index + 1) as usize;
        if p[name_start..dot_index].chars().any(|c| c != '.') {
            return (&p[..dot_index], &p[dot_index..]);
        }
    }
    (p, "")
}

/// The extension (`ntpath.splitext(p)[1]`).
pub(crate) fn ext(p: &str) -> &str {
    splitext(p).1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_examples() {
        assert!(isabs(r"C:\x"));
        assert!(isabs("C:/x"));
        assert!(!isabs(r"\x"));
        assert!(!isabs("C:x"));
        assert!(isabs(r"\\server\share"));
        assert_eq!(splitroot(r"C:\Windows\x"), ("C:", "\\", r"Windows\x"));
        assert_eq!(splitroot(r"\\server\share\dir"), (r"\\server\share", "\\", "dir"));
        assert_eq!(join(r"C:\Windows", &["System32"]), r"C:\Windows\System32");
        assert_eq!(join(r"C:\a", &[r"D:\b"]), r"D:\b");
        assert_eq!(join("C:", &["x"]), "C:x");
        assert_eq!(normpath(r"C:\a\.\b\..\c\\d\"), r"C:\a\c\d");
        assert_eq!(normpath(r"C:\..\x"), r"C:\x");
        assert_eq!(normpath(r"..\x"), r"..\x");
        assert_eq!(basename(r"C:\a\b.exe"), "b.exe");
        assert_eq!(basename(r"C:\a\"), "");
        assert_eq!(dirname(r"C:\a\b.exe"), r"C:\a");
        assert_eq!(splitext(r"C:\a\b.tar.gz"), (r"C:\a\b.tar", ".gz"));
        assert_eq!(splitext(r"C:\a\.hidden"), (r"C:\a\.hidden", ""));
        assert_eq!(splitext(r"C:\a.b\file"), (r"C:\a.b\file", ""));
        assert_eq!(splitext("x."), ("x", "."));
    }
}
