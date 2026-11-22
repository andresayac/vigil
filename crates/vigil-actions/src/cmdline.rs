//! Windows path and command-line helpers (the parts the actions need).

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::runner::{system32, windir};

static FIRST_EXT_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)^(.+?\.(?:exe|com|scr|bat|cmd|pif|msi|dll|sys|cpl|ocx|vbs|vbe|js|jse|wsf|ps1|hta|jar))(?:[\s,]|$)")
        .ok()
});

/// `%NAME%` replaced by the folder Windows reports for it (`vigil_sys::paths::known_variables`),
/// never by the process environment, which the user's own environment (HKCU\Environment) changes
/// even for an elevated Vigil. An unknown name is left as it is: see [`unknown_variables`].
pub fn expand_env(text: &str) -> String {
    vigil_sys::paths::expand_known(text).0
}

/// The `%NAME%` variables of `text` that [`expand_env`] does not know. Something about to start
/// with administrator rights is refused when there is one: its value would come from the user.
pub fn unknown_variables(text: &str) -> Vec<String> {
    vigil_sys::paths::expand_known(text).1
}

/// Drive letter plus root (`C:\`) or a UNC path: what Windows treats as a full path.
pub fn is_abs(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && is_sep(bytes[0]) && is_sep(bytes[1]) {
        return true;
    }
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && is_sep(bytes[2])
}

fn is_sep(byte: u8) -> bool {
    byte == b'\\' || byte == b'/'
}

/// Splits `C:` or `\\server\share` from the rest of the path.
fn split_drive(path: &str) -> (&str, &str) {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && is_sep(bytes[0]) && is_sep(bytes[1]) && !(bytes.len() > 2 && is_sep(bytes[2])) {
        // \\server\share
        let rest = &path[2..];
        if let Some(server_end) = rest.find(['\\', '/']) {
            let after = &rest[server_end + 1..];
            let share_end = after
                .find(['\\', '/'])
                .map(|i| i + server_end + 1 + 2)
                .unwrap_or(path.len());
            return (&path[..share_end], &path[share_end..]);
        }
        return (path, "");
    }
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return (&path[..2], &path[2..]);
    }
    ("", path)
}

/// `ntpath.normpath`: one kind of separator, no `.` or `..` components, no doubled separators.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let path = path.replace('/', "\\");
    let (drive, rest) = split_drive(&path);
    let rooted = rest.starts_with('\\');
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let mut out = String::from(drive);
    if rooted {
        out.push('\\');
    }
    out.push_str(&parts.join("\\"));
    if out.is_empty() { ".".to_string() } else { out }
}

/// `os.path.abspath`: relative paths are taken from the current folder.
pub fn abspath(path: &str) -> String {
    if is_abs(path) {
        return normpath(path);
    }
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    if path.starts_with(['\\', '/']) {
        let (drive, _) = split_drive(&cwd);
        return normpath(&format!("{drive}{path}"));
    }
    normpath(&format!("{cwd}\\{path}"))
}

/// `os.path.normcase` on Windows.
pub fn normcase(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

/// True when `path` is `folder` or inside it (paths compared like Windows does: case-insensitively).
pub fn in_dir(path: &str, folder: &str) -> bool {
    let path = normcase(&abspath(path));
    let folder = normcase(&abspath(folder));
    path == folder || path.starts_with(&format!("{}\\", folder.trim_end_matches('\\')))
}

/// The last component of a Windows path.
pub fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// The folder part of a Windows path (`ntpath.dirname`).
pub fn dirname(path: &str) -> String {
    let (drive, rest) = split_drive(path);
    let cut = rest.rfind(['\\', '/']).map(|i| i + 1).unwrap_or(0);
    let head = &rest[..cut];
    let trimmed = head.trim_end_matches(['\\', '/']);
    let head = if trimmed.is_empty() { head } else { trimmed };
    format!("{drive}{head}")
}

fn has_ext(path: &str) -> bool {
    basename(path).trim_start_matches('.').contains('.')
}

/// Paths as written in services, tasks and registry values: quotes, `%VARS%`, `\??\`, `\SystemRoot\`.
pub fn normalize_path(path: &str) -> String {
    let path = expand_env(path.trim().trim_matches('"').trim());
    if path.is_empty() {
        return path;
    }
    let mut path = path;
    let low = path.to_lowercase();
    if low.starts_with("\\??\\") || low.starts_with("\\\\?\\") {
        path = path[4..].to_string();
    }
    let low = path.to_lowercase();
    if low.starts_with("\\systemroot\\") {
        path = format!("{}\\{}", windir().to_string_lossy(), &path["\\systemroot\\".len()..]);
    } else if low.starts_with("system32\\") || low.starts_with("syswow64\\") {
        path = format!("{}\\{}", windir().to_string_lossy(), path);
    }
    let path = path.replace('/', "\\");
    if is_abs(&path) || path.starts_with("\\\\") {
        normpath(&path)
    } else {
        path
    }
}

fn is_file(path: &str) -> bool {
    !path.contains('\0') && !is_remote_path(path) && Path::new(path).is_file()
}

/// True for a path whose file lives on another computer or behind a device name: UNC
/// (`\\server\share\x`, `\\?\UNC\…`), the device namespace (`\\.\…`, `\\?\Volume{…}`), or a drive
/// letter mapped to a network share. Never probed: Windows would connect to that server (slowly,
/// and offering the user's credentials), and the path comes from a command line or a service
/// key. `\\?\C:\…` on a local drive is fine.
pub fn is_remote_path(path: &str) -> bool {
    let path = path.trim().trim_matches('"');
    let slashes = |c: char| c == '\\' || c == '/';
    let mut chars = path.chars();
    let (first, second) = (chars.next(), chars.next());
    if first.is_some_and(slashes) && second.is_some_and(slashes) {
        let rest: Vec<char> = path.chars().skip(4).take(2).collect();
        let long_drive = path.chars().nth(2).is_some_and(|c| c == '?' || c == '.')
            && path.chars().nth(3).is_some_and(slashes)
            && rest.len() == 2
            && rest[0].is_ascii_alphabetic()
            && rest[1] == ':';
        return !long_drive || drive_is_remote(rest[0]);
    }
    match (first, second) {
        (Some(letter), Some(':')) if letter.is_ascii_alphabetic() => drive_is_remote(letter),
        _ => false,
    }
}

/// True when the drive letter is mapped to a network share (Windows answers from its own table).
fn drive_is_remote(letter: char) -> bool {
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;
    let root: Vec<u16> = format!("{letter}:\\")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // DRIVE_REMOTE
    const REMOTE: u32 = 4;
    // SAFETY: `root` is a NUL-terminated wide string that lives for the call.
    unsafe { GetDriveTypeW(windows::core::PCWSTR(root.as_ptr())) == REMOTE }
}

fn search_dirs() -> Vec<String> {
    let system32 = system32().to_string_lossy().into_owned();
    let windir = windir().to_string_lossy().into_owned();
    let mut dirs = vec![
        system32.clone(),
        windir.clone(),
        format!("{system32}\\wbem"),
        format!("{system32}\\WindowsPowerShell\\v1.0"),
        format!("{windir}\\SysWOW64"),
    ];
    // PATH is the user's to change: an elevated Vigil looks only in the Windows folders.
    if crate::is_admin() {
        return dirs;
    }
    for entry in std::env::var("PATH").unwrap_or_default().split(';') {
        let entry = expand_env(entry.trim().trim_matches('"'));
        if !entry.is_empty() && is_abs(&entry) && !dirs.contains(&entry) {
            dirs.push(entry);
        }
    }
    dirs
}

/// (path, resolved). Bare names are searched in the system folders, and in `PATH` unless Vigil
/// runs as administrator.
pub fn resolve_program(token: &str) -> (String, bool) {
    let token = normalize_path(token);
    if token.is_empty() {
        return (token, false);
    }
    if is_abs(&token) || token.starts_with("\\\\") {
        if !has_ext(&token) && !is_file(&token) && is_file(&format!("{token}.exe")) {
            return (format!("{token}.exe"), true);
        }
        return (token, true);
    }
    let names: Vec<String> = if has_ext(&token) {
        vec![token.clone()]
    } else {
        [".exe", ".com", ".bat", ".cmd"]
            .iter()
            .map(|ext| format!("{token}{ext}"))
            .collect()
    };
    for directory in search_dirs() {
        for name in &names {
            let candidate = format!("{}\\{}", directory.trim_end_matches('\\'), name);
            if is_file(&candidate) {
                return (normpath(&candidate), true);
            }
        }
    }
    (token, false)
}

/// Splits a command line into (program, arguments, certain), the way `CreateProcess` reads it.
pub fn split_command(command: &str) -> (Option<String>, String, bool) {
    let text = expand_env(command.trim());
    if text.is_empty() {
        return (None, String::new(), false);
    }
    if let Some(inner) = text.strip_prefix('"') {
        return match inner.find('"') {
            None => {
                let (program, found) = resolve_program(inner);
                (Some(program), String::new(), found)
            }
            Some(end) => {
                let (program, found) = resolve_program(&inner[..end]);
                let certain = if is_abs(&program) { true } else { found };
                (Some(program), inner[end + 1..].trim().to_string(), certain)
            }
        };
    }
    // Unquoted: CreateProcess tries longer and longer space-separated prefixes.
    let parts: Vec<&str> = text.split(' ').collect();
    for i in 1..=parts.len() {
        let candidate = parts[..i].join(" ");
        let candidate = candidate.trim();
        if candidate.is_empty() {
            continue;
        }
        let rest = parts[i..].join(" ").trim().to_string();
        let norm = normalize_path(candidate);
        if is_abs(&norm) || norm.starts_with("\\\\") {
            if is_file(&norm) {
                return (Some(norm), rest, true);
            }
            if !has_ext(&norm) && is_file(&format!("{norm}.exe")) {
                return (Some(format!("{norm}.exe")), rest, true);
            }
        } else if i == 1 {
            let (program, found) = resolve_program(candidate);
            if found {
                return (Some(program), rest, true);
            }
            if !candidate.contains(['\\', '/', ':']) {
                return (Some(candidate.to_string()), rest, false);
            }
        }
    }
    // Nothing exists on disk: cut at the first executable extension.
    if let Some(caps) = FIRST_EXT_RE.as_ref().and_then(|re| re.captures(&text))
        && let Some(program) = caps.get(1)
    {
        return (
            Some(normalize_path(program.as_str())),
            text[program.end()..].trim().to_string(),
            !program.as_str().contains(' '),
        );
    }
    (
        Some(normalize_path(parts[0])),
        parts[1..].join(" ").trim().to_string(),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(normpath(r"C:\a\.\b\..\c\\d"), r"C:\a\c\d");
        assert_eq!(normpath("C:/x/../.."), r"C:\");
        assert_eq!(dirname(r"C:\a\b.exe"), r"C:\a");
        assert_eq!(dirname(r"C:\b.exe"), r"C:\");
        assert!(in_dir(r"C:\Windows\System32\x.dll", r"c:\windows"));
        assert!(!in_dir(r"C:\WindowsApps\x.dll", r"C:\Windows"));
        assert!(is_abs(r"C:\x") && is_abs(r"\\server\share\x") && !is_abs(r"\x") && !is_abs("x.exe"));
        assert_eq!(normalize_path(r#""\??\C:\Vendor\a.sys""#), r"C:\Vendor\a.sys");
    }

    #[test]
    fn commands_without_files_cut_at_the_extension() {
        let (program, args, certain) = split_command(r"C:\Nowhere\App Dir\tool.exe --run, now");
        assert_eq!(program.as_deref(), Some(r"C:\Nowhere\App Dir\tool.exe"));
        assert_eq!(args, "--run, now");
        assert!(!certain);
        let (program, args, _) = split_command(r#""C:\Nowhere\x.exe" /S"#);
        assert_eq!((program.as_deref(), args.as_str()), (Some(r"C:\Nowhere\x.exe"), "/S"));
    }
}
