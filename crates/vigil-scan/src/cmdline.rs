//! Windows command-line parsing.
//!
//! Answers two questions about a command (from a process, service, task or startup entry):
//! which program it starts, and which file really decides what runs. For a
//! `rundll32 x.dll,Start` or a `wscript x.vbs` what matters is the DLL or the script,
//! not the Windows binary that hosts them.

use std::path::Path;

use crate::lenient::{char_len, is_printable, lower, lstrip, rx, skip, split_ws, split_ws_once, strip};
use crate::ntpath::{SYSTEM32, SYSWOW64, WINDIR, basename, ext, isabs, join, normpath};

const EXEC_EXT: &str = "exe|com|scr|bat|cmd|pif|msi|dll|sys|cpl|ocx|vbs|vbe|js|jse|wsf|ps1|hta|jar";

rx!(ENV_RE, r"%([A-Za-z0-9_(). -]+)%");
rx!(FIRST_EXT_RE, &format!(r"(?i)^(.+?\.(?:{EXEC_EXT}))(?:[\s,]|$)"));
rx!(URL_RE, r"(?i)^(https?|ftp)://");
rx!(START_RE, r"(?i)^start(?:\.exe)?\s+");
rx!(
    START_SWITCH_RE,
    r"(?i)^/(min|max|b|wait|low|normal|high|realtime|abovenormal|belownormal|separate|shared|i)\s+"
);
rx!(START_DIR_RE, r#"(?i)^/d\s+("[^"]*"|\S+)\s+"#);
rx!(START_TITLE_RE, r#"^"([^"]*)"(\s+)\S"#);
rx!(CMD_SWITCH_RE, r"(?is)(?:^|\s)/[ck]\s*(.*)$");
rx!(QUOTED_RE, r#""[^"]*""#);
rx!(CHAIN_RE, r"[&|]");
rx!(RUNDLL_SWITCH_RE, r"(?i)^[-/](sta|d|localserver)\b");
rx!(SCRIPT_URL_RE, r"(?i)^(javascript|vbscript):");
rx!(MSHTA_INLINE_RE, r"(?i)^(javascript|vbscript|about):");
rx!(HEADLESS_RE, r"(?is)--headless\s+(.*)$");

pub const SCRIPT_EXTS: &[&str] = &[
    ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".py", ".pyw", ".jar",
    ".ahk", ".au3", ".php", ".rb", ".pl", ".sh",
];

/// How the payload is extracted from the arguments of each host program.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HostKind {
    Rundll32,
    Regsvr32,
    Script,
    Mshta,
    PowerShell,
    Cmd,
    Conhost,
    Msiexec,
    Java,
    Interp,
    Explorer,
    /// It takes no payload file.
    None,
}

/// Programs whose binary says nothing about what runs: their arguments decide.
fn host_kind(name: &str) -> Option<HostKind> {
    use HostKind::*;
    Some(match name {
        "rundll32.exe" => Rundll32,
        "regsvr32.exe" => Regsvr32,
        "wscript.exe" | "cscript.exe" => Script,
        "mshta.exe" => Mshta,
        "powershell.exe" | "pwsh.exe" | "powershell_ise.exe" => PowerShell,
        "cmd.exe" => Cmd,
        "conhost.exe" => Conhost,
        "msiexec.exe" => Msiexec,
        "java.exe" | "javaw.exe" => Java,
        "python.exe" | "pythonw.exe" | "py.exe" | "pyw.exe" | "node.exe" | "php.exe" | "ruby.exe" | "perl.exe"
        | "autohotkey.exe" | "autohotkey64.exe" | "autohotkey32.exe" | "autohotkeyu64.exe" | "autoit3.exe"
        | "autoit3_x64.exe" | "bun.exe" | "deno.exe" => Interp,
        "explorer.exe" => Explorer,
        "svchost.exe" | "dllhost.exe" | "schtasks.exe" | "sc.exe" | "net.exe" | "net1.exe" | "reg.exe"
        | "netsh.exe" | "bitsadmin.exe" | "certutil.exe" | "wmic.exe" | "forfiles.exe" | "pcalua.exe"
        | "msbuild.exe" | "installutil.exe" | "regasm.exe" | "regsvcs.exe" | "cmstp.exe" | "odbcconf.exe"
        | "curl.exe" | "wsl.exe" | "bash.exe" | "ssh.exe" | "taskkill.exe" | "timeout.exe" | "attrib.exe"
        | "wevtutil.exe" | "vssadmin.exe" | "bcdedit.exe" | "control.exe" | "ie4uinit.exe" => None,
        _ => return Option::None,
    })
}

/// Host programs (rundll32.exe, cmd.exe...): their arguments decide what runs.
pub fn is_host(name: &str) -> bool {
    host_kind(name).is_some()
}

/// Programs that only exist as part of Windows. Other host names (bash, ssh, curl, timeout...)
/// are also shipped by Git, MSYS2 and similar, so they are not required to be the Microsoft binary.
pub fn is_system_only_host(name: &str) -> bool {
    matches!(
        name,
        "rundll32.exe"
            | "regsvr32.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "powershell.exe"
            | "cmd.exe"
            | "conhost.exe"
            | "msiexec.exe"
            | "explorer.exe"
            | "svchost.exe"
            | "dllhost.exe"
            | "schtasks.exe"
            | "sc.exe"
            | "net.exe"
            | "net1.exe"
            | "reg.exe"
            | "netsh.exe"
            | "bitsadmin.exe"
            | "certutil.exe"
            | "wmic.exe"
            | "forfiles.exe"
            | "pcalua.exe"
            | "cmstp.exe"
            | "odbcconf.exe"
            | "wevtutil.exe"
            | "vssadmin.exe"
            | "bcdedit.exe"
    )
}

/// A parsed command line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedCommand {
    pub raw: String,
    /// Executable that starts (resolved path when possible).
    pub program: Option<String>,
    pub args: String,
    /// Name of the host program (rundll32.exe, cmd.exe...).
    pub host: Option<String>,
    /// File the host runs.
    pub payload: Option<String>,
    /// The payload is remote (URL).
    pub payload_url: Option<String>,
    /// Code passed inline (-Command, /c ...).
    pub inline: Option<String>,
    /// Content of a PowerShell -EncodedCommand.
    pub decoded: Option<String>,
    /// Asks for a hidden window.
    pub hidden: bool,
    /// Several commands chained with & or |.
    pub compound: bool,
    /// The program was identified unambiguously.
    pub certain: bool,
    /// Chained hosts (cmd -> powershell...).
    pub chain: Vec<String>,
}

impl ParsedCommand {
    pub fn new(raw: &str) -> Self {
        Self {
            raw: raw.to_string(),
            ..Self::default()
        }
    }

    /// File that really determines what runs.
    pub fn target(&self) -> Option<&str> {
        if self.host.is_none() {
            self.program.as_deref()
        } else {
            self.payload.as_deref()
        }
    }
}

/// `value or other` for optional strings (an empty string is falsy).
fn or_opt(value: Option<String>, other: Option<String>) -> Option<String> {
    match value {
        Some(v) if !v.is_empty() => Some(v),
        _ => other,
    }
}

fn nonempty(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|v| !v.is_empty())
}

/// Expands `%VARIABLE%` references (unknown variables stay as they are).
pub fn expand_env(text: &str) -> String {
    ENV_RE
        .replace_all(text, |caps: &regex::Captures| {
            std::env::var(&caps[1]).unwrap_or_else(|_| caps[0].to_string())
        })
        .into_owned()
}

/// Normalizes a path from the system: quotes, variables, `\??\`, `\SystemRoot\`, separators.
pub fn normalize_path(path: &str) -> String {
    let mut path = expand_env(strip(strip(path).trim_matches('"')));
    if path.is_empty() {
        return path;
    }
    let mut low = lower(&path);
    if low.starts_with("\\??\\") || low.starts_with("\\\\?\\") {
        path = skip(&path, 4).to_string();
        low = lower(&path);
    }
    if low.starts_with("\\systemroot\\") {
        path = join(&WINDIR, &[skip(&path, "\\systemroot\\".len())]);
    } else if low.starts_with("system32\\") || low.starts_with("syswow64\\") {
        path = join(&WINDIR, &[&path]);
    }
    path = path.replace('/', "\\");
    if isabs(&path) || path.starts_with("\\\\") {
        path = normpath(&path);
    }
    path
}

pub(crate) fn is_file(path: &str) -> bool {
    !path.is_empty() && !path.contains('\0') && Path::new(path).is_file()
}

fn search_dirs() -> Vec<String> {
    let mut dirs = vec![
        SYSTEM32.clone(),
        WINDIR.clone(),
        join(&SYSTEM32, &["wbem"]),
        join(&SYSTEM32, &["WindowsPowerShell", "v1.0"]),
        SYSWOW64.clone(),
    ];
    for entry in std::env::var("PATH").unwrap_or_default().split(';') {
        let entry = expand_env(strip(entry).trim_matches('"'));
        if !entry.is_empty() && isabs(&entry) && !dirs.contains(&entry) {
            dirs.push(entry);
        }
    }
    dirs
}

/// Returns (path, resolved). Bare names are searched in the system folders and PATH.
pub fn resolve_program(token: &str, cwd: Option<&str>) -> (String, bool) {
    let token = normalize_path(token);
    if token.is_empty() {
        return (token, false);
    }
    if isabs(&token) || token.starts_with("\\\\") {
        if ext(&token).is_empty() && !is_file(&token) && is_file(&format!("{token}.exe")) {
            return (format!("{token}.exe"), true);
        }
        return (token, true);
    }
    let names: Vec<String> = if ext(&token).is_empty() {
        [".exe", ".com", ".bat", ".cmd"]
            .iter()
            .map(|e| format!("{token}{e}"))
            .collect()
    } else {
        vec![token.clone()]
    };
    let mut dirs: Vec<String> = cwd
        .filter(|c| isabs(c))
        .map(|c| vec![c.to_string()])
        .unwrap_or_default();
    dirs.extend(search_dirs());
    for directory in &dirs {
        for name in &names {
            let candidate = join(directory, &[name]);
            if is_file(&candidate) {
                return (normpath(&candidate), true);
            }
        }
    }
    (token, false)
}

/// Splits into (program, arguments, certain), mimicking how CreateProcess parses the line.
pub fn split_command(command: &str, cwd: Option<&str>) -> (Option<String>, String, bool) {
    let text = expand_env(strip(command));
    if text.is_empty() {
        return (None, String::new(), false);
    }
    if let Some(quoted) = text.strip_prefix('"') {
        let Some(end) = quoted.find('"') else {
            let (program, found) = resolve_program(quoted, cwd);
            return (Some(program), String::new(), found);
        };
        let (program, found) = resolve_program(&quoted[..end], cwd);
        let certain = isabs(&program) || found;
        return (Some(program), strip(&quoted[end + 1..]).to_string(), certain);
    }

    // Unquoted: CreateProcess tries increasingly longer space-separated prefixes.
    let parts: Vec<&str> = text.split(' ').collect();
    for i in 1..=parts.len() {
        let candidate = strip(&parts[..i].join(" ")).to_string();
        if candidate.is_empty() {
            continue;
        }
        let rest = strip(&parts[i..].join(" ")).to_string();
        let norm = normalize_path(&candidate);
        if isabs(&norm) || norm.starts_with("\\\\") {
            if is_file(&norm) {
                return (Some(norm), rest, true);
            }
            if ext(&norm).is_empty() && is_file(&format!("{norm}.exe")) {
                return (Some(format!("{norm}.exe")), rest, true);
            }
        } else if i == 1 {
            let (program, found) = resolve_program(&candidate, cwd);
            if found {
                return (Some(program), rest, true);
            }
            if !candidate.contains(['\\', '/', ':']) {
                return (Some(candidate), rest, false);
            }
        }
    }

    // Nothing exists on disk: cut at the first executable extension.
    if let Some(caps) = FIRST_EXT_RE.captures(&text)
        && let Some(program) = caps.get(1)
    {
        let rest = strip(&text[program.end()..]).to_string();
        return (
            Some(normalize_path(program.as_str())),
            rest,
            !program.as_str().contains(' '),
        );
    }
    (
        Some(normalize_path(parts[0])),
        strip(&parts[1..].join(" ")).to_string(),
        false,
    )
}

/// Splits arguments the way the Microsoft C runtime does (quotes group, no escapes).
pub fn split_args(args: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut had_quote = false;
    for ch in args.chars() {
        if ch == '"' {
            quoted = !quoted;
            had_quote = true;
            continue;
        }
        if (ch == ' ' || ch == '\t') && !quoted {
            if !current.is_empty() || had_quote {
                tokens.push(std::mem::take(&mut current));
            }
            had_quote = false;
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() || had_quote {
        tokens.push(current);
    }
    tokens
}

/// (path, url) of a payload. DLLs or scripts without a path are searched on the system.
fn resolve_payload(token: &str, cwd: Option<&str>) -> (Option<String>, Option<String>) {
    let token = strip(token).trim_matches('"').trim_matches('\'');
    if token.is_empty() {
        return (None, None);
    }
    if URL_RE.is_match(token) {
        return (None, Some(token.to_string()));
    }
    (Some(resolve_program(token, cwd).0), None)
}

fn set_payload(parsed: &mut ParsedCommand, token: &str, cwd: Option<&str>) {
    let (payload, url) = resolve_payload(token, cwd);
    parsed.payload = payload;
    parsed.payload_url = url;
}

/// Lenient base64 decoding: characters outside the alphabet are
/// skipped and decoding stops at a complete padding sequence.
fn b64decode_lenient(text: &str) -> Option<Vec<u8>> {
    if !text.is_ascii() {
        return None;
    }
    let value = |b: u8| -> Option<u32> {
        Some(u32::from(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut quad_pos, mut left, mut pads) = (0u32, 0u32, 0u32);
    for b in text.bytes() {
        if b == b'=' {
            if quad_pos >= 2 {
                pads += 1;
                if quad_pos + pads >= 4 {
                    return Some(out);
                }
            }
            continue;
        }
        let Some(v) = value(b) else { continue };
        pads = 0;
        match quad_pos {
            0 => {
                quad_pos = 1;
                left = v;
            }
            1 => {
                quad_pos = 2;
                out.push(((left << 2) | (v >> 4)) as u8);
                left = v & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push(((left << 4) | (v >> 2)) as u8);
                left = v & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push(((left << 6) | v) as u8);
                left = 0;
            }
        }
    }
    if quad_pos != 0 { None } else { Some(out) }
}

/// Decodes an -EncodedCommand value (Base64 of UTF-16LE text); `None` when it is not readable text.
pub fn decode_encoded_command(token: &str) -> Option<String> {
    let token = strip(token).trim_matches('"').trim_matches('\'');
    let length = char_len(token);
    if length < 8 {
        return None;
    }
    let padded = format!("{token}{}", "=".repeat((4 - length % 4) % 4));
    let data = b64decode_lenient(&padded)?;
    if data.is_empty() {
        return None;
    }
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect();
    let mut text: String = char::decode_utf16(units).map(|r| r.unwrap_or('\u{fffd}')).collect();
    if data.len() % 2 == 1 {
        text.push('\u{fffd}');
    }
    let total = char_len(&text);
    let printable = text
        .chars()
        .filter(|&c| is_printable(c) || matches!(c, '\r' | '\n' | '\t'))
        .count();
    if (printable as f64) < total as f64 * 0.85 {
        return None;
    }
    Some(text)
}

fn is_prefix(name: &str, full: &str, minimum: usize) -> bool {
    char_len(name) >= minimum && full.starts_with(name)
}

fn parse_powershell(parsed: &mut ParsedCommand, cwd: Option<&str>) {
    let tokens = split_args(&parsed.args);
    let mut i = 0;
    while i < tokens.len() {
        let token = &tokens[i];
        if !(token.starts_with('-') || token.starts_with('/')) || char_len(token) < 2 {
            // First positional argument: a script, or inline code.
            let low = lower(token);
            if [".ps1", ".psm1", ".cmd", ".bat"].iter().any(|e| low.ends_with(e)) {
                set_payload(parsed, token, cwd);
            } else {
                parsed.inline = Some(tokens[i..].join(" "));
            }
            return;
        }
        let name = lower(skip(token, 1));
        let value = tokens.get(i + 1).map(String::as_str).unwrap_or("");
        if is_prefix(&name, "encodedcommand", 1) || name == "ec" {
            parsed.decoded = decode_encoded_command(value);
            parsed.inline = or_opt(parsed.decoded.clone(), parsed.inline.take());
            i += 2;
            continue;
        }
        if is_prefix(&name, "file", 1) {
            set_payload(parsed, value, cwd);
            return;
        }
        if is_prefix(&name, "command", 1) {
            parsed.inline = Some(tokens[(i + 1).min(tokens.len())..].join(" "));
            return;
        }
        if is_prefix(&name, "windowstyle", 1) {
            if ["hidden", "h", "hi", "hid", "hidd", "hidde", "1"].contains(&lower(value).as_str()) {
                parsed.hidden = true;
            }
            i += 2;
            continue;
        }
        if is_prefix(&name, "executionpolicy", 2)
            || name == "ep"
            || is_prefix(&name, "inputformat", 1)
            || is_prefix(&name, "outputformat", 1)
            || is_prefix(&name, "version", 1)
            || is_prefix(&name, "configurationname", 3)
            || is_prefix(&name, "workingdirectory", 2)
            || is_prefix(&name, "psconsolefile", 2)
            || is_prefix(&name, "settingsfile", 3)
            || is_prefix(&name, "custompipename", 3)
            || is_prefix(&name, "encodedarguments", 8)
        {
            i += 2;
            continue;
        }
        i += 1;
    }
}

/// Strips cmd's `start "title" /min ...` to reach the real program.
fn strip_start(inner: &str) -> String {
    let Some(found) = START_RE.find(inner) else {
        return inner.to_string();
    };
    let mut rest = lstrip(&inner[found.end()..]).to_string();
    let mut title_seen = false;
    loop {
        if let Some(switch) = START_SWITCH_RE.find(&rest) {
            rest = rest[switch.end()..].to_string();
            continue;
        }
        if let Some(directory) = START_DIR_RE.find(&rest) {
            rest = rest[directory.end()..].to_string();
            continue;
        }
        // The first quoted text is the window title (before or after the switches).
        if !title_seen
            && let Some(caps) = START_TITLE_RE.captures(&rest)
            && let (Some(title), Some(spaces)) = (caps.get(1), caps.get(2))
            && !is_file(&normalize_path(title.as_str()))
        {
            rest = rest[spaces.end()..].to_string();
            title_seen = true;
            continue;
        }
        return rest;
    }
}

fn parse_cmd(parsed: &mut ParsedCommand, cwd: Option<&str>, depth: usize) {
    let Some(caps) = CMD_SWITCH_RE.captures(&parsed.args) else {
        return;
    };
    let mut inner = strip(caps.get(1).map_or("", |m| m.as_str())).to_string();
    if char_len(&inner) >= 2 && inner.starts_with('"') && inner.ends_with('"') && inner.matches('"').count() == 2 {
        inner = strip(&inner[1..inner.len() - 1]).to_string();
    } else if inner.starts_with("\"\"") {
        inner = inner[1..].to_string();
    }
    parsed.inline = Some(inner.clone());
    // With & or | there is more than one command: looking at the first is not enough.
    if CHAIN_RE.is_match(&QUOTED_RE.replace_all(&inner, "\"\"")) {
        parsed.compound = true;
    }
    absorb(parsed, &strip_start(&inner), cwd, depth);
}

/// Parses a nested command and lifts its payload to the outer command.
fn absorb(parsed: &mut ParsedCommand, inner: &str, cwd: Option<&str>, depth: usize) {
    if inner.is_empty() || depth >= 4 {
        return;
    }
    let nested = parse(inner, cwd, depth + 1);
    let Some(program) = &nested.program else { return };
    parsed.chain.push(lower(basename(program)));
    parsed.chain.extend(nested.chain.iter().cloned());
    parsed.hidden = parsed.hidden || nested.hidden;
    parsed.compound = parsed.compound || nested.compound;
    parsed.decoded = or_opt(parsed.decoded.take(), nested.decoded.clone());
    if nested.host.is_none() {
        // A cmd builtin (echo, set, if...) is not a file: it only counts when it was resolved.
        if nested.certain || isabs(program) {
            parsed.payload = Some(program.clone());
        }
    } else {
        parsed.payload = nested.payload.clone();
        parsed.payload_url = nested.payload_url.clone();
        if nonempty(&nested.inline) {
            parsed.inline = nested.inline.clone();
        }
    }
}

/// Parses a command line (resolving programs on this computer).
pub fn parse_command(command: &str, cwd: Option<&str>) -> ParsedCommand {
    parse(command, cwd, 0)
}

fn parse(command: &str, cwd: Option<&str>, depth: usize) -> ParsedCommand {
    let mut parsed = ParsedCommand::new(command);
    let (program, args, certain) = split_command(command, cwd);
    parsed.program = program.clone();
    parsed.args = args.clone();
    parsed.certain = certain;
    let Some(program) = program.filter(|p| !p.is_empty()) else {
        return parsed;
    };

    let mut base = lower(basename(&program));
    if ext(&base).is_empty() {
        base.push_str(".exe");
    }
    let Some(kind) = host_kind(&base) else { return parsed };
    parsed.host = Some(base);
    let tokens = split_args(&args);

    match kind {
        HostKind::Rundll32 => {
            let mut rest = strip(&args).to_string();
            while RUNDLL_SWITCH_RE.is_match(&rest) {
                rest = split_ws_once(&rest).1.unwrap_or("").to_string();
            }
            let token = if let Some(quoted) = rest.strip_prefix('"') {
                match quoted.find('"') {
                    Some(end) => quoted[..end].to_string(),
                    None => quoted.to_string(),
                }
            } else if rest.contains(',') {
                // `C:\Program Files\x\y.dll,EntryPoint`: the DLL name runs up to the first comma.
                strip(rest.split(',').next().unwrap_or("")).to_string()
            } else {
                split_ws(&rest).first().map(|s| s.to_string()).unwrap_or_default()
            };
            if !token.is_empty() && !SCRIPT_URL_RE.is_match(&token) {
                let token = if ext(&token).is_empty() {
                    format!("{token}.dll")
                } else {
                    token
                };
                set_payload(&mut parsed, &token, cwd);
            }
        }
        HostKind::Regsvr32 => {
            if let Some(file) = tokens.iter().rfind(|t| !(t.starts_with('/') || t.starts_with('-'))) {
                set_payload(&mut parsed, &file.clone(), cwd);
            }
        }
        HostKind::Script => {
            if let Some(file) = tokens.iter().find(|t| !t.starts_with("//")) {
                set_payload(&mut parsed, &file.clone(), cwd);
            }
        }
        HostKind::Mshta => {
            if let Some(first) = tokens.first() {
                if !MSHTA_INLINE_RE.is_match(first) {
                    set_payload(&mut parsed, &first.clone(), cwd);
                } else {
                    parsed.inline = Some(args.clone());
                }
            }
        }
        HostKind::PowerShell => parse_powershell(&mut parsed, cwd),
        HostKind::Cmd => parse_cmd(&mut parsed, cwd, depth),
        HostKind::Conhost => {
            if let Some(caps) = HEADLESS_RE.captures(&args) {
                let inner = strip(caps.get(1).map_or("", |m| m.as_str())).to_string();
                absorb(&mut parsed, &inner, cwd, depth);
            }
        }
        HostKind::Msiexec => {
            for (i, token) in tokens.iter().enumerate() {
                let low = lower(token);
                if ["/i", "-i", "/package", "/a", "/y", "/z"].contains(&low.as_str()) && i + 1 < tokens.len() {
                    let value = &tokens[i + 1];
                    if !value.starts_with('{') {
                        set_payload(&mut parsed, &value.clone(), cwd);
                    }
                    break;
                }
            }
        }
        HostKind::Java => {
            for (i, token) in tokens.iter().enumerate() {
                if lower(token) == "-jar" && i + 1 < tokens.len() {
                    set_payload(&mut parsed, &tokens[i + 1].clone(), cwd);
                    break;
                }
            }
        }
        HostKind::Interp => {
            for (i, token) in tokens.iter().enumerate() {
                let low = lower(token);
                if ["-c", "-e", "--eval", "-p", "--print", "-r"].contains(&low.as_str()) {
                    parsed.inline = Some(tokens[i + 1..].join(" "));
                    break;
                }
                if low == "-m" {
                    break;
                }
                if token.starts_with('-') {
                    continue;
                }
                if SCRIPT_EXTS.iter().any(|e| low.ends_with(e)) || is_file(&normalize_path(token)) {
                    set_payload(&mut parsed, &token.clone(), cwd);
                }
                break;
            }
        }
        HostKind::Explorer => {
            if let Some(first) = tokens.first()
                && !(first.starts_with('/') || first.starts_with('-'))
                && !ext(first).is_empty()
            {
                let (path, url) = resolve_payload(first, cwd);
                if let Some(path) = path.filter(|p| !p.is_empty() && isabs(p)) {
                    parsed.payload = Some(path);
                    parsed.payload_url = url;
                }
            }
        }
        HostKind::None => {}
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenient_base64() {
        assert_eq!(b64decode_lenient("aGk="), Some(b"hi".to_vec()));
        assert_eq!(b64decode_lenient("a G\nk="), Some(b"hi".to_vec()));
        assert_eq!(b64decode_lenient("aGk"), None);
        assert_eq!(b64decode_lenient("aGk=junk"), Some(b"hi".to_vec()));
    }
}
