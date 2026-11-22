//! Secrets left in the clear: passwords and keys in the PowerShell history, in Windows setup and
//! Group Policy leftovers, in a few well-known registry values, and in files in the user's own
//! folders (`.env`, cloud credentials, private keys without a passphrase, password lists...).
//!
//! Everything here is READ-ONLY and bounded: a fixed list of places, depth 2 under the user's
//! folders, files up to 1 MB, a total budget of files and bytes. Links (reparse points) and cloud
//! placeholders are never opened, so the scan does not download anything from OneDrive and friends.
//!
//! **A secret's value is never kept.** Each line is matched in memory and only the place (path,
//! line numbers, registry value name) and the kind of secret leave this module. The fixed masked
//! form of a kind (`sk-…`, `AKIA…`) comes from the kind, never from the text that was read, so the
//! report, the HTML page, the AI payload and the MCP tools cannot receive a value: it is not there.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use vigil_i18n::tr;

use crate::lenient::{Get, list, rx, str_of, text, truthy};
use crate::model::{Flag, Item};

pub(crate) const SECTION: &str = "secrets";

/// The most read from one file (the end of a longer PowerShell history).
const FILE_LIMIT: u64 = 1024 * 1024;
/// Directory entries looked at, files opened and bytes read in one scan.
const MAX_ENTRIES: usize = 20_000;
const MAX_FILES: usize = 400;
const MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Line numbers kept per file.
const MAX_LINES: usize = 10;

// Windows file attributes of cloud files that are not on disk: opening them would download them.
const ATTR_OFFLINE: u32 = 0x1000;
const ATTR_RECALL_ON_OPEN: u32 = 0x40000;
const ATTR_RECALL_ON_DATA_ACCESS: u32 = 0x400000;

// --------------------------------------------------------------------------- kinds

/// The masked form shown for each kind of secret: fixed text, never derived from what was read.
pub(crate) fn mask(kind: &str) -> &'static str {
    match kind {
        "aws_key" => "AKIA…",
        "github_token" => "ghp_…",
        "slack_token" => "xox…",
        "anthropic_key" => "sk-ant-…",
        "openai_key" => "sk-…",
        "azure_key" => "AccountKey=…",
        "bearer_token" => "Bearer …",
        "url_credentials" | "git_credentials" => "https://user:…@",
        "connection_string" => "Password=…",
        "private_key" => "PRIVATE KEY",
        "rdp_password" => "password 51:b:…",
        "gpp_cpassword" => "cpassword=…",
        "unattend_password" => "<Password>…",
        "winlogon_password" => "DefaultPassword",
        "vnc_password" => "VNC password",
        "putty_proxy" => "ProxyPassword",
        "aws_credentials" => "aws_secret_access_key=…",
        "npm_token" => "_authToken=…",
        "pypi_password" => "password=…",
        "docker_credentials" => "auth=…",
        "azure_tokens" => "accessToken",
        "password_list" => "…",
        "password_database" => "KeePass",
        "secret" => "secret=…",
        _ => "password=…",
    }
}

rx!(AWS_KEY, r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b");
rx!(
    GITHUB_TOKEN,
    r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"
);
rx!(SLACK_TOKEN, r"\bxox[baprs]-[A-Za-z0-9-]{10,}");
rx!(ANTHROPIC_KEY, r"\bsk-ant-[A-Za-z0-9_-]{20,}");
rx!(OPENAI_KEY, r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}");
rx!(AZURE_KEY, r"(?i)\b(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{20,}");
rx!(BEARER, r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}");
rx!(URL_CREDS, r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^@\s/]{3,})@");
// `ConvertTo-SecureString "text" -AsPlainText`: a literal, not a variable.
rx!(
    SECURE_STRING,
    r#"(?i)ConvertTo-SecureString\s+(?:-String\s+)?(?:"([^"$]{3,})"|'([^']{3,})')[^|;]*-AsPlainText"#
);
// `net user NAME PASSWORD`: the password is the third word, not a switch or the prompt `*`.
rx!(NET_USER, r"(?i)\bnet(?:\.exe)?\s+user\s+\S+\s+([^\s/*]\S{2,})");
// `/pass:x`, `/password:x`, and `/p:x` without `=` (MSBuild's `/p:Name=Value` is a property).
rx!(
    PASS_SWITCH,
    r#"(?i)(?:^|\s)/(?:pass|password|p):("[^"]{3,}"|[^\s="]{3,})(?:\s|$)"#
);
// `-Password x` with a literal (not `$var`, `(...)`, `@splat` or the next parameter).
rx!(
    PASS_PARAM,
    r#"(?i)(?:^|\s)-(?:password|pass|pwd)\s+("[^"]{3,}"|'[^']{3,}'|[^\s$(@"'-]\S{2,})"#
);
rx!(
    CONN_PASSWORD,
    r#"(?i)(?:server|data source|host|uid|user id|database)\s*=[^;]*;.*?\b(?:password|pwd)\s*=\s*([^;'"\s]{3,})"#
);
rx!(
    GENERIC,
    r#"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret)\b["']?\s*[:=]\s*["']?([^\s"'&;,)]{4,})"#
);
rx!(
    ENV_LINE,
    r#"(?i)^\s*(?:export\s+)?([A-Z0-9_.-]*(?:pass|pwd|secret|token|api_?key|private_?key|access_?key|credential|auth)[A-Z0-9_.-]*)\s*=\s*(.*)$"#
);
rx!(CMDLET, r"^[A-Za-z]+-[A-Za-z]+$");

/// Text that stands for a value rather than being one: variables, templates, masks, examples.
fn placeholder(value: &str) -> bool {
    let v = value.trim().trim_matches(|c| c == '"' || c == '\'');
    if v.chars().count() < 3 {
        return true;
    }
    if v.starts_with(['$', '(', '%', '<', '{', '[', '@']) || v.contains("${") || v.contains("{{") {
        return true;
    }
    if v.chars()
        .all(|c| matches!(c, '*' | 'x' | 'X' | '.' | '-' | '_' | '#' | '•'))
    {
        return true;
    }
    if v.eq_ignore_ascii_case("*SENSITIVE*DATA*DELETED*") || CMDLET.is_match(v) {
        return true;
    }
    let lower = v.to_lowercase();
    matches!(
        lower.as_str(),
        "none"
            | "null"
            | "true"
            | "false"
            | "password"
            | "secret"
            | "token"
            | "example"
            | "changeit_example"
            | "your_password"
            | "yourpassword"
            | "your-password"
            | "required"
            | "optional"
            | "string"
            | "undefined"
            | "redacted"
            | "<redacted>"
            | "hidden"
            | "empty"
    ) || lower.starts_with("your_")
        || lower.starts_with("env:")
        || lower.starts_with("process.env")
}

fn capture_ok(caps: Option<regex::Captures<'_>>, groups: &[usize]) -> bool {
    caps.is_some_and(|c| {
        groups
            .iter()
            .filter_map(|g| c.get(*g))
            .any(|m| !placeholder(m.as_str()))
    })
}

/// The kinds of secret in one line of text (each kind once).
pub(crate) fn line_kinds(line: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut add = |kind: &'static str| {
        if !out.contains(&kind) {
            out.push(kind);
        }
    };
    if AWS_KEY.is_match(line) {
        add("aws_key");
    }
    if GITHUB_TOKEN.is_match(line) {
        add("github_token");
    }
    if SLACK_TOKEN.is_match(line) {
        add("slack_token");
    }
    if ANTHROPIC_KEY.is_match(line) {
        add("anthropic_key");
    } else if OPENAI_KEY.is_match(line) {
        add("openai_key");
    }
    if AZURE_KEY.is_match(line) {
        add("azure_key");
    }
    if BEARER.is_match(line) {
        add("bearer_token");
    }
    if capture_ok(URL_CREDS.captures(line), &[1]) {
        add("url_credentials");
    }
    if capture_ok(CONN_PASSWORD.captures(line), &[1]) {
        add("connection_string");
    }
    if capture_ok(SECURE_STRING.captures(line), &[1, 2])
        || capture_ok(NET_USER.captures(line), &[1])
        || capture_ok(PASS_SWITCH.captures(line), &[1])
        || capture_ok(PASS_PARAM.captures(line), &[1])
    {
        add("password");
    }
    let connection = capture_ok(CONN_PASSWORD.captures(line), &[1]);
    if let Some(caps) = GENERIC.captures(line)
        && caps.get(2).is_some_and(|m| !placeholder(m.as_str()))
        && !connection
    {
        let key = caps.get(1).map(|m| m.as_str().to_lowercase()).unwrap_or_default();
        add(if key.starts_with("pass") || key == "pwd" {
            "password"
        } else {
            "secret"
        });
    }
    out
}

// --------------------------------------------------------------------------- one file's findings

/// What a file holds: the kinds found and the line numbers (empty when only the end was read).
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Found {
    pub kinds: Vec<&'static str>,
    pub lines: Vec<usize>,
    pub count: usize,
}

impl Found {
    fn add(&mut self, kinds: &[&'static str], line: Option<usize>) {
        if kinds.is_empty() {
            return;
        }
        self.count += 1;
        for kind in kinds {
            if !self.kinds.contains(kind) {
                self.kinds.push(kind);
            }
        }
        if let Some(line) = line
            && self.lines.len() < MAX_LINES
        {
            self.lines.push(line);
        }
    }

    fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }
}

/// Every line checked with `check`; line numbers only when `numbered` (the text is the whole file).
fn scan_lines(text: &str, numbered: bool, check: impl Fn(&str) -> Vec<&'static str>) -> Found {
    let mut found = Found::default();
    for (index, line) in text.lines().enumerate() {
        let kinds = check(line);
        found.add(&kinds, numbered.then_some(index + 1));
    }
    found
}

/// A `.env` line `NAME=value` whose name says it is a secret, or any known token.
fn env_kinds(line: &str) -> Vec<&'static str> {
    let mut kinds = line_kinds(line);
    if let Some(caps) = ENV_LINE.captures(line) {
        let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let value = value.split(" #").next().unwrap_or("").trim();
        if !placeholder(value) && !kinds.contains(&"secret") && !kinds.contains(&"password") {
            kinds.push("secret");
        }
    }
    kinds
}

/// Windows setup answer files: `<Password><Value>…` (AutoLogon, AdministratorPassword, local
/// accounts) and sysprep.inf's `AdminPassword`. After setup Windows replaces the value with
/// `*SENSITIVE*DATA*DELETED*`, which is not a secret.
pub(crate) fn unattend_found(text: &str) -> Found {
    rx!(
        XML_VALUE,
        r"(?is)<(?:AdministratorPassword|Password)>\s*<Value>([^<]*)</Value>"
    );
    rx!(INF_VALUE, r#"(?im)^\s*AdminPassword\s*=\s*"?([^"\r\n]*)"?"#);
    let mut found = Found::default();
    let mut offset = 0;
    while let Some(caps) = XML_VALUE.captures(&text[offset..]) {
        let (Some(all), Some(value)) = (caps.get(0), caps.get(1)) else {
            break;
        };
        if !placeholder(value.as_str()) {
            let line = text[..offset + all.start()].matches('\n').count() + 1;
            found.add(&["unattend_password"], Some(line));
        }
        offset += all.end();
    }
    for (index, line) in text.lines().enumerate() {
        if INF_VALUE
            .captures(line)
            .and_then(|c| c.get(1))
            .is_some_and(|v| !placeholder(v.as_str()))
        {
            found.add(&["unattend_password"], Some(index + 1));
        }
    }
    found
}

/// Group Policy preference files: a non-empty `cpassword` (encrypted with a key Microsoft published).
pub(crate) fn gpp_found(text: &str) -> Found {
    rx!(CPASSWORD, r#"(?i)\bcpassword="([^"]+)""#);
    scan_lines(text, true, |line| {
        if CPASSWORD
            .captures(line)
            .and_then(|c| c.get(1))
            .is_some_and(|v| !v.as_str().trim().is_empty())
        {
            vec!["gpp_cpassword"]
        } else {
            Vec::new()
        }
    })
}

/// A PEM, OpenSSH or PuTTY private key that is not protected by a passphrase.
pub(crate) fn private_key_found(text: &str) -> bool {
    if text.contains("PuTTY-User-Key-File-") {
        return text.lines().any(|l| l.trim().eq_ignore_ascii_case("Encryption: none"));
    }
    let Some(start) = text.find("-----BEGIN ") else {
        return false;
    };
    let header = text[start..].lines().next().unwrap_or("");
    if !header.contains("PRIVATE KEY-----") || header.contains("ENCRYPTED") || text.contains("Proc-Type: 4,ENCRYPTED") {
        return false;
    }
    if header.contains("OPENSSH PRIVATE KEY") {
        // openssh-key-v1\0, then the cipher name as a length-prefixed string: "none" = no passphrase.
        let body: String = text[start..]
            .lines()
            .skip(1)
            .take_while(|l| !l.starts_with("-----END"))
            .collect::<String>();
        let bytes = base64_decode(&body[..body.len().min(200)]);
        let magic = b"openssh-key-v1\0";
        let Some(rest) = bytes.strip_prefix(magic.as_slice()) else {
            return false;
        };
        let Some(len) = rest
            .get(..4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
        else {
            return false;
        };
        return rest.get(4..4 + len) == Some(b"none".as_slice());
    }
    true
}

/// Standard base64 (no padding needed); stops at the first character outside the alphabet.
fn base64_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'\r' | b'\n' | b' ' => continue,
            _ => break,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

// --------------------------------------------------------------------------- files by name

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum FileKind {
    Rdp,
    Env,
    Kdbx,
    Key,
    AwsCredentials,
    GitCredentials,
    Npmrc,
    Pypirc,
    Connections,
    Docker,
    AzureTokens,
    ConfigText,
    PasswordList,
}

const TEXT_EXTENSIONS: &[&str] = &[
    "txt", "csv", "md", "json", "xml", "ini", "conf", "cfg", "yml", "yaml", "toml",
];
const LIST_WORDS: &[&str] = &[
    "password",
    "passwd",
    "contraseña",
    "contrasena",
    "credential",
    "secrets",
    "logins",
    "claves",
    "senha",
    "motdepasse",
    "mots de passe",
    "mot de passe",
    "密码",
];

/// Which files are worth opening, from their name and folder alone.
pub(crate) fn file_kind(path: &Path) -> Option<FileKind> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    let parent = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let in_folder = |folder: &str| {
        path.ancestors().skip(1).any(|a| {
            a.file_name()
                .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(folder))
        })
    };
    let extension = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    Some(match () {
        _ if extension == "rdp" => FileKind::Rdp,
        _ if name == ".env" || name.starts_with(".env.") || extension == "env" => FileKind::Env,
        _ if extension == "kdbx" => FileKind::Kdbx,
        _ if matches!(name.as_str(), "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519")
            || matches!(extension.as_str(), "pem" | "key" | "ppk") =>
        {
            FileKind::Key
        }
        _ if name == "credentials" && parent == ".aws" => FileKind::AwsCredentials,
        _ if name == ".git-credentials" => FileKind::GitCredentials,
        _ if name == ".npmrc" => FileKind::Npmrc,
        _ if name == ".pypirc" => FileKind::Pypirc,
        _ if name == "web.config" || (name.starts_with("appsettings") && extension == "json") => FileKind::Connections,
        _ if name == "config.json" && parent == ".docker" => FileKind::Docker,
        _ if in_folder(".azure") && matches!(name.as_str(), "accesstokens.json" | "msal_token_cache.json") => {
            FileKind::AzureTokens
        }
        _ if in_folder(".config") && TEXT_EXTENSIONS.contains(&extension.as_str()) => FileKind::ConfigText,
        _ if TEXT_EXTENSIONS.contains(&extension.as_str()) && LIST_WORDS.iter().any(|w| name.contains(w)) => {
            FileKind::PasswordList
        }
        _ => return None,
    })
}

/// What a file of that kind holds (text already read).
pub(crate) fn file_found(kind: FileKind, text: &str) -> Found {
    rx!(RDP_PASSWORD, r"(?i)^\s*password 51:b:\s*[0-9A-F]{8,}");
    rx!(
        AWS_SECRET,
        r"(?i)^\s*aws_(?:secret_access_key|session_token)\s*=\s*\S{8,}"
    );
    rx!(GIT_LINE, r"(?i)^[a-z][a-z0-9+.-]*://[^:/\s]+:[^@\s]{3,}@");
    rx!(NPM_LINE, r"(?i)(?:_authToken|_auth|_password)\s*=\s*(\S+)");
    rx!(PYPI_LINE, r"(?i)^\s*password\s*[:=]\s*(\S+)");
    rx!(DOCKER_AUTH, r#"(?i)"auth"\s*:\s*"([A-Za-z0-9+/=]{8,})""#);
    rx!(
        AZURE_TOKEN,
        r#"(?i)"(?:accessToken|refresh_token|secret)"\s*:\s*"[^"]{20,}""#
    );
    let only = |kind: &'static str, matched: bool| if matched { vec![kind] } else { Vec::new() };
    match kind {
        FileKind::Rdp => scan_lines(text, true, |l| only("rdp_password", RDP_PASSWORD.is_match(l))),
        FileKind::Env => scan_lines(text, true, env_kinds),
        FileKind::Kdbx => {
            let mut found = Found::default();
            found.add(&["password_database"], None);
            found
        }
        FileKind::Key => {
            let mut found = Found::default();
            if private_key_found(text) {
                found.add(&["private_key"], None);
            }
            found
        }
        FileKind::AwsCredentials => scan_lines(text, true, |l| only("aws_credentials", AWS_SECRET.is_match(l))),
        FileKind::GitCredentials => scan_lines(text, true, |l| only("git_credentials", GIT_LINE.is_match(l))),
        FileKind::Npmrc => scan_lines(text, true, |l| {
            only("npm_token", capture_ok(NPM_LINE.captures(l), &[1]))
        }),
        FileKind::Pypirc => scan_lines(text, true, |l| {
            only("pypi_password", capture_ok(PYPI_LINE.captures(l), &[1]))
        }),
        FileKind::Connections => scan_lines(text, true, |l| {
            let mut kinds = line_kinds(l);
            kinds.retain(|k| *k != "secret");
            kinds
        }),
        FileKind::Docker => scan_lines(text, true, |l| only("docker_credentials", DOCKER_AUTH.is_match(l))),
        FileKind::AzureTokens => scan_lines(text, true, |l| only("azure_tokens", AZURE_TOKEN.is_match(l))),
        FileKind::ConfigText => scan_lines(text, true, line_kinds),
        FileKind::PasswordList => {
            let mut found = scan_lines(text, true, line_kinds);
            if !text.trim().is_empty() {
                found.add(&["password_list"], None);
                found.count = found.count.max(1);
            }
            found
        }
    }
}

// --------------------------------------------------------------------------- bounded reading

/// What one scan may still read, and what it skipped.
#[derive(Debug, Default)]
pub(crate) struct Budget {
    pub entries: usize,
    pub files: usize,
    pub bytes: u64,
    pub skipped_links: usize,
    pub skipped_cloud: usize,
    pub exhausted: bool,
}

impl Budget {
    fn entry(&mut self) -> bool {
        if self.entries >= MAX_ENTRIES {
            self.exhausted = true;
            return false;
        }
        self.entries += 1;
        true
    }

    fn can_read(&mut self) -> bool {
        if self.files >= MAX_FILES || self.bytes >= MAX_BYTES {
            self.exhausted = true;
            return false;
        }
        true
    }
}

#[cfg(windows)]
fn attributes(meta: &fs::Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes()
}

#[cfg(not(windows))]
fn attributes(_: &fs::Metadata) -> u32 {
    0
}

/// Counts and refuses links and cloud placeholders. `meta` must not follow links.
///
/// A link is a symbolic link or a junction (a name-surrogate reparse point, which is what
/// `is_symlink` tests on Windows). OneDrive files are reparse points too, but with a cloud tag:
/// those that are on disk are read like any file; those that are not (recall on open or on data
/// access, offline) are skipped, so nothing is downloaded.
fn openable(meta: &fs::Metadata, budget: &mut Budget) -> bool {
    if meta.file_type().is_symlink() {
        budget.skipped_links += 1;
        return false;
    }
    let attrs = attributes(meta);
    if attrs & (ATTR_OFFLINE | ATTR_RECALL_ON_OPEN | ATTR_RECALL_ON_DATA_ACCESS) != 0 {
        budget.skipped_cloud += 1;
        return false;
    }
    true
}

/// Reads a whole file up to the limit, or its last `FILE_LIMIT` bytes when `tail` and it is longer.
/// Returns the text and whether it is complete (line numbers are only true then).
fn read_text(path: &Path, tail: bool, budget: &mut Budget) -> Option<(String, bool)> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || !openable(&meta, budget) || !budget.can_read() {
        return None;
    }
    let size = meta.len();
    if size > FILE_LIMIT && !tail {
        return None;
    }
    let mut file = fs::File::open(path).ok()?;
    let complete = size <= FILE_LIMIT;
    if !complete {
        file.seek(SeekFrom::Start(size - FILE_LIMIT)).ok()?;
    }
    let mut bytes = Vec::new();
    file.take(FILE_LIMIT).read_to_end(&mut bytes).ok()?;
    budget.files += 1;
    budget.bytes += bytes.len() as u64;
    Some((crate::persist::decode(&bytes), complete))
}

/// Files under `root` (down to `depth` folder levels) whose name is worth opening.
fn candidates(root: &Path, depth: usize, budget: &mut Budget, out: &mut Vec<(PathBuf, FileKind)>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut folders = Vec::new();
    for entry in entries.flatten() {
        if !budget.entry() {
            return;
        }
        // DirEntry::metadata does not follow links on Windows (it comes from the directory listing).
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let path = entry.path();
        if meta.file_type().is_symlink() {
            budget.skipped_links += 1;
        } else if meta.is_dir() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if depth > 0
                && !matches!(name.as_str(), "node_modules" | ".git" | "$recycle.bin" | "appdata")
                && openable(&meta, budget)
            {
                folders.push(path);
            }
        } else if let Some(kind) = file_kind(&path) {
            out.push((path, kind));
        }
    }
    folders.sort();
    for folder in folders {
        candidates(&folder, depth - 1, budget, out);
    }
}

// --------------------------------------------------------------------------- where to look

/// The places one scan looks at. Tests build their own with temporary folders.
#[derive(Debug, Default, Clone)]
pub(crate) struct Places {
    /// PowerShell history files and the account they belong to ("" for the current user).
    pub histories: Vec<(PathBuf, String)>,
    /// Windows setup answer files.
    pub setup_files: Vec<PathBuf>,
    /// Folders holding Group Policy preference files.
    pub gpp_roots: Vec<PathBuf>,
    /// Folders of the current user and how deep to look in each.
    pub user_roots: Vec<(PathBuf, usize)>,
    /// Whether the registry values are read.
    pub registry: bool,
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// PowerShell history files in a roaming AppData folder.
fn history_files(roaming: &Path) -> Vec<PathBuf> {
    let folder = roaming.join(r"Microsoft\Windows\PowerShell\PSReadLine");
    let mut out: Vec<PathBuf> = fs::read_dir(&folder)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .is_some_and(|n| n.to_string_lossy().to_lowercase().ends_with("_history.txt"))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

#[cfg(windows)]
fn known_folder(id: &windows::core::GUID) -> Option<PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    // SAFETY: the GUID outlives the call; the returned buffer is read once and freed with
    // CoTaskMemFree, as the API requires, on success.
    unsafe {
        let path = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let text = path.to_string().ok();
        CoTaskMemFree(Some(path.0 as *const core::ffi::c_void));
        text.filter(|t| !t.is_empty()).map(PathBuf::from)
    }
}

/// The places of this computer and its current user.
fn this_computer(elevated: bool) -> Places {
    let mut places = Places {
        registry: true,
        ..Places::default()
    };
    let appdata = env("APPDATA");
    if !appdata.is_empty() {
        for file in history_files(Path::new(&appdata)) {
            places.histories.push((file, String::new()));
        }
    }
    if elevated {
        for home in crate::browsers::other_homes() {
            for file in history_files(&home.roaming) {
                places.histories.push((file, home.account.clone()));
            }
        }
    }

    let windir = crate::ntpath::WINDIR.clone();
    let system_drive = {
        let d = env("SystemDrive");
        if d.is_empty() { "C:".to_string() } else { d }
    };
    let win = Path::new(&windir);
    for relative in [
        r"Panther\unattend.xml",
        r"Panther\Unattend\Unattend.xml",
        r"Panther\autounattend.xml",
        r"System32\sysprep\unattend.xml",
        r"System32\sysprep\sysprep.xml",
        r"System32\sysprep\Panther\unattend.xml",
        r"System32\sysprep.inf",
    ] {
        places.setup_files.push(win.join(relative));
    }
    let drive = PathBuf::from(format!(r"{system_drive}\"));
    for name in [
        "unattend.xml",
        "autounattend.xml",
        r"sysprep\sysprep.xml",
        r"sysprep\sysprep.inf",
    ] {
        places.setup_files.push(drive.join(name));
    }

    let program_data = env("ProgramData");
    if !program_data.is_empty() {
        places
            .gpp_roots
            .push(Path::new(&program_data).join(r"Microsoft\Group Policy\History"));
    }
    places.gpp_roots.push(win.join(r"SYSVOL\domain\Policies"));
    places.gpp_roots.push(win.join(r"SYSVOL\sysvol"));

    let profile = env("USERPROFILE");
    if !profile.is_empty() {
        let home = PathBuf::from(&profile);
        places.user_roots.push((home.clone(), 0));
        for dot in [".ssh", ".aws", ".azure", ".config", ".docker"] {
            places.user_roots.push((home.join(dot), 2));
        }
        #[cfg(windows)]
        let folders = {
            use windows::Win32::UI::Shell::{FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads};
            [
                known_folder(&FOLDERID_Desktop).unwrap_or_else(|| home.join("Desktop")),
                known_folder(&FOLDERID_Documents).unwrap_or_else(|| home.join("Documents")),
                known_folder(&FOLDERID_Downloads).unwrap_or_else(|| home.join("Downloads")),
            ]
        };
        #[cfg(not(windows))]
        let folders = [home.join("Desktop"), home.join("Documents"), home.join("Downloads")];
        for folder in folders {
            if !places.user_roots.iter().any(|(p, _)| *p == folder) {
                places.user_roots.push((folder, 2));
            }
        }
    }
    places
}

// --------------------------------------------------------------------------- collecting

fn entry(source: &str, path: &str, exposure: &str, found: &Found, extra: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    map.insert("source".into(), json!(source));
    map.insert("path".into(), json!(path));
    map.insert("exposure".into(), json!(exposure));
    map.insert("kinds".into(), json!(found.kinds));
    map.insert("lines".into(), json!(found.lines));
    map.insert("count".into(), json!(found.count));
    for (key, value) in extra {
        map.insert(key.into(), value);
    }
    Value::Object(map)
}

/// Group Policy preference XML files under a root (bounded walk, links never followed).
fn gpp_files(root: &Path, depth: usize, budget: &mut Budget, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut folders = Vec::new();
    for entry in entries.flatten() {
        if !budget.entry() {
            return;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let path = entry.path();
        if meta.file_type().is_symlink() {
            budget.skipped_links += 1;
        } else if meta.is_dir() {
            if depth > 0 && openable(&meta, budget) {
                folders.push(path);
            }
        } else if path
            .extension()
            .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case("xml"))
        {
            out.push(path);
        }
    }
    folders.sort();
    for folder in folders {
        gpp_files(&folder, depth - 1, budget, out);
    }
}

/// Registry values that hold a password: Winlogon's automatic sign-in, VNC servers and PuTTY
/// proxy passwords. Only the value's place is kept.
fn registry_entries() -> Vec<Value> {
    use crate::winreg::{self, Hive, View};
    let single = |kind: &'static str| {
        let mut found = Found::default();
        found.add(&[kind], None);
        found
    };
    let mut out = Vec::new();
    let winlogon = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    for view in [View::V64, View::V32] {
        let stored = winreg::value(Hive::Hklm, winlogon, "DefaultPassword", view).is_some_and(|v| v.truthy());
        if stored {
            let auto = winreg::value(Hive::Hklm, winlogon, "AutoAdminLogon", view)
                .map(|v| v.as_text())
                .unwrap_or_default();
            out.push(entry(
                "registry",
                &format!(r"HKLM\{winlogon}\DefaultPassword"),
                "shared",
                &single("winlogon_password"),
                vec![("auto_sign_in", json!(auto.trim() == "1"))],
            ));
            break;
        }
    }
    let vnc: [(Hive, &str, &str); 7] = [
        (Hive::Hklm, r"SOFTWARE\RealVNC\WinVNC4", "Password"),
        (Hive::Hklm, r"SOFTWARE\RealVNC\vncserver", "Password"),
        (Hive::Hklm, r"SOFTWARE\TightVNC\Server", "Password"),
        (Hive::Hkcu, r"Software\TightVNC\Server", "Password"),
        (Hive::Hklm, r"SOFTWARE\ORL\WinVNC3", "Password"),
        (Hive::Hkcu, r"Software\ORL\WinVNC3", "Password"),
        (Hive::Hklm, r"SOFTWARE\TigerVNC\WinVNC4", "Password"),
    ];
    for (hive, key, name) in vnc {
        if winreg::value(hive, key, name, View::V64).is_some_and(|v| v.truthy()) {
            let root = if matches!(hive, Hive::Hklm) { "HKLM" } else { "HKCU" };
            let exposure = if matches!(hive, Hive::Hklm) { "shared" } else { "user" };
            out.push(entry(
                "registry",
                &format!(r"{root}\{key}\{name}"),
                exposure,
                &single("vnc_password"),
                vec![],
            ));
        }
    }
    let putty = r"Software\SimonTatham\PuTTY\Sessions";
    for session in winreg::subkeys(Hive::Hkcu, putty, View::V64) {
        let key = format!(r"{putty}\{session}");
        if winreg::value(Hive::Hkcu, &key, "ProxyPassword", View::V64).is_some_and(|v| v.truthy()) {
            out.push(entry(
                "registry",
                &format!(r"HKCU\{key}\ProxyPassword"),
                "user",
                &single("putty_proxy"),
                vec![("session", json!(session))],
            ));
        }
    }
    out
}

/// Looks at every place and returns what to put in `sysconfig.secrets`.
pub(crate) fn collect_from(places: &Places, elevated: bool) -> Value {
    let mut budget = Budget::default();
    let mut entries: Vec<Value> = Vec::new();

    for (path, account) in &places.histories {
        let Some((text, complete)) = read_text(path, true, &mut budget) else {
            continue;
        };
        let found = scan_lines(&text, complete, line_kinds);
        if !found.is_empty() {
            let mut extra = vec![("partial", json!(!complete))];
            if !account.is_empty() {
                extra.push(("account", json!(account)));
            }
            entries.push(entry("ps_history", &path.to_string_lossy(), "user", &found, extra));
        }
    }

    for path in &places.setup_files {
        let Some((text, _)) = read_text(path, false, &mut budget) else {
            continue;
        };
        let found = unattend_found(&text);
        if !found.is_empty() {
            entries.push(entry("setup_file", &path.to_string_lossy(), "shared", &found, vec![]));
        }
    }

    let mut gpp = Vec::new();
    for root in &places.gpp_roots {
        gpp_files(root, 8, &mut budget, &mut gpp);
    }
    for path in gpp {
        let Some((text, _)) = read_text(&path, false, &mut budget) else {
            continue;
        };
        let found = gpp_found(&text);
        if !found.is_empty() {
            entries.push(entry("group_policy", &path.to_string_lossy(), "shared", &found, vec![]));
        }
    }

    if places.registry {
        entries.extend(registry_entries());
    }

    let mut files = Vec::new();
    for (root, depth) in &places.user_roots {
        if *depth == 0 {
            // The profile folder itself: only the files directly in it.
            candidates(root, 0, &mut budget, &mut files);
        } else if fs::symlink_metadata(root).is_ok_and(|m| m.is_dir() && openable(&m, &mut budget)) {
            candidates(root, *depth, &mut budget, &mut files);
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files.dedup_by(|a, b| a.0 == b.0);
    for (path, kind) in files {
        let found = if kind == FileKind::Kdbx {
            // A password database is reported by its presence; it is never opened.
            file_found(kind, "")
        } else {
            let Some((text, _)) = read_text(&path, false, &mut budget) else {
                continue;
            };
            file_found(kind, &text)
        };
        if !found.is_empty() {
            entries.push(entry("user_file", &path.to_string_lossy(), "user", &found, vec![]));
        }
    }

    let mut notes = Vec::new();
    if !elevated {
        notes.push(json!({"area": tr!("secrets in the clear"), "message":
            tr!("other accounts' PowerShell history was not checked (it needs administrator rights)")}));
    }
    if budget.exhausted {
        notes.push(json!({"area": tr!("secrets in the clear"), "message":
            tr!("the search for secrets in files stopped at its limit; some files were not read")}));
    }
    json!({
        "elevated": elevated,
        "entries": entries,
        "stats": {
            "entries_seen": budget.entries,
            "files_read": budget.files,
            "bytes_read": budget.bytes,
            "skipped_links": budget.skipped_links,
            "skipped_cloud_files": budget.skipped_cloud,
            "limit_reached": budget.exhausted,
        },
        "notes": notes,
    })
}

/// `sysconfig.secrets` for this computer.
pub(crate) fn collect(elevated: bool) -> Value {
    collect_from(&this_computer(elevated), elevated)
}

// --------------------------------------------------------------------------- judging

fn file_name(path: &str) -> String {
    crate::ntpath::basename(path).to_string()
}

/// Files of one topic in the user's folders shown one by one up to this many.
const GROUP_FROM: usize = 5;
/// Paths listed in a grouped finding.
const GROUP_PATHS: usize = 50;

/// One finding for many files of the same topic: the highest score, every kind, the paths.
fn grouped(topic: &'static str, group: Vec<Item>) -> Item {
    let count = group.len();
    let title = match topic {
        "secret_private_key" => tr!("Private keys without a passphrase: {0} files", count),
        "secret_password_list" => tr!("Files that look like lists of passwords: {0}", count),
        _ => tr!("Files that keep a password or key in the clear: {0}", count),
    };
    let best = group
        .iter()
        .max_by_key(|i| i.score)
        .map(|i| i.subtitle.clone())
        .unwrap_or_default();
    let score = group
        .iter()
        .flat_map(|i| i.flags.iter())
        .map(|f| f.weight)
        .max()
        .unwrap_or(0);
    let mut kinds: Vec<Value> = Vec::new();
    let mut paths: Vec<Value> = Vec::new();
    for item in &group {
        for kind in list(item.facts.at("kinds")) {
            if !kinds.contains(kind) {
                kinds.push(kind.clone());
            }
        }
        if paths.len() < GROUP_PATHS {
            paths.push(item.facts.at("path").clone());
        }
    }
    let mut item = Item::new("config", title, &best);
    item.facts.insert("topic".into(), json!(topic));
    item.facts.insert("category".into(), json!("secrets"));
    item.facts.insert("exposure".into(), json!("user"));
    item.facts.insert("kinds".into(), json!(kinds));
    item.facts.insert("files".into(), json!(count));
    item.facts.insert("paths".into(), json!(paths));
    item.add_flag(Flag::new(topic, score, best));
    item.rescore();
    item
}

/// One finding per place. The facts hold the place, the kinds (as fixed masks) and line numbers.
pub(crate) fn items(raw: &Value) -> Vec<Item> {
    let section = raw.at("sysconfig").at(SECTION);
    let mut items = Vec::new();
    let mut databases: Vec<String> = Vec::new();
    // Files in the user's folders, by topic: more than GROUP_FROM of one topic become one finding
    // (a developer's projects can hold dozens of test keys or .env files).
    let mut files: std::collections::BTreeMap<&'static str, Vec<Item>> = std::collections::BTreeMap::new();
    for e in list(section.at("entries")) {
        let source = str_of(e.at("source"));
        let path = text(e.at("path"));
        let kinds: Vec<String> = list(e.at("kinds")).iter().map(str_of).collect();
        if kinds.iter().all(|k| k == "password_database") {
            databases.push(path);
            continue;
        }
        let masks: Vec<&str> = kinds.iter().map(|k| mask(k)).collect();
        let shared = str_of(e.at("exposure")) == "shared";
        let has = |k: &str| kinds.iter().any(|x| x == k);
        let cloud = kinds.iter().any(|k| {
            matches!(
                k.as_str(),
                "aws_key"
                    | "aws_credentials"
                    | "github_token"
                    | "slack_token"
                    | "openai_key"
                    | "anthropic_key"
                    | "azure_key"
                    | "azure_tokens"
                    | "npm_token"
                    | "docker_credentials"
                    | "private_key"
                    | "git_credentials"
                    | "bearer_token"
            )
        });
        let (topic, title, score, about) = match source.as_str() {
            "setup_file" => (
                "secret_shared",
                tr!("Windows setup file keeps a password: {0}", file_name(&path)),
                60,
                tr!(
                    "any user of this computer can read this setup file, and the password in it is only encoded, not encrypted"
                ),
            ),
            "group_policy" => (
                "secret_shared",
                tr!("Group Policy file keeps a password: {0}", file_name(&path)),
                60,
                tr!(
                    "the cpassword in this file is encrypted with a key Microsoft published, so anyone who can read the file can read the password"
                ),
            ),
            "registry" if has("winlogon_password") => (
                "secret_shared",
                tr!("Windows keeps the password for automatic sign-in in the registry"),
                60,
                tr!("the DefaultPassword value is stored in plain text where every user of this computer can read it"),
            ),
            "registry" if has("vnc_password") => (
                "secret_registry",
                tr!("VNC password stored in the registry"),
                if shared { 40 } else { 30 },
                tr!(
                    "VNC stores its password with a fixed, publicly known key, so anyone who can read the value can recover it"
                ),
            ),
            "registry" => (
                "secret_registry",
                tr!("PuTTY keeps a proxy password: {0}", str_of(e.at("session"))),
                20,
                tr!("PuTTY stores proxy passwords in the registry in plain text"),
            ),
            "ps_history" => (
                "secret_history",
                tr!("Passwords or keys in the PowerShell history: {0}", file_name(&path)),
                if cloud { 30 } else { 25 },
                tr!(
                    "PowerShell saves every command you type in this file, including passwords and keys written on the command line"
                ),
            ),
            _ if has("private_key") => (
                "secret_private_key",
                tr!("Private key without a passphrase: {0}", file_name(&path)),
                30,
                tr!("anyone or any program that copies this file can use the key; it is not protected by a passphrase"),
            ),
            _ if has("rdp_password") => (
                "secret_file",
                tr!("Remote Desktop file keeps a password: {0}", file_name(&path)),
                15,
                tr!(
                    "the password is encrypted for your account only, but anyone who uses your account can connect with it"
                ),
            ),
            _ if has("password_list") => (
                "secret_password_list",
                tr!("File that looks like a list of passwords: {0}", file_name(&path)),
                25,
                tr!("a text file named like a password list; passwords kept in plain files are easy to steal"),
            ),
            _ => (
                "secret_file",
                tr!("File keeps a password or key in the clear: {0}", file_name(&path)),
                if cloud { 30 } else { 25 },
                tr!("this file holds a password, token or key in plain text; any program you run can read it"),
            ),
        };
        let mut facts = Map::new();
        facts.insert("topic".into(), json!(topic));
        facts.insert("category".into(), json!("secrets"));
        facts.insert("path".into(), json!(path));
        facts.insert("kinds".into(), json!(masks));
        facts.insert("exposure".into(), json!(if shared { "shared" } else { "user" }));
        let lines = list(e.at("lines"));
        if !lines.is_empty() {
            facts.insert("lines".into(), json!(lines));
        }
        facts.insert("count".into(), e.at("count").clone());
        if truthy(e.at("partial")) {
            facts.insert("partial".into(), json!(true));
        }
        for key in ["account", "session", "auto_sign_in"] {
            if !e.at(key).is_null() {
                facts.insert(key.into(), e.at(key).clone());
            }
        }
        let mut item = Item::new("config", &title, &about);
        item.facts = facts;
        item.add_flag(Flag::new(topic, score, about));
        item.rescore();
        if source == "user_file" {
            files.entry(topic).or_default().push(item);
        } else {
            items.push(item);
        }
    }
    for (topic, group) in files {
        if group.len() <= GROUP_FROM {
            items.extend(group);
        } else {
            items.push(grouped(topic, group));
        }
    }
    if !databases.is_empty() {
        let mut item = Item::new(
            "config",
            tr!("Password databases (KeePass): {0}", databases.len()),
            tr!("for your information: these files are encrypted by their own master password"),
        );
        item.facts.insert("topic".into(), json!("password_database"));
        item.facts.insert("category".into(), json!("secrets"));
        item.facts.insert("paths".into(), json!(databases));
        item.rescore();
        items.push(item);
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    // Obviously fake values in the formats real ones use.
    const FAKE_AWS: &str = "AKIAEXAMPLEEXAMPLE00";
    const FAKE_GITHUB: &str = "ghp_EXAMPLEexampleEXAMPLEexample00000000";
    const FAKE_OPENAI: &str = "sk-proj-EXAMPLEexampleEXAMPLE0000";
    const FAKE_ANTHROPIC: &str = "sk-ant-api03-EXAMPLEexampleEXAMPLE00";
    const FAKE_PASSWORD: &str = "Contoso-Fake-Pa55word!";
    const FAKE_SECRET: &str = "fake-secret-value-0000-example";

    fn fakes() -> [&'static str; 6] {
        [
            FAKE_AWS,
            FAKE_GITHUB,
            FAKE_OPENAI,
            FAKE_ANTHROPIC,
            FAKE_PASSWORD,
            FAKE_SECRET,
        ]
    }

    #[test]
    fn line_patterns_find_secrets_and_skip_placeholders() {
        let cases: &[(&str, &[&str])] = &[
            (&format!("$env:AWS_ACCESS_KEY_ID = '{FAKE_AWS}'"), &["aws_key"]),
            (
                &format!("git clone https://{FAKE_GITHUB}@github.com/contoso/app"),
                &["github_token"],
            ),
            (
                &format!("curl -H \"Authorization: Bearer {FAKE_OPENAI}\""),
                &["openai_key", "bearer_token"],
            ),
            (&format!("$k = \"{FAKE_ANTHROPIC}\""), &["anthropic_key"]),
            (
                &format!("$s = ConvertTo-SecureString \"{FAKE_PASSWORD}\" -AsPlainText -Force"),
                &["password"],
            ),
            (&format!("net user jdoe {FAKE_PASSWORD} /add"), &["password"]),
            (
                &format!("cmdkey /generic:host /user:jdoe /pass:{FAKE_PASSWORD}"),
                &["password"],
            ),
            (
                &format!("Connect-Thing -Server db -Password {FAKE_PASSWORD}"),
                &["password"],
            ),
            (
                &format!("Server=db;Database=app;User Id=sa;Password={FAKE_PASSWORD};"),
                &["connection_string"],
            ),
            (&format!("client_secret = {FAKE_SECRET}"), &["secret"]),
        ];
        for (line, expected) in cases {
            let mut got = line_kinds(line);
            got.sort_unstable();
            let mut want = expected.to_vec();
            want.sort_unstable();
            assert_eq!(got, want, "{line}");
        }
        for quiet in [
            "$s = ConvertTo-SecureString $plain -AsPlainText -Force",
            "$cred = Get-Credential",
            "Connect-Thing -Password $secure",
            "net user jdoe * /add",
            "net user jdoe /delete",
            "msbuild app.sln /p:Configuration=Release",
            "$password = Read-Host -AsSecureString",
            "password = ${DB_PASSWORD}",
            "token: <your token here>",
            "password=********",
            "Get-ChildItem -Path C:\\Users\\jdoe",
        ] {
            assert!(line_kinds(quiet).is_empty(), "{quiet}: {:?}", line_kinds(quiet));
        }
    }

    #[test]
    fn setup_files_ignore_the_value_windows_deleted() {
        let filled = "<AutoLogon>\n<Password>\n<Value>Q29udG9zbw==</Value>\n<PlainText>false</PlainText>\n</Password>\n</AutoLogon>";
        let found = unattend_found(filled);
        assert_eq!(found.kinds, ["unattend_password"]);
        assert_eq!(found.lines, [2]);
        let cleaned = "<Password><Value>*SENSITIVE*DATA*DELETED*</Value></Password>";
        assert!(unattend_found(cleaned).is_empty());
        assert!(unattend_found("<Password><Value></Value></Password>").is_empty());
        assert_eq!(
            unattend_found("[GuiUnattended]\nAdminPassword=\"Fake\"\n").kinds,
            ["unattend_password"]
        );
        let gpp =
            r#"<Properties action="U" userName="jdoe" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" />"#;
        assert_eq!(gpp_found(gpp).kinds, ["gpp_cpassword"]);
        assert!(gpp_found(r#"<Properties cpassword="" />"#).is_empty());
    }

    #[test]
    fn private_keys_count_only_without_a_passphrase() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEfakefake\n-----END RSA PRIVATE KEY-----\n";
        assert!(private_key_found(pem));
        let encrypted = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: x\n\nabc\n-----END RSA PRIVATE KEY-----";
        assert!(!private_key_found(encrypted));
        assert!(!private_key_found(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc\n-----END ENCRYPTED PRIVATE KEY-----"
        ));
        assert!(!private_key_found(
            "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----"
        ));
        // OpenSSH: the cipher name after the magic says whether a passphrase protects it.
        let openssh = |cipher: &str| {
            let mut bytes = b"openssh-key-v1\0".to_vec();
            bytes.extend((cipher.len() as u32).to_be_bytes());
            bytes.extend(cipher.as_bytes());
            bytes.extend([0u8; 12]);
            format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----",
                b64(&bytes)
            )
        };
        assert!(private_key_found(&openssh("none")));
        assert!(!private_key_found(&openssh("aes256-ctr")));
        assert!(private_key_found(
            "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n"
        ));
        assert!(!private_key_found(
            "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\n"
        ));
    }

    fn b64(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..=chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn file_names_decide_what_is_opened() {
        let kind = |p: &str| file_kind(Path::new(p));
        assert_eq!(kind(r"C:\Users\jdoe\Desktop\server.rdp"), Some(FileKind::Rdp));
        assert_eq!(kind(r"C:\Users\jdoe\Documents\app\.env"), Some(FileKind::Env));
        assert_eq!(kind(r"C:\Users\jdoe\Documents\app\.env.local"), Some(FileKind::Env));
        assert_eq!(kind(r"C:\Users\jdoe\.ssh\id_ed25519"), Some(FileKind::Key));
        assert_eq!(kind(r"C:\Users\jdoe\.ssh\id_ed25519.pub"), None);
        assert_eq!(kind(r"C:\Users\jdoe\.aws\credentials"), Some(FileKind::AwsCredentials));
        assert_eq!(kind(r"C:\Users\jdoe\.config\gh\hosts.yml"), Some(FileKind::ConfigText));
        assert_eq!(
            kind(r"C:\Users\jdoe\Desktop\Passwords.txt"),
            Some(FileKind::PasswordList)
        );
        assert_eq!(
            kind(r"C:\Users\jdoe\Documents\contraseñas.txt"),
            Some(FileKind::PasswordList)
        );
        assert_eq!(kind(r"C:\Users\jdoe\Documents\vault.kdbx"), Some(FileKind::Kdbx));
        assert_eq!(kind(r"C:\Users\jdoe\Documents\report.docx"), None);
        assert_eq!(kind(r"C:\Users\jdoe\Documents\notes.txt"), None);
    }

    /// A temporary folder tree, deleted when the test ends.
    struct Tree(PathBuf);

    impl Tree {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!("vigil-secrets-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("temp tree");
            Self(root)
        }

        fn file(&self, relative: &str, content: &str) -> PathBuf {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("folder");
            }
            fs::write(&path, content).expect("file");
            path
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A fictitious computer full of fake secrets, collected with the real collector.
    fn fake_computer(tree: &Tree) -> Value {
        let history = tree.file(
            r"Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
            &format!(
                "Get-Process\n$s = ConvertTo-SecureString \"{FAKE_PASSWORD}\" -AsPlainText -Force\nGet-Service\n$env:OPENAI_API_KEY='{FAKE_OPENAI}'\n"
            ),
        );
        let unattend = tree.file(
            r"Windows\Panther\unattend.xml",
            &format!("<UserAccounts><AdministratorPassword><Value>{FAKE_PASSWORD}</Value></AdministratorPassword>\n<LocalAccounts><LocalAccount><Password>\n<Value>{FAKE_PASSWORD}</Value></Password></LocalAccount></LocalAccounts></UserAccounts>"),
        );
        tree.file(
            r"ProgramData\GP\{31B2F340}\Machine\Preferences\Groups\Groups.xml",
            r#"<User name="Administrator"><Properties cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" userName="Administrator" /></User>"#,
        );
        tree.file(
            r"jdoe\.aws\credentials",
            &format!("[default]\naws_access_key_id = {FAKE_AWS}\naws_secret_access_key = {FAKE_SECRET}\n"),
        );
        tree.file(
            r"jdoe\.git-credentials",
            &format!("https://jdoe:{FAKE_GITHUB}@github.com\n"),
        );
        tree.file(
            r"jdoe\Documents\app\.env",
            &format!(
                "DB_HOST=localhost\nDB_PASSWORD={FAKE_PASSWORD}\nANTHROPIC_API_KEY={FAKE_ANTHROPIC}\nEMPTY_TOKEN=\n"
            ),
        );
        tree.file(r"jdoe\Desktop\passwords.txt", &format!("bank: {FAKE_PASSWORD}\n"));
        tree.file(r"jdoe\Documents\vault.kdbx", "not a real database");
        tree.file(
            r"jdoe\.ssh\id_rsa",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEfakefakefake\n-----END RSA PRIVATE KEY-----\n",
        );
        tree.file(r"jdoe\Documents\deep\a\b\c\.env", &format!("TOKEN={FAKE_SECRET}\n"));
        let places = Places {
            histories: vec![(history, String::new())],
            setup_files: vec![unattend, tree.0.join(r"Windows\Panther\missing.xml")],
            gpp_roots: vec![tree.0.join(r"ProgramData\GP")],
            user_roots: vec![
                (tree.0.join("jdoe"), 0),
                (tree.0.join(r"jdoe\.aws"), 2),
                (tree.0.join(r"jdoe\.ssh"), 2),
                (tree.0.join(r"jdoe\Desktop"), 2),
                (tree.0.join(r"jdoe\Documents"), 2),
            ],
            registry: false,
        };
        collect_from(&places, false)
    }

    fn by_source<'a>(collected: &'a Value, source: &str) -> Vec<&'a Value> {
        list(collected.at("entries"))
            .iter()
            .filter(|e| str_of(e.at("source")) == source)
            .collect()
    }

    #[test]
    fn the_collector_finds_each_place_and_keeps_no_value() {
        let tree = Tree::new("collect");
        let collected = fake_computer(&tree);
        let dump = collected.to_string();
        for fake in fakes() {
            assert!(!dump.contains(fake), "a value leaked into the inventory: {fake}");
        }
        let history = by_source(&collected, "ps_history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].at("lines"), &json!([2, 4]));
        assert_eq!(by_source(&collected, "setup_file").len(), 1);
        assert_eq!(by_source(&collected, "setup_file")[0].at("count"), &json!(2));
        assert_eq!(by_source(&collected, "group_policy").len(), 1);
        let files: Vec<String> = by_source(&collected, "user_file")
            .iter()
            .map(|e| file_name(&text(e.at("path"))))
            .collect();
        for expected in [
            "credentials",
            ".git-credentials",
            ".env",
            "passwords.txt",
            "vault.kdbx",
            "id_rsa",
        ] {
            assert!(files.contains(&expected.to_string()), "{expected} in {files:?}");
        }
        // Depth 2 under Documents: deep\a\b\c\.env is out of reach.
        assert_eq!(files.iter().filter(|f| *f == ".env").count(), 1, "{files:?}");
        assert_eq!(
            collected.at("stats").at("files_read"),
            &json!(8),
            "the database is never opened"
        );
        assert!(
            !list(collected.at("notes")).is_empty(),
            "not elevated: other accounts were not checked"
        );
    }

    #[test]
    fn the_report_the_html_and_the_ai_payload_never_hold_a_value() {
        let tree = Tree::new("leak");
        let collected = fake_computer(&tree);
        let raw = json!({
            "meta": {"is_admin": true, "user": "jdoe", "computer": "PC-VICTIM"},
            "system": {"defender": {"realtime": true, "antivirus": true}},
            "sysconfig": {SECTION: collected},
        });
        let mut analysis = crate::run_analysis(&raw, false);
        let secret_items: Vec<&Item> = analysis
            .items
            .iter()
            .filter(|i| i.facts.at("category") == "secrets")
            .collect();
        assert!(secret_items.len() >= 8, "{}", secret_items.len());
        let shared: Vec<&&Item> = secret_items
            .iter()
            .filter(|i| i.facts.at("exposure") == "shared")
            .collect();
        assert_eq!(shared.len(), 2, "unattend.xml and the Group Policy file");
        assert!(shared.iter().all(|i| i.score >= 60), "readable by every user: high");

        let json_report = crate::report::render_json(&analysis);
        let html = crate::report::render_html(&analysis);
        let sent = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let capture = std::sync::Arc::clone(&sent);
        let provider = crate::ai::Provider::custom(
            "test",
            "fake-model",
            "a test function",
            Box::new(move |system, user, _schema| {
                if let Ok(mut all) = capture.lock() {
                    all.push_str(system);
                    all.push_str(user);
                }
                Err(crate::ai::failed("no model in tests"))
            }),
        );
        let sent_file = tree.0.join("sent-to-ai.json");
        let _ = crate::ai::ai_analyze(&mut analysis, &provider, true, &|_| {}, Some(&sent_file));
        let to_ai = sent.lock().map(|s| s.clone()).unwrap_or_default();
        let saved = fs::read_to_string(&sent_file).unwrap_or_default();
        assert!(
            to_ai.contains("unattend.xml"),
            "the secret findings do reach the AI, without values"
        );
        for fake in fakes() {
            assert!(!json_report.contains(fake), "report JSON holds {fake}");
            assert!(!html.contains(fake), "report HTML holds {fake}");
            assert!(!to_ai.contains(fake), "AI payload holds {fake}");
            assert!(!saved.contains(fake), "sent-to-ai file holds {fake}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn links_are_never_followed() {
        let tree = Tree::new("links");
        let outside = Tree::new("links-target");
        outside.file(r"secret\.env", &format!("API_TOKEN={FAKE_SECRET}\n"));
        fs::create_dir_all(tree.0.join("Documents")).expect("folder");
        // A junction needs no special rights (a symbolic link does).
        let made = std::process::Command::new(
            std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
                .join(r"System32\cmd.exe"),
        )
        .args(["/c", "mklink", "/J"])
        .arg(tree.0.join(r"Documents\linked"))
        .arg(outside.0.join("secret"))
        .output()
        .is_ok_and(|o| o.status.success());
        if !made {
            return;
        }
        let places = Places {
            user_roots: vec![(tree.0.join("Documents"), 2)],
            ..Places::default()
        };
        let collected = collect_from(&places, true);
        assert!(list(collected.at("entries")).is_empty(), "{collected}");
        assert_eq!(collected.at("stats").at("skipped_links"), &json!(1));
    }

    #[test]
    fn many_files_of_one_kind_become_one_finding() {
        let key = |n: usize| {
            json!({"source": "user_file", "path": format!(r"C:\Users\jdoe\Documents\app{n}\server.key"),
                   "exposure": "user", "kinds": ["private_key"], "lines": [], "count": 1})
        };
        let mut entries: Vec<Value> = (0..7).map(key).collect();
        entries.push(json!({"source": "user_file", "path": r"C:\Users\jdoe\.aws\credentials",
                            "exposure": "user", "kinds": ["aws_credentials"], "lines": [3], "count": 1}));
        let raw = json!({"sysconfig": {SECTION: {"entries": entries}}});
        let found = items(&raw);
        assert_eq!(found.len(), 2, "seven keys in one finding, the AWS file on its own");
        let group = found
            .iter()
            .find(|i| i.facts.at("topic") == "secret_private_key")
            .expect("grouped keys");
        assert_eq!(group.facts.at("files"), &json!(7));
        assert_eq!(list(group.facts.at("paths")).len(), 7);
        assert!(group.score >= 30, "{}", group.score);
    }

    #[test]
    fn the_budget_stops_the_walk() {
        let mut budget = Budget {
            files: MAX_FILES,
            ..Budget::default()
        };
        assert!(!budget.can_read());
        assert!(budget.exhausted);
        let mut budget = Budget {
            entries: MAX_ENTRIES,
            ..Budget::default()
        };
        assert!(!budget.entry());
        assert!(budget.exhausted);
    }

    /// Counts by kind on this computer (never paths or values):
    /// `cargo test -p vigil-scan secrets::tests::live_counts -- --ignored --nocapture`
    #[test]
    #[ignore = "reads this computer"]
    fn live_counts() {
        let started = std::time::Instant::now();
        let collected = collect(crate::collect::is_admin());
        let mut by_kind: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        let mut by_source: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for e in list(collected.at("entries")) {
            *by_source.entry(str_of(e.at("source"))).or_default() += 1;
            for k in list(e.at("kinds")) {
                *by_kind.entry(str_of(k)).or_default() += 1;
            }
        }
        println!(
            "places {by_source:?} kinds {by_kind:?} stats {} in {:?}",
            collected.at("stats"),
            started.elapsed()
        );
    }
}
