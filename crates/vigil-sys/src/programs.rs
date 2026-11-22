//! The desktop programs installed on this computer, read live from the Uninstall keys (what
//! Settings > Installed apps lists for classic programs): the machine's keys (64- and 32-bit views),
//! this account's, and those of other accounts whose registry is loaded. Read-only.
//!
//! An entry is a **leftover** when its uninstaller is gone (the file it names no longer exists, or
//! Windows Installer no longer knows the product) and so are its files (no install folder, a missing
//! one, or an empty one): only the line in the list remains.

use std::path::Path;

use serde::Serialize;
use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FILETIME, HANDLE, HLOCAL, LocalFree, SYSTEMTIME};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::Win32::Security::{GetTokenInformation, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows::Win32::System::ApplicationInstallationAndServicing::{INSTALLSTATE_UNKNOWN, MsiQueryProductStateW};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_64KEY, REG_DWORD, REG_EXPAND_SZ,
    REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
};
use windows::Win32::System::SystemInformation::GetLocalTime;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
use windows::core::{PCWSTR, PWSTR};

use crate::startup::{executable_of, expand, is_host, version_strings};
use crate::util::{from_wide, wide};

/// Where the 64-bit programs of the machine (and of an account) are listed.
pub const UNINSTALL: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
/// Where 32-bit installers write on a 64-bit Windows.
pub const UNINSTALL_32: &str = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

/// One installed program.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Program {
    /// Stable identity: the full path of its Uninstall key (`HKLM\Software\...\Uninstall\<key>`).
    pub id: String,
    /// The Uninstall key's own name (often the MSI product code).
    pub key_name: String,
    pub name: String,
    pub publisher: String,
    pub version: String,
    /// The day it was installed, local, `YYYY-MM-DD` (empty when unknown).
    pub installed: String,
    /// The day comes from the key's last change, because the installer wrote no date.
    pub installed_estimated: bool,
    /// The size the installer declared, in bytes (0 when it declared none).
    pub size: u64,
    /// The install folder the installer declared (empty when it declared none).
    pub location: String,
    pub location_exists: bool,
    /// The install folder exists but holds nothing.
    pub location_empty: bool,
    /// The command Settings runs to uninstall it (UninstallString).
    pub uninstall: String,
    /// The silent variant, when the installer declared one.
    pub quiet_uninstall: String,
    /// The program the uninstall command starts.
    pub uninstaller: String,
    pub uninstaller_exists: bool,
    /// A Windows host (msiexec, rundll32...) runs the uninstall: its signature says nothing.
    pub uninstaller_host: bool,
    /// The file that gives the program its icon (`.exe` or `.ico`; empty when there is none).
    pub icon: String,
    /// The program's own executable, when the entry names one (its DisplayIcon).
    pub executable: String,
    /// Installed with Windows Installer.
    pub msi: bool,
    /// The MSI product code (`{...}`), when there is one.
    pub product_code: String,
    /// Windows Installer still knows the product (meaningful only for MSI entries).
    pub msi_known: bool,
    /// The installer asked Settings not to offer an uninstall.
    pub no_remove: bool,
    /// "machine", "machine32" or "user".
    pub scope: String,
    /// The account of a "user" entry that is not this account (SID and name); empty otherwise.
    pub sid: String,
    pub account: String,
    /// Only the entry is left: see the module documentation.
    pub leftover: bool,
}

// --------------------------------------------------------------------------- sources

/// The root of a registry path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    LocalMachine,
    CurrentUser,
    Users,
}

impl Root {
    fn handle(self) -> HKEY {
        match self {
            Root::LocalMachine => HKEY_LOCAL_MACHINE,
            Root::CurrentUser => HKEY_CURRENT_USER,
            Root::Users => HKEY_USERS,
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Root::LocalMachine => "HKLM",
            Root::CurrentUser => "HKCU",
            Root::Users => "HKU",
        }
    }

    fn parse(text: &str) -> Option<Root> {
        match text.to_ascii_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => Some(Root::LocalMachine),
            "HKCU" | "HKEY_CURRENT_USER" => Some(Root::CurrentUser),
            "HKU" | "HKEY_USERS" => Some(Root::Users),
            _ => None,
        }
    }
}

/// A key whose subkeys are installed programs.
#[derive(Debug, Clone)]
pub struct Source {
    pub root: Root,
    /// The key under `root` (for other accounts: `<SID>\Software\...\Uninstall`).
    pub key: String,
    /// "machine", "machine32" or "user".
    pub scope: &'static str,
    /// The account of another user's hive (SID); empty for the machine and this account.
    pub sid: String,
}

impl Source {
    /// `HKLM\Software\...\Uninstall`.
    pub fn path(&self) -> String {
        format!(r"{}\{}", self.root.short(), self.key)
    }
}

/// The Uninstall keys Settings reads, plus those of the other accounts whose registry is loaded
/// (signed in, or running a service or a task).
pub fn default_sources() -> Vec<Source> {
    let source = |root, key: &str, scope| Source {
        root,
        key: key.to_string(),
        scope,
        sid: String::new(),
    };
    let mut out = vec![
        source(Root::LocalMachine, UNINSTALL, "machine"),
        source(Root::LocalMachine, UNINSTALL_32, "machine32"),
        source(Root::CurrentUser, UNINSTALL, "user"),
        source(Root::CurrentUser, UNINSTALL_32, "user"),
    ];
    let own = current_sid().unwrap_or_default();
    for (sid, _) in subkeys(Root::Users, "") {
        let user_hive = sid.starts_with("S-1-5-21-") && !sid.ends_with("_Classes");
        if user_hive && !sid.eq_ignore_ascii_case(&own) {
            for key in [UNINSTALL, UNINSTALL_32] {
                out.push(Source {
                    root: Root::Users,
                    key: format!(r"{sid}\{key}"),
                    scope: "user",
                    sid: sid.clone(),
                });
            }
        }
    }
    out
}

/// Every installed program of this computer, read now, by name.
pub fn list() -> Vec<Program> {
    list_from(&default_sources())
}

/// The programs listed under the given keys (tests point them at a scratch key).
pub fn list_from(sources: &[Source]) -> Vec<Program> {
    let mut out = Vec::new();
    for source in sources {
        let account = if source.sid.is_empty() {
            String::new()
        } else {
            sid_name(&source.sid).unwrap_or_else(|| source.sid.clone())
        };
        for (name, written) in subkeys(source.root, &source.key) {
            if let Some(mut program) = read_program(source, &name, written) {
                program.account = account.clone();
                out.push(program);
            }
        }
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then(a.id.cmp(&b.id)));
    out
}

/// One program read again by its id, as listed now; `None` when the key is gone, is not directly
/// under one of the Uninstall keys, or is not a program Settings would list.
pub fn read_entry(id: &str) -> Option<Program> {
    read_entry_in(id, &default_sources())
}

/// [`read_entry`] against the given keys.
pub fn read_entry_in(id: &str, sources: &[Source]) -> Option<Program> {
    let (root, rest) = id.trim().split_once('\\')?;
    let root = Root::parse(root)?;
    let (parent, name) = rest.rsplit_once('\\')?;
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    let source = sources
        .iter()
        .find(|s| s.root == root && s.key.eq_ignore_ascii_case(parent))?;
    let written = key_written(root, &format!(r"{}\{name}", source.key));
    let mut program = read_program(source, name, written?)?;
    if !source.sid.is_empty() {
        program.account = sid_name(&source.sid).unwrap_or_else(|| source.sid.clone());
    }
    Some(program)
}

/// Installers that are updates of another program, not programs: Settings hides them too.
const UPDATE_KINDS: [&str; 6] = [
    "update",
    "hotfix",
    "security update",
    "update rollup",
    "service pack",
    "servicepack",
];

fn read_program(source: &Source, name: &str, written: i64) -> Option<Program> {
    let sub = format!(r"{}\{name}", source.key);
    let key = open(source.root, &sub)?;
    let text = |value: &str| query_text(&key, value);
    let display = text("DisplayName");
    if display.is_empty()
        || query_dword(&key, "SystemComponent") == Some(1)
        || !text("ParentKeyName").is_empty()
        || UPDATE_KINDS.contains(&text("ReleaseType").to_lowercase().as_str())
    {
        return None;
    }
    let uninstall = text("UninstallString");
    let product_code = product_code(name, &uninstall);
    let msi = query_dword(&key, "WindowsInstaller") == Some(1) || msi_command(&uninstall);
    let (installed, installed_estimated) = match parse_install_date(&text("InstallDate")) {
        Some(day) => (day, false),
        None => (local_day(written).unwrap_or_default(), true),
    };
    let location = clean_path(&text("InstallLocation"));
    let location_exists = !location.is_empty() && Path::new(&location).is_dir();
    let location_empty = location_exists
        && std::fs::read_dir(&location)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
    let uninstaller = uninstaller_of(&uninstall);
    let uninstaller_exists = !uninstaller.is_empty() && Path::new(&uninstaller).is_file();
    let uninstaller_host = !uninstaller.is_empty() && is_host(&uninstaller);
    let display_icon = icon_file(&text("DisplayIcon"));
    let executable = if display_icon.to_lowercase().ends_with(".exe") && !is_host(&display_icon) {
        display_icon.clone()
    } else {
        String::new()
    };
    let icon = if [".exe", ".ico"]
        .iter()
        .any(|ext| display_icon.to_lowercase().ends_with(ext))
    {
        display_icon
    } else if uninstaller_exists && !uninstaller_host && uninstaller.to_lowercase().ends_with(".exe") {
        uninstaller.clone()
    } else {
        String::new()
    };
    let mut publisher = text("Publisher");
    if publisher.is_empty() && !executable.is_empty() {
        publisher = version_strings(&executable).0;
    }
    let msi_known = msi && !product_code.is_empty() && msi_product_known(&product_code);
    let mut program = Program {
        id: format!(r"{}\{name}", source.path()),
        key_name: name.to_string(),
        name: display,
        publisher,
        version: text("DisplayVersion"),
        installed,
        installed_estimated,
        size: query_dword(&key, "EstimatedSize").map_or(0, |kb| u64::from(kb) * 1024),
        location,
        location_exists,
        location_empty,
        uninstall,
        quiet_uninstall: text("QuietUninstallString"),
        uninstaller,
        uninstaller_exists,
        uninstaller_host,
        icon,
        executable,
        msi,
        product_code,
        msi_known,
        no_remove: query_dword(&key, "NoRemove") == Some(1),
        scope: source.scope.to_string(),
        sid: source.sid.clone(),
        account: String::new(),
        leftover: false,
    };
    program.leftover = is_leftover(&program);
    Some(program)
}

/// See the module documentation. For an MSI entry the uninstaller is Windows Installer itself, so
/// "gone" means Windows Installer no longer knows the product; without a product code it cannot be
/// told, and the entry is not called a leftover.
pub fn is_leftover(program: &Program) -> bool {
    let uninstaller_gone = if program.msi {
        !program.product_code.is_empty() && !program.msi_known
    } else {
        !program.uninstall.is_empty() && Path::new(&program.uninstaller).is_absolute() && !program.uninstaller_exists
    };
    let files_gone = program.location.is_empty() || !program.location_exists || program.location_empty;
    uninstaller_gone && files_gone
}

/// A program Microsoft published (its own entries are never changed from Vigil).
pub fn is_microsoft(publisher: &str) -> bool {
    publisher.to_lowercase().contains("microsoft")
}

// --------------------------------------------------------------------------- values

/// `YYYYMMDD` (what installers write) or `YYYY-MM-DD` / `YYYY/MM/DD` as `YYYY-MM-DD`; `None` for
/// anything else or an impossible date.
pub fn parse_install_date(text: &str) -> Option<String> {
    let digits: String = text.trim().chars().filter(char::is_ascii_digit).collect();
    let separated = text.trim().len() == 10 && matches!(text.trim().as_bytes().get(4), Some(b'-' | b'/'));
    if digits.len() != 8 || !(text.trim().len() == 8 || separated) {
        return None;
    }
    let year: i64 = digits[..4].parse().ok()?;
    let month: i64 = digits[4..6].parse().ok()?;
    let day: i64 = digits[6..].parse().ok()?;
    let valid =
        (1980..=2200).contains(&year) && (1..=12).contains(&month) && (1..=days_in_month(year, month)).contains(&day);
    valid.then(|| format!("{year:04}-{month:02}-{day:02}"))
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn day_number(date: &str) -> Option<i64> {
    let mut parts = date.split('-').map(|p| p.parse::<i64>().ok());
    let (year, month, day) = (parts.next()??, parts.next()??, parts.next()??);
    Some(days_from_civil(year, month, day))
}

/// Whole days from `date` to `today` (both `YYYY-MM-DD`); negative when `date` is later.
pub fn days_between(date: &str, today: &str) -> Option<i64> {
    Some(day_number(today)? - day_number(date)?)
}

/// Today's local date, `YYYY-MM-DD`.
pub fn today() -> String {
    // SAFETY: returns a plain structure.
    let now = unsafe { GetLocalTime() };
    format!("{:04}-{:02}-{:02}", now.wYear, now.wMonth, now.wDay)
}

/// The local day of a FILETIME (100 ns since 1601, as a number).
fn local_day(filetime: i64) -> Option<String> {
    if filetime <= 0 {
        return None;
    }
    let time = FILETIME {
        dwLowDateTime: filetime as u32,
        dwHighDateTime: (filetime >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    // SAFETY: both calls only read and write the structures passed.
    unsafe {
        FileTimeToSystemTime(&time, &mut utc).ok()?;
        SystemTimeToTzSpecificLocalTime(None, &utc, &mut local).ok()?;
    }
    Some(format!("{:04}-{:02}-{:02}", local.wYear, local.wMonth, local.wDay))
}

/// A path as installers write it: quotes and surrounding blanks dropped, variables expanded.
fn clean_path(text: &str) -> String {
    let trimmed = text.trim().trim_matches('"').trim();
    if trimmed.is_empty() {
        return String::new();
    }
    expand(trimmed)
}

/// The file of a DisplayIcon value (`"C:\...\app.exe",0` or `C:\...\app.ico`): the index dropped.
/// Empty when that file does not exist.
pub fn icon_file(text: &str) -> String {
    let mut path = text.trim().to_string();
    if let Some((head, index)) = path.rsplit_once(',')
        && index.trim().trim_start_matches('-').chars().all(|c| c.is_ascii_digit())
        && !index.trim().is_empty()
    {
        path = head.to_string();
    }
    let path = clean_path(&path);
    if Path::new(&path).is_absolute() && Path::new(&path).is_file() {
        path
    } else {
        String::new()
    }
}

/// The program an uninstall command starts. Quoted paths are taken as they are; an unquoted one
/// ends at `.exe`, so a missing uninstaller in a folder with spaces is still named correctly.
pub fn uninstaller_of(command: &str) -> String {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if !trimmed.starts_with('"')
        && let Some(end) = trimmed.to_ascii_lowercase().find(".exe")
    {
        let candidate = expand(&trimmed[..end + 4]);
        if Path::new(&candidate).is_absolute() {
            return candidate;
        }
    }
    executable_of(trimmed)
}

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
fn is_guid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 38
        && bytes[0] == b'{'
        && bytes[37] == b'}'
        && bytes[1..37].iter().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

/// `msiexec /x{...}` or `msiexec /i{...}`.
fn msi_command(command: &str) -> bool {
    let low = command.trim().trim_start_matches('"').to_ascii_lowercase();
    let program = low.split(['"', ' ']).next().unwrap_or("");
    program.ends_with("msiexec.exe") || program.ends_with("msiexec")
}

/// The MSI product code: the key's name when it is one, else the one the uninstall command names.
pub fn product_code(key_name: &str, uninstall: &str) -> String {
    if is_guid(key_name) {
        return key_name.to_uppercase();
    }
    if msi_command(uninstall)
        && let Some(start) = uninstall.find('{')
        && let Some(candidate) = uninstall.get(start..start + 38)
        && is_guid(candidate)
    {
        return candidate.to_uppercase();
    }
    String::new()
}

/// Windows Installer still has the product (installed, advertised, or installed for another user).
pub fn msi_product_known(code: &str) -> bool {
    if !is_guid(code) {
        return false;
    }
    let text = wide(code);
    // SAFETY: `text` is NUL-terminated; the call only reads Windows Installer's own data.
    let state = unsafe { MsiQueryProductStateW(PCWSTR(text.as_ptr())) };
    state != INSTALLSTATE_UNKNOWN
}

// --------------------------------------------------------------------------- registry

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from RegOpenKeyExW and is closed once.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

fn open(root: Root, sub: &str) -> Option<Key> {
    let sub = wide(sub);
    let mut key = HKEY::default();
    // SAFETY: `sub` is NUL-terminated; `key` receives the handle, owned by `Key`.
    let status = unsafe {
        RegOpenKeyExW(
            root.handle(),
            PCWSTR(sub.as_ptr()),
            None,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    (status == ERROR_SUCCESS).then_some(Key(key))
}

/// The subkeys of a key with their last-write time (FILETIME as a number).
fn subkeys(root: Root, sub: &str) -> Vec<(String, i64)> {
    let Some(key) = open(root, sub) else { return Vec::new() };
    let mut out = Vec::new();
    let mut index = 0u32;
    loop {
        let mut name = vec![0u16; 512];
        let mut len = name.len() as u32;
        let mut written = FILETIME::default();
        // SAFETY: `name` is writable for `len` units; the other out pointers are valid.
        let status = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                Some(PWSTR(name.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                Some(&mut written),
            )
        };
        if status == ERROR_NO_MORE_ITEMS || index > 20_000 {
            break;
        }
        index += 1;
        if status != ERROR_SUCCESS {
            continue;
        }
        name.truncate(len as usize);
        let stamp = (i64::from(written.dwHighDateTime) << 32) | i64::from(written.dwLowDateTime);
        out.push((String::from_utf16_lossy(&name), stamp));
    }
    out
}

/// When a key was last written (FILETIME as a number), `None` when it does not exist.
fn key_written(root: Root, sub: &str) -> Option<i64> {
    let (parent, name) = sub.rsplit_once('\\')?;
    subkeys(root, parent)
        .into_iter()
        .find(|(found, _)| found.eq_ignore_ascii_case(name))
        .map(|(_, written)| written)
}

/// A value's type and bytes.
fn query(key: &Key, name: &str) -> Option<(REG_VALUE_TYPE, Vec<u8>)> {
    let name = wide(name);
    let mut size = 0u32;
    let mut kind = REG_VALUE_TYPE::default();
    // SAFETY: asks for the size only.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS || size > 64 * 1024 {
        return None;
    }
    let mut data = vec![0u8; size as usize + 2];
    let mut length = data.len() as u32;
    // SAFETY: `data` is writable for `length` bytes.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            Some(data.as_mut_ptr()),
            Some(&mut length),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    data.truncate(length as usize);
    Some((kind, data))
}

/// A text value, trimmed (an expandable one is expanded); "" when missing or not text.
fn query_text(key: &Key, name: &str) -> String {
    let Some((kind, data)) = query(key, name) else {
        return String::new();
    };
    if kind != REG_SZ && kind != REG_EXPAND_SZ {
        return String::new();
    }
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let text = from_wide(&units).trim().to_string();
    if kind == REG_EXPAND_SZ { expand(&text) } else { text }
}

/// A DWORD value (also when an installer wrote it as text).
fn query_dword(key: &Key, name: &str) -> Option<u32> {
    let (kind, data) = query(key, name)?;
    if kind == REG_DWORD && data.len() >= 4 {
        return Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]));
    }
    if kind == REG_SZ {
        let units: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        return from_wide(&units).trim().parse().ok();
    }
    None
}

// --------------------------------------------------------------------------- accounts

/// The SID of the account this program runs as (`S-1-5-21-...`).
fn current_sid() -> Option<String> {
    let mut token = HANDLE::default();
    // SAFETY: the current process pseudo-handle; `token` receives a handle closed below.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.ok()?;
    let mut buffer = vec![0u64; 64];
    let mut needed = 0u32;
    // SAFETY: the buffer is writable for its byte length and 8-byte aligned.
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            (buffer.len() * 8) as u32,
            &mut needed,
        )
    };
    // SAFETY: the token handle is closed once.
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(token);
    }
    result.ok()?;
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points inside it.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut text = PWSTR::null();
    // SAFETY: `sid` is valid while `buffer` lives; `text` receives a LocalAlloc'd string freed below.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }.ok()?;
    // SAFETY: on success `text` is a valid NUL-terminated string.
    let value = unsafe { text.to_string() }.ok();
    // SAFETY: `text` was allocated by ConvertSidToStringSidW and is freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
    }
    value
}

/// "DOMAIN\name" of a SID string.
fn sid_name(text: &str) -> Option<String> {
    let text = wide(text);
    let mut sid = PSID::default();
    // SAFETY: `text` is NUL-terminated; `sid` receives a LocalAlloc'd SID freed below.
    unsafe { ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &mut sid) }.ok()?;
    let name = crate::process::lookup_account(sid);
    // SAFETY: the SID was allocated by ConvertStringSidToSidW and is freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid.0)));
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use windows::Win32::System::Registry::{
        KEY_WRITE, REG_OPTION_NON_VOLATILE, RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegSetValueExW,
    };

    /// A temporary folder, deleted when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("vigil-programs-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).ok();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A scratch key under `HKCU\Software\VigilTests`, deleted when dropped.
    struct Scratch(String);

    impl Scratch {
        fn new(name: &str) -> Self {
            Scratch(format!(r"Software\VigilTests\programs-{name}-{}", std::process::id()))
        }

        fn source(&self) -> Source {
            Source {
                root: Root::CurrentUser,
                key: self.0.clone(),
                scope: "user",
                sid: String::new(),
            }
        }

        fn set(&self, entry: &str, value: &str, kind: REG_VALUE_TYPE, data: &[u8]) {
            let path = wide(&format!(r"{}\{entry}", self.0));
            let mut key = HKEY::default();
            // SAFETY: the path is NUL-terminated; the key is closed by `Key`.
            let status = unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(path.as_ptr()),
                    None,
                    None,
                    REG_OPTION_NON_VOLATILE,
                    KEY_WRITE,
                    None,
                    &mut key,
                    None,
                )
            };
            assert_eq!(status, ERROR_SUCCESS, "create the scratch key");
            let key = Key(key);
            let name = wide(value);
            // SAFETY: `name` is NUL-terminated and `data` is the value's bytes.
            let status = unsafe { RegSetValueExW(key.0, PCWSTR(name.as_ptr()), None, kind, Some(data)) };
            assert_eq!(status, ERROR_SUCCESS, "write the scratch value");
        }

        fn text(&self, entry: &str, value: &str, text: &str) {
            let data: Vec<u8> = text
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect();
            self.set(entry, value, REG_SZ, &data);
        }

        fn dword(&self, entry: &str, value: &str, number: u32) {
            self.set(entry, value, REG_DWORD, &number.to_le_bytes());
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let path = wide(&self.0);
            // SAFETY: deletes only the test's own scratch key, then the shared parent if no other
            // test still uses it (RegDeleteKeyW refuses a key that has subkeys).
            unsafe {
                let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
                let _ = RegDeleteKeyW(HKEY_CURRENT_USER, windows::core::w!(r"Software\VigilTests"));
            }
        }
    }

    #[test]
    fn install_dates_are_read_and_checked() {
        assert_eq!(parse_install_date("20260215").as_deref(), Some("2026-02-15"));
        assert_eq!(parse_install_date(" 2024-02-29 ").as_deref(), Some("2024-02-29"));
        assert_eq!(parse_install_date("2025/12/01").as_deref(), Some("2025-12-01"));
        assert_eq!(parse_install_date("20250229"), None, "not a leap year");
        assert_eq!(parse_install_date("20261301"), None);
        assert_eq!(parse_install_date("2/15/2026"), None, "ambiguous order");
        assert_eq!(parse_install_date(""), None);
        assert_eq!(parse_install_date("202602150"), None);
        assert_eq!(days_between("2026-02-15", "2026-02-22"), Some(7));
        assert_eq!(days_between("2024-12-31", "2025-01-01"), Some(1));
        assert_eq!(days_between("2024-02-28", "2024-03-01"), Some(2));
        assert_eq!(days_between("2026-03-01", "2026-02-27"), Some(-2));
        assert_eq!(days_between("never", "2026-02-27"), None);
        assert_eq!(today().len(), 10);
    }

    #[test]
    fn uninstallers_icons_and_product_codes_are_found() {
        let dir = TempDir::new("paths");
        let folder = dir.0.join("Contoso Sync");
        std::fs::create_dir_all(&folder).ok();
        let exe = folder.join("sync.exe");
        std::fs::write(&exe, b"MZ").ok();
        let exe_text = exe.display().to_string();
        assert_eq!(uninstaller_of(&format!("\"{exe_text}\" /uninstall")), exe_text);
        let missing = folder.join("Uninstall Me.exe").display().to_string();
        assert_eq!(
            uninstaller_of(&format!("{missing} /S")),
            missing,
            "an unquoted missing path ends at .exe"
        );
        assert!(
            uninstaller_of("MsiExec.exe /X{11111111-2222-3333-4444-555555555555}")
                .to_lowercase()
                .ends_with(r"system32\msiexec.exe")
        );
        assert_eq!(uninstaller_of("  "), "");

        assert_eq!(icon_file(&format!("\"{exe_text}\",0")), exe_text);
        assert_eq!(icon_file(&format!("{exe_text},-101")), exe_text);
        assert_eq!(icon_file(&exe_text), exe_text);
        assert_eq!(icon_file(r"C:\nowhere\app.exe,0"), "");

        let code = "{11111111-2222-3333-4444-55555555AAAA}";
        assert_eq!(product_code(code, ""), code);
        assert_eq!(product_code("ContosoSync", &format!("MsiExec.exe /X{code}")), code);
        assert_eq!(
            product_code("ContosoSync", &format!("\"{exe_text}\" {code}")),
            "",
            "not an MSI command"
        );
        assert!(!is_guid("{1111-2222}"));
        assert!(
            !msi_product_known("{00000000-0000-0000-0000-00000000F00D}"),
            "Windows Installer does not know it"
        );
        assert!(!msi_product_known("not a guid"));
        assert!(is_microsoft("Microsoft Corporation") && !is_microsoft("Contoso Ltd."));
    }

    #[test]
    fn programs_are_read_from_the_uninstall_keys() {
        let scratch = Scratch::new("list");
        let dir = TempDir::new("list");
        let app = dir.0.join("Contoso");
        std::fs::create_dir_all(&app).ok();
        let exe = app.join("contoso.exe");
        std::fs::write(&exe, b"MZ").ok();
        let uninst = app.join("uninst.exe");
        std::fs::write(&uninst, b"MZ").ok();
        let empty = dir.0.join("Empty");
        std::fs::create_dir_all(&empty).ok();

        // A healthy program.
        scratch.text("Contoso", "DisplayName", "Contoso Notes");
        scratch.text("Contoso", "Publisher", "Contoso Ltd.");
        scratch.text("Contoso", "DisplayVersion", "4.2.1");
        scratch.text("Contoso", "InstallDate", "20260110");
        scratch.dword("Contoso", "EstimatedSize", 2048);
        scratch.text("Contoso", "InstallLocation", &format!("\"{}\"", app.display()));
        scratch.text(
            "Contoso",
            "UninstallString",
            &format!("\"{}\" /remove", uninst.display()),
        );
        scratch.text("Contoso", "DisplayIcon", &format!("{},0", exe.display()));
        // Its uninstaller and files are gone: a leftover.
        scratch.text("Gone", "DisplayName", "Fabrikam Viewer");
        scratch.text(
            "Gone",
            "UninstallString",
            &format!("{} /S", dir.0.join("Fabrikam").join("unins000.exe").display()),
        );
        scratch.text("Gone", "InstallLocation", &empty.display().to_string());
        // The uninstaller is gone but the files are still there: not a leftover.
        scratch.text("Half", "DisplayName", "Woodgrove Tools");
        scratch.text(
            "Half",
            "UninstallString",
            &dir.0.join("missing.exe").display().to_string(),
        );
        scratch.text("Half", "InstallLocation", &app.display().to_string());
        // An MSI product Windows Installer does not know, with no install folder: a leftover.
        let code = "{00000000-0000-0000-0000-00000000F00D}";
        scratch.text(code, "DisplayName", "Northwind Agent");
        scratch.dword(code, "WindowsInstaller", 1);
        scratch.text(code, "UninstallString", &format!("MsiExec.exe /X{code}"));
        scratch.dword(code, "NoRemove", 1);
        // Hidden from Settings: components, updates and nameless keys.
        scratch.text("Component", "DisplayName", "Contoso Runtime");
        scratch.dword("Component", "SystemComponent", 1);
        scratch.text("KB500001", "DisplayName", "Update for Contoso Notes");
        scratch.text("KB500001", "ParentKeyName", "Contoso");
        scratch.text("Patch", "DisplayName", "Contoso Notes hotfix");
        scratch.text("Patch", "ReleaseType", "Hotfix");
        scratch.text("Nameless", "UninstallString", "x.exe");

        let source = scratch.source();
        let programs = list_from(std::slice::from_ref(&source));
        let names: Vec<&str> = programs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["Contoso Notes", "Fabrikam Viewer", "Northwind Agent", "Woodgrove Tools"]
        );

        let notes = &programs[0];
        assert_eq!(notes.id, format!(r"HKCU\{}\Contoso", scratch.0));
        assert_eq!(notes.key_name, "Contoso");
        assert_eq!(
            (notes.version.as_str(), notes.installed.as_str()),
            ("4.2.1", "2026-01-10")
        );
        assert!(!notes.installed_estimated);
        assert_eq!(notes.size, 2048 * 1024);
        assert_eq!(notes.location, app.display().to_string(), "quotes are dropped");
        assert!(notes.location_exists && !notes.location_empty);
        assert_eq!(notes.uninstaller, uninst.display().to_string());
        assert!(notes.uninstaller_exists && !notes.uninstaller_host);
        assert_eq!(notes.executable, exe.display().to_string());
        assert_eq!(notes.icon, exe.display().to_string());
        assert!(!notes.msi && !notes.leftover && notes.scope == "user" && notes.sid.is_empty());

        let gone = &programs[1];
        assert!(gone.leftover, "{gone:#?}");
        assert!(gone.location_exists && gone.location_empty);
        assert!(
            gone.uninstaller.ends_with(r"Fabrikam\unins000.exe"),
            "{}",
            gone.uninstaller
        );
        assert!(
            gone.installed_estimated && gone.installed.len() == 10,
            "the key's date stands in"
        );

        let agent = &programs[2];
        assert!(agent.msi && agent.no_remove && !agent.msi_known);
        assert_eq!(agent.product_code, code);
        assert!(agent.uninstaller_host, "msiexec runs it");
        assert!(agent.leftover, "Windows Installer no longer knows it");

        assert!(!programs[3].leftover, "its files are still there");

        // Read again by id, through the same keys only.
        let again = read_entry_in(&notes.id, std::slice::from_ref(&source)).expect("by id");
        assert_eq!(&again, notes);
        assert_eq!(
            read_entry_in(&notes.id.to_uppercase(), std::slice::from_ref(&source)).map(|p| p.name),
            Some("Contoso Notes".to_string()),
            "ids compare without case"
        );
        assert!(read_entry_in(&format!(r"HKCU\{}\Component", scratch.0), std::slice::from_ref(&source)).is_none());
        assert!(read_entry_in(&format!(r"HKCU\{}\Missing", scratch.0), std::slice::from_ref(&source)).is_none());
        assert!(
            read_entry_in(
                &format!(r"HKCU\{}\Contoso\..", scratch.0),
                std::slice::from_ref(&source)
            )
            .is_none()
        );
        assert!(read_entry_in(&format!(r"HKLM\{}\Contoso", scratch.0), std::slice::from_ref(&source)).is_none());
        assert!(read_entry_in(r"HKCU\Software\Other\Contoso", std::slice::from_ref(&source)).is_none());
        assert!(read_entry_in("Contoso", std::slice::from_ref(&source)).is_none());
    }

    #[test]
    fn the_real_list_reads() {
        // Read-only: whatever is installed, the list comes back sorted and every id reads again.
        let programs = list();
        for pair in programs.windows(2) {
            assert!(pair[0].name.to_lowercase() <= pair[1].name.to_lowercase());
        }
        if let Some(first) = programs.iter().find(|p| p.sid.is_empty()) {
            assert_eq!(read_entry(&first.id).map(|p| p.id), Some(first.id.clone()));
        }
    }
}
