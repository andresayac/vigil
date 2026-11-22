//! The programs Windows starts when the user signs in, read live (what Task Manager calls
//! "Startup apps"): the Run and RunOnce keys of the user and of the machine (64- and 32-bit views),
//! the Run keys set by policy (`Policies\Explorer\Run`, which have no on/off switch), the user's
//! and the common Startup folders, and whether each one is turned on or off in the StartupApproved
//! keys — the same switch Task Manager flips. Read-only.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, PoisonError};

use serde::Serialize;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile,
    STGM_READ,
};
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
    RegCloseKey, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW,
};
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
use windows::core::{Interface, PCWSTR, PWSTR};

use crate::util::{filetime_to_unix_ms, from_wide, wide};

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_ONCE: &str = r"Software\Microsoft\Windows\CurrentVersion\RunOnce";
const RUN_32: &str = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
const RUN_ONCE_32: &str = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce";
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
/// Run keys set by policy: Windows runs them at sign-in; Task Manager has no switch for them.
const POLICY_RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";

/// One program Windows starts at sign-in.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StartupEntry {
    /// Stable identity: `reg:<key>\<value>` or `file:<path>`.
    pub id: String,
    /// The registry value name, or the file name without its extension.
    pub name: String,
    /// What Windows runs: the registry data, or the shortcut's target and arguments.
    pub command: String,
    /// The program the command starts (empty when it cannot be told).
    pub executable: String,
    /// The registry key (`HKCU\...\Run`) or the Startup folder.
    pub location: String,
    /// "run", "run_once", "policy" (a Run key set by policy: no on/off switch) or "folder".
    pub kind: String,
    /// "user" (this account) or "machine" (every user).
    pub scope: String,
    /// On at sign-in (Task Manager's "Enabled").
    pub enabled: bool,
    /// When it was turned off, if Windows recorded it (ms since 1970).
    pub disabled_at_ms: Option<i64>,
    /// It has an on/off switch (RunOnce entries do not: Windows deletes them after one run;
    /// policy Run entries do not either).
    pub can_toggle: bool,
    /// The registry key holding the switch, `HKCU\...\StartupApproved\Run`; empty without one.
    pub approved_key: String,
    /// The value name in the Run key, or the file name in the Startup folder.
    pub value: String,
    /// The file in the Startup folder (folder entries only).
    pub file: String,
    /// The program's publisher (CompanyName of its version resource).
    pub publisher: String,
    /// The program's friendly name (FileDescription).
    pub description: String,
    /// The program's file exists.
    pub exists: bool,
    /// The program is a Windows host (rundll32, wscript, powershell...) that runs a DLL or script
    /// named in the command: its publisher and signature say nothing about what really runs.
    pub host: bool,
    /// Vigil's own sign-in entry (Settings > Start Vigil in the tray when I sign in).
    pub own: bool,
}

/// The value name of Vigil's own entry in the user's Run key.
pub const OWN_VALUE: &str = "Vigil";

/// The command Vigil writes for itself: start hidden in the tray, without asking for elevation.
pub fn own_command(exe: &Path) -> String {
    format!("\"{}\" --tray --no-elevate", exe.display())
}

/// Vigil's own sign-in entry: the user's Run value `Vigil` holding exactly the command this very
/// program writes. Anything else under that name (another path, other arguments) is not trusted.
pub fn is_own(entry: &StartupEntry) -> bool {
    entry.kind == "run"
        && entry.scope == "user"
        && entry.value.eq_ignore_ascii_case(OWN_VALUE)
        && std::env::current_exe().is_ok_and(|exe| entry.command.trim().eq_ignore_ascii_case(&own_command(&exe)))
}

/// Windows programs that run whatever DLL or script their command line names.
const HOSTS: [&str; 12] = [
    "rundll32.exe",
    "regsvr32.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "conhost.exe",
    "explorer.exe",
    "msiexec.exe",
    "forfiles.exe",
];

/// Whether a program is one of the Windows hosts above.
pub fn is_host(executable: &str) -> bool {
    let name = executable.rsplit(['\\', '/']).next().unwrap_or("").to_ascii_lowercase();
    HOSTS.contains(&name.as_str())
}

/// Where Windows keeps a hive's keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    CurrentUser,
    LocalMachine,
}

impl Hive {
    fn handle(self) -> HKEY {
        match self {
            Hive::CurrentUser => HKEY_CURRENT_USER,
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Hive::CurrentUser => "HKCU",
            Hive::LocalMachine => "HKLM",
        }
    }

    fn scope(self) -> &'static str {
        match self {
            Hive::CurrentUser => "user",
            Hive::LocalMachine => "machine",
        }
    }
}

/// A registry key whose values Windows runs at sign-in.
#[derive(Debug, Clone)]
pub struct RegistrySource {
    pub hive: Hive,
    pub key: String,
    /// The StartupApproved key (same hive) with the on/off switch; `None` for RunOnce.
    pub approved: Option<String>,
    pub kind: &'static str,
}

/// A folder whose files Windows opens at sign-in.
#[derive(Debug, Clone)]
pub struct FolderSource {
    pub folder: PathBuf,
    /// The StartupApproved key with the switch of each file.
    pub approved_hive: Hive,
    pub approved: String,
}

/// The places Windows reads at sign-in, as Task Manager lists them.
pub fn default_sources() -> (Vec<RegistrySource>, Vec<FolderSource>) {
    let run = |hive, key: &str, leaf: Option<&str>, kind| RegistrySource {
        hive,
        key: key.to_string(),
        approved: leaf.map(|leaf| format!(r"{APPROVED}\{leaf}")),
        kind,
    };
    let registry = vec![
        run(Hive::CurrentUser, RUN, Some("Run"), "run"),
        run(Hive::CurrentUser, RUN_ONCE, None, "run_once"),
        run(Hive::LocalMachine, RUN, Some("Run"), "run"),
        run(Hive::LocalMachine, RUN_32, Some("Run32"), "run"),
        run(Hive::LocalMachine, RUN_ONCE, None, "run_once"),
        run(Hive::LocalMachine, RUN_ONCE_32, None, "run_once"),
        run(Hive::CurrentUser, POLICY_RUN, None, "policy"),
        run(Hive::LocalMachine, POLICY_RUN, None, "policy"),
    ];
    let mut folders = Vec::new();
    let startup = |base: &str, leaf: &str| {
        std::env::var_os(base).filter(|v| !v.is_empty()).map(|v| {
            PathBuf::from(v)
                .join(r"Microsoft\Windows\Start Menu\Programs")
                .join(leaf)
        })
    };
    if let Some(folder) = startup("APPDATA", "Startup") {
        folders.push(FolderSource {
            folder,
            approved_hive: Hive::CurrentUser,
            approved: format!(r"{APPROVED}\StartupFolder"),
        });
    }
    if let Some(folder) = startup("ProgramData", "StartUp") {
        folders.push(FolderSource {
            folder,
            approved_hive: Hive::LocalMachine,
            approved: format!(r"{APPROVED}\StartupFolder"),
        });
    }
    (registry, folders)
}

/// Every startup entry of this computer, read now.
pub fn list() -> Vec<StartupEntry> {
    let (registry, folders) = default_sources();
    list_from(&registry, &folders)
}

/// Every startup entry, and whether every place could be read (`false`: a key or folder that
/// exists could not be read, so missing entries may only be unreadable).
///
/// `light` leaves out what the background watch does not compare: the program's publisher and
/// description (version resources) and whether its file exists.
pub fn list_checked(light: bool) -> (Vec<StartupEntry>, bool) {
    let (registry, folders) = default_sources();
    read_from(&registry, &folders, light)
}

/// The entries of the given places (tests point them at a scratch key and a temporary folder).
pub fn list_from(registry: &[RegistrySource], folders: &[FolderSource]) -> Vec<StartupEntry> {
    read_from(registry, folders, false).0
}

/// The entries of the given places, and whether every place could be read.
pub fn read_from(registry: &[RegistrySource], folders: &[FolderSource], light: bool) -> (Vec<StartupEntry>, bool) {
    let mut out = Vec::new();
    let mut complete = true;
    let finish = |entry: StartupEntry| if light { finish_light(entry) } else { finish(entry) };
    for source in registry {
        let approved = match &source.approved {
            Some(key) => match approved_values(source.hive, key) {
                Some(values) => values,
                None => {
                    complete = false;
                    HashMap::new()
                }
            },
            None => HashMap::new(),
        };
        let Some(values) = read_values(source.hive, &source.key) else {
            complete = false;
            continue;
        };
        for (name, kind, data) in values {
            if name.is_empty() || (kind != REG_SZ && kind != REG_EXPAND_SZ) {
                continue;
            }
            let command = wide_text(&data);
            let (enabled, disabled_at_ms) = switch_state(approved.get(&name.to_lowercase()).map(Vec::as_slice));
            let location = format!(r"{}\{}", source.hive.short(), source.key);
            out.push(finish(StartupEntry {
                id: format!(r"reg:{location}\{name}"),
                name: name.clone(),
                executable: if light { String::new() } else { executable_of(&command) },
                command,
                location,
                kind: source.kind.to_string(),
                scope: source.hive.scope().to_string(),
                enabled: source.approved.is_none() || enabled,
                disabled_at_ms: if source.approved.is_some() {
                    disabled_at_ms
                } else {
                    None
                },
                can_toggle: source.approved.is_some(),
                approved_key: source
                    .approved
                    .as_ref()
                    .map(|key| format!(r"{}\{key}", source.hive.short()))
                    .unwrap_or_default(),
                value: name,
                ..StartupEntry::default()
            }));
        }
    }
    for source in folders {
        let approved = approved_values(source.approved_hive, &source.approved).unwrap_or_else(|| {
            complete = false;
            HashMap::new()
        });
        let files = match std::fs::read_dir(&source.folder) {
            Ok(files) => files,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    complete = false;
                }
                continue;
            }
        };
        let mut files: Vec<PathBuf> = files
            .filter_map(|f| match f {
                Ok(f) => Some(f),
                Err(_) => {
                    complete = false;
                    None
                }
            })
            .filter(|f| f.file_type().is_ok_and(|t| t.is_file()))
            .map(|f| f.path())
            .collect();
        files.sort();
        for path in files {
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            if file_name.is_empty() || file_name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let (command, executable) = folder_command(&path);
            let (enabled, disabled_at_ms) = switch_state(approved.get(&file_name.to_lowercase()).map(Vec::as_slice));
            out.push(finish(StartupEntry {
                id: format!("file:{}", path.display()),
                name: path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&file_name)
                    .to_string(),
                command,
                executable,
                location: source.folder.display().to_string(),
                kind: "folder".into(),
                scope: source.approved_hive.scope().to_string(),
                enabled,
                disabled_at_ms,
                can_toggle: true,
                approved_key: format!(r"{}\{}", source.approved_hive.short(), source.approved),
                value: file_name,
                file: path.display().to_string(),
                ..StartupEntry::default()
            }));
        }
    }
    (out, complete)
}

impl Default for StartupEntry {
    fn default() -> Self {
        StartupEntry {
            id: String::new(),
            name: String::new(),
            command: String::new(),
            executable: String::new(),
            location: String::new(),
            kind: String::new(),
            scope: String::new(),
            enabled: true,
            disabled_at_ms: None,
            can_toggle: false,
            approved_key: String::new(),
            value: String::new(),
            file: String::new(),
            publisher: String::new(),
            description: String::new(),
            exists: false,
            host: false,
            own: false,
        }
    }
}

/// Only what needs no file access: whether it is Vigil's own entry.
fn finish_light(mut entry: StartupEntry) -> StartupEntry {
    entry.own = is_own(&entry);
    entry
}

/// Fills what is known about the program file.
fn finish(mut entry: StartupEntry) -> StartupEntry {
    entry.own = is_own(&entry);
    if !entry.executable.is_empty() {
        entry.exists = Path::new(&entry.executable).is_file();
        entry.host = is_host(&entry.executable);
        // A host's name and publisher would describe the host, not what it runs.
        if entry.exists && !entry.host {
            let (company, description) = version_strings(&entry.executable);
            entry.publisher = company;
            entry.description = description;
        }
    }
    entry
}

// --------------------------------------------------------------------------- the switch

/// Task Manager's switch: the first byte is even when the entry is on (2, 6) and odd when it is
/// off (3, 7); an off entry carries the FILETIME it was turned off at bytes 4..12. No value (or an
/// empty one) means on.
pub fn switch_state(data: Option<&[u8]>) -> (bool, Option<i64>) {
    let Some(data) = data.filter(|d| !d.is_empty()) else {
        return (true, None);
    };
    if data[0] % 2 == 0 {
        return (true, None);
    }
    let when = data
        .get(4..12)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(i64::from_le_bytes)
        .map(filetime_to_unix_ms)
        .filter(|ms| *ms > 0);
    (false, when)
}

// --------------------------------------------------------------------------- command lines

/// Environment variables in a command (`%ProgramFiles%`) expanded.
pub(crate) fn expand(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let source = wide(text);
    let mut buffer = vec![0u16; 4096];
    // SAFETY: `source` is NUL-terminated; `buffer` is writable for its length.
    let written = unsafe { ExpandEnvironmentStringsW(PCWSTR(source.as_ptr()), Some(&mut buffer)) };
    if written == 0 || written as usize > buffer.len() {
        return text.to_string();
    }
    from_wide(&buffer)
}

/// The program a command line starts: the quoted path, or the longest leading run of words that
/// names an existing file (unquoted paths with spaces), or the first word; a bare name is looked up
/// in System32. Empty for an empty command.
pub fn executable_of(command: &str) -> String {
    let command = expand(command.trim());
    if command.is_empty() {
        return String::new();
    }
    let program = if let Some(rest) = command.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").to_string()
    } else {
        let words: Vec<&str> = command.split_whitespace().collect();
        let mut found = None;
        for end in (1..=words.len()).rev() {
            let candidate = words[..end].join(" ");
            for name in [candidate.clone(), format!("{candidate}.exe")] {
                if Path::new(&name).is_absolute() && Path::new(&name).is_file() {
                    found = Some(name);
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        found.unwrap_or_else(|| words.first().map(|w| w.to_string()).unwrap_or_default())
    };
    if program.contains('\\') || program.contains('/') || program.is_empty() {
        return program;
    }
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    for name in [program.clone(), format!("{program}.exe")] {
        let candidate = root.join("System32").join(&name);
        if candidate.is_file() {
            return candidate.display().to_string();
        }
    }
    program
}

/// The command and the program of a file in a Startup folder (shortcuts are resolved).
fn folder_command(path: &Path) -> (String, String) {
    let is_link = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("lnk"));
    if is_link && let Some((target, arguments)) = shortcut_target(path) {
        let quoted = if target.contains(' ') {
            format!("\"{target}\"")
        } else {
            target.clone()
        };
        let command = if arguments.is_empty() {
            quoted
        } else {
            format!("{quoted} {arguments}")
        };
        return (command, expand(&target));
    }
    let file = path.display().to_string();
    (file.clone(), file)
}

/// The target and arguments of a shortcut (`.lnk`), read without running anything.
pub fn shortcut_target(path: &Path) -> Option<(String, String)> {
    // SAFETY: plain COM initialisation for this thread; balanced below when it succeeded.
    let initialized = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_ok();
    let result = read_shortcut(path);
    if initialized {
        // SAFETY: balances the successful CoInitializeEx above on the same thread.
        unsafe { CoUninitialize() };
    }
    result
}

fn read_shortcut(path: &Path) -> Option<(String, String)> {
    // SAFETY: creates the in-process Shell Link object; the interfaces are released when dropped.
    let link: IShellLinkW = unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }.ok()?;
    let file: IPersistFile = link.cast().ok()?;
    let name = wide(&path.display().to_string());
    // SAFETY: `name` is NUL-terminated; the shortcut is only read.
    unsafe { file.Load(PCWSTR(name.as_ptr()), STGM_READ) }.ok()?;
    let mut target = vec![0u16; 1024];
    // SAFETY: `target` is writable for its length; no WIN32_FIND_DATA is requested.
    unsafe { link.GetPath(&mut target, std::ptr::null_mut(), 0) }.ok()?;
    let mut arguments = vec![0u16; 4096];
    // SAFETY: `arguments` is writable for its length.
    let _ = unsafe { link.GetArguments(&mut arguments) };
    let target = from_wide(&target);
    if target.is_empty() {
        return None;
    }
    Some((target, from_wide(&arguments).trim().to_string()))
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

/// The key; `Ok(None)` when it does not exist, `Err` when it exists but cannot be opened.
fn open(hive: Hive, sub: &str) -> Result<Option<Key>, ()> {
    let sub = wide(sub);
    let mut key = HKEY::default();
    // SAFETY: `sub` is NUL-terminated; `key` receives the handle, owned by `Key`.
    let status = unsafe {
        RegOpenKeyExW(
            hive.handle(),
            PCWSTR(sub.as_ptr()),
            None,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    match status {
        ERROR_SUCCESS => Ok(Some(Key(key))),
        ERROR_FILE_NOT_FOUND => Ok(None),
        _ => Err(()),
    }
}

/// The longest name and data of a key's values, as Windows reports them.
fn value_sizes(key: &Key) -> Option<(u32, u32)> {
    let mut max_name = 0u32;
    let mut max_data = 0u32;
    // SAFETY: only the two out values are requested.
    let status = unsafe {
        RegQueryInfoKeyW(
            key.0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&mut max_name),
            Some(&mut max_data),
            None,
            None,
        )
    };
    (status == ERROR_SUCCESS).then_some((max_name, max_data))
}

/// Every value of a key: (name, type, raw data). Empty when the key does not exist; `None` when it
/// exists but cannot be read completely (a value that grows while it is read is read again with a
/// bigger buffer, not skipped).
fn read_values(hive: Hive, sub: &str) -> Option<Vec<(String, REG_VALUE_TYPE, Vec<u8>)>> {
    let Some(key) = open(hive, sub).ok()? else {
        return Some(Vec::new());
    };
    let (mut max_name, mut max_data) = value_sizes(&key)?;
    let mut out = Vec::new();
    let mut index = 0u32;
    let mut retries = 0u32;
    loop {
        let mut name = vec![0u16; max_name as usize + 2];
        let mut name_len = name.len() as u32;
        let mut data = vec![0u8; max_data as usize + 2];
        let mut data_len = data.len() as u32;
        let mut kind = 0u32;
        // SAFETY: the buffers are writable for the lengths passed; the lengths are updated in place.
        let status = unsafe {
            RegEnumValueW(
                key.0,
                index,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut kind),
                Some(data.as_mut_ptr()),
                Some(&mut data_len),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status == ERROR_MORE_DATA && retries < 8 {
            // The value grew since the sizes were read: read them again and retry this index.
            retries += 1;
            let (name_now, data_now) = value_sizes(&key)?;
            max_name = name_now.max(max_name.saturating_mul(2));
            max_data = data_now.max(data_len).max(max_data.saturating_mul(2));
            continue;
        }
        if status != ERROR_SUCCESS {
            return None;
        }
        retries = 0;
        index += 1;
        name.truncate(name_len as usize);
        data.truncate(data_len as usize);
        out.push((String::from_utf16_lossy(&name), REG_VALUE_TYPE(kind), data));
        if index > 100_000 {
            return None;
        }
    }
    Some(out)
}

/// The switches of a StartupApproved key, by lower-case value name (`None`: it could not be read).
fn approved_values(hive: Hive, sub: &str) -> Option<HashMap<String, Vec<u8>>> {
    Some(
        read_values(hive, sub)?
            .into_iter()
            .map(|(name, _, data)| (name.to_lowercase(), data))
            .collect(),
    )
}

/// REG_SZ / REG_EXPAND_SZ data as text (an expandable value is expanded later, by the resolver).
fn wide_text(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    from_wide(&units).trim().to_string()
}

// --------------------------------------------------------------------------- publisher

static VERSIONS: LazyLock<Mutex<HashMap<String, (String, String)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// The CompanyName and FileDescription of a program, cached per path.
pub fn version_strings(path: &str) -> (String, String) {
    let key = path.to_lowercase();
    if let Some(found) = VERSIONS.lock().unwrap_or_else(PoisonError::into_inner).get(&key) {
        return found.clone();
    }
    let found = read_version_strings(path);
    VERSIONS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key, found.clone());
    found
}

fn query(block: &[u8], query: &str) -> Option<String> {
    let mut pointer: *mut c_void = std::ptr::null_mut();
    let mut length = 0u32;
    let query = wide(query);
    // SAFETY: `block` holds a version resource read by GetFileVersionInfoW; the out pointers are valid.
    let found = unsafe { VerQueryValueW(block.as_ptr().cast(), PCWSTR(query.as_ptr()), &mut pointer, &mut length) };
    if !found.as_bool() || pointer.is_null() || length == 0 {
        return None;
    }
    // SAFETY: VerQueryValueW points inside `block` at `length` UTF-16 units (terminator included).
    let units = unsafe { std::slice::from_raw_parts(pointer.cast::<u16>(), length as usize) };
    let text = from_wide(units).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn read_version_strings(path: &str) -> (String, String) {
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated.
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(name.as_ptr()), None) };
    if size == 0 || size > 4 * 1024 * 1024 {
        return (String::new(), String::new());
    }
    let mut block = vec![0u8; size as usize];
    // SAFETY: `block` is writable for `size` bytes.
    if unsafe { GetFileVersionInfoW(PCWSTR(name.as_ptr()), None, size, block.as_mut_ptr().cast()) }.is_err() {
        return (String::new(), String::new());
    }
    let mut codes: Vec<String> = Vec::new();
    let mut pointer: *mut c_void = std::ptr::null_mut();
    let mut length = 0u32;
    let translation = wide(r"\VarFileInfo\Translation");
    // SAFETY: as in `query`.
    let found = unsafe {
        VerQueryValueW(
            block.as_ptr().cast(),
            PCWSTR(translation.as_ptr()),
            &mut pointer,
            &mut length,
        )
    };
    if found.as_bool() && !pointer.is_null() && length >= 4 {
        // SAFETY: the translation table is an array of (language, code page) u16 pairs.
        let pairs = unsafe { std::slice::from_raw_parts(pointer.cast::<u16>(), (length / 2) as usize) };
        for pair in pairs.as_chunks::<2>().0.iter().take(4) {
            codes.push(format!("{:04x}{:04x}", pair[0], pair[1]));
        }
    }
    codes.extend(["040904b0".to_string(), "040904e4".to_string(), "000004b0".to_string()]);
    let field = |name: &str| {
        codes
            .iter()
            .find_map(|code| query(&block, &format!(r"\StringFileInfo\{code}\{name}")))
            .unwrap_or_default()
    };
    (field("CompanyName"), field("FileDescription"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Registry::{
        KEY_WRITE, REG_BINARY, REG_OPTION_NON_VOLATILE, RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegSetValueExW,
    };

    /// A temporary folder of the test, deleted when dropped (also when the test fails).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("vigil-startup-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).ok();
            TempDir(dir)
        }

        fn join(&self, part: &str) -> PathBuf {
            self.0.join(part)
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
            Scratch(format!(r"Software\VigilTests\startup-{name}-{}", std::process::id()))
        }

        fn set(&self, sub: &str, value: &str, kind: REG_VALUE_TYPE, data: &[u8]) {
            let path = wide(&format!(r"{}\{sub}", self.0));
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

    fn sz(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    #[test]
    fn switch_bytes_follow_task_manager() {
        assert_eq!(switch_state(None), (true, None));
        assert_eq!(switch_state(Some(&[])), (true, None));
        assert_eq!(switch_state(Some(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])), (true, None));
        assert_eq!(switch_state(Some(&[6, 0, 0, 0])), (true, None));
        // 2026-01-01 00:00:00 UTC as a FILETIME.
        let filetime: i64 = 134_116_992_000_000_000;
        let mut off = vec![3, 0, 0, 0];
        off.extend(filetime.to_le_bytes());
        let (enabled, when) = switch_state(Some(&off));
        assert!(!enabled);
        assert_eq!(when, Some(1_767_225_600_000));
        assert_eq!(switch_state(Some(&[7, 0, 0, 0])), (false, None));
    }

    #[test]
    fn programs_are_found_in_command_lines() {
        let dir = TempDir::new("cmd");
        let app_dir = dir.join("My App");
        std::fs::create_dir_all(&app_dir).ok();
        let exe = app_dir.join("tool.exe");
        std::fs::write(&exe, b"MZ").ok();
        let exe_text = exe.display().to_string();
        assert_eq!(executable_of(&format!("\"{exe_text}\" --tray")), exe_text);
        assert_eq!(
            executable_of(&format!("{exe_text} --tray --quiet")),
            exe_text,
            "unquoted path with spaces"
        );
        let without_ext = exe_text.trim_end_matches(".exe").to_string();
        assert_eq!(
            executable_of(&format!("{without_ext} /min")),
            format!("{without_ext}.exe")
        );
        let found = executable_of("rundll32.exe shell32.dll,Control_RunDLL");
        assert!(found.to_lowercase().ends_with(r"system32\rundll32.exe"), "{found}");
        assert!(
            executable_of(r"%SystemRoot%\System32\cmd.exe /c exit")
                .to_lowercase()
                .ends_with("cmd.exe")
        );
        assert_eq!(executable_of("   "), "");
    }

    #[test]
    fn registry_entries_and_their_switch_are_read() {
        let scratch = Scratch::new("reg");
        let dir = TempDir::new("reg");
        let exe = dir.join("updater.exe");
        std::fs::write(&exe, b"MZ").ok();
        scratch.set("Run", "Updater", REG_SZ, &sz(&format!("\"{}\" -silent", exe.display())));
        scratch.set(
            "Run",
            "Helper",
            REG_EXPAND_SZ,
            &sz(r"%SystemRoot%\System32\cmd.exe /c exit"),
        );
        scratch.set("Run", "Binary", REG_BINARY, &[1, 2, 3]);
        let mut off = vec![3, 0, 0, 0];
        off.extend(134_116_992_000_000_000i64.to_le_bytes());
        scratch.set("Approved", "Updater", REG_BINARY, &off);
        scratch.set("Once", "Setup", REG_SZ, &sz("setup.exe /finish"));
        let sources = [
            RegistrySource {
                hive: Hive::CurrentUser,
                key: format!(r"{}\Run", scratch.0),
                approved: Some(format!(r"{}\Approved", scratch.0)),
                kind: "run",
            },
            RegistrySource {
                hive: Hive::CurrentUser,
                key: format!(r"{}\Once", scratch.0),
                approved: None,
                kind: "run_once",
            },
        ];
        let entries = list_from(&sources, &[]);
        assert_eq!(entries.len(), 3, "{entries:#?}");
        let updater = entries.iter().find(|e| e.name == "Updater").expect("updater");
        assert!(!updater.enabled && updater.can_toggle);
        assert_eq!(updater.disabled_at_ms, Some(1_767_225_600_000));
        assert_eq!(updater.executable, exe.display().to_string());
        assert!(updater.exists && updater.scope == "user" && updater.kind == "run");
        assert_eq!(updater.id, format!(r"reg:HKCU\{}\Run\Updater", scratch.0));
        assert_eq!(updater.approved_key, format!(r"HKCU\{}\Approved", scratch.0));
        let helper = entries.iter().find(|e| e.name == "Helper").expect("helper");
        assert!(helper.enabled, "no switch value means on");
        assert!(helper.executable.to_lowercase().ends_with("cmd.exe") && helper.exists);
        assert!(
            helper.host && helper.publisher.is_empty(),
            "cmd.exe only hosts the command"
        );
        assert!(!updater.host);
        let setup = entries.iter().find(|e| e.name == "Setup").expect("run once");
        assert!(setup.enabled && !setup.can_toggle && setup.approved_key.is_empty());
        assert!(entries.iter().all(|e| !e.own));
    }

    #[test]
    fn vigil_recognises_its_own_entry() {
        let scratch = Scratch::new("own");
        let exe = std::env::current_exe().expect("test program");
        scratch.set("Run", OWN_VALUE, REG_SZ, &sz(&own_command(&exe)));
        // The same name with other arguments, or under another name, is not Vigil's.
        scratch.set("Run", "Vigil Helper", REG_SZ, &sz(&own_command(&exe)));
        scratch.set("Once", OWN_VALUE, REG_SZ, &sz(&own_command(&exe)));
        let source = |sub: &str, kind| RegistrySource {
            hive: Hive::CurrentUser,
            key: format!(r"{}\{sub}", scratch.0),
            approved: None,
            kind,
        };
        let entries = list_from(&[source("Run", "run"), source("Once", "run_once")], &[]);
        let own: Vec<&str> = entries.iter().filter(|e| e.own).map(|e| e.id.as_str()).collect();
        assert_eq!(own, [format!(r"reg:HKCU\{}\Run\{OWN_VALUE}", scratch.0)]);
        scratch.set(
            "Run",
            OWN_VALUE,
            REG_SZ,
            &sz(&format!("{} & calc.exe", own_command(&exe))),
        );
        assert!(list_from(&[source("Run", "run")], &[]).iter().all(|e| !e.own));
    }

    #[test]
    fn startup_folder_files_and_shortcuts_are_read() {
        let scratch = Scratch::new("folder");
        let dir = TempDir::new("folder");
        let target = dir.join("agent.exe");
        std::fs::write(&target, b"MZ").ok();
        let folder = dir.join("Startup");
        std::fs::create_dir_all(&folder).ok();
        std::fs::write(folder.join("cleanup.bat"), b"@echo off").ok();
        std::fs::write(folder.join("desktop.ini"), b"[.ShellClassInfo]").ok();
        let link = folder.join("Agent.lnk");
        assert!(
            write_shortcut(&link, &target, "--background"),
            "the test shortcut was created"
        );
        scratch.set("Approved", "cleanup.bat", REG_BINARY, &[3, 0, 0, 0]);
        let sources = [FolderSource {
            folder: folder.clone(),
            approved_hive: Hive::CurrentUser,
            approved: format!(r"{}\Approved", scratch.0),
        }];
        let entries = list_from(&[], &sources);
        assert_eq!(entries.len(), 2, "{entries:#?}");
        let agent = entries.iter().find(|e| e.name == "Agent").expect("shortcut");
        // Compared after resolution: the temp folder may be given by its short 8.3 name
        // ("RUNNER~1") while the shortcut resolves to the long one.
        assert_eq!(
            std::fs::canonicalize(&agent.executable).ok(),
            std::fs::canonicalize(&target).ok(),
            "{} vs {}",
            agent.executable,
            target.display()
        );
        assert!(agent.command.ends_with("--background") && agent.enabled && agent.kind == "folder");
        assert_eq!(agent.value, "Agent.lnk");
        let cleanup = entries.iter().find(|e| e.name == "cleanup").expect("batch file");
        assert!(!cleanup.enabled);
        assert_eq!(cleanup.file, folder.join("cleanup.bat").display().to_string());
    }

    #[test]
    fn unreadable_places_are_reported_and_policy_entries_have_no_switch() {
        let scratch = Scratch::new("checked");
        let dir = TempDir::new("checked");
        scratch.set("Policy", "Agent", REG_SZ, &sz(r"C:\Tools\agent.exe /run"));
        // A long value (bigger than any first guess) is read, not skipped.
        let long = format!(r"C:\Tools\{}.exe", "x".repeat(3000));
        scratch.set("Policy", "Long", REG_SZ, &sz(&long));
        let policy = RegistrySource {
            hive: Hive::CurrentUser,
            key: format!(r"{}\Policy", scratch.0),
            approved: None,
            kind: "policy",
        };
        let missing_key = RegistrySource {
            hive: Hive::CurrentUser,
            key: format!(r"{}\Missing", scratch.0),
            approved: Some(format!(r"{}\MissingApproved", scratch.0)),
            kind: "run",
        };
        let missing_folder = FolderSource {
            folder: dir.join("no such folder"),
            approved_hive: Hive::CurrentUser,
            approved: format!(r"{}\Approved", scratch.0),
        };
        let (entries, complete) = read_from(&[policy.clone(), missing_key], &[missing_folder], true);
        // A key or folder that does not exist is simply empty.
        assert!(complete);
        assert_eq!(entries.len(), 2, "{entries:#?}");
        let agent = entries.iter().find(|e| e.name == "Agent").expect("policy entry");
        assert!(agent.kind == "policy" && !agent.can_toggle && agent.enabled && agent.approved_key.is_empty());
        // Light: nothing about the file is read.
        assert!(agent.executable.is_empty() && agent.publisher.is_empty() && !agent.exists);
        let long_entry = entries.iter().find(|e| e.name == "Long").expect("long value");
        assert_eq!(long_entry.command, long);
        // A "folder" that is a file cannot be listed: the reading is incomplete.
        let file = dir.join("not a folder");
        std::fs::write(&file, b"x").ok();
        let broken = FolderSource {
            folder: file,
            approved_hive: Hive::CurrentUser,
            approved: format!(r"{}\Approved", scratch.0),
        };
        let (_, complete) = read_from(&[policy], &[broken], true);
        assert!(!complete);
        // The real places include the policy Run keys.
        let (registry, _) = default_sources();
        assert_eq!(registry.iter().filter(|s| s.kind == "policy").count(), 2);
    }

    #[test]
    fn publishers_come_from_the_version_resource() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let (company, description) = version_strings(&format!(r"{root}\System32\cmd.exe"));
        assert!(company.contains("Microsoft"), "{company}");
        assert!(!description.is_empty());
        assert_eq!(
            version_strings(r"C:\nowhere\missing.exe"),
            (String::new(), String::new())
        );
    }

    /// Creates a shortcut for the folder test (test-only; Vigil never writes shortcuts).
    fn write_shortcut(path: &Path, target: &Path, arguments: &str) -> bool {
        // SAFETY: COM for this test thread, balanced below.
        let initialized = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_ok();
        let made = (|| -> Option<()> {
            // SAFETY: creates the in-process Shell Link object.
            let link: IShellLinkW = unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }.ok()?;
            let target = wide(&target.display().to_string());
            let arguments = wide(arguments);
            // SAFETY: both strings are NUL-terminated and outlive the calls.
            unsafe {
                link.SetPath(PCWSTR(target.as_ptr())).ok()?;
                link.SetArguments(PCWSTR(arguments.as_ptr())).ok()?;
            }
            let file: IPersistFile = link.cast().ok()?;
            let name = wide(&path.display().to_string());
            // SAFETY: `name` is NUL-terminated.
            unsafe { file.Save(PCWSTR(name.as_ptr()), true) }.ok()?;
            Some(())
        })()
        .is_some();
        if initialized {
            // SAFETY: balances the CoInitializeEx above.
            unsafe { CoUninitialize() };
        }
        made
    }
}
