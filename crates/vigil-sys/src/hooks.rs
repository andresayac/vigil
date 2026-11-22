//! Registry places Windows reads to load or run something, read cheaply for the background watch:
//! image hijacks (IFEO, SilentProcessExit), Winlogon, AppInit and AppCert DLLs, BootExecute, the
//! LSA packages, per-user class handlers used to bypass UAC, the .NET profiler variables, NetSh
//! helpers, print monitors, time providers, Microsoft Defender exclusions, and the kernel and file
//! system drivers. Only registry reads: no file is opened, no signature checked. Read-only.

use std::collections::BTreeMap;

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_QWORD, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW,
    RegQueryInfoKeyW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::util::{from_wide, wide};

/// The most subkeys or values read from one key (a bound, not an expected size).
const MAX_ITEMS: u32 = 20_000;

/// Which registry hive a source is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    LocalMachine,
    CurrentUser,
}

impl Root {
    fn handle(self) -> HKEY {
        match self {
            Self::LocalMachine => HKEY_LOCAL_MACHINE,
            Self::CurrentUser => HKEY_CURRENT_USER,
        }
    }

    fn prefix(self) -> &'static str {
        match self {
            Self::LocalMachine => "HKLM",
            Self::CurrentUser => "HKCU",
        }
    }
}

/// What is read from a source's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    /// These values of the key ("" is the default value).
    Values(Vec<&'static str>),
    /// Every value of the key (Defender exclusions: the names are what matters).
    AllValues,
    /// These values of every subkey, named `subkey\value`.
    Subkeys(Vec<&'static str>),
    /// The names of the subkeys, each with an empty value (AMSI providers by CLSID, root
    /// certificates by thumbprint: the names are what matters).
    SubkeyNames,
}

/// One registry place the watch reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Stable id, also the fingerprint key ("ifeo", "winlogon", ...); unique among the sources.
    pub id: String,
    /// What it is, for the alert ("ifeo", "silent_exit", "winlogon", "appinit", "appcert",
    /// "boot_execute", "lsa", "class", "profiler", "netsh", "print_monitor", "time_provider",
    /// "exclusion", "amsi", "amsi_enable", "root_cert").
    pub kind: &'static str,
    pub root: Root,
    pub path: String,
    /// Read the 32-bit view (WOW6432Node) instead of the 64-bit one.
    pub view32: bool,
    pub shape: Shape,
}

impl Source {
    fn new(id: &str, kind: &'static str, root: Root, path: &str, shape: Shape) -> Self {
        Self {
            id: id.to_string(),
            kind,
            root,
            path: path.to_string(),
            view32: false,
            shape,
        }
    }

    /// `HKLM\SYSTEM\...` as shown in alerts.
    pub fn location(&self) -> String {
        format!("{}\\{}", self.root.prefix(), self.path)
    }
}

const IFEO: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const IFEO_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const SILENT_EXIT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
const SILENT_EXIT_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
const WINDOWS: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
const WINDOWS_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows";
const SESSION_MANAGER: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager";
const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const PROFILER_NAMES: [&str; 6] = [
    "COR_ENABLE_PROFILING",
    "COR_PROFILER",
    "COR_PROFILER_PATH",
    "CORECLR_ENABLE_PROFILING",
    "CORECLR_PROFILER",
    "CORECLR_PROFILER_PATH",
];
/// Classes whose per-user `shell\open\command` is used to run a program with administrator rights
/// without a prompt (the auto-elevating Settings app, consoles and others read HKCU first).
const HIJACKED_CLASSES: [&str; 5] = ["ms-settings", "mscfile", "exefile", "Folder", "Launcher.SystemSettings"];
const DEFENDER_EXCLUSIONS: &str = r"SOFTWARE\Microsoft\Windows Defender\Exclusions";
const DEFENDER_POLICY_EXCLUSIONS: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions";
const AMSI_PROVIDERS: &str = r"SOFTWARE\Microsoft\AMSI\Providers";
const AMSI_PROVIDERS_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\AMSI\Providers";
const SCRIPT_SETTINGS: &str = r"SOFTWARE\Microsoft\Windows Script\Settings";
/// The root certificate stores (one registry key per certificate, named by its SHA-1 thumbprint):
/// (source id, hive, key).
pub const ROOT_STORES: [(&str, Root, &str); 4] = [
    (
        "root_machine",
        Root::LocalMachine,
        r"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates",
    ),
    (
        "root_user",
        Root::CurrentUser,
        r"Software\Microsoft\SystemCertificates\Root\Certificates",
    ),
    (
        "root_policy",
        Root::LocalMachine,
        r"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates",
    ),
    (
        "root_enterprise",
        Root::LocalMachine,
        r"SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates",
    ),
];

/// The places the watch reads on this computer.
pub fn default_sources() -> Vec<Source> {
    use Root::{CurrentUser as Cu, LocalMachine as Lm};
    let mut out = vec![
        Source::new(
            "ifeo",
            "ifeo",
            Lm,
            IFEO,
            Shape::Subkeys(vec!["Debugger", "VerifierDlls"]),
        ),
        Source::new(
            "ifeo32",
            "ifeo",
            Lm,
            IFEO_32,
            Shape::Subkeys(vec!["Debugger", "VerifierDlls"]),
        ),
        Source::new(
            "silent_exit",
            "silent_exit",
            Lm,
            SILENT_EXIT,
            Shape::Subkeys(vec!["MonitorProcess"]),
        ),
        Source::new(
            "silent_exit32",
            "silent_exit",
            Lm,
            SILENT_EXIT_32,
            Shape::Subkeys(vec!["MonitorProcess"]),
        ),
        Source::new(
            "winlogon",
            "winlogon",
            Lm,
            WINLOGON,
            Shape::Values(vec!["Shell", "Userinit", "Taskman", "AppSetup"]),
        ),
        Source::new("winlogon_user", "winlogon", Cu, WINLOGON, Shape::Values(vec!["Shell"])),
        Source::new(
            "appinit",
            "appinit",
            Lm,
            WINDOWS,
            Shape::Values(vec!["AppInit_DLLs", "LoadAppInit_DLLs"]),
        ),
        Source::new(
            "appinit32",
            "appinit",
            Lm,
            WINDOWS_32,
            Shape::Values(vec!["AppInit_DLLs", "LoadAppInit_DLLs"]),
        ),
        Source::new(
            "appcert",
            "appcert",
            Lm,
            &format!(r"{SESSION_MANAGER}\AppCertDlls"),
            Shape::AllValues,
        ),
        Source::new(
            "boot_execute",
            "boot_execute",
            Lm,
            SESSION_MANAGER,
            Shape::Values(vec!["BootExecute", "SetupExecute", "Execute"]),
        ),
        Source::new(
            "lsa",
            "lsa",
            Lm,
            LSA,
            Shape::Values(vec![
                "Authentication Packages",
                "Notification Packages",
                "Security Packages",
            ]),
        ),
        Source::new(
            "lsa_osconfig",
            "lsa",
            Lm,
            &format!(r"{LSA}\OSConfig"),
            Shape::Values(vec!["Security Packages"]),
        ),
        Source::new(
            "profiler_user",
            "profiler",
            Cu,
            "Environment",
            Shape::Values(PROFILER_NAMES.to_vec()),
        ),
        Source::new(
            "profiler_machine",
            "profiler",
            Lm,
            &format!(r"{SESSION_MANAGER}\Environment"),
            Shape::Values(PROFILER_NAMES.to_vec()),
        ),
        Source::new("netsh", "netsh", Lm, r"SOFTWARE\Microsoft\NetSh", Shape::AllValues),
        Source::new(
            "print_monitors",
            "print_monitor",
            Lm,
            r"SYSTEM\CurrentControlSet\Control\Print\Monitors",
            Shape::Subkeys(vec!["Driver"]),
        ),
        Source::new(
            "time_providers",
            "time_provider",
            Lm,
            r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders",
            Shape::Subkeys(vec!["DllName"]),
        ),
    ];
    // AMSI: the providers that see every script, and the switch that turns scanning off for
    // Windows Script Host.
    out.push(Source::new(
        "amsi_providers",
        "amsi",
        Lm,
        AMSI_PROVIDERS,
        Shape::SubkeyNames,
    ));
    out.push(Source::new(
        "amsi_providers32",
        "amsi",
        Lm,
        AMSI_PROVIDERS_32,
        Shape::SubkeyNames,
    ));
    for (id, root) in [("amsi_enable_user", Cu), ("amsi_enable_machine", Lm)] {
        out.push(Source::new(
            id,
            "amsi_enable",
            root,
            SCRIPT_SETTINGS,
            Shape::Values(vec!["AmsiEnable"]),
        ));
    }
    // Root certificates: a new one lets whoever holds its key impersonate websites and programs.
    for (id, root, path) in ROOT_STORES {
        out.push(Source::new(id, "root_cert", root, path, Shape::SubkeyNames));
    }
    // The 32-bit places are spelled out (WOW6432Node) and read through the 64-bit view.
    for class in HIJACKED_CLASSES {
        out.push(Source::new(
            &format!("class_{}", class.to_lowercase()),
            "class",
            Cu,
            &format!(r"Software\Classes\{class}\shell\open\command"),
            Shape::Values(vec!["", "DelegateExecute"]),
        ));
    }
    for (list, id) in [
        ("Paths", "paths"),
        ("Processes", "processes"),
        ("Extensions", "extensions"),
    ] {
        out.push(Source::new(
            &format!("exclusions_{id}"),
            "exclusion",
            Lm,
            &format!(r"{DEFENDER_EXCLUSIONS}\{list}"),
            Shape::AllValues,
        ));
        out.push(Source::new(
            &format!("exclusions_policy_{id}"),
            "exclusion",
            Lm,
            &format!(r"{DEFENDER_POLICY_EXCLUSIONS}\{list}"),
            Shape::AllValues,
        ));
    }
    out
}

/// Every source that could be read, by id: value name -> value as text. A source whose key could
/// not be read (no rights) is left out, so the watch neither compares nor replaces it; a key that
/// does not exist reads as empty.
pub fn read(sources: &[Source]) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for source in sources {
        if let Some(values) = read_source(source) {
            out.insert(source.id.clone(), values);
        }
    }
    out
}

fn read_source(source: &Source) -> Option<BTreeMap<String, String>> {
    let view = if source.view32 {
        REG_SAM_FLAGS(0x0200) // KEY_WOW64_32KEY
    } else {
        KEY_WOW64_64KEY
    };
    let Some(key) = Key::open(source.root.handle(), &source.path, view).ok()? else {
        return Some(BTreeMap::new());
    };
    let mut out = BTreeMap::new();
    match &source.shape {
        Shape::Values(names) => {
            for (name, value) in key.values()? {
                if names.iter().any(|n| n.eq_ignore_ascii_case(&name)) && !value.is_empty() {
                    out.insert(shown_name(&name), value);
                }
            }
        }
        Shape::AllValues => {
            for (name, value) in key.values()? {
                out.insert(shown_name(&name), value);
            }
        }
        Shape::SubkeyNames => {
            for sub in key.subkeys()? {
                out.insert(sub, String::new());
            }
        }
        Shape::Subkeys(names) => {
            for sub in key.subkeys()? {
                let Ok(Some(child)) = Key::open(key.0, &sub, view) else {
                    // A subkey that cannot be opened is skipped; the rest of the source still counts.
                    continue;
                };
                let Some(values) = child.values() else { continue };
                for (name, value) in values {
                    if names.iter().any(|n| n.eq_ignore_ascii_case(&name)) && !value.is_empty() {
                        out.insert(format!(r"{sub}\{name}"), value);
                    }
                }
            }
        }
    }
    Some(out)
}

fn shown_name(name: &str) -> String {
    if name.is_empty() {
        "(default)".to_string()
    } else {
        name.to_string()
    }
}

/// The DLL an AMSI provider registered under its CLSID (`HKLM\SOFTWARE\Classes\CLSID\{...}\
/// InprocServer32`), quotes removed; "" when it cannot be read.
pub fn amsi_provider_dll(clsid: &str) -> String {
    let path = format!(r"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32");
    let Ok(Some(key)) = Key::open(HKEY_LOCAL_MACHINE, &path, KEY_WOW64_64KEY) else {
        return String::new();
    };
    key.values()
        .and_then(|values| values.into_iter().find(|(name, _)| name.is_empty()).map(|(_, v)| v))
        .map(|v| v.trim().trim_matches('"').to_string())
        .unwrap_or_default()
}

// --------------------------------------------------------------------------- drivers

/// A kernel or file system driver as the service database records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Driver {
    /// The service key name ("tcpip").
    pub name: String,
    /// ImagePath as written (often `\SystemRoot\System32\drivers\x.sys`); "" when it names none,
    /// in which case Windows loads `System32\drivers\<name>.sys`.
    pub path: String,
    /// "boot", "system", "auto", "demand", "disabled" or "" when unknown.
    pub start: String,
}

const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";

/// Every kernel (type 1) and file system (type 2) driver; `None` when the service database could
/// not be read.
pub fn drivers() -> Option<Vec<Driver>> {
    drivers_under(HKEY_LOCAL_MACHINE, SERVICES)
}

/// [`drivers`] under another key (tests use a scratch key).
pub fn drivers_under_current_user(path: &str) -> Option<Vec<Driver>> {
    drivers_under(HKEY_CURRENT_USER, path)
}

fn drivers_under(root: HKEY, path: &str) -> Option<Vec<Driver>> {
    let key = Key::open(root, path, KEY_WOW64_64KEY).ok()??;
    let mut out = Vec::new();
    for name in key.subkeys()? {
        let Ok(Some(service)) = Key::open(key.0, &name, KEY_WOW64_64KEY) else {
            continue;
        };
        let Some(values) = service.raw_values() else { continue };
        let dword = |wanted: &str| {
            values
                .iter()
                .find(|(n, kind, _)| n.eq_ignore_ascii_case(wanted) && *kind == REG_DWORD)
                .and_then(|(_, _, data)| data.get(..4))
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        if !matches!(dword("Type"), Some(1 | 2)) {
            continue;
        }
        let path = values
            .iter()
            .find(|(n, _, _)| n.eq_ignore_ascii_case("ImagePath"))
            .map(|(_, kind, data)| text(*kind, data))
            .unwrap_or_default();
        let start = match dword("Start") {
            Some(0) => "boot",
            Some(1) => "system",
            Some(2) => "auto",
            Some(3) => "demand",
            Some(4) => "disabled",
            _ => "",
        };
        out.push(Driver {
            name,
            path,
            start: start.to_string(),
        });
    }
    Some(out)
}

/// Whether a driver path is in the folders Windows installs drivers to (`System32\drivers`, the
/// driver store); an empty path means the default `System32\drivers\<name>.sys`.
pub fn standard_driver_path(path: &str) -> bool {
    let windir = std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| r"C:\Windows".into());
    driver_path_in(path, &windir)
}

/// [`standard_driver_path`] against a given Windows folder. Only the Windows folder itself counts,
/// written the ways ImagePath values write it (`\SystemRoot\`, relative `System32\...`,
/// `%SystemRoot%\`, `\??\C:\Windows\`, `C:\Windows\`), followed by `System32\drivers\` or
/// `System32\DriverStore\`. A path that merely contains those folder names somewhere else
/// (`C:\ProgramData\x\System32\drivers\x.sys`) does not.
fn driver_path_in(path: &str, windir: &str) -> bool {
    let lower = path.trim().trim_matches('"').to_lowercase().replace('/', "\\");
    if lower.is_empty() {
        return true;
    }
    if lower.contains(r"\..\") || lower.contains(r"\.\") {
        return false;
    }
    let windir = windir.trim_end_matches('\\').to_lowercase().replace('/', "\\");
    let rest = if lower.starts_with(r"system32\") {
        Some(lower.as_str())
    } else {
        [
            r"\systemroot\".to_string(),
            r"%systemroot%\".to_string(),
            r"%windir%\".to_string(),
            format!(r"\??\{windir}\"),
            format!(r"\\?\{windir}\"),
            format!(r"{windir}\"),
        ]
        .iter()
        .find_map(|prefix| lower.strip_prefix(prefix.as_str()))
    };
    rest.is_some_and(|rest| rest.starts_with(r"system32\drivers\") || rest.starts_with(r"system32\driverstore\"))
}

// --------------------------------------------------------------------------- registry

pub(crate) struct Key(pub(crate) HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from RegOpenKeyExW and is closed once.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

impl Key {
    /// `Ok(None)` when the key does not exist, `Err` when it exists but cannot be opened.
    pub(crate) fn open(parent: HKEY, sub: &str, view: REG_SAM_FLAGS) -> Result<Option<Self>, ()> {
        let sub = wide(sub);
        let mut key = HKEY::default();
        // SAFETY: `sub` is NUL-terminated; `key` receives the handle, owned by `Key`.
        let status = unsafe { RegOpenKeyExW(parent, PCWSTR(sub.as_ptr()), None, KEY_READ | view, &mut key) };
        match status {
            ERROR_SUCCESS => Ok(Some(Self(key))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            _ => Err(()),
        }
    }

    /// The longest subkey name, value name and value data, as Windows reports them.
    fn sizes(&self) -> Option<(u32, u32, u32)> {
        let (mut subkey, mut name, mut data) = (0u32, 0u32, 0u32);
        // SAFETY: only the three out values are requested.
        let status = unsafe {
            RegQueryInfoKeyW(
                self.0,
                None,
                None,
                None,
                None,
                Some(&mut subkey),
                None,
                None,
                Some(&mut name),
                Some(&mut data),
                None,
                None,
            )
        };
        (status == ERROR_SUCCESS).then_some((subkey, name, data))
    }

    /// When the key was last written (Unix ms); `None` when Windows does not say.
    pub(crate) fn last_write_ms(&self) -> Option<i64> {
        let mut written = windows::Win32::Foundation::FILETIME::default();
        // SAFETY: only the last-write time is requested, into a local FILETIME.
        let status = unsafe {
            RegQueryInfoKeyW(
                self.0,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(&mut written),
            )
        };
        let raw = (i64::from(written.dwHighDateTime) << 32) | i64::from(written.dwLowDateTime);
        (status == ERROR_SUCCESS && raw > 0).then(|| crate::util::filetime_to_unix_ms(raw))
    }

    /// The names of the subkeys; `None` when they cannot be listed.
    pub(crate) fn subkeys(&self) -> Option<Vec<String>> {
        let (longest, _, _) = self.sizes()?;
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name = vec![0u16; longest as usize + 2];
            let mut len = name.len() as u32;
            // SAFETY: `name` is writable for `len` characters; `len` is updated in place.
            let status = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                return Some(out);
            }
            if status == ERROR_MORE_DATA {
                // A longer name appeared since the size was read: list again from the start.
                return self.subkeys_retry(index);
            }
            if status != ERROR_SUCCESS {
                return None;
            }
            name.truncate(len as usize);
            out.push(String::from_utf16_lossy(&name));
            index += 1;
            if index > MAX_ITEMS {
                return None;
            }
        }
    }

    fn subkeys_retry(&self, from: u32) -> Option<Vec<String>> {
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name = vec![0u16; 512];
            let mut len = name.len() as u32;
            // SAFETY: as in `subkeys`; key names are at most 255 characters.
            let status = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                return Some(out);
            }
            if status != ERROR_SUCCESS || index > MAX_ITEMS.max(from) {
                return None;
            }
            name.truncate(len as usize);
            out.push(String::from_utf16_lossy(&name));
            index += 1;
        }
    }

    /// Every value as (name, type, raw data); `None` when it cannot be read completely (a value
    /// that grows while it is read is read again with a bigger buffer, not skipped).
    pub(crate) fn raw_values(&self) -> Option<Vec<(String, REG_VALUE_TYPE, Vec<u8>)>> {
        let (_, mut max_name, mut max_data) = self.sizes()?;
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
                    self.0,
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
                return Some(out);
            }
            if status == ERROR_MORE_DATA && retries < 8 {
                retries += 1;
                let (_, name_now, data_now) = self.sizes()?;
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
            if index > MAX_ITEMS {
                return None;
            }
        }
    }

    /// Every value as (name, text).
    fn values(&self) -> Option<Vec<(String, String)>> {
        Some(
            self.raw_values()?
                .into_iter()
                .map(|(name, kind, data)| (name, text(kind, &data)))
                .collect(),
        )
    }
}

/// A value as text: strings as they are, multi-strings joined with "; ", numbers in decimal,
/// anything else in hex.
pub(crate) fn text(kind: REG_VALUE_TYPE, data: &[u8]) -> String {
    let units = || -> Vec<u16> {
        data.as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect()
    };
    match kind {
        REG_SZ | REG_EXPAND_SZ => from_wide(&units()).trim().to_string(),
        REG_MULTI_SZ => units()
            .split(|&u| u == 0)
            .map(String::from_utf16_lossy)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("; "),
        REG_DWORD if data.len() >= 4 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string(),
        REG_QWORD if data.len() >= 8 => {
            u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]).to_string()
        }
        _ => data.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Registry::{
        KEY_WRITE, REG_OPTION_NON_VOLATILE, RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegSetValueExW,
    };

    /// A scratch key under `HKCU\Software\VigilTests`, deleted when dropped.
    struct Scratch(String, #[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

    impl Scratch {
        fn new(name: &str) -> Self {
            let lock = crate::util::TEST_REGISTRY.lock().unwrap_or_else(|p| p.into_inner());
            Scratch(
                format!(r"Software\VigilTests\hooks-{name}-{}", std::process::id()),
                lock,
            )
        }

        fn set(&self, sub: &str, value: &str, kind: REG_VALUE_TYPE, data: &[u8]) {
            let path = wide(&if sub.is_empty() {
                self.0.clone()
            } else {
                format!(r"{}\{sub}", self.0)
            });
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
            assert_eq!(status, ERROR_SUCCESS);
            let key = Key(key);
            let name = wide(value);
            // SAFETY: `name` is NUL-terminated and `data` is readable for its length.
            let status = unsafe { RegSetValueExW(key.0, PCWSTR(name.as_ptr()), None, kind, Some(data)) };
            assert_eq!(status, ERROR_SUCCESS);
        }

        fn source(&self, id: &str, sub: &str, shape: Shape) -> Source {
            let path = if sub.is_empty() {
                self.0.clone()
            } else {
                format!(r"{}\{sub}", self.0)
            };
            Source::new(id, "test", Root::CurrentUser, &path, shape)
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

    fn multi(items: &[&str]) -> Vec<u8> {
        let mut units: Vec<u16> = Vec::new();
        for item in items {
            units.extend(item.encode_utf16());
            units.push(0);
        }
        units.push(0);
        units.into_iter().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn values_subkeys_and_missing_keys_are_read() {
        let scratch = Scratch::new("read");
        scratch.set(
            r"ifeo\sethc.exe",
            "Debugger",
            REG_SZ,
            &sz(r"C:\Windows\System32\cmd.exe"),
        );
        scratch.set(r"ifeo\notepad.exe", "GlobalFlag", REG_DWORD, &512u32.to_le_bytes());
        scratch.set(
            "lsa",
            "Security Packages",
            REG_MULTI_SZ,
            &multi(&["kerberos", "msv1_0", "evil"]),
        );
        scratch.set("lsa", "Other", REG_SZ, &sz("ignored"));
        scratch.set("excl", r"C:\Users\jdoe\Downloads", REG_DWORD, &0u32.to_le_bytes());
        let sources = vec![
            scratch.source("ifeo", "ifeo", Shape::Subkeys(vec!["Debugger"])),
            scratch.source("lsa", "lsa", Shape::Values(vec!["Security Packages"])),
            scratch.source("excl", "excl", Shape::AllValues),
            scratch.source("missing", "missing", Shape::AllValues),
        ];
        let read = read(&sources);
        assert_eq!(
            read["ifeo"].get(r"sethc.exe\Debugger").map(String::as_str),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(read["ifeo"].len(), 1, "values not asked for are left out");
        assert_eq!(
            read["lsa"].get("Security Packages").map(String::as_str),
            Some("kerberos; msv1_0; evil")
        );
        assert!(read["excl"].contains_key(r"C:\Users\jdoe\Downloads"));
        assert!(read["missing"].is_empty(), "a key that does not exist reads as empty");
    }

    #[test]
    fn drivers_are_read_by_type() {
        let scratch = Scratch::new("drivers");
        scratch.set("tcpip", "Type", REG_DWORD, &1u32.to_le_bytes());
        scratch.set("tcpip", "Start", REG_DWORD, &0u32.to_le_bytes());
        scratch.set("tcpip", "ImagePath", REG_EXPAND_SZ, &sz(r"System32\drivers\tcpip.sys"));
        scratch.set("contosofs", "Type", REG_DWORD, &2u32.to_le_bytes());
        scratch.set("contosofs", "Start", REG_DWORD, &1u32.to_le_bytes());
        scratch.set(
            "contosofs",
            "ImagePath",
            REG_EXPAND_SZ,
            &sz(r"\??\C:\Users\jdoe\AppData\Local\Temp\cfs.sys"),
        );
        scratch.set("spooler", "Type", REG_DWORD, &16u32.to_le_bytes());
        let mut list = drivers_under_current_user(&scratch.0).unwrap_or_default();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(list.len(), 2, "{list:?}");
        assert_eq!(list[0].name, "contosofs");
        assert_eq!(list[0].start, "system");
        assert!(!standard_driver_path(&list[0].path));
        assert_eq!(list[1].start, "boot");
        assert!(standard_driver_path(&list[1].path));
    }

    #[test]
    fn standard_driver_folders() {
        assert!(standard_driver_path(""));
        assert!(standard_driver_path(r"\SystemRoot\System32\drivers\ntfs.sys"));
        assert!(standard_driver_path(r"System32\drivers\x.sys"));
        assert!(standard_driver_path(
            r"\SystemRoot\System32\DriverStore\FileRepository\nv.inf_amd64_1\nvlddmkm.sys"
        ));
        assert!(!standard_driver_path(r"\??\C:\ProgramData\Contoso\cdrv.sys"));
    }

    #[test]
    fn lookalike_driver_folders_are_not_standard() {
        let windir = r"C:\Windows";
        for good in [
            "",
            r"\SystemRoot\System32\drivers\ntfs.sys",
            r"System32\drivers\x.sys",
            r"system32\DRIVERS\x.sys",
            r"%SystemRoot%\System32\drivers\x.sys",
            r"%windir%\system32\drivers\x.sys",
            r"\??\C:\Windows\System32\drivers\x.sys",
            r"C:\Windows\System32\drivers\x.sys",
            r"C:\WINDOWS\system32\DriverStore\FileRepository\a.inf_amd64_1\a.sys",
            r#""\SystemRoot\System32\drivers\x.sys""#,
        ] {
            assert!(driver_path_in(good, windir), "{good}");
        }
        for bad in [
            r"C:\ProgramData\evil\System32\drivers\x.sys",
            r"\??\C:\ProgramData\evil\System32\drivers\x.sys",
            r"\??\C:\Users\jdoe\System32\DriverStore\x.sys",
            r"D:\Windows\System32\drivers\x.sys",
            r"C:\Windows.old\System32\drivers\x.sys",
            r"C:\Windows\Temp\System32\drivers\x.sys",
            r"\SystemRoot\System32\drivers\..\..\Temp\x.sys",
            r"\SystemRoot\Temp\x.sys",
            r"\??\C:\ProgramData\Contoso\cdrv.sys",
        ] {
            assert!(!driver_path_in(bad, windir), "{bad}");
        }
    }

    #[test]
    fn default_sources_have_unique_ids() {
        let sources = default_sources();
        let mut ids: Vec<&str> = sources.iter().map(|s| s.id.as_str()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len());
    }

    #[test]
    #[ignore = "reads this computer's registry; run by hand"]
    fn live_counts() {
        let start = std::time::Instant::now();
        let read = read(&default_sources());
        let hooks = start.elapsed();
        let start = std::time::Instant::now();
        let drivers = drivers().map(|d| d.len());
        println!(
            "sources read {} of {}, values {} in {hooks:?}; drivers {drivers:?} in {:?}",
            read.len(),
            default_sources().len(),
            read.values().map(BTreeMap::len).sum::<usize>(),
            start.elapsed()
        );
        for (id, values) in &read {
            println!("  {id}: {}", values.len());
        }
    }
}
