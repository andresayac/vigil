//! The Windows, System32, program and data folders, from Windows itself.
//!
//! `%SystemRoot%`, `%windir%`, `%ProgramFiles%`, `%ProgramData%`, `%LOCALAPPDATA%` and the like
//! come from the process environment, and a user's own environment (`HKCU\Environment`) can
//! override them for programs that user starts, elevated ones included. Paths that decide trust
//! (the Windows folder a guard refuses, the System32 tool Vigil runs, Microsoft Defender's tool,
//! Vigil's own data folder) therefore come from `GetSystemWindowsDirectoryW`,
//! `GetSystemDirectoryW` and `SHGetKnownFolderPath`, which no environment variable changes.

use std::path::PathBuf;
use std::sync::OnceLock;

use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW};
use windows::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_Profile, FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesCommon,
    FOLDERID_ProgramFilesX86, FOLDERID_Public, FOLDERID_RoamingAppData, KF_FLAG_DONT_VERIFY, SHGetKnownFolderPath,
};
use windows::core::GUID;

/// A known folder through `SHGetKnownFolderPath`; `None` when Windows cannot tell.
fn known_folder(id: &GUID) -> Option<PathBuf> {
    // SAFETY: `id` is a valid known-folder id; no token (this process's user); the returned string
    // is owned by the caller and freed with CoTaskMemFree once copied.
    let raw = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DONT_VERIFY, None) }.ok()?;
    // SAFETY: on success the call returns a valid NUL-terminated wide string.
    let text = unsafe { raw.to_string() };
    // SAFETY: frees the string SHGetKnownFolderPath allocated, once.
    unsafe { CoTaskMemFree(Some(raw.0 as *const _)) };
    let text = text.ok()?;
    let path = PathBuf::from(text);
    path.is_absolute().then_some(path)
}

/// `C:\Program Files` (the native one, for this 64-bit process).
pub fn program_files() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| known_folder(&FOLDERID_ProgramFiles).unwrap_or_else(|| drive_root().join("Program Files")))
        .clone()
}

/// `C:\Program Files (x86)`.
pub fn program_files_x86() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        known_folder(&FOLDERID_ProgramFilesX86).unwrap_or_else(|| drive_root().join("Program Files (x86)"))
    })
    .clone()
}

/// `C:\Program Files\Common Files`.
pub fn common_program_files() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        known_folder(&FOLDERID_ProgramFilesCommon).unwrap_or_else(|| program_files().join("Common Files"))
    })
    .clone()
}

/// `C:\ProgramData`.
pub fn program_data() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| known_folder(&FOLDERID_ProgramData).unwrap_or_else(|| drive_root().join("ProgramData")))
        .clone()
}

/// This user's `AppData\Local`.
pub fn local_app_data() -> Option<PathBuf> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| known_folder(&FOLDERID_LocalAppData)).clone()
}

/// This user's `AppData\Roaming`.
pub fn roaming_app_data() -> Option<PathBuf> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| known_folder(&FOLDERID_RoamingAppData)).clone()
}

/// This user's profile folder (`C:\Users\<name>`).
pub fn profile() -> Option<PathBuf> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| known_folder(&FOLDERID_Profile)).clone()
}

/// The drive Windows is on (`C:\`).
fn drive_root() -> PathBuf {
    windows_dir()
        .ancestors()
        .last()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\"))
}

/// Windows PowerShell's own module folder (`C:\Windows\System32\WindowsPowerShell\v1.0\Modules`).
pub fn powershell_modules() -> PathBuf {
    system_dir().join(r"WindowsPowerShell\v1.0\Modules")
}

/// The variables every PowerShell Vigil starts gets, overriding what it inherits:
///
/// - `PSModulePath`: Windows' own module folder only. A module planted in the user's Documents
///   (`WindowsPowerShell\Modules`) would otherwise replace the cmdlets Vigil calls, elevated.
///   Windows PowerShell 5.1 still adds `%ProgramFiles%\WindowsPowerShell\Modules`, which only
///   administrators can write; `ProgramFiles` below makes that the real one.
/// - The folder variables, set to what Windows reports, so neither PowerShell nor a script finds a
///   folder through a value the user's environment changed.
pub fn powershell_env() -> Vec<(String, String)> {
    let text = |p: PathBuf| p.to_string_lossy().into_owned();
    vec![
        ("PSModulePath".into(), text(powershell_modules())),
        ("SystemRoot".into(), text(windows_dir())),
        ("windir".into(), text(windows_dir())),
        ("ProgramFiles".into(), text(program_files())),
        ("ProgramW6432".into(), text(program_files())),
        ("ProgramFiles(x86)".into(), text(program_files_x86())),
        ("CommonProgramFiles".into(), text(common_program_files())),
        ("ProgramData".into(), text(program_data())),
        ("ALLUSERSPROFILE".into(), text(program_data())),
    ]
}

// ------------------------------------------------------------------------- child environments

/// Variables that make a program load code it was not built with: the .NET profiler and
/// runtime hooks (`COR_ENABLE_PROFILING`/`COR_PROFILER_PATH`, `COMPlus_*`, `CORECLR_*`,
/// `DOTNET_STARTUP_HOOKS`). A user's own environment (`HKCU\Environment`) reaches programs that
/// user starts elevated too, so Windows PowerShell (.NET) or an MMC console started by an elevated
/// Vigil would load the user's DLL with administrator rights. No child ever receives these.
pub fn is_loader_variable(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    ["COR_", "COMPLUS_", "CORECLR_"].iter().any(|p| upper.starts_with(p)) || upper == "DOTNET_STARTUP_HOOKS"
}

/// Names a child of an elevated Vigil may receive; everything else is dropped (see
/// [`elevated_env`]). Exported for the tests and the documentation.
pub const ELEVATED_ENV_NAMES: &[&str] = &[
    "SystemRoot",
    "windir",
    "ComSpec",
    "PATHEXT",
    "PATH",
    "TEMP",
    "TMP",
    "ProgramData",
    "ALLUSERSPROFILE",
    "ProgramFiles",
    "ProgramW6432",
    "ProgramFiles(x86)",
    "CommonProgramFiles",
    "PUBLIC",
    "SystemDrive",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
    "COMPUTERNAME",
    "USERNAME",
    "USERDOMAIN",
    "OS",
    "PSModulePath",
];

/// The whole environment a child of an **elevated** Vigil gets, built from what Windows reports
/// and never from Vigil's own environment, which the user's `HKCU\Environment` shaped:
///
/// - folders from `GetSystemWindowsDirectoryW` / `SHGetKnownFolderPath`;
/// - `PATH` with Windows' own folders only (no user folder, so no program found by name can be
///   one the user planted), `ComSpec` and `PATHEXT` fixed;
/// - `TEMP`/`TMP` in Vigil's administrators-only data folder ([`private_temp`]);
/// - processor and account names from Windows' own calls;
/// - `PSModulePath` as in [`powershell_env`].
///
/// Callers add their own `PC_*` values afterwards.
pub fn elevated_env() -> Vec<(String, String)> {
    let text = |p: PathBuf| p.to_string_lossy().into_owned();
    let system = system_dir();
    let windows = windows_dir();
    let temp = text(private_temp());
    let mut env: Vec<(String, String)> = vec![
        ("SystemRoot".into(), text(windows.clone())),
        ("windir".into(), text(windows.clone())),
        ("ComSpec".into(), text(system.join("cmd.exe"))),
        (
            "PATHEXT".into(),
            ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC".into(),
        ),
        (
            "PATH".into(),
            [
                system.clone(),
                system.join("Wbem"),
                system.join(r"WindowsPowerShell\v1.0"),
                system.join("OpenSSH"),
            ]
            .into_iter()
            .map(text)
            .collect::<Vec<_>>()
            .join(";"),
        ),
        ("TEMP".into(), temp.clone()),
        ("TMP".into(), temp),
        ("ProgramData".into(), text(program_data())),
        ("ALLUSERSPROFILE".into(), text(program_data())),
        ("ProgramFiles".into(), text(program_files())),
        ("ProgramW6432".into(), text(program_files())),
        ("ProgramFiles(x86)".into(), text(program_files_x86())),
        ("CommonProgramFiles".into(), text(common_program_files())),
        ("SystemDrive".into(), system_drive()),
        ("OS".into(), "Windows_NT".into()),
        ("PSModulePath".into(), text(powershell_modules())),
    ];
    if let Some(public) = known_folder(&FOLDERID_Public) {
        env.push(("PUBLIC".into(), text(public)));
    }
    for (name, folder) in [
        ("USERPROFILE", profile()),
        ("APPDATA", roaming_app_data()),
        ("LOCALAPPDATA", local_app_data()),
    ] {
        if let Some(folder) = folder {
            env.push((name.into(), text(folder)));
        }
    }
    let (architecture, processors) = processor();
    env.push(("PROCESSOR_ARCHITECTURE".into(), architecture.into()));
    env.push(("NUMBER_OF_PROCESSORS".into(), processors.to_string()));
    if let Some(computer) = computer_name() {
        env.push(("COMPUTERNAME".into(), computer));
    }
    if let Some((user, domain)) = account_names() {
        env.push(("USERNAME".into(), user));
        env.push(("USERDOMAIN".into(), domain));
    }
    env
}

// ------------------------------------------------------------------- controlled expansion

/// The `%NAME%` variables Vigil expands itself in paths and command lines it reads from the system
/// (REG_EXPAND_SZ values, scheduled task actions, App Paths, PATH entries), each from Windows' own
/// calls: the Windows, program and data folders, this account's profile folders and its temp folder
/// (`AppData\Local\Temp`), the drive, computer and account names. Never from the environment,
/// which any program of the user can change (`HKCU\Environment`). Names compare case-insensitively.
pub fn known_variables() -> &'static [(String, String)] {
    static TABLE: OnceLock<Vec<(String, String)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let text = |p: PathBuf| p.to_string_lossy().into_owned();
        let windows = text(windows_dir());
        let mut table: Vec<(String, String)> = vec![
            ("SystemRoot".into(), windows.clone()),
            ("windir".into(), windows),
            ("SystemDrive".into(), system_drive()),
            ("ProgramFiles".into(), text(program_files())),
            ("ProgramW6432".into(), text(program_files())),
            ("ProgramFiles(x86)".into(), text(program_files_x86())),
            ("CommonProgramFiles".into(), text(common_program_files())),
            ("CommonProgramW6432".into(), text(common_program_files())),
            (
                "CommonProgramFiles(x86)".into(),
                text(program_files_x86().join("Common Files")),
            ),
            ("ProgramData".into(), text(program_data())),
            ("ALLUSERSPROFILE".into(), text(program_data())),
        ];
        if let Some(public) = known_folder(&FOLDERID_Public) {
            table.push(("PUBLIC".into(), text(public)));
        }
        if let Some(profile) = profile() {
            table.push(("USERPROFILE".into(), text(profile)));
        }
        if let Some(roaming) = roaming_app_data() {
            table.push(("APPDATA".into(), text(roaming)));
        }
        if let Some(local) = local_app_data() {
            table.push(("LOCALAPPDATA".into(), text(local.clone())));
            table.push(("TEMP".into(), text(local.join("Temp"))));
            table.push(("TMP".into(), text(local.join("Temp"))));
        }
        if let Some(computer) = computer_name() {
            table.push(("COMPUTERNAME".into(), computer));
        }
        if let Some((user, domain)) = account_names() {
            table.push(("USERNAME".into(), user));
            table.push(("USERDOMAIN".into(), domain));
        }
        table
    })
}

/// `text` with each `%NAME%` of [`known_variables`] replaced, and the names it did not know (left
/// as they were, `%` signs included). A caller about to start something with administrator rights
/// refuses when that list is not empty.
pub fn expand_known(text: &str) -> (String, Vec<String>) {
    expand_with(text, known_variables())
}

fn expand_with(text: &str, table: &[(String, String)]) -> (String, Vec<String>) {
    let valid = |c: char| c.is_ascii_alphanumeric() || "_(). -".contains(c);
    let mut out = String::with_capacity(text.len());
    let mut unknown: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 && after[..end].trim() == &after[..end] && after[..end].chars().all(valid) => {
                let name = &after[..end];
                match table.iter().find(|(known, _)| known.eq_ignore_ascii_case(name)) {
                    Some((_, value)) => out.push_str(value),
                    None => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                        if !unknown.iter().any(|u| u.eq_ignore_ascii_case(name)) {
                            unknown.push(name.to_string());
                        }
                    }
                }
                rest = &after[end + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    (out, unknown)
}

/// The environment a child process gets: [`elevated_env`] when Vigil runs elevated, otherwise
/// Vigil's own environment without the [loader variables](is_loader_variable).
pub fn child_env() -> Vec<(String, String)> {
    if elevated() {
        elevated_env()
    } else {
        std::env::vars_os()
            .filter(|(name, _)| !is_loader_variable(&name.to_string_lossy()))
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect()
    }
}

/// Gives `command` the [child environment](child_env). Call it before adding the command's own
/// variables (it clears what was set before when elevated).
pub fn apply_child_env(command: &mut std::process::Command) {
    if elevated() {
        command.env_clear();
        command.envs(elevated_env());
    } else {
        for (name, _) in std::env::vars_os() {
            if is_loader_variable(&name.to_string_lossy()) {
                command.env_remove(name);
            }
        }
    }
}

/// The [child environment](child_env) as a `CreateProcessW` environment block (UTF-16, sorted by
/// name as Windows expects, each `NAME=value` NUL-terminated, the block ending with one more NUL);
/// pass `CREATE_UNICODE_ENVIRONMENT` with it.
pub fn child_env_block() -> Vec<u16> {
    let mut env = child_env();
    env.sort_by_key(|(name, _)| name.to_uppercase());
    let mut block: Vec<u16> = Vec::new();
    for (name, value) in env {
        if name.is_empty() || name.contains('=') || name.contains('\0') || value.contains('\0') {
            continue;
        }
        block.extend(format!("{name}={value}").encode_utf16());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

/// Whether this process runs elevated (asked once: it does not change while Vigil runs).
fn elevated() -> bool {
    static ELEVATED: OnceLock<bool> = OnceLock::new();
    *ELEVATED.get_or_init(crate::elevation::is_elevated)
}

/// The temporary folder children of an elevated Vigil use: `%ProgramData%\Vigil\temp`, created
/// with Administrators and SYSTEM as its only users when missing. A folder already there must be a
/// plain folder owned by Administrators or SYSTEM; otherwise (or when it cannot be made) the
/// Windows folder's own `Temp` is used, which standard users cannot read from.
pub fn private_temp() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = program_data().join("Vigil").join("temp");
        let usable = |dir: &PathBuf| {
            std::fs::symlink_metadata(dir).is_ok_and(|m| {
                use std::os::windows::fs::MetadataExt;
                m.is_dir() && m.file_attributes() & 0x400 == 0 // FILE_ATTRIBUTE_REPARSE_POINT
            }) && admin_owned(dir)
        };
        // Created only by an elevated Vigil (the data folder is its own); a standard copy or a test
        // never makes anything in ProgramData.
        if usable(&dir) || (elevated() && create_private_dir(&dir) && usable(&dir)) {
            dir
        } else {
            windows_dir().join("Temp")
        }
    })
    .clone()
}

/// Creates `dir` in one step with Administrators and SYSTEM as its only users (the data folder's
/// own permissions). False when it cannot (the parent is missing, or it exists).
fn create_private_dir(dir: &std::path::Path) -> bool {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows::core::PCWSTR;
    let sddl = crate::util::wide("O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)");
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor, freed below.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), 1, &mut sd, None) }.is_err()
    {
        return false;
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    let name = crate::util::wide(&dir.to_string_lossy());
    // SAFETY: `name` is NUL-terminated; `attributes` and its descriptor live until the call returns.
    let made = unsafe { CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&attributes)) }.is_ok();
    // SAFETY: frees the descriptor allocated above, once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    made
}

/// True when `dir`'s owner is Administrators or SYSTEM.
fn admin_owned(dir: &std::path::Path) -> bool {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid,
        WinLocalSystemSid,
    };
    use windows::core::PCWSTR;
    let name = crate::util::wide(&dir.to_string_lossy());
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `name` is NUL-terminated; `owner` points into `sd`, which is freed below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut sd,
        )
    };
    if status.is_err() {
        return false;
    }
    // SAFETY: `owner` is a valid SID inside `sd`, which is still allocated.
    let ok = unsafe {
        IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool()
            || IsWellKnownSid(owner, WinLocalSystemSid).as_bool()
    };
    // SAFETY: frees the descriptor GetNamedSecurityInfoW allocated, once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    ok
}

/// `C:` for the drive Windows is on.
fn system_drive() -> String {
    let root = drive_root().to_string_lossy().into_owned();
    root.trim_end_matches('\\').to_string()
}

/// The processor architecture name (`AMD64`, `ARM64`, `x86`) and the logical processor count.
fn processor() -> (&'static str, u32) {
    use windows::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};
    let mut info = SYSTEM_INFO::default();
    // SAFETY: `info` is writable for its size.
    unsafe { GetNativeSystemInfo(&mut info) };
    // SAFETY: reading the architecture member of the union GetNativeSystemInfo filled.
    let architecture = unsafe { info.Anonymous.Anonymous.wProcessorArchitecture.0 };
    let name = match architecture {
        9 => "AMD64",
        12 => "ARM64",
        5 => "ARM",
        0 => "x86",
        _ => "AMD64",
    };
    (name, info.dwNumberOfProcessors.max(1))
}

/// The computer's NetBIOS name, from Windows.
fn computer_name() -> Option<String> {
    use windows::Win32::System::SystemInformation::{ComputerNameNetBIOS, GetComputerNameExW};
    use windows::core::PWSTR;
    let mut buffer = vec![0u16; 64];
    let mut size = buffer.len() as u32;
    // SAFETY: `buffer` is writable for `size` characters.
    unsafe { GetComputerNameExW(ComputerNameNetBIOS, Some(PWSTR(buffer.as_mut_ptr())), &mut size) }.ok()?;
    let name = String::from_utf16_lossy(&buffer[..(size as usize).min(buffer.len())]);
    (!name.is_empty()).then_some(name)
}

/// This process's account name and domain, from its token (not `%USERNAME%`).
fn account_names() -> Option<(String, String)> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::{PCWSTR, PWSTR};
    let mut token = HANDLE::default();
    // SAFETY: the pseudo handle of the current process is valid; `token` is closed below.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.ok()?;
    let mut buffer = vec![0u64; 64];
    let mut needed = 0u32;
    // SAFETY: `buffer` is writable for its size in bytes and 8-byte aligned for TOKEN_USER.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            (buffer.len() * 8) as u32,
            &mut needed,
        )
    };
    // SAFETY: the handle was opened above and is closed once.
    unsafe {
        let _ = CloseHandle(token);
    }
    read.ok()?;
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points inside it.
    let sid = unsafe { (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid };
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
    let mut kind = SID_NAME_USE::default();
    // SAFETY: both buffers are writable for the lengths passed; `sid` stays valid inside `buffer`.
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
    }
    .ok()?;
    let name = String::from_utf16_lossy(&name[..(name_len as usize).min(name.len())]);
    let domain = String::from_utf16_lossy(&domain[..(domain_len as usize).min(domain.len())]);
    (!name.is_empty()).then_some((name, domain))
}

/// Reads a folder through one of the two calls; `None` when it fails.
fn read(call: fn(&mut [u16]) -> u32) -> Option<PathBuf> {
    let mut buffer = vec![0u16; 260];
    for _ in 0..2 {
        let len = call(&mut buffer) as usize;
        if len == 0 {
            return None;
        }
        if len < buffer.len() {
            return Some(PathBuf::from(String::from_utf16_lossy(&buffer[..len])));
        }
        buffer.resize(len + 1, 0);
    }
    None
}

/// The Windows folder (`C:\Windows`), from `GetSystemWindowsDirectoryW`.
pub fn windows_dir() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        // SAFETY: the buffer is writable for its whole length, which is the size passed.
        read(|buf| unsafe { GetSystemWindowsDirectoryW(Some(buf)) }).unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
    })
    .clone()
}

/// The System32 folder (`C:\Windows\System32`), from `GetSystemDirectoryW`.
pub fn system_dir() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        // SAFETY: the buffer is writable for its whole length, which is the size passed.
        read(|buf| unsafe { GetSystemDirectoryW(Some(buf)) }).unwrap_or_else(|| windows_dir().join("System32"))
    })
    .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn the_folders_exist_and_nest() {
        let windows = windows_dir();
        let system = system_dir();
        assert!(windows.is_dir(), "{}", windows.display());
        assert!(system.is_dir(), "{}", system.display());
        assert!(
            system
                .to_string_lossy()
                .to_lowercase()
                .starts_with(&windows.to_string_lossy().to_lowercase()),
            "{} in {}",
            system.display(),
            windows.display()
        );
        assert!(system.join("kernel32.dll").is_file());
    }

    #[test]
    fn only_known_variables_are_expanded() {
        let table = vec![
            ("SystemRoot".to_string(), r"C:\Windows".to_string()),
            ("LOCALAPPDATA".to_string(), r"C:\Users\jdoe\AppData\Local".to_string()),
        ];
        let (text, unknown) = expand_with(r"%systemroot%\System32\x.exe %LocalAppData%\v\y.dll", &table);
        assert_eq!(text, r"C:\Windows\System32\x.exe C:\Users\jdoe\AppData\Local\v\y.dll");
        assert!(unknown.is_empty());
        let (text, unknown) = expand_with(r"%VENDOR_HOME%\bin\up.exe /p=%VENDOR_HOME% 50% %1 %%", &table);
        assert_eq!(text, r"%VENDOR_HOME%\bin\up.exe /p=%VENDOR_HOME% 50% %1 %%");
        assert_eq!(unknown, ["VENDOR_HOME"]);
        assert_eq!(expand_with("100%", &table), ("100%".to_string(), vec![]));
        // The real table: Windows' own folders, never PATH or loader variables.
        let (text, unknown) = expand_known(r"%SystemRoot%\System32");
        assert!(text.eq_ignore_ascii_case(&system_dir().to_string_lossy()), "{text}");
        assert!(unknown.is_empty());
        let names: Vec<&str> = known_variables().iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !names
                .iter()
                .any(|n| n.eq_ignore_ascii_case("PATH") || is_loader_variable(n))
        );
    }

    #[test]
    fn the_elevated_environment_is_only_the_allowlist() {
        let env = elevated_env();
        for (name, value) in &env {
            assert!(
                ELEVATED_ENV_NAMES.iter().any(|n| n.eq_ignore_ascii_case(name)),
                "{name} is not on the list"
            );
            assert!(!is_loader_variable(name), "{name}");
            assert!(!value.is_empty(), "{name} is empty");
        }
        let get = |name: &str| env.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
        assert_eq!(get("SystemRoot"), Some(windows_dir().to_string_lossy().into_owned()));
        assert_eq!(
            get("ComSpec"),
            Some(system_dir().join("cmd.exe").to_string_lossy().into_owned())
        );
        let system = system_dir().to_string_lossy().to_lowercase();
        for folder in get("PATH").unwrap_or_default().split(';') {
            assert!(
                folder.to_lowercase().starts_with(&system),
                "{folder} is not one of Windows' own folders"
            );
        }
        for name in [
            "TEMP",
            "PSModulePath",
            "ProgramFiles",
            "ProgramData",
            "PROCESSOR_ARCHITECTURE",
            "OS",
        ] {
            assert!(get(name).is_some(), "{name} missing");
        }
        assert!(Path::new(&get("TEMP").unwrap_or_default()).is_absolute());
    }

    #[test]
    fn loader_variables_never_reach_a_child() {
        for name in [
            "COR_PROFILER_PATH",
            "cor_enable_profiling",
            "COMPlus_ETWEnabled",
            "CORECLR_PROFILER",
            "DOTNET_STARTUP_HOOKS",
        ] {
            assert!(is_loader_variable(name), "{name}");
        }
        for name in ["PATH", "TEMP", "DOTNET_ROOT", "CORPORATE"] {
            assert!(!is_loader_variable(name), "{name}");
        }
        // SAFETY: the variables are set for this test only, with names nothing else in the tests
        // reads; Windows' environment functions are safe to call from several threads.
        unsafe {
            std::env::set_var("COR_PROFILER_PATH", r"C:\Users\jdoe\planted.dll");
            std::env::set_var("COMPlus_VigilTestPlanted", "1");
        }
        let env = child_env();
        assert!(
            env.iter().all(|(name, _)| !is_loader_variable(name)),
            "child_env keeps a loader variable"
        );
        let mut command = std::process::Command::new(system_dir().join("cmd.exe"));
        apply_child_env(&mut command);
        let out = command.args(["/d", "/c", "set"]).output().expect("cmd /c set");
        let text = String::from_utf8_lossy(&out.stdout).to_uppercase();
        assert!(
            !text.contains("COR_PROFILER_PATH"),
            "the planted profiler reached the child"
        );
        assert!(!text.contains("COMPLUS_VIGILTESTPLANTED"));
        assert!(
            text.contains("SYSTEMROOT="),
            "the child still gets a working environment"
        );
        let block = child_env_block();
        assert!(block.ends_with(&[0, 0]));
        let text = String::from_utf16_lossy(&block).to_uppercase();
        assert!(!text.contains("COR_PROFILER_PATH"));
    }

    /// Windows PowerShell and the system modules the collectors use work with only the elevated
    /// environment (run by hand: it starts PowerShell).
    #[test]
    #[ignore]
    fn powershell_runs_with_the_elevated_environment() {
        let mut command = std::process::Command::new(system_dir().join(r"WindowsPowerShell\v1.0\powershell.exe"));
        command.env_clear().envs(elevated_env());
        let out = command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "(Get-Command Get-ScheduledTask).Source; (Get-Command Get-NetFirewallRule).Source; \
                 (Get-Command Get-Volume).Source; [IO.Path]::GetTempPath()",
            ])
            .output()
            .expect("powershell");
        let text = String::from_utf8_lossy(&out.stdout);
        println!("{text}");
        assert!(text.contains("ScheduledTasks"), "{text}");
        assert!(text.contains("NetSecurity"), "{text}");
        assert!(text.contains("Storage"), "{text}");
    }

    #[test]
    fn known_folders_come_from_windows() {
        let files = program_files();
        assert!(files.is_dir(), "{}", files.display());
        assert!(program_data().is_dir());
        assert!(program_files_x86().is_absolute());
        assert!(local_app_data().is_some_and(|p| p.is_dir()));
        assert!(profile().is_some_and(|p| p.is_dir()));
        let env = powershell_env();
        let modules = env.iter().find(|(k, _)| k == "PSModulePath").map(|(_, v)| v.clone());
        assert_eq!(modules, Some(powershell_modules().to_string_lossy().into_owned()));
        assert!(powershell_modules().join("Microsoft.PowerShell.Management").is_dir());
    }
}
