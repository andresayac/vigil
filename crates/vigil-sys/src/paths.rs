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
    FOLDERID_ProgramFilesX86, FOLDERID_RoamingAppData, KF_FLAG_DONT_VERIFY, SHGetKnownFolderPath,
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
