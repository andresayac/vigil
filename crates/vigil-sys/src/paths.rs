//! The Windows and System32 folders, from Windows itself.
//!
//! `%SystemRoot%` and `%windir%` come from the process environment, and a user's own environment
//! (`HKCU\Environment`) can override them for programs that user starts, elevated ones included.
//! Paths that decide trust (the Windows folder a guard refuses, the System32 tool Vigil runs, the
//! policy file it reads) therefore come from `GetSystemWindowsDirectoryW` and
//! `GetSystemDirectoryW`, which no environment variable changes.

use std::path::PathBuf;
use std::sync::OnceLock;

use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW};

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
}
