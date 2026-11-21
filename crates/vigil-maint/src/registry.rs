//! Read-only registry access (64-bit view).

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_DWORD, REG_DWORD_BIG_ENDIAN,
    REG_EXPAND_SZ, REG_QWORD, REG_SZ, REG_VALUE_TYPE, RRF_RT_ANY, RRF_SUBKEY_WOW6464KEY, RegCloseKey, RegEnumValueW,
    RegGetValueW, RegOpenKeyExW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::win::{from_wide, wide};

#[derive(Clone, Copy)]
pub(crate) enum Hive {
    LocalMachine,
    CurrentUser,
}

impl Hive {
    fn key(self) -> HKEY {
        match self {
            Self::LocalMachine => HKEY_LOCAL_MACHINE,
            Self::CurrentUser => HKEY_CURRENT_USER,
        }
    }
}

/// An integer value (REG_DWORD or REG_QWORD), or None if missing or of another type, like
/// A registry value that is not a DWORD/QWORD.
pub(crate) fn read_int(hive: Hive, subkey: &str, name: &str) -> Option<i64> {
    let subkey = wide(subkey);
    let name = wide(name);
    let mut kind = REG_VALUE_TYPE(0);
    let mut data = [0u8; 8];
    let mut size = data.len() as u32;
    // SAFETY: the strings are null-terminated; `data` and `size` describe a writable buffer.
    let status = unsafe {
        RegGetValueW(
            hive.key(),
            PCWSTR(subkey.as_ptr()),
            PCWSTR(name.as_ptr()),
            RRF_RT_ANY | RRF_SUBKEY_WOW6464KEY,
            Some(&mut kind),
            Some(data.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    match kind {
        REG_DWORD if size >= 4 => Some(i64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))),
        REG_DWORD_BIG_ENDIAN if size >= 4 => Some(i64::from(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))),
        REG_QWORD if size >= 8 => Some(i64::from_le_bytes(data)),
        _ => None,
    }
}

/// Every string value of a key, as (name, text), in registry order. Empty if the key is missing.
pub(crate) fn string_values(hive: Hive, subkey: &str) -> Vec<(String, String)> {
    let path = wide(subkey);
    let mut key = HKEY::default();
    // SAFETY: `path` is null-terminated and `key` receives the opened handle.
    let status = unsafe {
        RegOpenKeyExW(
            hive.key(),
            PCWSTR(path.as_ptr()),
            None,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if status != ERROR_SUCCESS {
        return Vec::new();
    }
    let mut out = Vec::new();
    for index in 0..10_000u32 {
        let mut name = vec![0u16; 16_384];
        let mut name_len = name.len() as u32;
        let mut data = vec![0u8; 65_536];
        let mut data_len = data.len() as u32;
        let mut kind = 0u32;
        // SAFETY: every buffer is writable and its length is passed alongside it.
        let status = unsafe {
            RegEnumValueW(
                key,
                index,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut kind),
                Some(data.as_mut_ptr()),
                Some(&mut data_len),
            )
        };
        if status != ERROR_SUCCESS {
            break; // ERROR_NO_MORE_ITEMS, or a value too large to matter here
        }
        let kind = REG_VALUE_TYPE(kind);
        if kind != REG_SZ && kind != REG_EXPAND_SZ {
            continue;
        }
        let units: Vec<u16> = data[..data_len as usize]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        out.push((from_wide(&name[..name_len as usize]), from_wide(&units)));
    }
    // SAFETY: closes the key opened above, exactly once.
    let _ = unsafe { RegCloseKey(key) };
    out
}
