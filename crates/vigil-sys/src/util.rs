//! Small helpers: UTF-16 strings, times and registry values.

use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_ROUTINE_FLAGS, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
};
use windows::core::PCWSTR;

/// 1970-01-01 in 100 ns units since 1601 (the FILETIME epoch).
pub(crate) const EPOCH_AS_FILETIME: i64 = 116_444_736_000_000_000;

/// A NUL-terminated UTF-16 copy of `text` for Win32 calls.
pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// UTF-16 up to the first NUL (or the whole slice), lossy.
pub(crate) fn from_wide(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// FILETIME (100 ns since 1601) to milliseconds since the Unix epoch; 0 stays 0.
pub(crate) fn filetime_to_unix_ms(raw: i64) -> i64 {
    if raw <= 0 {
        0
    } else {
        (raw - EPOCH_AS_FILETIME) / 10_000
    }
}

pub(crate) fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn reg_get(key: HKEY, subkey: &str, value: &str, flags: REG_ROUTINE_FLAGS, data: &mut [u8]) -> Option<usize> {
    let subkey = wide(subkey);
    let value = wide(value);
    let mut size = data.len() as u32;
    // SAFETY: the strings are NUL-terminated and outlive the call; `data` is writable for `size` bytes.
    let status = unsafe {
        RegGetValueW(
            key,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            flags,
            None,
            Some(data.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    status.is_ok().then_some(size as usize)
}

/// A REG_SZ value under HKEY_LOCAL_MACHINE, trimmed ("" when missing).
pub(crate) fn hklm_string(subkey: &str, value: &str) -> String {
    reg_string(HKEY_LOCAL_MACHINE, subkey, value)
}

/// A REG_SZ value under HKEY_CURRENT_USER, trimmed ("" when missing).
pub(crate) fn hkcu_string(subkey: &str, value: &str) -> String {
    reg_string(HKEY_CURRENT_USER, subkey, value)
}

fn reg_string(key: HKEY, subkey: &str, value: &str) -> String {
    let mut data = vec![0u8; 1024];
    match reg_get(key, subkey, value, RRF_RT_REG_SZ, &mut data) {
        Some(size) => {
            let units: Vec<u16> = data[..size.min(data.len())]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&pair| u16::from_le_bytes(pair))
                .collect();
            from_wide(&units).trim().to_string()
        }
        None => String::new(),
    }
}

/// A REG_DWORD value under HKEY_LOCAL_MACHINE.
pub(crate) fn hklm_dword(subkey: &str, value: &str) -> Option<u32> {
    let mut data = [0u8; 4];
    reg_get(HKEY_LOCAL_MACHINE, subkey, value, RRF_RT_REG_DWORD, &mut data)
        .filter(|&size| size == 4)
        .map(|_| u32::from_le_bytes(data))
}

/// Number of logical processors in every processor group.
pub(crate) fn logical_processors() -> u32 {
    const ALL_PROCESSOR_GROUPS: u16 = 0xFFFF;
    // SAFETY: no pointers are involved.
    let count = unsafe { windows::Win32::System::Threading::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
    count.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_round_trip() {
        let units = wide("C:\\Windows");
        assert_eq!(units.last(), Some(&0));
        assert_eq!(from_wide(&units), "C:\\Windows");
    }

    #[test]
    fn filetime_conversion() {
        assert_eq!(filetime_to_unix_ms(0), 0);
        assert_eq!(filetime_to_unix_ms(EPOCH_AS_FILETIME), 0);
        assert_eq!(filetime_to_unix_ms(EPOCH_AS_FILETIME + 10_000_000), 1_000);
    }

    #[test]
    fn cpu_registry_values_are_readable() {
        let key = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0";
        assert!(!hklm_string(key, "ProcessorNameString").is_empty());
        assert!(hklm_dword(key, "~MHz").unwrap_or(0) > 0);
        assert!(hklm_string(key, "NoSuchValue").is_empty());
    }
}
