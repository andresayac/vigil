//! Read-only registry access with stable conversions of the value types
//! (strings, lists of strings, integers, bytes).

use serde_json::{Value, json};

use crate::lenient::bytes_literal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hive {
    Hklm,
    Hkcu,
}

impl Hive {
    pub(crate) fn short(self) -> &'static str {
        match self {
            Self::Hklm => "HKLM",
            Self::Hkcu => "HKCU",
        }
    }
}

/// Registry view: the 64-bit one, or the 32-bit one (WOW6432Node).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum View {
    V64,
    V32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RegData {
    None,
    Str(String),
    Multi(Vec<String>),
    Int(u64),
    Bytes(Vec<u8>),
}

impl RegData {
    /// Truthiness of the converted value.
    pub(crate) fn truthy(&self) -> bool {
        match self {
            Self::None => false,
            Self::Str(s) => !s.is_empty(),
            Self::Multi(items) => !items.is_empty(),
            Self::Int(n) => *n != 0,
            Self::Bytes(b) => !b.is_empty(),
        }
    }

    /// `value == number`.
    pub(crate) fn eq_int(&self, number: u64) -> bool {
        matches!(self, Self::Int(n) if *n == number)
    }

    /// `_as_text(value)`: lists joined with spaces, `None` empty, anything else `str()`.
    pub(crate) fn as_text(&self) -> String {
        match self {
            Self::None => String::new(),
            Self::Str(s) => s.clone(),
            Self::Multi(items) => items
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join(" "),
            Self::Int(n) => n.to_string(),
            Self::Bytes(b) => bytes_literal(b),
        }
    }

    /// JSON form (bytes as a quoted literal, the way reports keep them).
    pub(crate) fn to_value(&self) -> Value {
        match self {
            Self::None => Value::Null,
            Self::Str(s) => json!(s),
            Self::Multi(items) => json!(items),
            Self::Int(n) => json!(n),
            Self::Bytes(b) => json!(bytes_literal(b)),
        }
    }
}

/// `values.get(name)` over an ordered list of values.
pub(crate) fn get<'a>(values: &'a [(String, RegData)], name: &str) -> Option<&'a RegData> {
    values.iter().find(|(n, _)| n == name).map(|(_, d)| d)
}

/// Readable path of a key, with WOW6432Node for the 32-bit view.
pub(crate) fn display(hive: Hive, key: &str, view: View) -> String {
    if view == View::V32 && hive == Hive::Hklm && key.to_uppercase().starts_with("SOFTWARE\\") {
        return format!(
            "{}\\SOFTWARE\\WOW6432Node\\{}",
            hive.short(),
            crate::lenient::skip(key, "SOFTWARE\\".len())
        );
    }
    format!("{}\\{key}", hive.short())
}

#[cfg(windows)]
mod imp {
    use super::{Hive, RegData, View};
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_DWORD,
        REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW, RegEnumValueW,
        RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW,
    };
    use windows::core::{PCWSTR, PWSTR};

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// An open key, closed when dropped.
    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by RegOpenKeyExW and is closed once.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    fn open(hive: Hive, key: &str, view: View) -> Option<Key> {
        let root = match hive {
            Hive::Hklm => HKEY_LOCAL_MACHINE,
            Hive::Hkcu => HKEY_CURRENT_USER,
        };
        let access = KEY_READ
            | if view == View::V64 {
                KEY_WOW64_64KEY
            } else {
                KEY_WOW64_32KEY
            };
        let name = wide(key);
        let mut handle = HKEY::default();
        // SAFETY: `name` is NUL-terminated and outlives the call; `handle` receives the key.
        let status = unsafe { RegOpenKeyExW(root, PCWSTR(name.as_ptr()), None, access, &mut handle) };
        (status == ERROR_SUCCESS).then_some(Key(handle))
    }

    fn convert(kind: REG_VALUE_TYPE, data: &[u8]) -> RegData {
        let units = || -> Vec<u16> { data.as_chunks::<2>().0.iter().map(|&p| u16::from_le_bytes(p)).collect() };
        match kind {
            REG_SZ | REG_EXPAND_SZ => {
                let units = units();
                let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
                RegData::Str(String::from_utf16_lossy(&units[..end]))
            }
            REG_MULTI_SZ => {
                let units = units();
                let mut out = Vec::new();
                for part in units.split(|&u| u == 0) {
                    if part.is_empty() {
                        break;
                    }
                    out.push(String::from_utf16_lossy(part));
                }
                RegData::Multi(out)
            }
            REG_DWORD if data.len() >= 4 => {
                RegData::Int(u64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]])))
            }
            REG_QWORD if data.len() >= 8 => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[..8]);
                RegData::Int(u64::from_le_bytes(bytes))
            }
            REG_DWORD | REG_QWORD => RegData::Int(0),
            _ if data.is_empty() => RegData::None,
            _ => RegData::Bytes(data.to_vec()),
        }
    }

    /// Registry data of any type and length (odd byte counts, no terminator, empty) converts
    /// without a panic.
    #[cfg(test)]
    #[test]
    fn any_registry_data_converts() {
        use crate::fuzz::{Rng, check};
        use windows::Win32::System::Registry::{REG_BINARY, REG_LINK};
        let mut rng = Rng::new(30);
        let kinds = [
            REG_SZ,
            REG_EXPAND_SZ,
            REG_MULTI_SZ,
            REG_DWORD,
            REG_QWORD,
            REG_BINARY,
            REG_LINK,
            REG_VALUE_TYPE(99),
        ];
        for _ in 0..4_000 {
            let kind = kinds[rng.below(kinds.len())];
            let data = rng.bytes(300);
            check("registry data", &data, || {
                let _ = convert(kind, &data);
            });
        }
    }

    fn sizes(key: &Key) -> (u32, u32, u32) {
        let (mut max_subkey, mut max_name, mut max_data) = (0u32, 0u32, 0u32);
        // SAFETY: the out-pointers are valid for the duration of the call.
        unsafe {
            let _ = RegQueryInfoKeyW(
                key.0,
                None,
                None,
                None,
                None,
                Some(&mut max_subkey),
                None,
                None,
                Some(&mut max_name),
                Some(&mut max_data),
                None,
                None,
            );
        }
        (max_subkey, max_name, max_data)
    }

    pub(crate) fn values(hive: Hive, key: &str, view: View) -> Vec<(String, RegData)> {
        let Some(key) = open(hive, key, view) else {
            return Vec::new();
        };
        let (_, max_name, max_data) = sizes(&key);
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name = vec![0u16; max_name as usize + 2];
            let mut data = vec![0u8; max_data as usize + 8];
            let mut name_len = name.len() as u32;
            let mut data_len = data.len() as u32;
            let mut kind = 0u32;
            // SAFETY: the buffers are writable for the lengths passed in.
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
            if status != ERROR_SUCCESS {
                break;
            }
            let name = String::from_utf16_lossy(&name[..(name_len as usize).min(name.len())]);
            let data = &data[..(data_len as usize).min(data.len())];
            out.push((name, convert(REG_VALUE_TYPE(kind), data)));
            index += 1;
        }
        out
    }

    pub(crate) fn subkeys(hive: Hive, key: &str, view: View) -> Vec<String> {
        let Some(key) = open(hive, key, view) else {
            return Vec::new();
        };
        let (max_subkey, _, _) = sizes(&key);
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name = vec![0u16; max_subkey as usize + 2];
            let mut name_len = name.len() as u32;
            // SAFETY: the buffer is writable for the length passed in.
            let status = unsafe {
                RegEnumKeyExW(
                    key.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut name_len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if status != ERROR_SUCCESS {
                break;
            }
            out.push(String::from_utf16_lossy(&name[..(name_len as usize).min(name.len())]));
            index += 1;
        }
        out
    }

    pub(crate) fn value(hive: Hive, key: &str, name: &str, view: View) -> Option<RegData> {
        let key = open(hive, key, view)?;
        let name = wide(name);
        let mut size = 0u32;
        let mut kind = REG_VALUE_TYPE::default();
        // SAFETY: first call only asks for the size and type.
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
        if status != ERROR_SUCCESS {
            return None;
        }
        let mut data = vec![0u8; size as usize + 8];
        let mut size = data.len() as u32;
        // SAFETY: the buffer is writable for `size` bytes.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut kind),
                Some(data.as_mut_ptr()),
                Some(&mut size),
            )
        };
        (status == ERROR_SUCCESS).then(|| convert(kind, &data[..(size as usize).min(data.len())]))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{Hive, RegData, View};
    pub(crate) fn values(_: Hive, _: &str, _: View) -> Vec<(String, RegData)> {
        Vec::new()
    }
    pub(crate) fn subkeys(_: Hive, _: &str, _: View) -> Vec<String> {
        Vec::new()
    }
    pub(crate) fn value(_: Hive, _: &str, _: &str, _: View) -> Option<RegData> {
        None
    }
}

/// Every value of a key (empty when it does not exist or cannot be read).
pub(crate) fn values(hive: Hive, key: &str, view: View) -> Vec<(String, RegData)> {
    imp::values(hive, key, view)
}

/// Names of the subkeys of a key.
pub(crate) fn subkeys(hive: Hive, key: &str, view: View) -> Vec<String> {
    imp::subkeys(hive, key, view)
}

/// One value (`None` when it does not exist or cannot be read).
pub(crate) fn value(hive: Hive, key: &str, name: &str, view: View) -> Option<RegData> {
    imp::value(hive, key, name, view)
}
