//! Registry values as undo records store them: `{"type": "REG_SZ", "data": ...}`, with binary
//! data as `{"hex": "..."}`. Always the 64-bit view.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_BINARY,
    REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_QWORD, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE,
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

use crate::error::{ActionError, Result, fail};
use vigil_i18n::tr;

/// Which root a key path starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    LocalMachine,
    CurrentUser,
}

impl Hive {
    fn handle(self) -> HKEY {
        match self {
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
            Hive::CurrentUser => HKEY_CURRENT_USER,
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKLM",
            Hive::CurrentUser => "HKCU",
        }
    }

    pub fn long(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKEY_LOCAL_MACHINE",
            Hive::CurrentUser => "HKEY_CURRENT_USER",
        }
    }
}

/// `HKLM\SOFTWARE\...` -> (hive, subkey).
pub fn split_key(key: &str) -> Result<(Hive, String)> {
    let trimmed = key.trim();
    let (hive, sub) = trimmed.split_once('\\').unwrap_or((trimmed, ""));
    let hive = match hive.to_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => Hive::LocalMachine,
        "HKCU" | "HKEY_CURRENT_USER" => Hive::CurrentUser,
        _ => return fail(tr!("unsupported registry key: {0}", key)),
    };
    if sub.is_empty() {
        return fail(tr!("unsupported registry key: {0}", key));
    }
    Ok((hive, sub.to_string()))
}

/// The text of a Windows error code ("Access is denied.").
pub(crate) fn win32_text(code: WIN32_ERROR) -> String {
    let text = windows::core::Error::from(code.to_hresult()).message();
    let text = text.trim();
    if text.is_empty() {
        format!("error {}", code.0)
    } else {
        text.to_string()
    }
}

/// An open registry key, closed when dropped.
pub(crate) struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from RegOpenKeyExW/RegCreateKeyExW and is closed only here.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

impl Key {
    pub(crate) fn open(hive: Hive, sub: &str, access: REG_SAM_FLAGS) -> std::result::Result<Key, WIN32_ERROR> {
        let mut handle = HKEY::default();
        let sub = HSTRING::from(sub);
        // SAFETY: `sub` outlives the call and `handle` is a valid out pointer.
        let status = unsafe { RegOpenKeyExW(hive.handle(), &sub, None, access | KEY_WOW64_64KEY, &mut handle) };
        if status == ERROR_SUCCESS {
            Ok(Key(handle))
        } else {
            Err(status)
        }
    }

    fn create(hive: Hive, sub: &str, access: REG_SAM_FLAGS) -> std::result::Result<Key, WIN32_ERROR> {
        let mut handle = HKEY::default();
        let sub = HSTRING::from(sub);
        // SAFETY: `sub` outlives the call and `handle` is a valid out pointer.
        let status = unsafe {
            RegCreateKeyExW(
                hive.handle(),
                &sub,
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                access | KEY_WOW64_64KEY,
                None,
                &mut handle,
                None,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(Key(handle))
        } else {
            Err(status)
        }
    }

    /// Raw value: (type, bytes). `Ok(None)` when the value does not exist.
    pub(crate) fn query(&self, name: &str) -> std::result::Result<Option<(u32, Vec<u8>)>, WIN32_ERROR> {
        let name = HSTRING::from(name);
        let mut size = 0u32;
        let mut kind = REG_VALUE_TYPE::default();
        loop {
            let mut buffer = vec![0u8; size as usize];
            let data = if size == 0 { None } else { Some(buffer.as_mut_ptr()) };
            // SAFETY: `buffer` holds `size` bytes; the out pointers are valid for the call.
            let status =
                unsafe { RegQueryValueExW(self.0, &name, None, Some(&raw mut kind), data, Some(&raw mut size)) };
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if status == ERROR_MORE_DATA || (status == ERROR_SUCCESS && data.is_none() && size > 0) {
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(status);
            }
            buffer.truncate(size as usize);
            return Ok(Some((kind.0, buffer)));
        }
    }

    /// Every value of the key: (name, type, bytes).
    pub(crate) fn values(&self) -> Vec<(String, u32, Vec<u8>)> {
        let mut out = Vec::new();
        let mut index = 0u32;
        let mut name_cap = 256usize;
        let mut data_cap = 1024usize;
        loop {
            let mut name = vec![0u16; name_cap];
            let mut data = vec![0u8; data_cap];
            let mut name_len = name_cap as u32;
            let mut data_len = data_cap as u32;
            let mut kind = 0u32;
            // SAFETY: the buffers have the capacities passed in `name_len` / `data_len`.
            let status = unsafe {
                RegEnumValueW(
                    self.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&raw mut kind),
                    Some(data.as_mut_ptr()),
                    Some(&raw mut data_len),
                )
            };
            if status == ERROR_MORE_DATA {
                name_cap = (name_cap * 2).min(32_768);
                data_cap = (data_len as usize).max(data_cap * 2);
                if name_cap == 32_768 && data_cap > 64 * 1024 * 1024 {
                    break;
                }
                continue;
            }
            if status == ERROR_NO_MORE_ITEMS || status != ERROR_SUCCESS {
                break;
            }
            name.truncate(name_len as usize);
            data.truncate(data_len as usize);
            out.push((String::from_utf16_lossy(&name), kind, data));
            index += 1;
        }
        out
    }
}

fn wide_bytes_to_string(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

fn multi_sz(data: &[u8]) -> Vec<String> {
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let mut out = Vec::new();
    for part in units.split(|&u| u == 0) {
        if part.is_empty() {
            break;
        }
        out.push(String::from_utf16_lossy(part));
    }
    out
}

/// Registry data as undo records keep it: text, a number, a list of text or bytes.
pub(crate) fn decode_value(kind: u32, data: &[u8]) -> Value {
    match REG_VALUE_TYPE(kind) {
        REG_SZ | REG_EXPAND_SZ => Value::String(wide_bytes_to_string(data)),
        REG_MULTI_SZ => json!(multi_sz(data)),
        REG_DWORD if data.len() >= 4 => json!(u32::from_le_bytes([data[0], data[1], data[2], data[3]])),
        REG_QWORD if data.len() >= 8 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[..8]);
            json!(u64::from_le_bytes(bytes))
        }
        _ => json!({ "hex": hex(data) }),
    }
}

pub(crate) fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn type_name(kind: u32) -> Value {
    let name = match REG_VALUE_TYPE(kind) {
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_DWORD => "REG_DWORD",
        REG_QWORD => "REG_QWORD",
        REG_MULTI_SZ => "REG_MULTI_SZ",
        REG_BINARY => "REG_BINARY",
        _ => return Value::String(kind.to_string()),
    };
    Value::String(name.to_string())
}

fn type_value(name: &Value) -> Option<u32> {
    let text = match name {
        Value::String(text) => text.as_str(),
        Value::Number(number) => return number.as_u64().and_then(|n| u32::try_from(n).ok()),
        _ => return None,
    };
    let kind = match text {
        "REG_SZ" => REG_SZ,
        "REG_EXPAND_SZ" => REG_EXPAND_SZ,
        "REG_DWORD" => REG_DWORD,
        "REG_QWORD" => REG_QWORD,
        "REG_MULTI_SZ" => REG_MULTI_SZ,
        "REG_BINARY" => REG_BINARY,
        other => return other.trim().parse::<u32>().ok(),
    };
    Some(kind.0)
}

/// Value snapshot `{"type": ..., "data": ...}`, or `None` if it does not exist.
pub fn reg_read(key: &str, value: &str) -> Result<Option<Value>> {
    let (hive, sub) = split_key(key)?;
    let handle = match Key::open(hive, &sub, KEY_READ) {
        Ok(handle) => handle,
        Err(status) if status == ERROR_FILE_NOT_FOUND => return Ok(None),
        Err(status) => return fail(tr!("cannot read {0}\\{1}: {2}", key, value, win32_text(status))),
    };
    match handle.query(value) {
        Ok(None) => Ok(None),
        Ok(Some((kind, data))) => Ok(Some(
            json!({ "type": type_name(kind), "data": decode_value(kind, &data) }),
        )),
        Err(status) => fail(tr!("cannot read {0}\\{1}: {2}", key, value, win32_text(status))),
    }
}

fn encode_text(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

fn encode_data(kind: u32, data: &Value) -> Option<Vec<u8>> {
    if let Some(hex_text) = data.get("hex").and_then(Value::as_str) {
        return unhex(hex_text);
    }
    match REG_VALUE_TYPE(kind) {
        REG_DWORD => {
            let number = data.as_i64()?;
            Some((number as u32).to_le_bytes().to_vec())
        }
        REG_QWORD => {
            let number = data.as_u64().or_else(|| data.as_i64().map(|n| n as u64))?;
            Some(number.to_le_bytes().to_vec())
        }
        REG_MULTI_SZ => {
            let mut out: Vec<u8> = Vec::new();
            for item in data.as_array()? {
                out.extend(encode_text(item.as_str()?));
            }
            out.extend([0, 0]);
            Some(out)
        }
        REG_SZ | REG_EXPAND_SZ => Some(encode_text(data.as_str()?)),
        _ => match data {
            Value::String(text) => Some(encode_text(text)),
            Value::Null => Some(Vec::new()),
            _ => None,
        },
    }
}

/// Writes a value from a snapshot (the type is a name such as `REG_SZ` or a number).
pub fn reg_write(key: &str, value: &str, snapshot: &Value) -> Result<()> {
    let (hive, sub) = split_key(key)?;
    let type_field = snapshot.get("type").cloned().unwrap_or(Value::Null);
    let Some(kind) = type_value(&type_field) else {
        let shown = match &type_field {
            Value::String(text) => text.clone(),
            Value::Null => "None".to_string(),
            other => other.to_string(),
        };
        return fail(tr!("unknown registry type {0}", shown));
    };
    let data = snapshot.get("data").cloned().unwrap_or(Value::Null);
    let Some(bytes) = encode_data(kind, &data) else {
        return fail(tr!(
            "cannot write {0}\\{1}: the saved data does not match its type",
            key,
            value
        ));
    };
    let handle = Key::create(hive, &sub, KEY_SET_VALUE)
        .map_err(|s| ActionError::new(tr!("cannot write {0}\\{1}: {2}", key, value, win32_text(s))))?;
    let name = HSTRING::from(value);
    // SAFETY: the key is open with KEY_SET_VALUE and `bytes` outlives the call.
    let status = unsafe { RegSetValueExW(handle.0, &name, None, REG_VALUE_TYPE(kind), Some(&bytes)) };
    if status != ERROR_SUCCESS {
        return fail(tr!("cannot write {0}\\{1}: {2}", key, value, win32_text(status)));
    }
    Ok(())
}

/// Deletes a value (nothing happens when it does not exist).
pub fn reg_delete(key: &str, value: &str) -> Result<()> {
    let (hive, sub) = split_key(key)?;
    let handle = match Key::open(hive, &sub, KEY_SET_VALUE) {
        Ok(handle) => handle,
        Err(status) if status == ERROR_FILE_NOT_FOUND => return Ok(()),
        Err(status) => return fail(tr!("cannot delete {0}\\{1}: {2}", key, value, win32_text(status))),
    };
    let name = HSTRING::from(value);
    // SAFETY: the key is open with KEY_SET_VALUE.
    let status = unsafe { RegDeleteValueW(handle.0, &name) };
    if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
        return fail(tr!("cannot delete {0}\\{1}: {2}", key, value, win32_text(status)));
    }
    Ok(())
}

/// Puts a value back as it was: written from the snapshot, or deleted if it did not exist.
pub fn restore_value(key: &str, value: &str, snapshot: Option<&Value>) -> Result<()> {
    match snapshot {
        None | Some(Value::Null) => reg_delete(key, value),
        Some(snapshot) => reg_write(key, value, snapshot),
    }
}

/// Every value of a key with its data (missing key -> `None`).
pub(crate) fn read_values(hive: Hive, sub: &str) -> std::result::Result<Option<Map<String, Value>>, WIN32_ERROR> {
    let handle = match Key::open(hive, sub, KEY_READ) {
        Ok(handle) => handle,
        Err(status) if status == ERROR_FILE_NOT_FOUND => return Ok(None),
        Err(status) => return Err(status),
    };
    let mut out = Map::new();
    for (name, kind, data) in handle.values() {
        let value = match decode_value(kind, &data) {
            // winreg returns bytes for binary data; the service guard only needs text and numbers.
            Value::Object(_) => Value::Null,
            other => other,
        };
        out.insert(name, value);
    }
    Ok(Some(out))
}

/// Deletes a whole key. Only used for the scratch key of the tests (`HKCU\Software\VigilTests\...`).
pub(crate) fn delete_scratch_tree(sub: &str) -> Result<()> {
    let low = sub.to_lowercase();
    if !(low == "software\\vigiltests" || low.starts_with("software\\vigiltests\\")) {
        return fail("only HKCU\\Software\\VigilTests may be deleted by the tests");
    }
    let handle = match Key::open(Hive::CurrentUser, sub, KEY_ALL_ACCESS) {
        Ok(handle) => handle,
        Err(status) if status == ERROR_FILE_NOT_FOUND => return Ok(()),
        Err(status) => return fail(win32_text(status)),
    };
    drop(handle);
    let wide = HSTRING::from(sub);
    // SAFETY: deletes HKCU\<sub>, which was checked to be under the tests' scratch key.
    let status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, &wide) };
    if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
        return fail(win32_text(status));
    }
    Ok(())
}

/// Registry values that Vigil may delete or change (startup locations only).
type Editable = (Regex, Option<Regex>);

static EDITABLE_VALUES: LazyLock<Vec<Editable>> = LazyLock::new(|| {
    let rules: [(&str, Option<&str>); 6] = [
        (
            r"(?i)^HK(LM|CU)\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|Policies\\Explorer\\Run)$",
            None,
        ),
        (
            r"(?i)^HKLM\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\[^\\]+$",
            Some(r"(?i)^Debugger$"),
        ),
        (
            r"(?i)^HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\[^\\]+$",
            Some(r"(?i)^MonitorProcess$"),
        ),
        (
            r"(?i)^HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows$",
            Some(r"(?i)^(Load|Run)$"),
        ),
        (r"(?i)^HKCU\\Environment$", Some(r"(?i)^UserInitMprLogonScript$")),
        (
            r"(?i)^HK(LM|CU)\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon$",
            Some(r"(?i)^(Shell|Userinit|Taskman|AppSetup|VmApplet)$"),
        ),
    ];
    rules
        .iter()
        .filter_map(|(key, value)| {
            let key = Regex::new(key).ok()?;
            let value = match value {
                Some(pattern) => Some(Regex::new(pattern).ok()?),
                None => None,
            };
            Some((key, value))
        })
        .collect()
});

pub(crate) fn check_editable(key: &str, value: &str) -> Result<()> {
    let matches =
        |(key_rx, value_rx): &Editable| key_rx.is_match(key) && value_rx.as_ref().is_none_or(|rx| rx.is_match(value));
    if EDITABLE_VALUES.iter().any(matches) || crate::testing::extra_editable(key, value) {
        return Ok(());
    }
    fail(tr!(
        "Vigil only edits startup locations; {0}\\{1} is not one of them",
        key,
        value
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_hex() {
        assert!(matches!(
            split_key(r"HKEY_LOCAL_MACHINE\SOFTWARE\x"),
            Ok((Hive::LocalMachine, _))
        ));
        assert!(split_key(r"HKCR\x").is_err());
        assert!(split_key("HKCU").is_err());
        assert_eq!(unhex("0a0B"), Some(vec![10, 11]));
        assert_eq!(hex(&[3, 0, 255]), "0300ff");
    }

    #[test]
    fn only_startup_locations_are_editable() {
        assert!(check_editable(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "x").is_ok());
        assert!(
            check_editable(
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                "x"
            )
            .is_ok()
        );
        assert!(
            check_editable(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\a.exe",
                "Debugger"
            )
            .is_ok()
        );
        assert!(
            check_editable(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\a.exe",
                "Other"
            )
            .is_err()
        );
        assert!(check_editable(r"HKLM\SYSTEM\CurrentControlSet\Services\x", "ImagePath").is_err());
    }
}
