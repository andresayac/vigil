//! Current state of the settings the Optimize page explains (read-only, fast).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows::Win32::System::Power::{ACCESS_SCHEME, PowerEnumerate, PowerGetActiveScheme, PowerReadFriendlyName};
use windows::core::GUID;

use crate::registry::{Hive, read_int, string_values};
use crate::win::lstat;

/// A power plan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct PowerPlan {
    /// Lower case, without braces: "381b4222-f694-41f0-9685-ff5bb260df2e".
    pub guid: String,
    /// As Windows shows it (localized).
    pub name: String,
    pub active: bool,
}

/// Hibernation and the size of `hiberfil.sys`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct Hibernation {
    pub enabled: bool,
    pub file_size: u64,
}

/// Per-app GPU choice from Settings > Display > Graphics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct GpuPreference {
    /// The program, as Windows stores it (a full path, or an app identifier).
    pub exe: String,
    /// 0 = let Windows decide, 1 = power saving, 2 = high performance.
    pub preference: i64,
}

/// The settings the Optimize page can explain. Serialized in camelCase for the UI; parsed
/// from snake_case (the collector's shape, used by the test fixtures).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct TuningState {
    pub power_plans: Vec<PowerPlan>,
    pub hibernation: Hibernation,
    /// On by default since Windows 10 1903: no value means on.
    pub game_mode: bool,
    /// Hardware-accelerated GPU scheduling; None if the driver never set it.
    pub hags: Option<bool>,
    /// Memory integrity (HVCI); None if never configured.
    pub memory_integrity: Option<bool>,
    /// VisualFXSetting: 0 = let Windows choose, 1 = best appearance, 2 = best performance,
    /// 3 = custom; None if never set.
    pub visual_effects: Option<i64>,
    pub gpu_preferences: Vec<GpuPreference>,
}

/// Reads the current state. Never fails: what cannot be read is left empty or None.
pub fn tuning_state() -> TuningState {
    let game_mode = read_int(Hive::CurrentUser, r"Software\Microsoft\GameBar", "AutoGameModeEnabled");
    let hags = read_int(
        Hive::LocalMachine,
        r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
        "HwSchMode",
    );
    let hvci = read_int(
        Hive::LocalMachine,
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        "Enabled",
    );
    TuningState {
        power_plans: power_plans(),
        hibernation: hibernation(),
        game_mode: game_mode.is_none_or(|value| value != 0),
        // HwSchMode: 2 = on, 1 = off.
        hags: hags.map(|value| value == 2),
        memory_integrity: hvci.map(|value| value != 0),
        visual_effects: read_int(
            Hive::CurrentUser,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
            "VisualFXSetting",
        ),
        gpu_preferences: gpu_preferences(),
    }
}

fn guid_text(guid: &GUID) -> String {
    let d4 = guid.data4;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1, guid.data2, guid.data3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    )
}

fn active_scheme() -> Option<String> {
    let mut pointer: *mut GUID = std::ptr::null_mut();
    // SAFETY: `pointer` receives a GUID allocated by Windows, freed below with LocalFree.
    let status = unsafe { PowerGetActiveScheme(None, &mut pointer) };
    if status != ERROR_SUCCESS || pointer.is_null() {
        return None;
    }
    // SAFETY: on success `pointer` points at a valid GUID.
    let text = guid_text(unsafe { &*pointer });
    // SAFETY: frees the buffer PowerGetActiveScheme allocated, exactly once.
    let _ = unsafe { LocalFree(Some(HLOCAL(pointer.cast()))) };
    Some(text)
}

fn friendly_name(guid: &GUID) -> String {
    let mut size = 0u32;
    // SAFETY: a null buffer asks for the size only; `guid` and `size` are valid.
    let status = unsafe { PowerReadFriendlyName(None, Some(guid), None, None, None, &mut size) };
    if status != ERROR_SUCCESS || size == 0 {
        return String::new();
    }
    let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
    let mut bytes = (buffer.len() * 2) as u32;
    // SAFETY: `buffer` is writable and `bytes` holds its size in bytes.
    let status = unsafe {
        PowerReadFriendlyName(
            None,
            Some(guid),
            None,
            None,
            Some(buffer.as_mut_ptr().cast()),
            &mut bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return String::new();
    }
    crate::win::from_wide(&buffer).trim().to_string()
}

/// Power plans through powrprof: localized names as Windows shows them, no console output to
/// parse.
fn power_plans() -> Vec<PowerPlan> {
    let active = active_scheme().unwrap_or_default();
    let mut plans = Vec::new();
    for index in 0..64u32 {
        let mut guid = GUID::zeroed();
        let mut size = size_of::<GUID>() as u32;
        // SAFETY: `guid` is a writable GUID and `size` holds its size in bytes.
        let status = unsafe {
            PowerEnumerate(
                None,
                None,
                None,
                ACCESS_SCHEME,
                index,
                Some((&mut guid as *mut GUID).cast()),
                &mut size,
            )
        };
        if status != ERROR_SUCCESS {
            break; // ERROR_NO_MORE_ITEMS
        }
        let text = guid_text(&guid);
        let name = friendly_name(&guid);
        plans.push(PowerPlan {
            name: if name.is_empty() { text.clone() } else { name },
            active: text == active,
            guid: text,
        });
    }
    plans
}

fn hibernation() -> Hibernation {
    let enabled = read_int(
        Hive::LocalMachine,
        r"SYSTEM\CurrentControlSet\Control\Power",
        "HibernateEnabled",
    );
    let drive = std::env::var("SystemDrive")
        .ok()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "C:".to_string());
    // The file itself is locked: its size comes from the directory entry.
    let file_size = lstat(&PathBuf::from(format!("{drive}\\hiberfil.sys")))
        .map(|e| e.size)
        .unwrap_or(0);
    Hibernation {
        enabled: enabled.map_or(file_size > 0, |value| value != 0),
        file_size,
    }
}

/// "GpuPreference=2;" -> 2.
fn parse_preference(data: &str) -> Option<i64> {
    let start = data.find("GpuPreference=")? + "GpuPreference=".len();
    let digits: String = data[start..].chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

fn gpu_preferences() -> Vec<GpuPreference> {
    string_values(Hive::CurrentUser, r"Software\Microsoft\DirectX\UserGpuPreferences")
        .into_iter()
        .filter(|(name, _)| name != "DirectXUserGlobalSettings")
        .filter_map(|(exe, data)| parse_preference(&data).map(|preference| GpuPreference { exe, preference }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gpu_preference_values() {
        assert_eq!(parse_preference("GpuPreference=2;"), Some(2));
        assert_eq!(parse_preference("SwapEffectUpgradeEnable=1;GpuPreference=1;"), Some(1));
        assert_eq!(parse_preference("SwapEffectUpgradeEnable=1;"), None);
        assert_eq!(parse_preference("GpuPreference=;"), None);
    }

    #[test]
    fn guid_text_is_lower_case_without_braces() {
        let guid = GUID::from_u128(0xa1841308_3541_4fab_bc81_f71556f20b4a);
        assert_eq!(guid_text(&guid), "a1841308-3541-4fab-bc81-f71556f20b4a");
    }

    #[test]
    fn reads_this_pc() {
        let state = tuning_state();
        assert!(state.power_plans.iter().filter(|plan| plan.active).count() <= 1);
        assert!(
            state
                .power_plans
                .iter()
                .all(|plan| plan.guid.len() == 36 && !plan.name.is_empty())
        );
        let json = serde_json::to_value(&state).unwrap();
        assert!(json.get("powerPlans").is_some() && json.get("gpuPreferences").is_some());
        assert!(json["hibernation"].get("fileSize").is_some());
    }
}
