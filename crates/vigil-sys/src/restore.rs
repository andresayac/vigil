//! System Restore, read only: the restore points, which drives System Protection covers, how much
//! space it uses and may use, and the policies that turn it off.
//!
//! The restore points (WMI `root\default:SystemRestore`) and the shadow storage
//! (`Win32_ShadowStorage`) can be read only with administrator rights; which drives are protected
//! comes from the registry and needs none.

use serde::Serialize;
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY};

use crate::defender::{self, Row, Val};
use crate::hooks::{Key, text};
use crate::util::hklm_dword;

/// What Vigil writes as the description of the restore points it makes ("Vigil", or
/// "Vigil: <what the user typed>").
pub const VIGIL_PREFIX: &str = "Vigil";

/// The registry value listing the volumes System Protection covers.
const SPP_CLIENTS: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients";
const SPP_VALUE: &str = "{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}";
const SR_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore";
const SR_SETTINGS: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore";
/// Windows makes at most one restore point every 24 hours unless this is set (in minutes).
pub const DEFAULT_FREQUENCY_MINUTES: u32 = 1440;

/// One restore point.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestorePoint {
    pub sequence: u32,
    pub description: String,
    /// "install", "uninstall", "driver", "settings", "checkpoint", "restore", "cancelled",
    /// "backup" or "other".
    pub kind: String,
    /// Milliseconds since 1970-01-01 UTC (0 when unreadable).
    pub created_ms: i64,
    /// Made by Vigil (its description starts with "Vigil").
    pub vigil: bool,
}

/// The space System Protection uses on one drive (`None`: not readable).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShadowStorage {
    /// "C:".
    pub drive: String,
    pub used: u64,
    pub allocated: u64,
    /// `None`: no limit.
    pub max: Option<u64>,
}

/// Everything the Restore points page shows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreState {
    /// Newest first.
    pub points: Vec<RestorePoint>,
    /// False without administrator rights (the list is then empty, not "none").
    pub points_readable: bool,
    /// Drives System Protection covers ("C:"), from the registry.
    pub protected: Vec<String>,
    /// False when that registry key cannot be read (it needs administrator rights on some
    /// Windows versions): `protected` is then unknown, not empty.
    pub protected_readable: bool,
    pub storage: Vec<ShadowStorage>,
    pub storage_readable: bool,
    /// A policy turns System Restore off.
    pub off_by_policy: bool,
    /// A policy hides its settings.
    pub config_locked: bool,
    /// The shortest time Windows keeps between two restore points, in minutes.
    pub frequency_minutes: u32,
    pub problem: String,
}

/// The kind of a `RestorePointType`.
pub fn kind_name(code: i64) -> &'static str {
    match code {
        0 => "install",
        1 => "uninstall",
        6 => "restore",
        7 => "checkpoint",
        10 => "driver",
        12 => "settings",
        13 => "cancelled",
        14 => "backup",
        _ => "other",
    }
}

/// A CIM datetime (`20261121193000.000000-300`: local time and its offset in minutes from UTC)
/// as Unix milliseconds.
pub fn cim_datetime_ms(value: &str) -> Option<i64> {
    let value = value.trim();
    let digits = |range: std::ops::Range<usize>| value.get(range).filter(|s| s.bytes().all(|b| b.is_ascii_digit()));
    let iso = format!(
        "{}-{}-{}T{}:{}:{}",
        digits(0..4)?,
        digits(4..6)?,
        digits(6..8)?,
        digits(8..10)?,
        digits(10..12)?,
        digits(12..14)?
    );
    let local = crate::reliability::iso_utc_ms(&iso)?;
    let offset = value
        .get(21..25)
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(0);
    Some(local - offset * 60_000)
}

fn row_text(row: &Row, name: &str) -> String {
    match row.get(name) {
        Some(Val::Text(s)) => s.trim().to_string(),
        Some(Val::Int(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn row_u64(row: &Row, name: &str) -> Option<u64> {
    match row.get(name) {
        Some(Val::Int(n)) => u64::try_from(*n).ok(),
        Some(Val::Text(s)) => s.trim().parse().ok(),
        _ => None,
    }
}

/// A restore point from its WMI row.
pub fn point_from(row: &Row) -> RestorePoint {
    let description = row_text(row, "Description");
    RestorePoint {
        sequence: row_u64(row, "SequenceNumber")
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0),
        kind: kind_name(row_u64(row, "RestorePointType").map_or(-1, |n| n as i64)).to_string(),
        created_ms: cim_datetime_ms(&row_text(row, "CreationTime")).unwrap_or(0),
        vigil: description == VIGIL_PREFIX || description.starts_with(&format!("{VIGIL_PREFIX}:")),
        description,
    }
}

/// The drive letters in System Protection's list: entries look like
/// `\\?\Volume{…}\:(C%3A)`.
pub fn protected_from(list: &str) -> Vec<String> {
    let mut out: Vec<String> = list
        .split(';')
        .filter_map(|entry| {
            let start = entry.rfind('(')?;
            let inner = entry.get(start + 1..)?;
            let letter = inner.chars().next()?;
            (letter.is_ascii_alphabetic() && inner[1..].to_ascii_uppercase().starts_with("%3A"))
                .then(|| format!("{}:", letter.to_ascii_uppercase()))
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The shadow storage of each drive, from `Win32_ShadowStorage` and `Win32_Volume` rows.
pub fn storage_from(storage: &[Row], volumes: &[Row]) -> Vec<ShadowStorage> {
    let letter_of = |reference: &str| -> Option<String> {
        // `Win32_Volume.DeviceID="\\\\?\\Volume{…}\\"`: the id is between the quotes, with
        // its backslashes doubled.
        let id = reference.split_once('"')?.1.rsplit_once('"')?.0.replace(r"\\", r"\");
        volumes
            .iter()
            .find(|v| row_text(v, "DeviceID").eq_ignore_ascii_case(&id))
            .map(|v| row_text(v, "DriveLetter"))
            .filter(|l| !l.is_empty())
    };
    let mut out: Vec<ShadowStorage> = storage
        .iter()
        .filter_map(|row| {
            let drive = letter_of(&row_text(row, "Volume"))?;
            Some(ShadowStorage {
                drive: drive.to_ascii_uppercase(),
                used: row_u64(row, "UsedSpace").unwrap_or(0),
                allocated: row_u64(row, "AllocatedSpace").unwrap_or(0),
                // UINT64_MAX means "no limit".
                max: row_u64(row, "MaxSpace").filter(|&m| m != u64::MAX),
            })
        })
        .collect();
    out.sort_by(|a, b| a.drive.cmp(&b.drive));
    out
}

/// The protected drives; `None` when the key cannot be read (a missing key means none).
fn protected_drives() -> Option<Vec<String>> {
    let key = match Key::open(HKEY_LOCAL_MACHINE, SPP_CLIENTS, KEY_WOW64_64KEY) {
        Ok(Some(key)) => key,
        Ok(None) => return Some(Vec::new()),
        Err(()) => return None,
    };
    let values = key.raw_values()?;
    Some(
        values
            .into_iter()
            .find(|(name, _, _)| name.eq_ignore_ascii_case(SPP_VALUE))
            .map(|(_, kind, data)| protected_from(&text(kind, &data)))
            .unwrap_or_default(),
    )
}

/// Reads the state; the WMI parts only with administrator rights (they answer slowly with an
/// access error otherwise).
pub fn read(elevated: bool) -> RestoreState {
    let protected = protected_drives();
    let mut state = RestoreState {
        protected_readable: protected.is_some(),
        protected: protected.unwrap_or_default(),
        off_by_policy: hklm_dword(SR_POLICY, "DisableSR") == Some(1),
        config_locked: hklm_dword(SR_POLICY, "DisableConfig") == Some(1),
        frequency_minutes: hklm_dword(SR_SETTINGS, "SystemRestorePointCreationFrequency")
            .unwrap_or(DEFAULT_FREQUENCY_MINUTES),
        ..Default::default()
    };
    if !elevated {
        return state;
    }
    // SAFETY: COM for this thread only; balanced below when it succeeded.
    let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
    match defender::connect(r"ROOT\DEFAULT").and_then(|services| {
        defender::query(
            &services,
            "SystemRestore",
            &["SequenceNumber", "Description", "RestorePointType", "CreationTime"],
            500,
        )
    }) {
        Ok(rows) => {
            state.points_readable = true;
            state.points = rows.iter().map(point_from).collect();
            state
                .points
                .sort_by(|a, b| b.created_ms.cmp(&a.created_ms).then(b.sequence.cmp(&a.sequence)));
        }
        Err(error) => state.problem = error.to_string(),
    }
    if let Ok(services) = defender::connect(r"ROOT\CIMV2") {
        let storage = defender::query(
            &services,
            "Win32_ShadowStorage",
            &["Volume", "UsedSpace", "AllocatedSpace", "MaxSpace"],
            64,
        );
        let volumes = defender::query(&services, "Win32_Volume", &["DeviceID", "DriveLetter"], 128);
        if let (Ok(storage), Ok(volumes)) = (storage, volumes) {
            state.storage_readable = true;
            state.storage = storage_from(&storage, &volumes);
        }
    }
    if initialized {
        // SAFETY: balances the successful CoInitializeEx above; every interface was released.
        unsafe { CoUninitialize() };
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pairs: &[(&str, Val)]) -> Row {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn restore_points_are_read_from_their_rows() {
        let vigil = point_from(&row(&[
            ("SequenceNumber", Val::Int(42)),
            ("Description", Val::Text("Vigil".into())),
            ("RestorePointType", Val::Int(12)),
            ("CreationTime", Val::Text("20261121193000.000000-000".into())),
        ]));
        assert_eq!(vigil.sequence, 42);
        assert_eq!(vigil.kind, "settings");
        assert!(vigil.vigil);
        assert_eq!(
            vigil.created_ms,
            crate::reliability::iso_utc_ms("2026-11-21T19:30:00Z").unwrap()
        );

        let typed = point_from(&row(&[
            ("Description", Val::Text("Vigil: before the driver update".into())),
            ("RestorePointType", Val::Int(10)),
        ]));
        assert!(typed.vigil);
        assert_eq!(typed.kind, "driver");
        assert_eq!(typed.created_ms, 0);

        let windows = point_from(&row(&[
            ("Description", Val::Text("Windows Update".into())),
            ("RestorePointType", Val::Int(0)),
            ("CreationTime", Val::Text("20261120080000.000000-300".into())),
        ]));
        assert!(!windows.vigil);
        assert_eq!(windows.kind, "install");
        // 08:00 at UTC−5 is 13:00 UTC.
        assert_eq!(
            windows.created_ms,
            crate::reliability::iso_utc_ms("2026-11-20T13:00:00Z").unwrap()
        );
        assert!(!point_from(&row(&[("Description", Val::Text("Vigilant app".into()))])).vigil);
        assert_eq!(kind_name(99), "other");
        assert_eq!(cim_datetime_ms("not a date"), None);
    }

    #[test]
    fn protected_drives_and_storage_are_read() {
        let list = r"\\?\Volume{0a1b}\:(C%3A); \\?\Volume{2c3d}\:(d%3A); garbage";
        assert_eq!(protected_from(list), vec!["C:".to_string(), "D:".to_string()]);
        assert!(protected_from("").is_empty());

        let storage = [
            row(&[
                (
                    "Volume",
                    Val::Text(r#"Win32_Volume.DeviceID="\\\\?\\Volume{0a1b}\\""#.into()),
                ),
                ("UsedSpace", Val::Text("1073741824".into())),
                ("AllocatedSpace", Val::Text("2147483648".into())),
                ("MaxSpace", Val::Text("18446744073709551615".into())),
            ]),
            row(&[
                (
                    "Volume",
                    Val::Text(r#"Win32_Volume.DeviceID="\\\\?\\Volume{9999}\\""#.into()),
                ),
                ("UsedSpace", Val::Text("1".into())),
            ]),
        ];
        let volumes = [row(&[
            ("DeviceID", Val::Text(r"\\?\Volume{0a1b}\".into())),
            ("DriveLetter", Val::Text("c:".into())),
        ])];
        let read = storage_from(&storage, &volumes);
        assert_eq!(read.len(), 1, "a volume without a letter is left out");
        assert_eq!(read[0].drive, "C:");
        assert_eq!(read[0].used, 1 << 30);
        assert_eq!(read[0].allocated, 2 << 30);
        assert_eq!(read[0].max, None, "UINT64_MAX means no limit");
    }

    /// Reads this computer's state (counts only). `cargo test -p vigil-sys restore -- --ignored --nocapture`
    #[test]
    #[ignore = "reads this computer"]
    fn live_read() {
        let state = read(crate::elevation::is_elevated());
        println!(
            "points readable {} ({} points, {} by Vigil), protected readable {} ({} drives), storage readable {} ({}), policy off {}, frequency {} min",
            state.points_readable,
            state.points.len(),
            state.points.iter().filter(|p| p.vigil).count(),
            state.protected_readable,
            state.protected.len(),
            state.storage_readable,
            state.storage.len(),
            state.off_by_policy,
            state.frequency_minutes
        );
    }
}
