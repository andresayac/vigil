//! Hardware inventory: CPU, memory modules, GPUs, physical disks and their health counters,
//! board, BIOS, OS, battery, page file and TRIM, collected by a read-only PowerShell script.
//!
//! The script is embedded in the binary and fed to PowerShell through standard input: no
//! script file is written to disk, so nothing can swap it between writing and running (the app
//! may run elevated). The result comes back on standard output as ASCII-only JSON, which does
//! not depend on the console code page.
//!
//! Field names are parsed in the script's snake_case and serialized in camelCase for the UI.
//! Values the script could not read are None; the reason is in `notes`.

use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::error::{MaintError, MaintErrorKind};
use crate::win::{powershell_path, run_hidden};
use vigil_i18n::tr;

const HARDWARE_PS1: &str = include_str!("../scripts/hardware.ps1");
const COMMON_PS1: &str = include_str!("../scripts/_common.ps1");
const INCLUDE_LINE: &str = ". \"$PSScriptRoot\\_common.ps1\"";
const MARKER: &str = "VIGIL-JSON:";
const TIMEOUT: Duration = Duration::from_secs(120);

/// Writes the result to standard output instead of a file, as pure ASCII (`\uXXXX` escapes).
const STDOUT_WRITER: &str = r#"
function Write-JsonFile {
    param([string]$Path, $Data)
    $json = ConvertTo-Json -InputObject $Data -Depth 8 -Compress
    $ascii = [regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
    [Console]::Out.Write("`n" + 'VIGIL-JSON:' + $ascii + "`n")
}
"#;

// --------------------------------------------------------------------------- lenient parsing

/// PowerShell output is loosely typed: numbers can arrive as text or with decimals, text as
/// numbers. A wrong type becomes None (or the default) instead of failing the whole inventory.
mod lenient {
    use super::{Deserialize, Deserializer, Value};

    fn integer(value: &Value) -> Option<i64> {
        match value {
            Value::Number(number) => number
                .as_i64()
                .or_else(|| number.as_f64().filter(|f| f.is_finite()).map(|f| f as i64)),
            Value::String(text) => text.trim().parse::<i64>().ok(),
            Value::Bool(flag) => Some(i64::from(*flag)),
            _ => None,
        }
    }

    fn text(value: &Value) -> Option<String> {
        match value {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            Value::Bool(flag) => Some(flag.to_string()),
            _ => None,
        }
    }

    fn flag(value: &Value) -> Option<bool> {
        match value {
            Value::Bool(flag) => Some(*flag),
            Value::Number(number) => number.as_f64().map(|f| f != 0.0),
            _ => None,
        }
    }

    pub fn opt_int<'de, D: Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
        Ok(integer(&Value::deserialize(d)?))
    }

    pub fn int<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
        Ok(integer(&Value::deserialize(d)?).unwrap_or(0))
    }

    pub fn opt_text<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
        Ok(text(&Value::deserialize(d)?))
    }

    pub fn string<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        Ok(text(&Value::deserialize(d)?).unwrap_or_default())
    }

    pub fn opt_flag<'de, D: Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
        Ok(flag(&Value::deserialize(d)?))
    }

    pub fn boolean<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
        Ok(flag(&Value::deserialize(d)?).unwrap_or(false))
    }

    pub fn texts<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::Array(items) => items.iter().filter_map(text).collect(),
            other => text(&other).into_iter().collect(),
        })
    }

    /// A list, a single object (PowerShell unrolls one-item lists) or null.
    pub fn list<'de, D: Deserializer<'de>, T: serde::de::DeserializeOwned>(d: D) -> Result<Vec<T>, D::Error> {
        Ok(opt_list(d)?.unwrap_or_default())
    }

    pub fn opt_list<'de, D: Deserializer<'de>, T: serde::de::DeserializeOwned>(
        d: D,
    ) -> Result<Option<Vec<T>>, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::Null => None,
            Value::Array(items) => Some(
                items
                    .into_iter()
                    .filter_map(|item| serde_json::from_value(item).ok())
                    .collect(),
            ),
            single => Some(serde_json::from_value(single).ok().into_iter().collect()),
        })
    }

    /// An object, or None if it is null or not an object of that shape.
    pub fn opt_object<'de, D: Deserializer<'de>, T: serde::de::DeserializeOwned>(d: D) -> Result<Option<T>, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::Object(map) => serde_json::from_value(Value::Object(map)).ok(),
            _ => None,
        })
    }
}

// --------------------------------------------------------------------------- data

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct Cpu {
    #[serde(deserialize_with = "lenient::opt_text")]
    pub name: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub manufacturer: Option<String>,
    #[serde(deserialize_with = "lenient::int")]
    pub sockets: i64,
    #[serde(deserialize_with = "lenient::int")]
    pub cores: i64,
    #[serde(deserialize_with = "lenient::int")]
    pub logical: i64,
    #[serde(deserialize_with = "lenient::int")]
    pub max_mhz: i64,
    #[serde(deserialize_with = "lenient::int")]
    pub l2_kb: i64,
    #[serde(deserialize_with = "lenient::int")]
    pub l3_kb: i64,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub socket: Option<String>,
    #[serde(deserialize_with = "lenient::boolean")]
    pub virtualization: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct MemoryModule {
    /// Bytes.
    #[serde(deserialize_with = "lenient::int")]
    pub capacity: i64,
    /// Rated speed, MT/s.
    #[serde(deserialize_with = "lenient::int")]
    pub speed: i64,
    /// Running speed, MT/s.
    #[serde(deserialize_with = "lenient::int")]
    pub configured_speed: i64,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub manufacturer: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub part_number: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub slot: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub bank: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub form_factor: Option<String>,
    /// "DDR4", "DDR5"...
    #[serde(rename = "type", deserialize_with = "lenient::opt_text")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct Memory {
    #[serde(deserialize_with = "lenient::list")]
    pub modules: Vec<MemoryModule>,
    #[serde(deserialize_with = "lenient::int")]
    pub slots: i64,
    /// Bytes.
    #[serde(deserialize_with = "lenient::int")]
    pub max_capacity: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct Gpu {
    #[serde(deserialize_with = "lenient::opt_text")]
    pub name: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub driver_version: Option<String>,
    /// "YYYY-MM-DD".
    #[serde(deserialize_with = "lenient::opt_text")]
    pub driver_date: Option<String>,
    /// PCI vendor, upper-case hex ("10DE").
    #[serde(deserialize_with = "lenient::opt_text")]
    pub vendor_id: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub device_id: Option<String>,
    #[serde(deserialize_with = "lenient::int")]
    pub refresh_rate: i64,
    #[serde(deserialize_with = "lenient::int")]
    pub width: i64,
    #[serde(deserialize_with = "lenient::int")]
    pub height: i64,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct Disk {
    #[serde(deserialize_with = "lenient::opt_int")]
    pub number: Option<i64>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub name: Option<String>,
    /// "SSD", "HDD", "Unspecified".
    #[serde(deserialize_with = "lenient::string")]
    pub media: String,
    #[serde(deserialize_with = "lenient::string")]
    pub bus: String,
    /// Bytes.
    #[serde(deserialize_with = "lenient::int")]
    pub size: i64,
    /// "Healthy", "Warning", "Unhealthy"; empty if unknown.
    #[serde(deserialize_with = "lenient::string")]
    pub health: String,
    #[serde(deserialize_with = "lenient::string")]
    pub status: String,
    /// "C:", "D:".
    #[serde(deserialize_with = "lenient::texts")]
    pub letters: Vec<String>,
    /// °C. The health counters usually need administrator rights.
    #[serde(deserialize_with = "lenient::opt_int")]
    pub temperature: Option<i64>,
    #[serde(deserialize_with = "lenient::opt_int")]
    pub temperature_max: Option<i64>,
    /// Percent of the rated write endurance used.
    #[serde(deserialize_with = "lenient::opt_int")]
    pub wear: Option<i64>,
    #[serde(deserialize_with = "lenient::opt_int")]
    pub power_on_hours: Option<i64>,
    #[serde(deserialize_with = "lenient::opt_int")]
    pub read_errors: Option<i64>,
    #[serde(deserialize_with = "lenient::opt_int")]
    pub write_errors: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct Board {
    #[serde(deserialize_with = "lenient::opt_text")]
    pub manufacturer: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub product: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct Bios {
    #[serde(deserialize_with = "lenient::opt_text")]
    pub manufacturer: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub version: Option<String>,
    /// "YYYY-MM-DD".
    #[serde(deserialize_with = "lenient::opt_text")]
    pub date: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct Computer {
    #[serde(deserialize_with = "lenient::opt_text")]
    pub manufacturer: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub model: Option<String>,
    #[serde(deserialize_with = "lenient::opt_flag")]
    pub auto_pagefile: Option<bool>,
    #[serde(deserialize_with = "lenient::opt_flag")]
    pub hypervisor: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct OperatingSystem {
    #[serde(deserialize_with = "lenient::opt_text")]
    pub caption: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub version: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub build: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub arch: Option<String>,
    /// "YYYY-MM-DDTHH:MM:SS", local time.
    #[serde(deserialize_with = "lenient::opt_text")]
    pub installed: Option<String>,
    #[serde(deserialize_with = "lenient::opt_text")]
    pub last_boot: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct Battery {
    /// Percent.
    #[serde(deserialize_with = "lenient::int")]
    pub charge: i64,
    /// Win32_Battery.BatteryStatus.
    #[serde(deserialize_with = "lenient::int")]
    pub status: i64,
    /// mWh.
    #[serde(deserialize_with = "lenient::opt_int")]
    pub designed_capacity: Option<i64>,
    #[serde(deserialize_with = "lenient::opt_int")]
    pub full_capacity: Option<i64>,
    #[serde(deserialize_with = "lenient::opt_int")]
    pub cycles: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct PageFile {
    #[serde(deserialize_with = "lenient::opt_text")]
    pub path: Option<String>,
    #[serde(deserialize_with = "lenient::int")]
    pub allocated_mb: i64,
    #[serde(deserialize_with = "lenient::int")]
    pub current_mb: i64,
    #[serde(deserialize_with = "lenient::int")]
    pub peak_mb: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct Trim {
    /// True when TRIM commands are sent (DisableDeleteNotify = 0).
    #[serde(deserialize_with = "lenient::opt_flag")]
    pub ntfs: Option<bool>,
    #[serde(deserialize_with = "lenient::opt_flag")]
    pub refs: Option<bool>,
    /// "fsutil" or "registry".
    #[serde(deserialize_with = "lenient::opt_text")]
    pub source: Option<String>,
}

/// Something the script could not read, and why.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Note {
    #[serde(deserialize_with = "lenient::string")]
    pub area: String,
    #[serde(deserialize_with = "lenient::string")]
    pub message: String,
}

/// The hardware inventory. Sections Windows refused are None.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct Hardware {
    #[serde(deserialize_with = "lenient::boolean")]
    pub is_admin: bool,
    #[serde(deserialize_with = "lenient::opt_object")]
    pub cpu: Option<Cpu>,
    #[serde(deserialize_with = "lenient::opt_object")]
    pub memory: Option<Memory>,
    #[serde(deserialize_with = "lenient::list")]
    pub gpus: Vec<Gpu>,
    #[serde(deserialize_with = "lenient::list")]
    pub disks: Vec<Disk>,
    #[serde(deserialize_with = "lenient::opt_object")]
    pub board: Option<Board>,
    #[serde(deserialize_with = "lenient::opt_object")]
    pub bios: Option<Bios>,
    #[serde(deserialize_with = "lenient::opt_object")]
    pub computer: Option<Computer>,
    #[serde(deserialize_with = "lenient::opt_object")]
    pub os: Option<OperatingSystem>,
    /// Laptops only.
    #[serde(deserialize_with = "lenient::opt_object")]
    pub battery: Option<Battery>,
    /// None if the page file could not be read; empty if there is none.
    #[serde(deserialize_with = "lenient::opt_list")]
    pub pagefiles: Option<Vec<PageFile>>,
    #[serde(deserialize_with = "lenient::opt_object")]
    pub trim: Option<Trim>,
    #[serde(deserialize_with = "lenient::list")]
    pub notes: Vec<Note>,
}

// --------------------------------------------------------------------------- collector

/// The script PowerShell runs: the collector with its helpers inlined and the output sent to
/// standard output.
fn script() -> String {
    let helpers = format!("{COMMON_PS1}\n{STDOUT_WRITER}");
    HARDWARE_PS1.replacen(INCLUDE_LINE, &helpers, 1)
}

/// Parses the JSON the collector writes (snake_case field names).
pub fn parse_hardware(json: &str) -> Result<Hardware, MaintError> {
    serde_json::from_str(json.trim_start_matches('\u{feff}'))
        .map_err(|e| MaintError::new(MaintErrorKind::Collector, tr!("hardware: invalid JSON ({0})", e)))
}

/// Collects the hardware inventory. Takes a few seconds: call it from a worker thread.
pub fn hardware() -> Result<Hardware, MaintError> {
    let command = "& ([scriptblock]::Create([Console]::In.ReadToEnd())) -OutPath stdout";
    let output = run_hidden(
        &powershell_path(),
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        &[],
        Some(script().as_bytes()),
        TIMEOUT,
    )
    .map_err(|e| MaintError::new(MaintErrorKind::Collector, format!("hardware: {}", e.message)))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(json) = stdout
        .lines()
        .rev()
        .find_map(|line| line.trim_end().strip_prefix(MARKER))
    else {
        let detail = if output.stderr.is_empty() {
            &output.stdout
        } else {
            &output.stderr
        };
        let detail = String::from_utf8_lossy(detail);
        let detail = detail.trim();
        let tail: String = detail
            .chars()
            .rev()
            .take(600)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let code = output.code.map_or_else(|| "none".to_string(), |c| c.to_string());
        return Err(MaintError::new(
            MaintErrorKind::Collector,
            tr!("hardware: no output (exit code {0}). {1}", code, tail),
        ));
    };
    parse_hardware(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_is_ascii_and_self_contained() {
        let text = script();
        assert!(
            text.is_ascii(),
            "Windows PowerShell 5.1 reads BOM-less scripts in the ANSI code page"
        );
        assert!(!text.contains("$PSScriptRoot"), "the helpers must be inlined");
        assert!(text.contains("function Add-Note") && text.contains(MARKER));
        // The stdout writer comes after the file writer, so it wins.
        let file_writer = text.find("[System.IO.File]::WriteAllText").unwrap_or(usize::MAX);
        let stdout_writer = text.find("[Console]::Out.Write").unwrap_or(0);
        assert!(file_writer < stdout_writer);
        // param() must stay the first statement.
        let first = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .unwrap_or("");
        assert!(first.starts_with("param("));
    }

    #[test]
    fn parses_the_collector_shape_and_serializes_camel_case() {
        let json = r#"{"is_admin":false,"cpu":{"name":"Example CPU","cores":8,"logical":16,"max_mhz":3600,
            "l2_kb":4096,"l3_kb":32768,"virtualization":true,"sockets":1},
            "memory":{"modules":{"capacity":17179869184,"speed":3200,"configured_speed":2666,
            "part_number":"PART-1","type":"DDR4"},"slots":4,"max_capacity":137438953472},
            "gpus":[{"name":"Example GPU","vendor_id":"10DE","driver_date":"2024-01-01","refresh_rate":144}],
            "disks":[{"number":0,"name":"Example SSD","media":"SSD","health":"Healthy","letters":["C:"],
            "temperature":41,"wear":"3","read_errors":null,"size":1000204886016.0}],
            "battery":null,"pagefiles":[],"computer":{"auto_pagefile":false},"trim":{"ntfs":true,"source":"registry"},
            "os":{"build":"26100","last_boot":"2026-01-01T08:00:00"},
            "notes":[{"area":"disks","message":"Access denied"}]}"#;
        let hw = parse_hardware(json).unwrap();
        assert_eq!(hw.cpu.as_ref().map(|c| c.max_mhz), Some(3600));
        let memory = hw.memory.as_ref().unwrap();
        assert_eq!(memory.modules.len(), 1, "a single object is a one-item list");
        assert_eq!(memory.modules[0].kind.as_deref(), Some("DDR4"));
        assert_eq!(hw.disks[0].wear, Some(3));
        assert_eq!(hw.disks[0].size, 1_000_204_886_016);
        assert_eq!(hw.disks[0].read_errors, None);
        assert_eq!(hw.pagefiles, Some(Vec::new()));
        assert_eq!(hw.battery, None);
        assert_eq!(hw.notes[0].area, "disks");
        let out = serde_json::to_value(&hw).unwrap();
        assert_eq!(out["cpu"]["maxMhz"], 3600);
        assert_eq!(out["memory"]["modules"][0]["configuredSpeed"], 2666);
        assert_eq!(out["memory"]["modules"][0]["type"], "DDR4");
        assert_eq!(out["gpus"][0]["vendorId"], "10DE");
        assert_eq!(out["disks"][0]["letters"][0], "C:");
        assert_eq!(out["computer"]["autoPagefile"], false);
        assert_eq!(out["os"]["lastBoot"], "2026-01-01T08:00:00");
        assert_eq!(out["isAdmin"], false);
    }

    #[test]
    fn missing_sections_stay_empty() {
        let hw = parse_hardware(r#"{"notes":[]}"#).unwrap();
        assert!(hw.cpu.is_none() && hw.pagefiles.is_none() && hw.disks.is_empty());
        assert!(parse_hardware("not json").is_err());
    }

    /// Runs the real collector (read-only, a few seconds): `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn collects_this_pc() {
        let hw = hardware().unwrap();
        assert!(hw.cpu.as_ref().is_some_and(|c| c.logical > 0), "{:?}", hw.notes);
        assert!(hw.os.is_some());
    }
}
