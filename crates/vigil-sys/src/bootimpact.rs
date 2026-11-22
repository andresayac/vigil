//! Startup impact: how much each program that starts at sign-in weighed on the last starts, as
//! Windows measured it. READ-ONLY.
//!
//! Two sources, both written by Windows itself and readable only with administrator rights:
//! - the startup records Task Manager uses (`System32\wdi\LogFiles\StartupInfo\<SID>_StartupInfo*.xml`):
//!   per program, the processor time and the bytes read from disk in the first minute after
//!   sign-in, one file per recent start;
//! - the Diagnostics-Performance log: event 101 names an application that made the start slower than
//!   usual, with how much slower (its "degradation"), and event 100 gives each start's duration.
//!
//! The level follows Task Manager's meaning:
//! - High: more than 1 s of processor time or more than 3 MB read from disk, or a start made at
//!   least 1 s slower;
//! - Medium: more than 300 ms of processor time or 300 KB read, or a start made 300 ms slower;
//! - Low: measured, under both;
//! - Not measured: no record names the program (it did not run at the last starts, or the records
//!   could not be read).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::reliability::{Boot, LogReader, Record, boot_from_xml};
use crate::util::now_unix_ms;
use crate::xml::{Node, parse_xml};

/// Start records read at most (Windows keeps about five).
const MAX_FILES: usize = 8;
/// A start record is read up to this size.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const BOOT_LOG: &str = "Microsoft-Windows-Diagnostics-Performance/Operational";
const DAY_MS: i64 = 86_400_000;
/// Days of boot durations read for the trend.
pub const BOOT_DAYS: i64 = 30;

pub const HIGH_CPU_MS: u64 = 1_000;
pub const HIGH_DISK_BYTES: u64 = 3 * 1024 * 1024;
pub const MEDIUM_CPU_MS: u64 = 300;
pub const MEDIUM_DISK_BYTES: u64 = 300 * 1024;
pub const HIGH_DEGRADATION_MS: u64 = 1_000;
pub const MEDIUM_DEGRADATION_MS: u64 = 300;

/// What one program cost at the last starts that recorded it.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProgramImpact {
    /// The program's file name in lower case ("contosomail.exe").
    pub key: String,
    /// Its full path when the record gives one ("" otherwise).
    pub path: String,
    /// Processor time and bytes read in the first minute of the newest start that recorded it.
    pub cpu_ms: u64,
    pub disk_bytes: u64,
    /// Starts that recorded it.
    pub boots: u32,
    /// The newest start that recorded it (Unix ms; 0 when unknown).
    pub last_ms: i64,
    /// The most a start was slowed by it (Diagnostics-Performance 101), and when.
    pub degradation_ms: u64,
    pub degraded_ms: i64,
    /// "high", "medium" or "low".
    pub level: &'static str,
}

/// Every measured program and the recent start durations.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BootImpact {
    pub read_ms: i64,
    /// A source could be read (the start records or the boot log).
    pub measured: bool,
    /// A source refused this account (it needs administrator rights).
    pub needs_admin: bool,
    pub programs: Vec<ProgramImpact>,
    /// Start durations of the last [`BOOT_DAYS`] days, newest first.
    pub boots: Vec<Boot>,
}

impl BootImpact {
    /// The impact of a program, by its full path first, then by its file name.
    pub fn of(&self, executable: &str) -> Option<&ProgramImpact> {
        if executable.is_empty() {
            return None;
        }
        let lower = executable.to_lowercase();
        let name = file_name(&lower);
        self.programs
            .iter()
            .find(|p| !p.path.is_empty() && p.path.to_lowercase() == lower)
            .or_else(|| self.programs.iter().find(|p| p.key == name))
    }
}

/// The level of a measured program.
pub fn level(cpu_ms: u64, disk_bytes: u64, degradation_ms: u64) -> &'static str {
    if cpu_ms > HIGH_CPU_MS || disk_bytes > HIGH_DISK_BYTES || degradation_ms >= HIGH_DEGRADATION_MS {
        "high"
    } else if cpu_ms > MEDIUM_CPU_MS || disk_bytes > MEDIUM_DISK_BYTES || degradation_ms >= MEDIUM_DEGRADATION_MS {
        "medium"
    } else {
        "low"
    }
}

fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_lowercase()
}

/// Reads both sources.
pub fn read() -> BootImpact {
    let mut out = BootImpact {
        read_ms: now_unix_ms(),
        ..BootImpact::default()
    };
    let mut measured: Vec<Measured> = Vec::new();
    match startup_records() {
        Ok(files) => {
            out.measured = true;
            for (time_ms, text) in files {
                measured.extend(parse_startup_info(&text, time_ms));
            }
        }
        Err(Refused::Access) => out.needs_admin = true,
        Err(Refused::Missing) => {}
    }
    let mut reader = LogReader::default();
    let window = BOOT_DAYS * DAY_MS;
    let query = format!("*[System[(EventID=100 or EventID=101) and TimeCreated[timediff(@SystemTime) <= {window}]]]");
    match reader.query(BOOT_LOG, &query, false) {
        Ok((records, _)) => {
            out.measured = true;
            for (xml, _) in &records {
                if let Some(boot) = boot_from_xml(xml) {
                    out.boots.push(boot);
                } else if let Some(slow) = degradation_from_xml(xml) {
                    measured.push(slow);
                }
            }
        }
        Err(error) => {
            if error.code() != crate::reliability::ERROR_EVT_CHANNEL_NOT_FOUND {
                out.needs_admin = true;
            }
        }
    }
    out.boots.sort_by_key(|b| std::cmp::Reverse(b.time_ms));
    out.programs = aggregate(measured);
    out
}

enum Refused {
    Access,
    Missing,
}

/// The start records of this account (newest first, with their time), read without following links.
fn startup_records() -> Result<Vec<(i64, String)>, Refused> {
    let windows = crate::paths::windows_dir();
    let dir = windows.join(r"System32\wdi\LogFiles\StartupInfo");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return Err(Refused::Access),
        Err(_) => return Err(Refused::Missing),
    };
    let sid = crate::accounts::token_user_sid().unwrap_or_default().to_lowercase();
    let mut files: Vec<(i64, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            let ours = sid.is_empty() || name.starts_with(&sid);
            if !ours || !name.contains("_startupinfo") || !name.ends_with(".xml") {
                return None;
            }
            let meta = std::fs::symlink_metadata(entry.path()).ok()?;
            if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
                return None;
            }
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(0));
            Some((modified, entry.path()))
        })
        .collect();
    files.sort_by_key(|(time, _)| std::cmp::Reverse(*time));
    files.truncate(MAX_FILES);
    let mut out = Vec::new();
    for (time, path) in files {
        match read_text(&path) {
            Ok(text) => out.push((time, text)),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return Err(Refused::Access),
            Err(_) => {}
        }
    }
    Ok(out)
}

/// A record as text: UTF-16 (with a byte order mark, as Windows writes them) or UTF-8.
fn read_text(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_FILE_BYTES)
        .read_to_end(&mut bytes)?;
    Ok(decode(&bytes))
}

pub fn decode(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let rest = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(rest).into_owned()
}

/// One program in one record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Measured {
    pub path: String,
    pub cpu_ms: u64,
    pub disk_bytes: u64,
    pub time_ms: i64,
    /// How much it slowed a start (from the boot log, not a start record).
    pub degradation_ms: u64,
    /// It comes from the boot log (event 101), not from a start record.
    pub from_log: bool,
}

/// A number with its `Unit` attribute: processor time in ms, sizes in bytes.
fn amount(node: Option<&Node>, time: bool) -> u64 {
    let Some(node) = node else { return 0 };
    let value: f64 = node.text.trim().parse().unwrap_or(0.0);
    let unit = node.attr("Unit").to_ascii_lowercase();
    let scaled = if time {
        match unit.as_str() {
            "s" => value * 1000.0,
            "ms" => value,
            // Task Manager's records count processor time in microseconds.
            _ => value / 1000.0,
        }
    } else {
        match unit.as_str() {
            "kb" => value * 1024.0,
            "mb" => value * 1024.0 * 1024.0,
            _ => value,
        }
    };
    scaled.max(0.0).round() as u64
}

/// The programs of one start record.
pub fn parse_startup_info(xml: &str, time_ms: i64) -> Vec<Measured> {
    let Some(root) = parse_xml(xml) else { return Vec::new() };
    let mut out = Vec::new();
    let mut stack = vec![&root];
    while let Some(node) = stack.pop() {
        if node.name == "Process" {
            let path = match node.attr("Name") {
                "" => node.text_at(&["Name"]).to_string(),
                name => name.to_string(),
            };
            if !path.is_empty() {
                out.push(Measured {
                    path,
                    cpu_ms: amount(node.child("CpuUsage"), true),
                    disk_bytes: amount(node.child("DiskUsage"), false),
                    time_ms,
                    degradation_ms: 0,
                    from_log: false,
                });
            }
        }
        // In document order (the stack takes the last child first).
        stack.extend(node.children.iter().rev());
    }
    out
}

/// A Diagnostics-Performance event 101 ("this application took longer than usual to start").
pub fn degradation_from_xml(xml: &str) -> Option<Measured> {
    let record = Record::parse(xml)?;
    if record.event_id != 101 {
        return None;
    }
    let name = [record.get("Name", usize::MAX), record.get("FileName", usize::MAX)]
        .into_iter()
        .find(|n| !n.trim().is_empty())?
        .trim()
        .to_string();
    let number = |key: &str| record.get(key, usize::MAX).trim().parse::<u64>().unwrap_or(0);
    Some(Measured {
        path: name,
        cpu_ms: 0,
        disk_bytes: 0,
        time_ms: record.time_ms,
        degradation_ms: number("DegradationTime"),
        from_log: true,
    })
}

/// One entry per program: the newest start record's figures, how many starts named it, and the
/// largest degradation.
pub fn aggregate(measured: Vec<Measured>) -> Vec<ProgramImpact> {
    let mut by: BTreeMap<String, ProgramImpact> = BTreeMap::new();
    for m in measured {
        let key = file_name(&m.path);
        if key.is_empty() {
            continue;
        }
        let p = by.entry(key.clone()).or_insert_with(|| ProgramImpact {
            key,
            ..ProgramImpact::default()
        });
        if m.from_log {
            if m.degradation_ms > p.degradation_ms {
                p.degradation_ms = m.degradation_ms;
                p.degraded_ms = m.time_ms;
            }
            continue;
        }
        p.boots += 1;
        if m.time_ms >= p.last_ms {
            p.last_ms = m.time_ms;
            p.cpu_ms = m.cpu_ms;
            p.disk_bytes = m.disk_bytes;
            if m.path.contains(['\\', '/']) {
                p.path = m.path;
            }
        }
    }
    let mut out: Vec<ProgramImpact> = by
        .into_values()
        .map(|mut p| {
            p.level = level(p.cpu_ms, p.disk_bytes, p.degradation_ms);
            p
        })
        .collect();
    out.sort_by(|a, b| rank(b.level).cmp(&rank(a.level)).then(b.cpu_ms.cmp(&a.cpu_ms)));
    out
}

fn rank(level: &str) -> u8 {
    match level {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<StartupData Version="2">
  <Process Name="C:\Program Files\Contoso\Mail\ContosoMail.exe" PID="4120">
    <StartTime>133000000000000000</StartTime>
    <CommandLine>"C:\Program Files\Contoso\Mail\ContosoMail.exe" /background</CommandLine>
    <DiskUsage Unit="bytes">5242880</DiskUsage>
    <CpuUsage Unit="us">420000</CpuUsage>
    <ParentPID>3180</ParentPID>
    <ParentName>explorer.exe</ParentName>
  </Process>
  <Process Name="C:\Users\jdoe\AppData\Local\Contoso\OneSync\OneSync.exe" PID="4200">
    <DiskUsage Unit="bytes">409600</DiskUsage>
    <CpuUsage Unit="us">120000</CpuUsage>
  </Process>
  <Process Name="C:\Program Files\Tailspin\VPN\TailspinVPN.exe" PID="4300">
    <DiskUsage Unit="bytes">20480</DiskUsage>
    <CpuUsage Unit="us">15000</CpuUsage>
  </Process>
</StartupData>"#;

    #[test]
    fn levels_follow_task_manager() {
        assert_eq!(level(1_500, 0, 0), "high");
        assert_eq!(level(0, 4 * 1024 * 1024, 0), "high");
        assert_eq!(level(0, 0, 1_200), "high");
        assert_eq!(level(400, 0, 0), "medium");
        assert_eq!(level(0, 400 * 1024, 0), "medium");
        assert_eq!(level(0, 0, 300), "medium");
        assert_eq!(level(100, 100 * 1024, 0), "low");
    }

    #[test]
    fn start_records_are_read() {
        let found = parse_startup_info(INFO, 1_000);
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].cpu_ms, 420, "microseconds become milliseconds");
        assert_eq!(found[0].disk_bytes, 5_242_880);
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(INFO.encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(parse_startup_info(&decode(&utf16), 1_000).len(), 3);
        assert!(parse_startup_info("not xml", 0).is_empty());
    }

    #[test]
    fn the_newest_record_counts_and_degradations_raise_the_level() {
        let mut measured = parse_startup_info(INFO, 2_000);
        let older = parse_startup_info(&INFO.replace("420000", "2400000"), 1_000);
        measured.extend(older);
        measured.push(Measured {
            path: "TailspinVPN.exe".into(),
            time_ms: 1_500,
            degradation_ms: 1_800,
            from_log: true,
            ..Measured::default()
        });
        let all = aggregate(measured);
        let impact = BootImpact {
            programs: all,
            ..BootImpact::default()
        };
        let mail = impact
            .of(r"C:\Program Files\Contoso\Mail\ContosoMail.exe")
            .expect("mail");
        assert_eq!((mail.cpu_ms, mail.boots, mail.level), (420, 2, "high"), "5 MB read");
        let sync = impact
            .of(r"c:\users\jdoe\appdata\local\contoso\onesync\onesync.exe")
            .expect("sync");
        assert_eq!(sync.level, "medium");
        let vpn = impact.of(r"D:\Elsewhere\TailspinVPN.exe").expect("by file name");
        assert_eq!((vpn.level, vpn.degradation_ms, vpn.boots), ("high", 1_800, 2));
        assert!(impact.of(r"C:\Program Files\Woodgrove\Notes\Notes.exe").is_none());
        assert!(impact.of("").is_none());
        assert_eq!(impact.programs[0].level, "high");
    }

    #[test]
    fn slow_start_events_are_read() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Diagnostics-Performance"/><EventID>101</EventID><Level>3</Level><TimeCreated SystemTime="2026-11-20T08:00:00.0000000Z"/><EventRecordID>5</EventRecordID><Channel>Microsoft-Windows-Diagnostics-Performance/Operational</Channel><Computer>PC-VICTIM</Computer></System><EventData><Data Name="Name">FabrikamChat.exe</Data><Data Name="FriendlyName">Fabrikam Chat</Data><Data Name="Version">3.1</Data><Data Name="TotalTime">2600</Data><Data Name="DegradationTime">1900</Data></EventData></Event>"#;
        let slow = degradation_from_xml(xml).expect("101");
        assert_eq!((slow.path.as_str(), slow.degradation_ms), ("FabrikamChat.exe", 1_900));
        assert!(degradation_from_xml(&xml.replace("<EventID>101", "<EventID>100")).is_none());
    }

    #[test]
    #[ignore = "reads this computer's start records; run by hand"]
    fn live_read_counts_only() {
        let started = std::time::Instant::now();
        let impact = read();
        let count = |l: &str| impact.programs.iter().filter(|p| p.level == l).count();
        println!(
            "measured {} needs admin {} programs {} (high {} medium {} low {}) boots {} in {:?}",
            impact.measured,
            impact.needs_admin,
            impact.programs.len(),
            count("high"),
            count("medium"),
            count("low"),
            impact.boots.len(),
            started.elapsed()
        );
    }
}
