//! Health and performance insights from the hardware inventory and the current settings.
//!
//! Pure functions over plain data (the hardware inventory, the tuning state, volumes), so they
//! can be tested without the machine they describe. Each insight says what was found and, when
//! there is one, the concrete fix. Nothing here recommends weakening security for speed (memory
//! integrity, Defender and the like are never on the list).

use serde::{Deserialize, Serialize};

use crate::date::Date;
use crate::hardware::Hardware;
use crate::storage::Volume;
use crate::tuning::TuningState;
use vigil_i18n::tr;

/// The Power saver plan.
pub const POWER_SAVER: &str = "a1841308-3541-4fab-bc81-f71556f20b4a";

const GIB: f64 = 1_073_741_824.0;

/// How serious an insight is. Ordered from the most serious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Bad,
    Warn,
    Info,
    Ok,
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Insight {
    pub level: Level,
    /// "Storage", "Memory", "Graphics", "System", "Power", "Battery".
    pub area: String,
    pub text: String,
    /// Empty when there is nothing to do.
    pub fix: String,
}

fn insight(level: Level, area: &str, text: impl Into<String>, fix: impl Into<String>) -> Insight {
    Insight {
        level,
        area: area.to_string(),
        text: text.into(),
        fix: fix.into(),
    }
}

fn vendor(id: &str) -> Option<(&'static str, &'static str)> {
    match id.to_uppercase().as_str() {
        "10DE" => Some(("NVIDIA", "nvidia.com/drivers")),
        "1002" => Some(("AMD", "amd.com/support")),
        "8086" => Some(("Intel", "intel.com/support (Driver & Support Assistant)")),
        _ => None,
    }
}

fn age_days(iso: Option<&str>, today: Date) -> Option<i64> {
    let iso = iso.filter(|text| !text.is_empty())?;
    Some(today.days_since(&Date::parse_iso(iso)?))
}

/// A whole number rounded half to even (banker's rounding), so 7.5 reads 8 and 14.5 reads 14.
fn round0(value: f64) -> String {
    format!("{:.0}", value)
}

pub fn disks(hw: &Hardware) -> Vec<Insight> {
    let mut out = Vec::new();
    let mut known = false;
    for disk in &hw.disks {
        let number = disk.number.map_or_else(|| "None".to_string(), |n| n.to_string());
        let model = disk
            .name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| tr!("unknown model"));
        let name = tr!("Disk {0} ({1})", number, model);
        let health = disk.health.as_str();
        if !health.is_empty() {
            known = true;
        }
        if !health.is_empty() && !matches!(health.to_lowercase().as_str(), "healthy" | "0") {
            out.push(insight(
                Level::Bad,
                "Storage",
                tr!("{0} reports its health as {1}.", name, health),
                tr!("Back up your files now and plan to replace the drive."),
            ));
        }
        if let Some(temperature) = disk.temperature.filter(|&t| t > 0) {
            if temperature >= 70 {
                out.push(insight(
                    Level::Bad,
                    "Storage",
                    tr!("{0} is at {1} °C.", name, temperature),
                    tr!("Improve airflow around the drive; sustained heat shortens its life."),
                ));
            } else if temperature >= 60 {
                out.push(insight(
                    Level::Warn,
                    "Storage",
                    tr!("{0} runs warm ({1} °C).", name, temperature),
                    tr!("Check the case airflow or add a heatsink to the SSD."),
                ));
            }
        }
        if let Some(wear) = disk.wear.filter(|&w| w > 0) {
            if wear >= 95 {
                out.push(insight(
                    Level::Bad,
                    "Storage",
                    tr!("{0} has used {1}% of its rated write endurance.", name, wear),
                    tr!("Back up your files and replace the SSD soon."),
                ));
            } else if wear >= 80 {
                out.push(insight(
                    Level::Warn,
                    "Storage",
                    tr!("{0} has used {1}% of its rated write endurance.", name, wear),
                    tr!("Keep backups current; the drive is nearing the end of its rated life."),
                ));
            }
        }
        let errors = disk.read_errors.unwrap_or(0) + disk.write_errors.unwrap_or(0);
        if errors != 0 {
            out.push(insight(
                Level::Warn,
                "Storage",
                tr!("{0} reports {1} uncorrected read/write errors.", name, errors),
                tr!("Back up your files and run the manufacturer's diagnostic tool."),
            ));
        }
    }
    if known && !out.iter().any(|i| matches!(i.level, Level::Warn | Level::Bad)) {
        out.push(insight(
            Level::Ok,
            "Storage",
            tr!("Every disk reports a healthy status."),
            "",
        ));
    }
    let has_ssd = hw.disks.iter().any(|d| d.media.to_uppercase() == "SSD");
    let trim = hw.trim.as_ref().and_then(|t| t.ntfs);
    if has_ssd && trim == Some(false) {
        out.push(insight(
            Level::Bad,
            "Storage",
            tr!("TRIM is turned off, so the SSD slows down as it fills."),
            tr!("Run as administrator: fsutil behavior set DisableDeleteNotify 0"),
        ));
    }
    out
}

pub fn memory(hw: &Hardware) -> Vec<Insight> {
    let mut out = Vec::new();
    let Some(info) = hw.memory.as_ref() else { return out };
    let modules: Vec<_> = info.modules.iter().filter(|m| m.capacity != 0).collect();
    if modules.is_empty() {
        return out;
    }
    let total: f64 = modules.iter().map(|m| m.capacity as f64 / GIB).sum();
    if total != 0.0 && total < 8.0 {
        out.push(insight(
            Level::Warn,
            "Memory",
            tr!("Only {0} GB of RAM installed.", round0(total)),
            tr!("8 GB is the practical minimum for Windows 11 with a browser; 16 GB is comfortable."),
        ));
    }
    if modules.len() == 1 && info.slots >= 2 {
        out.push(insight(
            Level::Warn,
            "Memory",
            tr!("A single memory module runs in single-channel mode."),
            tr!(
                "Adding a second identical module enables dual-channel and roughly doubles memory bandwidth \
             (noticeable in games and with integrated graphics)."
            ),
        ));
    }
    let rated: Vec<i64> = modules.iter().map(|m| m.speed).collect();
    let running: Vec<i64> = modules.iter().map(|m| m.configured_speed).collect();
    let all_running = running.iter().all(|&s| s != 0);
    let min_rated = rated.iter().copied().min().unwrap_or(0);
    let min_running = running.iter().copied().min().unwrap_or(0);
    if rated.iter().all(|&s| s != 0) && all_running && (min_running as f64) < min_rated as f64 * 0.95 {
        out.push(insight(
            Level::Warn,
            "Memory",
            tr!(
                "Memory runs at {0} MT/s although the modules report {1} MT/s.",
                min_running,
                min_rated
            ),
            tr!("Enable the memory profile in the BIOS (XMP, EXPO or DOCP)."),
        ));
    }
    let first = (modules[0].capacity, &modules[0].part_number);
    if modules.iter().any(|m| (m.capacity, &m.part_number) != first) {
        out.push(insight(
            Level::Info,
            "Memory",
            tr!("The memory modules are not identical (size or model differ)."),
            tr!("Mixed modules usually work but may run at the slowest module's speed."),
        ));
    }
    if out.is_empty() {
        let text = match (modules.len() > 1, all_running) {
            (false, true) => tr!(
                "{0} GB in {1} module at {2} MT/s.",
                round0(total),
                modules.len(),
                min_running
            ),
            (true, true) => tr!(
                "{0} GB in {1} modules at {2} MT/s.",
                round0(total),
                modules.len(),
                min_running
            ),
            (false, false) => tr!("{0} GB in {1} module.", round0(total), modules.len()),
            (true, false) => tr!("{0} GB in {1} modules.", round0(total), modules.len()),
        };
        out.push(insight(Level::Ok, "Memory", text, ""));
    }
    out
}

pub fn graphics(hw: &Hardware, today: Date) -> Vec<Insight> {
    let mut out = Vec::new();
    for gpu in &hw.gpus {
        let Some((vendor_name, site)) = vendor(gpu.vendor_id.as_deref().unwrap_or("")) else {
            continue;
        };
        let date = gpu.driver_date.as_deref();
        let age = age_days(date, today);
        let name = gpu.name.as_deref().filter(|n| !n.is_empty()).unwrap_or(vendor_name);
        let shown = date.unwrap_or("None");
        match age {
            Some(age) if age > 365 => out.push(insight(
                Level::Warn,
                "Graphics",
                tr!(
                    "The {0} driver is {1} months old ({2}).",
                    name,
                    age.div_euclid(30),
                    shown
                ),
                tr!("Install the current driver from {0}.", site),
            )),
            Some(_) => out.push(insight(
                Level::Ok,
                "Graphics",
                tr!("The {0} driver is recent ({1}).", name, shown),
                "",
            )),
            None => {}
        }
    }
    out
}

pub fn system(hw: &Hardware, uptime_seconds: f64, today: Date) -> Vec<Insight> {
    let mut out = Vec::new();
    let bios_date = hw.bios.as_ref().and_then(|b| b.date.as_deref());
    if age_days(bios_date, today).is_some_and(|age| age > 4 * 365) {
        out.push(insight(
            Level::Info,
            "System",
            tr!("The BIOS is from {0}.", bios_date.unwrap_or("None")),
            tr!(
                "Check the motherboard maker's site: BIOS updates fix security and stability issues. Update only \
             on stable power."
            ),
        ));
    }
    let auto = hw.computer.as_ref().and_then(|c| c.auto_pagefile);
    if hw.pagefiles.as_ref().is_some_and(Vec::is_empty) && auto == Some(false) {
        out.push(insight(
            Level::Warn,
            "System",
            tr!("There is no page file."),
            tr!("Programs can crash when memory runs out. Let Windows manage the page file size."),
        ));
    }
    for page in hw.pagefiles.iter().flatten() {
        let (allocated, peak) = (page.allocated_mb, page.peak_mb);
        if allocated != 0 && peak as f64 >= allocated as f64 * 0.9 {
            out.push(insight(
                Level::Warn,
                "System",
                tr!("The page file reached {0} MB of its {1} MB.", peak, allocated),
                tr!("Memory runs short at times: close heavy programs or add RAM."),
            ));
        }
    }
    let days = if uptime_seconds != 0.0 {
        uptime_seconds / 86400.0
    } else {
        0.0
    };
    if days >= 14.0 {
        out.push(insight(
            Level::Info,
            "System",
            tr!("Windows has been running for {0} days.", round0(days)),
            tr!("Restart now and then: some updates and driver changes only finish after a restart."),
        ));
    }
    if let Some(battery) = hw.battery.as_ref() {
        let designed = battery.designed_capacity.unwrap_or(0);
        let full = battery.full_capacity.unwrap_or(0);
        if designed != 0 && full != 0 {
            let health = full as f64 / designed as f64 * 100.0;
            let level = if health < 50.0 {
                Level::Bad
            } else if health < 70.0 {
                Level::Warn
            } else {
                Level::Ok
            };
            let text = match battery.cycles {
                Some(cycles) if cycles != 0 => {
                    tr!(
                        "The battery holds {0}% of its original capacity after {1} cycles.",
                        round0(health),
                        cycles
                    )
                }
                _ => tr!("The battery holds {0}% of its original capacity.", round0(health)),
            };
            out.push(insight(
                level,
                "Battery",
                text,
                if level == Level::Ok {
                    String::new()
                } else {
                    tr!("Consider replacing it.")
                },
            ));
        }
    }
    out
}

pub fn space(volumes: &[Volume]) -> Vec<Insight> {
    let mut out = Vec::new();
    for volume in volumes {
        if volume.total == 0 || volume.network || volume.removable {
            continue;
        }
        let share = volume.free as f64 / volume.total as f64 * 100.0;
        let mount = volume.mount.trim_end_matches('\\');
        if share < 5.0 {
            out.push(insight(
                Level::Bad,
                "Storage",
                tr!("{0} is almost full ({1}% free).", mount, round0(share)),
                tr!("Free space in Storage: Windows needs room for updates, the page file and caches."),
            ));
        } else if share < 12.0 {
            out.push(insight(
                Level::Warn,
                "Storage",
                tr!("{0} is getting full ({1}% free).", mount, round0(share)),
                tr!("Clean up junk files or move large files in Storage."),
            ));
        }
    }
    out
}

pub fn power(tuning: Option<&TuningState>, hw: &Hardware) -> Vec<Insight> {
    let mut out = Vec::new();
    let active = tuning.and_then(|t| t.power_plans.iter().find(|p| p.active));
    if active.is_some_and(|plan| plan.guid.to_lowercase() == POWER_SAVER) && hw.battery.is_none() {
        out.push(insight(
            Level::Warn,
            "Power",
            tr!("This desktop uses the Power saver plan, which caps the CPU speed."),
            tr!("Switch to Balanced or High performance in Optimize."),
        ));
    }
    out
}

/// Every insight, problems first. `today` defaults to the local date.
pub fn collect(
    hw: &Hardware,
    tuning: Option<&TuningState>,
    volumes: &[Volume],
    uptime_seconds: f64,
    today: Option<Date>,
) -> Vec<Insight> {
    let today = today.unwrap_or_else(Date::today);
    let mut found = disks(hw);
    found.extend(space(volumes));
    found.extend(memory(hw));
    found.extend(graphics(hw, today));
    found.extend(system(hw, uptime_seconds, today));
    found.extend(power(tuning, hw));
    found.sort_by_key(|i| i.level); // stable: same order within a level
    found
}
