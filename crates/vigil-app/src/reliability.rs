//! The Reliability page and `vigil reliability`: blue screens, unexpected shutdowns, crashing and
//! hanging programs, service, hardware and disk errors, failed updates and installs, read from the
//! event logs. Read-only: nothing here changes the computer.

use std::time::Duration;

use serde_json::Value;
use vigil_i18n::{tl, tr};
use vigil_sys::reliability::{AppGroup, DEFAULT_DAYS, Hint, MAX_DAYS, Reliability, ReliabilityEvent};

use crate::cli::say;
use crate::tools::{flags, print_json, table};

/// A busy log takes well under a second; this only bounds a stuck Event Log service.
const READ_TIMEOUT: Duration = Duration::from_secs(45);

const HELP: &str = tl!("\
Crashes, blue screens and other problems Windows recorded in its event logs.

Usage: vigil reliability [--days N] [--json] [--lang CODE]

  --days N     how many days back to look (default: 30, at most 365)
  --json       machine-readable output");

/// The last `days` days of the event logs, with the hints written in the user's language.
pub fn load(days: u32) -> Result<Reliability, String> {
    let mut data =
        vigil_sys::reliability::read(days, READ_TIMEOUT).map_err(|e| tr!("Could not read the event logs: {0}", e))?;
    for hint in &mut data.hints {
        let (title, text) = hint_text(hint);
        hint.title = title;
        hint.text = text;
    }
    Ok(data)
}

/// The Reliability page's data (read-only).
#[tauri::command]
pub async fn reliability_read(days: Option<u32>) -> Result<Reliability, String> {
    let days = days.unwrap_or(DEFAULT_DAYS);
    tauri::async_runtime::spawn_blocking(move || load(days))
        .await
        .map_err(|e| e.to_string())?
}

/// "disk 2" for `\Device\Harddisk2\DR3`; other names as they are.
pub fn device_name(device: &str) -> String {
    let lower = device.to_ascii_lowercase();
    lower
        .find("harddisk")
        .map(|i| &device[i + "harddisk".len()..])
        .map(|rest| rest.chars().take_while(char::is_ascii_digit).collect::<String>())
        .filter(|number| !number.is_empty())
        .map_or_else(|| device.to_string(), |number| tr!("disk {0}", number))
}

/// The title and text of a hint. They say what the logs show and what usually helps; none of them
/// is a diagnosis.
pub fn hint_text(hint: &Hint) -> (String, String) {
    let n = hint.count;
    let subject = hint.subject.as_str();
    match hint.code {
        "hardware_errors" if hint.severity == "warn" => (
            tr!("Hardware errors"),
            if n == 1 {
                tr!(
                    "Windows recorded a hardware error it could not fully correct. It comes from the processor, memory, motherboard or an expansion card, not from programs. Check temperatures, undo any overclocking and update the BIOS; if it happens again, have the hardware tested."
                )
            } else {
                tr!(
                    "Windows recorded {0} hardware errors it could not fully correct. They come from the processor, memory, motherboard or an expansion card, not from programs. Check temperatures, undo any overclocking and update the BIOS; if they continue, have the hardware tested.",
                    n
                )
            },
        ),
        "hardware_errors" => (
            tr!("Corrected hardware errors"),
            tr!(
                "Windows corrected {0} hardware errors on its own. Corrected errors do no harm by themselves, but a steady stream of them can announce a failing part; check temperatures and undo any overclocking.",
                n
            ),
        ),
        "graphics_driver" => (
            tr!("Graphics driver"),
            if n == 1 {
                tr!(
                    "One problem involves the graphics driver ({0}). Install the latest driver from the graphics card maker (NVIDIA, AMD or Intel); if it started after a driver update, go back to the previous version.",
                    subject
                )
            } else {
                tr!(
                    "{0} problems involve the graphics driver ({1}). Install the latest driver from the graphics card maker (NVIDIA, AMD or Intel); if they started after a driver update, go back to the previous version.",
                    n,
                    subject
                )
            },
        ),
        "memory_stop_codes" => (
            tr!("Blue screens that can point to memory"),
            if n == 1 {
                tr!(
                    "A blue screen with the stop code {0}. It often comes from faulty memory, sometimes from a driver. Windows Memory Diagnostic (mdsched.exe) tests the memory at the next restart.",
                    subject
                )
            } else {
                tr!(
                    "{0} blue screens with stop codes such as {1}. They often come from faulty memory, sometimes from a driver. Windows Memory Diagnostic (mdsched.exe) tests the memory at the next restart.",
                    n,
                    subject
                )
            },
        ),
        "disk_errors" => (
            tr!("Disk errors"),
            if n == 1 {
                tr!(
                    "A read, write or file system error was recorded ({0}). Back up what matters, then check the drive's health on the System page.",
                    device_name(subject)
                )
            } else {
                tr!(
                    "{0} read, write or file system errors were recorded ({1}). Back up what matters, then check the drive's health on the System page.",
                    n,
                    device_name(subject)
                )
            },
        ),
        "disk_retries" => (
            tr!("Disk retries"),
            tr!(
                "Windows retried {0} reads or writes on {1}. Occasional retries are harmless; many can mean a loose cable, a USB drive without enough power or a disk that is wearing out.",
                n,
                device_name(subject)
            ),
        ),
        "repeated_stop_code" => (
            tr!("The same blue screen again"),
            tr!(
                "The stop code {1} ({2}) happened {0} times. When one stop code repeats, a driver is the usual cause: think of what changed before the first one (new hardware, a driver or a Windows update).",
                n,
                subject,
                hint.detail
            ),
        ),
        "manual_crash" => (
            tr!("Blue screens started on purpose"),
            if n == 1 {
                tr!(
                    "A blue screen was started on purpose ({0}), with a keyboard shortcut, a tool or by holding the power button. It is not a fault.",
                    subject
                )
            } else {
                tr!(
                    "{0} blue screens were started on purpose ({1}), with a keyboard shortcut, a tool or by holding the power button. They are not a fault.",
                    n,
                    subject
                )
            },
        ),
        "power_loss" => (
            tr!("Shutdowns without a blue screen"),
            if n == 1 {
                tr!(
                    "The computer stopped once without shutting down properly and without a blue screen. That usually means a power cut, a forced restart or the computer freezing completely. If it happens while you use it normally, check the power supply and temperatures."
                )
            } else {
                tr!(
                    "The computer stopped {0} times without shutting down properly and without a blue screen. That usually means a power cut, a forced restart or the computer freezing completely. If it happens while you use it normally, check the power supply and temperatures.",
                    n
                )
            },
        ),
        "power_button" => (
            tr!("Switched off with the power button"),
            if n == 1 {
                tr!(
                    "The power button was used once to switch the computer off, usually because it had stopped responding."
                )
            } else {
                tr!(
                    "The power button was used {0} times to switch the computer off, usually because it had stopped responding.",
                    n
                )
            },
        ),
        "shared_module" => (
            tr!("One module in several crashes"),
            tr!(
                "{0} crashes in {2} different programs happened inside {1}. That points to {1} (or the add-in, overlay, security program or driver it belongs to) rather than to the programs themselves.",
                n,
                subject,
                hint.detail
            ),
        ),
        "app_repeat" => (
            tr!("{0} keeps crashing", subject),
            tr!(
                "{0} crashed {1} times. Update it, or repair or reinstall it; if it keeps crashing, its maker's support can use the details of these crashes.",
                subject,
                n
            ),
        ),
        "update_repeat" => (
            tr!("An update keeps failing"),
            tr!(
                "{0} failed to install {1} times (error {2}). Windows tries again on its own; if it keeps failing, the Windows Update troubleshooter in Settings can repair the update components.",
                subject,
                n,
                hint.detail
            ),
        ),
        "service_repeat" => (
            tr!("A service keeps stopping"),
            tr!(
                "The service {0} stopped unexpectedly {1} times. Windows usually starts it again; if it belongs to a program you no longer use, uninstall that program.",
                subject,
                n
            ),
        ),
        other => (other.to_string(), String::new()),
    }
}

/// The name of a category, for the terminal.
pub fn category_label(category: &str) -> String {
    match category {
        "bluescreen" => tr!("Blue screens"),
        "shutdown" => tr!("Unexpected shutdowns"),
        "app_crash" => tr!("Program crashes"),
        "app_hang" => tr!("Programs not responding"),
        "service" => tr!("Service failures"),
        "hardware" => tr!("Hardware errors"),
        "disk" => tr!("Disk errors"),
        "update" => tr!("Failed updates"),
        "install" => tr!("Installs and removals"),
        other => other.to_string(),
    }
}

/// What happened, in a few words, for the terminal.
pub fn kind_label(event: &ReliabilityEvent) -> String {
    match event.kind {
        "power_loss" => tr!("Lost power or forced restart"),
        "power_button" => tr!("Switched off with the power button"),
        "unexpected" => tr!("Unexpected shutdown"),
        "crashed" => tr!("Stopped unexpectedly"),
        "start_failed" => tr!("Could not start"),
        "start_timeout" => tr!("Did not start in time"),
        "stopped_with_error" => tr!("Stopped with an error"),
        "fatal" => tr!("Hardware error"),
        "corrected" => tr!("Corrected hardware error"),
        "bad_block" => tr!("Bad block"),
        "controller_error" => tr!("Controller error"),
        "paging_error" => tr!("Error while paging"),
        "retried" => tr!("Read or write retried"),
        "corruption" => tr!("File system damaged"),
        "needs_repair" => tr!("Volume needs a repair"),
        "install_failed" if event.category == "update" => tr!("Update failed"),
        "installed" => tr!("Installed"),
        "install_failed" => tr!("Install failed"),
        "removed" => tr!("Removed"),
        "remove_failed" => tr!("Removal failed"),
        "crash" => tr!("Crashed"),
        "hang" => tr!("Stopped responding"),
        _ => tr!("Blue screen"),
    }
}

/// `2026-01-01T10:05:00` as `2026-01-01 10:05`.
fn short_time(time: &str) -> String {
    time.get(..16).unwrap_or(time).replace('T', " ")
}

fn subject_of(event: &ReliabilityEvent) -> String {
    let subject = match event.category {
        "disk" => device_name(&event.subject),
        _ => event.subject.clone(),
    };
    match (event.category, event.code.is_empty()) {
        ("bluescreen", _) if !event.code_name.is_empty() => format!("{} ({})", event.code_name, event.code),
        ("update" | "service", false) => format!("{subject} ({})", event.code),
        _ => subject,
    }
}

/// `vigil reliability`.
pub fn cli(args: &[String]) -> Result<(), String> {
    let mut days = DEFAULT_DAYS;
    let (json, help) = flags(args, |arg, rest| match arg {
        "--days" => {
            days = rest
                .next()
                .and_then(|n| n.parse::<u32>().ok())
                .filter(|n| (1..=MAX_DAYS).contains(n))
                .ok_or(tr!("--days needs a number from 1 to {0}", MAX_DAYS))?;
            Ok(true)
        }
        _ => Ok(false),
    })?;
    if help {
        say(&tr!(HELP));
        return Ok(());
    }
    let data = load(days)?;
    if json {
        print_json(&serde_json::to_value(&data).unwrap_or(Value::Null));
        return Ok(());
    }
    print_text(&data);
    Ok(())
}

fn print_text(data: &Reliability) {
    say(&tr!("Last {0} days:", data.days));
    for category in vigil_sys::reliability::CATEGORIES {
        let count = data.counts.get(category).copied().unwrap_or(0);
        say(&format!("  {:<32}{count}", category_label(category)));
    }
    if !data.hints.is_empty() {
        say("");
        for hint in &data.hints {
            say(&format!("* {}", hint.title));
            say(&format!("  {}", hint.text));
        }
    }
    if !data.crashing_apps.is_empty() {
        say("");
        say(&tr!("Programs that crashed:"));
        apps_table(&data.crashing_apps, true);
    }
    if !data.hanging_apps.is_empty() {
        say("");
        say(&tr!("Programs that stopped responding:"));
        apps_table(&data.hanging_apps, false);
    }
    let problems: Vec<&ReliabilityEvent> = data
        .events
        .iter()
        .filter(|e| !matches!(e.category, "install" | "app_crash" | "app_hang"))
        .take(25)
        .collect();
    if !problems.is_empty() {
        say("");
        say(&tr!("Latest problems:"));
        let headers = [tr!("Time"), tr!("Type"), tr!("What happened"), tr!("Details")];
        let rows: Vec<Vec<String>> = problems
            .iter()
            .map(|e| {
                vec![
                    short_time(&e.time),
                    category_label(e.category),
                    kind_label(e),
                    subject_of(e),
                ]
            })
            .collect();
        table(&headers, &rows, &[16, 24, 30]);
    }
    if data
        .unread_logs
        .iter()
        .any(|log| log.contains("Diagnostics-Performance"))
    {
        say("");
        say(&tr!("Boot times are read only when Vigil runs as administrator."));
    }
    if data
        .unread_logs
        .iter()
        .any(|log| !log.contains("Diagnostics-Performance"))
    {
        say(&tr!(
            "Some event logs could not be read: {0}",
            data.unread_logs.join(", ")
        ));
    }
}

fn apps_table(groups: &[AppGroup], crashes: bool) {
    let mut headers = vec![tr!("Times"), tr!("Last"), tr!("Program")];
    if crashes {
        headers.push(tr!("Module it failed in"));
    }
    let rows: Vec<Vec<String>> = groups
        .iter()
        .take(15)
        .map(|g| {
            let last = vigil_sys::reliability::local_time(g.last_ms);
            let mut row = vec![g.count.to_string(), short_time(&last), g.name.clone()];
            if crashes {
                row.push(if g.top_module.is_empty() {
                    String::new()
                } else {
                    format!("{} ({})", g.top_module, g.top_module_count)
                });
            }
            row
        })
        .collect();
    table(&headers, &rows, &[6, 16, 32]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(code: &'static str, severity: &'static str, subject: &str, count: usize, detail: &str) -> Hint {
        Hint {
            code,
            severity,
            subject: subject.into(),
            count,
            detail: detail.into(),
            ..Hint::default()
        }
    }

    #[test]
    fn every_hint_has_a_text() {
        let hints = [
            hint("hardware_errors", "warn", "", 2, ""),
            hint("hardware_errors", "info", "", 5, ""),
            hint("graphics_driver", "warn", "nvlddmkm.sys", 3, ""),
            hint("memory_stop_codes", "warn", "MEMORY_MANAGEMENT", 1, ""),
            hint("disk_errors", "warn", r"\Device\Harddisk1\DR1", 4, ""),
            hint("disk_retries", "info", r"\Device\Harddisk2\DR3", 40, ""),
            hint(
                "repeated_stop_code",
                "warn",
                "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
                2,
                "0x000000D1",
            ),
            hint("manual_crash", "info", "MANUALLY_INITIATED_CRASH", 1, ""),
            hint("power_loss", "info", "", 3, ""),
            hint("power_button", "info", "", 1, ""),
            hint("shared_module", "warn", "contoso.dll", 4, "2"),
            hint("app_repeat", "info", "notes.exe", 6, ""),
            hint("update_repeat", "info", "Contoso Notes 1.2", 9, "0x80073D02"),
            hint("service_repeat", "info", "Contoso Updater", 3, ""),
        ];
        for hint in &hints {
            let (title, text) = hint_text(hint);
            assert!(!title.is_empty() && !text.is_empty(), "{}", hint.code);
            assert!(!text.contains('{'), "{text}");
        }
        let (_, text) = hint_text(&hints[4]);
        assert!(text.contains("disk 1"), "{text}");
        let (title, text) = vigil_i18n::with_language("es", || hint_text(&hints[11]));
        assert!(title.contains("notes.exe") && text.contains('6'), "{title} {text}");
        assert_ne!(title, "notes.exe keeps crashing");
    }

    #[test]
    fn devices_and_labels() {
        assert_eq!(device_name(r"\Device\Harddisk2\DR3"), "disk 2");
        assert_eq!(device_name("C:"), "C:");
        assert_eq!(device_name(r"\Device\HarddiskVolume"), r"\Device\HarddiskVolume");
        assert_eq!(short_time("2026-01-01T10:05:00"), "2026-01-01 10:05");
        assert_eq!(category_label("bluescreen"), "Blue screens");
        for category in vigil_sys::reliability::CATEGORIES {
            assert_ne!(category_label(category), category);
        }
        let event = ReliabilityEvent {
            category: "bluescreen",
            kind: "bugcheck",
            code: "0x0000007E".into(),
            code_name: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED".into(),
            ..ReliabilityEvent::default()
        };
        assert_eq!(subject_of(&event), "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (0x0000007E)");
        assert_eq!(kind_label(&event), "Blue screen");
    }

    #[test]
    fn options_are_checked() {
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(cli(&args(&["--days", "0"])).is_err());
        assert!(cli(&args(&["--days", "many"])).is_err());
        assert!(cli(&args(&["--days", "400"])).is_err());
        assert!(cli(&args(&["--bogus"])).is_err());
        assert!(cli(&args(&["--help"])).is_ok());
    }
}
