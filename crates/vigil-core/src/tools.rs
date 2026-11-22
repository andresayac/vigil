//! `vigil list`, `vigil ports`, `vigil services`, `vigil programs`, `vigil reliability` and `vigil --help`:
//! read-only views of the computer for a terminal or a script (`--json`). They never change
//! anything.

use std::time::Duration;

use serde_json::{Value, json};
use vigil_i18n::{tl, tr};

use crate::cli::{attach_console, say};
use crate::requests::size_text;

const TOP_HELP: &str = tl!("\
Vigil: security analysis, live performance and maintenance for Windows.

Usage:
  vigil                       open the app
  vigil scan [options]        read-only security scan (see vigil scan --help)
  vigil list [options]        running processes
  vigil ports [options]       network connections and listening ports
  vigil services [options]    Windows services
  vigil programs [options]    installed programs
  vigil reliability [options] crashes, blue screens and other problems
  vigil export [options]      a saved report as CSV, SARIF, HTML or JSON
  vigil mcp [options]         read-only tools for AI clients (MCP server)

  --no-elevate                open the app without asking for administrator rights
  --lang CODE                 language: auto, en, es, fr, pt or zh

These commands only read; changes are made from the app.");

const LIST_HELP: &str = tl!("\
Running processes, with CPU measured over one second.

Usage: vigil list [--sort cpu|mem|name|pid] [-n N] [--json] [--lang CODE]

  --sort KEY   order: cpu (default), mem, name or pid
  -n N         how many processes to show (default: 25; 0 for all)
  --json       machine-readable output");

const PORTS_HELP: &str = tl!("\
Network connections and listening ports, with the process that owns each one.

Usage: vigil ports [--listening] [--json] [--lang CODE]

  --listening  only listening ports
  --json       machine-readable output");

const SERVICES_HELP: &str = tl!("\
Windows services with their state and startup type.

Usage: vigil services [--running] [--json] [--lang CODE]

  --running    only running services
  --json       machine-readable output");

/// The commands handled here.
pub const COMMANDS: [&str; 9] = [
    "list",
    "ports",
    "services",
    "programs",
    "reliability",
    "export",
    "help",
    "--help",
    "-h",
];

/// Runs one of [`COMMANDS`]; returns the exit code.
pub fn run(command: &str, args: &[String]) -> i32 {
    attach_console();
    let early = args
        .iter()
        .position(|a| a == "--lang")
        .and_then(|i| args.get(i + 1))
        .filter(|code| crate::settings::LANGUAGES.contains(&code.as_str()));
    vigil_i18n::set_language(early.map_or("auto", String::as_str));
    let result = match command {
        "list" => list(args),
        "ports" => ports(args),
        "services" => services(args),
        "programs" => crate::programs::cli(args),
        "reliability" => crate::reliability::cli(args),
        "export" => crate::export::cli(args),
        _ => {
            say(&tr!(TOP_HELP));
            Ok(())
        }
    };
    match result {
        Ok(()) => 0,
        Err(problem) => {
            say(&format!("vigil {command}: {problem}"));
            2
        }
    }
}

/// Flags shared by the commands: (json, help) and the remaining arguments checked by `accept`.
pub(crate) fn flags(
    args: &[String],
    mut accept: impl FnMut(&str, &mut dyn Iterator<Item = &String>) -> Result<bool, String>,
) -> Result<(bool, bool), String> {
    let mut json = false;
    let mut help = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => help = true,
            "--lang" => {
                iter.next();
            }
            other => {
                if !accept(other, &mut iter)? {
                    return Err(tr!("unknown option {0} (see vigil --help)", other));
                }
            }
        }
    }
    Ok((json, help))
}

pub(crate) fn print_json(value: &Value) {
    say(&serde_json::to_string_pretty(value).unwrap_or_default());
}

fn clip(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else {
        format!("{}…", text.chars().take(width.saturating_sub(1)).collect::<String>())
    }
}

/// A plain text table: headers, then rows; the last column is not padded.
pub(crate) fn table(headers: &[String], rows: &[Vec<String>], widths: &[usize]) {
    let line = |cells: &[String]| {
        let mut out = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                out.push_str(cell);
            } else {
                let width = widths.get(i).copied().unwrap_or(12);
                let text = clip(cell, width);
                out.push_str(&text);
                out.push_str(&" ".repeat(width.saturating_sub(text.chars().count()) + 2));
            }
        }
        out.trim_end().to_string()
    };
    say(&line(headers));
    for row in rows {
        say(&line(row));
    }
}

// ---------------------------------------------------------------- vigil list

fn list(args: &[String]) -> Result<(), String> {
    let mut sort = "cpu".to_string();
    let mut limit = 25usize;
    let (json, help) = flags(args, |arg, rest| match arg {
        "--sort" => {
            sort = rest.next().cloned().ok_or(tr!("{0} needs a value", "--sort"))?;
            if !["cpu", "mem", "name", "pid"].contains(&sort.as_str()) {
                return Err(tr!("--sort must be cpu, mem, name or pid"));
            }
            Ok(true)
        }
        "-n" => {
            limit = rest
                .next()
                .and_then(|n| n.parse::<usize>().ok())
                .ok_or(tr!("-n needs a number"))?;
            Ok(true)
        }
        _ => Ok(false),
    })?;
    if help {
        say(&tr!(LIST_HELP));
        return Ok(());
    }
    let mut sampler = vigil_sys::process::ProcessSampler::new().map_err(|e| e.to_string())?;
    // CPU use is the difference between two samples.
    sampler.snapshot().map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_millis(1000));
    let mut rows = sampler.snapshot().map_err(|e| e.to_string())?;
    // PID 0 is the System Idle Process: its "CPU" is the time nothing ran, not a program.
    rows.retain(|r| r.pid != 0);
    match sort.as_str() {
        "mem" => rows.sort_by_key(|r| std::cmp::Reverse(r.private_bytes)),
        "name" => rows.sort_by_key(|r| r.name.to_lowercase()),
        "pid" => rows.sort_by_key(|r| r.pid),
        _ => rows.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(b.private_bytes.cmp(&a.private_bytes))),
    }
    if limit > 0 {
        rows.truncate(limit);
    }
    if json {
        print_json(&Value::Array(
            rows.iter()
                .map(|r| {
                    json!({"pid": r.pid, "parent": r.ppid, "name": r.name, "cpu": (f64::from(r.cpu) * 10.0).round() / 10.0,
                           "memory": r.private_bytes, "working_set": r.working_set, "threads": r.threads,
                           "user": r.user, "path": r.exe})
                })
                .collect(),
        ));
        return Ok(());
    }
    let headers = [tr!("PID"), tr!("CPU %"), tr!("Memory"), tr!("Name"), tr!("Path")];
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.pid.to_string(),
                format!("{:.1}", r.cpu),
                size_text(r.private_bytes),
                r.name.clone(),
                r.exe.clone(),
            ]
        })
        .collect();
    table(&headers, &body, &[7, 6, 11, 28]);
    Ok(())
}

// ---------------------------------------------------------------- vigil ports

/// Well-known ports (protocol names are the same in every language; Windows features are translated).
pub fn port_service(port: u16) -> String {
    let name = match port {
        20 => "FTP data",
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        80 => "HTTP",
        88 => "Kerberos",
        110 => "POP3",
        123 => "NTP",
        135 => "RPC",
        137..=139 => "NetBIOS",
        143 => "IMAP",
        161 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 | 587 => "SMTP",
        500 | 4500 => "IPsec",
        636 => "LDAPS",
        853 => "DNS over TLS",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "SQL Server",
        1900 => "SSDP (UPnP)",
        3306 => "MySQL",
        3389 => return tr!("Remote Desktop"),
        5040 => return tr!("Connected Devices Platform"),
        5353 => "mDNS",
        5355 => "LLMNR",
        5357 => "WSD",
        5432 => "PostgreSQL",
        5900 => "VNC",
        5938 => "TeamViewer",
        5985 | 5986 => "WinRM",
        6379 => "Redis",
        7680 => return tr!("Delivery Optimization"),
        8080 | 8443 => "HTTP(S)",
        11434 => "Ollama",
        27017 => "MongoDB",
        51820 => "WireGuard",
        _ => "",
    };
    name.to_string()
}

fn port_of(address: &str) -> Option<u16> {
    address.rsplit_once(':').and_then(|(_, port)| port.parse().ok())
}

fn ports(args: &[String]) -> Result<(), String> {
    let mut listening = false;
    let (json, help) = flags(args, |arg, _| {
        Ok(match arg {
            "--listening" => {
                listening = true;
                true
            }
            _ => false,
        })
    })?;
    if help {
        say(&tr!(PORTS_HELP));
        return Ok(());
    }
    let mut rows = vigil_sys::net::connections().map_err(|e| e.to_string())?;
    if listening {
        rows.retain(|c| c.remote.is_empty());
    }
    rows.sort_by(|a, b| {
        a.process
            .to_lowercase()
            .cmp(&b.process.to_lowercase())
            .then(a.local.cmp(&b.local))
    });
    let service = |c: &vigil_sys::net::Connection| {
        let address = if c.remote.is_empty() { &c.local } else { &c.remote };
        port_of(address).map(port_service).unwrap_or_default()
    };
    if json {
        print_json(&Value::Array(
            rows.iter()
                .map(|c| {
                    json!({"protocol": c.protocol, "local": c.local, "remote": c.remote, "state": c.state,
                           "pid": c.pid, "process": c.process, "path": c.exe, "service": service(c),
                           "internet": c.public})
                })
                .collect(),
        ));
        return Ok(());
    }
    let headers = [
        tr!("Protocol"),
        tr!("Local address"),
        tr!("Remote address"),
        tr!("State"),
        tr!("Service"),
        tr!("Process"),
    ];
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|c| {
            vec![
                c.protocol.clone(),
                c.local.clone(),
                c.remote.clone(),
                c.state.clone(),
                service(c),
                format!("{} ({})", c.process, c.pid),
            ]
        })
        .collect();
    table(&headers, &body, &[8, 24, 24, 12, 16]);
    Ok(())
}

// ---------------------------------------------------------------- vigil services

/// The display name of a service state.
pub fn state_label(state: &str) -> String {
    match state {
        "running" => tr!("Running"),
        "stopped" => tr!("Stopped"),
        "start_pending" => tr!("Starting"),
        "stop_pending" => tr!("Stopping"),
        "paused" => tr!("Paused"),
        "pause_pending" | "continue_pending" => tr!("Changing"),
        other => other.to_string(),
    }
}

/// The display name of a startup type.
pub fn start_label(start: &str) -> String {
    crate::requests::START_TYPES
        .iter()
        .find(|(value, _)| *value == start)
        .map(|(_, text)| tr!(text))
        .unwrap_or_else(|| match start {
            "boot" | "system" => tr!("Boot"),
            other => other.to_string(),
        })
}

fn services(args: &[String]) -> Result<(), String> {
    let mut running = false;
    let (json, help) = flags(args, |arg, _| {
        Ok(match arg {
            "--running" => {
                running = true;
                true
            }
            _ => false,
        })
    })?;
    if help {
        say(&tr!(SERVICES_HELP));
        return Ok(());
    }
    let mut rows = vigil_sys::services::list().map_err(|e| e.to_string())?;
    if running {
        rows.retain(|s| s.state == "running");
    }
    if json {
        print_json(&serde_json::to_value(&rows).unwrap_or(Value::Null));
        return Ok(());
    }
    let headers = [
        tr!("Name"),
        tr!("State"),
        tr!("Startup type"),
        tr!("PID"),
        tr!("Display name"),
    ];
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|s| {
            vec![
                s.name.clone(),
                state_label(&s.state),
                start_label(&s.start_type),
                if s.pid == 0 { String::new() } else { s.pid.to_string() },
                s.display_name.clone(),
            ]
        })
        .collect();
    table(&headers, &body, &[28, 10, 26, 7]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_are_named_and_parsed() {
        assert_eq!(port_of("[::]:445"), Some(445));
        assert_eq!(port_of("192.168.1.20:52114"), Some(52114));
        assert_eq!(port_service(443), "HTTPS");
        assert_eq!(
            vigil_i18n::with_language("es", || port_service(3389)),
            "Escritorio remoto"
        );
        assert_eq!(port_service(40000), "");
    }

    #[test]
    fn labels_follow_the_language() {
        assert_eq!(state_label("running"), "Running");
        assert_eq!(start_label("delayed-auto"), "Automatic (delayed start)");
        assert_eq!(vigil_i18n::with_language("es", || start_label("demand")), "Manual");
    }

    #[test]
    fn options_are_checked() {
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(list(&args(&["--sort", "colour"])).is_err());
        assert!(list(&args(&["-n", "many"])).is_err());
        assert!(ports(&args(&["--bogus"])).is_err());
        assert!(services(&args(&["--help"])).is_ok());
    }
}
