//! Vigil's read-only tools for AI models: the shared registry ([`registry`]) and the MCP server
//! (`vigil mcp`, [`server`]). The in-app investigation uses the same registry.

pub mod registry;
pub mod server;

use std::io::BufReader;
use std::path::PathBuf;

use vigil_i18n::{tl, tr};

use crate::cli::{attach_console, say};

const MCP_HELP: &str = tl!("\
Vigil as an MCP server: AI clients can read this computer's security state through read-only
tools (the latest scan, processes, connections, services, startup entries, scheduled tasks,
security settings, Microsoft Defender, browser extensions, sign-ins, event logs, alerts).
Nothing it offers can change the computer; changes are made in the app, where each one is
confirmed.

Usage: vigil mcp [--report FILE] [--no-anonymize] [--print-config] [--lang CODE]

  --report FILE     the scan report to read (default: the newest one this user can read)
  --no-anonymize    keep user and computer names (they are replaced by default)
  --print-config    print a configuration to paste into an MCP client, and exit
  --log FILE        append each tool call to FILE (used by Vigil's own investigations)

The client starts it and talks to it over stdin and stdout. It runs with the rights of the
user who started it: without administrator rights some data (the Security log, Defender
exclusions, other users' tasks) cannot be read.");

struct Options {
    report: Option<PathBuf>,
    anonymize: bool,
    print_config: bool,
    help: bool,
    log: Option<PathBuf>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        report: None,
        anonymize: true,
        print_config: false,
        help: false,
        log: None,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--report" => {
                let path = iter.next().ok_or_else(|| tr!("{0} needs a value", "--report"))?;
                options.report = Some(PathBuf::from(path));
            }
            "--log" => {
                let path = iter.next().ok_or_else(|| tr!("{0} needs a value", "--log"))?;
                options.log = Some(PathBuf::from(path));
            }
            "--no-anonymize" => options.anonymize = false,
            "--anonymize" => options.anonymize = true,
            "--print-config" => options.print_config = true,
            "-h" | "--help" => options.help = true,
            "--lang" => {
                iter.next();
            }
            other => return Err(tr!("unknown option {0} (see vigil mcp --help)", other)),
        }
    }
    Ok(options)
}

/// `vigil mcp ...`; returns the exit code.
pub fn cli(args: &[String]) -> i32 {
    let early = args
        .iter()
        .position(|a| a == "--lang")
        .and_then(|i| args.get(i + 1))
        .filter(|code| crate::settings::LANGUAGES.contains(&code.as_str()));
    vigil_i18n::set_language(early.map_or("auto", String::as_str));
    let options = match parse(args) {
        Ok(options) => options,
        Err(problem) => {
            attach_console();
            say(&format!("vigil mcp: {problem}"));
            return 2;
        }
    };
    if options.help {
        attach_console();
        say(&tr!(MCP_HELP));
        return 0;
    }
    if options.print_config {
        attach_console();
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "vigil.exe".into());
        say(&server::config_snippets(&exe));
        return 0;
    }
    // Serving: stdout carries only protocol messages, so no console is attached and nothing
    // is printed. A report given explicitly must load; otherwise the newest one is used.
    let report = match &options.report {
        Some(path) => match vigil_scan::pipeline::load_report(path) {
            Ok(analysis) => Some((analysis, path.clone())),
            Err(_) => return 3,
        },
        None => registry::newest_report(),
    };
    let server = server::Server {
        ctx: registry::Context::new(report, options.anonymize),
        log: options.log,
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    match server.serve(BufReader::new(stdin.lock()), stdout.lock()) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}
