//! `vigil scan`: the read-only security scan from the command line, without the window.
//!
//! It collects the inventory, applies the local rules, optionally asks the AI model the user chooses
//! for a second opinion (after showing where the data goes and asking, unless --yes), and writes the
//! HTML and JSON reports. It never changes the system: acting on findings happens in the app.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use serde_json::{Map, Value, json};
use vigil_scan::model::Analysis;

use vigil_i18n::{tl, tr};

use crate::secrets::{self, CredentialStore};

const HELP: &str = tl!("\
Vigil security scan (read-only): an inventory of processes, services, scheduled tasks, startup
entries, programs, browser extensions and events, evaluated with local rules and optionally by an
AI model you choose.

Usage: vigil scan [options]

  --ai PROVIDER    auto, openai-compatible, anthropic-compatible, claude-code, codex-cli,
                   gemini-cli or off (default: auto)
  --model ID       model to use (required for openai-compatible, except a local Ollama server)
  --endpoint URL   address of the API (https://, or http:// on this computer), for example
                   https://api.openai.com/v1 or http://localhost:11434/v1 (Ollama)
  --effort LEVEL   low, medium, high, xhigh or max, for providers that support it (default: high)
  --lang CODE      language of the findings and the AI's answers: auto, en, es, fr, pt or zh
  -y, --yes        send to the AI without asking
  --no-redact      do not replace the user and computer names in what is sent to the AI
  --days N         days of event logs to review (default: 30)
  --output DIR     folder for the reports (default: %USERPROFILE%\\Vigil\\reports)
  --virustotal     look up suspicious file hashes on VirusTotal
  --open           open the HTML report when the scan finishes
  --format NAME    also write the findings as csv, sarif, html or json (see vigil export)
  --out FILE       where to write that file (default: next to the report)
  --anonymize      in that file, replace the user, computer, account and profile folder names
  --force          replace that file if it exists
  --version        print the version

API keys come from the Windows Credential Manager (saved in the app's Settings) or from the
environment: OPENAI_API_KEY, ANTHROPIC_API_KEY, VT_API_KEY. OPENAI_BASE_URL and
ANTHROPIC_BASE_URL set the default address of each standard.

The scan changes nothing on the computer; it only writes the reports. Act on the findings from the
Vigil app.");

struct Options {
    ai: String,
    model: String,
    endpoint: String,
    effort: String,
    lang: String,
    yes: bool,
    redact: bool,
    days: u32,
    output: PathBuf,
    virustotal: bool,
    open: bool,
    /// `--format`: the findings also written in this format.
    format: Option<vigil_scan::export::Format>,
    out: Option<PathBuf>,
    anonymize: bool,
    force: bool,
}

pub(crate) fn say(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
    let _ = out.flush();
}

/// Release builds have no console of their own: write to the one that started us.
pub(crate) fn attach_console() {
    #[cfg(not(debug_assertions))]
    {
        use windows::Win32::System::Console::{ATTACH_PARENT_PROCESS, AllocConsole, AttachConsole};
        // SAFETY: plain calls without pointers; failure only means there is no console to use.
        unsafe {
            if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
                let _ = AllocConsole();
            }
        }
    }
}

fn parse(args: &[String]) -> Result<Option<Options>, String> {
    let home = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut options = Options {
        ai: "auto".into(),
        model: String::new(),
        endpoint: String::new(),
        effort: vigil_scan::ai::DEFAULT_EFFORT.into(),
        lang: "auto".into(),
        yes: false,
        redact: true,
        days: 30,
        output: home.join("Vigil").join("reports"),
        virustotal: false,
        open: false,
        format: None,
        out: None,
        anonymize: false,
        force: false,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let mut value = |name: &str| iter.next().cloned().ok_or(tr!("{0} needs a value", name));
        match arg.as_str() {
            "-h" | "--help" => {
                say(&tr!(HELP));
                return Ok(None);
            }
            "--version" => {
                say(&format!("Vigil {}", env!("CARGO_PKG_VERSION")));
                return Ok(None);
            }
            "--ai" => {
                options.ai = value("--ai")?;
                if vigil_scan::ai::provider_info(&options.ai).is_none() {
                    let known: Vec<&str> = vigil_scan::ai::PROVIDERS.iter().map(|p| p.id).collect();
                    return Err(tr!("--ai must be one of: {0}", known.join(", ")));
                }
            }
            "--model" => {
                options.model = value("--model")?;
                if !vigil_scan::ai::valid_model(&options.model) {
                    return Err(tr!("--model is not a valid model name"));
                }
            }
            "--endpoint" => {
                options.endpoint = vigil_scan::ai::check_endpoint(&value("--endpoint")?)
                    .map_err(|problem| format!("--endpoint: {problem}"))?;
            }
            "--effort" => {
                options.effort = value("--effort")?;
                if !vigil_scan::ai::EFFORTS.contains(&options.effort.as_str()) {
                    return Err(tr!("--effort must be low, medium, high, xhigh or max"));
                }
            }
            "--lang" => {
                options.lang = value("--lang")?;
                if !crate::settings::LANGUAGES.contains(&options.lang.as_str()) {
                    return Err(tr!("--lang must be auto, en, es, fr, pt or zh"));
                }
            }
            "-y" | "--yes" => options.yes = true,
            "--no-redact" => options.redact = false,
            "--days" => {
                options.days = value("--days")?
                    .parse::<u32>()
                    .map_err(|_| tr!("--days needs a number"))?
                    .clamp(1, 365)
            }
            "--output" => options.output = PathBuf::from(value("--output")?),
            "--virustotal" => options.virustotal = true,
            "--open" => options.open = true,
            "--format" => {
                let name = value("--format")?;
                options.format = Some(
                    vigil_scan::export::Format::parse(&name).ok_or(tr!("--format must be csv, sarif, html or json"))?,
                );
            }
            "--out" => options.out = Some(PathBuf::from(value("--out")?)),
            "--anonymize" => options.anonymize = true,
            "--force" => options.force = true,
            other => return Err(tr!("unknown option {0} (see vigil scan --help)", other)),
        }
    }
    if options.format.is_none() && (options.out.is_some() || options.anonymize || options.force) {
        return Err(tr!("--out, --anonymize and --force go with --format"));
    }
    Ok(Some(options))
}

fn clip(text: &str, max: usize) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() <= max {
        text
    } else {
        format!("{}…", text.chars().take(max - 1).collect::<String>())
    }
}

fn set_reason(analysis: &mut Analysis, reason: &str) {
    let mut ai = Map::new();
    ai.insert("reason".into(), json!(reason));
    analysis.ai = ai;
}

fn confirm(question: &str) -> bool {
    print!("{question}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    // Yes in every language Vigil speaks (s/sí/sim/oui/是).
    matches!(
        line.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "si" | "sí" | "sim" | "o" | "oui" | "是"
    )
}

fn run_ai(analysis: &mut Analysis, options: &Options, base: &std::path::Path) {
    if options.ai == "off" {
        set_reason(analysis, &tr!("the scan was run with --ai off"));
        return;
    }
    let store = CredentialStore::default();
    let keys = |id: &str| secrets::lookup(&store, id);
    let probe = vigil_scan::ai::SystemProbe { keys: &keys };
    let config = vigil_scan::ai::AiConfig {
        provider: options.ai.clone(),
        model: options.model.clone(),
        endpoint: options.endpoint.clone(),
        effort: options.effort.clone(),
    };
    let provider = match vigil_scan::ai::pick_provider(&config, &probe) {
        Ok(provider) => provider,
        Err(problem) => {
            set_reason(analysis, &tr!("the AI could not be reached ({0})", problem));
            say(&format!("\n{}", tr!("AI not available: {0}", problem)));
            say(&format!(
                "  {}",
                tr!(
                    "Options: sign in to Claude Code, Codex CLI or Gemini CLI, or set up an OpenAI- or Anthropic-compatible API in the app's Settings (a local server such as Ollama works too). Continuing with the local rules only."
                )
            ));
            return;
        }
    };
    let pending = analysis.items.iter().filter(|i| !i.trusted).count();
    if pending == 0 {
        set_reason(analysis, &tr!("there were no items to send to the AI"));
        return;
    }
    say(&format!(
        "\n{}",
        tr!("AI analysis: {0} items → {1}", pending, provider.destination)
    ));
    if provider.local {
        say(&format!(
            "  {}",
            tr!("The model runs on this computer: nothing leaves it.")
        ));
    }
    say(&format!(
        "  {}",
        if options.redact {
            tr!(
                "Program names, paths, command lines and event excerpts are sent. The user name and the computer name are replaced with placeholders."
            )
        } else {
            tr!("Program names, paths, command lines and event excerpts are sent. They are NOT anonymized.")
        }
    ));
    say(&format!(
        "  {}",
        tr!("Passwords and tokens detected in command lines are always hidden.")
    ));
    if !options.yes {
        if !std::io::stdin().is_terminal() {
            set_reason(
                analysis,
                &tr!("sending to the AI was not authorized (use --yes in non-interactive mode)"),
            );
            say(&format!(
                "  {}",
                tr!("Non-interactive session without --yes: the AI is skipped.")
            ));
            return;
        }
        if !confirm(&format!("  {} ", tr!("Send to the AI? [y/N]"))) {
            set_reason(analysis, &tr!("the user did not authorize sending to the AI"));
            return;
        }
    }
    let name = base.file_name().and_then(|n| n.to_str()).unwrap_or("scan");
    let sent = base.with_file_name(format!("{name}-sent-to-ai.json"));
    let progress = |text: &str| say(&format!("  {text}"));
    if let Err(error) = vigil_scan::ai::ai_analyze(analysis, &provider, options.redact, &progress, Some(&sent)) {
        set_reason(
            analysis,
            &tr!("the AI review failed ({0})", clip(&error.to_string(), 200)),
        );
        say(&format!("  ! {error}"));
    }
    for error in analysis
        .ai
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        say(&format!("  ! {}", error.as_str().unwrap_or("")));
    }
}

const VERDICT_TITLE: [(&str, &str); 6] = [
    ("remove", tl!("REMOVE")),
    ("disable", tl!("DISABLE")),
    ("review", tl!("REVIEW")),
    ("no_signals", tl!("No signals")),
    ("safe", tl!("Safe")),
    ("trusted", tl!("Trusted")),
];

fn print_summary(analysis: &Analysis) {
    say(&format!("\n{}", "=".repeat(72)));
    if let Some(summary) = &analysis.summary {
        let text = |key: &str| summary.get(key).and_then(Value::as_str).unwrap_or("").to_string();
        say(&tr!(
            "{0} RISK: {1}",
            text("risk_level").to_uppercase(),
            text("headline")
        ));
        say(&"=".repeat(72));
    }
    let counts: Vec<String> = VERDICT_TITLE
        .iter()
        .filter_map(|(verdict, title)| {
            let n = analysis.items.iter().filter(|i| i.verdict == *verdict).count();
            (n > 0).then(|| format!("{}: {n}", tr!(title)))
        })
        .collect();
    say(&counts.join("  "));
    for (verdict, title) in &VERDICT_TITLE[..3] {
        let items: Vec<_> = analysis.items.iter().filter(|i| i.verdict == *verdict).collect();
        if items.is_empty() {
            continue;
        }
        say(&format!("\n{} ({})", tr!(title), items.len()));
        for item in items.iter().take(12) {
            let reason = if item.reason.is_empty() {
                &item.what
            } else {
                &item.reason
            };
            let mut line = format!("  [{}] {}", item.id, clip(&item.title, 70));
            if !reason.is_empty() {
                line.push_str(&format!("\n        {}", clip(reason, 150)));
            }
            say(&line);
        }
        if items.len() > 12 {
            say(&format!(
                "  {}",
                tr!("... and {0} more in the report", items.len() - 12)
            ));
        }
    }
}

/// Runs `vigil scan`; returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    attach_console();
    // Help and option errors use --lang when it is given, otherwise the Windows display language.
    let early = args
        .iter()
        .position(|a| a == "--lang")
        .and_then(|i| args.get(i + 1))
        .filter(|code| crate::settings::LANGUAGES.contains(&code.as_str()));
    vigil_i18n::set_language(early.map_or("auto", String::as_str));
    let options = match parse(args) {
        Ok(Some(options)) => options,
        Ok(None) => return 0,
        Err(problem) => {
            say(&format!("vigil scan: {problem}"));
            return 2;
        }
    };
    // Findings, messages and the AI's answers are written in this language.
    vigil_i18n::set_language(&options.lang);
    if let Err(error) = std::fs::create_dir_all(&options.output) {
        say(&tr!(
            "Could not create the output folder {0}: {1}",
            options.output.display(),
            error
        ));
        return 2;
    }
    let base = vigil_scan::pipeline::scan_base(&options.output);
    let vt_key = if options.virustotal {
        let key = secrets::lookup(&CredentialStore::default(), "virustotal");
        if key.is_none() {
            say(&tr!(
                "--virustotal: save a VirusTotal key in the app's Settings or set VT_API_KEY. Continuing without VirusTotal."
            ));
        }
        key
    } else {
        None
    };
    say(&tr!(
        "Vigil scan v{0} — read-only, it changes nothing on the computer",
        env!("CARGO_PKG_VERSION")
    ));
    if !vigil_actions::is_admin() {
        say(&tr!(
            "Warning: without administrator rights the coverage is partial (the Security event log and the antivirus exclusions cannot be read)."
        ));
    }
    let started = Instant::now();
    let cancel = AtomicBool::new(false);
    let progress = |text: &str| say(&format!("  {text}"));
    say(&format!("\n{}", tr!("Collecting the inventory...")));
    // The same signature cache as the app, in the data folder of this user or of the elevated copy.
    let cache = vigil_actions::data_dir()
        .ok()
        .map(|root| root.join(crate::api::SIGNATURE_CACHE));
    let (raw, mut analysis) = match vigil_scan::collect_and_analyze_cached(
        options.days,
        vt_key.as_deref(),
        cache.as_deref(),
        &progress,
        &cancel,
    ) {
        Ok(result) => result,
        Err(error) => {
            say(&tr!("The scan failed: {0}", error));
            return 1;
        }
    };
    let name = base.file_name().and_then(|n| n.to_str()).unwrap_or("scan").to_string();
    if let Err(error) = std::fs::write(base.with_file_name(format!("{name}-inventory.json")), raw.to_string()) {
        say(&tr!("The raw inventory could not be saved: {0}", error));
    }
    let stat = |key: &str| analysis.stats.get(key).and_then(Value::as_u64).unwrap_or(0);
    say(&format!(
        "  {}",
        tr!(
            "{0} items: {1} verified automatically, {2} to study",
            stat("elements"),
            stat("auto_trusted"),
            stat("to_analyze")
        )
    ));
    run_ai(&mut analysis, &options, &base);
    if let Some(changes) = vigil_scan::pipeline::attach_changes(&mut analysis, &base) {
        say(&format!(
            "  {}",
            tr!(
                "Since the last scan: {0} new, {1} gone, {2} changed, {3} settings changed",
                changes.new.len(),
                changes.gone.len(),
                changes.changed.len(),
                changes.posture.len()
            )
        ));
    }
    let (json_path, html_path) = match vigil_scan::pipeline::save_report(&analysis, &base, true) {
        Ok(paths) => paths,
        Err(error) => {
            say(&tr!("The report could not be saved: {0}", error));
            return 1;
        }
    };
    print_summary(&analysis);
    if let Some(html) = &html_path {
        say(&format!("\n{}", tr!("Report: {0}", html.display())));
    }
    say(&tr!("Data: {0}", json_path.display()));
    if let Some(format) = options.format {
        let out = options
            .out
            .clone()
            .unwrap_or_else(|| base.with_file_name(format!("{name}-findings.{}", format.extension())));
        let export = vigil_scan::export::Options {
            anonymize: options.anonymize,
            include_trusted: false,
        };
        if let Err(problem) = crate::export::write_export(&analysis, format, export, &out, options.force) {
            say(&problem);
            return 1;
        }
    }
    if let Some(log) = analysis.ai.get("sent_log").and_then(Value::as_str) {
        say(&tr!("Sent to the AI (for your review): {0}", log));
    }
    say(&tr!(
        "Total time: {0} s",
        format!("{:.0}", started.elapsed().as_secs_f64())
    ));
    if options.open
        && let Some(html) = &html_path
        && let Err(error) = open_with_default_app(html)
    {
        say(&tr!("Could not open the report: {0}", error));
    }
    0
}

/// Opens our own report with the default browser (Explorer by absolute path, argument list).
fn open_with_default_app(path: &std::path::Path) -> std::io::Result<()> {
    let windir = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    std::process::Command::new(windir.join("explorer.exe"))
        .arg(path)
        .spawn()
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn options_parse_and_validate() {
        let parsed = parse(&args(&["--ai", "off", "--days", "7", "-y", "--no-redact"]));
        let Ok(Some(options)) = parsed else {
            panic!("options did not parse")
        };
        assert_eq!(options.ai, "off");
        assert_eq!(options.days, 7);
        assert!(options.yes && !options.redact);
        assert!(parse(&args(&["--ai", "gpt"])).is_err());
        assert!(parse(&args(&["--effort", "huge"])).is_err());
        let Ok(Some(local)) = parse(&args(&[
            "--ai",
            "openai-compatible",
            "--model",
            "qwen3:14b",
            "--endpoint",
            "http://localhost:11434/v1/",
            "--lang",
            "es",
        ])) else {
            panic!("local options did not parse")
        };
        assert_eq!(
            (local.ai.as_str(), local.endpoint.as_str(), local.lang.as_str()),
            ("openai-compatible", "http://localhost:11434/v1", "es")
        );
        assert!(
            parse(&args(&["--endpoint", "http://203.0.113.7:11434"])).is_err(),
            "plain http only on this computer"
        );
        assert!(parse(&args(&["--model", "a b"])).is_err());
        assert!(parse(&args(&["--lang", "de"])).is_err());
        assert!(parse(&args(&["--days"])).is_err());
        assert!(parse(&args(&["--rm"])).is_err());
        let export = parse(&args(&["--format", "csv", "--out", "a.csv", "--anonymize", "--force"]));
        assert!(
            matches!(export, Ok(Some(ref o)) if o.format == Some(vigil_scan::export::Format::Csv)
            && o.out.as_deref() == Some(std::path::Path::new("a.csv")) && o.anonymize && o.force)
        );
        assert!(parse(&args(&["--format", "pdf"])).is_err());
        assert!(parse(&args(&["--out", "a.csv"])).is_err(), "--out needs --format");
    }

    #[test]
    fn clip_shortens_and_flattens() {
        assert_eq!(clip("a  b\nc", 10), "a b c");
        assert_eq!(clip("abcdefghij", 5), "abcd…");
    }
}
