//! Local AI agents driven through their command line: Claude Code, Codex CLI and Gemini CLI.
//!
//! Each one uses the account the user already signed in to. They are coding agents, so every call
//! takes their tools away (or, where a CLI cannot remove them, restricts them to a read-only
//! sandbox without network or shell), runs in an empty temporary folder, and receives the
//! inventory through stdin only: nothing from the inspected computer is ever put on a command line.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::Value;

use super::agent::McpLaunch;
use super::{AiError, Provider, failed, parse_json_text};
use crate::collect::{ChildError, Finished, run_child};
use crate::lenient::{Get, as_number, int_of, last, strip, text, truthy};
use crate::ntpath::isabs;
use crate::privacy::clip;

/// How long one answer may take.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(1500);

// --------------------------------------------------------------------------- finding the programs

/// Finds an executable on PATH, ignoring relative entries and the current directory.
pub(super) fn find_on_path(names: &[&str]) -> Option<PathBuf> {
    for entry in std::env::var("PATH").unwrap_or_default().split(';') {
        let entry = crate::cmdline::expand_env(strip(entry).trim_matches('"'));
        if entry.is_empty() || !isabs(&entry) {
            continue;
        }
        for name in names {
            let candidate = Path::new(&entry).join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// How to start a program: an executable, or Node.js with a script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launcher {
    pub program: PathBuf,
    /// The script Node.js runs (for npm/pnpm installs), before the program's own arguments.
    pub script: Option<PathBuf>,
}

impl Launcher {
    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        if let Some(script) = &self.script {
            command.arg(script);
        }
        command
    }
}

/// The script an npm or pnpm `.cmd` launcher runs with Node.js. Launchers are never run through
/// cmd.exe: their argument quoting is not safe, so the script is started with `node.exe` directly.
pub fn node_script_of_shim(shim: &Path) -> Option<PathBuf> {
    let content = std::fs::read_to_string(shim).ok()?;
    let folder = shim.parent()?;
    for quoted in content.split('"').skip(1).step_by(2) {
        let lower = quoted.to_ascii_lowercase();
        if !(lower.ends_with(".js") || lower.ends_with(".mjs") || lower.ends_with(".cjs")) {
            continue;
        }
        let relative = quoted
            .strip_prefix("%~dp0")
            .or_else(|| quoted.strip_prefix("%dp0%"))?
            .trim_start_matches(['\\', '/']);
        if relative.contains("..") || relative.contains('%') {
            continue;
        }
        let script = folder.join(relative);
        if script.is_file() {
            return Some(script);
        }
    }
    None
}

/// A CLI installed as `name.exe`, or as an npm/pnpm launcher (`name.cmd`) run with Node.js.
pub(super) fn find_launcher(name: &str) -> Option<Launcher> {
    if let Some(program) = find_on_path(&[&format!("{name}.exe")]) {
        return Some(Launcher { program, script: None });
    }
    let shim = find_on_path(&[&format!("{name}.cmd"), &format!("{name}.CMD")])?;
    let script = node_script_of_shim(&shim)?;
    let folder = shim.parent()?;
    let node = Some(folder.join("node.exe"))
        .filter(|p| p.is_file())
        .or_else(|| find_on_path(&["node.exe"]))?;
    Some(Launcher {
        program: node,
        script: Some(script),
    })
}

// --------------------------------------------------------------------------- running them

/// Variables that agent CLIs set for their own session: a child session must not inherit them.
const SESSION_ENV: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_PID",
    "CLAUDE_AGENT_SDK_VERSION",
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_SESSION_ID",
    "CLAUDE_CODE_CHILD_SESSION",
    "CLAUDE_CODE_CHILD_NOTES_DIR",
    "CLAUDE_CODE_MESSAGING_SOCKET",
    "CLAUDE_CODE_MESSAGING_TOKEN",
    "CLAUDE_CODE_SESSION_ATTENDED",
    "CLAUDE_CODE_STARTUP_FAILURE_RESULTS",
    "CLAUDE_CODE_EMIT_STARTUP_TIMING",
    "CLAUDE_CODE_QUESTION_PREVIEW_FORMAT",
    "CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING",
    "CLAUDE_CODE_ENABLE_TASKS",
    "CODEX_THREAD_ID",
    "CODEX_SANDBOX",
    "CODEX_SANDBOX_NETWORK_DISABLED",
    "GEMINI_CLI",
    "GEMINI_CLI_IDE_SERVER_PORT",
];

fn clean_env(command: &mut Command) {
    for name in SESSION_ENV {
        command.env_remove(name);
    }
}

/// A temporary folder for one call, deleted when dropped.
pub(super) struct TempDir(PathBuf);

impl TempDir {
    pub(super) fn create(prefix: &str) -> std::io::Result<Self> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "{prefix}{}-{nanos:x}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(name: &str, command: Command, stdin: Option<&str>, timeout: Duration) -> Result<Finished, AiError> {
    match run_child(command, stdin, timeout, &AtomicBool::new(false)) {
        Ok(finished) => Ok(finished),
        Err(ChildError::Timeout | ChildError::Cancelled) => Err(failed(format!("{name} did not respond in time"))),
        Err(ChildError::Spawn(error)) => Err(failed(format!("could not run {name}: {error}"))),
    }
}

fn unexpected(name: &str, finished: &Finished) -> AiError {
    let stdout = String::from_utf8_lossy(&finished.stdout);
    let stderr = String::from_utf8_lossy(&finished.stderr);
    let detail = if strip(&stderr).is_empty() { stdout } else { stderr };
    let code = finished.code.map_or_else(|| "none".to_string(), |c| c.to_string());
    failed(format!(
        "unexpected response from {name} (exit code {code}): {}",
        last(strip(&detail), 400)
    ))
}

/// The help text of a command (stdout and stderr), for detecting supported options.
fn help_text(launcher: &Launcher, args: &[&str], name: &str) -> Result<String, String> {
    let mut command = launcher.command();
    command.args(args);
    clean_env(&mut command);
    let finished = run_child(command, None, Duration::from_secs(60), &AtomicBool::new(false)).map_err(|e| match e {
        ChildError::Spawn(error) => format!("could not run {name}: {error}"),
        _ => format!("could not run {name}: it did not answer in time"),
    })?;
    Ok(format!(
        "{}\n{}",
        String::from_utf8_lossy(&finished.stdout),
        String::from_utf8_lossy(&finished.stderr)
    ))
}

fn flags_in(help: &str, known: &[&str]) -> BTreeSet<String> {
    known
        .iter()
        .filter(|flag| help.contains(*flag))
        .map(|f| f.to_string())
        .collect()
}

/// Compact JSON with ", " and ": " separators, the layout of the data sent.
pub(super) fn dumps_compact_spaced(value: &Value) -> String {
    let compact = crate::lenient::dumps_compact(value);
    let mut out = String::with_capacity(compact.len() + compact.len() / 8);
    let mut in_string = false;
    let mut escaped = false;
    for c in compact.chars() {
        out.push(c);
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
        } else if c == ',' || c == ':' {
            out.push(' ');
        }
    }
    out
}

// --------------------------------------------------------------------------- Claude Code

/// The native Claude Code executable on PATH (`claude.exe`).
pub fn find_claude() -> Option<Launcher> {
    find_on_path(&["claude.exe"]).map(|program| Launcher { program, script: None })
}

/// Options of `claude --help` that matter here.
pub(super) fn claude_flags(launcher: &Launcher) -> Result<BTreeSet<String>, String> {
    let help = help_text(launcher, &["--help"], "Claude Code")?;
    let flags = flags_in(
        &help,
        &[
            "--print",
            "--output-format",
            "--system-prompt",
            "--tools",
            "--json-schema",
            "--safe-mode",
            "--strict-mcp-config",
            "--no-session-persistence",
            "--effort",
            "--model",
        ],
    );
    let missing: Vec<&str> = ["--print", "--output-format", "--system-prompt", "--tools"]
        .into_iter()
        .filter(|f| !flags.contains(*f))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "this version of Claude Code does not support {}; update it with `claude update`",
            missing.join(", ")
        ));
    }
    Ok(flags)
}

pub(super) fn claude_complete(
    provider: &Provider,
    launcher: &Launcher,
    flags: &BTreeSet<String>,
    system: &str,
    user: &str,
    schema: &Value,
) -> Result<Value, AiError> {
    let mut command = launcher.command();
    // No tools: the model can only read the text and answer.
    command.args([
        "--print",
        "--output-format",
        "json",
        "--system-prompt",
        system,
        "--tools",
        "",
    ]);
    let mut user = user.to_string();
    if flags.contains("--json-schema") {
        command.arg("--json-schema").arg(dumps_compact_spaced(schema));
    } else {
        user.push_str("\n\nRespond only with a JSON object that conforms to this schema:\n");
        user.push_str(&dumps_compact_spaced(schema));
    }
    for flag in ["--safe-mode", "--strict-mcp-config", "--no-session-persistence"] {
        if flags.contains(flag) {
            command.arg(flag); // no plugins, hooks, MCP servers or user memory
        }
    }
    if flags.contains("--model") && !provider.model.is_empty() {
        command.arg("--model").arg(&provider.model);
    }
    if flags.contains("--effort") && !provider.effort.is_empty() {
        command.arg("--effort").arg(&provider.effort);
    }
    clean_env(&mut command);
    let cwd = TempDir::create("vigil-ai-").map_err(|e| failed(format!("could not run Claude Code: {e}")))?;
    command.current_dir(cwd.path());
    let finished = run("Claude Code", command, Some(&user), ANSWER_TIMEOUT)?;
    drop(cwd);
    claude_answer(provider, &finished)
}

/// The JSON answer in Claude Code's `--output-format json` result.
fn claude_answer(provider: &Provider, finished: &Finished) -> Result<Value, AiError> {
    let stdout = String::from_utf8_lossy(&finished.stdout).into_owned();
    let result: Value = match serde_json::from_str::<Value>(&stdout) {
        Ok(value @ Value::Object(_)) => value,
        _ => return Err(unexpected("Claude Code", finished)),
    };
    let usage = result.at("usage");
    provider.record_usage(
        int_of(usage.at("input_tokens"))
            + int_of(usage.at("cache_read_input_tokens"))
            + int_of(usage.at("cache_creation_input_tokens")),
        int_of(usage.at("output_tokens")),
        as_number(result.at("total_cost_usd")).unwrap_or(0.0),
    );
    if result.at("stop_reason").as_str() == Some("refusal") || truthy(result.at("safety_stops")) {
        return Err(AiError::Refusal(
            "the model refused the analysis because of its safety filters".into(),
        ));
    }
    let subtype_ok = matches!(result.at("subtype"), Value::Null) || result.at("subtype").as_str() == Some("success");
    if truthy(result.at("is_error")) || !subtype_ok {
        return Err(failed(format!(
            "Claude Code reported an error: {}",
            clip(&crate::lenient::str_of(result.at("result")), 300)
        )));
    }
    if result.at("stop_reason").as_str() == Some("max_tokens") {
        return Err(AiError::Truncated("the response was cut off by the token limit".into()));
    }
    if let structured @ Value::Object(_) = result.at("structured_output") {
        return Ok(structured.clone());
    }
    parse_json_text(&text(result.at("result")))
}

// --------------------------------------------------------------------------- Codex CLI

/// Codex CLI: the native `codex.exe`, or the npm launcher run with Node.js.
pub fn find_codex() -> Option<Launcher> {
    find_launcher("codex")
}

/// Features that give Codex tools; the ones this version knows are turned off for every call.
const CODEX_TOOL_FEATURES: &[&str] = &[
    "shell_tool",
    "unified_exec",
    "apps",
    "plugins",
    "remote_plugin",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "computer_use",
    "in_app_browser",
    "tool_suggest",
    "skill_search",
    "skill_mcp_dependency_install",
    "standalone_web_search",
    "sleep_tool",
];

/// What `codex exec --help` and `codex features list` say this version supports.
#[derive(Clone, Debug, Default)]
pub(super) struct CodexSupport {
    pub flags: BTreeSet<String>,
    /// Tool features this version knows (and that are not removed), to turn off.
    pub tool_features: Vec<String>,
}

pub(super) fn codex_support(launcher: &Launcher) -> Result<CodexSupport, String> {
    let help = help_text(launcher, &["exec", "--help"], "Codex CLI")?;
    let flags = flags_in(
        &help,
        &[
            "--sandbox",
            "--output-schema",
            "--output-last-message",
            "--skip-git-repo-check",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--color",
            "--model",
            "--disable",
        ],
    );
    let missing: Vec<&str> = ["--sandbox", "--output-last-message", "--skip-git-repo-check"]
        .into_iter()
        .filter(|f| !flags.contains(*f))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "this version of Codex CLI does not support {}; update it with `codex update`",
            missing.join(", ")
        ));
    }
    let features = help_text(launcher, &["features", "list"], "Codex CLI").unwrap_or_default();
    let tool_features = features
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next()?;
            let removed = parts.any(|p| p == "removed");
            (!removed && CODEX_TOOL_FEATURES.contains(&name)).then(|| name.to_string())
        })
        .collect();
    Ok(CodexSupport { flags, tool_features })
}

pub(super) fn codex_complete(
    provider: &Provider,
    launcher: &Launcher,
    support: &CodexSupport,
    system: &str,
    user: &str,
    schema: &Value,
) -> Result<Value, AiError> {
    let cwd = TempDir::create("vigil-ai-").map_err(|e| failed(format!("could not run Codex CLI: {e}")))?;
    let schema_file = cwd.path().join("answer-schema.json");
    let answer_file = cwd.path().join("answer.txt");
    std::fs::write(&schema_file, crate::lenient::dumps_compact(schema))
        .map_err(|e| failed(format!("could not run Codex CLI: {e}")))?;
    let mut prompt = format!("{system}\n\n{user}");
    let mut command = launcher.command();
    command.arg("exec");
    // Read-only, no approvals, no shell, no web search, no user configuration (MCP servers,
    // profiles), no rules, nothing saved.
    command.args(["--sandbox", "read-only", "--skip-git-repo-check"]);
    command.args(["-c", "approval_policy=\"never\"", "-c", "web_search=\"disabled\""]);
    for flag in ["--ephemeral", "--ignore-user-config", "--ignore-rules"] {
        if support.flags.contains(flag) {
            command.arg(flag);
        }
    }
    if support.flags.contains("--disable") {
        for feature in &support.tool_features {
            command.arg("--disable").arg(feature);
        }
    }
    if support.flags.contains("--color") {
        command.args(["--color", "never"]);
    }
    if support.flags.contains("--output-schema") {
        command.arg("--output-schema").arg(&schema_file);
    } else {
        prompt.push_str("\n\nRespond only with a JSON object that conforms to this schema:\n");
        prompt.push_str(&dumps_compact_spaced(schema));
    }
    command.arg("--output-last-message").arg(&answer_file);
    if support.flags.contains("--model") && !provider.model.is_empty() {
        command.arg("--model").arg(&provider.model);
    }
    command.arg("-"); // the prompt comes from stdin
    clean_env(&mut command);
    command.current_dir(cwd.path());
    let finished = run("Codex CLI", command, Some(&prompt), ANSWER_TIMEOUT)?;
    provider.record_usage(0, 0, 0.0);
    let answer = std::fs::read_to_string(&answer_file).unwrap_or_default();
    if answer.trim().is_empty() {
        return Err(unexpected("Codex CLI", &finished));
    }
    parse_json_text(&answer)
}

// --------------------------------------------------------------------------- Gemini CLI

/// Gemini CLI: `gemini.exe`, or the npm/pnpm launcher run with Node.js.
pub fn find_gemini() -> Option<Launcher> {
    find_launcher("gemini")
}

/// A policy that denies every tool (built-in and MCP): denied tools are not even offered to the model.
const GEMINI_DENY_ALL: &str = "[[rule]]\ntoolName = \"*\"\ndecision = \"deny\"\npriority = 999\n";

pub(super) fn gemini_flags(launcher: &Launcher) -> Result<BTreeSet<String>, String> {
    let help = help_text(launcher, &["--help"], "Gemini CLI")?;
    let flags = flags_in(
        &help,
        &[
            "--prompt",
            "--output-format",
            "--approval-mode",
            "--policy",
            "--admin-policy",
            "--model",
        ],
    );
    if !flags.contains("--prompt") || !flags.contains("--output-format") {
        return Err("this version of Gemini CLI has no headless mode with JSON output; update it".into());
    }
    if !flags.contains("--policy") && !flags.contains("--admin-policy") {
        return Err("this version of Gemini CLI cannot turn its tools off (no policy engine); update it".into());
    }
    Ok(flags)
}

pub(super) fn gemini_complete(
    provider: &Provider,
    launcher: &Launcher,
    flags: &BTreeSet<String>,
    system: &str,
    user: &str,
    schema: &Value,
) -> Result<Value, AiError> {
    let cwd = TempDir::create("vigil-ai-").map_err(|e| failed(format!("could not run Gemini CLI: {e}")))?;
    let policy = cwd.path().join("deny-all-tools.toml");
    std::fs::write(&policy, GEMINI_DENY_ALL).map_err(|e| failed(format!("could not run Gemini CLI: {e}")))?;
    let stdin = format!(
        "{system}\n\n{user}\n\nRespond only with a JSON object that conforms to this schema:\n{}",
        dumps_compact_spaced(schema)
    );
    let mut command = launcher.command();
    // The instruction is fixed; the data travels on stdin (the CLI appends this prompt to it).
    command.args([
        "--prompt",
        "Answer the request above as instructed.",
        "--output-format",
        "json",
    ]);
    if flags.contains("--approval-mode") {
        command.args(["--approval-mode", "default"]);
    }
    for flag in ["--admin-policy", "--policy"] {
        if flags.contains(flag) {
            command.arg(flag).arg(&policy);
        }
    }
    if flags.contains("--model") && !provider.model.is_empty() {
        command.arg("--model").arg(&provider.model);
    }
    clean_env(&mut command);
    command.current_dir(cwd.path());
    let finished = run("Gemini CLI", command, Some(&stdin), ANSWER_TIMEOUT)?;
    provider.record_usage(0, 0, 0.0);
    let stdout = String::from_utf8_lossy(&finished.stdout).into_owned();
    let start = stdout.find('{').unwrap_or(0);
    let result: Value = match serde_json::from_str::<Value>(&stdout[start..]) {
        Ok(value @ Value::Object(_)) => value,
        _ => return Err(unexpected("Gemini CLI", &finished)),
    };
    if !result.at("error").is_null() {
        let message = result
            .at("error")
            .at("message")
            .as_str()
            .map_or_else(|| crate::lenient::str_of(result.at("error")), str::to_string);
        return Err(failed(format!("Gemini CLI reported an error: {}", clip(&message, 300))));
    }
    let response = text(result.at("response"));
    if response.trim().is_empty() {
        return Err(unexpected("Gemini CLI", &finished));
    }
    parse_json_text(&response)
}

// --------------------------------------------------------------------------- investigations

/// The name of Vigil's MCP server in the agents' configuration (Claude Code then names its tools
/// `mcp__vigil__<tool>`).
pub const MCP_NAME: &str = "vigil";

/// `{"mcpServers": {"vigil": {...}}}`, the configuration shape Claude Code and Gemini CLI read.
pub fn mcp_servers_json(launch: &McpLaunch, gemini: bool) -> Value {
    let mut server = serde_json::Map::new();
    if !gemini {
        server.insert("type".into(), Value::from("stdio"));
    }
    server.insert("command".into(), Value::from(launch.exe.to_string_lossy().into_owned()));
    server.insert("args".into(), Value::from(launch.args.clone()));
    if gemini {
        // Only this server's own read-only tools; no confirmation prompts in a headless run.
        server.insert("trust".into(), Value::Bool(true));
    }
    let mut servers = serde_json::Map::new();
    servers.insert(MCP_NAME.into(), Value::Object(server));
    serde_json::json!({ "mcpServers": servers })
}

/// A TOML string for `codex -c key=value`: a literal string, or a basic one when the text holds a
/// single quote.
pub fn toml_string(text: &str) -> String {
    if !text.contains('\'') && !text.contains('\n') {
        format!("'{text}'")
    } else {
        let escaped: String = text
            .chars()
            .flat_map(|c| match c {
                '\\' => vec!['\\', '\\'],
                '"' => vec!['\\', '"'],
                '\n' => vec!['\\', 'n'],
                other => vec![other],
            })
            .collect();
        format!("\"{escaped}\"")
    }
}

/// `-c` overrides that add Vigil's MCP server to one Codex run.
pub fn codex_mcp_overrides(launch: &McpLaunch) -> Vec<String> {
    let args: Vec<String> = launch.args.iter().map(|a| toml_string(a)).collect();
    vec![
        "-c".into(),
        format!(
            "mcp_servers.{MCP_NAME}.command={}",
            toml_string(&launch.exe.to_string_lossy())
        ),
        "-c".into(),
        format!("mcp_servers.{MCP_NAME}.args=[{}]", args.join(", ")),
    ]
}

/// Gemini CLI policy for an investigation: Vigil's MCP tools are allowed, every other tool is denied.
pub const GEMINI_VIGIL_ONLY: &str = "[[rule]]\nmcpName = \"vigil\"\ndecision = \"allow\"\npriority = 1000\n\n[[rule]]\ntoolName = \"*\"\ndecision = \"deny\"\npriority = 999\n";

fn write_in(dir: &Path, name: &str, text: &str) -> Result<PathBuf, AiError> {
    let path = dir.join(name);
    std::fs::write(&path, text).map_err(|e| failed(format!("could not prepare the investigation: {e}")))?;
    Ok(path)
}

fn run_cancellable(name: &str, command: Command, stdin: &str, cancel: &AtomicBool) -> Result<Finished, AiError> {
    match run_child(command, Some(stdin), ANSWER_TIMEOUT, cancel) {
        Ok(finished) => Ok(finished),
        Err(ChildError::Cancelled) => Err(failed("the investigation was cancelled")),
        Err(ChildError::Timeout) => Err(failed(format!("{name} did not respond in time"))),
        Err(ChildError::Spawn(error)) => Err(failed(format!("could not run {name}: {error}"))),
    }
}

/// Claude Code with only Vigil's MCP server (`--mcp-config` + `--strict-mcp-config`), its built-in
/// tools turned off (`--tools ""`) and Vigil's tools allowed without prompts (`--allowedTools mcp__vigil`).
#[allow(clippy::too_many_arguments)]
pub(super) fn claude_investigate(
    provider: &Provider,
    launcher: &Launcher,
    flags: &BTreeSet<String>,
    system: &str,
    user: &str,
    schema: &Value,
    launch: &McpLaunch,
    cancel: &AtomicBool,
) -> Result<Value, AiError> {
    if !flags.contains("--strict-mcp-config") {
        return Err(failed(
            "this version of Claude Code cannot be limited to Vigil's tools (no --strict-mcp-config); update it with `claude update`",
        ));
    }
    let config = write_in(
        &launch.work,
        "mcp.json",
        &crate::lenient::dumps_compact(&mcp_servers_json(launch, false)),
    )?;
    let mut command = launcher.command();
    command.args([
        "--print",
        "--output-format",
        "json",
        "--system-prompt",
        system,
        "--tools",
        "",
    ]);
    command.arg("--mcp-config").arg(&config).arg("--strict-mcp-config");
    command.args(["--allowedTools", &format!("mcp__{MCP_NAME}")]);
    let mut prompt = user.to_string();
    if flags.contains("--json-schema") {
        command.arg("--json-schema").arg(dumps_compact_spaced(schema));
    } else {
        prompt.push_str("\n\nRespond only with a JSON object that conforms to this schema:\n");
        prompt.push_str(&dumps_compact_spaced(schema));
    }
    for flag in ["--safe-mode", "--no-session-persistence"] {
        if flags.contains(flag) {
            command.arg(flag);
        }
    }
    if flags.contains("--model") && !provider.model.is_empty() {
        command.arg("--model").arg(&provider.model);
    }
    if flags.contains("--effort") && !provider.effort.is_empty() {
        command.arg("--effort").arg(&provider.effort);
    }
    clean_env(&mut command);
    command.current_dir(&launch.work);
    let finished = run_cancellable("Claude Code", command, &prompt, cancel)?;
    claude_answer(provider, &finished)
}

/// Codex CLI with Vigil's MCP server added for this run (`-c mcp_servers.vigil.*`), read-only
/// sandbox, no approvals, no web search.
#[allow(clippy::too_many_arguments)]
pub(super) fn codex_investigate(
    provider: &Provider,
    launcher: &Launcher,
    support: &CodexSupport,
    system: &str,
    user: &str,
    schema: &Value,
    launch: &McpLaunch,
    cancel: &AtomicBool,
) -> Result<Value, AiError> {
    let schema_file = write_in(
        &launch.work,
        "answer-schema.json",
        &crate::lenient::dumps_compact(schema),
    )?;
    let answer_file = launch.work.join("answer.txt");
    let mut prompt = format!("{system}\n\n{user}");
    let mut command = launcher.command();
    command.arg("exec");
    command.args(["--sandbox", "read-only", "--skip-git-repo-check"]);
    command.args(["-c", "approval_policy=\"never\"", "-c", "web_search=\"disabled\""]);
    command.args(codex_mcp_overrides(launch));
    for flag in ["--ephemeral", "--ignore-user-config", "--ignore-rules"] {
        if support.flags.contains(flag) {
            command.arg(flag);
        }
    }
    if support.flags.contains("--disable") {
        // The shell and the other built-in tools go; MCP support stays.
        for feature in support.tool_features.iter().filter(|f| !f.contains("mcp")) {
            command.arg("--disable").arg(feature);
        }
    }
    if support.flags.contains("--color") {
        command.args(["--color", "never"]);
    }
    if support.flags.contains("--output-schema") {
        command.arg("--output-schema").arg(&schema_file);
    } else {
        prompt.push_str("\n\nRespond only with a JSON object that conforms to this schema:\n");
        prompt.push_str(&dumps_compact_spaced(schema));
    }
    command.arg("--output-last-message").arg(&answer_file);
    if support.flags.contains("--model") && !provider.model.is_empty() {
        command.arg("--model").arg(&provider.model);
    }
    command.arg("-");
    clean_env(&mut command);
    command.current_dir(&launch.work);
    let finished = run_cancellable("Codex CLI", command, &prompt, cancel)?;
    provider.record_usage(0, 0, 0.0);
    let answer = std::fs::read_to_string(&answer_file).unwrap_or_default();
    if answer.trim().is_empty() {
        return Err(unexpected("Codex CLI", &finished));
    }
    parse_json_text(&answer)
}

/// Gemini CLI started in a work folder whose `.gemini/settings.json` names Vigil's MCP server
/// (project settings), with a policy that allows only that server's tools.
#[allow(clippy::too_many_arguments)]
pub(super) fn gemini_investigate(
    provider: &Provider,
    launcher: &Launcher,
    flags: &BTreeSet<String>,
    system: &str,
    user: &str,
    schema: &Value,
    launch: &McpLaunch,
    cancel: &AtomicBool,
) -> Result<Value, AiError> {
    let settings_dir = launch.work.join(".gemini");
    std::fs::create_dir_all(&settings_dir).map_err(|e| failed(format!("could not prepare the investigation: {e}")))?;
    write_in(
        &settings_dir,
        "settings.json",
        &crate::lenient::dumps_compact(&mcp_servers_json(launch, true)),
    )?;
    let policy = write_in(&launch.work, "vigil-tools-only.toml", GEMINI_VIGIL_ONLY)?;
    let stdin = format!(
        "{system}\n\n{user}\n\nRespond only with a JSON object that conforms to this schema:\n{}",
        dumps_compact_spaced(schema)
    );
    let mut command = launcher.command();
    command.args([
        "--prompt",
        "Answer the request above as instructed.",
        "--output-format",
        "json",
    ]);
    if flags.contains("--approval-mode") {
        command.args(["--approval-mode", "default"]);
    }
    for flag in ["--admin-policy", "--policy"] {
        if flags.contains(flag) {
            command.arg(flag).arg(&policy);
        }
    }
    command.args(["--allowed-mcp-server-names", MCP_NAME]);
    if flags.contains("--model") && !provider.model.is_empty() {
        command.arg("--model").arg(&provider.model);
    }
    clean_env(&mut command);
    command.current_dir(&launch.work);
    let finished = run_cancellable("Gemini CLI", command, &stdin, cancel)?;
    provider.record_usage(0, 0, 0.0);
    let stdout = String::from_utf8_lossy(&finished.stdout).into_owned();
    let start = stdout.find('{').unwrap_or(0);
    let result: Value = match serde_json::from_str::<Value>(&stdout[start..]) {
        Ok(value @ Value::Object(_)) => value,
        _ => return Err(unexpected("Gemini CLI", &finished)),
    };
    if !result.at("error").is_null() {
        return Err(failed(format!(
            "Gemini CLI reported an error: {}",
            clip(&crate::lenient::str_of(result.at("error")), 300)
        )));
    }
    let response = text(result.at("response"));
    if response.trim().is_empty() {
        return Err(unexpected("Gemini CLI", &finished));
    }
    parse_json_text(&response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shims_resolve_to_their_node_script() {
        let dir = TempDir::create("vigil-shim-test-").expect("temp");
        let script = dir.path().join("node_modules").join("tool").join("bin.js");
        std::fs::create_dir_all(script.parent().expect("parent")).expect("dirs");
        std::fs::write(&script, "// js").expect("script");
        let shim = dir.path().join("tool.cmd");
        std::fs::write(
            &shim,
            "@IF EXIST \"%~dp0\\node.exe\" (\r\n  \"%~dp0\\node.exe\"  \"%~dp0\\node_modules\\tool\\bin.js\" %*\r\n)",
        )
        .expect("shim");
        assert_eq!(node_script_of_shim(&shim), Some(script));
        std::fs::write(&shim, "\"%~dp0\\..\\..\\evil.js\" %*").expect("shim");
        assert_eq!(node_script_of_shim(&shim), None, "no way out of the launcher's folder");
        std::fs::write(&shim, "node \"C:\\elsewhere\\bin.js\" %*").expect("shim");
        assert_eq!(node_script_of_shim(&shim), None, "only scripts next to the launcher");
    }

    #[test]
    fn spaced_json_layout() {
        assert_eq!(
            dumps_compact_spaced(&serde_json::json!({"a": [1, 2], "b": "x,y: z"})),
            "{\"a\": [1, 2], \"b\": \"x,y: z\"}"
        );
    }

    fn launch() -> McpLaunch {
        McpLaunch {
            exe: PathBuf::from(r"C:\Program Files\Vigil\vigil.exe"),
            args: vec![
                "mcp".into(),
                "--report".into(),
                r"C:\ProgramData\Vigil\scans\scan-20260101-100000-report.json".into(),
                "--log".into(),
                r"C:\ProgramData\Vigil\investigations\run-1\calls.jsonl".into(),
            ],
            log: PathBuf::from(r"C:\ProgramData\Vigil\investigations\run-1\calls.jsonl"),
            work: PathBuf::from(r"C:\ProgramData\Vigil\investigations\run-1"),
        }
    }

    #[test]
    fn mcp_configuration_for_claude_code_and_gemini() {
        let claude = mcp_servers_json(&launch(), false);
        let server = &claude["mcpServers"]["vigil"];
        assert_eq!(server["type"], "stdio");
        assert_eq!(server["command"], r"C:\Program Files\Vigil\vigil.exe");
        assert_eq!(server["args"][0], "mcp");
        assert!(server.get("trust").is_none());
        let gemini = mcp_servers_json(&launch(), true);
        assert_eq!(gemini["mcpServers"]["vigil"]["trust"], true);
        assert!(gemini["mcpServers"]["vigil"].get("type").is_none());
        assert!(GEMINI_VIGIL_ONLY.contains("mcpName = \"vigil\"") && GEMINI_VIGIL_ONLY.contains("decision = \"deny\""));
    }

    #[test]
    fn codex_overrides_are_valid_toml_values() {
        let overrides = codex_mcp_overrides(&launch());
        assert_eq!(overrides[0], "-c");
        assert_eq!(
            overrides[1],
            r"mcp_servers.vigil.command='C:\Program Files\Vigil\vigil.exe'"
        );
        assert!(overrides[3].starts_with("mcp_servers.vigil.args=['mcp', '--report', 'C:\\ProgramData"));
        assert_eq!(toml_string(r"C:\it's\x.exe"), r#""C:\\it's\\x.exe""#);
        assert_eq!(toml_string("say \"hi\""), r#"'say "hi"'"#);
    }

    #[test]
    fn flags_are_read_from_help() {
        let flags = flags_in(
            "  --print  --tools <list>\n --model",
            &["--print", "--tools", "--effort", "--model"],
        );
        assert!(flags.contains("--print") && flags.contains("--model") && !flags.contains("--effort"));
    }
}
