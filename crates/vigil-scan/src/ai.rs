//! AI review: an AI model classifies the findings the local rules could not clear and writes the
//! executive summary.
//!
//! The user chooses who answers, with no provider built in:
//!   * an API that speaks one of the two common standards, at the address the user gives: the OpenAI
//!     Chat Completions API (OpenAI, OpenRouter, Google's OpenAI endpoint, DeepSeek, Groq, and local
//!     servers such as Ollama, LM Studio, llama.cpp or vLLM) or the Anthropic Messages API (Anthropic
//!     and compatible services). On this computer (localhost) nothing leaves it;
//!   * a local agent already signed in on this computer: Claude Code, Codex CLI, Gemini CLI.
//!
//! Whatever the provider, the model only receives data and returns JSON validated against a schema:
//! it has no tools, so text inside the inventory cannot make it run anything. Its answers are data
//! too: verdicts outside the allowed set are ignored, and an item the local rules rate critical is
//! never downgraded to "safe".

pub mod agent;
mod anthropic;
mod cli;
pub mod net;
mod ollama;
mod openai;

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::Instant;

use serde_json::{Map, Value, json};

use crate::analyze::signature_text;
use crate::error::ScanError;
use crate::lenient::{Get, dumps_compact, dumps_pretty, list, round_to, str_of, strip, take, text, truthy};
use crate::model::{Analysis, Item};
use crate::privacy::{Redactor, clip};
use vigil_i18n::tr;

pub use anthropic::{API_BASE, DEFAULT_MODEL};
pub use cli::{Launcher, node_script_of_shim, toml_string};
pub use net::{check_endpoint, is_loopback_url};
pub use ollama::is_cloud_name;
pub use openai::DEFAULT_BASE as OPENAI_BASE;

pub const DEFAULT_EFFORT: &str = "high";
pub const EFFORTS: [&str; 5] = ["low", "medium", "high", "xhigh", "max"];

pub const SYSTEM_PROMPT: &str = include_str!("ai/system-prompt.txt");
pub const SUMMARY_PROMPT: &str = include_str!("ai/summary-prompt.txt");

/// The classification instructions, asking for the free-text fields in the user's language.
pub fn system_prompt() -> String {
    localized_prompt(SYSTEM_PROMPT)
}

/// The summary instructions, asking for the free-text fields in the user's language.
pub fn summary_prompt() -> String {
    localized_prompt(SUMMARY_PROMPT)
}

fn localized_prompt(base: &str) -> String {
    let language = vigil_i18n::language_name(vigil_i18n::language());
    if language == "English" {
        return base.to_string();
    }
    format!(
        "{}\n- Keep every JSON key and every enumerated value (verdict, confidence, risk_level) exactly as specified, in English; only the free-text fields are written in {language}.",
        base.replace("plain English", &format!("plain {language}"))
    )
}

/// JSON schema of the classification answer.
pub fn verdict_schema() -> Value {
    serde_json::from_str(include_str!("ai/verdict-schema.json")).unwrap_or(Value::Null)
}

/// JSON schema of the executive summary.
pub fn summary_schema() -> Value {
    serde_json::from_str(include_str!("ai/summary-schema.json")).unwrap_or(Value::Null)
}

/// The call to the AI failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AiError {
    /// Credentials, network, invalid response...
    Failed(String),
    /// The model refused the request because of its safety filters.
    Refusal(String),
    /// The response was cut off by the token limit.
    Truncated(String),
}

impl fmt::Display for AiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(m) | Self::Refusal(m) | Self::Truncated(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for AiError {}

pub(crate) fn failed(message: impl Into<String>) -> AiError {
    AiError::Failed(message.into())
}

/// The JSON object inside a model's text (code fences and chatter around it are ignored).
pub(crate) fn parse_json_text(text: &str) -> Result<Value, AiError> {
    let mut text = strip(text).to_string();
    if text.starts_with("```") {
        if let Some((_, rest)) = text.split_once('\n') {
            text = rest.to_string();
        }
        if let Some(end) = text.rfind("```") {
            text.truncate(end);
        }
    }
    let (Some(start), Some(end)) = (text.find('{'), text.rfind('}')) else {
        return Err(failed("the AI did not return a JSON object"));
    };
    if end <= start {
        return Err(failed("the AI did not return a JSON object"));
    }
    match serde_json::from_str::<Value>(&text[start..=end]) {
        Ok(value @ Value::Object(_)) => Ok(value),
        Ok(_) => Err(failed("the AI did not return a JSON object")),
        Err(error) => Err(failed(format!("the AI returned invalid JSON: {error}"))),
    }
}

/// A model id the settings accept: letters, digits and `._:-@/[]+`, at most 120 characters.
pub fn valid_model(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 120
        && model
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:-@/[]+".contains(c))
}

// --------------------------------------------------------------------------- the catalog

/// Static facts about one provider, for the settings page and the selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderInfo {
    /// "auto", "openai-compatible", "anthropic-compatible", "claude-code", "codex-cli", "gemini-cli",
    /// "off".
    pub id: &'static str,
    pub name: &'static str,
    /// "api", "local-agent", "auto", "off".
    pub kind: &'static str,
    /// The secret (API key) it can use: "openai-compatible" or "anthropic-compatible".
    pub secret: Option<&'static str>,
    pub needs_endpoint: bool,
    pub default_endpoint: Option<&'static str>,
    /// Empty: no default (the CLI's configured model, or a model the user chooses).
    pub default_model: &'static str,
    pub suggested_models: &'static [&'static str],
    pub supports_effort: bool,
}

const CLAUDE_MODELS: &[&str] = &["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"];

/// Every provider, in the order the settings show them.
pub const PROVIDERS: [ProviderInfo; 7] = [
    ProviderInfo {
        id: "auto",
        name: "Automatic",
        kind: "auto",
        secret: None,
        needs_endpoint: false,
        default_endpoint: None,
        default_model: "",
        suggested_models: &[],
        supports_effort: false,
    },
    ProviderInfo {
        id: "openai-compatible",
        name: "OpenAI-compatible API",
        kind: "api",
        secret: Some("openai-compatible"),
        needs_endpoint: true,
        default_endpoint: Some(openai::DEFAULT_BASE),
        default_model: "",
        suggested_models: &[],
        supports_effort: false,
    },
    ProviderInfo {
        id: "anthropic-compatible",
        name: "Anthropic-compatible API",
        kind: "api",
        secret: Some("anthropic-compatible"),
        needs_endpoint: true,
        default_endpoint: Some(API_BASE),
        default_model: DEFAULT_MODEL,
        suggested_models: CLAUDE_MODELS,
        supports_effort: true,
    },
    ProviderInfo {
        id: "claude-code",
        name: "Claude Code",
        kind: "local-agent",
        secret: None,
        needs_endpoint: false,
        default_endpoint: None,
        default_model: DEFAULT_MODEL,
        suggested_models: CLAUDE_MODELS,
        supports_effort: true,
    },
    ProviderInfo {
        id: "codex-cli",
        name: "Codex CLI",
        kind: "local-agent",
        secret: None,
        needs_endpoint: false,
        default_endpoint: None,
        default_model: "",
        suggested_models: &["gpt-5-codex", "gpt-5"],
        supports_effort: false,
    },
    ProviderInfo {
        id: "gemini-cli",
        name: "Gemini CLI",
        kind: "local-agent",
        secret: None,
        needs_endpoint: false,
        default_endpoint: None,
        default_model: "",
        suggested_models: &["gemini-2.5-pro", "gemini-2.5-flash"],
        supports_effort: false,
    },
    ProviderInfo {
        id: "off",
        name: "Off",
        kind: "off",
        secret: None,
        needs_endpoint: false,
        default_endpoint: None,
        default_model: "",
        suggested_models: &[],
        supports_effort: false,
    },
];

/// The order "auto" tries: local agents first, then the two API standards when configured.
pub const AUTO_ORDER: [&str; 5] = [
    "claude-code",
    "codex-cli",
    "gemini-cli",
    "anthropic-compatible",
    "openai-compatible",
];

/// The catalog entry of a provider id.
pub fn provider_info(id: &str) -> Option<&'static ProviderInfo> {
    PROVIDERS.iter().find(|p| p.id == id)
}

/// The provider's display name in the current language (product names stay as they are).
pub fn display_name(info: &ProviderInfo) -> String {
    match info.id {
        "auto" => tr!("Automatic"),
        "off" => tr!("Off"),
        "openai-compatible" => tr!("OpenAI-compatible API"),
        "anthropic-compatible" => tr!("Anthropic-compatible API"),
        _ => info.name.to_string(),
    }
}

/// Environment variables that hold a secret when the credential store has none.
pub fn env_names(secret: &str) -> &'static [&'static str] {
    match secret {
        "anthropic-compatible" => &["ANTHROPIC_API_KEY"],
        "openai-compatible" => &["OPENAI_API_KEY"],
        "virustotal" => &["VT_API_KEY", "VIRUSTOTAL_API_KEY"],
        _ => &[],
    }
}

/// A secret from the environment (the fallback of the credential store). Never while Vigil runs as
/// administrator: a standard user's program can set the user's environment (HKCU\Environment), so
/// the elevated copy uses only the keys stored in the Credential Manager.
pub fn env_key(secret: &str) -> Option<String> {
    from_env(env_names(secret), cli::running_elevated(), &|name| {
        std::env::var(name).ok()
    })
}

/// The first non-blank value of `names` read through `read`, or `None` when elevated (see
/// [`env_key`]).
fn from_env(names: &[&str], elevated: bool, read: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    if elevated {
        return None;
    }
    names
        .iter()
        .filter_map(|name| read(name))
        .map(|v| v.trim().to_string())
        .find(|v| !v.is_empty())
}

/// The environment variables that can stand in for a stored secret, as a hint for the user: none
/// while Vigil runs as administrator, which ignores them.
fn env_hint(secret: &str, elevated: bool) -> &'static [&'static str] {
    if elevated { &[] } else { env_names(secret) }
}

/// The program that answers at an endpoint on this computer (the owner of the listening socket).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalServer {
    pub pid: u32,
    /// Its image path; empty when it cannot be read (a protected process, or HTTP.sys's System).
    pub program: String,
    /// Who signed it, when it has a valid signature.
    pub signer: Option<String>,
}

/// What the user configured for the AI review.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AiConfig {
    pub provider: String,
    /// Empty: the provider's default.
    pub model: String,
    /// Empty: the provider's default endpoint (`OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` when Vigil
    /// does not run as administrator, then the standard's own address).
    pub endpoint: String,
    pub effort: String,
}

// --------------------------------------------------------------------------- availability

/// What the selection needs to know about this computer (a fake in the tests).
pub trait Probe {
    /// How to start a local agent ("claude-code", "codex-cli", "gemini-cli"), if it is installed.
    fn launcher(&self, provider: &str) -> Option<Launcher>;
    /// Whether Vigil runs as administrator: local agents are then never started.
    fn elevated(&self) -> bool {
        cli::running_elevated()
    }
    /// A stored or environment secret.
    fn key(&self, secret: &str) -> Option<String>;
    /// Whether a model server answers at a local endpoint (only asked for loopback addresses).
    fn reachable(&self, provider: &str, endpoint: &str) -> bool;
    /// For an endpoint on this computer that is an Ollama server: the models that really run here
    /// (cloud models left out). `None` when the server is not Ollama.
    fn ollama_models(&self, endpoint: &str) -> Option<Result<Vec<String>, String>> {
        ollama::is_ollama(endpoint).then(|| ollama::local_models(endpoint))
    }
    /// The address an environment variable sets for a standard (`OPENAI_BASE_URL`,
    /// `ANTHROPIC_BASE_URL`), if any. Ignored while Vigil runs as administrator: only the stored
    /// settings choose where the findings go.
    fn base_url(&self, provider: &str) -> Option<String> {
        let name = match provider {
            "openai-compatible" => "OPENAI_BASE_URL",
            "anthropic-compatible" => "ANTHROPIC_BASE_URL",
            _ => return None,
        };
        from_env(&[name], self.elevated(), &|n| std::env::var(n).ok())
    }
    /// A bearer token for the Anthropic standard (`ANTHROPIC_AUTH_TOKEN`); never while Vigil runs
    /// as administrator.
    fn bearer_token(&self) -> Option<String> {
        from_env(&["ANTHROPIC_AUTH_TOKEN"], self.elevated(), &|n| std::env::var(n).ok())
    }
    /// For an endpoint on this computer: the programs listening at its port, with their signers.
    /// `None` when they could not be read.
    fn local_servers(&self, endpoint: &str) -> Option<Vec<LocalServer>>;
}

/// The real computer: CLIs on PATH, secrets from the given lookup, servers on the network.
pub struct SystemProbe<'a> {
    pub keys: &'a dyn Fn(&str) -> Option<String>,
    /// Who signed a program (a valid signature only), for telling the user which program serves a
    /// local model.
    pub signer: &'a dyn Fn(&str) -> Option<String>,
}

impl Probe for SystemProbe<'_> {
    fn launcher(&self, provider: &str) -> Option<Launcher> {
        match provider {
            "claude-code" => cli::find_claude(),
            "codex-cli" => cli::find_codex(),
            "gemini-cli" => cli::find_gemini(),
            _ => None,
        }
    }

    fn key(&self, secret: &str) -> Option<String> {
        (self.keys)(secret).filter(|k| !k.trim().is_empty())
    }

    fn reachable(&self, provider: &str, endpoint: &str) -> bool {
        if !is_loopback_url(endpoint) {
            return false;
        }
        match provider {
            "openai-compatible" => openai::reachable(endpoint, (self.keys)("openai-compatible").as_deref()),
            "anthropic-compatible" => {
                anthropic::models(endpoint, &ApiAuth::None).is_ok() || ollama::is_ollama(endpoint)
            }
            _ => false,
        }
    }

    fn local_servers(&self, endpoint: &str) -> Option<Vec<LocalServer>> {
        #[cfg(windows)]
        {
            let (port, v4, v6) = net::loopback_target(endpoint)?;
            let owners = vigil_sys::net::loopback_listeners(port, v4, v6).ok()?;
            Some(
                owners
                    .into_iter()
                    .map(|(pid, program)| {
                        let signer = if program.is_empty() {
                            None
                        } else {
                            (self.signer)(&program)
                        };
                        LocalServer { pid, program, signer }
                    })
                    .collect(),
            )
        }
        #[cfg(not(windows))]
        {
            let _ = endpoint;
            None
        }
    }
}

/// Whether `path` is inside one of `roots` (case-insensitive, whole folder names, no `..`).
fn inside_any(path: &str, roots: &[std::path::PathBuf]) -> bool {
    if path.split(['\\', '/']).any(|part| part == "..") {
        return false;
    }
    let lower = path.to_lowercase();
    roots.iter().any(|root| {
        let root = root.display().to_string().trim_end_matches('\\').to_lowercase();
        !root.is_empty() && lower.strip_prefix(&root).is_some_and(|rest| rest.starts_with('\\'))
    })
}

/// The Program Files folders (from the known-folder API), which only administrators can change.
fn program_files_roots() -> Vec<std::path::PathBuf> {
    #[cfg(windows)]
    {
        vec![vigil_sys::paths::program_files(), vigil_sys::paths::program_files_x86()]
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// Who answers at an endpoint on this computer, to show in the consent dialog. While Vigil runs as
/// administrator, a server a standard user's program could have started gets nothing: one Vigil
/// cannot identify, or an unsigned program outside Program Files (a folder the user can write).
fn check_local_server(endpoint: &str, probe: &dyn Probe) -> Result<Vec<LocalServer>, String> {
    let servers = probe.local_servers(endpoint);
    if !probe.elevated() {
        return Ok(servers.unwrap_or_default());
    }
    let unknown = || {
        tr!(
            "Vigil cannot tell which program answers at {0}, so while it runs as administrator it sends nothing there. To use a local model, run Vigil without administrator rights.",
            endpoint
        )
    };
    let servers = servers.ok_or_else(unknown)?;
    if servers.is_empty() {
        return Err(tr!("No server answers at {0}.", endpoint));
    }
    let admin_only = program_files_roots();
    for server in &servers {
        if server.program.is_empty() {
            return Err(unknown());
        }
        if server.signer.is_none() && !inside_any(&server.program, &admin_only) {
            return Err(tr!(
                "{0} answers at {1}. It is not signed and is not in Program Files, so any program of yours could have put it there: while Vigil runs as administrator it sends it nothing. To use a local model, run Vigil without administrator rights.",
                clip(&server.program, 260),
                endpoint
            ));
        }
    }
    Ok(servers)
}

/// The programs serving a local model, for the destination shown in the consent dialog.
fn served_by(destination: String, servers: &[LocalServer]) -> String {
    if servers.is_empty() {
        return destination;
    }
    let programs: Vec<String> = servers
        .iter()
        .map(|server| {
            let program = if server.program.is_empty() {
                tr!("an unknown program (PID {0})", server.pid)
            } else {
                clip(&server.program, 260)
            };
            match &server.signer {
                Some(signer) => tr!("{0}, signed by {1}", program, clip(signer, 120)),
                None => tr!("{0}, not signed", program),
            }
        })
        .collect();
    tr!(
        "{0}. The program answering there: {1}",
        destination,
        programs.join("; ")
    )
}

/// Whether a provider can be used now, and a short note for the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderStatus {
    pub info: &'static ProviderInfo,
    pub available: bool,
    pub note: String,
}

/// The endpoint a provider uses: the configured one (for the selected provider), the address of
/// the environment variable, or the standard's own address.
fn endpoint_for(info: &ProviderInfo, config: &AiConfig, probe: &dyn Probe) -> String {
    if config.provider == info.id && !config.endpoint.trim().is_empty() {
        return config.endpoint.trim().trim_end_matches('/').to_string();
    }
    probe
        .base_url(info.id)
        .map(|b| b.trim().trim_end_matches('/').to_string())
        .unwrap_or_else(|| info.default_endpoint.unwrap_or("").to_string())
}

/// Whether "auto" can tell which model an API standard would use: Anthropic's own address has a
/// default model, and a local Ollama server has its first installed model. Elsewhere the user has to
/// choose the provider and the model explicitly.
fn auto_knows_model(info: &ProviderInfo, config: &AiConfig, probe: &dyn Probe) -> bool {
    if info.kind != "api" {
        return true;
    }
    let endpoint = endpoint_for(info, config, probe);
    if info.id == "anthropic-compatible" && endpoint == API_BASE {
        return true;
    }
    is_loopback_url(&endpoint) && matches!(probe.ollama_models(&endpoint), Some(Ok(local)) if !local.is_empty())
}

/// The host of an endpoint, for telling the user where the data goes.
fn host_of(endpoint: &str) -> String {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    rest.split('/').next().unwrap_or(rest).to_string()
}

fn status_of(info: &'static ProviderInfo, config: &AiConfig, probe: &dyn Probe) -> ProviderStatus {
    let (available, note) = match info.id {
        "off" => (true, tr!("Only the local rules judge the findings.")),
        "auto" => match AUTO_ORDER.iter().find_map(|id| {
            let other = provider_info(id)?;
            (status_of(other, config, probe).available && auto_knows_model(other, config, probe)).then_some(other)
        }) {
            Some(first) => (true, tr!("Uses {0}, the first one available.", display_name(first))),
            None => (
                false,
                tr!(
                    "No AI is available: install a local agent, or set up an OpenAI- or Anthropic-compatible API (a local server such as Ollama or LM Studio works too)."
                ),
            ),
        },
        "claude-code" | "codex-cli" | "gemini-cli" if probe.elevated() => (false, cli::elevated_refusal(info.name)),
        "claude-code" | "codex-cli" | "gemini-cli" => match probe.launcher(info.id) {
            Some(_) => (true, tr!("Uses the {0} session signed in on this computer.", info.name)),
            None => (false, tr!("{0} is not installed on this computer.", info.name)),
        },
        _ => {
            let endpoint = endpoint_for(info, config, probe);
            match check_endpoint(&endpoint) {
                Err(problem) => (false, problem),
                Ok(endpoint) if is_loopback_url(&endpoint) => {
                    let refused = || {
                        probe
                            .elevated()
                            .then(|| check_local_server(&endpoint, probe).err())
                            .flatten()
                    };
                    if !probe.reachable(info.id, &endpoint) {
                        (false, tr!("No server answers at {0}.", endpoint))
                    } else if let Some(problem) = refused() {
                        (false, problem)
                    } else if probe.ollama_models(&endpoint).is_some() {
                        (
                            true,
                            tr!(
                                "Ollama answers at {0}. Your data stays on this computer: Ollama cloud models are never used. Start Ollama with OLLAMA_NO_CLOUD=1 so that it does not contact ollama.com either, and with OLLAMA_CONTEXT_LENGTH=32768 so that long batches are not cut.",
                                endpoint
                            ),
                        )
                    } else {
                        (true, tr!("Answers at {0}. Your data stays on this computer.", endpoint))
                    }
                }
                Ok(endpoint) => {
                    let secret = info.secret.unwrap_or("");
                    let token = info.id == "anthropic-compatible" && probe.bearer_token().is_some();
                    if probe.key(secret).is_some() || token {
                        (
                            true,
                            tr!("API key saved. The findings to review go to {0}.", host_of(&endpoint)),
                        )
                    } else {
                        let names = env_hint(secret, probe.elevated());
                        let note = if names.is_empty() {
                            tr!("Add an API key in Settings.")
                        } else {
                            tr!("Add an API key in Settings (or set {0}).", names.join(" / "))
                        };
                        (false, note)
                    }
                }
            }
        }
    };
    ProviderStatus { info, available, note }
}

/// Every provider with its availability (in catalog order).
pub fn statuses(config: &AiConfig, probe: &dyn Probe) -> Vec<ProviderStatus> {
    PROVIDERS.iter().map(|info| status_of(info, config, probe)).collect()
}

// --------------------------------------------------------------------------- providers

/// How an Anthropic-standard request authenticates.
#[derive(Clone)]
pub enum ApiAuth {
    /// `x-api-key`.
    Key(String),
    /// `Authorization: Bearer` (ANTHROPIC_AUTH_TOKEN).
    Bearer(String),
    /// No credentials (a server on this computer).
    None,
}

/// A function that answers like the model: `(system, user, schema) -> JSON object`.
pub type CompleteFn = dyn Fn(&str, &str, &Value) -> Result<Value, AiError> + Send + Sync;

enum Backend {
    Anthropic {
        base: String,
        auth: ApiAuth,
        retries: u32,
    },
    OpenAi {
        base: String,
        key: Option<String>,
        retries: u32,
    },
    ClaudeCode {
        launcher: Launcher,
        flags: BTreeSet<String>,
    },
    CodexCli {
        launcher: Launcher,
        support: cli::CodexSupport,
    },
    GeminiCli {
        launcher: Launcher,
        flags: BTreeSet<String>,
    },
    Custom(Box<CompleteFn>),
}

#[derive(Default)]
struct Usage {
    calls: i64,
    input_tokens: i64,
    output_tokens: i64,
    cost_usd: f64,
}

/// Who answers the AI review. One interface for every provider: [`Provider::complete`].
pub struct Provider {
    /// The provider id ("openai-compatible", "claude-code"...), or the name of a custom provider.
    pub id: String,
    /// Display name ("OpenAI-compatible API", "Claude Code"...).
    pub name: String,
    /// "cloud", "local-agent", "local-model" or "custom".
    pub kind: String,
    pub model: String,
    pub effort: String,
    /// Where the data goes, for the user.
    pub destination: String,
    /// The data stays on this computer (a model served locally).
    pub local: bool,
    backend: Backend,
    usage: Mutex<Usage>,
}

impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never prints credentials.
        f.debug_struct("Provider")
            .field("id", &self.id)
            .field("model", &self.model)
            .field("destination", &self.destination)
            .field("local", &self.local)
            .finish()
    }
}

impl Provider {
    fn new(
        id: &str,
        kind: &str,
        model: &str,
        effort: &str,
        destination: String,
        local: bool,
        backend: Backend,
    ) -> Self {
        let name = provider_info(id).map_or_else(|| id.to_string(), display_name);
        Self {
            id: id.into(),
            name,
            kind: kind.into(),
            model: model.into(),
            effort: effort.into(),
            destination,
            local,
            backend,
            usage: Mutex::new(Usage::default()),
        }
    }

    /// A server that speaks the Anthropic Messages API at `base` (Anthropic itself: [`API_BASE`]).
    pub fn anthropic(model: &str, effort: &str, auth: ApiAuth, base: &str) -> Self {
        let base = base.trim_end_matches('/').to_string();
        let local = is_loopback_url(&base);
        let destination = if local {
            tr!("The model server on this computer at {0} (model {1})", base, model)
        } else {
            tr!("The Anthropic-compatible API at {0} (model {1})", host_of(&base), model)
        };
        let backend = Backend::Anthropic { base, auth, retries: 2 };
        let kind = if local { "local-model" } else { "cloud" };
        Self::new("anthropic-compatible", kind, model, effort, destination, local, backend)
    }

    /// A server that speaks the OpenAI Chat Completions API at `base` (key optional).
    pub fn openai_compatible(model: &str, key: Option<&str>, base: &str) -> Self {
        let base = base.trim_end_matches('/').to_string();
        let local = is_loopback_url(&base);
        let destination = if local {
            tr!("The model server on this computer at {0} (model {1})", base, model)
        } else {
            tr!("The OpenAI-compatible API at {0} (model {1})", host_of(&base), model)
        };
        let backend = Backend::OpenAi {
            base,
            key: key.map(str::to_string),
            retries: 2,
        };
        let kind = if local { "local-model" } else { "cloud" };
        Self::new("openai-compatible", kind, model, "", destination, local, backend)
    }

    /// Claude Code (`claude -p`), using the session that is already signed in.
    pub fn claude_code(model: &str, effort: &str, launcher: Launcher) -> Result<Self, String> {
        let flags = cli::claude_flags(&launcher)?;
        let destination = tr!("Anthropic, through your Claude Code session (model {0})", model);
        let backend = Backend::ClaudeCode { launcher, flags };
        Ok(Self::new(
            "claude-code",
            "local-agent",
            model,
            effort,
            destination,
            false,
            backend,
        ))
    }

    /// Codex CLI (`codex exec`), using the session that is already signed in.
    pub fn codex_cli(model: &str, launcher: Launcher) -> Result<Self, String> {
        let support = cli::codex_support(&launcher)?;
        let destination = if model.is_empty() {
            tr!("OpenAI, through your Codex CLI session")
        } else {
            tr!("OpenAI, through your Codex CLI session (model {0})", model)
        };
        let backend = Backend::CodexCli { launcher, support };
        Ok(Self::new(
            "codex-cli",
            "local-agent",
            model,
            "",
            destination,
            false,
            backend,
        ))
    }

    /// Gemini CLI (`gemini -p`), using the session that is already signed in.
    pub fn gemini_cli(model: &str, launcher: Launcher) -> Result<Self, String> {
        let flags = cli::gemini_flags(&launcher)?;
        let destination = if model.is_empty() {
            tr!("Google, through your Gemini CLI session")
        } else {
            tr!("Google, through your Gemini CLI session (model {0})", model)
        };
        let backend = Backend::GeminiCli { launcher, flags };
        Ok(Self::new(
            "gemini-cli",
            "local-agent",
            model,
            "",
            destination,
            false,
            backend,
        ))
    }

    /// A provider backed by a function (tests, or another transport).
    pub fn custom(name: &str, model: &str, destination: &str, complete: Box<CompleteFn>) -> Self {
        let mut provider = Self::new(
            name,
            "custom",
            model,
            "",
            destination.to_string(),
            false,
            Backend::Custom(complete),
        );
        provider.name = name.to_string();
        provider
    }

    /// Marks a custom provider as running on this computer (tests of the local-model path).
    pub fn local(mut self, local: bool) -> Self {
        self.local = local;
        self
    }

    /// Retries after rate limits, overloads and connection errors (2 by default, HTTP providers).
    pub fn with_retries(mut self, retries: u32) -> Self {
        match &mut self.backend {
            Backend::Anthropic { retries: r, .. } | Backend::OpenAi { retries: r, .. } => {
                *r = retries;
            }
            _ => {}
        }
        self
    }

    /// Adds one call to the usage counters.
    pub fn record_usage(&self, tokens_in: i64, tokens_out: i64, cost: f64) {
        if let Ok(mut usage) = self.usage.lock() {
            usage.calls = usage.calls.saturating_add(1);
            usage.input_tokens = usage.input_tokens.saturating_add(tokens_in.max(0));
            usage.output_tokens = usage.output_tokens.saturating_add(tokens_out.max(0));
            usage.cost_usd = round_to(usage.cost_usd + if cost.is_finite() { cost.max(0.0) } else { 0.0 }, 4);
        }
    }

    /// `{"calls", "input_tokens", "output_tokens", "cost_usd"}`.
    pub fn usage(&self) -> Value {
        match self.usage.lock() {
            Ok(u) => {
                json!({"calls": u.calls, "input_tokens": u.input_tokens, "output_tokens": u.output_tokens, "cost_usd": u.cost_usd})
            }
            Err(_) => json!({"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}),
        }
    }

    /// Batch size and parallel requests that suit the provider: a local model works one request
    /// at a time on a short context; cloud APIs take larger batches in parallel.
    pub fn batching(&self) -> (usize, usize) {
        match self.kind.as_str() {
            "local-model" => (12, 1),
            "local-agent" => (45, 2),
            _ => (45, 3),
        }
    }

    /// One request: the system prompt, the user text and the JSON schema of the answer.
    pub fn complete(&self, system: &str, user: &str, schema: &Value) -> Result<Value, AiError> {
        // Last line of defence: a server on this computer may relay a cloud model (Ollama does);
        // the data must not leave the computer when the user was told it stays here.
        if self.local && ollama::is_cloud_name(&self.model) {
            return Err(failed(tr!(
                "{0} is an Ollama cloud model: it runs on ollama.com, not on this computer. Choose a model installed locally.",
                self.model
            )));
        }
        let answer = match &self.backend {
            Backend::Anthropic { base, auth, retries } => {
                anthropic::complete(self, base, auth, *retries, system, user, schema)
            }
            Backend::OpenAi { base, key, retries } => {
                openai::complete(self, base, key.as_deref(), *retries, system, user, schema)
            }
            Backend::ClaudeCode { launcher, flags } => {
                cli::claude_complete(self, launcher, flags, system, user, schema)
            }
            Backend::CodexCli { launcher, support } => {
                cli::codex_complete(self, launcher, support, system, user, schema)
            }
            Backend::GeminiCli { launcher, flags } => cli::gemini_complete(self, launcher, flags, system, user, schema),
            Backend::Custom(complete) => complete(system, user, schema),
        }?;
        if answer.is_object() {
            Ok(answer)
        } else {
            Err(failed("the AI did not return a JSON object"))
        }
    }
}

/// The Claude Code executable on PATH, if installed.
pub fn find_claude_cli() -> Option<Launcher> {
    cli::find_claude()
}

/// Builds the provider the configuration asks for. The error explains why there is none.
pub fn pick_provider(config: &AiConfig, probe: &dyn Probe) -> Result<Provider, String> {
    let id = config.provider.trim();
    let Some(info) = provider_info(id) else {
        let known: Vec<&str> = PROVIDERS.iter().map(|p| p.id).collect();
        return Err(tr!(
            "unknown AI provider \"{0}\" (use one of: {1})",
            id,
            known.join(", ")
        ));
    };
    match info.id {
        "off" => Err(tr!("the AI review is turned off")),
        "auto" => {
            let mut problems = Vec::new();
            for candidate in AUTO_ORDER {
                let Some(other) = provider_info(candidate) else {
                    continue;
                };
                let status = status_of(other, config, probe);
                if !status.available || !auto_knows_model(other, config, probe) {
                    continue;
                }
                // "auto" uses each provider's defaults, not the model typed for another one.
                let defaults = AiConfig {
                    provider: candidate.to_string(),
                    model: String::new(),
                    endpoint: String::new(),
                    effort: config.effort.clone(),
                };
                match build(other, &defaults, probe) {
                    Ok(provider) => return Ok(provider),
                    Err(problem) => problems.push(format!("{}: {problem}", display_name(other))),
                }
            }
            if problems.is_empty() {
                Err(tr!(
                    "No AI is available: install a local agent, or set up an OpenAI- or Anthropic-compatible API (a local server such as Ollama or LM Studio works too)."
                ))
            } else {
                Err(problems.join("; "))
            }
        }
        _ => build(info, config, probe),
    }
}

fn build(info: &'static ProviderInfo, config: &AiConfig, probe: &dyn Probe) -> Result<Provider, String> {
    let model = {
        let typed = config.model.trim();
        if typed.is_empty() {
            info.default_model.to_string()
        } else {
            typed.to_string()
        }
    };
    if !model.is_empty() && !valid_model(&model) {
        return Err(tr!("the model name \"{0}\" is not valid", clip(&model, 60)));
    }
    let effort = if EFFORTS.contains(&config.effort.as_str()) {
        config.effort.clone()
    } else {
        DEFAULT_EFFORT.to_string()
    };
    let key = |secret: &str| probe.key(secret);
    let missing_key = |secret: &str| {
        let names = env_hint(secret, probe.elevated());
        if names.is_empty() {
            tr!("no API key is saved for {0}", display_name(info))
        } else {
            tr!(
                "no API key is saved for {0} (or set {1})",
                display_name(info),
                names.join(" / ")
            )
        }
    };
    let launcher = || {
        probe
            .launcher(info.id)
            .ok_or_else(|| tr!("{0} is not installed on this computer.", info.name))
    };
    // On this computer, an Ollama server may also list cloud models: only local ones are used.
    let keep_local = |endpoint: &str, model: &str| -> Result<(), String> {
        if !is_loopback_url(endpoint) {
            return Ok(());
        }
        let refused = || {
            tr!(
                "{0} is not a model installed on this computer (Ollama cloud models are not used, so the data never leaves it)",
                model
            )
        };
        if ollama::is_cloud_name(model) {
            return Err(refused());
        }
        match probe.ollama_models(endpoint) {
            Some(Ok(local)) if !local.iter().any(|m| m == model) => Err(refused()),
            Some(Err(problem)) => Err(problem),
            _ => Ok(()),
        }
    };
    // Who serves a model on this computer: shown with the destination, refused when elevated if a
    // standard user's program could have started it.
    let local_servers_of = |endpoint: &str| -> Result<Vec<LocalServer>, String> {
        if is_loopback_url(endpoint) {
            check_local_server(endpoint, probe)
        } else {
            Ok(Vec::new())
        }
    };
    match info.id {
        "openai-compatible" => {
            let endpoint = check_endpoint(&endpoint_for(info, config, probe))?;
            let model = if model.is_empty() {
                let first_local = is_loopback_url(&endpoint)
                    .then(|| probe.ollama_models(&endpoint))
                    .flatten()
                    .and_then(Result::ok)
                    .and_then(|local| local.into_iter().next());
                first_local.ok_or_else(|| tr!("choose the model the server should use"))?
            } else {
                model
            };
            keep_local(&endpoint, &model)?;
            let servers = local_servers_of(&endpoint)?;
            let mut provider = Provider::openai_compatible(&model, key("openai-compatible").as_deref(), &endpoint);
            provider.destination = served_by(provider.destination, &servers);
            Ok(provider)
        }
        "anthropic-compatible" => {
            let endpoint = check_endpoint(&endpoint_for(info, config, probe))?;
            // The default Claude model only makes sense on Anthropic's own address.
            if config.model.trim().is_empty() && endpoint != API_BASE {
                return Err(tr!("choose the model the server should use"));
            }
            keep_local(&endpoint, &model)?;
            let servers = local_servers_of(&endpoint)?;
            let auth = match key("anthropic-compatible") {
                Some(k) => ApiAuth::Key(k),
                None => match probe.bearer_token() {
                    Some(token) => ApiAuth::Bearer(token),
                    None if is_loopback_url(&endpoint) => ApiAuth::None,
                    None => return Err(missing_key("anthropic-compatible")),
                },
            };
            let mut provider = Provider::anthropic(&model, &effort, auth, &endpoint);
            provider.destination = served_by(provider.destination, &servers);
            Ok(provider)
        }
        "claude-code" => Provider::claude_code(&model, &effort, launcher()?),
        "codex-cli" => Provider::codex_cli(&model, launcher()?),
        "gemini-cli" => Provider::gemini_cli(&model, launcher()?),
        other => Err(tr!("unknown AI provider \"{0}\"", other)),
    }
}

/// The models a provider offers: what the server at the endpoint lists (only the models that run on
/// this computer for a local Ollama server), the suggestions otherwise.
pub fn list_models(
    provider: &str,
    endpoint: &str,
    keys: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<String>, String> {
    let info = provider_info(provider).ok_or_else(|| tr!("unknown AI provider \"{0}\"", provider))?;
    let suggestions = || Ok(info.suggested_models.iter().map(|m| m.to_string()).collect());
    if info.kind != "api" {
        return suggestions();
    }
    let probe = SystemProbe {
        keys,
        signer: &|_| None,
    };
    let config = AiConfig {
        provider: provider.to_string(),
        endpoint: endpoint.to_string(),
        ..AiConfig::default()
    };
    let endpoint = check_endpoint(&endpoint_for(info, &config, &probe))?;
    if let Some(local) = probe.ollama_models(&endpoint) {
        return local;
    }
    match info.id {
        "openai-compatible" => openai::models(&endpoint, keys("openai-compatible").as_deref()),
        _ => {
            let auth = match keys("anthropic-compatible") {
                Some(k) => ApiAuth::Key(k),
                None => probe.bearer_token().map_or(ApiAuth::None, ApiAuth::Bearer),
            };
            match anthropic::models(&endpoint, &auth) {
                Ok(models) if !models.is_empty() => Ok(models),
                Ok(_) => suggestions(),
                Err(_) if endpoint == API_BASE => suggestions(),
                Err(problem) => Err(problem),
            }
        }
    }
}

// --------------------------------------------------------------------------- data sent

fn is_blank(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// Trims long strings and lists so that no single item monopolizes the context.
fn trim(value: &Value, text_limit: usize, list_limit: usize) -> Value {
    match value {
        Value::String(s) => json!(clip(s, text_limit)),
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(_, v)| !is_blank(v))
                .map(|(k, v)| (k.clone(), trim(v, text_limit, list_limit)))
                .collect(),
        ),
        Value::Array(items) => {
            let mut out: Vec<Value> = items
                .iter()
                .take(list_limit)
                .map(|v| trim(v, text_limit, list_limit))
                .collect();
            if items.len() > list_limit {
                out.push(json!(format!("(+{} more)", items.len() - list_limit)));
            }
            Value::Array(out)
        }
        other => other.clone(),
    }
}

/// Compact view of an item for the AI (not anonymized yet).
pub fn item_payload(item: &Item) -> Value {
    let signals: Vec<&str> = item
        .flags
        .iter()
        .filter(|f| f.weight > 0)
        .map(|f| f.text.as_str())
        .collect();
    let mut data = Map::new();
    data.insert("id".into(), json!(item.id));
    let roles: Vec<&str> = item.roles.iter().take(6).map(|r| r.label.as_str()).collect();
    let decoded = item.decoded.first().map_or_else(String::new, |d| clip(d, 600));
    let facts = &item.facts;
    let mut put = |key: &str, value: Value| {
        data.insert(key.into(), value);
    };
    match item.kind.as_str() {
        "executable" => {
            let info = item.file.clone().unwrap_or_default();
            let version = if truthy(info.at("version")) {
                json!(format!("v{}", str_of(info.at("version"))))
            } else {
                Value::Null
            };
            let parts: Vec<String> = [info.at("description"), info.at("company"), &version]
                .into_iter()
                .filter(|x| truthy(x))
                .map(str_of)
                .collect();
            put("type", json!("executable"));
            put("file", json!(item.path));
            put("signature", json!(signature_text(item)));
            put("info", json!(parts.join(" · ")));
            put("modified", json!(take(&text(info.at("modified")), 10)));
            put("presence", json!(roles));
            put(
                "commands",
                json!(item.commands.iter().take(2).map(|c| clip(c, 350)).collect::<Vec<_>>()),
            );
            put("decoded", json!(decoded));
            put("launched_by", facts.at("launched_by").clone());
        }
        "command" => {
            let command = item.commands.first().unwrap_or(&item.title);
            put("type", json!("command"));
            put("command", json!(clip(command, 600)));
            put("interpreter", facts.at("host").clone());
            put("presence", json!(roles));
            put("decoded", json!(decoded));
        }
        "group" => {
            let components: Vec<String> = item
                .members
                .iter()
                .take(30)
                .map(|m| {
                    let description = if truthy(m.at("description")) {
                        text(m.at("description"))
                    } else {
                        text(m.at("company"))
                    };
                    let roles = list(m.at("roles")).iter().map(str_of).collect::<Vec<_>>().join("; ");
                    let parts = [str_of(m.at("name")), description, roles, text(m.at("path"))];
                    clip(
                        &parts
                            .into_iter()
                            .filter(|p| !p.is_empty())
                            .collect::<Vec<_>>()
                            .join(" — "),
                        300,
                    )
                })
                .collect();
            put("type", json!("vendor"));
            put("signer", json!(item.title));
            put("total_components", json!(item.members.len()));
            put("components", json!(components));
        }
        "program" => {
            put("type", json!("program"));
            put("name", json!(item.title));
            put("publisher", facts.at("publisher").clone());
            put("version", facts.at("version").clone());
            put("installed", facts.at("installed").clone());
            put("origin", facts.at("origin").clone());
        }
        "extension" => {
            let first = |key: &str, n: usize| json!(list(facts.at(key)).iter().take(n).collect::<Vec<_>>());
            put("type", json!("extension"));
            put("browser", facts.at("browser").clone());
            put("name", json!(item.title));
            put("version", facts.at("version").clone());
            put("origin", facts.at("origin").clone());
            put("active", facts.at("active").clone());
            put("description", json!(clip(&text(facts.at("description")), 140)));
            put("permissions", first("permissions", 14));
            put("sites", first("sites", 6));
        }
        "event" => {
            put("type", json!("event"));
            put("title", json!(item.title));
            put("detail", trim(&Value::Object(facts.clone()), 380, 12));
        }
        _ => {
            put("type", json!("configuration"));
            put("title", json!(item.title));
            put("detail", trim(&Value::Object(facts.clone()), 300, 14));
        }
    }
    if !item.network.is_empty() {
        let listening = if truthy(item.network.at("exposed")) {
            item.network.at("exposed")
        } else {
            item.network.at("listen")
        };
        put(
            "network",
            json!({"listening": listening, "connections_to": item.network.at("remote")}),
        );
    }
    if let Some(vt) = item.vt.as_ref().filter(|v| !v.is_empty()) {
        put("virustotal", vt.at("summary").clone());
    }
    if !signals.is_empty() {
        put("signals", json!(signals));
        put("score", json!(item.score));
    }
    Value::Object(data.into_iter().filter(|(_, v)| !is_blank(v)).collect())
}

fn context(analysis: &Analysis) -> Value {
    let inventory: Map<String, Value> = ["processes", "services", "tasks", "programs", "extensions"]
        .iter()
        .map(|k| (k.to_string(), analysis.stats.at(k).clone()))
        .collect();
    let auto_trusted = analysis.stats.get("auto_trusted").cloned().unwrap_or(json!(0));
    json!({
        "system_state": analysis.posture,
        "inventory": inventory,
        "note": format!("{} Microsoft components with a valid signature were trusted automatically and are not included.", str_of(&auto_trusted)),
    })
}

/// Programs go separately (there are many and they are very short); the rest, in risk order.
fn make_batches(items: &[&Item], pending: &[usize], size: usize) -> Vec<Vec<usize>> {
    let programs: Vec<usize> = pending
        .iter()
        .copied()
        .filter(|&i| items[i].kind == "program")
        .collect();
    let others: Vec<usize> = pending
        .iter()
        .copied()
        .filter(|&i| items[i].kind != "program")
        .collect();
    let mut chunks: Vec<Vec<usize>> = others.chunks(size).map(<[usize]>::to_vec).collect();
    chunks.extend(programs.chunks(size * 2).map(<[usize]>::to_vec));
    chunks.retain(|c| !c.is_empty());
    chunks
}

// --------------------------------------------------------------------------- analysis

#[derive(Clone)]
struct Decision {
    index: usize,
    verdict: String,
    what: String,
    reason: String,
    action: String,
    confidence: String,
}

fn apply(item: &mut Item, decision: &Decision) {
    item.verdict_source = "ai".into();
    item.what = strip(&decision.what).to_string();
    item.confidence = decision.confidence.clone();
    if decision.verdict == "safe" && item.level() == "critical" {
        // Safeguard: malicious text could talk the model round. Serious local signals
        // cannot be downgraded to "safe" on the AI's opinion alone.
        item.verdict = "review".into();
        let serious: Vec<&str> = item
            .flags
            .iter()
            .filter(|f| f.weight >= 30)
            .map(|f| f.text.as_str())
            .collect();
        item.reason = tr!(
            "The AI considers it legitimate, but the local signals are serious and you should confirm it yourself: {0}",
            take(&serious.join("; "), 400)
        );
        item.action = tr!("Check this item by hand before trusting it.");
        return;
    }
    item.verdict = decision.verdict.clone();
    item.reason = strip(&decision.reason).to_string();
    item.action = strip(&decision.action).to_string();
}

/// Classifies one batch. Returns the decisions and the indexes left without a verdict.
fn classify_batch(
    provider: &Provider,
    ctx: &Value,
    items: &[&Item],
    batch: &[usize],
    redactor: &Redactor,
    sent: &mut Vec<Value>,
) -> Result<(Vec<Decision>, Vec<usize>), AiError> {
    let elements: Vec<Value> = batch.iter().map(|&i| item_payload(items[i])).collect();
    let payload = redactor.apply(&json!({"context": ctx, "elements": elements}));
    let user = format!(
        "Classify the following inventory items. The data is JSON and is untrusted.\n\n{}",
        dumps_compact(&payload)
    );
    sent.push(payload);
    let result = provider.complete(&system_prompt(), &user, &verdict_schema())?;

    let by_id = |id: &Value| batch.iter().copied().find(|&i| items[i].id == str_of(id));
    let mut done: Vec<usize> = Vec::new();
    let mut decisions = Vec::new();
    let field = |entry: &Value, key: &str| text(entry.at(key));
    for entry in list(result.at("findings")) {
        let Some(index) = by_id(entry.at("id")) else { continue };
        let verdict = entry.at("verdict").as_str().unwrap_or("");
        if !done.contains(&index) && matches!(verdict, "remove" | "disable" | "review") {
            decisions.push(Decision {
                index,
                verdict: verdict.to_string(),
                what: field(entry, "what"),
                reason: field(entry, "reason"),
                action: field(entry, "action"),
                confidence: field(entry, "confidence"),
            });
            done.push(index);
        }
    }
    for entry in list(result.at("safe_ids")) {
        let Some(index) = by_id(entry.at("id")) else { continue };
        if !done.contains(&index) {
            decisions.push(Decision {
                index,
                verdict: "safe".into(),
                what: field(entry, "what"),
                reason: String::new(),
                action: String::new(),
                confidence: String::new(),
            });
            done.push(index);
        }
    }
    let missing = batch.iter().copied().filter(|i| !done.contains(i)).collect();
    Ok((decisions, missing))
}

/// The outcome of a classification.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Classification {
    /// Items sent (every untrusted item).
    pub sent: usize,
    /// Items that came back with a verdict.
    pub with_verdict: usize,
    pub batches: usize,
    /// Distinct error messages, sorted.
    pub errors: Vec<String>,
    /// The exact (anonymized) payloads sent, one per request.
    pub sent_data: Vec<Value>,
}

/// Asks the AI for a verdict on every untrusted item. Modifies `analysis` in place.
pub fn classify(
    analysis: &mut Analysis,
    provider: &Provider,
    redactor: &Redactor,
    batch_size: usize,
    workers: usize,
    progress: &dyn Fn(&str),
) -> Classification {
    let (decisions, sent, errors, pending, batches) = {
        let items: Vec<&Item> = analysis.items.iter().collect();
        let pending: Vec<usize> = (0..items.len()).filter(|&i| !items[i].trusted).collect();
        let batches = make_batches(&items, &pending, batch_size.max(1));
        let ctx = context(analysis);
        let next = AtomicUsize::new(0);
        let finished = AtomicUsize::new(0);
        type Outcome = (usize, Vec<Value>, Vec<Decision>, Vec<String>);
        let outcomes: Mutex<Vec<Outcome>> = Mutex::new(Vec::new());
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::scope(|scope| {
            for _ in 0..workers.max(1).min(batches.len()) {
                let tx = tx.clone();
                let (items, batches, ctx, next, finished, outcomes) =
                    (&items, &batches, &ctx, &next, &finished, &outcomes);
                scope.spawn(move || {
                    loop {
                        let n = next.fetch_add(1, Ordering::Relaxed);
                        let Some(batch) = batches.get(n) else { break };
                        let mut local_sent = Vec::new();
                        let mut decisions = Vec::new();
                        let mut errors = Vec::new();
                        let first = classify_batch(provider, ctx, items, batch, redactor, &mut local_sent).and_then(
                            |(found, missing)| {
                                decisions.extend(found);
                                if missing.is_empty() {
                                    return Ok(());
                                }
                                // Second attempt with only the ones the model left out.
                                let (found, _) =
                                    classify_batch(provider, ctx, items, &missing, redactor, &mut local_sent)?;
                                decisions.extend(found);
                                Ok(())
                            },
                        );
                        match first {
                            Ok(()) => {}
                            Err(AiError::Truncated(_)) => {
                                // The response was too long: split the batch in two.
                                let half = (batch.len() / 2).max(1);
                                for part in [&batch[..half.min(batch.len())], &batch[half.min(batch.len())..]] {
                                    if part.is_empty() {
                                        continue;
                                    }
                                    match classify_batch(provider, ctx, items, part, redactor, &mut local_sent) {
                                        Ok((found, _)) => decisions.extend(found),
                                        Err(error) => errors.push(error.to_string()),
                                    }
                                }
                            }
                            Err(error) => errors.push(error.to_string()),
                        }
                        let done = finished.fetch_add(1, Ordering::Relaxed) + 1;
                        let _ = tx.send(tr!(
                            "  batch {0}/{1} analyzed ({2} items)",
                            done,
                            batches.len(),
                            batch.len()
                        ));
                        if let Ok(mut list) = outcomes.lock() {
                            list.push((n, local_sent, decisions, errors));
                        }
                    }
                });
            }
            drop(tx);
            for message in rx {
                progress(&message);
            }
        });
        let mut outcomes = outcomes.into_inner().unwrap_or_default();
        outcomes.sort_by_key(|(n, ..)| *n);
        let mut sent = Vec::new();
        let mut decisions = Vec::new();
        let mut errors = BTreeSet::new();
        for (_, batch_sent, batch_decisions, batch_errors) in outcomes {
            sent.extend(batch_sent);
            decisions.extend(batch_decisions);
            errors.extend(batch_errors);
        }
        (decisions, sent, errors, pending, batches.len())
    };
    for decision in &decisions {
        if let Some(item) = analysis.items.get_mut(decision.index) {
            apply(item, decision);
        }
    }
    let with_verdict = pending
        .iter()
        .filter(|&&i| analysis.items[i].verdict_source == "ai")
        .count();
    Classification {
        sent: pending.len(),
        with_verdict,
        batches,
        errors: errors.into_iter().collect(),
        sent_data: sent,
    }
}

/// Executive summary built from the verdicts. Returns (summary, exact payload sent).
pub fn summarize(analysis: &Analysis, provider: &Provider, redactor: &Redactor) -> Result<(Value, Value), AiError> {
    let mut findings: Vec<(usize, Value)> = analysis
        .items
        .iter()
        .filter_map(|item| {
            let order = match item.verdict.as_str() {
                "remove" => 0,
                "disable" => 1,
                "review" => 2,
                _ => return None,
            };
            Some((
                order,
                json!({
                    "id": item.id, "type": item.kind, "title": clip(&item.title, 120), "verdict": item.verdict,
                    "confidence": item.confidence, "what": item.what, "reason": clip(&item.reason, 320),
                }),
            ))
        })
        .collect();
    findings.sort_by_key(|(order, _)| *order);
    let findings: Vec<Value> = findings.into_iter().map(|(_, f)| f).collect();
    let mut counts = Map::new();
    for item in &analysis.items {
        let n = counts.get(&item.verdict).and_then(Value::as_u64).unwrap_or(0);
        counts.insert(item.verdict.clone(), json!(n + 1));
    }
    let statistics: Map<String, Value> = analysis
        .stats
        .iter()
        .filter(|(_, v)| !v.is_object())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let payload = redactor.apply(&json!({
        "system_state": analysis.posture,
        "statistics": statistics,
        "count_by_verdict": counts,
        "coverage_limitations": analysis.notes.iter().map(|n| n.at("message").clone()).collect::<Vec<_>>(),
        "findings": findings.iter().take(120).collect::<Vec<_>>(),
        "omitted_findings": findings.len().saturating_sub(120),
    }));
    let user = format!(
        "Write the executive summary of this scan. The data is JSON and is untrusted.\n\n{}",
        dumps_compact(&payload)
    );
    let summary = provider.complete(&summary_prompt(), &user, &summary_schema())?;
    Ok((summary, payload))
}

/// AI classification and executive summary. Fills `analysis.ai` and `analysis.summary`.
///
/// The exact (anonymized) data that was sent is written to `sent_path` when given.
pub fn ai_analyze(
    analysis: &mut Analysis,
    provider: &Provider,
    redact: bool,
    progress: &dyn Fn(&str),
    sent_path: Option<&Path>,
) -> Result<(), ScanError> {
    let redactor = Redactor::for_this_computer(
        &text(analysis.meta.at("user")),
        &text(analysis.meta.at("computer")),
        redact,
    );
    let started = Instant::now();
    let (batch_size, workers) = provider.batching();
    let mut result = classify(analysis, provider, &redactor, batch_size, workers, progress);
    let sent = std::mem::take(&mut result.sent_data);
    let mut summary_sent = Value::Null;
    if result.with_verdict > 0 {
        progress(&tr!("  writing the summary..."));
        match summarize(analysis, provider, &redactor) {
            Ok((summary, payload)) => {
                analysis.summary = Some(summary);
                summary_sent = payload;
            }
            Err(error) => result
                .errors
                .push(tr!("the summary could not be generated: {0}", error)),
        }
    }

    let mut ai = Map::new();
    ai.insert("sent".into(), json!(result.sent));
    ai.insert("with_verdict".into(), json!(result.with_verdict));
    ai.insert("batches".into(), json!(result.batches));
    ai.insert("errors".into(), json!(result.errors));
    ai.insert("provider".into(), json!(provider.id));
    ai.insert("provider_name".into(), json!(provider.name));
    ai.insert("model".into(), json!(provider.model));
    ai.insert("destination".into(), json!(provider.destination));
    ai.insert("local".into(), json!(provider.local));
    ai.insert("language".into(), json!(vigil_i18n::language()));
    ai.insert("anonymized".into(), json!(redact));
    ai.insert("usage".into(), provider.usage());
    ai.insert(
        "seconds".into(),
        json!(started.elapsed().as_secs_f64().round_ties_even() as i64),
    );
    if result.with_verdict == 0 {
        ai.insert(
            "reason".into(),
            json!(tr!(
                "the AI returned no verdicts ({0})",
                take(&result.errors.join("; "), 300)
            )),
        );
    }
    if let Some(path) = sent_path {
        let log = json!({"batches": sent, "summary": summary_sent});
        std::fs::write(path, dumps_pretty(&log)).map_err(|e| ScanError::io(path, e))?;
        ai.insert("sent_log".into(), json!(path.display().to_string()));
    }
    analysis.ai = ai;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemas_and_prompts_load() {
        assert!(verdict_schema().at("properties").at("findings").is_object());
        assert!(summary_schema().at("properties").at("risk_level").is_object());
        assert!(SYSTEM_PROMPT.starts_with("You are a security analyst"));
        assert!(SUMMARY_PROMPT.ends_with("plain English."));
    }

    #[test]
    fn prompts_ask_for_the_user_language() {
        let english = vigil_i18n::with_language("en", system_prompt);
        assert_eq!(english, SYSTEM_PROMPT);
        let spanish = vigil_i18n::with_language("es", system_prompt);
        assert!(spanish.contains("plain Spanish"), "{spanish}");
        assert!(spanish.contains("exactly as specified, in English"));
        let chinese = vigil_i18n::with_language("zh", summary_prompt);
        assert!(chinese.contains("plain Simplified Chinese"));
    }

    #[test]
    fn json_text_extraction() {
        assert_eq!(parse_json_text("```json\n{\"a\": 1}\n```"), Ok(json!({"a": 1})));
        assert_eq!(parse_json_text("noise {\"a\": [1]} more"), Ok(json!({"a": [1]})));
        assert!(parse_json_text("[1, 2]").is_err());
    }

    #[test]
    fn trimming() {
        let long = "x".repeat(400);
        let trimmed = trim(&json!({"a": long, "b": null, "c": [1, 2, 3]}), 10, 2);
        assert_eq!(
            trimmed,
            json!({"a": "xxxxxxxxxx… (+390 characters)", "c": [1, 2, "(+1 more)"]})
        );
    }

    #[test]
    fn model_names_are_checked() {
        for good in [
            "claude-opus-5-5",
            "qwen3:14b",
            "meta-llama/Llama-3.1-8B-Instruct",
            "gpt-5",
            "org/model@rev3+q4",
        ] {
            assert!(valid_model(good), "{good}");
        }
        for bad in ["", "model name", "x;rm", "a\"b", &"m".repeat(121)] {
            assert!(!valid_model(bad), "{bad}");
        }
    }

    struct FakeProbe {
        agents: Vec<&'static str>,
        keys: Vec<&'static str>,
        /// Providers whose local server answers.
        servers: Vec<&'static str>,
        /// The local server is Ollama, with these models installed on the computer.
        ollama: Option<Vec<&'static str>>,
        /// Vigil runs as administrator (the CI runner does: never ask Windows here).
        elevated: bool,
        /// The programs listening at a local endpoint (`None`: they could not be read).
        listeners: Option<Vec<LocalServer>>,
    }

    impl FakeProbe {
        fn new(agents: Vec<&'static str>, keys: Vec<&'static str>) -> Self {
            Self {
                agents,
                keys,
                servers: vec![],
                ollama: None,
                elevated: false,
                listeners: Some(vec![]),
            }
        }
    }

    impl Probe for FakeProbe {
        fn elevated(&self) -> bool {
            self.elevated
        }
        fn launcher(&self, provider: &str) -> Option<Launcher> {
            self.agents.contains(&provider).then(|| Launcher {
                program: std::path::PathBuf::from(r"C:\nowhere\agent.exe"),
                script: None,
            })
        }
        fn key(&self, secret: &str) -> Option<String> {
            self.keys.contains(&secret).then(|| "test-key".to_string())
        }
        fn reachable(&self, provider: &str, endpoint: &str) -> bool {
            is_loopback_url(endpoint) && self.servers.contains(&provider)
        }
        fn ollama_models(&self, endpoint: &str) -> Option<Result<Vec<String>, String>> {
            let models = self.ollama.as_ref().filter(|_| is_loopback_url(endpoint))?;
            Some(Ok(models.iter().map(|m| m.to_string()).collect()))
        }
        fn base_url(&self, _provider: &str) -> Option<String> {
            None
        }
        fn bearer_token(&self) -> Option<String> {
            None
        }
        fn local_servers(&self, endpoint: &str) -> Option<Vec<LocalServer>> {
            self.listeners.clone().filter(|_| is_loopback_url(endpoint))
        }
    }

    fn config(provider: &str) -> AiConfig {
        AiConfig {
            provider: provider.into(),
            ..AiConfig::default()
        }
    }

    fn configured(provider: &str, model: &str, endpoint: &str) -> AiConfig {
        AiConfig {
            provider: provider.into(),
            model: model.into(),
            endpoint: endpoint.into(),
            ..AiConfig::default()
        }
    }

    #[test]
    fn the_catalog_has_two_standards_and_three_agents() {
        let ids: Vec<&str> = PROVIDERS.iter().map(|p| p.id).collect();
        assert_eq!(
            ids,
            [
                "auto",
                "openai-compatible",
                "anthropic-compatible",
                "claude-code",
                "codex-cli",
                "gemini-cli",
                "off"
            ]
        );
        for removed in ["openai", "anthropic", "gemini", "ollama"] {
            assert!(provider_info(removed).is_none(), "{removed}");
        }
    }

    #[test]
    fn the_elevated_copy_ignores_the_environment() {
        let read = |name: &str| (name == "OPENAI_BASE_URL").then(|| " http://203.0.113.7/v1 ".to_string());
        assert_eq!(
            from_env(&["OPENAI_BASE_URL"], false, &read).as_deref(),
            Some("http://203.0.113.7/v1")
        );
        assert_eq!(from_env(&["OPENAI_BASE_URL"], true, &read), None);
        assert_eq!(env_hint("openai-compatible", false), ["OPENAI_API_KEY"]);
        assert!(env_hint("openai-compatible", true).is_empty());
        // Whatever the environment holds, the elevated copy reads no key from it.
        cli::set_elevated(Some(true));
        for secret in ["openai-compatible", "anthropic-compatible", "virustotal"] {
            assert_eq!(env_key(secret), None, "{secret}");
        }
        cli::set_elevated(None);
        // Elevated, the hints name no variable either.
        let mut probe = FakeProbe::new(vec![], vec![]);
        probe.elevated = true;
        let status = statuses(
            &configured("openai-compatible", "m", "https://api.example.com/v1"),
            &probe,
        )
        .into_iter()
        .find(|s| s.info.id == "openai-compatible")
        .expect("status");
        assert!(
            !status.available && !status.note.contains("OPENAI_API_KEY"),
            "{}",
            status.note
        );
    }

    #[test]
    fn loopback_targets_name_the_port_and_the_address_family() {
        assert_eq!(
            net::loopback_target("http://localhost:11434/v1"),
            Some((11434, true, true))
        );
        assert_eq!(net::loopback_target("http://127.0.0.1/v1"), Some((80, true, false)));
        assert_eq!(net::loopback_target("https://[::1]:8443"), Some((8443, false, true)));
        assert_eq!(net::loopback_target("https://api.example.com/v1"), None);
        assert_eq!(net::loopback_target("http://localhost:99999"), None);
    }

    #[test]
    fn only_program_files_counts_as_admin_only() {
        let roots = [std::path::PathBuf::from(r"C:\Program Files")];
        assert!(inside_any(r"C:\Program Files\Ollama\ollama.exe", &roots));
        assert!(inside_any(r"c:\program files\Ollama\ollama.exe", &roots));
        assert!(!inside_any(r"C:\Program FilesX\ollama.exe", &roots));
        assert!(!inside_any(r"C:\Program Files\..\Users\jdoe\ollama.exe", &roots));
        assert!(!inside_any(
            r"C:\Users\jdoe\AppData\Local\Programs\Ollama\ollama.exe",
            &roots
        ));
        assert!(!inside_any(r"C:\Program Files\x.exe", &[std::path::PathBuf::new()]));
    }

    #[test]
    fn a_local_model_server_is_named_and_refused_when_a_user_could_have_planted_it() {
        let endpoint = "http://127.0.0.1:11434/v1";
        let user_copy = r"C:\Users\jdoe\AppData\Local\Programs\Ollama\ollama.exe";
        let server = |program: &str, signer: Option<&str>| LocalServer {
            pid: 4242,
            program: program.into(),
            signer: signer.map(str::to_string),
        };
        let probe_with = |elevated: bool, listeners: Option<Vec<LocalServer>>| {
            let mut probe = FakeProbe::new(vec![], vec![]);
            probe.servers = vec!["openai-compatible", "anthropic-compatible"];
            probe.elevated = elevated;
            probe.listeners = listeners;
            probe
        };
        let pick = |probe: &FakeProbe, provider: &str| pick_provider(&configured(provider, "m", endpoint), probe);
        let status = |probe: &FakeProbe| {
            statuses(&configured("openai-compatible", "m", endpoint), probe)
                .into_iter()
                .find(|s| s.info.id == "openai-compatible")
                .expect("status")
        };

        // Without administrator rights it is used, and the consent dialog names the program.
        let plain = probe_with(false, Some(vec![server(user_copy, None)]));
        let provider = pick(&plain, "openai-compatible").expect("used");
        assert!(provider.destination.contains(user_copy), "{}", provider.destination);
        assert!(provider.destination.contains("not signed"), "{}", provider.destination);
        assert!(status(&plain).available);

        // As administrator, an unsigned program in a user's folder gets nothing.
        let elevated = probe_with(true, Some(vec![server(user_copy, None)]));
        for provider in ["openai-compatible", "anthropic-compatible"] {
            let problem = pick(&elevated, provider).expect_err("refused");
            assert!(
                problem.contains(user_copy) && problem.contains("without administrator"),
                "{problem}"
            );
        }
        let refused = status(&elevated);
        assert!(
            !refused.available && refused.note.contains("without administrator"),
            "{}",
            refused.note
        );

        // A signed program passes, and its signer is shown.
        let signed = probe_with(true, Some(vec![server(user_copy, Some("Example Models Inc."))]));
        let provider = pick(&signed, "anthropic-compatible").expect("signed");
        assert!(
            provider.destination.contains("signed by Example Models Inc."),
            "{}",
            provider.destination
        );
        assert!(status(&signed).available);

        // So does an unsigned program in Program Files, which only administrators can change.
        #[cfg(windows)]
        {
            let installed = vigil_sys::paths::program_files()
                .join(r"Example\server.exe")
                .display()
                .to_string();
            let probe = probe_with(true, Some(vec![server(&installed, None)]));
            let provider = pick(&probe, "openai-compatible").expect("Program Files");
            assert!(provider.destination.contains(&installed), "{}", provider.destination);
        }

        // An unknown owner (HTTP.sys answers as System), an unreadable table, no listener, or a
        // second, planted listener next to a signed one: refused.
        let signed_one = server(user_copy, Some("Example Models Inc."));
        for listeners in [
            Some(vec![server("", None)]),
            None,
            Some(vec![]),
            Some(vec![
                signed_one.clone(),
                server(r"C:\Users\jdoe\Downloads\proxy.exe", None),
            ]),
        ] {
            let probe = probe_with(true, listeners.clone());
            assert!(pick(&probe, "openai-compatible").is_err(), "{listeners:?}");
        }

        // A remote endpoint is not about local programs.
        let mut remote = probe_with(true, None);
        remote.keys = vec!["openai-compatible"];
        let provider = pick_provider(
            &configured("openai-compatible", "m", "https://api.example.com/v1"),
            &remote,
        )
        .expect("remote");
        assert!(!provider.destination.contains("program"), "{}", provider.destination);
    }

    #[test]
    fn local_agents_are_never_used_while_vigil_runs_as_administrator() {
        let mut probe = FakeProbe::new(vec!["claude-code", "codex-cli"], vec!["anthropic-compatible"]);
        probe.elevated = true;
        let all = statuses(&config("auto"), &probe);
        for id in ["claude-code", "codex-cli", "gemini-cli"] {
            let status = all.iter().find(|s| s.info.id == id).expect("status");
            assert!(!status.available, "{id}");
            assert!(status.note.contains("administrator"), "{}", status.note);
        }
        // "auto" skips them and takes the API that is set up.
        let picked = pick_provider(&config("auto"), &probe).expect("an API");
        assert_eq!(picked.id, "anthropic-compatible");
        // Chosen explicitly, an agent is refused rather than started.
        assert!(pick_provider(&config("claude-code"), &probe).is_err());
        // The CLI layer refuses on its own too, whatever chose it.
        cli::set_elevated(Some(true));
        assert!(cli::running_elevated());
        cli::set_elevated(Some(false));
        assert!(!cli::running_elevated());
        cli::set_elevated(None);
    }

    #[test]
    fn auto_uses_agents_then_an_api_whose_model_is_known() {
        let none = FakeProbe::new(vec![], vec![]);
        let all = statuses(&config("auto"), &none);
        assert_eq!(all.len(), PROVIDERS.len());
        assert!(!all[0].available, "auto has nothing to use");
        assert!(all.iter().any(|s| s.info.id == "off" && s.available));
        assert!(pick_provider(&config("auto"), &none).is_err());

        // An Anthropic key: Anthropic's own address has a default model.
        let anthropic = FakeProbe::new(vec![], vec!["anthropic-compatible"]);
        let picked = pick_provider(&config("auto"), &anthropic).expect("anthropic standard");
        assert_eq!(
            (picked.id.as_str(), picked.model.as_str(), picked.local),
            ("anthropic-compatible", DEFAULT_MODEL, false)
        );
        assert!(
            statuses(&config("auto"), &anthropic)[0]
                .note
                .contains("Anthropic-compatible API")
        );

        // An OpenAI key alone does not tell which model to use: "auto" does not guess one.
        let openai = FakeProbe::new(vec![], vec!["openai-compatible"]);
        assert!(!statuses(&config("auto"), &openai)[0].available);
        assert!(pick_provider(&config("auto"), &openai).is_err());
    }

    #[test]
    fn explicit_providers_explain_what_is_missing() {
        let none = FakeProbe::new(vec![], vec![]);
        assert!(pick_provider(&config("off"), &none).is_err());
        for unknown in ["sometimes", "openai", "ollama"] {
            let error = pick_provider(&config(unknown), &none).expect_err("unknown");
            assert!(error.contains("unknown AI provider"), "{error}");
        }
        let no_model = pick_provider(&config("openai-compatible"), &none).expect_err("model");
        assert!(no_model.contains("choose the model"), "{no_model}");
        // The OpenAI standard takes servers without a key; the server answers if it needs one.
        let keyless = pick_provider(&configured("openai-compatible", "gpt-5", ""), &none).expect("keyless");
        assert_eq!(
            keyless.destination,
            "The OpenAI-compatible API at api.openai.com (model gpt-5)"
        );
        let anthropic = pick_provider(&config("anthropic-compatible"), &none).expect_err("no key");
        assert!(anthropic.contains("ANTHROPIC_API_KEY"), "{anthropic}");
        let elsewhere = configured("anthropic-compatible", "", "https://llm.example.com/anthropic");
        let keys = FakeProbe::new(vec![], vec!["anthropic-compatible", "openai-compatible"]);
        assert!(
            pick_provider(&elsewhere, &keys)
                .expect_err("model")
                .contains("choose the model")
        );
        let codex = pick_provider(&config("codex-cli"), &none).expect_err("not installed");
        assert!(codex.contains("Codex CLI"), "{codex}");
        let bad_model = configured("openai-compatible", "gpt 5; x", "");
        assert!(
            pick_provider(&bad_model, &keys)
                .expect_err("bad model")
                .contains("not valid")
        );
        let remote_http = configured("openai-compatible", "m", "http://203.0.113.5:1234/v1");
        assert!(
            pick_provider(&remote_http, &keys)
                .expect_err("plain http")
                .contains("https")
        );
    }

    #[test]
    fn local_servers_keep_the_data_on_the_computer() {
        let local = Provider::openai_compatible("m", None, "http://localhost:1234/v1");
        assert!(local.local && local.kind == "local-model");
        assert_eq!(local.batching(), (12, 1));
        assert!(local.destination.contains("this computer"));
        let remote = Provider::openai_compatible("m", Some("sk-test-secret-123"), "https://models.example.com/v1");
        assert!(!remote.local && remote.kind == "cloud");
        assert!(!format!("{remote:?}").contains("sk-test-secret-123"), "no key in Debug");
        let anthropic_local = Provider::anthropic("m", "high", ApiAuth::None, "http://127.0.0.1:11434");
        assert!(anthropic_local.local);

        let ollama = FakeProbe {
            agents: vec![],
            keys: vec![],
            servers: vec!["openai-compatible", "anthropic-compatible"],
            ollama: Some(vec!["llama3.1:8b", "qwen3:14b"]),
            elevated: false,
            listeners: Some(vec![]),
        };
        let here = "http://localhost:11434/v1";
        let status = statuses(&configured("openai-compatible", "qwen3:14b", here), &ollama)
            .into_iter()
            .find(|s| s.info.id == "openai-compatible")
            .expect("status");
        assert!(status.available, "{}", status.note);
        assert!(status.note.contains("stays on this computer") && status.note.contains("OLLAMA_NO_CLOUD=1"));
        assert!(status.note.contains("OLLAMA_CONTEXT_LENGTH"));
        let picked = pick_provider(&configured("openai-compatible", "qwen3:14b", here), &ollama).expect("local");
        assert!(picked.local && picked.model == "qwen3:14b");
        let first = pick_provider(&configured("openai-compatible", "", here), &ollama).expect("first local");
        assert_eq!(first.model, "llama3.1:8b");
        let keyless = pick_provider(
            &configured("anthropic-compatible", "qwen3:14b", "http://localhost:11434"),
            &ollama,
        );
        assert!(keyless.expect("no key needed on this computer").local);
        // Ollama on this computer also lists cloud models: they are refused.
        for cloud in ["kimi-k3:cloud", "gemma4:31b-cloud", "someone/relayed:latest"] {
            let error = pick_provider(&configured("openai-compatible", cloud, here), &ollama).expect_err(cloud);
            assert!(
                error.contains("not a model installed on this computer"),
                "{cloud}: {error}"
            );
        }
        // "auto" can use a local Ollama server reached through the OpenAI standard's environment address.
        let auto_local = AiConfig {
            endpoint: here.into(),
            ..config("openai-compatible")
        };
        assert!(auto_knows_model(
            provider_info("openai-compatible").expect("info"),
            &auto_local,
            &ollama
        ));
    }

    #[test]
    fn a_cloud_model_is_refused_before_sending() {
        let relay = Provider::openai_compatible("glm-5.3:cloud", None, "http://127.0.0.1:9/v1").with_retries(0);
        let error = relay
            .complete("s", "inventory", &verdict_schema())
            .expect_err("refused");
        assert!(error.to_string().contains("Ollama cloud model"), "{error}");
    }
}
