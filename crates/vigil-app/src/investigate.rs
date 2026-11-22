//! "Investigate with AI": the chosen AI agent looks into one finding with Vigil's read-only tools.
//!
//! The order of things:
//!   1. the provider comes from the settings, with the usual rules (HTTPS for remote endpoints,
//!      Ollama cloud models refused);
//!   2. a native Windows dialog says where the data goes, whether it stays on this computer, whether
//!      names are anonymized, and that the agent will call read-only tools that read more of the
//!      computer; nothing is sent before the person agrees;
//!   3. the model investigates (the registry's tools, through the API's tool calling, or through
//!      `vigil mcp` for the local agents), within limits on steps, calls, result sizes and time;
//!   4. its answer is validated like any AI answer: a verdict outside the allowed set becomes
//!      "review", and an item the local rules rate critical never becomes "safe";
//!   5. the conclusion, the evidence and every tool call are shown and saved in the data folder.
//!
//! The model never acts. A suggested action is text; the finding's own action buttons (built by
//! `requests.rs`, confirmed natively) are the only way anything changes.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, WebviewWindow};
use vigil_i18n::tr;
use vigil_scan::ai::agent::{self, Limits, McpLaunch, ToolCall};
use vigil_scan::model::{Item, VERDICTS};
use vigil_scan::privacy::clip;

use crate::commands::{ask, investigation_inputs, pick_ai};
use crate::confirm::{Answer, Prompt};
use crate::mcp::registry::{Context, Host};

/// Pages the evidence may link to (anything else is dropped).
pub const PAGES: [&str; 13] = [
    "findings",
    "processes",
    "network",
    "services",
    "startup",
    "tasks",
    "posture",
    "protection",
    "extensions",
    "accounts",
    "reliability",
    "alerts",
    "firewall",
];

static CANCEL: AtomicBool = AtomicBool::new(false);
static RUNNING: AtomicBool = AtomicBool::new(false);

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Evidence {
    pub text: String,
    /// A page of the app that shows it ("" when none).
    pub page: String,
}

/// What the page shows after an investigation.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationView {
    pub finding_id: String,
    pub verdict: String,
    pub confidence: String,
    pub conclusion: String,
    pub evidence: Vec<Evidence>,
    pub suggested_action: String,
    pub open_questions: Vec<String>,
    /// Set when Vigil changed the model's verdict (critical local signals).
    pub guard_note: String,
    pub calls: Vec<ToolCall>,
    pub steps: usize,
    pub limit: String,
    pub destination: String,
    pub local: bool,
    pub anonymized: bool,
    /// Where the record was saved ("" when it could not be).
    pub saved: String,
}

#[derive(Serialize, Clone)]
struct Progress {
    phase: &'static str,
    text: String,
}

/// The JSON schema of the final answer.
pub fn answer_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": VERDICTS},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "conclusion": {"type": "string"},
            "evidence": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"},
                        "page": {"type": "string", "enum": PAGES.iter().copied().chain([""]).collect::<Vec<_>>()},
                    },
                    "required": ["text", "page"],
                    "additionalProperties": false,
                },
            },
            "suggested_action": {"type": "string"},
            "open_questions": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["verdict", "confidence", "conclusion", "evidence", "suggested_action", "open_questions"],
        "additionalProperties": false,
    })
}

fn system_prompt() -> String {
    format!(
        "You are a Windows security analyst inside Vigil, a security app on the person's own computer. \
Investigate the finding you are given: confirm or rule out that it is malicious or unwanted, using the tools \
to check its file, signature, how it starts, what it runs, its network activity and anything related. A good \
order: get_scan_summary for the whole picture, get_finding for this finding, get_related for what shares its \
file, folder, signer, parent or network endpoint, then inspect_process or get_file_history (where the file came \
from and since when it starts) and get_process_events (its crashes, detections, services, tasks and firewall \
rules). Skip what you do not need. Be \
precise and honest about uncertainty; say what you could not check. Write the conclusion, the evidence, the \
suggested action and the open questions in {} (keep JSON keys and enumerated values in English).\n\n{}",
        vigil_i18n::language_name(vigil_i18n::language()),
        agent::TOOL_RULES
    )
}

fn user_prompt(item: &Item) -> String {
    let payload = vigil_scan::ai::item_payload(item);
    format!(
        "Investigate this finding of Vigil's latest scan (id {:?}). Its data, as the local rules saw it:\n{}\n\
The local rules rated it \"{}\" (score {}). Use get_finding for every detail, get_related for what shares \
something with it, and the other tools to look further.",
        item.id,
        serde_json::to_string(&payload).unwrap_or_default(),
        item.verdict,
        item.score
    )
}

/// Validates the model's answer. An item the local rules rate critical never becomes safe,
/// trusted or "no signals"; unknown verdicts become "review"; texts and lists are capped.
pub fn validate(item: &Item, answer: &Value) -> (String, String, String, Vec<Evidence>, String, Vec<String>, String) {
    let text = |key: &str, limit: usize| clip(answer.get(key).and_then(Value::as_str).unwrap_or("").trim(), limit);
    let mut verdict = answer.get("verdict").and_then(Value::as_str).unwrap_or("").to_string();
    if !VERDICTS.contains(&verdict.as_str()) {
        verdict = "review".into();
    }
    let mut guard = String::new();
    if item.level() == "critical" && matches!(verdict.as_str(), "safe" | "trusted" | "no_signals") {
        verdict = "review".into();
        guard = tr!(
            "The AI considers it harmless, but the local signals are serious: Vigil keeps it under review. Check it yourself before trusting it."
        );
    }
    let confidence = match text("confidence", 10).as_str() {
        c @ ("low" | "medium" | "high") => c.to_string(),
        _ => "low".into(),
    };
    let evidence: Vec<Evidence> = answer
        .get("evidence")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .take(12)
                .filter_map(|e| {
                    let text = clip(e.get("text").and_then(Value::as_str)?.trim(), 500);
                    let page = e.get("page").and_then(Value::as_str).unwrap_or("");
                    let page = if PAGES.contains(&page) {
                        page.to_string()
                    } else {
                        String::new()
                    };
                    (!text.is_empty()).then_some(Evidence { text, page })
                })
                .collect()
        })
        .unwrap_or_default();
    let questions: Vec<String> = answer
        .get("open_questions")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(|q| clip(q.trim(), 300))
                .filter(|q| !q.is_empty())
                .take(6)
                .collect()
        })
        .unwrap_or_default();
    (
        verdict,
        confidence,
        text("conclusion", 2000),
        evidence,
        text("suggested_action", 400),
        questions,
        guard,
    )
}

fn stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format!("{secs}")
}

fn save(root: &Path, view: &InvestigationView, model: &str) -> String {
    let dir = root.join("investigations");
    if std::fs::create_dir_all(&dir).is_err() {
        return String::new();
    }
    let safe_id: String = view
        .finding_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(24)
        .collect();
    let path = dir.join(format!("investigation-{}-{safe_id}.json", stamp()));
    let record = json!({"view": view, "model": model, "saved_by": "vigil"});
    match std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap_or_default()) {
        Ok(()) => path.to_string_lossy().into_owned(),
        Err(_) => String::new(),
    }
}

/// Stops a running investigation (between steps; a local agent is ended).
#[tauri::command]
pub fn investigate_cancel() {
    CANCEL.store(true, Ordering::Relaxed);
}

/// Investigates one finding of the loaded report with the configured AI agent.
#[tauri::command]
pub async fn investigate_finding(
    app: AppHandle,
    window: WebviewWindow,
    id: String,
) -> Result<Option<InvestigationView>, String> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err(tr!("An investigation is already running."));
    }
    let result = run(&app, &window, &id).await;
    RUNNING.store(false, Ordering::SeqCst);
    result
}

async fn run(app: &AppHandle, window: &WebviewWindow, id: &str) -> Result<Option<InvestigationView>, String> {
    let (settings, report, root) = investigation_inputs(app);
    let (analysis, report_path) = report.ok_or_else(|| tr!("Run or open a scan first."))?;
    let item = analysis
        .items
        .iter()
        .find(|i| i.id == id)
        .cloned()
        .ok_or_else(|| tr!("This finding is not in the loaded report."))?;
    let picker = app.clone();
    let picked_settings = settings.clone();
    let provider = tauri::async_runtime::spawn_blocking(move || pick_ai(&picker, &picked_settings))
        .await
        .map_err(|e| e.to_string())??;
    // Names are anonymized for anything that leaves the computer, when the settings say so.
    let anonymize = settings.ai.redact && !provider.local;
    let where_text = if provider.local {
        tr!("Your data stays on this computer.")
    } else {
        tr!("Data about this computer leaves it and is processed by this service.")
    };
    let names = if anonymize {
        tr!("User, account, profile folder and computer names are replaced before anything is sent.")
    } else {
        tr!("User, account and computer names are sent as they are.")
    };
    let prompt = Prompt {
        title: tr!("Investigate with AI"),
        body: tr!(
            "The AI agent will look into \"{0}\".\n\nDestination: {1}\n{2}\n\nThe agent can call Vigil's read-only tools, which read more of this computer than the finding itself: the scan report, processes, connections, services, startup entries, scheduled tasks, security settings, Microsoft Defender, browser extensions, sign-ins, event logs and individual files' signatures and hashes. {3}\n\nNothing on the computer is changed. Every tool call is shown afterwards.",
            clip(&item.title, 120),
            provider.destination,
            where_text,
            names
        ),
        warning: String::new(),
        confirm: tr!("Investigate"),
        destructive: false,
        restore_point: None,
    };
    let hwnd = window.hwnd().map(|h| h.0 as isize).unwrap_or(0);
    if !matches!(ask(app, hwnd, prompt).await, Answer::Confirm { .. }) {
        return Ok(None);
    }
    CANCEL.store(false, Ordering::Relaxed);
    let emitter = app.clone();
    let model = provider.model.clone();
    let destination = provider.destination.clone();
    let local = provider.local;
    let item_for_run = item.clone();
    let root_for_run = root.clone();
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let ctx = Context::new(Some((analysis, report_path.clone())), anonymize);
        let host = Host { ctx: &ctx, skip: &[] };
        let work = root_for_run
            .join("investigations")
            .join(format!("run-{}-{}", stamp(), std::process::id()));
        let launch = mcp_launch(&work, &report_path, anonymize);
        // The run's configuration files go, whatever happens (an error, a cancel, a panic).
        let _cleanup = RemoveOnDrop(work.clone());
        let progress = |call: &ToolCall| {
            let _ = emitter.emit(
                "investigate",
                Progress {
                    phase: "tool",
                    text: format!("{} ({} B)", call.name, call.bytes),
                },
            );
        };
        launch.as_ref().map_err(String::clone).and_then(|launch| {
            std::fs::create_dir_all(&launch.work).map_err(|e| e.to_string())?;
            agent::investigate(
                &provider,
                &system_prompt(),
                &user_prompt(&item_for_run),
                &answer_schema(),
                &host,
                Some(launch),
                &Limits::default(),
                &CANCEL,
                &progress,
            )
            .map_err(|e| e.to_string())
        })
    })
    .await
    .map_err(|e| e.to_string())??;
    let (verdict, confidence, conclusion, evidence, suggested_action, open_questions, guard_note) =
        validate(&item, &outcome.answer);
    let mut view = InvestigationView {
        finding_id: item.id.clone(),
        verdict,
        confidence,
        conclusion,
        evidence,
        suggested_action,
        open_questions,
        guard_note,
        calls: outcome.calls,
        steps: outcome.steps,
        limit: outcome.limit.unwrap_or_default(),
        destination,
        local,
        anonymized: anonymize,
        saved: String::new(),
    };
    view.saved = save(&root, &view, &model);
    let _ = app.emit(
        "investigate",
        Progress {
            phase: "done",
            text: String::new(),
        },
    );
    Ok(Some(view))
}

/// Deletes a run's work folder when dropped. The agent's process tree has already been ended (it
/// runs in a job), but its handles may close a moment later, so a few attempts are made.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        for attempt in 0..5 {
            match std::fs::remove_dir_all(&self.0) {
                Ok(()) => return,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(100 * (attempt + 1))),
            }
        }
    }
}

/// How a local agent starts `vigil mcp` for this run: this executable, the loaded report, a call log
/// and a work folder inside Vigil's data folder.
fn mcp_launch(work: &Path, report: &Path, anonymize: bool) -> Result<McpLaunch, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let log = work.join("calls.jsonl");
    let mut args = vec![
        "mcp".to_string(),
        "--report".to_string(),
        report.to_string_lossy().into_owned(),
        "--log".to_string(),
        log.to_string_lossy().into_owned(),
    ];
    if !anonymize {
        args.push("--no-anonymize".into());
    }
    // The same budget the API loop has, enforced by the server the agent talks to.
    let limits = Limits::default();
    for (flag, value) in [
        ("--max-calls", limits.max_calls),
        ("--max-bytes", limits.max_total_bytes),
        ("--max-result", limits.max_result_bytes),
    ] {
        args.push(flag.to_string());
        args.push(value.to_string());
    }
    Ok(McpLaunch {
        exe,
        args,
        log,
        work: PathBuf::from(work),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn critical() -> Item {
        let mut item = Item::new("executable", "updater", "");
        item.id = "x".into();
        item.score = 85;
        item.verdict = "remove".into();
        item
    }

    #[test]
    fn a_critical_item_never_becomes_safe() {
        for verdict in ["safe", "trusted", "no_signals"] {
            let (v, _, _, _, _, _, guard) = validate(&critical(), &json!({"verdict": verdict, "confidence": "high"}));
            assert_eq!(v, "review", "{verdict}");
            assert!(!guard.is_empty());
        }
        let (v, _, _, _, _, _, guard) = validate(&critical(), &json!({"verdict": "remove"}));
        assert_eq!(v, "remove");
        assert!(guard.is_empty());
    }

    #[test]
    fn answers_are_checked_and_capped() {
        let mut quiet = critical();
        quiet.score = 0;
        let answer = json!({
            "verdict": "obliterate",
            "confidence": "certain",
            "conclusion": "x".repeat(10_000),
            "evidence": [
                {"text": "Signed by Contoso", "page": "processes"},
                {"text": "Opens a shell", "page": "javascript:alert(1)"},
                {"text": "", "page": "findings"},
            ],
            "suggested_action": "Run del /s C:\\ as admin",
            "open_questions": ["Who installed it?", 5],
        });
        let (verdict, confidence, conclusion, evidence, action, questions, _) = validate(&quiet, &answer);
        assert_eq!(verdict, "review");
        assert_eq!(confidence, "low");
        assert!(conclusion.chars().count() < 2100);
        assert_eq!(evidence.len(), 2);
        assert_eq!(evidence[1].page, "", "unknown pages are dropped");
        // A suggested action is only text: nothing in Vigil runs it.
        assert!(action.contains("del /s"));
        assert_eq!(questions, ["Who installed it?"]);
    }

    #[test]
    fn the_schema_requires_every_field() {
        let schema = answer_schema();
        assert_eq!(schema["required"].as_array().map(Vec::len), Some(6));
        assert_eq!(schema["additionalProperties"], false);
    }

    #[test]
    fn the_mcp_launch_names_the_report_log_and_anonymization() {
        let work = std::env::temp_dir().join("vigil-launch-test");
        let launch = mcp_launch(&work, Path::new("C:\\data\\scan-20260101-100000-report.json"), true).expect("launch");
        assert_eq!(launch.args[0], "mcp");
        assert!(launch.args.contains(&"--report".to_string()) && launch.args.contains(&"--log".to_string()));
        assert!(!launch.args.contains(&"--no-anonymize".to_string()));
        let open = mcp_launch(&work, Path::new("C:\\r.json"), false).expect("launch");
        assert!(open.args.contains(&"--no-anonymize".to_string()));
    }
}
