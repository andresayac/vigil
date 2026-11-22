//! How the window asks for a change: it hands a typed request to
//! `vigil_core::service::run_action`. That rebuilds the action
//! from Rust's own state (`requests.rs`), confirms it in the native Windows task dialog
//! (`confirm.rs`, shown by the core) and runs it through `vigil_actions::execute()`. Nothing in
//! this crate builds an `ActionSpec`, calls the engine or answers a confirmation: the core's
//! `confirm::ask` is private to it (a compile-time seal), and a test below checks the sources.
//!
//! The request runs on its own thread, so the UI thread keeps pumping messages while the task
//! dialog is open; the dialog is owned by the main window, which Windows disables meanwhile (the
//! same pattern GPUI uses for its own native dialogs).

use std::sync::Arc;

use futures::channel::{mpsc, oneshot};
use vigil_core::requests::Request;
use vigil_core::service::{self, ActionOutcome, Ui};
use vigil_core::state::AppState;

/// What the page shows after a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Done; the lines say what happened (one per journal record, or a message).
    Done(Vec<String>),
    Cancelled,
    Failed(String),
}

/// The native window's side of the action path.
struct NativeUi {
    owner: isize,
    progress: mpsc::UnboundedSender<String>,
}

impl Ui for NativeUi {
    /// The main window: the core's confirmation dialog belongs to it (its modal loop runs on the
    /// request's thread).
    fn owner(&self) -> isize {
        self.owner
    }

    fn progress(&self, text: &str) {
        let _ = self.progress.unbounded_send(text.to_string());
    }
}

/// Starts `request` on a worker thread. The receiver gets the outcome; `progress` gets each line
/// of progress while it runs.
pub fn run(
    state: Arc<AppState>,
    request: Request,
    owner: isize,
    progress: mpsc::UnboundedSender<String>,
) -> oneshot::Receiver<Outcome> {
    let (tx, rx) = oneshot::channel();
    let spawned = std::thread::Builder::new().name("vigil-action".into()).spawn(move || {
        let ui = NativeUi { owner, progress };
        let outcome = summarize(service::run_action(&state, &request, &ui));
        let _ = tx.send(outcome);
    });
    if let Err(error) = spawned {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Outcome::Failed(error.to_string()));
        return rx;
    }
    rx
}

/// Investigates a finding with the AI agent on a worker thread: the consent dialog (destination,
/// anonymization, read-only tools) is native and owned by the main window. `Ok(None)`: declined.
pub fn investigate(
    state: Arc<AppState>,
    id: String,
    owner: isize,
    progress: mpsc::UnboundedSender<String>,
) -> oneshot::Receiver<Result<Option<serde_json::Value>, String>> {
    let (tx, rx) = oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("vigil-investigate".into())
        .spawn(move || {
            let ui = NativeUi { owner, progress };
            let result = vigil_core::investigate::investigate(&state, &id, &ui)
                .and_then(|view| view.map(serde_json::to_value).transpose().map_err(|e| e.to_string()));
            let _ = tx.send(result);
        });
    if let Err(error) = spawned {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Err(error.to_string()));
        return rx;
    }
    rx
}

/// Asks the Assistant on a worker thread: the consent dialog (destination, anonymization,
/// read-only tools) is native and owned by the main window. `Ok(None)`: declined.
pub fn ask(
    state: Arc<AppState>,
    question: String,
    history: Vec<vigil_core::assistant::Turn>,
    from: String,
    owner: isize,
    progress: mpsc::UnboundedSender<String>,
) -> oneshot::Receiver<Result<Option<serde_json::Value>, String>> {
    let (tx, rx) = oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("vigil-assistant".into())
        .spawn(move || {
            let ui = NativeUi { owner, progress };
            let result = vigil_core::assistant::ask(&state, &question, &history, &from, &ui)
                .and_then(|reply| reply.map(serde_json::to_value).transpose().map_err(|e| e.to_string()));
            let _ = tx.send(result);
        });
    if let Err(error) = spawned {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Err(error.to_string()));
        return rx;
    }
    rx
}

fn summarize(result: Result<ActionOutcome, String>) -> Outcome {
    match result {
        Err(error) => Outcome::Failed(error),
        Ok(outcome) if outcome.cancelled && outcome.message.is_empty() => Outcome::Cancelled,
        Ok(outcome) => {
            let mut lines: Vec<String> = outcome
                .records
                .iter()
                .map(|record| {
                    let text = |key: &str| record.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let message = text("message");
                    if message.is_empty() { text("label") } else { message }
                })
                .filter(|line| !line.is_empty())
                .collect();
            if !outcome.message.is_empty() {
                lines.push(outcome.message);
            }
            Outcome::Done(lines)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The security boundary: the window only sends requests. It never builds an action, never
    /// calls the engine (it does not even depend on it) and never answers a confirmation. The
    /// core's `confirm::ask` is `pub(crate)`, so calling it does not compile; this also catches an
    /// attempt to implement the action path's `Ui` anywhere but here, or to name an answer.
    #[test]
    fn the_ui_never_builds_or_runs_actions() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
        assert!(
            !manifest.contains("vigil-actions"),
            "the app must not depend on the action engine"
        );
        let bridge = root.join("src").join("actions.rs");
        let mut checked = 0;
        let mut stack = vec![root.join("src")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                // The bridge's own tests (these lists) are not part of what it runs, and comments
                // are not code. Whitespace is removed, so `confirm :: { ask }` or a line break
                // cannot hide a name.
                let code = if path == bridge {
                    text.split("#[cfg(test)]").next().unwrap_or("")
                } else {
                    text.as_str()
                };
                let compact: String = code
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("//"))
                    .flat_map(str::chars)
                    .filter(|c| !c.is_whitespace())
                    .collect();
                let mut forbidden = vec![
                    "vigil_actions",
                    "ActionSpec",
                    "execute_plan",
                    "execute(",
                    "confirm::ask",
                    "confirm::{",
                    "Answer::Confirm",
                    "Answer::Cancel",
                    "confirm::Answer",
                    "confirm::Prompt",
                ];
                // Only the bridge implements the action path's `Ui` (and imports it).
                if path != bridge {
                    forbidden.extend(["implUi", "service::Ui", "service::{"]);
                }
                for name in forbidden {
                    assert!(!compact.contains(name), "{} uses {name}", path.display());
                }
                checked += 1;
            }
        }
        assert!(checked > 20, "the sources were not found ({checked} files)");
    }

    /// `NativeUi` only names the owner window and passes progress on: it has no way to answer.
    #[test]
    fn the_bridge_cannot_answer() {
        let text = include_str!("actions.rs");
        let code = text.split("#[cfg(test)]").next().unwrap_or("");
        let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(!compact.contains("fnask("), "the bridge must not answer confirmations");
    }

    #[test]
    fn outcomes_read_as_lines() {
        let done = ActionOutcome {
            records: vec![serde_json::json!({"label": "End process", "message": "Ended notepad.exe"})],
            ..Default::default()
        };
        assert_eq!(summarize(Ok(done)), Outcome::Done(vec!["Ended notepad.exe".into()]));
        let cancelled = ActionOutcome {
            cancelled: true,
            ..Default::default()
        };
        assert_eq!(summarize(Ok(cancelled)), Outcome::Cancelled);
        assert_eq!(summarize(Err("no".into())), Outcome::Failed("no".into()));
    }
}
