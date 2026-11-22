//! How the native window asks for a change: it hands a typed request to
//! `vigil_core::service::run_action`, exactly as the Tauri app does. That rebuilds the action
//! from Rust's own state (`requests.rs`), confirms it in the native Windows task dialog
//! (`confirm.rs`) and runs it through `vigil_actions::execute()`. Nothing in this crate builds an
//! `ActionSpec` or calls the engine (a test below checks the sources).
//!
//! The request runs on its own thread, so the UI thread keeps pumping messages while the task
//! dialog is open; the dialog is owned by the main window, which Windows disables meanwhile (the
//! same pattern GPUI uses for its own native dialogs).

use std::sync::Arc;

use futures::channel::{mpsc, oneshot};
use vigil_core::confirm::{self, Answer, Prompt};
use vigil_core::requests::Request;
use vigil_core::service::{self, ActionOutcome, Ui};
use vigil_core::state::AppState;
use windows::Win32::Foundation::HWND;

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
    fn owner(&self) -> isize {
        self.owner
    }

    /// Runs on the request's thread: the dialog's modal loop runs there, owned by the main window.
    fn ask(&self, prompt: Prompt) -> Answer {
        confirm::ask(HWND(self.owner as *mut core::ffi::c_void), &prompt)
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

    /// The security boundary: this frontend only sends requests. It never builds an action,
    /// never calls the engine and does not even depend on it.
    #[test]
    fn the_ui_never_builds_or_runs_actions() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
        assert!(
            !manifest.contains("vigil-actions"),
            "vigil-gpui must not depend on the action engine"
        );
        let mut stack = vec![root.join("src")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") || path.ends_with("actions.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                for forbidden in [
                    "vigil_actions",
                    "ActionSpec",
                    "execute_plan",
                    "execute(",
                    "confirm::ask",
                ] {
                    assert!(!text.contains(forbidden), "{} uses {forbidden}", path.display());
                }
            }
        }
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
