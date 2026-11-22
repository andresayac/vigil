//! "Investigate with AI" for the Tauri window. The investigation itself (consent, the agent with
//! Vigil's read-only tools, validation, the saved record) is `vigil_core::investigate`.

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, WebviewWindow};
use vigil_core::confirm::{Answer, Prompt};
use vigil_core::investigate::InvestigationView;

use crate::commands::ask_on_main;

#[derive(Serialize, Clone)]
struct Progress {
    phase: &'static str,
    text: String,
}

/// The consent dialog on the main thread, a progress event per tool call.
struct Ui<'a> {
    app: &'a AppHandle,
    hwnd: isize,
}

impl vigil_core::service::Ui for Ui<'_> {
    fn owner(&self) -> isize {
        self.hwnd
    }

    fn ask(&self, prompt: Prompt) -> Answer {
        ask_on_main(self.app, self.hwnd, prompt)
    }

    fn progress(&self, text: &str) {
        let _ = self.app.emit(
            "investigate",
            Progress {
                phase: "tool",
                text: text.to_string(),
            },
        );
    }
}

/// Stops a running investigation (between steps; a local agent is ended).
#[tauri::command]
pub fn investigate_cancel() {
    vigil_core::investigate::cancel();
}

/// Investigates one finding of the loaded report with the configured AI agent.
#[tauri::command]
pub async fn investigate_finding(
    app: AppHandle,
    window: WebviewWindow,
    id: String,
) -> Result<Option<InvestigationView>, String> {
    let hwnd = window.hwnd().map(|h| h.0 as isize).unwrap_or(0);
    let worker = app.clone();
    let view = tauri::async_runtime::spawn_blocking(move || {
        let ui = Ui { app: &worker, hwnd };
        let state = worker.state::<vigil_core::state::AppState>();
        vigil_core::investigate::investigate(&state, &id, &ui)
    })
    .await
    .map_err(|e| e.to_string())??;
    if view.is_some() {
        let _ = app.emit(
            "investigate",
            Progress {
                phase: "done",
                text: String::new(),
            },
        );
    }
    Ok(view)
}
