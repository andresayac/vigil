//! The Security posture page's command. Reading the posture and checking requests live in
//! `vigil_core::posture`.

use vigil_sys::posture::Posture;

/// The security posture (read-only); changes go through run_action ({ kind: "posture" }).
#[tauri::command]
pub async fn posture_state() -> Result<Posture, String> {
    tauri::async_runtime::spawn_blocking(vigil_core::posture::read)
        .await
        .map_err(|e| e.to_string())
}
