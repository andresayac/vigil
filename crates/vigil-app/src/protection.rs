//! The Protection page's command and the events of the scans Vigil follows. Reading Defender and
//! checking requests live in `vigil_core::protection`.

use tauri::{AppHandle, Emitter};
use vigil_core::protection::ProtectionView;

/// Microsoft Defender's state (read-only); changes go through run_action ({ kind: "defender" }).
#[tauri::command]
pub async fn protection_state() -> Result<ProtectionView, String> {
    tauri::async_runtime::spawn_blocking(vigil_core::protection::view)
        .await
        .map_err(|e| e.to_string())
}

/// Follows the scans Vigil starts and sends each step to the page (`defender-scan` events).
pub fn start_monitor(app: AppHandle) {
    vigil_core::protection::start_monitor(move |event| {
        let _ = app.emit("defender-scan", event);
    });
}
