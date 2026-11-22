//! The Reliability page's command. Reading the event logs and writing the hints live in
//! `vigil_core::reliability`.

use vigil_sys::reliability::{DEFAULT_DAYS, Reliability};

/// The Reliability page's data (read-only).
#[tauri::command]
pub async fn reliability_read(days: Option<u32>) -> Result<Reliability, String> {
    let days = days.unwrap_or(DEFAULT_DAYS);
    tauri::async_runtime::spawn_blocking(move || vigil_core::reliability::load(days))
        .await
        .map_err(|e| e.to_string())?
}
