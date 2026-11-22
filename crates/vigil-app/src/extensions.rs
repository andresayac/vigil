//! The Browser extensions page's commands. Reading the browsers and checking requests live in
//! `vigil_core::extensions`.

use std::collections::HashMap;

use vigil_scan::browsers::BrowserData;

/// Every browser extension and browser policy, read now (read-only).
#[tauri::command]
pub async fn extensions_list() -> Result<BrowserData, String> {
    tauri::async_runtime::spawn_blocking(vigil_core::extensions::list)
        .await
        .map_err(|e| e.to_string())
}

/// The icons (PNG data URLs) of extensions of the list read last, by key. Only the icon files that
/// list named are read; keys without an icon are left out.
#[tauri::command]
pub async fn extension_icons(keys: Vec<String>) -> Result<HashMap<String, String>, String> {
    tauri::async_runtime::spawn_blocking(move || vigil_core::extensions::icons(keys))
        .await
        .map_err(|e| e.to_string())
}
