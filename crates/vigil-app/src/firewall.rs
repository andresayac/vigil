//! The Firewall rules page's command. The reading, the views and the request checks live in
//! `vigil_core::firewall`.

pub use vigil_core::firewall::FirewallView;

/// The firewall profiles and every rule with its flags (read-only).
#[tauri::command]
pub async fn firewall_list() -> Result<FirewallView, String> {
    tauri::async_runtime::spawn_blocking(vigil_core::firewall::view)
        .await
        .map_err(|e| e.to_string())?
}
