//! The Accounts and sign-ins page's command. Reading the accounts and checking requests live in
//! `vigil_core::accounts`.

use tauri::{AppHandle, Manager};
use vigil_core::accounts::AccountsView;
use vigil_core::state::AppState;

/// The page's data (read-only): accounts, groups, sessions and the last `days` days of sign-ins.
#[tauri::command]
pub async fn accounts_read(app: AppHandle, days: Option<u32>) -> Result<AccountsView, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let records = app.state::<AppState>().store.records();
        vigil_core::accounts::read(days, &records)
    })
    .await
    .map_err(|e| e.to_string())
}
