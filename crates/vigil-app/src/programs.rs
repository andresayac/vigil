//! The Installed programs page's commands. The reading, the signature checks and the request
//! checks live in `vigil_core::programs`.

use std::collections::HashMap;

use vigil_core::programs::{ProgramSignature, ProgramView};

/// Every installed program, read now (read-only).
#[tauri::command]
pub async fn programs_list() -> Result<Vec<ProgramView>, String> {
    tauri::async_runtime::spawn_blocking(vigil_core::programs::list)
        .await
        .map_err(|e| e.to_string())
}

/// The Authenticode signatures of programs' files (read-only). Only files of the live list are
/// checked, in a few PowerShell batches at a time; results are kept for the session.
#[tauri::command]
pub async fn program_signatures(paths: Vec<String>) -> Result<HashMap<String, ProgramSignature>, String> {
    tauri::async_runtime::spawn_blocking(move || vigil_core::programs::signatures(paths))
        .await
        .map_err(|e| e.to_string())
}
