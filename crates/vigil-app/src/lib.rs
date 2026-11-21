//! The Vigil desktop app: Tauri window, commands for the UI and the live sampler.
//!
//! The web UI only displays data and asks for things. Everything that touches the system runs
//! here in Rust: a request from the page is rebuilt into an action from Rust's own state, shown in
//! a native confirmation dialog and run by the action engine, so text coming from the inspected
//! computer (process names, command lines) can never trigger anything.

mod cli;
mod commands;
mod confirm;
mod live;
mod planner;
mod requests;
mod secrets;
mod settings;
mod storage_ops;
mod tools;

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use vigil_sys::{elevation, metrics, net};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: String,
    elevated: bool,
    cpu_name: String,
    adapters: Vec<metrics::GpuAdapter>,
    data_dir: String,
    data_warning: Option<String>,
    /// The language the core writes its texts in ("en", "es", "fr", "pt", "zh").
    language: String,
}

#[tauri::command]
async fn app_info(app: AppHandle) -> AppInfo {
    let (cpu_name, adapters) = tauri::async_runtime::spawn_blocking(|| (metrics::cpu_name(), metrics::adapters()))
        .await
        .unwrap_or_default();
    let state = app.state::<commands::AppState>();
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        elevated: elevation::is_elevated(),
        cpu_name,
        adapters,
        data_dir: state.root.display().to_string(),
        data_warning: state.warning.clone(),
        language: vigil_i18n::language().to_string(),
    }
}

/// The UI calls this when a live page opens (true) and when the last one closes (false).
#[tauri::command]
fn set_live(active: bool, live: State<'_, live::Live>) {
    live.set_active(active);
}

#[tauri::command]
async fn connections() -> Result<Vec<net::Connection>, String> {
    tauri::async_runtime::spawn_blocking(|| net::connections().map_err(|e| e.to_string()))
        .await
        .map_err(|e| e.to_string())?
}

/// Asks Windows for administrator rights; on success the elevated copy starts and this one exits.
#[tauri::command]
fn restart_elevated(app: AppHandle) -> Result<bool, String> {
    match elevation::relaunch_elevated(&["--elevated"]) {
        Ok(true) => {
            app.exit(0);
            Ok(true)
        }
        Ok(false) => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

/// `vigil scan`: the command-line scan. Returns the exit code.
pub fn scan_cli(args: &[String]) -> i32 {
    cli::run(args)
}

/// The read-only commands `vigil list`, `vigil ports`, `vigil services` and `vigil --help`;
/// `None` when `command` is not one of them.
pub fn tool_cli(command: &str, args: &[String]) -> Option<i32> {
    tools::COMMANDS.contains(&command).then(|| tools::run(command, args))
}

pub fn run() {
    let state = match commands::AppState::new() {
        Ok(state) => state,
        Err(error) => {
            let parent = windows::Win32::Foundation::HWND(std::ptr::null_mut());
            confirm::tell(parent, "Vigil could not prepare its data folder", &error);
            std::process::exit(1);
        }
    };
    storage_ops::register_all();
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .setup(|app| {
            let live = live::Live::start(app.handle().clone());
            app.manage(live);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            set_live,
            connections,
            restart_elevated,
            commands::report_current,
            commands::report_open,
            commands::report_export_html,
            commands::scan_collect,
            commands::scan_finish,
            commands::plan_actions,
            commands::ignored_list,
            commands::ignored_set,
            commands::journal,
            commands::quarantine_list,
            commands::volumes,
            commands::cleanup_measure,
            commands::space_scan,
            commands::space_cancel,
            commands::choose_folder,
            commands::choose_exe,
            commands::choose_program,
            commands::process_affinity,
            commands::hardware,
            commands::insights,
            commands::tuning_state,
            commands::settings_get,
            commands::settings_set,
            commands::ai_status,
            commands::run_action,
            commands::process_details,
            commands::process_icons,
            commands::services_list,
            commands::startup_list,
            commands::startup_signatures,
            commands::ai_providers,
            commands::ai_models,
        ])
        .run(tauri::generate_context!());
    if let Err(error) = result {
        eprintln!("Vigil could not start: {error}");
        std::process::exit(1);
    }
}
