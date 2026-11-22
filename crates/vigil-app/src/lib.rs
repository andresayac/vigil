//! The Vigil desktop app: Tauri window, commands for the UI and the live sampler.
//!
//! The web UI only displays data and asks for things. Everything that touches the system runs
//! in Rust: a request from the page is rebuilt into an action from Rust's own state, shown in a
//! native confirmation dialog and run by the action engine (`vigil_core::service`), so text coming
//! from the inspected computer (process names, command lines) can never trigger anything.

mod accounts;
mod alerts;
mod commands;
mod extensions;
mod firewall;
mod live;
mod notify;
mod posture;
mod programs;
mod protection;
mod reliability;
mod tray;
mod userdir;
mod watch;

// The frontend-independent modules, under the names the rest of the app uses.
use vigil_core::{autostart, confirm, storage_ops};

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
    /// Started with `--tray` (at sign-in): the window stays hidden until opened from the tray.
    start_hidden: bool,
}

#[tauri::command]
async fn app_info(app: AppHandle) -> AppInfo {
    let (cpu_name, adapters) = tauri::async_runtime::spawn_blocking(|| (metrics::cpu_name(), metrics::adapters()))
        .await
        .unwrap_or_default();
    let state = app.state::<vigil_core::state::AppState>();
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        elevated: elevation::is_elevated(),
        cpu_name,
        adapters,
        data_dir: state.root.display().to_string(),
        data_warning: state.warning.clone(),
        language: vigil_i18n::language().to_string(),
        start_hidden: started_in_tray(),
    }
}

/// `--tray`: start hidden, watching from the tray.
fn started_in_tray() -> bool {
    std::env::args().skip(1).any(|a| a == "--tray")
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
    vigil_core::scan_cli(args)
}

/// The read-only commands `vigil list`, `vigil ports`, `vigil services`, `vigil reliability` and
/// `vigil --help`;
/// `None` when `command` is not one of them.
pub fn tool_cli(command: &str, args: &[String]) -> Option<i32> {
    vigil_core::tool_cli(command, args)
}

pub fn run() {
    let state = match vigil_core::state::AppState::new() {
        Ok(state) => state,
        Err(error) => {
            let parent = windows::Win32::Foundation::HWND(std::ptr::null_mut());
            confirm::tell(parent, "Vigil could not prepare its data folder", &error);
            std::process::exit(1);
        }
    };
    storage_ops::register_all();
    autostart::register_all();
    // One copy watches and owns the tray icon. Started at sign-in while another copy already
    // watches: nothing to do.
    let owner = watch::claim_watch();
    let hidden = started_in_tray();
    if hidden && !owner {
        return;
    }
    let store = watch::Store::in_profile().unwrap_or_else(|| watch::Store::new(state.root.join("watch")));
    let watcher = std::sync::Arc::new(watch::Watcher::new(store, state.admin, owner));
    // A state saved before a language was ever chosen takes this copy's language.
    watcher.adopt_language(vigil_i18n::language());
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .manage(std::sync::Arc::clone(&watcher))
        .setup(move |app| {
            let live = live::Live::start(app.handle().clone(), !hidden);
            app.manage(live);
            if owner {
                tray::install(app.handle());
            }
            watcher.start(app.handle().clone());
            protection::start_monitor(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event
                && tray::close_to_tray(window.app_handle())
            {
                api.prevent_close();
            }
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
            commands::tasks_list,
            firewall::firewall_list,
            programs::programs_list,
            programs::program_signatures,
            extensions::extensions_list,
            extensions::extension_icons,
            protection::protection_state,
            posture::posture_state,
            reliability::reliability_read,
            accounts::accounts_read,
            commands::ai_providers,
            commands::ai_models,
            alerts::watch_status,
            alerts::watch_alerts,
            alerts::watch_mark_read,
            alerts::watch_clear,
            alerts::watch_set_watching,
            alerts::watch_pause_notifications,
            alerts::watch_configure,
        ])
        .run(tauri::generate_context!());
    if let Err(error) = result {
        eprintln!("Vigil could not start: {error}");
        std::process::exit(1);
    }
}
