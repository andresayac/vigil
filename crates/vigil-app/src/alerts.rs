//! Commands of the background watch: its state, the alerts and its settings (Overview's Watching
//! card, the Alerts page, the sidebar and Settings). They change Vigil's own files only.

use std::sync::Arc;

use tauri::{AppHandle, Emitter, Manager, State};

use crate::watch::{Alert, Status, WatchSettings, Watcher};

type CmdResult<T> = Result<T, String>;

fn changed(app: &AppHandle, watcher: &Watcher) -> Status {
    let status = watcher.status();
    let _ = app.emit("watch", status.clone());
    crate::tray::refresh(app);
    status
}

#[tauri::command]
pub fn watch_status(watcher: State<'_, Arc<Watcher>>) -> Status {
    watcher.status()
}

/// Every alert kept, newest first.
#[tauri::command]
pub fn watch_alerts(watcher: State<'_, Arc<Watcher>>) -> Vec<Alert> {
    watcher.store.load().alerts
}

/// Marks alerts as read (`ids` missing: all of them).
#[tauri::command]
pub fn watch_mark_read(app: AppHandle, ids: Option<Vec<u64>>) -> CmdResult<Status> {
    let watcher = app.state::<Arc<Watcher>>();
    watcher.store.update(|file| {
        for alert in &mut file.alerts {
            if ids.as_ref().is_none_or(|ids| ids.contains(&alert.id)) {
                alert.read = true;
            }
        }
    })?;
    Ok(changed(&app, &watcher))
}

/// Deletes every alert (what is watched and its baseline stay).
#[tauri::command]
pub fn watch_clear(app: AppHandle) -> CmdResult<Status> {
    let watcher = app.state::<Arc<Watcher>>();
    watcher.store.update(|file| file.alerts.clear())?;
    Ok(changed(&app, &watcher))
}

#[tauri::command]
pub fn watch_set_watching(app: AppHandle, on: bool) -> Status {
    if crate::tray::set_watching(&app, Some(on)) {
        app.state::<Arc<Watcher>>().check_soon();
    }
    app.state::<Arc<Watcher>>().status()
}

/// Pauses notifications for an hour (`pause` true) or resumes them.
#[tauri::command]
pub fn watch_pause_notifications(app: AppHandle, pause: bool) -> Status {
    crate::tray::pause_notifications(&app, pause);
    app.state::<Arc<Watcher>>().status()
}

/// Opens the report of the last automatic scan and makes it the current report (`None`: there is
/// none). The path comes from the watch's own state and is checked first: the right name, directly
/// in this copy's scans folder or the user's, a plain file in a plain folder.
#[tauri::command]
pub async fn watch_open_auto_report(app: AppHandle) -> CmdResult<Option<serde_json::Value>> {
    let report = app.state::<Arc<Watcher>>().store.load().auto_scan.report;
    if report.is_empty() {
        return Ok(None);
    }
    let path = std::path::PathBuf::from(report);
    let own = crate::commands::scans_folder(&app);
    let mut folders = vec![own.clone()];
    if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        folders.push(std::path::PathBuf::from(local).join("Vigil").join("scans"));
    }
    crate::autoscan::check_report_path(&path, &folders)?;
    // An elevated copy reads a report the standard-user tray copy wrote in a folder any program of
    // this user can write to: it may look, but nothing is planned from it (a planted report could
    // mark a security product "remove"). Its own folder (Administrators only) is trusted.
    let elevated = app.state::<crate::commands::AppState>().admin;
    let trusted = !elevated || crate::autoscan::inside(&path, &own);
    crate::commands::open_report_file(&app, path, trusted).await
}

/// Saves the Background watch settings.
#[tauri::command]
pub fn watch_configure(app: AppHandle, settings: WatchSettings) -> CmdResult<Status> {
    let watcher = app.state::<Arc<Watcher>>();
    let resumed = watcher.store.update(|file| {
        let resumed = settings.watching && !file.settings.watching;
        file.settings = WatchSettings {
            tray_notice_shown: file.settings.tray_notice_shown,
            ..settings
        };
        resumed
    })?;
    if resumed {
        watcher.check_soon();
    }
    Ok(changed(&app, &watcher))
}
