//! The commands the UI calls.
//!
//! Reading commands return data. The one command that changes the system is `run_action`: it hands
//! the request to `vigil_core::service::run_action`, which rebuilds the action from the request
//! (requests.rs), confirms it in a native dialog (confirm.rs) and runs it through the action engine,
//! which journals it. The state they share is `vigil_core::state::AppState`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde::Serialize;
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use vigil_actions::{ActionSpec, QuarantineEntry};
use vigil_core::confirm::{self, Answer, Prompt};
use vigil_core::planner;
use vigil_core::requests::{self, Request};
use vigil_core::secrets;
use vigil_core::service::{self, ActionOutcome, record_json};
use vigil_core::settings::{self, Stored, View};
pub use vigil_core::state::AppState;
use vigil_core::state::{Inner, Pending};
use vigil_maint::hardware::Hardware;
use vigil_maint::insights::Insight;
use vigil_maint::storage::{self, CleanupTarget, SpaceScan, Volume};
use vigil_maint::tuning::TuningState;

type CmdResult<T> = Result<T, String>;

/// Runs slow work off the async runtime (and off the UI thread).
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|e| e.to_string())
}

fn state(app: &AppHandle) -> State<'_, AppState> {
    app.state::<AppState>()
}

#[derive(Serialize, Clone)]
struct Progress<'a> {
    phase: &'a str,
    text: String,
}

// ------------------------------------------------------------------------------------ reports

#[tauri::command]
pub fn report_current(state: State<'_, AppState>) -> Option<Value> {
    state.lock().analysis_json.clone()
}

#[tauri::command]
pub async fn report_open(app: AppHandle) -> CmdResult<Option<Value>> {
    let dir = state(&app).scans_dir();
    let picked = app
        .dialog()
        .file()
        .set_title("Open report")
        .set_directory(dir)
        .add_filter("Vigil reports", &["json"])
        .blocking_pick_file();
    let Some(path) = picked.and_then(|p| p.into_path().ok()) else {
        return Ok(None);
    };
    let worker = app.clone();
    blocking(move || state(&worker).open_report(&path)).await??;
    Ok(state(&app).lock().analysis_json.clone())
}

#[tauri::command]
pub async fn report_export_html(app: AppHandle) -> CmdResult<Option<String>> {
    let (html, name) = state(&app).report_html()?;
    let mut dialog = app
        .dialog()
        .file()
        .set_title("Export HTML report")
        .set_file_name(name)
        .add_filter("HTML", &["html"]);
    if let Some(docs) = std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("Documents")) {
        dialog = dialog.set_directory(docs);
    }
    let Some(path) = dialog.blocking_save_file().and_then(|p| p.into_path().ok()) else {
        return Ok(None);
    };
    std::fs::write(&path, html).map_err(|e| format!("Could not write the report: {e}"))?;
    Ok(Some(path.display().to_string()))
}

// ------------------------------------------------------------------------------------ scans

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewOffer {
    pending: usize,
    destination: Option<String>,
    /// The data stays on this computer (a local model).
    local: bool,
    problem: Option<String>,
    redact: bool,
    preview: Vec<Value>,
}

#[tauri::command]
pub async fn scan_collect(app: AppHandle, days: u32, virustotal: bool) -> CmdResult<ReviewOffer> {
    let settings = {
        let st = state(&app);
        let mut inner = st.lock();
        if inner.pending.is_some() {
            return Err("A scan is already waiting for the AI review decision.".into());
        }
        inner.settings.days = days.clamp(1, 365);
        inner.settings.virustotal = virustotal;
        let _ = inner.settings.save(&st.root.join("settings.json"));
        inner.settings.clone()
    };
    let (vt_key, base) = {
        let st = state(&app);
        let vt_key = if settings.virustotal {
            secrets::lookup(&*st.secrets, "virustotal")
        } else {
            None
        };
        (vt_key, vigil_scan::pipeline::scan_base(&st.scans_dir()))
    };
    let cancel = state(&app).scan_cancel.clone();
    cancel.store(false, Ordering::Relaxed);
    let emitter = app.clone();
    let days = settings.days;
    let redact = settings.ai.redact;
    let inventory = base.with_file_name(format!("{}-inventory.json", file_name(&base)));
    let collected = blocking(move || {
        let progress = |text: &str| {
            let _ = emitter.emit(
                "scan",
                Progress {
                    phase: "collect",
                    text: text.to_string(),
                },
            );
        };
        if settings.virustotal && vt_key.is_none() {
            progress(&vigil_i18n::tr!(
                "VirusTotal: no API key in Settings; the scan continues without it"
            ));
        }
        let result = vigil_scan::collect_and_analyze(days, vt_key.as_deref(), &progress, &cancel);
        let (raw, analysis) = result.map_err(|e| e.to_string())?;
        if let Err(error) = std::fs::write(&inventory, raw.to_string()) {
            progress(&vigil_i18n::tr!("The raw inventory could not be saved ({0})", error));
        }
        let (provider, problem) = match pick_ai(&emitter, &settings) {
            Ok(provider) => (Some(provider), None),
            Err(problem) => (None, Some(problem)),
        };
        Ok::<_, String>((analysis, provider, problem))
    })
    .await??;
    let (analysis, provider, problem) = collected;
    let meta = |key: &str| analysis.meta.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    let redactor = vigil_scan::privacy::Redactor::new(&meta("user"), &meta("computer"), redact);
    let pending_items: Vec<_> = analysis.items.iter().filter(|i| !i.trusted).collect();
    let preview: Vec<Value> = pending_items
        .iter()
        .map(|i| redactor.apply(&vigil_scan::ai::item_payload(i)))
        .collect();
    let offer = ReviewOffer {
        pending: pending_items.len(),
        destination: provider.as_ref().map(|p| p.destination.clone()),
        local: provider.as_ref().is_some_and(|p| p.local),
        problem: problem.clone(),
        redact,
        preview,
    };
    let pending = offer.pending;
    state(&app).lock().pending = Some(Pending {
        analysis,
        base,
        provider,
        problem,
        pending,
    });
    Ok(offer)
}

/// The provider the settings ask for (the error says why there is none). Blocking: it may start
/// a CLI to read its options or ask a local server for its models.
pub(crate) fn pick_ai(app: &AppHandle, settings: &Stored) -> Result<vigil_scan::ai::Provider, String> {
    state(app).pick_ai(settings)
}

fn file_name(path: &Path) -> String {
    path.file_name().and_then(|n| n.to_str()).unwrap_or("scan").to_string()
}

/// Finishes the scan: with the AI review (`review`) or without it. `selected`: the user chose the
/// AI review in the scan dialog (false: it was not selected, so skipping is not "you skipped").
#[tauri::command]
pub async fn scan_finish(app: AppHandle, review: bool, selected: Option<bool>) -> CmdResult<Value> {
    let (mut pending, redact) = {
        let st = state(&app);
        let mut inner = st.lock();
        let pending = inner.pending.take().ok_or("There is no scan to finish.")?;
        (pending, inner.settings.ai.redact)
    };
    let emitter = app.clone();
    let finished = blocking(move || {
        let progress = |text: &str| {
            let _ = emitter.emit(
                "scan",
                Progress {
                    phase: "ai",
                    text: text.to_string(),
                },
            );
        };
        let reason = match (&pending.provider, review) {
            (Some(provider), true) if pending.pending > 0 => {
                progress(&format!(
                    "Sending {} items to {}",
                    pending.pending, provider.destination
                ));
                let sent = pending
                    .base
                    .with_file_name(format!("{}-sent-to-ai.json", file_name(&pending.base)));
                match vigil_scan::ai::ai_analyze(&mut pending.analysis, provider, redact, &progress, Some(&sent)) {
                    Ok(()) => None,
                    Err(error) => Some(vigil_i18n::tr!(
                        "the AI review failed ({0})",
                        truncate(&error.to_string(), 200)
                    )),
                }
            }
            (None, _) => Some(vigil_i18n::tr!(
                "the AI could not be reached ({0})",
                pending.problem.clone().unwrap_or_default()
            )),
            (Some(_), _) if pending.pending == 0 => Some(vigil_i18n::tr!("there were no items to send to the AI")),
            _ if selected == Some(false) => Some(vigil_i18n::tr!("the AI review was not selected for this scan")),
            _ => Some(vigil_i18n::tr!("you skipped the AI review")),
        };
        if let Some(reason) = reason {
            let mut ai = serde_json::Map::new();
            ai.insert("reason".into(), json!(reason));
            pending.analysis.ai = ai;
        }
        // What changed since the previous scan in the same folder travels with the report.
        vigil_scan::pipeline::attach_changes(&mut pending.analysis, &pending.base);
        let saved = vigil_scan::pipeline::save_report(&pending.analysis, &pending.base, false);
        let path = match saved {
            Ok((json, _)) => Some(json),
            Err(error) => {
                progress(&format!("The scan finished but could not be saved: {error}"));
                None
            }
        };
        (pending.analysis, path)
    })
    .await?;
    let (analysis, path) = finished;
    let st = state(&app);
    st.set_analysis(analysis, path);
    let _ = app.emit(
        "scan",
        Progress {
            phase: "done",
            text: "Scan saved".into(),
        },
    );
    st.lock()
        .analysis_json
        .clone()
        .ok_or_else(|| "The report could not be read back.".into())
}

fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

// ------------------------------------------------------------------------------------ findings

#[tauri::command]
pub fn plan_actions(state: State<'_, AppState>, item_id: String) -> Vec<ActionSpec> {
    let inner = state.lock();
    let analysis = inner.analysis_json.as_ref();
    requests::find_item(analysis, &item_id)
        .map(|item| planner::plan_actions(item, requests::scan_started(analysis)))
        .unwrap_or_default()
}

fn item_key(item: &Value) -> String {
    let text = |key: &str| item.get(key).and_then(Value::as_str).unwrap_or("");
    settings::item_key(text("kind"), Some(text("path")), text("title"))
}

fn ignored_ids(inner: &Inner) -> Vec<String> {
    let items = inner
        .analysis_json
        .as_ref()
        .and_then(|a| a.get("items"))
        .and_then(Value::as_array);
    items
        .map(|items| {
            items
                .iter()
                .filter(|i| inner.ignored.contains(&item_key(i)))
                .filter_map(|i| i.get("id").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[tauri::command]
pub fn ignored_list(state: State<'_, AppState>) -> Vec<String> {
    ignored_ids(&state.lock())
}

#[tauri::command]
pub fn ignored_set(state: State<'_, AppState>, item_id: String, value: bool) -> CmdResult<Vec<String>> {
    let mut inner = state.lock();
    let item = requests::find_item(inner.analysis_json.as_ref(), &item_id)
        .cloned()
        .ok_or("Unknown finding.")?;
    let text = |key: &str| item.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    inner
        .ignored
        .set(item_key(&item), &text("title"), &text("kind"), value)?;
    Ok(ignored_ids(&inner))
}

// ------------------------------------------------------------------------------------ history

#[tauri::command]
pub async fn journal(app: AppHandle) -> CmdResult<Vec<Value>> {
    blocking(move || {
        let st = state(&app);
        let mut records: Vec<Value> = st.store.records().iter().map(record_json).collect();
        records.reverse();
        records
    })
    .await
}

#[tauri::command]
pub async fn quarantine_list(app: AppHandle) -> CmdResult<Vec<QuarantineEntry>> {
    blocking(move || state(&app).store.quarantined()).await
}

// ------------------------------------------------------------------------------------ maintenance

#[tauri::command]
pub async fn volumes() -> CmdResult<Vec<Volume>> {
    blocking(storage::volumes).await
}

#[tauri::command]
pub async fn cleanup_measure(app: AppHandle) -> CmdResult<Vec<CleanupTarget>> {
    let emitter = app.clone();
    let targets = blocking(move || {
        let mut targets = storage::cleanup_targets(None);
        let progress = |text: &str| {
            let _ = emitter.emit("cleanup", json!({"text": text}));
        };
        storage::measure(&mut targets, &progress, &storage::NeverCancel);
        targets
    })
    .await?;
    state(&app).lock().cleanup = targets.clone();
    Ok(targets)
}

#[tauri::command]
pub async fn space_scan(app: AppHandle, root: String) -> CmdResult<SpaceScan> {
    let path = PathBuf::from(&root);
    if !path.is_absolute() || !path.is_dir() {
        return Err("Choose a drive or a folder that exists.".into());
    }
    let cancel = state(&app).space_cancel.clone();
    cancel.store(false, Ordering::Relaxed);
    let emitter = app.clone();
    let scan = blocking(move || {
        let progress = |text: &str| {
            let _ = emitter.emit("space", json!({"text": text}));
        };
        storage::scan_space(&path, &progress, &*cancel, 500, 300)
    })
    .await?;
    state(&app).lock().space_files = scan.largest_files.iter().map(|f| (f.path.clone(), f.size)).collect();
    Ok(scan)
}

#[tauri::command]
pub fn space_cancel(state: State<'_, AppState>) {
    state.space_cancel.store(true, Ordering::Relaxed);
}

#[tauri::command]
pub async fn choose_folder(app: AppHandle) -> Option<String> {
    app.dialog()
        .file()
        .set_title("Choose a folder")
        .blocking_pick_folder()
        .map(|p| p.to_string())
}

#[tauri::command]
pub async fn choose_exe(app: AppHandle) -> Option<String> {
    let mut dialog = app
        .dialog()
        .file()
        .set_title("Choose an app")
        .add_filter("Programs", &["exe"]);
    if let Some(dir) = std::env::var_os("ProgramFiles") {
        dialog = dialog.set_directory(PathBuf::from(dir));
    }
    dialog.blocking_pick_file().map(|p| p.to_string())
}

/// Run new task's Browse button. The path only fills the dialog's text box: running it is a
/// separate request, checked and confirmed like any other.
#[tauri::command]
pub async fn choose_program(app: AppHandle) -> Option<String> {
    let mut dialog = app
        .dialog()
        .file()
        .set_title(vigil_i18n::tr!("Choose a program to run"))
        .add_filter(vigil_i18n::tr!("Programs"), &vigil_actions::run::RUNNABLE);
    if let Some(dir) = std::env::var_os("ProgramFiles") {
        dialog = dialog.set_directory(PathBuf::from(dir));
    }
    dialog.blocking_pick_file().map(|p| p.to_string())
}

/// The logical processors of this computer and the ones a process may use now (read-only).
#[derive(Serialize)]
pub struct Affinity {
    processors: Vec<vigil_sys::cpusets::LogicalProcessor>,
    allowed: Vec<u32>,
}

#[tauri::command]
pub async fn process_affinity(pid: u32, created_ms: i64) -> CmdResult<Affinity> {
    blocking(move || {
        let started = vigil_actions::Proc::get(i64::from(pid))
            .ok()
            .and_then(|p| p.create_time())
            .ok_or(vigil_i18n::tr!("The process has exited."))?;
        if created_ms != 0 && (started * 1000.0 - created_ms as f64).abs() > 1000.0 {
            return Err(vigil_i18n::tr!("The process has exited."));
        }
        let allowed = vigil_sys::cpusets::process_processors(pid).map_err(|e| e.to_string())?;
        Ok(Affinity {
            processors: vigil_sys::cpusets::logical_processors(),
            allowed,
        })
    })
    .await?
}

async fn cached_hardware(app: &AppHandle, force: bool) -> CmdResult<Hardware> {
    let worker = app.clone();
    blocking(move || state(&worker).hardware(force)).await?
}

#[tauri::command]
pub async fn hardware(app: AppHandle, force: Option<bool>) -> CmdResult<Hardware> {
    cached_hardware(&app, force.unwrap_or(false)).await
}

#[tauri::command]
pub async fn insights(app: AppHandle) -> CmdResult<Vec<Insight>> {
    let hw = cached_hardware(&app, false).await?;
    blocking(move || {
        let tuning = vigil_maint::tuning::tuning_state();
        let volumes = storage::volumes();
        vigil_maint::insights::collect(&hw, Some(&tuning), &volumes, uptime_seconds(), None)
    })
    .await
}

fn uptime_seconds() -> f64 {
    // SAFETY: GetTickCount64 has no preconditions.
    (unsafe { windows::Win32::System::SystemInformation::GetTickCount64() }) as f64 / 1000.0
}

#[tauri::command]
pub async fn tuning_state() -> CmdResult<TuningState> {
    blocking(vigil_maint::tuning::tuning_state).await
}

// ------------------------------------------------------------------------------------ settings

#[tauri::command]
pub fn settings_get(state: State<'_, AppState>) -> View {
    let stored = secrets::stored(&*state.secrets);
    state.lock().settings.view(stored)
}

/// Saves the settings. `secrets`: a value stores that API key, "" removes it, null or missing keeps it.
#[tauri::command]
pub fn settings_set(
    state: State<'_, AppState>,
    watcher: State<'_, Arc<crate::watch::Watcher>>,
    settings: View,
    secrets: Option<std::collections::HashMap<String, Option<String>>>,
) -> CmdResult<View> {
    for (id, value) in secrets.unwrap_or_default() {
        match value {
            Some(value) if value.trim().is_empty() => state.secrets.delete(&id)?,
            Some(value) => state.secrets.set(&id, &value)?,
            None => {}
        }
    }
    let mut inner = state.lock();
    inner.settings.apply(&settings)?;
    inner.settings.save(&state.root.join("settings.json"))?;
    let language = vigil_i18n::set_language(&inner.settings.language);
    // The copy of Vigil that watches from the tray (its own settings file when it runs without
    // administrator rights) writes its alerts and notifications in the language chosen here.
    watcher.set_language(language);
    let stored = secrets::stored(&*state.secrets);
    Ok(inner.settings.view(stored))
}

#[derive(Serialize)]
pub struct AiStatus {
    provider: String,
    destination: Option<String>,
    /// The data stays on this computer.
    local: bool,
    problem: Option<String>,
}

#[tauri::command]
pub async fn ai_status(app: AppHandle) -> CmdResult<AiStatus> {
    let settings = state(&app).lock().settings.clone();
    let worker = app.clone();
    blocking(move || match pick_ai(&worker, &settings) {
        Ok(provider) => AiStatus {
            provider: provider.id.clone(),
            local: provider.local,
            destination: Some(provider.destination),
            problem: None,
        },
        Err(problem) => AiStatus {
            provider: settings.ai.provider.clone(),
            destination: None,
            local: false,
            problem: Some(problem),
        },
    })
    .await
}

/// One AI provider for the settings page.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiProviderView {
    id: &'static str,
    name: String,
    kind: &'static str,
    secret: Option<&'static str>,
    needs_endpoint: bool,
    default_endpoint: Option<&'static str>,
    default_model: &'static str,
    suggested_models: Vec<&'static str>,
    supports_effort: bool,
    available: bool,
    note: String,
}

/// Every AI provider with its availability on this computer (it looks for the CLIs on PATH and
/// asks a local model server whether it answers; nothing is sent to any AI).
#[tauri::command]
pub async fn ai_providers(app: AppHandle) -> CmdResult<Vec<AiProviderView>> {
    let config = state(&app).lock().settings.ai.config();
    let worker = app.clone();
    blocking(move || {
        let st = state(&worker);
        let keys = |id: &str| secrets::lookup(&*st.secrets, id);
        let probe = vigil_scan::ai::SystemProbe { keys: &keys };
        vigil_scan::ai::statuses(&config, &probe)
            .into_iter()
            .map(|status| AiProviderView {
                id: status.info.id,
                name: vigil_scan::ai::display_name(status.info),
                kind: status.info.kind,
                secret: status.info.secret,
                needs_endpoint: status.info.needs_endpoint,
                default_endpoint: status.info.default_endpoint,
                default_model: status.info.default_model,
                suggested_models: status.info.suggested_models.to_vec(),
                supports_effort: status.info.supports_effort,
                available: status.available,
                note: status.note,
            })
            .collect()
    })
    .await
}

/// The models an API standard offers at an endpoint (on a local Ollama server, only the models installed on
/// this computer: its cloud models are left out).
#[tauri::command]
pub async fn ai_models(app: AppHandle, provider: String, endpoint: Option<String>) -> CmdResult<Vec<String>> {
    blocking(move || {
        let st = state(&app);
        let keys = |id: &str| secrets::lookup(&*st.secrets, id);
        vigil_scan::ai::list_models(&provider, endpoint.as_deref().unwrap_or(""), &keys)
    })
    .await?
}

// ------------------------------------------------------------------------------------ actions

/// The one command that changes the system. The whole path (checks, native confirmation, the
/// action engine) is `vigil_core::service::run_action`; this only runs it off the async runtime.
#[tauri::command]
pub async fn run_action(app: AppHandle, window: WebviewWindow, request: Request) -> CmdResult<ActionOutcome> {
    let hwnd = window.hwnd().map(|h| h.0 as isize).unwrap_or(0);
    let worker = app.clone();
    blocking(move || {
        let ui = TauriUi { app: &worker, hwnd };
        service::run_action(&state(&worker), &request, &ui)
    })
    .await?
}

/// Asks on the main thread (the dialog's owner window lives there) and waits for the answer.
/// Blocking: call it from a worker thread.
pub(crate) fn ask_on_main(app: &AppHandle, hwnd: isize, prompt: Prompt) -> Answer {
    let (tx, rx) = std::sync::mpsc::channel();
    let sent = app.run_on_main_thread(move || {
        let parent = windows::Win32::Foundation::HWND(hwnd as *mut core::ffi::c_void);
        let _ = tx.send(confirm::ask(parent, &prompt));
    });
    if sent.is_err() {
        return Answer::Cancel;
    }
    rx.recv().unwrap_or(Answer::Cancel)
}

/// The Tauri side of the action path: the dialog on the main thread, progress as events.
struct TauriUi<'a> {
    app: &'a AppHandle,
    hwnd: isize,
}

impl service::Ui for TauriUi<'_> {
    fn owner(&self) -> isize {
        self.hwnd
    }

    fn ask(&self, prompt: Prompt) -> Answer {
        ask_on_main(self.app, self.hwnd, prompt)
    }

    fn progress(&self, text: &str) {
        let _ = self.app.emit("action", json!({"text": text}));
    }
}

// ------------------------------------------------------------------------------------ services

/// A service for the Services page: what Windows reports, plus whether Vigil refuses to change it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceView {
    #[serde(flatten)]
    service: vigil_sys::services::Service,
    /// An essential Windows service, or a Windows component (its binary or service DLL lives in the
    /// Windows folder): the action engine refuses to change it, so the page does not offer it.
    protected: bool,
}

/// Every Win32 service (read-only).
#[tauri::command]
pub async fn services_list() -> CmdResult<Vec<ServiceView>> {
    let services = blocking(|| vigil_sys::services::list().map_err(|e| e.to_string())).await??;
    Ok(services
        .into_iter()
        .map(|service| ServiceView {
            protected: requests::protected_service(&service),
            service,
        })
        .collect())
}

// ------------------------------------------------------------------------------------ startup apps

/// The programs Windows starts at sign-in, read now (read-only).
#[tauri::command]
pub async fn startup_list() -> CmdResult<Vec<vigil_sys::startup::StartupEntry>> {
    blocking(vigil_sys::startup::list).await
}

pub use vigil_core::inspect::StartupSignature;

/// The Authenticode signatures of startup programs (read-only). Only programs of the live startup
/// list are checked, a few at a time; results are kept for the session.
#[tauri::command]
pub async fn startup_signatures(paths: Vec<String>) -> CmdResult<std::collections::HashMap<String, StartupSignature>> {
    blocking(move || vigil_core::inspect::startup_signatures(paths)).await
}

// ------------------------------------------------------------------------------------ scheduled tasks

/// Every scheduled task, read now (read-only).
#[tauri::command]
pub async fn tasks_list() -> CmdResult<Vec<vigil_sys::tasks::ScheduledTask>> {
    blocking(vigil_core::inspect::scheduled_tasks).await?
}

// ------------------------------------------------------------------------------------ process inspector

/// Program icons for the process list, as PNG data URLs keyed by the path asked for (paths without
/// an icon are left out). Read-only; each executable is read once and cached.
#[tauri::command]
pub async fn process_icons(paths: Vec<String>) -> CmdResult<std::collections::HashMap<String, String>> {
    blocking(move || {
        paths
            .into_iter()
            .take(512)
            .filter(|path| {
                let file = Path::new(path);
                // Executables, and the .ico files installers name as a program's icon.
                file.is_absolute()
                    && file
                        .extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("exe") || e.eq_ignore_ascii_case("ico"))
            })
            .filter_map(|path| vigil_sys::apps::icon_data_url(&path).map(|url| (path, url)))
            .collect()
    })
    .await
}

/// Modules and hosted services of one process (read-only).
#[tauri::command]
pub async fn process_details(pid: u32) -> CmdResult<vigil_core::inspect::ProcessDetails> {
    blocking(move || vigil_core::inspect::process_details(pid)).await
}
