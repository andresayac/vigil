//! The commands the UI calls, and the state they share.
//!
//! Reading commands return data. The one command that changes the system is `run_action`: it
//! rebuilds the action from the request (requests.rs), confirms it in a native dialog
//! (confirm.rs) and runs it through the action engine, which journals it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::Serialize;
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use vigil_actions::{ActionSpec, QuarantineEntry, Record, Store};
use vigil_maint::hardware::Hardware;
use vigil_maint::insights::Insight;
use vigil_maint::storage::{self, CleanupTarget, SpaceScan, Volume};
use vigil_maint::tuning::TuningState;
use vigil_scan::model::Analysis;

use crate::confirm::{self, Answer, Prompt};
use crate::planner::{self, spec};
use crate::requests::{self, Context, Plan, Request};
use crate::secrets::{self, CredentialStore, SecretStore};
use crate::settings::{self, Ignored, Stored, View};

type CmdResult<T> = Result<T, String>;

/// A scan whose inventory is analysed and that waits for the decision on the AI review.
struct Pending {
    analysis: Analysis,
    base: PathBuf,
    provider: Option<vigil_scan::ai::Provider>,
    problem: Option<String>,
    pending: usize,
}

#[derive(Default)]
struct Inner {
    settings: Stored,
    ignored: Ignored,
    analysis: Option<Analysis>,
    /// The report in the form the UI and the planner read (render_json).
    analysis_json: Option<Value>,
    report_path: Option<PathBuf>,
    restore_point_done: bool,
    pending: Option<Pending>,
    cleanup: Vec<CleanupTarget>,
    space_files: Vec<(String, u64)>,
    hardware: Option<Hardware>,
}

pub struct AppState {
    pub root: PathBuf,
    pub store: Store,
    pub admin: bool,
    pub warning: Option<String>,
    /// API keys (Windows Credential Manager).
    pub secrets: Box<dyn SecretStore>,
    inner: Mutex<Inner>,
    /// One change at a time.
    acting: AtomicBool,
    scan_cancel: Arc<AtomicBool>,
    space_cancel: Arc<AtomicBool>,
}

impl AppState {
    pub fn new() -> Result<Self, String> {
        let root = vigil_actions::data_dir().map_err(|e| e.to_string())?;
        let store = Store::open(&root).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(root.join("scans")).map_err(|e| format!("{}: {e}", root.display()))?;
        let inner = Inner {
            settings: Stored::load(&root.join("settings.json")),
            ignored: Ignored::load(root.join("ignored.json")),
            ..Default::default()
        };
        // Texts produced by the core (findings, actions, the AI's answers) follow the chosen language.
        vigil_i18n::set_language(&inner.settings.language);
        let state = AppState {
            warning: vigil_actions::data_dir_warning(),
            admin: vigil_actions::is_admin(),
            secrets: Box::new(CredentialStore::default()),
            root,
            store,
            inner: Mutex::new(inner),
            acting: AtomicBool::new(false),
            scan_cancel: Arc::new(AtomicBool::new(false)),
            space_cancel: Arc::new(AtomicBool::new(false)),
        };
        state.load_latest();
        Ok(state)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn scans_dir(&self) -> PathBuf {
        self.root.join("scans")
    }

    /// Opens the newest report that loads.
    fn load_latest(&self) {
        let Ok(entries) = std::fs::read_dir(self.scans_dir()) else {
            return;
        };
        let mut reports: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                name.starts_with("scan-") && name.ends_with("-report.json")
            })
            .collect();
        reports.sort();
        for path in reports.iter().rev() {
            if let Ok(analysis) = vigil_scan::pipeline::load_report(path) {
                self.set_analysis(analysis, Some(path.clone()));
                return;
            }
        }
    }

    fn set_analysis(&self, analysis: Analysis, path: Option<PathBuf>) {
        let json = analysis.to_value();
        let mut inner = self.lock();
        inner.analysis = Some(analysis);
        inner.analysis_json = Some(json);
        inner.report_path = path;
    }

    /// Saves the current report in place (after an action recorded on one of its findings).
    fn save_current(&self) {
        let inner = self.lock();
        let (Some(analysis), Some(path)) = (&inner.analysis, &inner.report_path) else {
            return;
        };
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let Some(stem) = name.strip_suffix("-report.json") else {
            return;
        };
        let base = path.with_file_name(stem);
        let _ = vigil_scan::pipeline::save_report(analysis, &base, false);
    }
}

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
    let loaded = blocking(move || vigil_scan::pipeline::load_report(&path).map(|a| (a, path))).await?;
    let (analysis, path) = loaded.map_err(|e| format!("Could not open the report: {e}"))?;
    let st = state(&app);
    st.set_analysis(analysis, Some(path));
    Ok(st.lock().analysis_json.clone())
}

/// This copy's scans folder (automatic scans save their reports there too).
pub(crate) fn scans_folder(app: &AppHandle) -> PathBuf {
    state(app).scans_dir()
}

/// Opens a report whose path Rust chose and checked itself (the last automatic scan) and makes it
/// the current report.
pub(crate) async fn open_report_file(app: &AppHandle, path: PathBuf) -> CmdResult<Option<Value>> {
    let loaded = blocking(move || vigil_scan::pipeline::load_report(&path).map(|a| (a, path))).await?;
    let (analysis, path) = loaded.map_err(|e| format!("Could not open the report: {e}"))?;
    let st = state(app);
    st.set_analysis(analysis, Some(path));
    Ok(st.lock().analysis_json.clone())
}

#[tauri::command]
pub async fn report_export_html(app: AppHandle) -> CmdResult<Option<String>> {
    let (html, started) = {
        let st = state(&app);
        let inner = st.lock();
        let analysis = inner.analysis.as_ref().ok_or("Run or open a scan first.")?;
        let started = requests::scan_started(inner.analysis_json.as_ref())
            .unwrap_or("")
            .to_string();
        (vigil_scan::report::render_html(analysis), started)
    };
    let stamp: String = started
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'T')
        .take(13)
        .collect();
    let name = format!("scan-{}-report.html", stamp.replace('T', "-"));
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
    let st = state(app);
    let keys = |id: &str| secrets::lookup(&*st.secrets, id);
    let probe = vigil_scan::ai::SystemProbe { keys: &keys };
    vigil_scan::ai::pick_provider(&settings.ai.config(), &probe)
}

/// What an AI investigation needs from the app: the settings, the loaded report (with its file)
/// and the data folder.
pub(crate) fn investigation_inputs(app: &AppHandle) -> (Stored, Option<(Analysis, PathBuf)>, PathBuf) {
    let st = state(app);
    let inner = st.lock();
    let report = match (&inner.analysis, &inner.report_path) {
        (Some(analysis), Some(path)) => Some((analysis.clone(), path.clone())),
        _ => None,
    };
    (inner.settings.clone(), report, st.root.clone())
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

fn record_json(record: &Record) -> Value {
    let mut value = record.as_value();
    if let Value::Object(map) = &mut value {
        map.insert("can_undo".into(), json!(vigil_actions::can_undo(record)));
        map.insert("op_label".into(), json!(vigil_actions::op_label(record.op())));
    }
    value
}

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
    if !force && let Some(hw) = state(app).lock().hardware.clone() {
        return Ok(hw);
    }
    let hw = blocking(vigil_maint::hardware::hardware)
        .await?
        .map_err(|e| e.to_string())?;
    state(app).lock().hardware = Some(hw.clone());
    Ok(hw)
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

#[derive(Serialize, Default)]
pub struct ActionOutcome {
    cancelled: bool,
    records: Vec<Value>,
    message: String,
}

impl ActionOutcome {
    fn cancelled() -> Self {
        ActionOutcome {
            cancelled: true,
            ..Default::default()
        }
    }
    fn message(text: impl Into<String>) -> Self {
        ActionOutcome {
            message: text.into(),
            ..Default::default()
        }
    }
}

/// Ops a standard user may run even when the spec says administrator (they work on own processes).
const USER_OPS: [&str; 4] = [
    "process.suspend",
    "process.resume",
    "defender.scan_file",
    "process.terminate",
];

#[tauri::command]
pub async fn run_action(app: AppHandle, window: WebviewWindow, request: Request) -> CmdResult<ActionOutcome> {
    let st = state(&app);
    let _busy = Busy::take(&st.acting).ok_or_else(|| vigil_i18n::tr!("Wait for the current task to finish."))?;
    let plan = build_plan(&app, &request).await?;
    let hwnd = window.hwnd().map(|h| h.0 as isize).unwrap_or(0);
    match plan {
        Plan::Shell(spec) => run_shell(&app, &spec, hwnd).await,
        Plan::Run { spec, item } => run_spec(&app, spec, item, hwnd).await,
        Plan::Undo(id) => {
            let worker = app.clone();
            let result = blocking(move || vigil_actions::undo(&id, &state(&worker).store)).await?;
            match result {
                Ok(record) => Ok(ActionOutcome::message(
                    record
                        .undo_message()
                        .map_or_else(|| vigil_i18n::tr!("Undone."), str::to_string),
                )),
                Err(error) => Err(error.to_string()),
            }
        }
        Plan::UndoBatch(batch) => {
            let worker = app.clone();
            let results = blocking(move || vigil_actions::undo_batch(&batch, &state(&worker).store)).await?;
            let mut lines: Vec<String> = Vec::new();
            for (record, error) in &results {
                match error {
                    Some(error) => lines.push(format!("{}: {error}", record.label())),
                    None => lines.extend(record.undo_message().map(str::to_string)),
                }
            }
            Ok(ActionOutcome::message(if lines.is_empty() {
                vigil_i18n::tr!("Nothing to undo.")
            } else {
                lines.join("\n")
            }))
        }
        Plan::Restore(id) => quarantine_action(&app, id, false, hwnd).await,
        Plan::Delete(id) => quarantine_action(&app, id, true, hwnd).await,
    }
}

/// Marks the app busy with a change until dropped (Send, unlike a MutexGuard held across awaits).
struct Busy<'a>(&'a AtomicBool);

impl<'a> Busy<'a> {
    fn take(flag: &'a AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Busy(flag))
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

async fn build_plan(app: &AppHandle, request: &Request) -> CmdResult<Plan> {
    if let Request::Defender {
        op,
        setting,
        list,
        value,
    } = request
    {
        let live = crate::protection::read_async().await?;
        return crate::protection::plan(op, setting, list, value, &live);
    }
    if let Request::Posture { op } = request {
        let live = crate::posture::read_async().await?;
        return crate::posture::plan(op, &live);
    }
    match request {
        Request::Extension { op, key, browser } => {
            return crate::extensions::plan_extension(op.clone(), key.clone(), browser.clone()).await;
        }
        Request::BrowserPolicy { op, id } => return crate::extensions::plan_policy(op.clone(), id.clone()).await,
        _ => {}
    }
    let processes = match request {
        Request::Process { .. } => {
            blocking(|| {
                vigil_sys::process::ProcessSampler::new()
                    .and_then(|mut s| s.snapshot())
                    .map_err(|e| e.to_string())
            })
            .await??
        }
        _ => Vec::new(),
    };
    let power_plans: Vec<(String, String, bool)> = match request {
        Request::Tuning { op, .. } if op == "power.plan" => blocking(vigil_maint::tuning::tuning_state)
            .await?
            .power_plans
            .into_iter()
            .map(|p| (p.guid, p.name, p.active))
            .collect(),
        _ => Vec::new(),
    };
    let drive_media: Vec<(String, String)> = match request {
        Request::Tuning { op, .. } if op == "disk.optimize" => cached_hardware(app, false)
            .await?
            .disks
            .iter()
            .flat_map(|d| {
                d.letters
                    .iter()
                    .map(|l| (l.trim_end_matches(':').to_ascii_uppercase(), d.media.clone()))
            })
            .collect(),
        _ => Vec::new(),
    };
    let services = match request {
        Request::Service { .. } => blocking(|| vigil_sys::services::list().map_err(|e| e.to_string())).await??,
        _ => Vec::new(),
    };
    let startup = match request {
        Request::Startup { .. } => blocking(vigil_sys::startup::list).await?,
        _ => Vec::new(),
    };
    let tasks = match request {
        Request::Task { .. } => scheduled_tasks().await?,
        _ => Vec::new(),
    };
    let firewall = match request {
        Request::FirewallRule { .. } => crate::firewall::live_rules().await?,
        _ => Vec::new(),
    };
    let st = state(app);
    let inner = st.lock();
    let cleanup: Vec<Value> = inner
        .cleanup
        .iter()
        .filter_map(|t| serde_json::to_value(t).ok())
        .collect();
    let ctx = Context {
        analysis: inner.analysis_json.as_ref(),
        processes: &processes,
        cleanup: &cleanup,
        services: &services,
        startup: &startup,
        tasks: &tasks,
        firewall: &firewall,
        space_files: &inner.space_files,
        power_plans: &power_plans,
        drive_media: &drive_media,
    };
    requests::build(request, &ctx)
}

/// Asks on the main thread (the dialog's owner window lives there) and waits for the answer.
pub(crate) async fn ask(app: &AppHandle, hwnd: isize, prompt: Prompt) -> Answer {
    let (tx, rx) = std::sync::mpsc::channel();
    let sent = app.run_on_main_thread(move || {
        let parent = windows::Win32::Foundation::HWND(hwnd as *mut core::ffi::c_void);
        let _ = tx.send(confirm::ask(parent, &prompt));
    });
    if sent.is_err() {
        return Answer::Cancel;
    }
    blocking(move || rx.recv().unwrap_or(Answer::Cancel))
        .await
        .unwrap_or(Answer::Cancel)
}

fn prompt_for(spec: &ActionSpec, offer_restore_point: bool) -> Prompt {
    let mut body = spec.explain.clone();
    if spec.steps.is_empty() {
        if !spec.target.is_empty() {
            body.push_str(&format!("\n\n{}", vigil_i18n::tr!("Target: {0}", spec.target)));
        }
    } else {
        body.push_str(&format!("\n\n{}", vigil_i18n::tr!("Steps, in this order:")));
        for (n, step) in spec.steps.iter().enumerate() {
            body.push_str(&format!("\n{}.  {}\n      {}", n + 1, step.label, step.target));
        }
    }
    let undo = if spec.reversible {
        vigil_i18n::tr!("You can undo this from History.")
    } else if spec.steps.is_empty() {
        vigil_i18n::tr!("This cannot be undone.")
    } else {
        vigil_i18n::tr!("Ending processes cannot be undone; the other steps can be undone from History.")
    };
    body.push_str(&format!("\n\n{undo}"));
    let mut warnings: Vec<&str> = Vec::new();
    for warning in std::iter::once(spec.warning.as_str()).chain(spec.steps.iter().map(|s| s.warning.as_str())) {
        if !warning.is_empty() && !warnings.contains(&warning) {
            warnings.push(warning);
        }
    }
    let destructive = spec.destructive || spec.steps.iter().any(|s| s.destructive);
    Prompt {
        title: spec.label.clone(),
        body,
        warning: warnings.join("\n"),
        confirm: if spec.label.chars().count() < 40 {
            spec.label.clone()
        } else {
            vigil_i18n::tr!("Continue")
        },
        destructive,
        restore_point: if offer_restore_point {
            Some(true)
        } else if destructive {
            Some(false)
        } else {
            None
        },
    }
}

async fn run_spec(app: &AppHandle, spec: ActionSpec, item: Option<String>, hwnd: isize) -> CmdResult<ActionOutcome> {
    let st = state(app);
    if spec.admin && !st.admin && !USER_OPS.contains(&spec.op.as_str()) {
        return Err(vigil_i18n::tr!(
            "This action needs administrator rights. Use “Restart as administrator” in the sidebar."
        ));
    }
    let destructive = spec.destructive || spec.steps.iter().any(|s| s.destructive);
    let offer = {
        let inner = st.lock();
        inner.settings.restore_point
            && st.admin
            && destructive
            && !inner.restore_point_done
            && spec.op != "system.restore_point"
    };
    let Answer::Confirm { restore_point } = ask(app, hwnd, prompt_for(&spec, offer)).await else {
        return Ok(ActionOutcome::cancelled());
    };
    let make_point = restore_point && st.admin;
    let title = item
        .as_ref()
        .and_then(|id| {
            let inner = st.lock();
            requests::find_item(inner.analysis_json.as_ref(), id)
                .and_then(|i| i.get("title").and_then(Value::as_str).map(str::to_string))
        })
        .unwrap_or_else(|| spec.target.clone());
    let worker = app.clone();
    let run = spec.clone();
    let records = blocking(move || {
        let st = state(&worker);
        let mut records = Vec::new();
        if make_point {
            let point = spec_restore_point();
            records.push(vigil_actions::execute(&point, &st.store, None, &title));
        }
        let progress = |text: &str| {
            let _ = worker.emit("action", json!({"text": text}));
        };
        records.extend(vigil_actions::execute_plan(&run, &st.store, &title, &progress));
        records
    })
    .await?;
    if make_point && records.first().is_some_and(Record::ok) {
        st.lock().restore_point_done = true;
    }
    if let Some(id) = &item {
        record_on_item(&st, id, &records);
    }
    Ok(ActionOutcome {
        records: records.iter().map(record_json).collect(),
        ..Default::default()
    })
}

fn spec_restore_point() -> ActionSpec {
    let mut point = spec(
        "system.restore_point",
        vigil_i18n::tr!("Create a restore point"),
        "Windows",
        "",
    );
    point.group = "fix".into();
    point.reversible = false;
    point
}

/// Keeps what was done on the finding (shown in its detail) and saves the report.
fn record_on_item(st: &AppState, item_id: &str, records: &[Record]) {
    let stamp = local_minutes();
    {
        let mut inner = st.lock();
        let Some(analysis) = inner.analysis.as_mut() else {
            return;
        };
        let Some(item) = analysis.items.iter_mut().find(|i| i.id == item_id) else {
            return;
        };
        for record in records.iter().filter(|r| r.op() != "system.restore_point") {
            item.actions_taken
                .push(json!({"time": stamp, "label": record.label(), "ok": record.ok(), "message": record.message()}));
        }
        inner.analysis_json = inner.analysis.as_ref().map(Analysis::to_value);
    }
    st.save_current();
}

/// Local time to the minute, ISO 8601 (`2026-01-01T10:05`).
fn local_minutes() -> String {
    // SAFETY: GetLocalTime only writes the returned structure.
    let t = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute
    )
}

async fn run_shell(app: &AppHandle, spec: &ActionSpec, hwnd: isize) -> CmdResult<ActionOutcome> {
    use vigil_actions::shell;
    let text = |key: &str| spec.params.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    let result = match spec.op.as_str() {
        "shell.location" => shell::open_location(&text("path")),
        "shell.properties" => shell::show_properties(&text("path"), hwnd),
        "shell.folder" => shell::open_folder(&text("path")),
        "shell.regedit" => shell::open_regedit(&text("key")),
        "shell.url" => {
            let url = text("url");
            if !requests::allowed_url(&url) {
                return Err(vigil_i18n::tr!("This address is not opened from Vigil."));
            }
            shell::open_url(&url)
        }
        "shell.browser" => shell::open_browser_extensions(&text("browser")),
        "shell.hosts" => shell::edit_hosts(),
        "shell.console" => shell::open_console(&text("name")),
        "shell.tool" => shell::open_tool(&text("name")),
        "signature.verify" => {
            let path = text("path");
            let shown = path.clone();
            let info = blocking(move || vigil_actions::verify_signature(Path::new(&path))).await?;
            let info = info.map_err(|e| e.to_string())?;
            return Ok(ActionOutcome::message(signature_text(&shown, &info)));
        }
        other => return Err(vigil_i18n::tr!("Unknown request: {0}", other)),
    };
    let _ = app;
    result.map_err(|e| e.to_string())?;
    Ok(ActionOutcome::cancelled())
}

fn signature_text(path: &str, info: &vigil_actions::SignatureInfo) -> String {
    use vigil_i18n::{tl, tr};
    let status = info.sig_status.clone().unwrap_or_else(|| tr!("unknown"));
    let mut plain = match status.as_str() {
        "Valid" => tr!("Valid signature"),
        "NotSigned" => tr!("Not signed"),
        "HashMismatch" => tr!("BROKEN: the file was modified after it was signed"),
        "NotTrusted" => tr!("Signed with a certificate Windows does not trust"),
        other => other.to_string(),
    };
    if info.exists == Some(false) {
        plain = tr!("The file no longer exists");
    }
    let mut lines = vec![plain, String::new(), tr!("File: {0}", path)];
    let fields = [
        (&info.signer, tl!("Signer: {0}")),
        (&info.issuer, tl!("Issued by: {0}")),
        (&info.cert_not_after, tl!("Certificate valid until: {0}")),
        (&info.company, tl!("Publisher: {0}")),
        (&info.description, tl!("Description: {0}")),
        (&info.version, tl!("Version: {0}")),
    ];
    for (value, template) in fields {
        if let Some(value) = value.as_ref().filter(|v| !v.is_empty()) {
            lines.push(tr!(template, value));
        }
    }
    lines.join("\n")
}

async fn quarantine_action(app: &AppHandle, id: String, delete: bool, hwnd: isize) -> CmdResult<ActionOutcome> {
    let st = state(app);
    let entry = st
        .store
        .quarantined()
        .into_iter()
        .find(|e| e.id == id)
        .ok_or_else(|| vigil_i18n::tr!("That file is no longer in quarantine."))?;
    let prompt = if delete {
        Prompt {
            title: vigil_i18n::tr!("Delete {0} permanently", entry.name),
            body: vigil_i18n::tr!(
                "The quarantined copy is deleted. It cannot be restored afterwards.\n\nOriginal location: {0}",
                entry.original_path
            ),
            confirm: vigil_i18n::tr!("Delete permanently"),
            destructive: true,
            ..Default::default()
        }
    } else {
        Prompt {
            title: vigil_i18n::tr!("Restore {0}", entry.name),
            body: vigil_i18n::tr!(
                "The file goes back to its original location and can run again.\n\nOriginal location: {0}",
                entry.original_path
            ),
            warning: vigil_i18n::tr!("Restore only files you are sure are safe."),
            confirm: vigil_i18n::tr!("Restore"),
            ..Default::default()
        }
    };
    if ask(app, hwnd, prompt).await == Answer::Cancel {
        return Ok(ActionOutcome::cancelled());
    }
    let worker = app.clone();
    let result = blocking(move || {
        let st = state(&worker);
        if delete {
            vigil_actions::delete_quarantined(&id, &st.store)
        } else {
            vigil_actions::restore_quarantined(&id, &st.store)
        }
    })
    .await?;
    result.map(ActionOutcome::message).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_lists_steps_and_warnings_once() {
        let mut plan = spec("plan.remove", "Remove completely", "Tool", "Ends it.");
        plan.destructive = true;
        plan.reversible = false;
        let mut a = spec("driver.disable", "Disable driver", "driver x", "");
        a.warning = "Careful.".into();
        let b = a.clone();
        plan.steps = vec![a, b];
        let prompt = prompt_for(&plan, true);
        assert!(prompt.body.contains("1.  Disable driver"));
        assert!(prompt.body.contains("Ending processes cannot be undone"));
        assert_eq!(prompt.warning, "Careful.");
        assert!(prompt.destructive);
        assert_eq!(prompt.restore_point, Some(true));
        let plain = prompt_for(&spec("shell.location", "Open", "C:\\x", "Opens."), false);
        assert_eq!(plain.restore_point, None);
        assert!(!plain.destructive);
    }

    #[test]
    fn confirmation_follows_the_language() {
        let mut one = spec(
            "task.disable",
            "Deshabilitar tarea",
            "\\Updater",
            "Deshabilita la tarea.",
        );
        one.reversible = true;
        let spanish = vigil_i18n::with_language("es", || prompt_for(&one, false));
        assert!(spanish.body.contains("Destino: \\Updater"), "{}", spanish.body);
        assert!(
            spanish.body.ends_with("Puede deshacerlo desde Historial."),
            "{}",
            spanish.body
        );
        let mut plan = spec("plan.remove", "A label longer than forty characters, in total", "", "");
        plan.steps = vec![spec("task.disable", "Disable", "\\Updater", "")];
        let chinese = vigil_i18n::with_language("zh", || prompt_for(&plan, false));
        assert!(chinese.body.contains("步骤（按此顺序）："), "{}", chinese.body);
        assert_eq!(chinese.confirm, "继续");
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

/// The signature of a startup program, as the Startup apps page shows it.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StartupSignature {
    /// "valid", "unsigned", "broken", "untrusted", "missing" or "unknown".
    status: String,
    signer: String,
}

/// Checked signatures by lower-case path, for this session (each check starts PowerShell).
static STARTUP_SIGNATURES: std::sync::LazyLock<Mutex<std::collections::HashMap<String, StartupSignature>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

fn startup_signature(path: &str) -> StartupSignature {
    let Ok(info) = vigil_actions::verify_signature(Path::new(path)) else {
        return StartupSignature {
            status: "unknown".into(),
            signer: String::new(),
        };
    };
    let status = match (info.exists, info.sig_status.as_deref()) {
        (Some(false), _) => "missing",
        (_, Some("Valid")) => "valid",
        (_, Some("NotSigned")) => "unsigned",
        (_, Some("HashMismatch")) => "broken",
        (_, Some("NotTrusted")) => "untrusted",
        _ => "unknown",
    };
    StartupSignature {
        status: status.into(),
        signer: info.signer.unwrap_or_default(),
    }
}

/// The Authenticode signatures of startup programs (read-only). Only programs of the live startup
/// list are checked, a few at a time; results are kept for the session.
#[tauri::command]
pub async fn startup_signatures(paths: Vec<String>) -> CmdResult<std::collections::HashMap<String, StartupSignature>> {
    blocking(move || {
        let known: std::collections::HashSet<String> = vigil_sys::startup::list()
            .into_iter()
            .filter(|e| e.exists && !e.host)
            .map(|e| e.executable.to_lowercase())
            .collect();
        let mut out = std::collections::HashMap::new();
        let mut todo: Vec<String> = Vec::new();
        {
            let cache = STARTUP_SIGNATURES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for path in paths.into_iter().take(256) {
                let key = path.to_lowercase();
                if !known.contains(&key) {
                    continue;
                }
                if let Some(found) = cache.get(&key) {
                    out.insert(path, found.clone());
                } else if !todo.iter().any(|p| p.eq_ignore_ascii_case(&path)) {
                    todo.push(path);
                }
            }
        }
        let size = todo.len().div_ceil(4).max(1);
        let checked: Vec<(String, StartupSignature)> = std::thread::scope(|scope| {
            let workers: Vec<_> = todo
                .chunks(size)
                .map(|chunk| {
                    scope.spawn(move || {
                        chunk
                            .iter()
                            .map(|p| (p.clone(), startup_signature(p)))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap_or_default())
                .collect()
        });
        let mut cache = STARTUP_SIGNATURES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (path, signature) in checked {
            if signature.status != "unknown" {
                cache.insert(path.to_lowercase(), signature.clone());
            }
            out.insert(path, signature);
        }
        out
    })
    .await
}

// ------------------------------------------------------------------------------------ scheduled tasks

/// Every scheduled task, read now (read-only).
#[tauri::command]
pub async fn tasks_list() -> CmdResult<Vec<vigil_sys::tasks::ScheduledTask>> {
    scheduled_tasks().await
}

async fn scheduled_tasks() -> CmdResult<Vec<vigil_sys::tasks::ScheduledTask>> {
    let mut tasks = blocking(|| vigil_sys::tasks::list().map_err(|e| e.to_string())).await??;
    for task in &mut tasks {
        task.user_writable = task_writable(task);
    }
    Ok(tasks)
}

/// A program the task runs (or its COM DLL, or the script a Windows host such as PowerShell runs
/// for it) is in a folder a standard user can change.
fn task_writable(task: &vigil_sys::tasks::ScheduledTask) -> bool {
    task.actions.iter().any(|action| {
        !action.program.is_empty()
            && (user_writable(&action.program)
                || (vigil_sys::startup::is_host(&action.program)
                    && argument_paths(&action.arguments).iter().any(|p| user_writable(p))))
    })
}

/// The absolute paths (`C:\...`, `%LOCALAPPDATA%\...`) a command line's arguments name.
fn argument_paths(arguments: &str) -> Vec<String> {
    arguments
        .split(['"', '\'', ' ', '\t', '=', ','])
        .map(|word| {
            let expanded = word
                .strip_prefix('%')
                .and_then(|rest| rest.split_once('%'))
                .and_then(|(name, tail)| std::env::var(name).ok().map(|value| format!("{value}{tail}")));
            expanded.unwrap_or_else(|| word.to_string())
        })
        .filter(|word| {
            let bytes = word.as_bytes();
            bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
        })
        .collect()
}

// ------------------------------------------------------------------------------------ process inspector

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleView {
    name: String,
    path: String,
    size: u64,
    /// Loaded from a folder a standard user can write to (profile, ProgramData, temp): where
    /// side-loaded DLLs usually come from.
    user_writable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessDetails {
    modules: Vec<ModuleView>,
    modules_error: Option<String>,
    services: Vec<vigil_sys::inspect::HostedService>,
}

fn user_writable(path: &str) -> bool {
    let low = path.to_lowercase();
    let under = |var: &str| {
        std::env::var(var)
            .ok()
            .map(|dir| dir.trim_end_matches('\\').to_lowercase())
            .filter(|dir| !dir.is_empty())
            .is_some_and(|dir| low.starts_with(&format!("{dir}\\")))
    };
    let users = std::env::var("SystemDrive")
        .map(|d| format!(r"{}\users\", d.to_lowercase()))
        .unwrap_or_default();
    (under("USERPROFILE") || under("ProgramData") || under("TEMP") || (!users.is_empty() && low.starts_with(&users)))
        && !under("SystemRoot")
        && !under("ProgramFiles")
        && !under("ProgramFiles(x86)")
}

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
pub async fn process_details(pid: u32) -> CmdResult<ProcessDetails> {
    blocking(move || {
        let (modules, modules_error) = match vigil_sys::inspect::modules(pid) {
            Ok(list) => (list, None),
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
        let modules = modules
            .into_iter()
            .map(|m| ModuleView {
                user_writable: user_writable(&m.path),
                name: m.name,
                path: m.path,
                size: m.size,
            })
            .collect();
        let services = vigil_sys::inspect::hosted_services(pid).unwrap_or_default();
        ProcessDetails {
            modules,
            modules_error,
            services,
        }
    })
    .await
}

#[cfg(test)]
mod inspector_tests {
    use super::{argument_paths, task_writable, user_writable};

    #[test]
    fn writable_folders_are_flagged() {
        let profile = std::env::var("USERPROFILE").unwrap_or_default();
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        assert!(user_writable(&format!(r"{profile}\AppData\Local\Temp\x.dll")));
        assert!(!user_writable(&format!(r"{root}\System32\ntdll.dll")));
        assert!(!user_writable(r"C:\Program Files\App\app.dll"));
    }

    #[test]
    fn tasks_that_run_files_from_writable_folders_are_flagged() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let action = |program: &str, arguments: &str| vigil_sys::tasks::TaskAction {
            kind: "exec".into(),
            program: program.into(),
            arguments: arguments.into(),
            ..Default::default()
        };
        let task = |actions: Vec<vigil_sys::tasks::TaskAction>| vigil_sys::tasks::ScheduledTask {
            actions,
            ..Default::default()
        };
        let powershell = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
        assert!(task_writable(&task(vec![action(
            &powershell,
            r#"-NoProfile -File "%LOCALAPPDATA%\Vendor\sync.ps1""#
        )])));
        let profile = std::env::var("USERPROFILE").unwrap_or_default();
        assert!(task_writable(&task(vec![action(
            &format!(r"{profile}\AppData\Local\Temp\x.exe"),
            ""
        )])));
        assert!(!task_writable(&task(vec![action(&powershell, "-Command Get-Date")])));
        assert!(!task_writable(&task(vec![action(
            r"C:\Program Files\Vendor\updater.exe",
            "/check"
        )])));
        assert!(!task_writable(&task(Vec::new())));
        assert_eq!(
            argument_paths(r#"/a="C:\One Two\x.ps1",D:\y.dll -z"#),
            [r"C:\One", r"D:\y.dll"]
        );
    }
}
