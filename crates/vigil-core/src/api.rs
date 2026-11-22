//! What the window reads and asks, as plain functions over [`AppState`]: reports and scans,
//! findings, history, maintenance, settings and the AI providers. Slow functions block (call them
//! off the UI thread); long ones report progress through a callback. Nothing here changes the
//! computer: changes go through [`crate::service::run_action`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use serde::Serialize;
use serde_json::{Value, json};
use vigil_maint::storage::{self, CleanupTarget, SpaceScan, Volume};

use crate::planner;
use crate::requests;
use crate::secrets;
use crate::settings::{self, View};
use crate::state::{AppState, Inner, Pending};

/// What a scan offers before the AI review: the items that would be sent and where they go.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewOffer {
    pub pending: usize,
    pub destination: Option<String>,
    /// The data stays on this computer (a local model).
    pub local: bool,
    pub problem: Option<String>,
    pub redact: bool,
    pub preview: Vec<Value>,
}

fn file_name(path: &Path) -> String {
    path.file_name().and_then(|n| n.to_str()).unwrap_or("scan").to_string()
}

fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// Collects the inventory and runs the local rules; the AI review is offered next
/// ([`scan_finish`]). `progress` gets one line per step.
pub fn scan_collect(
    st: &AppState,
    days: u32,
    virustotal: bool,
    progress: &dyn Fn(&str),
) -> Result<ReviewOffer, String> {
    let settings = {
        let mut inner = st.lock();
        if inner.pending.is_some() {
            return Err("A scan is already waiting for the AI review decision.".into());
        }
        inner.settings.days = days.clamp(1, 365);
        inner.settings.virustotal = virustotal;
        let _ = inner.settings.save(&st.root.join("settings.json"));
        inner.settings.clone()
    };
    let vt_key = if settings.virustotal {
        secrets::lookup(&*st.secrets, "virustotal")
    } else {
        None
    };
    let base = vigil_scan::pipeline::scan_base(&st.scans_dir());
    let cancel = st.scan_cancel.clone();
    cancel.store(false, Ordering::Relaxed);
    let redact = settings.ai.redact;
    let inventory = base.with_file_name(format!("{}-inventory.json", file_name(&base)));
    if settings.virustotal && vt_key.is_none() {
        progress(&vigil_i18n::tr!(
            "VirusTotal: no API key in Settings; the scan continues without it"
        ));
    }
    let (raw, analysis) = vigil_scan::collect_and_analyze(settings.days, vt_key.as_deref(), &progress, &cancel)
        .map_err(|e| e.to_string())?;
    if let Err(error) = std::fs::write(&inventory, raw.to_string()) {
        progress(&vigil_i18n::tr!("The raw inventory could not be saved ({0})", error));
    }
    let (provider, problem) = match st.pick_ai(&settings) {
        Ok(provider) => (Some(provider), None),
        Err(problem) => (None, Some(problem)),
    };
    let meta = |key: &str| analysis.meta.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    let redactor = vigil_scan::privacy::Redactor::for_this_computer(&meta("user"), &meta("computer"), redact);
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
    st.lock().pending = Some(Pending {
        analysis,
        base,
        provider,
        problem,
        pending,
    });
    Ok(offer)
}

/// Finishes the scan: with the AI review (`review`) or without it, and saves the report.
/// `selected`: the AI review was chosen in the scan dialog. Returns the report.
pub fn scan_finish(st: &AppState, review: bool, selected: bool, progress: &dyn Fn(&str)) -> Result<Value, String> {
    let (mut pending, redact) = {
        let mut inner = st.lock();
        let pending = inner.pending.take().ok_or("There is no scan to finish.")?;
        (pending, inner.settings.ai.redact)
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
        _ if !selected => Some(vigil_i18n::tr!("the AI review was not selected for this scan")),
        _ => Some(vigil_i18n::tr!("you skipped the AI review")),
    };
    if let Some(reason) = reason {
        let mut ai = serde_json::Map::new();
        ai.insert("reason".into(), json!(reason));
        pending.analysis.ai = ai;
    }
    // What changed since the previous scan in the same folder travels with the report.
    vigil_scan::pipeline::attach_changes(&mut pending.analysis, &pending.base);
    let path = match vigil_scan::pipeline::save_report(&pending.analysis, &pending.base, false) {
        Ok((json, _)) => Some(json),
        Err(error) => {
            progress(&format!("The scan finished but could not be saved: {error}"));
            None
        }
    };
    st.set_analysis(pending.analysis, path);
    st.lock()
        .analysis_json
        .clone()
        .ok_or_else(|| "The report could not be read back.".into())
}

/// Stops a scan that collects (between collectors).
pub fn scan_cancel(st: &AppState) {
    st.scan_cancel.store(true, Ordering::Relaxed);
}

/// The actions offered for a finding, as the page shows them (label, explanation, warning, flags).
/// The page sends `Request::Finding { item_id, index }`; Rust plans them again before anything runs.
pub fn plan_actions(st: &AppState, item_id: &str) -> Vec<Value> {
    let inner = st.lock();
    let analysis = inner.actionable();
    requests::find_item(analysis, item_id)
        .map(|item| planner::plan_actions(item, requests::scan_started(analysis)))
        .unwrap_or_default()
        .iter()
        .filter_map(|spec| serde_json::to_value(spec).ok())
        .collect()
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

/// The findings of the loaded report the user chose to ignore.
pub fn ignored_list(st: &AppState) -> Vec<String> {
    ignored_ids(&st.lock())
}

/// Ignores (or stops ignoring) a finding of the loaded report; Vigil's own file only.
pub fn ignored_set(st: &AppState, item_id: &str, value: bool) -> Result<Vec<String>, String> {
    let mut inner = st.lock();
    let item = requests::find_item(inner.analysis_json.as_ref(), item_id)
        .cloned()
        .ok_or("Unknown finding.")?;
    let text = |key: &str| item.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    inner
        .ignored
        .set(item_key(&item), &text("title"), &text("kind"), value)?;
    Ok(ignored_ids(&inner))
}

/// Every journal record, newest first, as History shows it.
pub fn journal(st: &AppState) -> Vec<Value> {
    let mut records: Vec<Value> = st.store.records().iter().map(crate::service::record_json).collect();
    records.reverse();
    records
}

pub fn volumes() -> Vec<Volume> {
    storage::volumes()
}

/// Measures the cleanup targets (kept: a cleanup request is checked against them).
pub fn cleanup_measure(st: &AppState, progress: &dyn Fn(&str)) -> Vec<CleanupTarget> {
    let mut targets = storage::cleanup_targets(None);
    storage::measure(&mut targets, &progress, &storage::NeverCancel);
    st.lock().cleanup = targets.clone();
    targets
}

/// Walks a drive or folder for the space analysis (the largest files are kept: a Recycle request
/// is checked against them).
pub fn space_scan(st: &AppState, root: &str, progress: &dyn Fn(&str)) -> Result<SpaceScan, String> {
    let path = PathBuf::from(root);
    if !path.is_absolute() || !path.is_dir() {
        return Err("Choose a drive or a folder that exists.".into());
    }
    let cancel = st.space_cancel.clone();
    cancel.store(false, Ordering::Relaxed);
    let scan = storage::scan_space(&path, &progress, &*cancel, 500, 300);
    st.lock().space_files = scan.largest_files.iter().map(|f| (f.path.clone(), f.size)).collect();
    Ok(scan)
}

pub fn space_cancel(st: &AppState) {
    st.space_cancel.store(true, Ordering::Relaxed);
}

/// The logical processors of this computer and the ones a process may use now (read-only).
#[derive(Debug, Serialize)]
pub struct Affinity {
    pub processors: Vec<vigil_sys::cpusets::LogicalProcessor>,
    pub allowed: Vec<u32>,
}

pub fn process_affinity(pid: u32, created_ms: i64) -> Result<Affinity, String> {
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
}

fn uptime_seconds() -> f64 {
    // SAFETY: GetTickCount64 has no preconditions.
    (unsafe { windows::Win32::System::SystemInformation::GetTickCount64() }) as f64 / 1000.0
}

/// The insights of the Optimize page (hardware read once, kept).
pub fn insights(st: &AppState) -> Result<Vec<vigil_maint::insights::Insight>, String> {
    let hw = st.hardware(false)?;
    let tuning = vigil_maint::tuning::tuning_state();
    let volumes = storage::volumes();
    Ok(vigil_maint::insights::collect(
        &hw,
        Some(&tuning),
        &volumes,
        uptime_seconds(),
        None,
    ))
}

/// The settings as the page shows them (which API keys are stored, never their values).
pub fn settings_get(st: &AppState) -> View {
    let stored = secrets::stored(&*st.secrets);
    st.lock().settings.view(stored)
}

/// Saves the settings. `secrets`: a value stores that API key in Windows Credential Manager, ""
/// removes it, `None` keeps it. Returns the language in use, for the watch's own texts.
pub fn settings_set(
    st: &AppState,
    view: &View,
    secrets_changed: &HashMap<String, Option<String>>,
) -> Result<(View, &'static str), String> {
    for (id, value) in secrets_changed {
        match value {
            Some(value) if value.trim().is_empty() => st.secrets.delete(id)?,
            Some(value) => st.secrets.set(id, value)?,
            None => {}
        }
    }
    let mut inner = st.lock();
    inner.settings.apply(view)?;
    inner.settings.save(&st.root.join("settings.json"))?;
    let language = vigil_i18n::set_language(&inner.settings.language);
    let stored = secrets::stored(&*st.secrets);
    Ok((inner.settings.view(stored), language))
}

#[derive(Debug, Serialize)]
pub struct AiStatus {
    pub provider: String,
    pub destination: Option<String>,
    /// The data stays on this computer.
    pub local: bool,
    pub problem: Option<String>,
}

/// The provider the next scan will use (after "auto" is resolved).
pub fn ai_status(st: &AppState) -> AiStatus {
    let settings = st.lock().settings.clone();
    match st.pick_ai(&settings) {
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
    }
}

/// One AI provider for Settings.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiProviderView {
    pub id: &'static str,
    pub name: String,
    pub kind: &'static str,
    pub secret: Option<&'static str>,
    pub needs_endpoint: bool,
    pub default_endpoint: Option<&'static str>,
    pub default_model: &'static str,
    pub suggested_models: Vec<&'static str>,
    pub supports_effort: bool,
    pub available: bool,
    pub note: String,
}

/// Every AI provider with its availability here (looks for the CLIs and asks a local model server
/// whether it answers; nothing is sent to any AI).
pub fn ai_providers(st: &AppState) -> Vec<AiProviderView> {
    let config = st.lock().settings.ai.config();
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
}

/// The models an API offers at an endpoint (a local Ollama server: only models installed here).
pub fn ai_models(st: &AppState, provider: &str, endpoint: &str) -> Result<Vec<String>, String> {
    let keys = |id: &str| secrets::lookup(&*st.secrets, id);
    vigil_scan::ai::list_models(provider, endpoint, &keys)
}

/// A service with whether Vigil refuses to change it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceView {
    #[serde(flatten)]
    pub service: vigil_sys::services::Service,
    pub protected: bool,
}

pub fn services_list() -> Result<Vec<ServiceView>, String> {
    let services = vigil_sys::services::list().map_err(|e| e.to_string())?;
    Ok(services
        .into_iter()
        .map(|service| ServiceView {
            protected: requests::protected_service(&service),
            service,
        })
        .collect())
}

/// Program icons as PNG data URLs by path (paths without an icon are left out).
pub fn process_icons(paths: Vec<String>) -> HashMap<String, String> {
    paths
        .into_iter()
        .take(512)
        .filter(|path| {
            let file = Path::new(path);
            file.is_absolute()
                && file
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("exe") || e.eq_ignore_ascii_case("ico"))
        })
        .filter_map(|path| vigil_sys::apps::icon_data_url(&path).map(|url| (path, url)))
        .collect()
}

/// Opens the report of the last automatic scan and makes it the current report (`None`: there is
/// none). The path comes from the watch's own state and is checked first: the right name, directly
/// in this copy's scans folder or the user's, a plain file in a plain folder.
pub fn open_auto_report(st: &AppState, watcher: &crate::watch::Watcher) -> Result<Option<Value>, String> {
    let report = watcher.store.load().auto_scan.report;
    if report.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(report);
    let own = st.scans_dir();
    let mut folders = vec![own.clone()];
    if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        folders.push(PathBuf::from(local).join("Vigil").join("scans"));
    }
    crate::autoscan::check_report_path(&path, &folders)?;
    // An elevated copy reads a report the standard-user tray copy wrote in a folder any program of
    // this user can write to: it may look, but nothing is planned from it (a planted report could
    // mark a security product "remove"). Its own folder (Administrators only) is trusted.
    let trusted = !st.admin || crate::autoscan::inside(&path, &own);
    let analysis = vigil_scan::pipeline::load_report(&path).map_err(|e| format!("Could not open the report: {e}"))?;
    if trusted {
        st.set_analysis(analysis, Some(path));
    } else {
        st.set_analysis_untrusted(analysis, path);
    }
    let mut json = st.lock().analysis_json.clone();
    // The page says why this report offers no actions.
    if let (false, Some(Value::Object(map))) = (trusted, json.as_mut()) {
        map.insert("viewOnly".into(), Value::Bool(true));
    }
    Ok(json)
}
