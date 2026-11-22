//! The shared state: the data folder and journal, the settings, the loaded report,
//! the measurements requests are checked against, and the flag that allows one change at a time.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::Value;
use vigil_actions::Store;
/// Journal records and quarantine entries as front ends read them.
pub use vigil_actions::{QuarantineEntry, Record};
use vigil_maint::hardware::Hardware;
use vigil_maint::storage::CleanupTarget;
use vigil_scan::model::Analysis;

use crate::secrets::{CredentialStore, SecretStore};
use crate::settings::{Ignored, Stored};

/// A scan whose inventory is analysed and that waits for the decision on the AI review.
pub struct Pending {
    pub analysis: Analysis,
    pub base: PathBuf,
    pub provider: Option<vigil_scan::ai::Provider>,
    pub problem: Option<String>,
    pub pending: usize,
}

#[derive(Default)]
pub struct Inner {
    pub settings: Stored,
    pub ignored: Ignored,
    pub analysis: Option<Analysis>,
    /// The report in the form the UI and the planner read (render_json).
    pub analysis_json: Option<Value>,
    pub report_path: Option<PathBuf>,
    /// The loaded report came from a folder a standard user can write to while this copy runs
    /// elevated (the tray copy's automatic scan): it is shown, but no action is planned or built
    /// from it, since its findings could have been planted.
    pub report_untrusted: bool,
    pub restore_point_done: bool,
    pub pending: Option<Pending>,
    pub cleanup: Vec<CleanupTarget>,
    pub space_files: Vec<(String, u64)>,
    /// The groups of the last duplicate search (a request to remove copies is checked against them).
    pub duplicates: Vec<vigil_maint::storage::DupGroup>,
    pub hardware: Option<Hardware>,
}

impl Inner {
    /// The loaded report, for planning or building actions: none when it is only to be looked at.
    pub fn actionable(&self) -> Option<&Value> {
        if self.report_untrusted {
            None
        } else {
            self.analysis_json.as_ref()
        }
    }
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
    pub acting: AtomicBool,
    pub scan_cancel: Arc<AtomicBool>,
    pub space_cancel: Arc<AtomicBool>,
    pub dupes_cancel: Arc<AtomicBool>,
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
            dupes_cancel: Arc::new(AtomicBool::new(false)),
        };
        state.load_latest();
        Ok(state)
    }

    pub fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn scans_dir(&self) -> PathBuf {
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

    pub fn set_analysis(&self, analysis: Analysis, path: Option<PathBuf>) {
        self.set(analysis, path, false);
    }

    /// Loads a report to look at only (see `Inner::report_untrusted`).
    pub fn set_analysis_untrusted(&self, analysis: Analysis, path: PathBuf) {
        self.set(analysis, Some(path), true);
    }

    /// Both in one lock: a request planned meanwhile never sees the new report as trusted.
    fn set(&self, analysis: Analysis, path: Option<PathBuf>, untrusted: bool) {
        let json = analysis.to_value();
        let mut inner = self.lock();
        inner.analysis = Some(analysis);
        inner.analysis_json = Some(json);
        inner.report_path = path;
        inner.report_untrusted = untrusted;
    }

    /// Saves the current report in place (after an action recorded on one of its findings).
    pub fn save_current(&self) {
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

    /// Whether a report at `path` may be acted on: a plain file directly in this copy's own scans
    /// folder (for an elevated copy `%ProgramData%\Vigil\scans`, which only administrators can
    /// write). Any other report (picked in "Open report…", sent by someone, or written by the
    /// standard-user tray copy) could have been planted to mark a security product "remove": it is
    /// shown, but nothing is planned or built from it.
    pub fn report_trusted(&self, path: &std::path::Path) -> bool {
        crate::autoscan::plain_file_in(path, &self.scans_dir())
    }

    /// Opens a saved report (`*-report.json`) as the current one, trusted or to look at only (see
    /// [`AppState::report_trusted`]). Returns whether it is trusted. Blocking.
    pub fn open_report(&self, path: &std::path::Path) -> Result<bool, String> {
        let analysis =
            vigil_scan::pipeline::load_report(path).map_err(|e| format!("Could not open the report: {e}"))?;
        let trusted = self.report_trusted(path);
        if trusted {
            self.set_analysis(analysis, Some(path.to_path_buf()));
        } else {
            self.set_analysis_untrusted(analysis, path.to_path_buf());
        }
        Ok(trusted)
    }

    /// The current report as the window reads it, with `viewOnly: true` when it is only to be
    /// looked at (the page then says why no action is offered).
    pub fn report_view(&self) -> Option<Value> {
        let inner = self.lock();
        let mut json = inner.analysis_json.clone();
        if inner.report_untrusted
            && let Some(Value::Object(map)) = json.as_mut()
        {
            map.insert("viewOnly".into(), Value::Bool(true));
        }
        json
    }

    /// The current report as HTML and the file name to suggest for it
    /// (`scan-20260101-1005-report.html`).
    pub fn report_html(&self) -> Result<(String, String), String> {
        let inner = self.lock();
        let analysis = inner.analysis.as_ref().ok_or("Run or open a scan first.")?;
        let started = crate::requests::scan_started(inner.analysis_json.as_ref()).unwrap_or("");
        let stamp: String = started
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == 'T')
            .take(13)
            .collect();
        let name = format!("scan-{}-report.html", stamp.replace('T', "-"));
        Ok((vigil_scan::report::render_html(analysis), name))
    }

    /// The AI provider `settings` ask for (the error says why there is none). Blocking: it may
    /// start a CLI to read its options or ask a local server for its models.
    pub fn pick_ai(&self, settings: &Stored) -> Result<vigil_scan::ai::Provider, String> {
        let keys = |id: &str| crate::secrets::lookup(&*self.secrets, id);
        let probe = vigil_scan::ai::SystemProbe { keys: &keys };
        vigil_scan::ai::pick_provider(&settings.ai.config(), &probe)
    }

    /// What an AI investigation needs: the settings, the loaded report (with its file) and the
    /// data folder.
    pub fn investigation_inputs(&self) -> (Stored, Option<(Analysis, PathBuf)>, PathBuf) {
        let inner = self.lock();
        let report = match (&inner.analysis, &inner.report_path) {
            (Some(analysis), Some(path)) => Some((analysis.clone(), path.clone())),
            _ => None,
        };
        (inner.settings.clone(), report, self.root.clone())
    }

    /// The hardware facts, read once and kept (`force` reads them again). Slow the first time:
    /// call it off the UI thread.
    pub fn hardware(&self, force: bool) -> Result<Hardware, String> {
        if !force && let Some(hw) = self.lock().hardware.clone() {
            return Ok(hw);
        }
        let hw = vigil_maint::hardware::hardware().map_err(|e| e.to_string())?;
        self.lock().hardware = Some(hw.clone());
        Ok(hw)
    }
}
