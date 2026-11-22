//! The one path by which the window changes the system.
//!
//! The window sends a typed [`Request`]; [`run_action`] rebuilds the action from Rust's own state
//! (requests.rs), asks for confirmation in a native Windows dialog (confirm.rs) and runs it through
//! the action engine (`vigil_actions::execute`), which journals it. The window never builds an
//! `ActionSpec`, never calls the engine and never answers the confirmation: it only implements
//! [`Ui`], which names the window that owns the dialog and passes progress lines on. The dialog
//! itself is shown here, by the core.
//!
//! [`run_action`] blocks (it reads live state, waits for the user and runs the action): call it on
//! a worker thread, never on the UI thread.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use serde_json::{Value, json};
use vigil_actions::{ActionSpec, Record};
use vigil_scan::model::Analysis;

use crate::confirm::{Answer, Prompt};
use crate::planner::spec;
use crate::requests::{self, Context, Plan, Request};
use crate::state::AppState;

/// What the window provides to the action path: where the native confirmation belongs and where
/// progress goes. It cannot answer the confirmation; the core shows it ([`confirm`]).
pub trait Ui {
    /// The window that owns the confirmation dialog (an HWND; 0 for none).
    fn owner(&self) -> isize;
    /// One line of progress while an action runs.
    fn progress(&self, text: &str);
}

/// Shows the native confirmation, owned by the window of `ui`, and waits for the answer.
pub(crate) fn confirm(ui: &dyn Ui, prompt: &Prompt) -> Answer {
    crate::confirm::ask_owned(ui.owner(), prompt)
}

#[derive(Debug, Serialize, Default)]
pub struct ActionOutcome {
    pub cancelled: bool,
    pub records: Vec<Value>,
    pub message: String,
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

/// A journal record as History shows it.
pub fn record_json(record: &Record) -> Value {
    let mut value = record.as_value();
    if let Value::Object(map) = &mut value {
        map.insert("can_undo".into(), json!(vigil_actions::can_undo(record)));
        map.insert("op_label".into(), json!(vigil_actions::op_label(record.op())));
    }
    value
}

/// Checks, confirms and runs one request. Blocking: call it off the UI thread.
pub fn run_action(st: &AppState, request: &Request, ui: &dyn Ui) -> Result<ActionOutcome, String> {
    let _busy = Busy::take(&st.acting).ok_or_else(|| vigil_i18n::tr!("Wait for the current task to finish."))?;
    let plan = build_plan(st, request)?;
    match plan {
        Plan::Shell(spec) => run_shell(&spec, ui.owner()),
        Plan::Run { spec, item } => run_spec(st, spec, item, ui),
        Plan::Undo(id) => {
            let record = st
                .store
                .find(&id)
                .ok_or_else(|| vigil_i18n::tr!("that action is not in the journal"))?;
            if confirm(ui, &undo_prompt(&[record])) == Answer::Cancel {
                return Ok(ActionOutcome::cancelled());
            }
            match vigil_actions::undo(&id, &st.store) {
                Ok(record) => Ok(ActionOutcome::message(
                    record
                        .undo_message()
                        .map_or_else(|| vigil_i18n::tr!("Undone."), str::to_string),
                )),
                Err(error) => Err(error.to_string()),
            }
        }
        Plan::UndoBatch(batch) => {
            let steps: Vec<Record> = st
                .store
                .records()
                .into_iter()
                .filter(|r| r.batch() == Some(batch.as_str()) && vigil_actions::can_undo(r))
                .collect();
            if steps.is_empty() {
                return Ok(ActionOutcome::message(vigil_i18n::tr!("Nothing to undo.")));
            }
            if confirm(ui, &undo_prompt(&steps)) == Answer::Cancel {
                return Ok(ActionOutcome::cancelled());
            }
            let results = vigil_actions::undo_batch(&batch, &st.store);
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
        Plan::Restore(id) => quarantine_action(st, id, false, ui),
        Plan::Delete(id) => quarantine_action(st, id, true, ui),
    }
}

/// Marks the app busy with a change until dropped.
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

/// Reads the live state the request is checked against (only what this kind of request needs)
/// and rebuilds the action from it.
fn build_plan(st: &AppState, request: &Request) -> Result<Plan, String> {
    if let Request::Defender {
        op,
        setting,
        list,
        value,
    } = request
    {
        let live = vigil_sys::defender::read();
        return crate::protection::plan(op, setting, list, value, &live);
    }
    if let Request::Duplicates { paths } = request {
        let groups = st.lock().duplicates.clone();
        return crate::duplicates::plan(paths, &groups);
    }
    if let Request::Posture { op } = request {
        let live = crate::posture::read();
        return crate::posture::plan(op, &live);
    }
    match request {
        Request::Extension { op, key, browser } => return crate::extensions::plan_extension(op, key, browser),
        Request::BrowserPolicy { op, id } => return crate::extensions::plan_policy(op, id),
        _ => {}
    }
    let processes = match request {
        Request::Process { .. } => vigil_sys::process::ProcessSampler::new()
            .and_then(|mut s| s.snapshot())
            .map_err(|e| e.to_string())?,
        _ => Vec::new(),
    };
    let power_plans: Vec<(String, String, bool)> = match request {
        Request::Tuning { op, .. } if op == "power.plan" => vigil_maint::tuning::tuning_state()
            .power_plans
            .into_iter()
            .map(|p| (p.guid, p.name, p.active))
            .collect(),
        _ => Vec::new(),
    };
    let drive_media: Vec<(String, String)> = match request {
        Request::Tuning { op, .. } if op == "disk.optimize" => st
            .hardware(false)?
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
        Request::Service { .. } => vigil_sys::services::list().map_err(|e| e.to_string())?,
        _ => Vec::new(),
    };
    let startup = match request {
        Request::Startup { .. } => vigil_sys::startup::list(),
        _ => Vec::new(),
    };
    let tasks = match request {
        Request::Task { .. } => crate::inspect::scheduled_tasks()?,
        _ => Vec::new(),
    };
    let firewall = match request {
        Request::FirewallRule { .. } => crate::firewall::live_rules()?,
        _ => Vec::new(),
    };
    let inner = st.lock();
    let cleanup: Vec<Value> = inner
        .cleanup
        .iter()
        .filter_map(|t| serde_json::to_value(t).ok())
        .collect();
    let ctx = Context {
        analysis: inner.actionable(),
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

/// The confirmation for an action: what it does, its steps, whether it can be undone, warnings.
pub fn prompt_for(spec: &ActionSpec, offer_restore_point: bool) -> Prompt {
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

/// Undo ops that put a file back where it ran (a quarantine undo): the same warning as the
/// Quarantine page's Restore.
const RESTORES_FILE: [&str; 1] = ["file.quarantine"];

/// The confirmation for undoing journaled steps (one, or every step of a composite action): what
/// each undo puts back, and a warning when a quarantined file goes back where it can run.
pub fn undo_prompt(steps: &[Record]) -> Prompt {
    let mut body = vigil_i18n::tr!("Vigil puts back what these steps changed:");
    for step in steps {
        if step.target().is_empty() {
            body.push_str(&format!("\n•  {}", step.label()));
        } else {
            body.push_str(&format!("\n•  {}\n      {}", step.label(), step.target()));
        }
    }
    let restores_file = steps.iter().any(|s| RESTORES_FILE.contains(&s.op()));
    if restores_file {
        body.push_str(&format!(
            "\n\n{}",
            vigil_i18n::tr!("Quarantined files go back to their original location and can run again.")
        ));
    }
    let title = match steps {
        [one] => vigil_i18n::tr!("Undo: {0}", one.label()),
        _ => vigil_i18n::tr!("Undo {0} steps", steps.len()),
    };
    Prompt {
        title,
        body,
        warning: if restores_file {
            vigil_i18n::tr!("Restore only files you are sure are safe.")
        } else {
            String::new()
        },
        confirm: vigil_i18n::tr!("Undo"),
        // Undoing can turn persistence back on or let a file run again: Cancel is the default.
        destructive: restores_file,
        restore_point: None,
    }
}

fn run_spec(st: &AppState, spec: ActionSpec, item: Option<String>, ui: &dyn Ui) -> Result<ActionOutcome, String> {
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
    let Answer::Confirm { restore_point } = confirm(ui, &prompt_for(&spec, offer)) else {
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
    let mut records = Vec::new();
    if make_point {
        let point = spec_restore_point();
        records.push(vigil_actions::execute(&point, &st.store, None, &title));
    }
    let progress = |text: &str| ui.progress(text);
    records.extend(vigil_actions::execute_plan(&spec, &st.store, &title, &progress));
    if make_point && records.first().is_some_and(Record::ok) {
        st.lock().restore_point_done = true;
    }
    if let Some(id) = &item {
        record_on_item(st, id, &records);
    }
    // What Vigil removed leaves the background watch's baseline: if it comes back, that is news.
    crate::watch::forget_removed(&records);
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

fn run_shell(spec: &ActionSpec, hwnd: isize) -> Result<ActionOutcome, String> {
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
            let info = vigil_actions::verify_signature(Path::new(&path)).map_err(|e| e.to_string())?;
            return Ok(ActionOutcome::message(signature_text(&path, &info)));
        }
        other => return Err(vigil_i18n::tr!("Unknown request: {0}", other)),
    };
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

fn quarantine_action(st: &AppState, id: String, delete: bool, ui: &dyn Ui) -> Result<ActionOutcome, String> {
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
    if confirm(ui, &prompt) == Answer::Cancel {
        return Ok(ActionOutcome::cancelled());
    }
    let result = if delete {
        vigil_actions::delete_quarantined(&id, &st.store)
    } else {
        vigil_actions::restore_quarantined(&id, &st.store)
    };
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

    fn record(op: &str, label: &str, target: &str) -> Record {
        let value = json!({"id": "r1", "op": op, "label": label, "target": target, "ok": true});
        Record(value.as_object().cloned().unwrap_or_default())
    }

    #[test]
    fn undoing_a_quarantine_warns_like_restore() {
        let prompt = undo_prompt(&[record(
            "file.quarantine",
            "Quarantine file",
            "C:\\Users\\jdoe\\AppData\\Roaming\\winupd.exe",
        )]);
        assert_eq!(prompt.title, "Undo: Quarantine file");
        assert!(prompt.body.contains("winupd.exe"), "{}", prompt.body);
        assert!(prompt.body.contains("can run again"), "{}", prompt.body);
        assert_eq!(prompt.warning, "Restore only files you are sure are safe.");
        assert!(prompt.destructive);
        assert_eq!(prompt.confirm, "Undo");
    }

    #[test]
    fn undoing_several_steps_lists_each_one() {
        let prompt = undo_prompt(&[
            record("startup.disable", "Disable startup entry", "HKCU Run: winupd"),
            record("task.disable", "Disable task", "\\Contoso\\Updater"),
        ]);
        assert_eq!(prompt.title, "Undo 2 steps");
        assert!(prompt.body.contains("Disable startup entry") && prompt.body.contains("\\Contoso\\Updater"));
        assert!(prompt.warning.is_empty());
        assert!(!prompt.destructive);
    }

    #[test]
    fn busy_allows_one_change_at_a_time() {
        let flag = AtomicBool::new(false);
        let first = Busy::take(&flag);
        assert!(first.is_some());
        assert!(Busy::take(&flag).is_none());
        drop(first);
        assert!(Busy::take(&flag).is_some());
    }
}
