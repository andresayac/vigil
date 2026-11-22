//! The security operations: processes, services and drivers, scheduled tasks, startup entries,
//! registry values, quarantine, uninstallers, firewall, Microsoft Defender and a few settings.

use std::path::Path;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{Map, Value, json};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_STATUS,
};
use windows::core::{HSTRING, PCWSTR};

use crate::cmdline::{basename, in_dir, is_abs, normalize_path, split_command};
use crate::engine::{Builtin, Outcome, run_fn, undo_fn};
use crate::error::{ActionError, Result, fail};
use crate::guards::{guard_file, guard_service};
use crate::params::{Params, as_int, text_of, truthy};
use crate::procs::{self, Proc};
use crate::quarantine::{self, new_id};
use crate::registry::{self, Hive, read_values, reg_delete, reg_read, reg_write, restore_value, split_key, win32_text};
use crate::runner::{self, first_line, ps, ps_ok, run, tool};
use crate::store::Store;
use vigil_i18n::tr;

// --------------------------------------------------------------------------- processes

fn op_process_terminate(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let path = p.str_or_empty("path");
    let pids: Vec<i64> = p.list("pids").into_iter().filter_map(as_int).collect();
    let names: Vec<String> = p.list("names").into_iter().filter(|v| truthy(v)).map(text_of).collect();
    let scan_started = p.str_or_empty("scan_started");
    let found = procs::find_processes(
        Some(path.as_str()).filter(|s| !s.is_empty()),
        &pids,
        &names,
        Some(scan_started.as_str()).filter(|s| !s.is_empty()),
    );
    // A group ended from the process list names each instance (PID + start time): a PID reused since
    // the confirmation is left alone.
    let instances: Vec<(i64, f64)> = p
        .list("instances")
        .into_iter()
        .filter_map(|v| Some((as_int(v.get("pid")?)?, v.get("create_time")?.as_f64()?)))
        .collect();
    let found: Vec<Proc> = if instances.is_empty() {
        found
    } else {
        found
            .into_iter()
            .filter(|proc| {
                instances.iter().any(|(pid, started)| {
                    *pid == i64::from(proc.pid)
                        && procs::create_time(proc.pid).is_some_and(|now| (now - started).abs() <= 1.0)
                })
            })
            .collect()
    };
    if found.is_empty() {
        return Ok(Outcome::done(tr!("no matching process is running now")));
    }
    let (done, failed) = procs::terminate(&found, p.flag("tree"));
    if !failed.is_empty() && done.is_empty() {
        return fail(failed.join("; "));
    }
    let mut message = if done.is_empty() {
        tr!("nothing was ended")
    } else {
        tr!("ended {0}", done.join(", "))
    };
    if !failed.is_empty() {
        message.push_str(&tr!(". Not ended: {0}", failed.join("; ")));
    }
    Ok(Outcome::done(message))
}

/// The process of `params["pid"]` if it is still the same instance (`create_time`) and may be touched.
pub(crate) fn live_process(p: Params<'_>, protect: bool) -> Result<Proc> {
    let proc = Proc::get(p.req_int("pid")?)?;
    if p.flag("create_time") {
        let recorded = p.float("create_time").unwrap_or(0.0);
        let Some(started) = proc.create_time() else {
            return fail(tr!("access denied"));
        };
        if (started - recorded).abs() > 1.0 {
            return fail(tr!("that process has exited (its PID now belongs to another program)"));
        }
    }
    if protect && let Some(reason) = procs::process_protection(&proc) {
        return fail(tr!("not allowed: {0}", reason));
    }
    Ok(proc)
}

fn process_suspend(p: Params<'_>, resume: bool) -> Result<Outcome> {
    let proc = live_process(p, true)?;
    procs::suspend(proc.pid, resume)?;
    let label = proc.describe();
    if resume {
        return Ok(Outcome::done(format!("resumed {label}")));
    }
    let created = proc.create_time().map_or(Value::Null, |t| json!(t));
    Ok(Outcome::new(
        tr!("suspended {0}", label),
        Some(json!({ "pid": proc.pid, "create_time": created })),
    ))
}

fn op_process_suspend(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    process_suspend(p, false)
}

fn op_process_resume(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    process_suspend(p, true)
}

fn undo_process_suspend(u: Params<'_>, _store: &Store) -> Result<String> {
    Ok(process_suspend(u, true)?.message)
}

// --------------------------------------------------------------------------- services and drivers

const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";

/// The values of a service's registry key (plus `ServiceDll` from its Parameters subkey).
pub(crate) fn service_reg(name: &str) -> Result<Map<String, Value>> {
    if let Some(read) = crate::testing::service_reg() {
        return read(name);
    }
    if name.is_empty() || name.contains(['\\', '/']) {
        return fail(tr!("invalid service name"));
    }
    let sub = format!("{SERVICES_KEY}\\{name}");
    let mut values = match read_values(Hive::LocalMachine, &sub) {
        Ok(Some(values)) => values,
        Ok(None) => return fail(tr!("the service \"{0}\" no longer exists (run a new scan)", name)),
        Err(status) => return fail(tr!("cannot read the service \"{0}\": {1}", name, win32_text(status))),
    };
    if let Ok(Some(parameters)) = read_values(Hive::LocalMachine, &format!("{sub}\\Parameters"))
        && let Some(dll) = parameters.get("ServiceDll")
    {
        values.insert("ServiceDll".into(), dll.clone());
    }
    Ok(values)
}

/// A Service Control Manager handle, closed when dropped.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW/OpenServiceW and is closed only here.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

/// "running", "stopped", "start_pending"... or `None` when the service does not exist.
pub fn service_status(name: &str) -> Option<String> {
    if let Some(query) = crate::testing::service_status() {
        return query(name);
    }
    // SAFETY: plain call; the handle is owned by `ScHandle`.
    let manager = ScHandle(unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }.ok()?);
    let wide = HSTRING::from(name);
    // SAFETY: `wide` outlives the call; the handle is owned by `ScHandle`.
    let service = ScHandle(unsafe { OpenServiceW(manager.0, &wide, SERVICE_QUERY_STATUS) }.ok()?);
    let mut status = SERVICE_STATUS::default();
    // SAFETY: valid service handle and out pointer.
    unsafe { QueryServiceStatus(service.0, &mut status) }.ok()?;
    let state = match status.dwCurrentState.0 {
        1 => "stopped",
        2 => "start_pending",
        3 => "stop_pending",
        4 => "running",
        5 => "continue_pending",
        6 => "pause_pending",
        7 => "paused",
        _ => return None,
    };
    Some(state.to_string())
}

fn wait_status(name: &str, wanted: &str, timeout: Duration) -> bool {
    let end = Instant::now() + timeout;
    let mut checks = 0u32;
    while Instant::now() < end {
        let status = service_status(name);
        if status.as_deref() == Some(wanted) || (wanted == "stopped" && status.is_none()) {
            return true;
        }
        if crate::testing::no_sleep() {
            checks += 1;
            if checks > 1000 {
                return false;
            }
        } else {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    false
}

fn sc_args(args: &[&str]) -> Vec<String> {
    std::iter::once(tool("sc.exe"))
        .chain(args.iter().map(|a| (*a).to_string()))
        .collect()
}

pub(crate) fn sc(args: &[&str], what: &str) -> Result<runner::ToolResult> {
    let result = run(sc_args(args), 60)?;
    if result.code != 0 {
        let text = if result.out.is_empty() {
            &result.err
        } else {
            &result.out
        };
        let line = first_line(text);
        let detail = if line.is_empty() {
            tr!("error {0}", result.code)
        } else {
            line
        };
        return fail(format!("{what} failed: {detail}"));
    }
    Ok(result)
}

/// Stops the service if it is running. True if it was running.
pub(crate) fn stop_service(name: &str) -> Result<bool> {
    if matches!(service_status(name).as_deref(), None | Some("stopped")) {
        return Ok(false);
    }
    let result = run(sc_args(&["stop", name]), 60)?;
    if result.code != 0 && result.code != 1062 {
        let text = if result.out.is_empty() {
            &result.err
        } else {
            &result.out
        };
        return fail(tr!("could not stop \"{0}\": {1}", name, first_line(text)));
    }
    if !wait_status(name, "stopped", Duration::from_secs(30)) {
        return fail(tr!("\"{0}\" did not stop within 30 seconds", name));
    }
    Ok(true)
}

fn op_service_stop(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let name = p.req_str("name")?;
    let values = service_reg(&name)?;
    guard_service(&name, &values)?;
    if !stop_service(&name)? {
        return Ok(Outcome::done(tr!("\"{0}\" was not running", name)));
    }
    Ok(Outcome::new(
        tr!("stopped \"{0}\"", name),
        Some(json!({ "name": name })),
    ))
}

fn undo_service_stop(u: Params<'_>, _store: &Store) -> Result<String> {
    let name = u.req_str("name")?;
    sc(&["start", &name], &tr!("starting \"{0}\"", name))?;
    Ok(format!("started \"{name}\" again"))
}

pub(crate) fn start_arg(start: i64, delayed: bool) -> &'static str {
    match start {
        2 if delayed => "delayed-auto",
        0 => "boot",
        1 => "system",
        2 => "auto",
        3 => "demand",
        4 => "disabled",
        _ => "demand",
    }
}

pub(crate) fn service_start(values: &Map<String, Value>) -> Result<(i64, bool)> {
    let start = match values.get("Start") {
        None => 3,
        Some(value) => as_int(value).ok_or_else(|| ActionError::new(tr!("the service has an invalid start type")))?,
    };
    let delayed = values.get("DelayedAutostart").is_some_and(truthy);
    Ok((start, delayed))
}

fn service_disable(p: Params<'_>, stop: bool) -> Result<Outcome> {
    let name = p.req_str("name")?;
    let values = service_reg(&name)?;
    guard_service(&name, &values)?;
    let (start, delayed) = service_start(&values)?;
    let was_running = if stop { stop_service(&name)? } else { false };
    if start == 4 {
        let suffix = if was_running {
            tr!(" (stopped it)")
        } else {
            String::new()
        };
        let undo = was_running.then(|| json!({ "name": name, "start": 4, "delayed": false, "was_running": true }));
        return Ok(Outcome::new(tr!("\"{0}\" was already disabled{1}", name, suffix), undo));
    }
    sc(
        &["config", &name, "start=", "disabled"],
        &tr!("disabling \"{0}\"", name),
    )?;
    let mut message = tr!(
        "disabled \"{0}\" (it was set to {1} start)",
        name,
        start_arg(start, delayed)
    );
    if was_running {
        message.push_str(&tr!(" and stopped it"));
    }
    Ok(Outcome::new(
        message,
        Some(json!({ "name": name, "start": start, "delayed": delayed, "was_running": was_running })),
    ))
}

fn op_service_disable(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    service_disable(p, p.flag_or("stop", true))
}

fn op_driver_disable(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    service_disable(p, false)
}

pub(crate) fn undo_service_disable(u: Params<'_>, _store: &Store) -> Result<String> {
    let name = u.req_str("name")?;
    service_reg(&name)?;
    let start = u.int_or("start", 3)?;
    let delayed = u.flag("delayed");
    if start != 4 {
        sc(
            &["config", &name, "start=", start_arg(start, delayed)],
            &tr!("restoring the start type of \"{0}\"", name),
        )?;
    }
    if u.flag("was_running") {
        let result = run(sc_args(&["start", &name]), 60)?;
        if result.code != 0 && result.code != 1056 {
            return Ok(tr!(
                "restored the start type of \"{0}\", but it did not start: {1}",
                name,
                first_line(&result.out)
            ));
        }
    }
    Ok(format!("restored \"{name}\" to {} start", start_arg(start, delayed)))
}

pub(crate) fn export_key(key: &str, store: &Store, record_id: &str) -> Result<String> {
    let target = store.backup_dir().join(format!("{record_id}.reg"));
    let target_text = target.to_string_lossy().into_owned();
    let result = run(
        vec![
            tool("reg.exe"),
            "export".into(),
            key.into(),
            target_text.clone(),
            "/y".into(),
        ],
        60,
    )?;
    if result.code != 0 || !target.is_file() {
        return fail(tr!("could not back up {0}: {1}", key, first_line(&result.text())));
    }
    Ok(target_text)
}

fn op_service_delete(p: Params<'_>, store: &Store, record_id: &str) -> Result<Outcome> {
    let name = p.req_str("name")?;
    let values = service_reg(&name)?;
    guard_service(&name, &values)?;
    let id = if record_id.is_empty() {
        new_id()
    } else {
        record_id.to_string()
    };
    let backup = export_key(&format!("HKLM\\{SERVICES_KEY}\\{name}"), store, &id)?;
    // Deleting still works when it does not stop: the service is removed when it stops or at restart.
    let _ = stop_service(&name);
    sc(&["delete", &name], &tr!("deleting \"{0}\"", name))?;
    Ok(Outcome::new(
        tr!("deleted the service \"{0}\" (backup of its registry key saved)", name),
        Some(json!({ "name": name, "backup": backup })),
    ))
}

fn undo_service_delete(u: Params<'_>, _store: &Store) -> Result<String> {
    let backup = u.str_or_empty("backup");
    if backup.is_empty() || !Path::new(&backup).is_file() {
        return fail(tr!("the registry backup of this service is missing"));
    }
    let result = run(vec![tool("reg.exe"), "import".into(), backup], 60)?;
    if result.code != 0 {
        return fail(tr!("could not import the backup: {0}", first_line(&result.text())));
    }
    Ok(tr!(
        "restored the registry key of \"{0}\"; restart Windows for the service to be available again",
        u.req_str("name")?
    ))
}

/// Starts a stopped service and waits until it runs (30 s).
fn start_service(name: &str) -> Result<()> {
    let result = run(sc_args(&["start", name]), 60)?;
    // 1056: the service is already running.
    if result.code != 0 && result.code != 1056 {
        let text = if result.out.is_empty() {
            &result.err
        } else {
            &result.out
        };
        return fail(tr!("could not start \"{0}\": {1}", name, first_line(text)));
    }
    if !wait_status(name, "running", Duration::from_secs(30)) {
        return fail(tr!("\"{0}\" did not start within 30 seconds", name));
    }
    Ok(())
}

/// The live service, re-read and checked against the guards before any change.
fn guarded_service(p: Params<'_>) -> Result<(String, Map<String, Value>)> {
    let name = p.req_str("name")?;
    let values = service_reg(&name)?;
    guard_service(&name, &values)?;
    Ok((name, values))
}

fn op_service_start(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let (name, values) = guarded_service(p)?;
    if service_start(&values)?.0 == 4 {
        return fail(tr!("\"{0}\" is disabled; change its startup type first", name));
    }
    if service_status(&name).as_deref() == Some("running") {
        return Ok(Outcome::done(tr!("\"{0}\" was already running", name)));
    }
    start_service(&name)?;
    Ok(Outcome::done(tr!("started \"{0}\"", name)))
}

fn op_service_restart(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let (name, values) = guarded_service(p)?;
    if service_start(&values)?.0 == 4 {
        return fail(tr!("\"{0}\" is disabled; change its startup type first", name));
    }
    let was_running = stop_service(&name)?;
    start_service(&name)?;
    Ok(Outcome::done(if was_running {
        tr!("restarted \"{0}\"", name)
    } else {
        tr!("\"{0}\" was not running; started it", name)
    }))
}

/// The `sc config start=` value for a startup type the app offers.
fn start_type_arg(value: &str) -> Option<&'static str> {
    match value {
        "auto" => Some("auto"),
        "delayed-auto" => Some("delayed-auto"),
        "demand" => Some("demand"),
        "disabled" => Some("disabled"),
        _ => None,
    }
}

fn op_service_start_type(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let (name, values) = guarded_service(p)?;
    let wanted = p.req_str("start_type")?;
    let arg = start_type_arg(&wanted).ok_or_else(|| ActionError::new(tr!("unknown startup type \"{0}\"", wanted)))?;
    let (start, delayed) = service_start(&values)?;
    if start == 0 || start == 1 {
        return fail(tr!("drivers that load during boot are not changed"));
    }
    if start_arg(start, delayed) == arg {
        return Ok(Outcome::done(tr!("\"{0}\" already has that startup type", name)));
    }
    sc(
        &["config", &name, "start=", arg],
        &tr!("changing the start type of \"{0}\"", name),
    )?;
    Ok(Outcome::new(
        tr!(
            "\"{0}\" now has {1} start (it was set to {2} start)",
            name,
            arg,
            start_arg(start, delayed)
        ),
        Some(json!({ "name": name, "start": start, "delayed": delayed, "was_running": false })),
    ))
}

// --------------------------------------------------------------------------- scheduled tasks

fn task_full(p: Params<'_>) -> Result<String> {
    let path = {
        let path = p.str_or_empty("path");
        if path.is_empty() { "\\".to_string() } else { path }
    };
    let name = p.str_or_empty("name");
    if name.is_empty() {
        return fail(tr!("the task has no name"));
    }
    let mut full = if path.ends_with('\\') {
        format!("{path}{name}")
    } else {
        format!("{path}\\{name}")
    };
    if !full.starts_with('\\') {
        full.insert(0, '\\');
    }
    if full.to_lowercase().starts_with("\\microsoft\\") {
        return fail(tr!("tasks under \\Microsoft\\ belong to Windows and are not changed"));
    }
    Ok(full)
}

fn schtasks(args: &[&str]) -> Vec<String> {
    std::iter::once(tool("schtasks.exe"))
        .chain(args.iter().map(|a| (*a).to_string()))
        .collect()
}

/// The task's definition as Task Scheduler stores it. Read through its COM API: `schtasks /XML`
/// prints through the console code page, which would turn characters outside it (in a path or a
/// name) into `?` and make the saved copy recreate a different task.
fn task_xml(full: &str) -> Result<String> {
    if !crate::runner::faked() {
        return vigil_sys::tasks::definition(full).map_err(|e| {
            ActionError::new(tr!(
                "the task \"{0}\" was not found (run a new scan): {1}",
                full,
                e.to_string()
            ))
        });
    }
    let result = run(schtasks(&["/Query", "/TN", full, "/XML"]), 60)?;
    if result.code != 0 {
        return fail(tr!(
            "the task \"{0}\" was not found (run a new scan): {1}",
            full,
            first_line(&result.text())
        ));
    }
    Ok(result.out)
}

static SETTINGS_RE: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"(?is)<Settings>(.*?)</Settings>").ok());
static ENABLED_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)<Enabled>\s*(true|false)\s*</Enabled>").ok());
static ENCODING_RE: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r#"(?i)encoding="[^"]+""#).ok());

/// Whether a task definition is enabled (no `<Enabled>` in its settings means enabled).
pub fn task_enabled(xml: &str) -> bool {
    let settings = SETTINGS_RE
        .as_ref()
        .and_then(|re| re.captures(xml))
        .and_then(|c| c.get(1))
        .map_or("", |m| m.as_str());
    match ENABLED_RE.as_ref().and_then(|re| re.captures(settings)) {
        None => true,
        Some(caps) => caps.get(1).is_some_and(|m| m.as_str().eq_ignore_ascii_case("true")),
    }
}

fn op_task_disable(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let full = task_full(p)?;
    if !task_enabled(&task_xml(&full)?) {
        return Ok(Outcome::done(tr!("\"{0}\" was already disabled", full)));
    }
    let result = run(schtasks(&["/Change", "/TN", &full, "/DISABLE"]), 60)?;
    if result.code != 0 {
        return fail(tr!("could not disable the task: {0}", first_line(&result.text())));
    }
    Ok(Outcome::new(
        tr!("disabled the scheduled task \"{0}\"", full),
        Some(json!({ "full": full })),
    ))
}

fn undo_task_disable(u: Params<'_>, _store: &Store) -> Result<String> {
    let full = u.req_str("full")?;
    let result = run(schtasks(&["/Change", "/TN", &full, "/ENABLE"]), 60)?;
    if result.code != 0 {
        return fail(tr!("could not enable the task: {0}", first_line(&result.text())));
    }
    Ok(tr!("enabled the scheduled task \"{0}\" again", full))
}

fn op_task_enable(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let full = task_full(p)?;
    if task_enabled(&task_xml(&full)?) {
        return Ok(Outcome::done(tr!("\"{0}\" was already enabled", full)));
    }
    let result = run(schtasks(&["/Change", "/TN", &full, "/ENABLE"]), 60)?;
    if result.code != 0 {
        return fail(tr!("could not enable the task: {0}", first_line(&result.text())));
    }
    Ok(Outcome::new(
        tr!("enabled the scheduled task \"{0}\"", full),
        Some(json!({ "full": full })),
    ))
}

fn undo_task_enable(u: Params<'_>, _store: &Store) -> Result<String> {
    let full = u.req_str("full")?;
    let result = run(schtasks(&["/Change", "/TN", &full, "/DISABLE"]), 60)?;
    if result.code != 0 {
        return fail(tr!("could not disable the task: {0}", first_line(&result.text())));
    }
    Ok(tr!("disabled the scheduled task \"{0}\" again", full))
}

/// Runs a task now, as Task Scheduler's "Run" does (its own account and run level). Not undoable.
fn op_task_run(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let full = task_full(p)?;
    if !task_enabled(&task_xml(&full)?) {
        return fail(tr!("\"{0}\" is disabled; enable it first", full));
    }
    let result = run(schtasks(&["/Run", "/TN", &full]), 60)?;
    if result.code != 0 {
        return fail(tr!("could not run the task: {0}", first_line(&result.text())));
    }
    Ok(Outcome::done(tr!("started the scheduled task \"{0}\"", full)))
}

/// UTF-16 with a byte order mark and Windows line ends, as Task Scheduler exports task definitions.
fn utf16_file(text: &str) -> Vec<u8> {
    let text = text.replace("\r\n", "\n").replace('\n', "\r\n");
    [0xFF, 0xFE]
        .into_iter()
        .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
        .collect()
}

fn op_task_delete(p: Params<'_>, store: &Store, record_id: &str) -> Result<Outcome> {
    let full = task_full(p)?;
    let xml = task_xml(&full)?;
    let id = if record_id.is_empty() {
        new_id()
    } else {
        record_id.to_string()
    };
    let backup = store.backup_dir().join(format!("{id}.xml"));
    let xml = match ENCODING_RE.as_ref() {
        Some(re) => re.replacen(&xml, 1, r#"encoding="UTF-16""#).into_owned(),
        None => xml,
    };
    std::fs::write(&backup, utf16_file(&xml)).map_err(|e| {
        ActionError::new(tr!(
            "could not save the task definition: {0}",
            crate::error::io_text(&e)
        ))
    })?;
    // A task that stores a password cannot be recreated from its definition (the password is
    // not in it): the copy is kept for reference, but the deletion is not offered as undoable.
    let stores_password = task_stores_password(&xml);
    let result = run(schtasks(&["/Delete", "/TN", &full, "/F"]), 60)?;
    if result.code != 0 {
        return fail(tr!("could not delete the task: {0}", first_line(&result.text())));
    }
    if stores_password {
        return Ok(Outcome::done(tr!(
            "deleted the scheduled task \"{0}\"; it stored a password, so it cannot be recreated automatically (its definition was saved to {1})",
            full,
            backup.display()
        )));
    }
    Ok(Outcome::new(
        tr!("deleted the scheduled task \"{0}\" (its definition was saved)", full),
        Some(json!({ "full": full, "backup": backup.to_string_lossy() })),
    ))
}

/// Whether a task definition runs with a stored password (logon type Password, or
/// InteractiveTokenOrPassword).
pub fn task_stores_password(xml: &str) -> bool {
    vigil_sys::tasks::from_xml(r"\task", xml).logon_type == "password"
}

fn undo_task_delete(u: Params<'_>, _store: &Store) -> Result<String> {
    let backup = u.str_or_empty("backup");
    if backup.is_empty() || !Path::new(&backup).is_file() {
        return fail(tr!("the saved task definition is missing"));
    }
    let full = u.req_str("full")?;
    let result = run(schtasks(&["/Create", "/TN", &full, "/XML", &backup]), 60)?;
    if result.code != 0 {
        return fail(tr!(
            "could not recreate the task: {0} (tasks that store a password must be recreated by hand)",
            first_line(&result.text())
        ));
    }
    Ok(tr!("recreated the scheduled task \"{0}\"", full))
}

// --------------------------------------------------------------------------- startup entries

const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

static RUN_KEY_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^software\\(wow6432node\\)?microsoft\\windows\\currentversion\\run$").ok());

/// The StartupApproved key Task Manager uses for a Run key (`None` if the key has no switch).
pub fn approved_location(reg_key: &str) -> Result<Option<String>> {
    if let Some(map) = crate::testing::approved() {
        return Ok(map(reg_key));
    }
    let (hive, sub) = split_key(reg_key)?;
    let low = sub.to_lowercase();
    if RUN_KEY_RE.as_ref().is_some_and(|re| re.is_match(&low)) {
        let leaf = if low.contains("wow6432node") { "Run32" } else { "Run" };
        return Ok(Some(format!("{}\\{APPROVED}\\{leaf}", hive.short())));
    }
    Ok(None)
}

/// The StartupApproved key of a file in a Startup folder.
pub fn startup_folder_approved(file_path: &str) -> String {
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let hive = if !appdata.is_empty() && in_dir(file_path, &appdata) {
        "HKCU"
    } else {
        "HKLM"
    };
    format!("{hive}\\{APPROVED}\\StartupFolder")
}

fn disabled_blob() -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let filetime = (now.as_secs_f64() + 11_644_473_600.0) * 10_000_000.0;
    let mut out = vec![3, 0, 0, 0];
    out.extend((filetime as u64).to_le_bytes());
    out
}

/// The switch of a startup entry: (StartupApproved key, value name, label for messages). The same
/// checks guard turning it off and on.
fn startup_switch(p: &Params<'_>) -> Result<(String, String, String)> {
    Ok(if p.flag("file") {
        let file_path = p.req_str("file")?;
        if !Path::new(&file_path).exists() {
            return fail(tr!("the file is no longer in the Startup folder"));
        }
        let value = basename(&file_path).to_string();
        let label = tr!("\"{0}\" in the Startup folder", value);
        (startup_folder_approved(&file_path), value, label)
    } else {
        let key = p.req_str("key")?;
        let value = p.req_str("value")?;
        registry::check_editable(&key, &value)?;
        if reg_read(&key, &value)?.is_none() {
            return fail(tr!(
                "the startup entry \"{0}\" no longer exists (run a new scan)",
                value
            ));
        }
        let Some(approved) = approved_location(&key)? else {
            return fail(tr!(
                "this kind of startup entry has no on/off switch; delete it instead"
            ));
        };
        let label = format!("\"{value}\"");
        (approved, value, label)
    })
}

/// Whether a StartupApproved value (as `reg_read` returns it) turns the entry off: an odd first
/// byte. No value means on.
fn switch_is_off(previous: Option<&Value>) -> bool {
    previous
        .and_then(|s| s.get("data"))
        .and_then(|d| d.get("hex"))
        .and_then(Value::as_str)
        .and_then(|hex| hex.get(..2))
        .and_then(|byte| u8::from_str_radix(byte, 16).ok())
        .is_some_and(|byte| byte % 2 == 1)
}

fn op_startup_enable(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let (approved, value, label) = startup_switch(&p)?;
    let previous = reg_read(&approved, &value)?;
    if !switch_is_off(previous.as_ref()) {
        return Ok(Outcome::done(tr!("{0} was already enabled", label)));
    }
    // What Task Manager writes when an entry is turned back on.
    let enabled = [2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    reg_write(
        &approved,
        &value,
        &json!({ "type": "REG_BINARY", "data": { "hex": registry::hex(&enabled) } }),
    )?;
    Ok(Outcome::new(
        tr!("enabled the startup entry {0} (same switch as Task Manager)", label),
        Some(json!({ "key": approved, "value": value, "previous": previous })),
    ))
}

fn op_startup_disable(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let (approved, value, label) = startup_switch(&p)?;
    let previous = reg_read(&approved, &value)?;
    if switch_is_off(previous.as_ref()) {
        return Ok(Outcome::done(tr!("{0} was already disabled", label)));
    }
    reg_write(
        &approved,
        &value,
        &json!({ "type": "REG_BINARY", "data": { "hex": registry::hex(&disabled_blob()) } }),
    )?;
    Ok(Outcome::new(
        tr!("disabled the startup entry {0} (same switch as Task Manager)", label),
        Some(json!({ "key": approved, "value": value, "previous": previous })),
    ))
}

fn undo_registry_value(u: Params<'_>, _store: &Store) -> Result<String> {
    let key = u.req_str("key")?;
    let value = u.req_str("value")?;
    restore_value(&key, &value, u.0.get("previous"))?;
    Ok(format!("restored {key}\\{value}"))
}

fn op_registry_delete(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let key = p.req_str("key")?;
    let value = p.req_str("value")?;
    registry::check_editable(&key, &value)?;
    let Some(previous) = reg_read(&key, &value)? else {
        return Ok(Outcome::done(tr!("\"{0}\" no longer exists in {1}", value, key)));
    };
    reg_delete(&key, &value)?;
    Ok(Outcome::new(
        tr!("deleted \"{0}\" from {1} (its data was saved)", value, key),
        Some(json!({ "key": key, "value": value, "previous": previous })),
    ))
}

fn winlogon_default(value: &str) -> Option<String> {
    match value.to_lowercase().as_str() {
        "shell" => Some("explorer.exe".to_string()),
        "userinit" => Some(format!(
            "{},",
            runner::system32().join("userinit.exe").to_string_lossy()
        )),
        _ => None,
    }
}

fn op_winlogon_restore(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let key = p.req_str("key")?;
    let value = p.req_str("value")?;
    registry::check_editable(&key, &value)?;
    let previous = reg_read(&key, &value)?;
    let default = winlogon_default(&value);
    let message = match default {
        Some(default) if key.to_uppercase().starts_with("HKLM") => {
            let current = previous
                .as_ref()
                .map(|s| text_of(s.get("data").unwrap_or(&Value::Null)));
            if current.is_some_and(|c| c.trim().to_lowercase() == default.to_lowercase()) {
                return Ok(Outcome::done(tr!("Winlogon {0} already has its default value", value)));
            }
            reg_write(&key, &value, &json!({ "type": "REG_SZ", "data": default }))?;
            tr!("set Winlogon {0} back to its default ({1})", value, default)
        }
        _ => {
            if previous.is_none() {
                return Ok(Outcome::done(tr!("Winlogon {0} is not set", value)));
            }
            reg_delete(&key, &value)?;
            tr!("removed the Winlogon {0} value", value)
        }
    };
    Ok(Outcome::new(
        tr!("{0} (previous value saved)", message),
        Some(json!({ "key": key, "value": value, "previous": previous })),
    ))
}

static APPINIT_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)^HKLM\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\Windows$").ok()
});

fn op_appinit_off(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let key = p.req_str("key")?;
    if !APPINIT_RE.as_ref().is_some_and(|re| re.is_match(&key)) {
        return fail(tr!("unexpected AppInit key"));
    }
    let previous = reg_read(&key, "LoadAppInit_DLLs")?;
    reg_write(&key, "LoadAppInit_DLLs", &json!({ "type": "REG_DWORD", "data": 0 }))?;
    Ok(Outcome::new(
        tr!("turned off AppInit DLL loading"),
        Some(json!({ "key": key, "value": "LoadAppInit_DLLs", "previous": previous })),
    ))
}

const WMI_REMOVE: &str = r#"
$n = $env:PC_NAME
$consumers = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | Where-Object { $_.Name -eq $n })
if ($consumers.Count -eq 0) { throw "the WMI subscription no longer exists" }
$bindings = @(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding |
    Where-Object { $_.Consumer.Name -eq $n })
$filters = @($bindings | ForEach-Object { $_.Filter.Name })
$bindings | Remove-CimInstance
foreach ($f in $filters) {
    $still = @(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding |
        Where-Object { $_.Filter.Name -eq $f })
    if ($still.Count -eq 0) {
        Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Where-Object { $_.Name -eq $f } |
            Remove-CimInstance
    }
}
$consumers | Remove-CimInstance
"removed $($consumers.Count) consumer(s), $($bindings.Count) binding(s)"
"#;

fn op_wmi_remove(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let name = p.req_str("name")?;
    let out = ps_ok(
        WMI_REMOVE,
        &tr!("removing the WMI subscription"),
        180,
        &[("name", &name)],
    )?;
    let last = out.lines().last().filter(|_| !out.is_empty()).unwrap_or("removed");
    Ok(Outcome::done(tr!("WMI subscription \"{0}\": {1}", name, last)))
}

// --------------------------------------------------------------------------- quarantine

fn op_file_quarantine(p: Params<'_>, store: &Store, _id: &str) -> Result<Outcome> {
    let path = p.req_str("path")?;
    quarantine::quarantine_file(&path, store, &p.str_or_empty("reason"), p.flag_or("kill", true), true)
}

fn undo_file_quarantine(u: Params<'_>, store: &Store) -> Result<String> {
    quarantine::restore_quarantined(&u.req_str("quarantine_id")?, store)
}

// --------------------------------------------------------------------------- programs

static MSI_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)^"?(?:[a-z]:\\windows\\(?:system32|syswow64)\\)?msiexec(?:\.exe)?"?\s+/[ix]\s*(\{[0-9a-f-]{36}\})"#,
    )
    .ok()
});

fn op_program_uninstall(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let key = p.str_or_empty("registry_key");
    let mut command = String::new();
    if !key.is_empty() {
        let snapshot = reg_read(&key, "UninstallString")?;
        let data = snapshot.as_ref().and_then(|s| s.get("data")).filter(|d| truthy(d));
        command = data.map(text_of).unwrap_or_default().trim().to_string();
    }
    if command.is_empty() {
        return fail(tr!(
            "the program no longer lists an uninstaller (it may already be uninstalled)"
        ));
    }
    let name = text_of(p.get("name"));
    if let Some(guid) = MSI_RE
        .as_ref()
        .and_then(|re| re.captures(&command))
        .and_then(|c| c.get(1))
    {
        runner::launch(&tool("msiexec.exe"), &["/x", guid.as_str()])?;
        return Ok(Outcome::done(tr!(
            "started the Windows Installer uninstall of \"{0}\"",
            name
        )));
    }
    let (program, args, _certain) = split_command(&command);
    let program = program.unwrap_or_default();
    if program.is_empty() || !is_abs(&program) || !Path::new(&program).is_file() {
        let shown: String = command.chars().take(200).collect();
        return fail(tr!("the uninstaller was not found: {0}", shown));
    }
    runner::launch_raw(&program, &args)?;
    Ok(Outcome::done(tr!(
        "started the uninstaller of \"{0}\"; follow its window to finish",
        name
    )))
}

// --------------------------------------------------------------------------- network

const FIREWALL_BLOCK: &str = r#"
foreach ($d in @(@($env:PC_OUT, 'Outbound'), @($env:PC_IN, 'Inbound'))) {
    New-NetFirewallRule -Name $d[0] -DisplayName ("Vigil: block " + $env:PC_LABEL) -Direction $d[1] `
        -Program $env:PC_PATH -Action Block -Profile Any -Description 'Created by Vigil' | Out-Null
}
"#;

fn op_firewall_block(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let path = normalize_path(&p.req_str("path")?);
    guard_file(&path, true)?;
    let rid: String = new_id().chars().take(12).collect();
    let names = [format!("Vigil-{rid}-out"), format!("Vigil-{rid}-in")];
    let label = basename(&path).to_string();
    ps_ok(
        FIREWALL_BLOCK,
        &tr!("creating the firewall rules"),
        180,
        &[
            ("out", &names[0]),
            ("in", &names[1]),
            ("path", &path),
            ("label", &label),
        ],
    )?;
    Ok(Outcome::new(
        tr!("blocked all network traffic of {0} with two firewall rules", label),
        Some(json!({ "rules": names })),
    ))
}

fn undo_firewall_block(u: Params<'_>, _store: &Store) -> Result<String> {
    for rule in u.list("rules") {
        ps(
            "Remove-NetFirewallRule -Name $env:PC_NAME",
            180,
            &[("name", &text_of(rule))],
        )?;
    }
    Ok(tr!("removed the firewall rules"))
}

fn op_firewall_enable(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let out = ps_ok(
        "Get-NetFirewallProfile | ForEach-Object { '{0}={1}' -f $_.Name, [int][bool]$_.Enabled }",
        &tr!("reading the firewall profiles"),
        180,
        &[],
    )?;
    let mut previous: Vec<(String, bool)> = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        let (name, enabled) = line.split_once('=').unwrap_or((line, ""));
        if name.is_empty() {
            continue;
        }
        match previous.iter_mut().find(|(n, _)| n == name) {
            Some(entry) => entry.1 = enabled == "1",
            None => previous.push((name.to_string(), enabled == "1")),
        }
    }
    let off: Vec<String> = previous
        .into_iter()
        .filter(|(_, on)| !on)
        .map(|(name, _)| name)
        .collect();
    if off.is_empty() {
        return Ok(Outcome::done(tr!("the firewall was already on for every profile")));
    }
    let profiles = off.join(",");
    ps_ok(
        "Set-NetFirewallProfile -Profile ($env:PC_PROFILES -split ',') -Enabled True",
        &tr!("turning the firewall on"),
        180,
        &[("profiles", &profiles)],
    )?;
    Ok(Outcome::new(
        tr!("turned the firewall on for: {0}", off.join(", ")),
        Some(json!({ "profiles": off })),
    ))
}

fn undo_firewall_enable(u: Params<'_>, _store: &Store) -> Result<String> {
    u.req_str("profiles")?;
    let profiles: Vec<String> = u.list("profiles").into_iter().map(text_of).collect();
    ps_ok(
        "Set-NetFirewallProfile -Profile ($env:PC_PROFILES -split ',') -Enabled False",
        &tr!("turning the firewall off"),
        180,
        &[("profiles", &profiles.join(","))],
    )?;
    Ok(tr!("turned the firewall off again for: {0}", profiles.join(", ")))
}

// --------------------------------------------------------------------------- Microsoft Defender

fn mpcmdrun() -> Result<String> {
    let path = crate::defender::mpcmdrun_path();
    if !Path::new(&path).is_file() {
        return fail(tr!("Microsoft Defender's command-line tool was not found"));
    }
    Ok(path)
}

fn op_defender_scan_file(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let path = normalize_path(&p.req_str("path")?);
    if !Path::new(&path).exists() {
        return fail(tr!("the file no longer exists"));
    }
    let result = run(
        vec![
            mpcmdrun()?,
            "-Scan".into(),
            "-ScanType".into(),
            "3".into(),
            "-File".into(),
            path.clone(),
        ],
        1800,
    )?;
    match result.code {
        0 => Ok(Outcome::done(tr!(
            "Microsoft Defender found no threats in {0}",
            basename(&path)
        ))),
        2 => Ok(Outcome::done(tr!(
            "Microsoft Defender DETECTED a threat in {0} and handled it; see Windows Security → Protection history",
            basename(&path)
        ))),
        code => fail(tr!(
            "the Defender scan ended with code {0}: {1}",
            code,
            first_line(&result.out)
        )),
    }
}

/// One mechanism for every scan Vigil starts: the Protection page follows it (see `defender`).
fn op_defender_full_scan(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    crate::defender::start_scan("full")
}

fn op_defender_update(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let result = run(vec![mpcmdrun()?, "-SignatureUpdate".into()], 900)?;
    if result.code != 0 {
        return fail(tr!(
            "the update ended with code {0}: {1}",
            result.code,
            first_line(&result.out)
        ));
    }
    Ok(Outcome::done(tr!("updated Microsoft Defender's security intelligence")))
}

fn op_defender_realtime(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    ps_ok(
        "Set-MpPreference -DisableRealtimeMonitoring $false",
        &tr!("turning real-time protection on"),
        180,
        &[],
    )?;
    Ok(Outcome::done(tr!("turned Microsoft Defender real-time protection on")))
}

const EXCLUSION_PARAM: [(&str, &str); 3] = [
    ("path", "ExclusionPath"),
    ("process", "ExclusionProcess"),
    ("extension", "ExclusionExtension"),
];

fn op_defender_remove_exclusion(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let kind_name = {
        let kind = p.str_or_empty("kind");
        if kind.is_empty() { "path".to_string() } else { kind }
    };
    let Some((_, kind)) = EXCLUSION_PARAM.iter().find(|(name, _)| *name == kind_name) else {
        return fail(tr!("unknown exclusion type"));
    };
    let value = p.req_str("value")?;
    ps_ok(
        &format!("Remove-MpPreference -{kind} $env:PC_VALUE"),
        &tr!("removing the exclusion"),
        180,
        &[("value", &value)],
    )?;
    Ok(Outcome::new(
        tr!("removed the Defender exclusion \"{0}\"", value),
        Some(json!({ "kind": kind, "value": value })),
    ))
}

fn undo_defender_remove_exclusion(u: Params<'_>, _store: &Store) -> Result<String> {
    let saved = u.get("kind").as_str().unwrap_or("");
    let kind = EXCLUSION_PARAM
        .iter()
        .map(|(_, k)| *k)
        .find(|k| *k == saved)
        .unwrap_or("ExclusionPath");
    let value = u.req_str("value")?;
    ps_ok(
        &format!("Add-MpPreference -{kind} $env:PC_VALUE"),
        &tr!("adding the exclusion back"),
        180,
        &[("value", &value)],
    )?;
    Ok(tr!("added the Defender exclusion \"{0}\" back", value))
}

// --------------------------------------------------------------------------- settings

const TS_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";
const INET_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

fn op_rdp_disable(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let previous = reg_read(TS_KEY, "fDenyTSConnections")?;
    if previous.as_ref().and_then(|s| s.get("data")).and_then(Value::as_i64) == Some(1) {
        return Ok(Outcome::done(tr!("Remote Desktop was already off")));
    }
    reg_write(TS_KEY, "fDenyTSConnections", &json!({ "type": "REG_DWORD", "data": 1 }))?;
    Ok(Outcome::new(
        tr!("turned Remote Desktop off"),
        Some(json!({ "values": { "fDenyTSConnections": previous }, "key": TS_KEY })),
    ))
}

fn op_proxy_disable(_p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let mut saved = Map::new();
    for name in ["ProxyEnable", "AutoConfigURL"] {
        saved.insert(name.into(), reg_read(INET_KEY, name)?.unwrap_or(Value::Null));
    }
    reg_write(INET_KEY, "ProxyEnable", &json!({ "type": "REG_DWORD", "data": 0 }))?;
    reg_delete(INET_KEY, "AutoConfigURL")?;
    Ok(Outcome::new(
        tr!("turned the proxy and the proxy script off for your account"),
        Some(json!({ "values": saved, "key": INET_KEY })),
    ))
}

fn undo_values(u: Params<'_>, _store: &Store) -> Result<String> {
    if let Some(values) = u.object("values")
        && !values.is_empty()
    {
        let key = u.req_str("key")?;
        for (name, snapshot) in values {
            restore_value(&key, name, Some(snapshot))?;
        }
    }
    Ok(tr!("restored the previous settings"))
}

const GUEST_DISABLE: &str = "$u = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }; if (-not $u.Enabled) { \
                             'already' } else { Disable-LocalUser -SID $u.SID; $u.Name }";

fn op_account_disable(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    if p.flag("guest") {
        let out = ps_ok(GUEST_DISABLE, &tr!("disabling the Guest account"), 180, &[])?;
        if out == "already" {
            return Ok(Outcome::done(tr!("the Guest account was already disabled")));
        }
        return Ok(Outcome::new(
            tr!("disabled the Guest account \"{0}\"", out),
            Some(json!({ "sid_suffix": "-501", "name": out })),
        ));
    }
    // The Accounts page names the account by its SID: read again, guarded, changed through NetApi32.
    if !p.str_or_empty("sid").is_empty() {
        return crate::accounts::disable_by_sid(&p);
    }
    let name = p.req_str("name")?;
    let current = std::env::var("USERNAME").unwrap_or_default();
    if name.to_lowercase() == current.to_lowercase() {
        return fail(tr!("you cannot disable the account you are using"));
    }
    crate::accounts::guard_disable_by_name(&name)?;
    ps_ok(
        "Disable-LocalUser -Name $env:PC_NAME",
        &tr!("disabling the account"),
        180,
        &[("name", &name)],
    )?;
    Ok(Outcome::new(
        tr!("disabled the local account \"{0}\"", name),
        Some(json!({ "name": name })),
    ))
}

fn undo_account_disable(u: Params<'_>, _store: &Store) -> Result<String> {
    // Recorded with its SID (the Accounts page): enabled again by SID, whatever its name is now.
    if !u.str_or_empty("sid").is_empty() {
        return crate::accounts::enable_by_sid(&u);
    }
    let name = u.req_str("name")?;
    ps_ok(
        "Enable-LocalUser -Name $env:PC_NAME",
        &tr!("enabling the account"),
        180,
        &[("name", &name)],
    )?;
    Ok(tr!("enabled the account \"{0}\" again", name))
}

const RESTORE_POINT: &str = r#"
$before = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue).Count
Checkpoint-Computer -Description $env:PC_DESC -RestorePointType MODIFY_SETTINGS -WarningAction SilentlyContinue
$after = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue).Count
if ($after -gt $before) { 'created' } else { 'skipped' }
"#;

/// Creates a system restore point (Windows allows one every 24 hours).
pub fn create_restore_point(description: &str) -> Result<String> {
    let out = ps_ok(
        RESTORE_POINT,
        &tr!("creating a restore point"),
        600,
        &[("desc", description)],
    )?;
    if out.ends_with("created") {
        return Ok(tr!("created a system restore point"));
    }
    Ok(
        tr!(
            "Windows did not create a new restore point (it allows one every 24 hours, so a recent one already exists)"
        )
        .to_string(),
    )
}

fn op_restore_point(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let description = {
        let d = p.str_or_empty("description");
        if d.is_empty() { "Vigil".to_string() } else { d }
    };
    Ok(Outcome::done(create_restore_point(&description)?))
}

// --------------------------------------------------------------------------- table

pub(crate) fn builtin() -> Vec<Builtin> {
    vec![
        ("process.terminate", run_fn(op_process_terminate), None, false),
        (
            "process.suspend",
            run_fn(op_process_suspend),
            Some(undo_fn(undo_process_suspend)),
            true,
        ),
        ("process.resume", run_fn(op_process_resume), None, true),
        (
            "service.stop",
            run_fn(op_service_stop),
            Some(undo_fn(undo_service_stop)),
            false,
        ),
        (
            "service.disable",
            run_fn(op_service_disable),
            Some(undo_fn(undo_service_disable)),
            false,
        ),
        (
            "service.delete",
            run_fn(op_service_delete),
            Some(undo_fn(undo_service_delete)),
            false,
        ),
        ("service.start", run_fn(op_service_start), None, false),
        ("service.restart", run_fn(op_service_restart), None, false),
        (
            "service.start_type",
            run_fn(op_service_start_type),
            Some(undo_fn(undo_service_disable)),
            false,
        ),
        (
            "driver.disable",
            run_fn(op_driver_disable),
            Some(undo_fn(undo_service_disable)),
            false,
        ),
        (
            "task.disable",
            run_fn(op_task_disable),
            Some(undo_fn(undo_task_disable)),
            false,
        ),
        (
            "task.delete",
            run_fn(op_task_delete),
            Some(undo_fn(undo_task_delete)),
            false,
        ),
        (
            "task.enable",
            run_fn(op_task_enable),
            Some(undo_fn(undo_task_enable)),
            false,
        ),
        ("task.run", run_fn(op_task_run), None, false),
        (
            "startup.disable",
            run_fn(op_startup_disable),
            Some(undo_fn(undo_registry_value)),
            false,
        ),
        (
            "startup.enable",
            run_fn(op_startup_enable),
            Some(undo_fn(undo_registry_value)),
            false,
        ),
        (
            "registry.delete",
            run_fn(op_registry_delete),
            Some(undo_fn(undo_registry_value)),
            false,
        ),
        (
            "winlogon.restore",
            run_fn(op_winlogon_restore),
            Some(undo_fn(undo_registry_value)),
            false,
        ),
        (
            "appinit.off",
            run_fn(op_appinit_off),
            Some(undo_fn(undo_registry_value)),
            false,
        ),
        ("wmi.remove", run_fn(op_wmi_remove), None, false),
        (
            "file.quarantine",
            run_fn(op_file_quarantine),
            Some(undo_fn(undo_file_quarantine)),
            false,
        ),
        ("program.uninstall", run_fn(op_program_uninstall), None, false),
        (
            "firewall.block",
            run_fn(op_firewall_block),
            Some(undo_fn(undo_firewall_block)),
            false,
        ),
        (
            "firewall.enable",
            run_fn(op_firewall_enable),
            Some(undo_fn(undo_firewall_enable)),
            false,
        ),
        ("defender.scan_file", run_fn(op_defender_scan_file), None, true),
        ("defender.full_scan", run_fn(op_defender_full_scan), None, false),
        ("defender.update", run_fn(op_defender_update), None, false),
        ("defender.realtime_on", run_fn(op_defender_realtime), None, false),
        (
            "defender.remove_exclusion",
            run_fn(op_defender_remove_exclusion),
            Some(undo_fn(undo_defender_remove_exclusion)),
            false,
        ),
        ("rdp.disable", run_fn(op_rdp_disable), Some(undo_fn(undo_values)), false),
        (
            "proxy.disable",
            run_fn(op_proxy_disable),
            Some(undo_fn(undo_values)),
            false,
        ),
        (
            "account.disable",
            run_fn(op_account_disable),
            Some(undo_fn(undo_account_disable)),
            false,
        ),
        ("system.restore_point", run_fn(op_restore_point), None, false),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_enabled_parser() {
        assert!(task_enabled("<Task><Settings><Hidden>true</Hidden></Settings></Task>"));
        assert!(!task_enabled(
            "<Task><Settings><Enabled>false</Enabled></Settings></Task>"
        ));
        assert!(task_enabled(
            "<Task><Triggers><Enabled>false</Enabled></Triggers><Settings></Settings></Task>"
        ));
    }

    #[test]
    fn startup_approved_mapping() {
        let map = |key: &str| approved_location(key).ok().flatten();
        assert_eq!(
            map(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run").as_deref(),
            Some(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")
        );
        assert_eq!(
            map(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run").as_deref(),
            Some(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32")
        );
        assert_eq!(map(r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"), None);
    }

    #[test]
    fn microsoft_tasks_are_refused() {
        let params = json!({"path": "\\Microsoft\\Windows\\Defrag\\", "name": "ScheduledDefrag"});
        assert!(task_full(Params::new(&params)).is_err());
        let params = json!({"path": "\\Vendor", "name": "Updater"});
        assert_eq!(
            task_full(Params::new(&params)).ok().as_deref(),
            Some("\\Vendor\\Updater")
        );
    }
}
