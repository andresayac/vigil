//! Settings > "Start Vigil in the tray when I sign in": the `vigil.autostart` action.
//!
//! It writes one value for the user's account, `HKCU\...\Run\Vigil` = `"<vigil.exe>" --tray
//! --no-elevate`, and clears a Task Manager switch left off for it, so Windows really starts it.
//! Like every change it is confirmed, journaled and can be undone from History: the undo puts both
//! values back as they were. Standard rights are enough (it only touches the user's own keys).

use std::cell::RefCell;
use std::sync::Arc;

use serde_json::{Value, json};
use vigil_actions::{ActionError, Outcome, Store, reg_delete, reg_read, reg_write, register, restore_value};
use vigil_i18n::tr;
use vigil_sys::startup::{OWN_VALUE, own_command, switch_state};

type Result<T> = std::result::Result<T, ActionError>;

pub const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
pub const APPROVED_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

thread_local! {
    /// Tests point the action at a scratch key (only on their own thread).
    static KEYS: RefCell<Option<(String, String)>> = const { RefCell::new(None) };
}

/// (Run key, StartupApproved key) the action works on.
fn keys() -> (String, String) {
    KEYS.with(|k| k.borrow().clone())
        .unwrap_or_else(|| (RUN_KEY.to_string(), APPROVED_KEY.to_string()))
}

#[cfg(test)]
fn redirect(keys: Option<(String, String)>) {
    KEYS.with(|k| *k.borrow_mut() = keys);
}

pub fn register_all() {
    register("vigil.autostart", Arc::new(run), Some(Arc::new(undo)), true);
}

/// The command written to the Run key, for this copy of Vigil.
pub fn command() -> Result<String> {
    let exe = std::env::current_exe().map_err(|e| ActionError::new(tr!("cannot find this program: {0}", e)))?;
    Ok(own_command(&exe))
}

/// Vigil starts at sign-in: the Run value holds this copy's command and its switch is on.
pub fn enabled() -> bool {
    let (run_key, approved_key) = keys();
    let Ok(command) = command() else { return false };
    let written = reg_read(&run_key, OWN_VALUE)
        .ok()
        .flatten()
        .and_then(|v| v.get("data").and_then(Value::as_str).map(str::to_string))
        .is_some_and(|data| data.trim().eq_ignore_ascii_case(&command));
    written && switch_on(&approved_key)
}

/// The Task Manager switch of the value (no value: on).
fn switch_on(approved_key: &str) -> bool {
    let bytes = reg_read(approved_key, OWN_VALUE).ok().flatten().and_then(|v| {
        v.get("data")
            .and_then(|d| d.get("hex"))
            .and_then(Value::as_str)
            .map(unhex)
    });
    switch_state(bytes.as_deref()).0
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .filter_map(|i| text.get(i * 2..i * 2 + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

fn run(params: &Value, _store: &Store, _id: &str) -> Result<Outcome> {
    let on = params
        .get("on")
        .and_then(Value::as_bool)
        .ok_or_else(|| ActionError::new(tr!("Missing value: {0}", "on")))?;
    let (run_key, approved_key) = keys();
    let before = reg_read(&run_key, OWN_VALUE)?;
    let approved_before = reg_read(&approved_key, OWN_VALUE)?;
    let message = if on {
        // Rebuilt here from this program's own path: nothing from the page reaches the registry.
        reg_write(&run_key, OWN_VALUE, &json!({"type": "REG_SZ", "data": command()?}))?;
        // A switch turned off in Task Manager would keep Windows from starting it.
        reg_delete(&approved_key, OWN_VALUE)?;
        tr!("Vigil will start in the tray when you sign in.")
    } else {
        reg_delete(&run_key, OWN_VALUE)?;
        reg_delete(&approved_key, OWN_VALUE)?;
        tr!("Vigil will no longer start when you sign in.")
    };
    Ok(Outcome::new(
        message,
        Some(json!({"before": before, "approved_before": approved_before})),
    ))
}

fn undo(data: &Value, _store: &Store) -> Result<String> {
    let (run_key, approved_key) = keys();
    restore_value(&run_key, OWN_VALUE, data.get("before"))?;
    restore_value(&approved_key, OWN_VALUE, data.get("approved_before"))?;
    Ok(tr!("The sign-in setting is back as it was."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::{SpecExt, spec};

    #[test]
    fn autostart_is_written_and_undone_on_a_scratch_key() {
        let sub = format!(r"Software\VigilTests\autostart-{}", std::process::id());
        let run_key = format!(r"HKCU\{sub}\Run");
        let approved_key = format!(r"HKCU\{sub}\Approved");
        redirect(Some((run_key.clone(), approved_key.clone())));
        register_all();
        let dir = std::env::temp_dir().join(format!("vigil-autostart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).expect("store");
        let command = command().expect("command");
        assert!(command.ends_with("\" --tray --no-elevate"));
        // The scanner leaves out exactly this entry (vigil-scan cannot depend on vigil-sys).
        let exe = std::env::current_exe().expect("test program");
        assert_eq!(vigil_scan::own_autostart_command(&exe), command);

        // Turned off in Task Manager earlier, with an old path in the Run key.
        reg_write(
            &run_key,
            OWN_VALUE,
            &json!({"type": "REG_SZ", "data": r#""C:\Old\vigil.exe" --tray"#}),
        )
        .expect("old value");
        reg_write(
            &approved_key,
            OWN_VALUE,
            &json!({"type": "REG_BINARY", "data": {"hex": "030000000000000000000000"}}),
        )
        .expect("switch");
        assert!(!enabled());

        let on = spec("vigil.autostart", "on", RUN_KEY, "test")
            .params(json!({"on": true}))
            .no_admin();
        let record = vigil_actions::execute(&on, &store, None, "test");
        assert!(record.ok(), "{}", record.message());
        let written = reg_read(&run_key, OWN_VALUE).ok().flatten().expect("written");
        assert_eq!(written["data"], command);
        assert_eq!(
            reg_read(&approved_key, OWN_VALUE).ok().flatten(),
            None,
            "switch cleared"
        );
        assert!(enabled());

        vigil_actions::undo(record.id(), &store).expect("undo");
        let restored = reg_read(&run_key, OWN_VALUE).ok().flatten().expect("restored");
        assert_eq!(restored["data"], r#""C:\Old\vigil.exe" --tray"#);
        assert!(
            reg_read(&approved_key, OWN_VALUE).ok().flatten().is_some(),
            "switch back"
        );

        let off = spec("vigil.autostart", "off", RUN_KEY, "test")
            .params(json!({"on": false}))
            .no_admin();
        let record = vigil_actions::execute(&off, &store, None, "test");
        assert!(record.ok(), "{}", record.message());
        assert_eq!(reg_read(&run_key, OWN_VALUE).ok().flatten(), None);
        assert!(!enabled());
        vigil_actions::undo(record.id(), &store).expect("undo off");
        assert!(reg_read(&run_key, OWN_VALUE).ok().flatten().is_some());

        let missing = spec("vigil.autostart", "?", RUN_KEY, "test").no_admin();
        assert!(!vigil_actions::execute(&missing, &store, None, "test").ok());

        redirect(None);
        vigil_actions::testing::delete_scratch_key(&sub).expect("scratch key deleted");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
