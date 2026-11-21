//! Test seams. Each one only affects the calling thread (Rust tests run in parallel threads) and the
//! app never sets them. They stand in for elevation, live signature checks,
//! the service registry and state, the sleeps while waiting for a service, and the registry keys
//! the startup operations may touch (so the tests act on a scratch key, never on the real Run keys).

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use serde_json::{Map, Value};

use crate::error::Result;
use crate::signature::SignatureInfo;

type SignatureFn = Rc<dyn Fn(&str) -> Option<SignatureInfo>>;
type ServiceRegFn = Rc<dyn Fn(&str) -> Result<Map<String, Value>>>;
type ServiceStatusFn = Rc<dyn Fn(&str) -> Option<String>>;
type ApprovedFn = Rc<dyn Fn(&str) -> Option<String>>;

#[derive(Default)]
struct Seams {
    admin: Option<bool>,
    signature: Option<SignatureFn>,
    service_reg: Option<ServiceRegFn>,
    service_status: Option<ServiceStatusFn>,
    approved: Option<ApprovedFn>,
    editable: Vec<String>,
    settings: Vec<(String, String)>,
    no_sleep: bool,
}

thread_local! {
    static SEAMS: RefCell<Seams> = RefCell::new(Seams::default());
}

/// Pretends the app is (or is not) elevated. `None` asks Windows again.
pub fn set_admin(value: Option<bool>) {
    SEAMS.with(|s| s.borrow_mut().admin = value);
}

/// Replaces the live signature check (return `None` for "could not be checked").
pub fn set_signature(check: Option<SignatureFn>) {
    SEAMS.with(|s| s.borrow_mut().signature = check);
}

/// Replaces the read of `HKLM\SYSTEM\CurrentControlSet\Services\<name>`.
pub fn set_service_reg(read: Option<ServiceRegFn>) {
    SEAMS.with(|s| s.borrow_mut().service_reg = read);
}

/// Replaces the service state query ("running", "stopped"... or `None` when it does not exist).
pub fn set_service_status(query: Option<ServiceStatusFn>) {
    SEAMS.with(|s| s.borrow_mut().service_status = query);
}

/// Replaces the StartupApproved key chosen for a Run key.
pub fn set_approved_location(map: Option<ApprovedFn>) {
    SEAMS.with(|s| s.borrow_mut().approved = map);
}

/// Lets the startup operations edit one more key (exact path, any value). Only keys under
/// `HKCU\Software\VigilTests` are accepted.
pub fn allow_editable_key(key: &str) {
    let low = key.to_lowercase();
    if low.starts_with("hkcu\\software\\vigiltests\\") {
        SEAMS.with(|s| s.borrow_mut().editable.push(low));
    }
}

/// Makes the waits for a service return at once.
pub fn set_no_sleep(value: bool) {
    SEAMS.with(|s| s.borrow_mut().no_sleep = value);
}

/// Clears every seam of this thread.
pub fn reset() {
    SEAMS.with(|s| *s.borrow_mut() = Seams::default());
    crate::runner::set_runner(None);
}

/// Deletes `HKCU\<sub>` with everything below it; refuses anything outside `Software\VigilTests`.
pub fn delete_scratch_key(sub: &str) -> Result<()> {
    crate::registry::delete_scratch_tree(sub)
}

/// The data-folder lock-down with other accounts in place of Administrators (a test cannot count
/// on being elevated). Returns the warning it left, empty when the folder was fully restricted.
pub fn prepare_private_dir_as(root: &Path, owner_sid: &str, grant_sids: &[&str]) -> Result<String> {
    crate::datadir::forget_locked(root);
    crate::datadir::prepare_private_dir(root, owner_sid, grant_sids)?;
    Ok(crate::datadir::data_dir_warning().unwrap_or_default())
}

pub(crate) fn admin() -> Option<bool> {
    SEAMS.with(|s| s.borrow().admin)
}

pub(crate) fn signature() -> Option<SignatureFn> {
    SEAMS.with(|s| s.borrow().signature.clone())
}

pub(crate) fn service_reg() -> Option<ServiceRegFn> {
    SEAMS.with(|s| s.borrow().service_reg.clone())
}

pub(crate) fn service_status() -> Option<ServiceStatusFn> {
    SEAMS.with(|s| s.borrow().service_status.clone())
}

pub(crate) fn approved() -> Option<ApprovedFn> {
    SEAMS.with(|s| s.borrow().approved.clone())
}

pub(crate) fn extra_editable(key: &str, _value: &str) -> bool {
    let low = key.to_lowercase();
    SEAMS.with(|s| s.borrow().editable.contains(&low))
}

pub(crate) fn no_sleep() -> bool {
    SEAMS.with(|s| s.borrow().no_sleep)
}

/// Points one of the optimization settings (`gpu` = per-app GPU preference, `game_mode`) at another
/// key. Only keys under `HKCU\Software\VigilTests` are accepted.
pub fn redirect_setting(which: &str, key: &str) {
    if key.to_lowercase().starts_with("hkcu\\software\\vigiltests\\") {
        SEAMS.with(|s| s.borrow_mut().settings.push((which.to_string(), key.to_string())));
    }
}

pub(crate) fn setting_key(which: &str) -> Option<String> {
    SEAMS.with(|s| {
        s.borrow()
            .settings
            .iter()
            .rev()
            .find(|(w, _)| w == which)
            .map(|(_, k)| k.clone())
    })
}
