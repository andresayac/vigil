//! The disk cleanup actions. They live here
//! because they join two crates: the cleanup primitives of vigil-maint and the action engine of
//! vigil-actions, which journals them like every other change.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use vigil_actions::{ActionError, Outcome, Store, register};
use vigil_i18n::tr;
use vigil_maint::storage::{self, NeverCancel, format_size, no_progress};

type Result<T> = std::result::Result<T, ActionError>;

pub fn register_all() {
    register("storage.clean", Arc::new(clean), None, false);
    register("storage.empty_bin", Arc::new(empty_bin), None, false);
    register("storage.recycle", Arc::new(recycle), None, false);
    register(
        "storage.recycle_duplicates",
        Arc::new(crate::duplicates::recycle_copies),
        None,
        false,
    );
}

fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Absolute path with `\` separators and no `.` / `..` parts (a lexical normalization, like Windows' own path rules).
fn normpath(path: &str) -> String {
    let path = path.replace('/', "\\");
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('\\') {
        match part {
            "" | "." if !parts.is_empty() => {}
            ".." => {
                if parts.len() > 1 {
                    parts.pop();
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("\\");
    if joined.ends_with(':') {
        format!("{joined}\\")
    } else {
        joined
    }
}

fn in_dir(path: &str, folder: &str) -> bool {
    let folder = folder.trim_end_matches('\\').to_lowercase();
    let path = path.to_lowercase();
    path == folder || path.starts_with(&format!("{folder}\\"))
}

/// The Windows folder. From Windows (`GetSystemWindowsDirectoryW`), not `%SystemRoot%`, which a user's environment can override.
fn windir() -> String {
    vigil_sys::paths::windows_dir().display().to_string()
}

fn count(value: u64) -> String {
    crate::requests::thousands(value)
}

fn clean(params: &Value, _store: &Store, _id: &str) -> Result<Outcome> {
    let keys: Vec<&str> = params
        .get("keys")
        .and_then(Value::as_array)
        .map(|k| k.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    // The targets are rebuilt here: only keys Vigil itself defines can be cleaned.
    let mut targets: Vec<_> = storage::cleanup_targets(None)
        .into_iter()
        .filter(|t| keys.contains(&t.key.as_str()))
        .collect();
    if targets.is_empty() {
        return Ok(Outcome::done(tr!("nothing to clean")));
    }
    for target in &mut targets {
        target.selected = true;
    }
    let result = storage::clean(&targets, &no_progress, &NeverCancel);
    let mut message = tr!(
        "freed {0} ({1} files)",
        format_size(result.freed as f64),
        count(result.deleted)
    );
    if result.skipped > 0 {
        message.push_str(&tr!("; {0} files in use were left", count(result.skipped)));
    }
    if !result.errors.is_empty() {
        let first: Vec<&str> = result.errors.iter().take(3).map(String::as_str).collect();
        message.push_str(&tr!(". Problems: {0}", first.join("; ")));
    }
    Ok(Outcome::done(message))
}

fn empty_bin(_params: &Value, _store: &Store, _id: &str) -> Result<Outcome> {
    let (size, items) = storage::recycle_bin_size();
    storage::empty_recycle_bin().map_err(|e| ActionError::new(e.to_string()))?;
    Ok(Outcome::done(tr!(
        "emptied the Recycle Bin ({0} items, {1})",
        count(items),
        format_size(size as f64)
    )))
}

const NEVER_RECYCLE: [&str; 4] = ["pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log.tmp"];

fn recycle(params: &Value, store: &Store, _id: &str) -> Result<Outcome> {
    let paths: Vec<String> = params
        .get("paths")
        .and_then(Value::as_array)
        .map(|p| p.iter().filter_map(Value::as_str).map(normpath).collect())
        .unwrap_or_default();
    if paths.is_empty() {
        return Err(ActionError::new(tr!("no files were chosen")));
    }
    let own = store.root().to_string_lossy().to_lowercase();
    let windows = windir();
    for path in &paths {
        let low = path.to_lowercase();
        let file = std::path::Path::new(path);
        if !file.is_absolute() || !file.exists() {
            return Err(ActionError::new(tr!("{0} no longer exists", path)));
        }
        let is_root = file.parent().is_none() || low.len() <= 3;
        if NEVER_RECYCLE.contains(&basename(&low)) || in_dir(path, &windows) || low.starts_with(&own) || is_root {
            return Err(ActionError::new(tr!(
                "{0} belongs to Windows or to Vigil and is not deleted from here",
                path
            )));
        }
        // The real path, resolved through a handle opened without following a link at its last
        // part: a folder on the way swapped for a link (to the Windows folder, say) changes it.
        let real = storage::resolved_path(file)
            .map(|real| normpath(&real.to_string_lossy()))
            .ok_or_else(|| ActionError::new(tr!("{0} no longer exists", path)))?;
        // Short (8.3) names are expanded first; a junction keeps its name, so a link still shows.
        let expected = normpath(&storage::long_path(file).to_string_lossy());
        if !real.eq_ignore_ascii_case(&expected) {
            return Err(ActionError::new(tr!(
                "{0} is now reached through a link ({1}); nothing was removed",
                path,
                real
            )));
        }
        if in_dir(&real, &windows) || real.to_lowercase().starts_with(&own) {
            return Err(ActionError::new(tr!(
                "{0} belongs to Windows or to Vigil and is not deleted from here",
                real
            )));
        }
    }
    let total: u64 = paths
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum();
    let list: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
    storage::send_to_recycle_bin(&list).map_err(|e| ActionError::new(tr!("the Recycle Bin refused it: {0}", e)))?;
    let what = if paths.len() == 1 {
        basename(&paths[0]).to_string()
    } else {
        tr!("{0} items", paths.len())
    };
    Ok(Outcome::done(tr!(
        "moved {0} ({1}) to the Recycle Bin; restore it from there if needed",
        what,
        format_size(total as f64)
    )))
}
