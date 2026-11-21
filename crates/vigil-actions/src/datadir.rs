//! Where the journal, quarantine and backups live, and how that folder is locked down.
//!
//! Elevated: `%ProgramData%\Vigil`, restricted to Administrators and SYSTEM so that non-elevated
//! malware cannot tamper with backups that the elevated app restores. Without elevation
//! (read-only mode): `%LOCALAPPDATA%\Vigil`.

use std::collections::HashSet;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use crate::error::{ActionError, Result, fail, io_text};
use crate::runner::{self, ToolResult};
use vigil_i18n::tr;

pub const APP_FOLDER: &str = "Vigil";
const DATA_DIR_OWNER: &str = "S-1-5-32-544"; // Administrators
const DATA_DIR_GRANTS: [&str; 2] = ["S-1-5-32-544", "S-1-5-18"]; // Administrators, SYSTEM
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

static LOCKED_DIRS: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
static WARNING: Mutex<String> = Mutex::new(String::new());

/// True when the app runs elevated (tests can pretend either way).
pub fn is_admin() -> bool {
    crate::testing::admin().unwrap_or_else(vigil_sys::elevation::is_elevated)
}

/// The data folder, created (and when elevated, locked down) if needed.
pub fn data_dir() -> Result<PathBuf> {
    if is_admin() {
        let base = env_dir("ProgramData").unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        let root = base.join(APP_FOLDER);
        prepare_private_dir(&root, DATA_DIR_OWNER, &DATA_DIR_GRANTS)?;
        Ok(root)
    } else {
        let base = env_dir("LOCALAPPDATA")
            .or_else(|| env_dir("USERPROFILE"))
            .ok_or_else(|| ActionError::new(tr!("the user profile folder is unknown")))?;
        let root = base.join(APP_FOLDER);
        fs::create_dir_all(&root)
            .map_err(|e| ActionError::new(tr!("could not create {0}: {1}", root.display(), io_text(&e))))?;
        Ok(root)
    }
}

/// Set when the data folder could not be fully restricted to administrators (the app shows it).
pub fn data_dir_warning() -> Option<String> {
    let text = WARNING.lock().map(|w| w.clone()).unwrap_or_default();
    if text.is_empty() { None } else { Some(text) }
}

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Junctions and symbolic links (never followed).
pub fn is_reparse_point(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

fn reparse_points_inside(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(folder) = pending.pop() {
        for entry in fs::read_dir(&folder)? {
            let path = entry?.path();
            let meta = fs::symlink_metadata(&path)?;
            if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                found.push(path);
            } else if meta.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(found)
}

pub(crate) fn forget_locked(root: &Path) {
    if let Ok(mut locked) = LOCKED_DIRS.lock() {
        locked.remove(&root.to_string_lossy().to_lowercase());
    }
}

fn set_warning(text: String) {
    if let Ok(mut warning) = WARNING.lock() {
        *warning = text;
    }
}

pub(crate) fn prepare_private_dir(root: &Path, owner: &str, grants: &[&str]) -> Result<()> {
    let redirect = tr!("Remove it before using Vigil: someone may be trying to redirect its files.");
    if is_reparse_point(root) {
        return fail(tr!("{0} is a junction or symbolic link. {1}", root.display(), redirect));
    }
    fs::create_dir_all(root)
        .map_err(|e| ActionError::new(tr!("could not create {0}: {1}", root.display(), io_text(&e))))?;
    let key = root.to_string_lossy().to_lowercase();
    if LOCKED_DIRS.lock().is_ok_and(|locked| locked.contains(&key)) {
        return Ok(());
    }
    // icacls below works recursively and would follow a planted junction out of the folder.
    let links = reparse_points_inside(root).map_err(|e| {
        ActionError::new(tr!(
            "Could not inspect the data folder {0}: {1}",
            root.display(),
            io_text(&e)
        ))
    })?;
    if let Some(link) = links.first() {
        return fail(tr!(
            "{0} is a junction or symbolic link inside the data folder. {1}",
            link.display(),
            redirect
        ));
    }
    let icacls = runner::tool("icacls.exe");
    let root_text = root.to_string_lossy().into_owned();
    let mut folder = vec![
        icacls.clone(),
        root_text.clone(),
        "/inheritance:r".into(),
        "/grant:r".into(),
    ];
    folder.extend(grants.iter().map(|sid| format!("*{sid}:(OI)(CI)F")));
    folder.push("/Q".into());
    let mut steps = vec![
        // The folder: no inherited entries, full control only for Administrators and SYSTEM, passed
        // down to everything created inside it.
        folder,
        // Everything already inside: drop explicit entries and inherit from the folder. (Granting the
        // folder's entries recursively instead would leave every file with an empty ACL: unusable.)
        vec![
            icacls.clone(),
            format!("{root_text}\\*"),
            "/reset".into(),
            "/T".into(),
            "/C".into(),
            "/Q".into(),
        ],
        // Administrators own it all, so no one else keeps the owner's right to change permissions.
        vec![
            icacls,
            root_text,
            "/setowner".into(),
            format!("*{owner}"),
            "/T".into(),
            "/C".into(),
            "/Q".into(),
        ],
    ];
    let empty = fs::read_dir(root)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(true);
    if empty {
        steps.remove(1);
    }
    let mut problem = String::new();
    for args in &steps {
        let result = runner::run_system(args, 120, None).unwrap_or_else(|e| ToolResult::new(1, "", e.to_string()));
        if result.code != 0 && problem.is_empty() {
            let line = runner::first_line(&result.text());
            problem = if line.is_empty() { tr!("icacls failed") } else { line };
        }
    }
    let probe = root.join(format!(".write-test-{}", std::process::id()));
    if let Err(e) = fs::write(&probe, b"").and_then(|()| fs::remove_file(&probe)) {
        return fail(tr!(
            "Vigil cannot write to its data folder {0} ({1}). Check its permissions, or delete the folder so it is \
             created again.",
            root.display(),
            io_text(&e)
        ));
    }
    if !problem.is_empty() {
        set_warning(tr!(
            "The data folder {0} could not be fully restricted to administrators ({1}).",
            root.display(),
            problem
        ));
        return Ok(());
    }
    set_warning(String::new());
    if let Ok(mut locked) = LOCKED_DIRS.lock() {
        locked.insert(key);
    }
    Ok(())
}
