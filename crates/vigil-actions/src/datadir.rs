//! Where the journal, quarantine and backups live, and how that folder is locked down.
//!
//! Elevated: `%ProgramData%\Vigil`, restricted to Administrators and SYSTEM so that non-elevated
//! malware cannot tamper with backups that the elevated app restores. Without elevation
//! (read-only mode): `%LOCALAPPDATA%\Vigil`.
//!
//! - A missing folder is created in one step with its permissions (`CreateDirectoryW` with a
//!   security descriptor): owner Administrators, full control for Administrators and SYSTEM only,
//!   nothing inherited from `ProgramData`, where any user may create folders.
//! - An existing folder that someone other than administrators owns, or that grants anyone else a
//!   right to add, delete or replace what is inside or to change its permissions, was not made by
//!   Vigil (or was changed since): it is moved aside to `Vigil.untrusted-<time>`, never deleted,
//!   and a fresh one is created. The window and History say so.
//! - When the folder cannot be made private, the elevated copy does not use it: it runs read-only
//!   (the local folder, no changes to the system) and says why.

use std::collections::HashSet;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};

use serde_json::{Map, Value, json};
use vigil_i18n::tr;
use vigil_sys::svcsec::{Dacl, Descriptor, Object, file_descriptor, map_generic};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::CreateDirectoryW;
use windows::core::PCWSTR;

use crate::error::{ActionError, Result, fail, io_text};
use crate::runner::{self, ToolResult};
use crate::store::{Record, Store};

pub const APP_FOLDER: &str = "Vigil";
const DATA_DIR_OWNER: &str = "S-1-5-32-544"; // Administrators
const DATA_DIR_GRANTS: [&str; 2] = ["S-1-5-32-544", "S-1-5-18"]; // Administrators, SYSTEM
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// Accounts that may own or control the data folder besides the ones asked for: SYSTEM,
/// Administrators, TrustedInstaller, and CREATOR OWNER (it stands for whoever creates a file
/// inside, which needs a right checked separately).
const ALWAYS_TRUSTED: [&str; 4] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    "S-1-3-0",
];
/// Rights on the folder that let their holder plant, replace or remove what is inside, rename the
/// folder away, or take it over: add a file, add a subfolder, delete anything inside, delete,
/// change the permissions, take ownership.
const FOLDER_WRITE: u32 = 0x0002 | 0x0004 | 0x0040 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000;
/// The journal's name for the notice that an untrusted folder was moved aside (History).
pub const MOVED_ASIDE_OP: &str = "vigil.data_folder";

static LOCKED_DIRS: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
static WARNING: Mutex<String> = Mutex::new(String::new());
/// The elevated copy could not make its data folder private and runs read-only.
static READ_ONLY: AtomicBool = AtomicBool::new(false);
/// An untrusted folder moved aside, waiting to be written to the journal.
static MOVED: Mutex<Option<Moved>> = Mutex::new(None);

/// A data folder that was moved aside because it was not private.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Moved {
    pub root: PathBuf,
    pub aside: PathBuf,
    pub reason: String,
}

impl Moved {
    fn text(&self) -> String {
        tr!(
            "Programs without administrator rights could change Vigil's data folder {0} ({1}). Vigil moved it \
             to {2}, deleting nothing, and created a new one. The journal and quarantine from before are in \
             the moved folder.",
            self.root.display(),
            self.reason,
            self.aside.display()
        )
    }
}

/// True when the app runs elevated and may change the system (tests can pretend either way). An
/// elevated copy whose data folder could not be made private is read-only: false.
pub fn is_admin() -> bool {
    crate::testing::admin().unwrap_or_else(|| vigil_sys::elevation::is_elevated() && !READ_ONLY.load(Ordering::SeqCst))
}

/// The data folder, created (and when elevated, locked down) if needed. When the elevated folder
/// cannot be made private, Vigil switches to read-only mode and returns the local folder.
pub fn data_dir() -> Result<PathBuf> {
    if is_admin() {
        // From Windows, never `%ProgramData%`: the user's environment could redirect it.
        let root = vigil_sys::paths::program_data().join(APP_FOLDER);
        match prepare_private_dir(&root, DATA_DIR_OWNER, &DATA_DIR_GRANTS) {
            Ok(moved) => {
                if let Some(moved) = moved {
                    set_warning(moved.text());
                    if let Ok(mut pending) = MOVED.lock() {
                        *pending = Some(moved);
                    }
                }
                return Ok(root);
            }
            // A test that pretends to be elevated sees the refusal itself.
            Err(error) if crate::testing::admin().is_some() => return Err(error),
            Err(error) => {
                READ_ONLY.store(true, Ordering::SeqCst);
                set_warning(tr!(
                    "Vigil does not use its data folder because it could not make it private to administrators: \
                     {0} It runs in read-only mode: it analyses the computer but changes nothing. Fix or remove \
                     the folder and start Vigil again.",
                    error
                ));
            }
        }
    }
    let base = vigil_sys::paths::local_app_data()
        .or_else(vigil_sys::paths::profile)
        .ok_or_else(|| ActionError::new(tr!("the user profile folder is unknown")))?;
    let root = base.join(APP_FOLDER);
    fs::create_dir_all(&root)
        .map_err(|e| ActionError::new(tr!("could not create {0}: {1}", root.display(), io_text(&e))))?;
    Ok(root)
}

/// What the window says about the data folder: it was moved aside, or Vigil runs read-only
/// because it could not be made private.
pub fn data_dir_warning() -> Option<String> {
    let text = WARNING.lock().map(|w| w.clone()).unwrap_or_default();
    if text.is_empty() { None } else { Some(text) }
}

/// Writes the notice that an untrusted data folder was moved aside to History, once.
pub fn record_data_dir_notice(store: &Store) {
    let moved = MOVED.lock().ok().and_then(|mut pending| pending.take());
    if let Some(moved) = moved {
        let _ = journal_moved(store, &moved);
    }
}

pub(crate) fn journal_moved(store: &Store, moved: &Moved) -> Result<()> {
    let mut map = Map::new();
    map.insert("id".into(), json!(crate::quarantine::new_id()));
    map.insert("batch".into(), Value::Null);
    map.insert("time".into(), json!(crate::quarantine::now_iso()));
    map.insert("op".into(), json!(MOVED_ASIDE_OP));
    map.insert("label".into(), json!(crate::labels::op_label(MOVED_ASIDE_OP)));
    map.insert("target".into(), json!(moved.root.to_string_lossy()));
    map.insert("item".into(), json!(""));
    map.insert("params".into(), json!({ "aside": moved.aside.to_string_lossy() }));
    map.insert("ok".into(), json!(true));
    map.insert("message".into(), json!(moved.text()));
    map.insert("undo".into(), Value::Null);
    map.insert("undone".into(), json!(false));
    store.append(&Record(map))
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

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The descriptor of a private folder: `owner`, full control for `grants` only (passed down to
/// everything inside), nothing inherited.
pub(crate) fn private_sddl(owner: &str, grants: &[&str]) -> String {
    let mut sddl = format!("O:{owner}D:P");
    for sid in grants {
        sddl.push_str(&format!("(A;OICI;FA;;;{sid})"));
    }
    sddl
}

/// Creates the folder with the security descriptor `sddl` in one step. Fails when it exists.
pub(crate) fn create_with_sddl(path: &Path, sddl: &str) -> Result<()> {
    let failed =
        |e: windows::core::Error| ActionError::new(tr!("could not create {0}: {1}", path.display(), e.message()));
    let text = wide(sddl);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `text` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor freed below.
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(text.as_ptr()), 1, &mut sd, None) }
        .map_err(failed)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    let name = wide(&path.to_string_lossy());
    // SAFETY: `name` is NUL-terminated; `attributes` and the descriptor it points to live until
    // the call returns.
    let result = unsafe { CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&attributes)) };
    // SAFETY: `sd` came from ConvertStringSecurityDescriptorToSecurityDescriptorW and is freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    result.map_err(failed)
}

/// Why a folder with this descriptor is not private to `owner`, `grants` and the system
/// accounts; `None` when it is. Inheritable entries count too: they would apply to what Vigil
/// creates inside.
pub(crate) fn untrusted_reason(descriptor: &Descriptor, owner: &str, grants: &[&str]) -> Option<String> {
    let trusted = |sid: &str| {
        sid.eq_ignore_ascii_case(owner)
            || grants.iter().any(|g| g.eq_ignore_ascii_case(sid))
            || ALWAYS_TRUSTED.iter().any(|t| t.eq_ignore_ascii_case(sid))
    };
    if !trusted(&descriptor.owner) {
        let who = if descriptor.owner.is_empty() {
            "?"
        } else {
            descriptor.owner.as_str()
        };
        return Some(tr!("its owner is {0}, not the administrators", who));
    }
    let aces = match &descriptor.dacl {
        Dacl::Null => return Some(tr!("it has no permissions, so everyone has full control")),
        Dacl::Aces(aces) => aces,
    };
    aces.iter()
        .find(|ace| ace.allow && !trusted(&ace.sid) && map_generic(ace.mask, Object::Folder) & FOLDER_WRITE != 0)
        .map(|ace| tr!("{0} may add, replace or delete what is inside it", ace.sid))
}

fn untrusted(root: &Path, owner: &str, grants: &[&str]) -> Option<String> {
    match file_descriptor(root) {
        Some(descriptor) => untrusted_reason(&descriptor, owner, grants),
        None => Some(tr!("its permissions cannot be read")),
    }
}

/// Renames the folder to `<name>.untrusted-<time>` next to it (a free name), deleting nothing.
fn move_aside(root: &Path) -> Result<PathBuf> {
    let name = root
        .file_name()
        .map_or_else(|| APP_FOLDER.into(), |n| n.to_string_lossy().into_owned());
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let parent = root.parent().unwrap_or(root);
    let mut aside = parent.join(format!("{name}.untrusted-{stamp}"));
    let mut n = 2;
    while fs::symlink_metadata(&aside).is_ok() {
        aside = parent.join(format!("{name}.untrusted-{stamp}-{n}"));
        n += 1;
    }
    fs::rename(root, &aside).map_err(|e| {
        ActionError::new(tr!(
            "could not move {0} aside to {1}: {2}",
            root.display(),
            aside.display(),
            io_text(&e)
        ))
    })?;
    Ok(aside)
}

/// Makes `root` a folder private to `owner` and `grants` (see the module notes). Returns what was
/// moved aside, if anything; an error when the folder cannot be made private.
pub(crate) fn prepare_private_dir(root: &Path, owner: &str, grants: &[&str]) -> Result<Option<Moved>> {
    let redirect = tr!("Remove it before using Vigil: someone may be trying to redirect its files.");
    if is_reparse_point(root) {
        return fail(tr!("{0} is a junction or symbolic link. {1}", root.display(), redirect));
    }
    let key = root.to_string_lossy().to_lowercase();
    if root.is_dir() && LOCKED_DIRS.lock().is_ok_and(|locked| locked.contains(&key)) {
        return Ok(None);
    }
    let sddl = private_sddl(owner, grants);
    let mut moved = None;
    let created = match fs::symlink_metadata(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_with_sddl(root, &sddl)?;
            true
        }
        Err(e) => {
            return fail(tr!(
                "Could not inspect the data folder {0}: {1}",
                root.display(),
                io_text(&e)
            ));
        }
        Ok(meta) => {
            let reason = if meta.is_dir() {
                untrusted(root, owner, grants)
            } else {
                Some(tr!("it is a file, not a folder"))
            };
            match reason {
                Some(reason) => {
                    let aside = move_aside(root)?;
                    create_with_sddl(root, &sddl)?;
                    moved = Some(Moved {
                        root: root.to_path_buf(),
                        aside,
                        reason,
                    });
                    true
                }
                None => false,
            }
        }
    };
    if !created {
        restrict_existing(root, owner, grants, &redirect)?;
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
    if let Ok(mut locked) = LOCKED_DIRS.lock() {
        locked.insert(key);
    }
    Ok(moved)
}

/// A private folder from before: everything inside is reset to inherit from it and owned by
/// `owner` (an earlier version, or a file put there by hand, may have left other entries). Any
/// failure is an error: the folder is not used half restricted.
fn restrict_existing(root: &Path, owner: &str, grants: &[&str], redirect: &str) -> Result<()> {
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
    for args in &steps {
        let result = runner::run_system(args, 120, None).unwrap_or_else(|e| ToolResult::new(1, "", e.to_string()));
        if result.code != 0 {
            let line = runner::first_line(&result.text());
            let problem = if line.is_empty() { tr!("icacls failed") } else { line };
            return fail(tr!(
                "The data folder {0} could not be fully restricted to administrators ({1}).",
                root.display(),
                problem
            ));
        }
    }
    if let Some(reason) = untrusted(root, owner, grants) {
        return fail(tr!(
            "The data folder {0} could not be fully restricted to administrators ({1}).",
            root.display(),
            reason
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_sys::svcsec::parse_descriptor;

    const ME: &str = "S-1-5-21-1000000000-2000000000-3000000000-1001";

    fn reason(sddl: &str) -> Option<String> {
        let descriptor = parse_descriptor(sddl).expect("sddl");
        untrusted_reason(&descriptor, DATA_DIR_OWNER, &DATA_DIR_GRANTS)
    }

    #[test]
    fn a_folder_only_administrators_control_is_trusted() {
        assert_eq!(reason(&private_sddl(DATA_DIR_OWNER, &DATA_DIR_GRANTS)), None);
        // What 2.5 left after icacls, and the same with read access for users and TrustedInstaller.
        assert_eq!(reason("O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"), None);
        assert_eq!(reason("O:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FR;;;BU)"), None);
        assert_eq!(
            reason("O:BAD:P(A;OICI;FA;;;BA)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)"),
            None
        );
        // Denials only take rights away.
        assert_eq!(reason("O:BAD:P(D;OICI;FA;;;BU)(A;OICI;FA;;;BA)"), None);
        // CREATOR OWNER becomes whoever creates a file, which needs a right checked on its own.
        assert_eq!(reason("O:BAD:P(A;OICIIO;FA;;;CO)(A;OICI;FA;;;BA)"), None);
    }

    #[test]
    fn a_folder_others_own_or_may_write_is_not_trusted() {
        let owned = reason(&format!("O:{ME}D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")).expect("owner");
        assert!(owned.contains(ME), "{owned}");
        assert!(reason("O:BAD:NO_ACCESS_CONTROL").is_some());
        for ace in [
            "(A;OICI;FA;;;BU)",             // full control for Users
            "(A;CI;0x4;;;BU)",              // create subfolders (what ProgramData passes down)
            "(A;;0x2;;;WD)",                // add a file, Everyone
            "(A;OICI;GW;;;AU)",             // generic write, Authenticated Users
            "(A;;0x40000;;;IU)",            // change the permissions, INTERACTIVE
            "(A;;0x10000;;;BU)",            // delete (rename the folder away)
            "(A;OICIIO;FA;;;BU)",           // inherited by what Vigil creates inside
            &format!("(A;OICI;FA;;;{ME})"), // a user account
        ] {
            let sddl = format!("O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY){ace}");
            assert!(reason(&sddl).is_some(), "{sddl}");
        }
        // Reading is not writing.
        assert_eq!(reason("O:BAD:P(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"), None);
    }

    #[test]
    fn the_notice_goes_to_history() {
        let root = std::env::temp_dir().join(format!("vigil-notice-{}", crate::quarantine::new_id()));
        let store = Store::open(&root).expect("store");
        let moved = Moved {
            root: PathBuf::from(r"C:\ProgramData\Vigil"),
            aside: PathBuf::from(r"C:\ProgramData\Vigil.untrusted-20260101-120000"),
            reason: "S-1-5-32-545 may add, replace or delete what is inside it".into(),
        };
        journal_moved(&store, &moved).expect("journal");
        let records = store.records();
        assert_eq!(records.len(), 1);
        let record = &records[0].0;
        assert_eq!(record["op"], MOVED_ASIDE_OP);
        assert_eq!(record["ok"], true);
        assert_eq!(record["undo"], Value::Null);
        assert_eq!(
            record["params"]["aside"],
            r"C:\ProgramData\Vigil.untrusted-20260101-120000"
        );
        assert!(record["message"].as_str().unwrap_or("").contains("deleting nothing"));
        assert!(!crate::can_undo(&records[0]));
        let _ = fs::remove_dir_all(&root);
    }
}
