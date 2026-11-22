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
//! - The folder is opened once, never through a link, and held without delete sharing; every check
//!   and change goes through that handle: the descriptor is read with `GetSecurityInfo` and set with
//!   `SetKernelObjectSecurity`, and the move aside is a rename of the handle. What is inside is
//!   opened relative to its folder's handle (`NtCreateFile`, no reparse) and judged the same way;
//!   one untrusted entry moves the whole folder aside, and a link inside is refused. Nothing is
//!   changed by path or recursively (no `icacls /T`).
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
use vigil_sys::svcsec::{Dacl, Descriptor, Object, handle_descriptor, map_generic};
use windows::Wdk::Storage::FileSystem::{FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, NTCREATEFILE_CREATE_OPTIONS};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, SetKernelObjectSecurity,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_DIRECTORY, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows::core::PCWSTR;

use crate::error::{ActionError, Result, fail, io_text};
use crate::nofollow;
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
    untrusted_object(descriptor, Object::Folder, owner, grants)
}

/// [`untrusted_reason`] for a folder or a file inside the data folder.
fn untrusted_object(descriptor: &Descriptor, object: Object, owner: &str, grants: &[&str]) -> Option<String> {
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
        .find(|ace| ace.allow && !trusted(&ace.sid) && map_generic(ace.mask, object) & FOLDER_WRITE != 0)
        .map(|ace| tr!("{0} may add, replace or delete what is inside it", ace.sid))
}

/// How often a data folder another Vigil copy is preparing at the same moment is tried again.
const BUSY_TRIES: u32 = 40;

/// Errors Windows gives when an open that refuses links meets one.
fn is_link_error(error: &std::io::Error) -> bool {
    // ERROR_STOPPED_ON_SYMLINK (681), ERROR_CANT_ACCESS_FILE (1920), ERROR_REPARSE_POINT_ENCOUNTERED (4395).
    matches!(error.raw_os_error(), Some(681 | 1920 | 4395))
}

/// Opens the data folder itself once, never following a link, held without delete sharing so it
/// cannot be renamed or replaced while Vigil checks and changes it. Asks for the rights to change
/// its permissions and to move it aside; with fewer rights (a folder someone else controls) it is
/// still opened to be judged.
fn open_root(root: &Path) -> std::io::Result<nofollow::Handle> {
    let judge = READ_CONTROL | FILE_READ_ATTRIBUTES;
    let tiers = [
        judge | WRITE_DAC | WRITE_OWNER | DELETE | FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_ADD_FILE,
        judge | DELETE,
        FILE_READ_ATTRIBUTES | DELETE,
        FILE_READ_ATTRIBUTES,
    ];
    let mut last = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    for access in tiers {
        let mut tries = 0;
        loop {
            match nofollow::open_path(root, access, nofollow::SHARE_NO_DELETE) {
                Ok(handle) => return Ok(handle),
                // A sharing violation: another copy holds it for a moment.
                Err(error) if error.raw_os_error() == Some(32) && tries < BUSY_TRIES => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    last = error;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
    }
    Err(last)
}

/// Why the folder held by `dir`, or anything inside it, is not private; `None` when all of it is.
/// Everything inside is opened relative to its folder's handle and never through a link: a link
/// inside is an error, not a reason to move the folder.
fn untrusted_tree(
    dir: &nofollow::Handle,
    root: &Path,
    owner: &str,
    grants: &[&str],
    redirect: &str,
) -> Result<Option<String>> {
    let Some(descriptor) = handle_descriptor(dir.raw()) else {
        return Ok(Some(tr!("its permissions cannot be read")));
    };
    if let Some(reason) = untrusted_reason(&descriptor, owner, grants) {
        return Ok(Some(reason));
    }
    let inspect = |path: &Path, e: &std::io::Error| {
        ActionError::new(tr!(
            "Could not inspect the data folder {0}: {1}",
            path.display(),
            io_text(e)
        ))
    };
    let link = |path: &Path| {
        ActionError::new(tr!(
            "{0} is a junction or symbolic link inside the data folder. {1}",
            path.display(),
            redirect
        ))
    };
    let mut pending: Vec<(Option<nofollow::Handle>, PathBuf)> = vec![(None, PathBuf::new())];
    while let Some((handle, relative)) = pending.pop() {
        let folder = handle.as_ref().unwrap_or(dir);
        let names = nofollow::entries(folder).map_err(|e| inspect(&root.join(&relative), &e))?;
        for (name, attributes) in names {
            let path = relative.join(&name);
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(link(&root.join(&path)));
            }
            let access = if attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
                READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE
            } else {
                READ_CONTROL | FILE_READ_ATTRIBUTES
            };
            let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
            let child = match nofollow::open_at(folder, &name, access, share, FILE_OPEN, NTCREATEFILE_CREATE_OPTIONS(0))
            {
                Ok(child) => child,
                Err(e) if is_link_error(&e) => return Err(link(&root.join(&path))),
                // Gone since the folder was listed.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(inspect(&root.join(&path), &e)),
            };
            let found = nofollow::info(&child).map_err(|e| inspect(&root.join(&path), &e))?;
            if nofollow::is_link(&found) {
                return Err(link(&root.join(&path)));
            }
            let object = if nofollow::is_dir(&found) {
                Object::Folder
            } else {
                Object::File
            };
            let reason = match handle_descriptor(child.raw()) {
                Some(descriptor) => untrusted_object(&descriptor, object, owner, grants),
                None => Some(tr!("its permissions cannot be read")),
            };
            if let Some(reason) = reason {
                return Ok(Some(format!("{}: {reason}", path.display())));
            }
            if nofollow::is_dir(&found) {
                pending.push((Some(child), path));
            }
        }
    }
    Ok(None)
}

/// Sets the private descriptor on the held folder itself (owner and a protected DACL) through the
/// handle. Nothing is propagated by path: what is inside was judged by handle and inherits from it.
fn restrict(dir: &nofollow::Handle, root: &Path, sddl: &str, owner: &str, grants: &[&str]) -> Result<()> {
    let failed = |problem: String| {
        ActionError::new(tr!(
            "The data folder {0} could not be fully restricted to administrators ({1}).",
            root.display(),
            problem
        ))
    };
    let text = wide(sddl);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `text` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor freed below.
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(text.as_ptr()), 1, &mut sd, None) }
        .map_err(|e| failed(e.message()))?;
    // The SDDL's "P" protects the DACL: nothing is inherited from the parent from now on.
    // SAFETY: the handle is open with WRITE_DAC and WRITE_OWNER; `sd` is a valid descriptor for
    // the call. Setting it on the handle changes this folder only.
    let result = unsafe {
        SetKernelObjectSecurity(
            dir.raw(),
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        )
    };
    // SAFETY: `sd` came from ConvertStringSecurityDescriptorToSecurityDescriptorW and is freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    result.map_err(|e| failed(e.message()))?;
    match handle_descriptor(dir.raw()) {
        Some(descriptor) => match untrusted_reason(&descriptor, owner, grants) {
            Some(reason) => Err(failed(reason)),
            None => Ok(()),
        },
        None => Err(failed(tr!("its permissions cannot be read"))),
    }
}

/// Renames the held folder (or file) to `<name>.untrusted-<time>` next to it (a free name),
/// deleting nothing. The rename goes through the handle: what moves is what was judged.
fn move_aside(held: &nofollow::Handle, root: &Path) -> Result<PathBuf> {
    let name = root
        .file_name()
        .map_or_else(|| APP_FOLDER.into(), |n| n.to_string_lossy().into_owned());
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let parent = root.parent().unwrap_or(root);
    let mut n = 1;
    loop {
        let candidate = if n == 1 {
            format!("{name}.untrusted-{stamp}")
        } else {
            format!("{name}.untrusted-{stamp}-{n}")
        };
        let aside = parent.join(&candidate);
        match nofollow::rename_here(held, &candidate) {
            Ok(()) => return Ok(aside),
            // ERROR_FILE_EXISTS (80), ERROR_ALREADY_EXISTS (183): the next name.
            Err(e) if matches!(e.raw_os_error(), Some(80 | 183)) && n < 100 => n += 1,
            Err(e) => {
                return fail(tr!(
                    "could not move {0} aside to {1}: {2}",
                    root.display(),
                    aside.display(),
                    io_text(&e)
                ));
            }
        }
    }
}

/// Creates the folder with its private descriptor and opens it like an existing one.
fn create_private(root: &Path, sddl: &str) -> Result<nofollow::Handle> {
    create_with_sddl(root, sddl)?;
    open_root(root).map_err(|e| {
        ActionError::new(tr!(
            "Could not inspect the data folder {0}: {1}",
            root.display(),
            io_text(&e)
        ))
    })
}

static PROBE_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Vigil can create (and delete) a file in the held folder.
fn probe(dir: &nofollow::Handle) -> std::io::Result<()> {
    let name = format!(
        ".write-test-{}-{}",
        std::process::id(),
        PROBE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let file = nofollow::open_at(
        dir,
        &name,
        FILE_GENERIC_WRITE | DELETE,
        FILE_SHARE_MODE(0),
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    )?;
    nofollow::delete_on_close(file.raw())
}

/// Makes `root` a folder private to `owner` and `grants` (see the module notes). Returns what was
/// moved aside, if anything; an error when the folder cannot be made private.
///
/// The folder is opened once (never through a link) and held without delete sharing; every check
/// and change after that goes through the handle, so swapping the path for a link changes nothing.
pub(crate) fn prepare_private_dir(root: &Path, owner: &str, grants: &[&str]) -> Result<Option<Moved>> {
    let redirect = tr!("Remove it before using Vigil: someone may be trying to redirect its files.");
    let key = root.to_string_lossy().to_lowercase();
    if !is_reparse_point(root) && root.is_dir() && LOCKED_DIRS.lock().is_ok_and(|locked| locked.contains(&key)) {
        return Ok(None);
    }
    let inspect = |e: &std::io::Error| {
        ActionError::new(tr!(
            "Could not inspect the data folder {0}: {1}",
            root.display(),
            io_text(e)
        ))
    };
    let sddl = private_sddl(owner, grants);
    let mut moved = None;
    let held = match open_root(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_private(root, &sddl)?,
        Err(e) => return Err(inspect(&e)),
        Ok(held) => {
            let found = nofollow::info(&held).map_err(|e| inspect(&e))?;
            if nofollow::is_link(&found) {
                return fail(tr!("{0} is a junction or symbolic link. {1}", root.display(), redirect));
            }
            let reason = if nofollow::is_dir(&found) {
                untrusted_tree(&held, root, owner, grants, &redirect)?
            } else {
                Some(tr!("it is a file, not a folder"))
            };
            match reason {
                Some(reason) => {
                    let aside = move_aside(&held, root)?;
                    drop(held);
                    let created = create_private(root, &sddl)?;
                    moved = Some(Moved {
                        root: root.to_path_buf(),
                        aside,
                        reason,
                    });
                    created
                }
                None => held,
            }
        }
    };
    let found = nofollow::info(&held).map_err(|e| inspect(&e))?;
    if nofollow::is_link(&found) || !nofollow::is_dir(&found) {
        return fail(tr!("{0} is a junction or symbolic link. {1}", root.display(), redirect));
    }
    restrict(&held, root, &sddl, owner, grants)?;
    if let Err(e) = probe(&held) {
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
