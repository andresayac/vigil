//! Duplicate files (the Storage page): the search, the request that sends chosen copies to the
//! Recycle Bin, and the action that does it.
//!
//! The page only names copies; the plan accepts a path only when the last search found it, keeps
//! at least one copy of every group, and hands the action the group's size and SHA-256. The action
//! reads every file again through one handle opened without following a link, and checks the
//! real path Windows resolves it to: a folder swapped for a link (a junction to Program Files, say)
//! changes it, and the copy is refused. The real path must not be Windows', a program's, Vigil's
//! or another account's. A copy moves only when it is still byte-identical to a different file
//! that stays (not another hard link of it). Nothing is deleted permanently: copies go to the
//! Recycle Bin, where they can be restored.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use serde_json::{Value, json};
use vigil_actions::{ActionError, Outcome, Store};
use vigil_i18n::tr;
use vigil_maint::storage::{self, DupGroup, DupOptions, DupScan, format_size};

use crate::planner::{SpecExt, spec};
use crate::requests::{Plan, size_text, thousands};
use crate::state::AppState;

/// The most copies one request may name.
pub const MAX_PATHS: usize = 1_000;
const MIB: u64 = 1 << 20;

/// Where a search starts when the page has not chosen a folder: the user's profile.
pub fn default_folder() -> String {
    std::env::var("USERPROFILE").unwrap_or_default()
}

/// Folders a search never enters: Vigil's own data folders.
fn own_folders(st: &AppState) -> Vec<PathBuf> {
    let mut out = vec![st.root.clone()];
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        out.push(PathBuf::from(local).join("Vigil"));
    }
    out
}

/// Searches `root` for duplicates of at least `min_mb` MB (the groups are remembered: a request is
/// checked against them).
pub fn find(st: &AppState, root: &str, min_mb: u64, progress: &(dyn Fn(&str) + Sync)) -> Result<DupScan, String> {
    let path = PathBuf::from(root.trim());
    if !path.is_absolute() || !path.is_dir() {
        return Err(tr!("Choose a folder that exists."));
    }
    if storage::in_system_folder(&path) {
        return Err(tr!(
            "Windows' folder, the program folders and ProgramData are not searched: removing a copy there can break Windows or a program."
        ));
    }
    let cancel = st.dupes_cancel.clone();
    cancel.store(false, Ordering::Relaxed);
    let options = DupOptions {
        // 0 MB compares every file; the minimum stays at one byte (empty files are all alike).
        min_size: (min_mb.min(100_000) * MIB).max(1),
        skip: own_folders(st),
        ..Default::default()
    };
    let scan = storage::find_duplicates(&path, &options, progress, &*cancel).map_err(|e| e.to_string())?;
    st.lock().duplicates = scan.groups.clone();
    Ok(scan)
}

pub fn cancel(st: &AppState) {
    st.dupes_cancel.store(true, Ordering::Relaxed);
}

fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Rebuilds "send these copies to the Recycle Bin" from the last search: every path must be a
/// copy it found, and every group keeps at least one copy.
pub fn plan(paths: &[String], groups: &[DupGroup]) -> Result<Plan, String> {
    if paths.is_empty() || paths.len() > MAX_PATHS {
        return Err(tr!("Choose the copies to remove."));
    }
    let mut chosen: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for path in paths {
        let (index, file) = groups
            .iter()
            .enumerate()
            .find_map(|(i, g)| {
                g.files
                    .iter()
                    .find(|f| f.path.eq_ignore_ascii_case(path))
                    .map(|f| (i, f))
            })
            .ok_or(tr!("Only copies found by the last search can be removed from here."))?;
        let list = chosen.entry(index).or_default();
        if !list.iter().any(|p| p.eq_ignore_ascii_case(&file.path)) {
            list.push(file.path.clone());
        }
    }
    let mut params = Vec::new();
    let (mut count, mut total) = (0u64, 0u64);
    for (index, remove) in &chosen {
        let group = &groups[*index];
        let keep: Vec<String> = group
            .files
            .iter()
            .filter(|f| !remove.iter().any(|r| r.eq_ignore_ascii_case(&f.path)))
            .map(|f| f.path.clone())
            .collect();
        if keep.is_empty() {
            return Err(tr!(
                "Keep at least one copy of {0}: every copy of it was chosen.",
                base_name(&group.files[0].path)
            ));
        }
        count += remove.len() as u64;
        total += group.size * remove.len() as u64;
        params.push(json!({
            "size": group.size,
            "sha256": group.sha256,
            "keep": keep,
            "remove": remove,
        }));
    }
    let target = if count == 1 {
        let one = chosen
            .values()
            .next()
            .and_then(|l| l.first())
            .cloned()
            .unwrap_or_default();
        format!("{one} ({})", size_text(total))
    } else {
        tr!("{0} copies ({1})", thousands(count), size_text(total))
    };
    let spec = spec(
        "storage.recycle_duplicates",
        tr!("Send duplicate copies to the Recycle Bin"),
        target,
        tr!(
            "Each copy is read again and moved only if it is still identical to a copy that stays. The copies go to the Recycle Bin: the space is freed when the bin is emptied, and until then you can restore them from it."
        ),
    )
    .params(json!({"groups": params}))
    .group("remove")
    .destructive()
    .irreversible()
    .no_admin()
    .warning(&tr!(
        "Some programs expect their own copy of a file in their own folder (game data, projects, libraries): remove copies there only if you know the program does not need them."
    ));
    Ok(Plan::Run { spec, item: None })
}

/// Absolute path with `\` separators and no `.` or `..` parts.
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
    parts.join("\\")
}

fn inside(path: &str, folder: &Path) -> bool {
    let folder = folder.to_string_lossy().trim_end_matches('\\').to_lowercase();
    let path = path.to_lowercase();
    !folder.is_empty() && (path == folder || path.starts_with(&format!("{folder}\\")))
}

/// Vigil's data folders, as written and as their real paths.
fn vigil_folders(store: &Store) -> Vec<PathBuf> {
    let mut out = vec![store.root().to_path_buf()];
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        out.push(PathBuf::from(local).join("Vigil"));
    }
    let real: Vec<PathBuf> = out.iter().filter_map(|f| storage::resolved_path(f)).collect();
    out.extend(real);
    out
}

/// Reads `path` again for the action: its real path must be `path` itself (no link in its
/// folders) and not Windows', a program's, Vigil's, a drive root or another account's.
fn verified(path: &str, store: &Store) -> Result<storage::CheckedFile, ActionError> {
    let file = storage::check_file(Path::new(path))
        .map_err(|e| ActionError::new(tr!("{0} changed since the search or cannot be read: {1}", path, e)))?;
    let real = normpath(&file.real_path);
    // Short (8.3) names are expanded first; a junction keeps its name, so a link still shows.
    let expected = normpath(&storage::long_path(Path::new(path)).to_string_lossy());
    if !real.eq_ignore_ascii_case(&expected) {
        return Err(ActionError::new(tr!(
            "{0} is now reached through a link ({1}); nothing was removed",
            path,
            real
        )));
    }
    let real_path = Path::new(&real);
    if real.len() <= 3
        || storage::in_system_folder(real_path)
        || storage::in_other_profile(real_path)
        || vigil_folders(store).iter().any(|folder| inside(&real, folder))
    {
        return Err(ActionError::new(tr!(
            "{0} belongs to Windows, a program, Vigil or another account and is not deleted from here",
            real
        )));
    }
    Ok(file)
}

/// Checks one path the action may touch: absolute, local, not Windows' or Vigil's.
fn checked(path: &str, store: &Store) -> Result<String, ActionError> {
    let path = normpath(path);
    let file = Path::new(&path);
    if !file.is_absolute() || path.starts_with(r"\\") || file.parent().is_none() || path.len() <= 3 {
        return Err(ActionError::new(tr!("not a full local path: {0}", path)));
    }
    let local_vigil = std::env::var_os("LOCALAPPDATA").map(|l| PathBuf::from(l).join("Vigil"));
    if storage::in_system_folder(file)
        || inside(&path, store.root())
        || local_vigil.is_some_and(|folder| inside(&path, &folder))
    {
        return Err(ActionError::new(tr!(
            "{0} belongs to Windows, a program or Vigil and is not deleted from here",
            path
        )));
    }
    Ok(path)
}

fn text_list(group: &Value, key: &str) -> Vec<String> {
    group
        .get(key)
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

/// `storage.recycle_duplicates`: every group is checked first (a kept copy still identical, every
/// chosen copy still identical to it); only then are the copies moved to the Recycle Bin, all
/// together.
pub fn recycle_copies(params: &Value, store: &Store, _id: &str) -> Result<Outcome, ActionError> {
    recycle_copies_with(params, store, &|paths| {
        storage::send_to_recycle_bin(paths).map_err(|e| ActionError::new(tr!("the Recycle Bin refused it: {0}", e)))
    })
}

/// [`recycle_copies`] with another way to move the files (tests use a fake Recycle Bin).
pub fn recycle_copies_with(
    params: &Value,
    store: &Store,
    recycle: &dyn Fn(&[PathBuf]) -> Result<(), ActionError>,
) -> Result<Outcome, ActionError> {
    let groups: Vec<&Value> = params
        .get("groups")
        .and_then(Value::as_array)
        .map(|g| g.iter().collect())
        .unwrap_or_default();
    let mut moves: Vec<PathBuf> = Vec::new();
    let mut total = 0u64;
    for group in groups {
        let size = group.get("size").and_then(Value::as_u64).unwrap_or(0);
        let sha = group
            .get("sha256")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        let remove = text_list(group, "remove");
        let keep = text_list(group, "keep");
        if remove.is_empty() {
            continue;
        }
        if sha.len() != 64 || size == 0 {
            return Err(ActionError::new(tr!("the copies to compare are not described")));
        }
        let keep: Vec<String> = keep.iter().map(|p| checked(p, store)).collect::<Result<_, _>>()?;
        let remove: Vec<String> = remove.iter().map(|p| checked(p, store)).collect::<Result<_, _>>()?;
        if remove.iter().any(|r| keep.iter().any(|k| k.eq_ignore_ascii_case(r))) {
            return Err(ActionError::new(tr!("a copy cannot be both kept and removed")));
        }
        let same = |file: &storage::CheckedFile| file.size == size && file.sha256 == sha;
        // A copy that stays must still be there, identical, and reached without a link: otherwise
        // removing the others would lose the content.
        let kept: Vec<storage::CheckedFile> = keep
            .iter()
            .filter_map(|k| verified(k, store).ok())
            .filter(|file| same(file))
            .collect();
        if kept.is_empty() {
            return Err(ActionError::new(tr!(
                "no identical copy of {0} remains; nothing was removed",
                base_name(&remove[0])
            )));
        }
        for path in &remove {
            let file = verified(path, store)?;
            if !same(&file) {
                return Err(ActionError::new(tr!(
                    "{0} changed since the search or cannot be read; nothing was removed",
                    path
                )));
            }
            // Another name of a kept file is the same file: removing it frees nothing, and the
            // content must stay in a different file.
            if kept.iter().all(|k| k.file_id == file.file_id) {
                return Err(ActionError::new(tr!(
                    "{0} is the same file as the copy that stays (a hard link); nothing was removed",
                    path
                )));
            }
            total += size;
            moves.push(PathBuf::from(path));
        }
    }
    if moves.is_empty() {
        return Err(ActionError::new(tr!("no copies were chosen")));
    }
    recycle(&moves)?;
    Ok(Outcome::done(tr!(
        "moved {0} duplicate copies ({1}) to the Recycle Bin; restore them from there if needed",
        thousands(moves.len() as u64),
        format_size(total as f64)
    )))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::sync::atomic::AtomicUsize;

    use vigil_maint::storage::{DupFile, NeverCancel};

    use super::*;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// A temporary folder and a journal store of its own, removed when dropped.
    struct Temp {
        base: PathBuf,
        store: Store,
    }

    impl Temp {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let base = std::env::temp_dir().join(format!("vigil-dup-op-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(base.join("files")).unwrap();
            let store = Store::open(&base.join("data")).unwrap();
            Self { base, store }
        }
        fn file(&self, name: &str, data: &[u8]) -> String {
            let path = self.base.join("files").join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, data).unwrap();
            path.to_string_lossy().into_owned()
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            if self.base.starts_with(std::env::temp_dir()) {
                let _ = fs::remove_dir_all(&self.base);
            }
        }
    }

    fn group_of(paths: &[&str], size: u64, sha: &str) -> DupGroup {
        DupGroup {
            size,
            sha256: sha.into(),
            files: paths
                .iter()
                .map(|p| DupFile {
                    path: (*p).into(),
                    modified_ms: 0,
                    created_ms: 0,
                })
                .collect(),
            wasted: size * (paths.len() as u64 - 1),
        }
    }

    #[test]
    fn the_plan_takes_only_found_copies_and_keeps_one_of_each() {
        let sha = "a".repeat(64);
        let groups = [group_of(&[r"C:\Users\jdoe\a.bin", r"C:\Users\jdoe\b.bin"], 2048, &sha)];
        let Plan::Run { spec, .. } = plan(&[r"c:\users\jdoe\B.BIN".into()], &groups).unwrap() else {
            panic!("a run plan")
        };
        assert_eq!(spec.op, "storage.recycle_duplicates");
        assert!(spec.destructive && !spec.reversible && !spec.admin);
        let group = &spec.params["groups"][0];
        assert_eq!(group["keep"], json!([r"C:\Users\jdoe\a.bin"]));
        assert_eq!(
            group["remove"],
            json!([r"C:\Users\jdoe\b.bin"]),
            "the path the search found"
        );
        assert_eq!(group["sha256"], json!(sha));

        let every = [r"C:\Users\jdoe\a.bin".to_string(), r"C:\Users\jdoe\b.bin".to_string()];
        assert!(plan(&every, &groups).is_err(), "the last copy is never removed");
        assert!(plan(&[r"C:\Users\jdoe\other.bin".into()], &groups).is_err());
        assert!(plan(&[], &groups).is_err());
    }

    #[test]
    fn copies_move_only_while_identical_to_a_kept_copy() {
        let temp = Temp::new();
        let data = vec![7u8; 4096];
        let keep = temp.file("keep.bin", &data);
        let copy = temp.file(r"sub\copy.bin", &data);
        let (size, sha) = storage::file_sha256(Path::new(&keep)).unwrap();
        let moved: RefCell<Vec<PathBuf>> = RefCell::new(Vec::new());
        let fake = |paths: &[PathBuf]| -> Result<(), ActionError> {
            moved.borrow_mut().extend(paths.iter().cloned());
            Ok(())
        };
        let params = json!({"groups": [{"size": size, "sha256": sha, "keep": [keep], "remove": [copy]}]});
        let outcome = recycle_copies_with(&params, &temp.store, &fake).unwrap();
        assert!(outcome.message.contains("Recycle Bin"), "{}", outcome.message);
        assert_eq!(moved.borrow().as_slice(), &[PathBuf::from(&copy)]);

        // The copy changed after the search: nothing moves.
        moved.borrow_mut().clear();
        fs::write(&copy, vec![8u8; 4096]).unwrap();
        assert!(recycle_copies_with(&params, &temp.store, &fake).is_err());
        // The kept copy is gone: removing the other would lose the content.
        fs::write(&copy, &data).unwrap();
        fs::remove_file(&keep).unwrap();
        assert!(recycle_copies_with(&params, &temp.store, &fake).is_err());
        assert!(moved.borrow().is_empty());
        // A copy named as both kept and removed.
        let both = json!({"groups": [{"size": size, "sha256": sha, "keep": [copy], "remove": [copy]}]});
        assert!(recycle_copies_with(&both, &temp.store, &fake).is_err());
    }

    #[test]
    fn links_and_protected_folders_are_refused() {
        let temp = Temp::new();
        let data = vec![3u8; 2048];
        let keep = temp.file("keep.bin", &data);
        let (size, sha) = storage::file_sha256(Path::new(&keep)).unwrap();
        let fake = |_: &[PathBuf]| -> Result<(), ActionError> { panic!("nothing may move") };
        // A junction named as a copy.
        let target = temp.base.join("target");
        fs::create_dir_all(&target).unwrap();
        let link = temp.base.join(r"files\link");
        let cmd = PathBuf::from(std::env::var("SystemRoot").unwrap()).join(r"System32\cmd.exe");
        let status = std::process::Command::new(&cmd)
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let params =
            json!({"groups": [{"size": size, "sha256": sha, "keep": [keep], "remove": [link.to_string_lossy()]}]});
        assert!(recycle_copies_with(&params, &temp.store, &fake).is_err());
        let _ = fs::remove_dir(&link);

        // A parent folder swapped for a junction after the search: the copy's real path changes.
        let outside = temp.base.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("same.bin"), &data).unwrap();
        let swapped = temp.base.join(r"files\swapped");
        let made = std::process::Command::new(&cmd)
            .args(["/c", "mklink", "/J"])
            .arg(&swapped)
            .arg(&outside)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(made.success());
        let through = swapped.join("same.bin").to_string_lossy().into_owned();
        let params = json!({"groups": [{"size": size, "sha256": sha, "keep": [keep], "remove": [through]}]});
        let error = recycle_copies_with(&params, &temp.store, &fake).unwrap_err();
        assert!(error.to_string().contains("link"), "{error}");
        let _ = fs::remove_dir(&swapped);

        // Another name (a hard link) of the copy that stays.
        let linked = temp.base.join(r"files\linked.bin");
        fs::hard_link(&keep, &linked).unwrap();
        let params =
            json!({"groups": [{"size": size, "sha256": sha, "keep": [keep], "remove": [linked.to_string_lossy()]}]});
        assert!(
            recycle_copies_with(&params, &temp.store, &fake).is_err(),
            "a hard link of the kept copy"
        );
        let _ = fs::remove_file(&linked);

        // Windows' folder, Vigil's data folder and a drive root.
        let windows = PathBuf::from(std::env::var("SystemRoot").unwrap()).join(r"System32\notepad.exe");
        let own = temp.store.root().join("journal.jsonl");
        for path in [
            windows.to_string_lossy().into_owned(),
            own.to_string_lossy().into_owned(),
            r"C:\".into(),
        ] {
            let params = json!({"groups": [{"size": size, "sha256": sha, "keep": [keep], "remove": [path]}]});
            assert!(recycle_copies_with(&params, &temp.store, &fake).is_err(), "{path}");
        }
        assert!(
            storage::find_duplicates(
                &PathBuf::from(std::env::var("SystemRoot").unwrap()),
                &DupOptions::default(),
                &|_| {},
                &NeverCancel
            )
            .is_err()
        );
    }
}
