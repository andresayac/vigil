//! A cache of the signature collector's results, so a scan only verifies the files that changed.
//!
//! Verifying a signature (catalog lookups for Windows' own files, certificate chains for the rest)
//! is the slowest part of a scan. Most files are the same from one scan to the next, so each
//! result is kept with the identity of the file it describes:
//!
//! - the **SHA-256 of the file's content**, with its size, last-write time and file ID (NTFS index
//!   and volume serial). Times can be set back by any program that can write the file, and an
//!   overwrite in place keeps the file ID, so only the content hash says the bytes are the ones
//!   that were verified. The identity is read before the file is verified and again after it, and
//!   a result is kept only when both match (a file changed while it was checked is not kept);
//! - files larger than [`MAX_HASH_BYTES`], links and other reparse points are never cached;
//! - an entry is trusted for [`MAX_AGE_SECS`] at most, so certificate expiry and revocation are
//!   checked again in time;
//! - the whole cache is dropped when the Windows build (CurrentBuild.UBR) changes, since an update
//!   can change how system files are catalog-signed;
//! - results that say the file could not be read or verified are never kept.
//!
//! Only an elevated copy uses the cache ([`SigCache::open`] returns `None` otherwise). Its file
//! lives in `%ProgramData%\Vigil`, where only administrators can write, so a standard-user process
//! can neither plant a "valid" result nor edit one. A standard copy's data folder can be written by
//! any program the user runs, so it always verifies every file. The file is read with a size cap,
//! never through a link, and replaced by writing a temporary file next to it and renaming it.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::lenient::{Get, lower, str_of};

/// Bump when the stored layout or the collector's fields change.
const VERSION: u32 = 2;
/// The most entries kept (the least recently used are dropped).
pub(crate) const MAX_ENTRIES: usize = 20_000;
/// How long a result is trusted, in seconds (7 days).
pub(crate) const MAX_AGE_SECS: i64 = 7 * 24 * 3600;
/// A cache file larger than this is ignored (it would be far beyond `MAX_ENTRIES`).
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Larger files are verified at every scan (hashing them would cost about as much).
pub(crate) const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;
/// Files hashed at the same time.
const HASH_WORKERS: usize = 4;

/// What identifies one version of a file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Identity {
    pub(crate) size: u64,
    /// Last-write time (FILETIME, 100 ns units).
    pub(crate) written: u64,
    /// Volume serial and file index.
    pub(crate) file_id: String,
    /// SHA-256 of the content (lower-case hex): what really says the file is the same.
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    #[serde(flatten)]
    identity: Identity,
    /// When the file was verified (Unix seconds).
    checked: i64,
    /// When the entry was last used (Unix seconds), for the least-recently-used order.
    used: i64,
    info: Value,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    version: u32,
    build: String,
    entries: BTreeMap<String, Entry>,
}

pub(crate) struct SigCache {
    path: PathBuf,
    build: String,
    now: i64,
    entries: HashMap<String, Entry>,
    /// Identities read for the files that missed, kept for the results that come back.
    pending: HashMap<String, Identity>,
    dirty: bool,
}

impl SigCache {
    /// Opens the cache at `path` (empty when missing, damaged, from another Windows build or
    /// behind a link). `None` when this process is not elevated: its data folder can be written
    /// by any program the user runs, so a cache there could be made to call a file valid.
    pub(crate) fn open(path: &Path) -> Option<Self> {
        if !elevated() {
            return None;
        }
        Some(Self::open_at(path, windows_build(), now()))
    }

    fn open_at(path: &Path, build: String, now: i64) -> Self {
        let entries = read_stored(path)
            .filter(|stored| stored.version == VERSION && stored.build == build)
            .map(|stored| stored.entries.into_iter().collect())
            .unwrap_or_default();
        Self {
            path: path.to_path_buf(),
            build,
            now,
            entries,
            pending: HashMap::new(),
            dirty: false,
        }
    }

    /// The cached results for `paths` (in the same order) when each file is still the one that
    /// was verified, recently. The files are hashed a few at a time.
    pub(crate) fn get_many(&mut self, paths: &[String]) -> Vec<Option<Value>> {
        let identities = identities(paths);
        paths
            .iter()
            .zip(identities)
            .map(|(path, identity)| identity.and_then(|identity| self.lookup(path, identity)))
            .collect()
    }

    /// Keeps fresh results: each file's identity is read again, and a result is kept only when
    /// the file is still exactly the one read before it was verified.
    pub(crate) fn put_many<'v>(&mut self, infos: impl Iterator<Item = &'v Value>) {
        let infos: Vec<&Value> = infos.filter(|info| cacheable(info)).collect();
        let paths: Vec<String> = infos
            .iter()
            .map(|info| info.get("path").map(str_of).unwrap_or_default())
            .collect();
        let after = identities(&paths);
        for (info, identity) in infos.into_iter().zip(after) {
            if let Some(identity) = identity {
                self.put_checked(info, &identity);
            }
        }
    }

    fn lookup(&mut self, path: &str, identity: Identity) -> Option<Value> {
        let key = lower(path);
        let now = self.now;
        let hit = self
            .entries
            .get_mut(&key)
            .filter(|entry| entry.identity == identity && now - entry.checked <= MAX_AGE_SECS && now >= entry.checked)
            .map(|entry| {
                entry.used = now;
                let mut info = entry.info.clone();
                // The path as this scan asked for it (its letter case may differ).
                if let Some(map) = info.as_object_mut() {
                    map.insert("path".into(), Value::String(path.to_string()));
                }
                info
            });
        if hit.is_some() {
            self.dirty = true;
        } else {
            self.pending.insert(key, identity);
        }
        hit
    }

    /// Keeps a fresh result (only results that describe a readable, verified file) when `after`,
    /// the identity read once it was verified, is the one read before.
    fn put_checked(&mut self, info: &Value, after: &Identity) {
        if !cacheable(info) {
            return;
        }
        let key = lower(&info.get("path").map(str_of).unwrap_or_default());
        let Some(identity) = self.pending.remove(&key) else {
            return;
        };
        if &identity != after {
            return;
        }
        self.entries.insert(
            key,
            Entry {
                identity,
                checked: self.now,
                used: self.now,
                info: info.clone(),
            },
        );
        self.dirty = true;
    }

    /// Writes the cache back when something changed: expired entries dropped, then the least
    /// recently used beyond [`MAX_ENTRIES`].
    pub(crate) fn save(mut self) {
        if !self.dirty {
            return;
        }
        let now = self.now;
        self.entries
            .retain(|_, entry| now - entry.checked <= MAX_AGE_SECS && now >= entry.checked);
        if self.entries.len() > MAX_ENTRIES {
            let mut by_use: Vec<(i64, String)> = self.entries.iter().map(|(k, e)| (e.used, k.clone())).collect();
            by_use.sort();
            let drop = by_use.len() - MAX_ENTRIES;
            for (_, key) in by_use.into_iter().take(drop) {
                self.entries.remove(&key);
            }
        }
        let stored = Stored {
            version: VERSION,
            build: self.build.clone(),
            entries: self.entries.into_iter().collect(),
        };
        if let Ok(bytes) = serde_json::to_vec(&stored) {
            let _ = write_replacing(&self.path, &bytes);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// A result worth keeping: the file existed, was read, and its signature was checked.
fn cacheable(info: &Value) -> bool {
    let status = info.at("sig_status").as_str().unwrap_or_default();
    info.at("exists") == &Value::Bool(true)
        && info.get("error").is_none()
        && info.at("is_dir") != &Value::Bool(true)
        && !status.is_empty()
        && !status.eq_ignore_ascii_case("Error")
        && !status.eq_ignore_ascii_case("UnknownError")
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// "26100.2314": CurrentBuild and UBR; empty when unreadable (the cache is then never reused
/// across a read that did return a build).
fn windows_build() -> String {
    use crate::winreg::{self, Hive, View};
    let key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let build = winreg::value(Hive::Hklm, key, "CurrentBuild", View::V64)
        .map(|v| v.as_text())
        .unwrap_or_default();
    let ubr = winreg::value(Hive::Hklm, key, "UBR", View::V64)
        .map(|v| v.as_text())
        .unwrap_or_default();
    format!("{build}.{ubr}")
}

fn is_link(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        fs::symlink_metadata(path).is_ok_and(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }
    #[cfg(not(windows))]
    {
        fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
    }
}

fn read_stored(path: &Path) -> Option<Stored> {
    if is_link(path) || path.parent().is_some_and(is_link) {
        return None;
    }
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Writes `bytes` to a new temporary file next to `path`, flushes it and renames it over `path`.
/// Refuses a target or folder that is a link.
fn write_replacing(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| std::io::Error::other("no folder"))?;
    fs::create_dir_all(parent)?;
    if is_link(parent) || is_link(path) {
        return Err(std::io::Error::other("refusing a link"));
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = parent.join(format!("{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// True when this process runs elevated (the only kind that uses the cache).
fn elevated() -> bool {
    #[cfg(windows)]
    {
        vigil_sys::elevation::is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// The identities of `paths` (same order), read a few files at a time.
fn identities(paths: &[String]) -> Vec<Option<Identity>> {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<Identity>>> = Mutex::new(vec![None; paths.len()]);
    std::thread::scope(|scope| {
        for _ in 0..HASH_WORKERS.min(paths.len()) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(path) = paths.get(index) else { break };
                    let found = identity(path);
                    if let Ok(mut all) = results.lock() {
                        all[index] = found;
                    }
                }
            });
        }
    });
    results.into_inner().unwrap_or_default()
}

/// The identity of the file at `path`: `None` when it cannot be opened (missing, denied), is a
/// folder, a link or another reparse point, is larger than [`MAX_HASH_BYTES`], or changed while it
/// was read.
#[cfg(windows)]
pub(crate) fn identity(path: &str) -> Option<Identity> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    use sha2::{Digest, Sha256};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};

    /// FILE_FLAG_OPEN_REPARSE_POINT: a link is opened itself (and then refused), never followed.
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const SEQUENTIAL_SCAN: u32 = 0x0800_0000;
    const SHARE_ALL: u32 = 0x7;
    const ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    /// FILE_ATTRIBUTE_OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS: reading would download it.
    const ATTRIBUTE_NOT_LOCAL: u32 = 0x1000 | 0x4_0000 | 0x40_0000;

    let mut file = fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_ALL)
        .custom_flags(OPEN_REPARSE_POINT | SEQUENTIAL_SCAN)
        .open(path)
        .ok()?;
    let info = |file: &fs::File| -> Option<BY_HANDLE_FILE_INFORMATION> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is open for the duration of the call; `info` is writable.
        unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }.ok()?;
        Some(info)
    };
    let before = info(&file)?;
    if before.dwFileAttributes & (ATTRIBUTE_DIRECTORY | ATTRIBUTE_REPARSE_POINT | ATTRIBUTE_NOT_LOCAL) != 0 {
        return None;
    }
    let size = (u64::from(before.nFileSizeHigh) << 32) | u64::from(before.nFileSizeLow);
    if size > MAX_HASH_BYTES {
        return None;
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut read_total = 0u64;
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        read_total += read as u64;
        if read_total > size {
            return None;
        }
    }
    let after = info(&file)?;
    let written = |i: &BY_HANDLE_FILE_INFORMATION| {
        (u64::from(i.ftLastWriteTime.dwHighDateTime) << 32) | u64::from(i.ftLastWriteTime.dwLowDateTime)
    };
    let after_size = (u64::from(after.nFileSizeHigh) << 32) | u64::from(after.nFileSizeLow);
    if read_total != size || after_size != size || written(&after) != written(&before) {
        return None;
    }
    Some(Identity {
        size,
        written: written(&before),
        file_id: format!(
            "{:08x}-{:08x}{:08x}",
            before.dwVolumeSerialNumber, before.nFileIndexHigh, before.nFileIndexLow
        ),
        sha256: digest.finalize().iter().map(|b| format!("{b:02x}")).collect(),
    })
}

#[cfg(not(windows))]
pub(crate) fn identity(_path: &str) -> Option<Identity> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vigil-sigcache-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn id(size: u64) -> Identity {
        Identity {
            size,
            written: 133_000_000_000_000_000,
            file_id: "0000abcd-0000000000001234".into(),
            sha256: "ab".repeat(32),
        }
    }

    /// `put_checked` with the identity read before (as `put_many` does when the file is unchanged).
    fn put(cache: &mut SigCache, info: &Value) {
        let key = lower(&info.get("path").map(str_of).unwrap_or_default());
        if let Some(identity) = cache.pending.get(&key).cloned() {
            cache.put_checked(info, &identity);
        } else {
            cache.put_checked(info, &id(0));
        }
    }

    fn info(path: &str, status: &str) -> Value {
        json!({"path": path, "exists": true, "size": 10, "sig_status": status, "signer": "Contoso"})
    }

    #[test]
    fn a_result_is_reused_while_the_file_is_the_same() {
        let dir = temp_dir("reuse");
        let file = dir.join("cache.json");
        let mut cache = SigCache::open_at(&file, "26100.1".into(), 1_000);
        assert!(cache.lookup(r"C:\Tools\a.exe", id(10)).is_none());
        put(&mut cache, &info(r"C:\Tools\a.exe", "Valid"));
        cache.save();

        let mut cache = SigCache::open_at(&file, "26100.1".into(), 2_000);
        let hit = cache.lookup(r"c:\tools\A.EXE", id(10)).expect("hit");
        assert_eq!(hit.at("signer"), &json!("Contoso"));
        assert_eq!(hit.at("path"), &json!(r"c:\tools\A.EXE"), "the path as asked this time");
        // A different size, time or file ID is a different file.
        assert!(cache.lookup(r"C:\Tools\a.exe", id(11)).is_none());
        let mut moved = id(10);
        moved.file_id = "0000abcd-0000000000009999".into();
        assert!(cache.lookup(r"C:\Tools\a.exe", moved).is_none());
        // Same size, time and file ID, other content (an overwrite in place with the time set
        // back): verified again.
        let mut overwritten = id(10);
        overwritten.sha256 = "cd".repeat(32);
        assert!(cache.lookup(r"C:\Tools\a.exe", overwritten).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_results_and_other_windows_builds_are_not_trusted() {
        let dir = temp_dir("expire");
        let file = dir.join("cache.json");
        let mut cache = SigCache::open_at(&file, "26100.1".into(), 1_000);
        cache.lookup(r"C:\a.exe", id(1));
        put(&mut cache, &info(r"C:\a.exe", "Valid"));
        cache.save();
        let mut later = SigCache::open_at(&file, "26100.1".into(), 1_000 + MAX_AGE_SECS + 1);
        assert!(later.lookup(r"C:\a.exe", id(1)).is_none(), "too old");
        let mut updated = SigCache::open_at(&file, "26100.2".into(), 2_000);
        assert_eq!(updated.len(), 0, "another Windows build");
        assert!(updated.lookup(r"C:\a.exe", id(1)).is_none());
        let mut clock_back = SigCache::open_at(&file, "26100.1".into(), 500);
        assert!(clock_back.lookup(r"C:\a.exe", id(1)).is_none(), "checked in the future");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn errors_and_unreadable_files_are_never_kept() {
        let dir = temp_dir("errors");
        let file = dir.join("cache.json");
        let mut cache = SigCache::open_at(&file, "b".into(), 1_000);
        for (path, value) in [
            (
                r"C:\e.exe",
                json!({"path": r"C:\e.exe", "exists": true, "sig_status": "Error"}),
            ),
            (
                r"C:\d.exe",
                json!({"path": r"C:\d.exe", "exists": null, "error": "denied"}),
            ),
            (r"C:\m.exe", json!({"path": r"C:\m.exe", "exists": false})),
            (r"C:\x", json!({"path": r"C:\x", "exists": true, "is_dir": true})),
            (
                r"C:\u.exe",
                json!({"path": r"C:\u.exe", "exists": true, "sig_status": "UnknownError"}),
            ),
        ] {
            cache.lookup(path, id(1));
            put(&mut cache, &value);
        }
        assert_eq!(cache.len(), 0);
        // A result for a file this scan never looked up (no identity read first) is not kept.
        put(&mut cache, &info(r"C:\never.exe", "Valid"));
        assert_eq!(cache.len(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_least_recently_used_go_first_and_damage_is_ignored() {
        let dir = temp_dir("lru");
        let file = dir.join("cache.json");
        let mut cache = SigCache::open_at(&file, "b".into(), 1_000);
        for n in 0..(MAX_ENTRIES + 5) {
            let path = format!(r"C:\f\{n}.exe");
            cache.pending.insert(lower(&path), id(n as u64));
            put(&mut cache, &info(&path, "Valid"));
            if let Some(entry) = cache.entries.get_mut(&lower(&path)) {
                entry.used = n as i64;
            }
        }
        cache.save();
        let reopened = SigCache::open_at(&file, "b".into(), 1_000);
        assert_eq!(reopened.len(), MAX_ENTRIES);
        assert!(
            !reopened.entries.contains_key(r"c:\f\0.exe"),
            "least recently used dropped"
        );
        assert!(reopened.entries.contains_key(&format!(r"c:\f\{}.exe", MAX_ENTRIES + 4)));

        fs::write(&file, b"{ not json").expect("damage");
        assert_eq!(SigCache::open_at(&file, "b".into(), 1_000).len(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_changed_while_it_was_verified_is_not_kept() {
        let dir = temp_dir("changed");
        let file = dir.join("cache.json");
        let mut cache = SigCache::open_at(&file, "b".into(), 1_000);
        assert!(cache.lookup(r"C:\a.exe", id(5)).is_none());
        let mut after = id(5);
        after.sha256 = "ef".repeat(32);
        cache.put_checked(&info(r"C:\a.exe", "Valid"), &after);
        assert_eq!(cache.len(), 0, "the content read after the check differs");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn an_overwrite_in_place_with_the_old_time_is_seen() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = temp_dir("inplace");
        let file = dir.join("tool.exe");
        fs::write(&file, b"signed content 1").expect("write");
        let path = file.display().to_string();
        let first = identity(&path).expect("identity");
        // Overwrite the same bytes count in place, then put the last-write time back, as a
        // program that can write the file could.
        let times = fs::metadata(&file).expect("meta").modified().expect("time");
        {
            let mut handle = fs::OpenOptions::new()
                .write(true)
                .share_mode(0x7)
                .open(&file)
                .expect("open");
            handle.write_all(b"payload content!").expect("overwrite");
            handle.set_modified(times).expect("set time");
        }
        let second = identity(&path).expect("identity");
        assert_eq!(first.size, second.size);
        assert_eq!(first.file_id, second.file_id, "an overwrite in place keeps the file ID");
        assert_eq!(first.written, second.written, "the time was put back");
        assert_ne!(first, second, "the content hash tells them apart");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn identity_follows_the_file() {
        let dir = temp_dir("identity");
        let file = dir.join("a.bin");
        fs::write(&file, b"one").expect("write");
        let path = file.display().to_string();
        let first = identity(&path).expect("identity");
        assert_eq!(first.size, 3);
        fs::write(&file, b"three").expect("rewrite");
        let second = identity(&path).expect("identity");
        assert_ne!(first, second);
        assert!(identity(&dir.display().to_string()).is_none(), "a folder");
        assert!(identity(&dir.join("missing").display().to_string()).is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod cost {
    /// Times hashing the files of a list (one path per line, from `VIGIL_HASH_LIST`); counts and
    /// times only: `cargo test --release -p vigil-scan sigcache::cost -- --ignored --nocapture`
    #[test]
    #[ignore = "reads every file of a list given by hand"]
    fn hashing_cost() {
        let Ok(list) = std::env::var("VIGIL_HASH_LIST") else {
            return;
        };
        let text = std::fs::read_to_string(list).unwrap_or_default();
        let paths: Vec<String> = text.lines().map(str::to_string).filter(|l| !l.is_empty()).collect();
        for round in ["first", "second"] {
            let started = std::time::Instant::now();
            let found = super::identities(&paths);
            let hashed = found.iter().flatten().count();
            let bytes: u64 = found.iter().flatten().map(|i| i.size).sum();
            println!(
                "{round}: {} files, {hashed} hashed, {:.1} MB, {:.2} s",
                paths.len(),
                bytes as f64 / 1048576.0,
                started.elapsed().as_secs_f64()
            );
        }
    }
}
