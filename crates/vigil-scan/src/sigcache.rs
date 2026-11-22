//! A cache of the signature collector's results, so a scan only verifies the files that changed.
//!
//! Verifying a signature (catalog lookups for Windows' own files, certificate chains for the rest)
//! is the slowest part of a scan. Most files are the same from one scan to the next, so each
//! result is kept with the identity of the file it describes:
//!
//! - the full path (lower case), its size, its last-write time and its file ID (NTFS index and
//!   volume serial), read before the file is verified. A file whose identity changed is verified
//!   again; a file replaced by another one with the same name and size gets a new file ID;
//! - an entry is trusted for [`MAX_AGE_SECS`] at most, so certificate expiry and revocation are
//!   checked again in time;
//! - the whole cache is dropped when the Windows build (CurrentBuild.UBR) changes, since an update
//!   can change how system files are catalog-signed;
//! - results that say the file could not be read or verified are never kept.
//!
//! The file lives in the data folder of the copy that scans: `%ProgramData%\Vigil` for an elevated
//! copy (only administrators can write there, so a standard-user process cannot plant a "valid"
//! result for its own file) and `%LOCALAPPDATA%\Vigil` for a standard-user copy, whose scans run
//! with that user's rights anyway. It is read with a size cap, never through a link, and replaced
//! by writing a temporary file next to it and renaming it.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::lenient::{Get, lower, str_of};

/// Bump when the stored layout or the collector's fields change.
const VERSION: u32 = 1;
/// The most entries kept (the least recently used are dropped).
pub(crate) const MAX_ENTRIES: usize = 20_000;
/// How long a result is trusted, in seconds (7 days).
pub(crate) const MAX_AGE_SECS: i64 = 7 * 24 * 3600;
/// A cache file larger than this is ignored (it would be far beyond `MAX_ENTRIES`).
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// What identifies one version of a file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Identity {
    pub(crate) size: u64,
    /// Last-write time (FILETIME, 100 ns units).
    pub(crate) written: u64,
    /// Volume serial and file index.
    pub(crate) file_id: String,
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
    /// behind a link).
    pub(crate) fn open(path: &Path) -> Self {
        Self::open_at(path, windows_build(), now())
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

    /// The cached result for `path` when the file is still the one that was verified, recently.
    pub(crate) fn get(&mut self, path: &str) -> Option<Value> {
        let identity = identity(path)?;
        self.lookup(path, identity)
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

    /// Keeps a fresh result (only results that describe a readable, verified file).
    pub(crate) fn put(&mut self, info: &Value) {
        if !cacheable(info) {
            return;
        }
        let key = lower(&info.get("path").map(str_of).unwrap_or_default());
        let Some(identity) = self.pending.remove(&key) else {
            return;
        };
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

/// The identity of the file at `path`, or `None` when it cannot be opened (missing, denied).
#[cfg(windows)]
pub(crate) fn identity(path: &str) -> Option<Identity> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING,
    };
    use windows::core::PCWSTR;
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a NUL-terminated path; only attributes are requested; the handle is closed
    // below.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .ok()?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: valid handle and output structure.
    let read = unsafe { GetFileInformationByHandle(handle, &mut info) };
    // SAFETY: the handle came from CreateFileW above and is closed once.
    unsafe {
        let _ = CloseHandle(handle);
    }
    read.ok()?;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return None;
    }
    Some(Identity {
        size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        written: (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32) | u64::from(info.ftLastWriteTime.dwLowDateTime),
        file_id: format!(
            "{:08x}-{:08x}{:08x}",
            info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
        ),
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
        cache.put(&info(r"C:\Tools\a.exe", "Valid"));
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
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_results_and_other_windows_builds_are_not_trusted() {
        let dir = temp_dir("expire");
        let file = dir.join("cache.json");
        let mut cache = SigCache::open_at(&file, "26100.1".into(), 1_000);
        cache.lookup(r"C:\a.exe", id(1));
        cache.put(&info(r"C:\a.exe", "Valid"));
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
            cache.put(&value);
        }
        assert_eq!(cache.len(), 0);
        // A result for a file this scan never looked up (no identity read first) is not kept.
        cache.put(&info(r"C:\never.exe", "Valid"));
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
            cache.put(&info(&path, "Valid"));
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
