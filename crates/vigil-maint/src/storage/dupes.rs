//! Duplicate files: the same content stored more than once under a folder.
//!
//! Files are grouped by size first (a listing reads sizes without opening anything), then by a
//! quick hash of their first and last 64 KB, and only the files still alike are read in full and
//! compared by SHA-256. Most files have a size nobody else has, so few are ever opened.
//!
//! Like the other walks, this never enters a link, and every file is opened without following
//! one. Files whose data is not on this disk (online-only cloud files) are never opened: reading
//! them would download them. Files kept by a cloud provider or by deduplication (other reparse
//! points) are left out as well. Windows' own folders, the program folders, ProgramData and other
//! accounts' profile folders are never searched. Every check is made on the folder's real path
//! (links and short names such as `PROGRA~1` resolved through a handle), so another spelling of a
//! protected folder is refused too. Hard links of one file are one file: they are never shown as
//! copies of each other.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vigil_i18n::tr;

use super::{Cancel, format_size, group_thousands};
use crate::error::{MaintError, MaintErrorKind};
use crate::walk::listings;
use crate::win::{ATTR_NOT_LOCAL, ATTR_REPARSE_POINT, Entry};

/// FILE_READ_ATTRIBUTES.
const READ_ATTRIBUTES: u32 = 0x80;
/// FILE_FLAG_BACKUP_SEMANTICS: needed to open a folder.
const BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// Files smaller than this are not compared by default (they rarely free much space).
pub const DEFAULT_MIN_SIZE: u64 = 1 << 20;
/// Bytes read from the start and from the end of a file for the quick hash.
const QUICK_BYTES: u64 = 64 * 1024;
/// Files read at the same time (reading is mostly waiting for the disk).
const HASH_WORKERS: usize = 4;
const CHUNK: usize = 1 << 20;
/// FILE_FLAG_OPEN_REPARSE_POINT: open a link itself, never what it points to.
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// FILE_FLAG_SEQUENTIAL_SCAN.
const SEQUENTIAL_SCAN: u32 = 0x0800_0000;
/// FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE: never block the programs using a file.
const SHARE_ALL: u32 = 0x7;

/// Limits of one search.
#[derive(Debug, Clone)]
pub struct DupOptions {
    /// Smaller files are left out.
    pub min_size: u64,
    /// The walk stops after this many files (the search is then marked `capped`).
    pub max_files: u64,
    /// The whole search stops after this long (marked `capped`).
    pub max_time: Duration,
    /// The groups kept, the ones that waste the most space first.
    pub max_groups: usize,
    /// Folders never entered (Vigil's own data folder, for example).
    pub skip: Vec<PathBuf>,
}

impl Default for DupOptions {
    fn default() -> Self {
        Self {
            min_size: DEFAULT_MIN_SIZE,
            max_files: 500_000,
            max_time: Duration::from_secs(15 * 60),
            max_groups: 1_000,
            skip: Vec::new(),
        }
    }
}

/// One copy of a duplicated file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DupFile {
    pub path: String,
    /// Milliseconds since 1970-01-01 UTC.
    pub modified_ms: i64,
    pub created_ms: i64,
}

/// Files with the same size and the same SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DupGroup {
    pub size: u64,
    /// Lower-case hex.
    pub sha256: String,
    /// Sorted by path.
    pub files: Vec<DupFile>,
    /// What keeping a single copy would free: `size × (copies − 1)`.
    pub wasted: u64,
}

/// The result of [`find_duplicates`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DupScan {
    pub root: String,
    /// The groups that waste the most space first.
    pub groups: Vec<DupGroup>,
    /// Sum of the groups' `wasted`.
    pub wasted: u64,
    /// Files seen by the walk.
    pub files: u64,
    pub folders: u64,
    /// Files that had a size twin and were opened.
    pub compared: u64,
    pub hashed_bytes: u64,
    /// Folders or files that could not be read.
    pub errors: u64,
    /// Links (junctions, symbolic links) not followed.
    pub links_skipped: u64,
    /// Files whose data is in the cloud or kept by a provider: never opened.
    pub cloud_skipped: u64,
    /// Extra names (hard links) of a file already counted: the same file, not a copy.
    #[serde(default)]
    pub hard_links: u64,
    pub min_size: u64,
    pub seconds: f64,
    pub cancelled: bool,
    /// The file count or time limit stopped the search early.
    pub capped: bool,
    /// More groups were found than kept.
    pub groups_capped: bool,
}

/// A file of the walk that has at least the minimum size.
struct Candidate {
    path: PathBuf,
    size: u64,
    modified_ms: i64,
    created_ms: i64,
}

fn ms(seconds: f64) -> i64 {
    (seconds * 1000.0).round() as i64
}

fn lower(path: &Path) -> String {
    path.to_string_lossy().trim_end_matches('\\').to_lowercase()
}

/// Windows' folder, the program folders and ProgramData (from the environment; the usual
/// locations when it is missing).
pub fn system_folders() -> Vec<PathBuf> {
    let var = |name: &str, fallback: &str| -> PathBuf {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| PathBuf::from(fallback))
    };
    let mut out = vec![
        var("SystemRoot", r"C:\Windows"),
        var("ProgramFiles", r"C:\Program Files"),
        var("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        var("ProgramW6432", r"C:\Program Files"),
        var("ProgramData", r"C:\ProgramData"),
    ];
    out.sort();
    out.dedup();
    out
}

/// True when `low` (lower case, no trailing `\\`) is `folder` or inside it.
fn under(low: &str, folder: &str) -> bool {
    !folder.is_empty() && (low == folder || low.starts_with(&format!("{folder}\\")))
}

/// [`system_folders`] as written and as their real paths, lower case.
fn system_folder_keys() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for folder in system_folders() {
        out.push(lower(&folder));
        if let Some(real) = resolved_path(&folder) {
            out.push(lower(&real));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// True when `path` is one of [`system_folders`] or inside one (compared with both their written
/// and real paths: pass a real path, see [`resolved_path`], to catch other spellings).
pub fn in_system_folder(path: &Path) -> bool {
    let low = lower(path);
    system_folder_keys().iter().any(|folder| under(&low, folder))
}

/// The real path of a file or folder: links in its folders resolved, short names (`PROGRA~1`)
/// expanded, the case on disk. The last part is opened without following a link. `None` when it
/// cannot be opened, or when it is on a network share.
/// `path` with every short (8.3) name expanded to its long name, without resolving links: a
/// folder that is a junction keeps its own name. Comparing this with the real path read through
/// a handle tells a link on the way apart from a short name (`C:\Users\RUNNER~1\…`). Returns the
/// path unchanged when it cannot be expanded (it no longer exists).
pub fn long_path(path: &Path) -> PathBuf {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut buffer = vec![0u16; 1024];
    for _ in 0..2 {
        // SAFETY: `wide` is NUL-terminated; `buffer` is writable for its whole length, which is
        // passed as its size.
        let length = unsafe {
            windows::Win32::Storage::FileSystem::GetLongPathNameW(
                windows::core::PCWSTR(wide.as_ptr()),
                Some(buffer.as_mut_slice()),
            )
        } as usize;
        if length == 0 {
            return path.to_path_buf();
        }
        if length < buffer.len() {
            return PathBuf::from(String::from_utf16_lossy(&buffer[..length]));
        }
        buffer.resize(length + 1, 0);
    }
    path.to_path_buf()
}

pub fn resolved_path(path: &Path) -> Option<PathBuf> {
    let handle = crate::win::open(path, READ_ATTRIBUTES, BACKUP_SEMANTICS | OPEN_REPARSE_POINT).ok()?;
    let real = crate::win::final_path_exact(handle.0)?;
    (!real.starts_with(r"\\")).then(|| PathBuf::from(real))
}

/// The folder that holds every account's profile (`C:\Users`) and this account's profile, both as
/// real paths in lower case; empty strings when they cannot be told.
fn profile_folders() -> (String, String) {
    let real = |path: PathBuf| resolved_path(&path).map(|p| lower(&p)).unwrap_or_else(|| lower(&path));
    let own = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute());
    let all = std::env::var_os("PUBLIC")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .or_else(|| own.as_ref().and_then(|p| p.parent().map(Path::to_path_buf)));
    (all.map(real).unwrap_or_default(), own.map(real).unwrap_or_default())
}

/// True when `real` (a real path) is inside another account's profile folder (or the shared
/// Public and Default ones): a search started by an administrator never touches those.
pub fn in_other_profile(real: &Path) -> bool {
    let (all, own) = profile_folders();
    let low = lower(real);
    !all.is_empty() && low != all && under(&low, &all) && !under(&low, &own)
}

/// Folders at a drive's root that hold Windows' own data.
fn is_system_name(entry: &Entry) -> bool {
    let name = entry.name_lossy().to_lowercase();
    matches!(
        name.as_str(),
        "$recycle.bin" | "system volume information" | "recovery" | "$windows.~bt" | "$windows.~ws"
    )
}

/// Opens a file for reading without following a link. `None` when it is a reparse point, its
/// data is not on this disk, or it cannot be opened.
fn open_plain(path: &Path) -> Option<(File, u64)> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_ALL)
        .custom_flags(OPEN_REPARSE_POINT | SEQUENTIAL_SCAN)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.file_attributes() & (ATTR_REPARSE_POINT | ATTR_NOT_LOCAL) != 0 {
        return None;
    }
    Some((file, meta.len()))
}

/// The volume serial and file index of an open file: the same for every hard link of it.
fn file_id(file: &File) -> Option<(u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open for the duration of the call; `info` is writable.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }.ok()?;
    Some((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

/// A file read again right before it is touched (see [`check_file`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedFile {
    pub size: u64,
    /// Lower-case hex.
    pub sha256: String,
    /// Volume serial and file index: the same for every hard link of the file.
    pub file_id: (u32, u64),
    /// The path Windows resolves the open file to (links in its folders resolved, short names
    /// expanded).
    pub real_path: String,
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of the first and last 64 KB (the whole file when it is smaller), with the size mixed
/// in, and the file's ID. `None` when the file changed size or cannot be read.
fn quick_hash(path: &Path, size: u64) -> Option<([u8; 32], (u32, u64))> {
    let (mut file, length) = open_plain(path)?;
    if length != size {
        return None;
    }
    let id = file_id(&file)?;
    let mut hasher = Sha256::new();
    hasher.update(size.to_le_bytes());
    let head = size.min(QUICK_BYTES) as usize;
    let mut buffer = vec![0u8; head];
    file.read_exact(&mut buffer).ok()?;
    hasher.update(&buffer);
    if size > QUICK_BYTES {
        let tail = (size - QUICK_BYTES).min(QUICK_BYTES);
        file.seek(SeekFrom::End(-(tail as i64))).ok()?;
        let mut buffer = vec![0u8; tail as usize];
        file.read_exact(&mut buffer).ok()?;
        hasher.update(&buffer);
    }
    Some((hasher.finalize().into(), id))
}

/// SHA-256 of the whole file, read in 1 MB chunks. `None` when it changed size, could not be
/// read, or the search stopped.
fn full_hash(path: &Path, size: u64, stop: &(dyn Fn() -> bool + Sync), read: &AtomicU64) -> Option<String> {
    let (mut file, length) = open_plain(path)?;
    if length != size {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        if stop() {
            return None;
        }
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total += count as u64;
        read.fetch_add(count as u64, Ordering::Relaxed);
    }
    (total == size).then(|| hex(&hasher.finalize()))
}

/// The SHA-256 (lower-case hex) and size of one file, opened without following a link. Refused
/// for links, reparse points and files whose data is not on this disk.
pub fn file_sha256(path: &Path) -> Result<(u64, String), MaintError> {
    check_file(path).map(|file| (file.size, file.sha256))
}

/// One file read again before it is touched, through one handle opened without following a link
/// at its last part: its size, SHA-256, file ID and the real path Windows resolves it to (compare
/// it with the path you expect: a folder swapped for a link changes it). Refused for links,
/// reparse points, folders and files whose data is not on this disk.
pub fn check_file(path: &Path) -> Result<CheckedFile, MaintError> {
    let text = path.to_string_lossy().into_owned();
    let entry = crate::win::lstat(path)
        .map_err(|_| MaintError::new(MaintErrorKind::NotFound, tr!("{0} no longer exists", text)))?;
    if entry.is_reparse() || entry.attributes & ATTR_NOT_LOCAL != 0 || entry.is_dir() {
        return Err(MaintError::new(
            MaintErrorKind::Unsupported,
            tr!("{0} is a link or a cloud file and is not touched", text),
        ));
    }
    let unreadable = || MaintError::new(MaintErrorKind::Windows, tr!("{0} could not be read", text));
    let (mut file, size) = open_plain(path).ok_or_else(unreadable)?;
    let id = file_id(&file).ok_or_else(unreadable)?;
    let real_path = {
        use std::os::windows::io::AsRawHandle;
        crate::win::final_path_exact(windows::Win32::Foundation::HANDLE(file.as_raw_handle())).ok_or_else(unreadable)?
    };
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(|_| unreadable())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total += count as u64;
    }
    if total != size {
        return Err(unreadable());
    }
    Ok(CheckedFile {
        size,
        sha256: hex(&hasher.finalize()),
        file_id: id,
        real_path,
    })
}

/// Runs `work` on every item with a few threads; results keep the items' order.
fn parallel<T: Sync, R: Send>(items: &[T], work: &(dyn Fn(&T) -> Option<R> + Sync)) -> Vec<Option<R>> {
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..HASH_WORKERS.min(items.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(index) else { break };
                    let result = work(item);
                    if let Ok(mut guard) = results.lock() {
                        guard[index] = result;
                    }
                }
            });
        }
    });
    results.into_inner().unwrap_or_default()
}

/// Finds files with the same content under `root` (see the module comment).
pub fn find_duplicates(
    root: &Path,
    options: &DupOptions,
    progress: &(dyn Fn(&str) + Sync),
    cancel: &(dyn Cancel + Sync),
) -> Result<DupScan, MaintError> {
    let started = Instant::now();
    let deadline = started + options.max_time;
    let root = std::path::absolute(root).unwrap_or_else(|_| root.to_path_buf());
    let text = root.to_string_lossy().into_owned();
    if !root.is_absolute() || text.starts_with(r"\\") {
        return Err(MaintError::new(
            MaintErrorKind::InvalidPath,
            tr!("Choose a folder on this computer: {0}", text),
        ));
    }
    // Checked as written, then walked and checked again as its real path: a short name or a link
    // to a protected folder is that folder.
    if in_system_folder(&root) {
        return Err(MaintError::new(
            MaintErrorKind::Unsupported,
            tr!(
                "{0} belongs to Windows or to installed programs and is not searched",
                text
            ),
        ));
    }
    let root = resolved_path(&root)
        .ok_or_else(|| MaintError::new(MaintErrorKind::NotFound, tr!("{0} does not exist", text)))?;
    if in_other_profile(&root) {
        return Err(MaintError::new(
            MaintErrorKind::Unsupported,
            tr!("{0} belongs to another account and is not searched", text),
        ));
    }
    if in_system_folder(&root) {
        return Err(MaintError::new(
            MaintErrorKind::Unsupported,
            tr!(
                "{0} belongs to Windows or to installed programs and is not searched",
                text
            ),
        ));
    }
    let top = crate::win::lstat(&root)
        .map_err(|_| MaintError::new(MaintErrorKind::NotFound, tr!("{0} does not exist", text)))?;
    if !top.is_dir() || top.is_link() {
        return Err(MaintError::new(
            MaintErrorKind::InvalidPath,
            tr!("{0} is not a folder", text),
        ));
    }
    let system = system_folder_keys();
    let skip: Vec<String> = options
        .skip
        .iter()
        .flat_map(|p| [Some(lower(p)), resolved_path(p).map(|r| lower(&r))])
        .flatten()
        .collect();
    let (profiles, own_profile) = profile_folders();

    let mut scan = DupScan {
        root: text,
        groups: Vec::new(),
        wasted: 0,
        files: 0,
        folders: 0,
        compared: 0,
        hashed_bytes: 0,
        errors: 0,
        links_skipped: 0,
        cloud_skipped: 0,
        hard_links: 0,
        min_size: options.min_size,
        seconds: 0.0,
        cancelled: false,
        capped: false,
        groups_capped: false,
    };
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut next_report = started + Duration::from_millis(250);
    let descend = |entry: &Entry| {
        if entry.is_link() || is_system_name(entry) {
            return false;
        }
        let low = lower(&entry.path);
        // Other accounts' profiles (and Public, Default) are never entered.
        let other_profile = !profiles.is_empty()
            && under(&low, &profiles)
            && low != profiles
            && !under(&low, &own_profile)
            && !under(&own_profile, &low);
        !system.contains(&low) && !skip.contains(&low) && !other_profile
    };
    listings(&root, &descend, &mut |listing| {
        if cancel.cancelled() {
            scan.cancelled = true;
            return false;
        }
        if Instant::now() >= deadline || scan.files >= options.max_files {
            scan.capped = true;
            return false;
        }
        scan.folders += 1;
        scan.errors += u64::from(listing.error.is_some());
        for entry in listing.entries {
            if entry.is_dir() {
                scan.links_skipped += u64::from(entry.is_link());
                continue;
            }
            scan.files += 1;
            if entry.is_link() {
                scan.links_skipped += 1;
                continue;
            }
            if entry.attributes & (ATTR_NOT_LOCAL | ATTR_REPARSE_POINT) != 0 {
                scan.cloud_skipped += 1;
                continue;
            }
            if entry.size >= options.min_size.max(1) {
                candidates.push(Candidate {
                    path: entry.path,
                    size: entry.size,
                    modified_ms: ms(entry.modified),
                    created_ms: ms(entry.created),
                });
            }
        }
        let now = Instant::now();
        if now >= next_report {
            next_report = now + Duration::from_millis(250);
            progress(&tr!(
                "{0} files in {1} folders · {2}",
                group_thousands(&scan.files.to_string()),
                group_thousands(&scan.folders.to_string()),
                listing.folder.display()
            ));
        }
        true
    });

    // Files with a size nobody else has cannot have a twin.
    let mut by_size: HashMap<u64, Vec<usize>> = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        by_size.entry(candidate.size).or_default().push(index);
    }
    let twins: Vec<usize> = by_size.into_values().filter(|list| list.len() > 1).flatten().collect();
    scan.compared = twins.len() as u64;

    let stopped = || cancel.cancelled() || Instant::now() >= deadline;
    let read = AtomicU64::new(0);
    let report = Mutex::new(Instant::now());
    let done = AtomicU64::new(0);
    let total = twins.len() as u64;
    let tick = |stage: &str| {
        let finished = done.fetch_add(1, Ordering::Relaxed) + 1;
        if let Ok(mut last) = report.lock()
            && last.elapsed() >= Duration::from_millis(250)
        {
            *last = Instant::now();
            progress(&tr!(
                "{0}: {1} of {2} files · {3} read",
                stage,
                group_thousands(&finished.to_string()),
                group_thousands(&total.to_string()),
                format_size(read.load(Ordering::Relaxed) as f64)
            ));
        }
    };

    // Quick hash of the files that share a size.
    let quick_stage = tr!("Comparing");
    let quick = parallel(&twins, &|&index| {
        if stopped() {
            return None;
        }
        let candidate = &candidates[index];
        let hash = quick_hash(&candidate.path, candidate.size);
        tick(&quick_stage);
        hash
    });
    let mut by_quick: HashMap<(u64, [u8; 32]), Vec<usize>> = HashMap::new();
    // Hard links of one file share its ID: only the first name found counts.
    let mut seen_ids: HashMap<(u32, u64), usize> = HashMap::new();
    for (&index, hash) in twins.iter().zip(quick) {
        match hash {
            Some((hash, id)) => {
                if seen_ids.insert(id, index).is_some() {
                    scan.hard_links += 1;
                    continue;
                }
                by_quick.entry((candidates[index].size, hash)).or_default().push(index);
            }
            None => scan.errors += u64::from(!stopped()),
        }
    }
    let alike: Vec<usize> = by_quick.into_values().filter(|list| list.len() > 1).flatten().collect();

    // Full SHA-256 of the files still alike.
    done.store(0, Ordering::Relaxed);
    let full_stage = tr!("Reading");
    let full = parallel(&alike, &|&index| {
        if stopped() {
            return None;
        }
        let candidate = &candidates[index];
        let hash = full_hash(&candidate.path, candidate.size, &stopped, &read);
        tick(&full_stage);
        hash
    });
    let mut by_hash: BTreeMap<(u64, String), Vec<usize>> = BTreeMap::new();
    for (&index, hash) in alike.iter().zip(full) {
        match hash {
            Some(hash) => by_hash.entry((candidates[index].size, hash)).or_default().push(index),
            None => scan.errors += u64::from(!stopped()),
        }
    }
    if cancel.cancelled() {
        scan.cancelled = true;
    } else if Instant::now() >= deadline {
        scan.capped = true;
    }

    let mut groups: Vec<DupGroup> = by_hash
        .into_iter()
        .filter(|(_, list)| list.len() > 1)
        .map(|((size, sha256), list)| {
            let mut files: Vec<DupFile> = list
                .iter()
                .map(|&index| {
                    let c = &candidates[index];
                    DupFile {
                        path: c.path.to_string_lossy().into_owned(),
                        modified_ms: c.modified_ms,
                        created_ms: c.created_ms,
                    }
                })
                .collect();
            files.sort_by_key(|f| f.path.to_lowercase());
            DupGroup {
                size,
                wasted: size.saturating_mul(files.len() as u64 - 1),
                sha256,
                files,
            }
        })
        .collect();
    groups.sort_by(|a, b| b.wasted.cmp(&a.wasted).then_with(|| a.sha256.cmp(&b.sha256)));
    if groups.len() > options.max_groups {
        groups.truncate(options.max_groups);
        scan.groups_capped = true;
    }
    scan.wasted = groups.iter().map(|g| g.wasted).sum();
    scan.groups = groups;
    scan.hashed_bytes = read.load(Ordering::Relaxed);
    scan.seconds = started.elapsed().as_secs_f64();
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::super::NeverCancel;
    use super::super::tests::TempTree;
    use super::*;

    fn options(min_size: u64) -> DupOptions {
        DupOptions {
            min_size,
            ..Default::default()
        }
    }

    fn bytes(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                (i as u8)
                    .wrapping_mul(31)
                    .wrapping_add(seed)
                    .wrapping_add((i / 251) as u8)
            })
            .collect()
    }

    fn write(path: &Path, data: &[u8]) -> PathBuf {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
        path.to_path_buf()
    }

    fn quiet(_: &str) {}

    #[test]
    fn identical_files_are_grouped_and_lookalikes_are_not() {
        let tree = TempTree::new("vigil-dupes-");
        let data = bytes(1, 300_000);
        let one = write(&tree.base.join(r"a\one.bin"), &data);
        write(&tree.base.join(r"b\two.bin"), &data);
        write(&tree.base.join(r"c\three.bin"), &data);
        // Same size and same first and last 64 KB, different in the middle: only the full hash
        // tells them apart.
        let mut middle = data.clone();
        middle[150_000] ^= 0xFF;
        write(&tree.base.join(r"d\middle.bin"), &middle);
        let mut head = data.clone();
        head[0] ^= 1;
        write(&tree.base.join(r"e\head.bin"), &head);
        write(&tree.base.join(r"f\small1.txt"), b"small");
        write(&tree.base.join(r"g\small2.txt"), b"small");

        let scan = find_duplicates(&tree.base, &options(100_000), &quiet, &NeverCancel).unwrap();
        assert_eq!(scan.groups.len(), 1, "{:?}", scan.groups);
        let group = &scan.groups[0];
        assert_eq!(group.size, 300_000);
        assert_eq!(group.files.len(), 3);
        assert_eq!(group.wasted, 600_000);
        assert_eq!(scan.wasted, 600_000);
        assert!(
            group
                .files
                .windows(2)
                .all(|w| w[0].path.to_lowercase() <= w[1].path.to_lowercase())
        );
        assert_eq!(scan.compared, 5, "the five files of 300,000 bytes were opened");
        assert!(!scan.cancelled && !scan.capped);
        let (size, hash) = file_sha256(&one).unwrap();
        assert_eq!((size, hash.as_str()), (300_000, group.sha256.as_str()));

        // With no minimum the small pair is found too, after the group that wastes more.
        let scan = find_duplicates(&tree.base, &options(1), &quiet, &NeverCancel).unwrap();
        assert_eq!(scan.groups.len(), 2);
        assert_eq!(scan.groups[0].size, 300_000);
        assert_eq!(scan.groups[1].size, 5);
    }

    #[test]
    fn links_and_files_not_on_this_disk_are_never_opened() {
        let mut tree = TempTree::new("vigil-dupes-");
        let outside = TempTree::new("vigil-dupes-out-");
        let data = bytes(7, 200_000);
        write(&tree.base.join(r"real\a.bin"), &data);
        write(&outside.base.join(r"target\b.bin"), &data);
        let link = tree.base.join("link");
        tree.junction(&link, &outside.base.join("target"));

        let scan = find_duplicates(&tree.base, &options(1), &quiet, &NeverCancel).unwrap();
        assert!(scan.groups.is_empty(), "the copy behind the junction is not followed");
        assert_eq!(scan.links_skipped, 1);

        // A second copy inside, then marked offline like an online-only cloud file.
        let copy = write(&tree.base.join(r"real\c.bin"), &data);
        let scan = find_duplicates(&tree.base, &options(1), &quiet, &NeverCancel).unwrap();
        assert_eq!(scan.groups.len(), 1);
        let wide = crate::win::wide_path(&copy);
        // SAFETY: `wide` is null-terminated; FILE_ATTRIBUTE_OFFLINE on a test file.
        unsafe {
            windows::Win32::Storage::FileSystem::SetFileAttributesW(
                windows::core::PCWSTR(wide.as_ptr()),
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0x1000),
            )
            .unwrap();
        }
        let scan = find_duplicates(&tree.base, &options(1), &quiet, &NeverCancel).unwrap();
        assert!(scan.groups.is_empty());
        assert_eq!(scan.cloud_skipped, 1);
        assert!(file_sha256(&copy).is_err(), "a file not on this disk is never hashed");
        assert!(file_sha256(&link).is_err(), "a link is never hashed");
    }

    #[test]
    fn hard_links_are_one_file_not_copies() {
        let tree = TempTree::new("vigil-dupes-");
        let data = bytes(9, 200_000);
        let one = write(&tree.base.join(r"a\one.bin"), &data);
        let link = tree.base.join(r"b\same.bin");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        fs::hard_link(&one, &link).unwrap();
        let scan = find_duplicates(&tree.base, &options(1), &quiet, &NeverCancel).unwrap();
        assert!(
            scan.groups.is_empty(),
            "two names of one file free nothing: {:?}",
            scan.groups
        );
        assert_eq!(scan.hard_links, 1);
        assert_eq!(check_file(&one).unwrap().file_id, check_file(&link).unwrap().file_id);

        // A real copy next to them: one group of two, the link not counted.
        write(&tree.base.join(r"c\copy.bin"), &data);
        let scan = find_duplicates(&tree.base, &options(1), &quiet, &NeverCancel).unwrap();
        assert_eq!(scan.groups.len(), 1);
        assert_eq!(scan.groups[0].files.len(), 2);
        assert_eq!(scan.groups[0].wasted, 200_000);
    }

    #[test]
    fn a_folder_reached_through_a_link_is_its_real_folder() {
        let mut tree = TempTree::new("vigil-dupes-");
        let real = tree.base.join("real");
        let data = bytes(4, 10_000);
        let file = write(&real.join("f.bin"), &data);
        let link = tree.base.join("via");
        tree.junction(&link, &real);
        // The file through the junction resolves to its real path.
        let through = check_file(&link.join("f.bin")).unwrap();
        // The temp folder may be written with short (8.3) names (CI runners: RUNNER~1); the real
        // path is always the long form.
        let long_file = long_path(&file);
        assert!(
            through.real_path.eq_ignore_ascii_case(&long_file.to_string_lossy()),
            "{} vs {}",
            through.real_path,
            long_file.display()
        );
        assert!(
            resolved_path(&link)
                .unwrap()
                .to_string_lossy()
                .eq_ignore_ascii_case(&long_path(&real).to_string_lossy())
                || resolved_path(&link).unwrap() == long_path(&link),
            "a junction opened without following it is the junction itself"
        );
        // A system folder reached by a short name is still refused.
        for folder in system_folders() {
            if let Some(real) = resolved_path(&folder) {
                assert!(in_system_folder(&real));
            }
        }
    }

    #[test]
    fn windows_and_program_folders_are_refused() {
        for folder in system_folders() {
            assert!(in_system_folder(&folder));
            assert!(in_system_folder(&folder.join("Sub")));
            assert!(find_duplicates(&folder, &options(1), &quiet, &NeverCancel).is_err());
        }
        assert!(!in_system_folder(&std::env::temp_dir()));
        assert!(find_duplicates(Path::new(r"\server\share"), &options(1), &quiet, &NeverCancel).is_err());
    }

    #[test]
    fn cancel_and_limits_stop_the_search() {
        let tree = TempTree::new("vigil-dupes-");
        for (folder, seed) in [("a", 1u8), ("b", 1), ("c", 2), ("d", 2)] {
            write(
                &tree.base.join(folder).join("f.bin"),
                &bytes(seed, 4096 + usize::from(seed)),
            );
        }
        let scan = find_duplicates(&tree.base, &options(1), &quiet, &|| true).unwrap();
        assert!(scan.cancelled);
        assert!(scan.groups.is_empty());

        let scan = find_duplicates(
            &tree.base,
            &DupOptions {
                min_size: 1,
                max_files: 1,
                ..Default::default()
            },
            &quiet,
            &NeverCancel,
        )
        .unwrap();
        assert!(scan.capped);

        let scan = find_duplicates(
            &tree.base,
            &DupOptions {
                min_size: 1,
                max_groups: 1,
                ..Default::default()
            },
            &quiet,
            &NeverCancel,
        )
        .unwrap();
        assert_eq!(scan.groups.len(), 1);
        assert!(scan.groups_capped);
        assert_eq!(scan.groups[0].size, 4098, "the group that wastes more is kept");

        // A skipped folder is not entered.
        let scan = find_duplicates(
            &tree.base,
            &DupOptions {
                min_size: 1,
                skip: vec![tree.base.join("a"), tree.base.join("c")],
                ..Default::default()
            },
            &quiet,
            &NeverCancel,
        )
        .unwrap();
        assert!(scan.groups.is_empty());
    }
}

#[cfg(test)]
mod smoke {
    use super::super::NeverCancel;
    use super::super::tests::TempTree;
    use super::*;

    /// A bigger temporary tree, counts only: `cargo test -p vigil-maint dupes::smoke -- --ignored --nocapture`
    #[test]
    #[ignore = "writes about 270 MB to the temporary folder"]
    fn live_smoke_on_a_temp_tree() {
        let tree = TempTree::new("vigil-dupes-smoke-");
        let mut written = 0u64;
        for i in 0..300usize {
            // Every fifth file has two twins in other folders; the rest are unique.
            let len = 64 * 1024 + i * 4096;
            let data: Vec<u8> = (0..len)
                .map(|n| (n as u8).wrapping_add(i as u8).wrapping_mul(7))
                .collect();
            let folder = tree.base.join(format!("f{}", i % 17));
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(folder.join(format!("file{i}.bin")), &data).unwrap();
            written += len as u64;
            if i % 5 == 0 {
                for copy in 0..2 {
                    let twin = tree.base.join(format!(r"copies{copy}\sub{}", i % 3));
                    std::fs::create_dir_all(&twin).unwrap();
                    std::fs::write(twin.join(format!("again{i}.bin")), &data).unwrap();
                    written += len as u64;
                }
            }
        }
        let started = Instant::now();
        let scan = find_duplicates(
            &tree.base,
            &DupOptions {
                min_size: 1,
                ..Default::default()
            },
            &|_| {},
            &NeverCancel,
        )
        .unwrap();
        println!(
            "wrote {} files ({:.1} MB); found {} groups, {:.1} MB to free, {} files seen, {} compared, {:.1} MB hashed, {} errors, in {:.2} s",
            scan.files,
            written as f64 / 1048576.0,
            scan.groups.len(),
            scan.wasted as f64 / 1048576.0,
            scan.files,
            scan.compared,
            scan.hashed_bytes as f64 / 1048576.0,
            scan.errors,
            started.elapsed().as_secs_f64()
        );
        assert_eq!(scan.groups.len(), 60);
        assert!(scan.groups.iter().all(|g| g.files.len() == 3));
    }
}
