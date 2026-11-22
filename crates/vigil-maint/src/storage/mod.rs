//! Disk space: volumes, cleanup of caches and temporary files, the Recycle Bin and folder sizes.
//!
//! Cleanup only offers data that Windows or the owning program rebuilds by itself. Cookies,
//! history, saved passwords, sign-ins, site storage, documents and downloads are never touched.
//!
//! The elevated app cleans folders that any program of the user can write to. A program could
//! plant a junction there to make an elevated delete land somewhere else, so:
//! * a root whose path contains a link is not offered and not cleaned;
//! * walks never enter a link (junction, symbolic link or other reparse point);
//! * every file is opened without following links, its real path is read from that same handle
//!   and checked to be inside the real root, and only then is it deleted through that handle.

mod dupes;
mod space;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap};
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use windows::Win32::Storage::FileSystem::{
    FILE_BASIC_INFO, FILE_INFO_BY_HANDLE_CLASS, GetDiskFreeSpaceExW, GetDriveTypeW, GetFileInformationByHandleEx,
    GetLogicalDriveStringsW, GetVolumeInformationW, RemoveDirectoryW, SetFileInformationByHandle,
};
use windows::Win32::UI::Shell::{
    SHEmptyRecycleBinW, SHFILEOPSTRUCTW, SHFileOperationW, SHQUERYRBINFO, SHQueryRecycleBinW,
};
use windows::core::PCWSTR;

pub use dupes::{
    DEFAULT_MIN_SIZE, DupFile, DupGroup, DupOptions, DupScan, file_sha256, find_duplicates, in_system_folder,
    system_folders,
};
pub use space::{LargeFile, Node, SpaceScan, scan_space};

use crate::error::{MaintError, MaintErrorKind};
use crate::walk::listings;
use crate::win::{
    ATTR_DIRECTORY, ATTR_NORMAL, ATTR_NOT_LOCAL, ATTR_READONLY, ATTR_REPARSE_POINT, ERROR_ACCESS_DENIED,
    ERROR_FILE_NOT_FOUND, ERROR_LOCK_VIOLATION, ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, Entry, NoErrorDialogs,
    OwnedHandle, StatError, final_path, lstat, open, powershell_path, read_folder, run_hidden, wide, wide_path,
};
use vigil_i18n::{tl, tr};

/// Stops a long operation between files. `&AtomicBool` and `&|| -> bool` closures both work.
pub trait Cancel {
    fn cancelled(&self) -> bool;
}

impl Cancel for AtomicBool {
    fn cancelled(&self) -> bool {
        self.load(Ordering::Relaxed)
    }
}

impl<F: Fn() -> bool> Cancel for F {
    fn cancelled(&self) -> bool {
        self()
    }
}

/// Never cancels.
pub struct NeverCancel;

impl Cancel for NeverCancel {
    fn cancelled(&self) -> bool {
        false
    }
}

/// Ignores progress messages.
pub fn no_progress(_: &str) {}

/// 1536 -> "1.5 KB" (binary units, as Explorer shows them).
pub fn format_size(size: f64) -> String {
    let mut value = size;
    for unit in ["bytes", "KB", "MB", "GB", "TB"] {
        if value.abs() < 1024.0 || unit == "TB" {
            return if unit == "bytes" {
                format!("{} {unit}", group_thousands(&format!("{value:.0}")))
            } else {
                format!("{} {unit}", group_thousands(&format!("{value:.1}")))
            };
        }
        value /= 1024.0;
    }
    String::new()
}

/// "1234567.8" -> "1,234,567.8".
fn group_thousands(number: &str) -> String {
    let (sign, rest) = number.strip_prefix('-').map_or(("", number), |r| ("-", r));
    let (int, frac) = rest.split_once('.').map_or((rest, None), |(i, f)| (i, Some(f)));
    let mut grouped = String::new();
    for (index, ch) in int.chars().enumerate() {
        if index > 0 && (int.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    match frac {
        Some(frac) => format!("{sign}{grouped}.{frac}"),
        None => format!("{sign}{grouped}"),
    }
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}

// --------------------------------------------------------------------------- volumes

/// A mounted drive and its space.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    pub mount: String,
    pub label: String,
    pub fs: String,
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub removable: bool,
    pub network: bool,
}

const DRIVE_UNKNOWN: u32 = 0;
const DRIVE_NO_ROOT_DIR: u32 = 1;
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const DRIVE_REMOTE: u32 = 4;
const DRIVE_CDROM: u32 = 5;
const DRIVE_RAMDISK: u32 = 6;

/// Hard drives and optical drives with their space (network drives, RAM disks and the floppy
/// drive are left out, as psutil does). Drives that are not ready (empty card readers) too.
pub fn volumes() -> Vec<Volume> {
    let _quiet = NoErrorDialogs::new();
    let mut buffer = vec![0u16; 1024];
    // SAFETY: the buffer is writable; the function writes at most its length.
    let length = unsafe { GetLogicalDriveStringsW(Some(&mut buffer)) } as usize;
    if length == 0 || length > buffer.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for drive in buffer[..length].split(|&c| c == 0).filter(|s| !s.is_empty()) {
        let mount = String::from_utf16_lossy(drive);
        let wide_drive = wide(&mount);
        // SAFETY: `wide_drive` is null-terminated.
        let kind = unsafe { GetDriveTypeW(PCWSTR(wide_drive.as_ptr())) };
        if matches!(kind, DRIVE_UNKNOWN | DRIVE_NO_ROOT_DIR | DRIVE_REMOTE | DRIVE_RAMDISK) {
            continue;
        }
        if kind == DRIVE_REMOVABLE && mount.eq_ignore_ascii_case("A:\\") {
            continue;
        }
        let mut name = [0u16; 261];
        let mut fs = [0u16; 261];
        // SAFETY: `wide_drive` is null-terminated; both buffers are writable.
        let info = unsafe {
            GetVolumeInformationW(
                PCWSTR(wide_drive.as_ptr()),
                Some(&mut name),
                None,
                None,
                None,
                Some(&mut fs),
            )
        };
        let (label, fs) = if info.is_ok() {
            (crate::win::from_wide(&name), crate::win::from_wide(&fs))
        } else {
            (String::new(), String::new())
        };
        let (mut total, mut free) = (0u64, 0u64);
        // SAFETY: `wide_drive` is null-terminated; the outputs are writable u64s.
        let usage =
            unsafe { GetDiskFreeSpaceExW(PCWSTR(wide_drive.as_ptr()), None, Some(&mut total), Some(&mut free)) };
        if usage.is_err() {
            continue;
        }
        out.push(Volume {
            mount,
            label,
            fs,
            total,
            used: total.saturating_sub(free),
            free,
            removable: matches!(kind, DRIVE_REMOVABLE | DRIVE_CDROM),
            network: kind == DRIVE_REMOTE,
        });
    }
    out
}

// --------------------------------------------------------------------------- cleanup targets

/// How a target is cleaned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Files,
    RecycleBin,
    DeliveryOptimization,
}

/// A place that can be cleaned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupTarget {
    pub key: String,
    pub label: String,
    pub description: String,
    /// "Windows", "Browsers", "Graphics", "Apps", "Recycle Bin".
    pub group: String,
    pub roots: Vec<String>,
    pub kind: TargetKind,
    pub size: u64,
    pub files: u64,
    pub admin: bool,
    pub selected: bool,
    pub note: String,
    pub min_age_hours: u32,
    /// File-name globs (`*` and `?`); empty = every file.
    pub patterns: Vec<String>,
}

/// What a clean removed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanResult {
    pub freed: u64,
    pub deleted: u64,
    /// In use, locked, or changed since it was measured.
    pub skipped: u64,
    pub errors: Vec<String>,
    pub per_target: BTreeMap<String, u64>,
}

const BROWSER_NOTE: &str = tl!(
    "Close the browser first; files in use are skipped. Sign-ins, cookies, history and saved \
                            passwords are not touched."
);
const GRAPHICS_NOTE: &str = tl!("Rebuilt automatically; the first launch of a game can be slower.");
const APP_NOTE: &str = tl!("Close the app first; files in use are skipped. Rebuilt automatically.");
const BROWSER_DESCRIPTION: &str =
    tl!("Copies of web pages, scripts and images the browser keeps to load sites faster.");

const CHROMIUM: [(&str, &str, &[&str]); 4] = [
    ("chrome", "Google Chrome", &["Google", "Chrome", "User Data"]),
    ("edge", "Microsoft Edge", &["Microsoft", "Edge", "User Data"]),
    ("brave", "Brave", &["BraveSoftware", "Brave-Browser", "User Data"]),
    ("vivaldi", "Vivaldi", &["Vivaldi", "User Data"]),
];
const OPERA: [(&str, &str, &str); 2] = [
    ("opera", "Opera", "Opera Stable"),
    ("opera_gx", "Opera GX", "Opera GX Stable"),
];
const CHROMIUM_CACHES: [&str; 2] = ["Code Cache", "GPUCache"];
const CHROMIUM_SHARED: [&str; 2] = ["ShaderCache", "GrShaderCache"];
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

/// Environment variables: the real ones, or a replacement map (tests).
fn env_get(env: Option<&HashMap<String, String>>, name: &str) -> String {
    match env {
        None => std::env::var(name).unwrap_or_default(),
        Some(map) => map
            .get(name)
            .or_else(|| map.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v))
            .cloned()
            .unwrap_or_default(),
    }
}

/// None unless `base` is an absolute folder: an empty variable must never become a relative
/// path that points into the current folder.
fn join(base: &str, parts: &[&str]) -> Option<PathBuf> {
    if base.is_empty() || !Path::new(base).is_absolute() {
        return None;
    }
    let mut path = PathBuf::from(base);
    for part in parts {
        path.push(part);
    }
    Some(path)
}

fn exists(path: &Path) -> bool {
    lstat(path).is_ok()
}

fn is_dir_following(path: &Path) -> bool {
    std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

fn is_file_following(path: &Path) -> bool {
    std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

/// The Delivery Optimization cache lives in a profile only administrators can read: without
/// rights, "access denied" is the best sign that it is there.
fn exists_or_denied(path: &Path) -> bool {
    matches!(lstat(path), Ok(_) | Err(StatError::Denied))
}

/// True if the path or any folder above it is a link (or cannot be checked).
pub(crate) fn has_link(path: &Path) -> bool {
    let start = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut current = start.clone();
    loop {
        match lstat(&current) {
            Err(StatError::NotFound) => return current != start,
            Err(_) => return true,
            Ok(entry) if entry.attributes & ATTR_REPARSE_POINT != 0 => return true,
            Ok(_) => {}
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent.to_path_buf(),
            _ => return false,
        }
    }
}

fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn usable(paths: Vec<Option<PathBuf>>) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for path in paths.into_iter().flatten() {
        let text = display(&path);
        if exists(&path) && !has_link(&path) && !seen.contains(&text) {
            seen.push(text);
        }
    }
    seen
}

/// Folders inside `folder` (not symbolic links), sorted by path.
fn subfolders(folder: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = read_folder(folder)
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.is_dir() && !(e.is_reparse() && e.reparse_tag == IO_REPARSE_TAG_SYMLINK))
        .map(|e| e.path)
        .collect();
    found.sort_by_key(|p| display(p));
    found
}

/// Caches of every profile (a folder of User Data with a Preferences file).
fn chromium_roots(user_data: Option<PathBuf>) -> Vec<Option<PathBuf>> {
    let Some(user_data) = user_data.filter(|p| is_dir_following(p)) else {
        return Vec::new();
    };
    let mut roots = Vec::new();
    for profile in subfolders(&user_data)
        .into_iter()
        .filter(|p| is_file_following(&p.join("Preferences")))
    {
        let cache = profile.join("Cache").join("Cache_Data");
        roots.push(Some(if is_dir_following(&cache) {
            cache
        } else {
            profile.join("Cache")
        }));
        roots.extend(CHROMIUM_CACHES.iter().map(|name| Some(profile.join(name))));
    }
    roots.extend(CHROMIUM_SHARED.iter().map(|name| Some(user_data.join(name))));
    roots
}

/// Opera keeps its profile in Roaming and the disk cache in Local.
fn opera_roots(local: &str, roaming: &str, folder: &str) -> Vec<Option<PathBuf>> {
    let mut roots = Vec::new();
    for base in [
        join(local, &["Opera Software", folder]),
        join(roaming, &["Opera Software", folder]),
    ]
    .into_iter()
    .flatten()
    {
        let cache = base.join("Cache").join("Cache_Data");
        roots.push(Some(if is_dir_following(&cache) {
            cache
        } else {
            base.join("Cache")
        }));
        roots.extend(
            CHROMIUM_CACHES
                .iter()
                .chain(CHROMIUM_SHARED.iter())
                .map(|name| Some(base.join(name))),
        );
    }
    roots
}

fn firefox_roots(local: &str) -> Vec<Option<PathBuf>> {
    match join(local, &["Mozilla", "Firefox", "Profiles"]) {
        Some(profiles) if is_dir_following(&profiles) => {
            // Sorted after joining: "x.default-release\cache2" < "x.default\cache2".
            let mut roots: Vec<PathBuf> = subfolders(&profiles).into_iter().map(|p| p.join("cache2")).collect();
            roots.sort_by_key(|p| display(p));
            roots.into_iter().map(Some).collect()
        }
        _ => Vec::new(),
    }
}

struct Spec<'a> {
    key: &'a str,
    label: &'a str,
    description: &'a str,
    group: &'a str,
    admin: bool,
    selected: bool,
    note: &'a str,
    min_age_hours: u32,
    patterns: &'a [&'a str],
}

impl<'a> Spec<'a> {
    fn new(key: &'a str, label: &'a str, description: &'a str, group: &'a str) -> Self {
        Self {
            key,
            label,
            description,
            group,
            admin: false,
            selected: true,
            note: "",
            min_age_hours: 0,
            patterns: &[],
        }
    }

    fn target(&self, roots: Vec<String>, kind: TargetKind) -> CleanupTarget {
        CleanupTarget {
            key: self.key.to_string(),
            label: tr!(self.label),
            description: tr!(self.description),
            group: tr!(self.group),
            roots,
            kind,
            size: 0,
            files: 0,
            admin: self.admin,
            selected: self.selected,
            note: tr!(self.note),
            min_age_hours: self.min_age_hours,
            patterns: self.patterns.iter().map(|p| p.to_string()).collect(),
        }
    }
}

/// What can be cleaned on this PC. Only targets with at least one existing root are listed.
///
/// Pre-selected: temporary files, Windows Update downloads, Delivery Optimization, thumbnails,
/// error reports and crash dumps (nothing anyone works with). Not pre-selected: browser and app
/// caches (the program should be closed first), graphics shader caches (games stutter once while
/// they are rebuilt) and the Recycle Bin (emptying it is permanent).
///
/// `env` replaces the environment variables (tests). The Recycle Bin and the Delivery
/// Optimization cache are system-wide and cleaned through Windows itself, so they are only
/// offered for the real environment.
pub fn cleanup_targets(env: Option<&HashMap<String, String>>) -> Vec<CleanupTarget> {
    let real = env.is_none();
    let local = env_get(env, "LOCALAPPDATA");
    let roaming = env_get(env, "APPDATA");
    let temp = Some(env_get(env, "TEMP"))
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| env_get(env, "TMP"));
    let windir = Some(env_get(env, "SystemRoot"))
        .filter(|w| !w.is_empty())
        .unwrap_or_else(|| env_get(env, "windir"));
    let programdata = env_get(env, "ProgramData");
    let mut out: Vec<CleanupTarget> = Vec::new();
    let mut add = |spec: Spec, roots: Vec<Option<PathBuf>>| {
        let roots = usable(roots);
        if !roots.is_empty() {
            out.push(spec.target(roots, TargetKind::Files));
        }
    };

    add(
        Spec {
            min_age_hours: 24,
            ..Spec::new(
                "user_temp",
                tl!("Temporary files (your account)"),
                tl!(
                    "Files programs left in your temporary folder. Files from the last 24 hours are kept, in case a \
                 program or installer is still using them."
                ),
                tl!("Windows"),
            )
        },
        vec![join(&temp, &[])],
    );
    add(
        Spec {
            admin: true,
            min_age_hours: 24,
            ..Spec::new(
                "windows_temp",
                tl!("Temporary files (Windows)"),
                tl!(
                    "Files Windows and services left in the Windows temporary folder. Files from the last 24 hours are \
                 kept."
                ),
                tl!("Windows"),
            )
        },
        vec![join(&windir, &["Temp"])],
    );
    add(
        Spec {
            admin: true,
            min_age_hours: 48,
            ..Spec::new(
                "update_cache",
                tl!("Windows Update downloads"),
                tl!(
                    "Installers Windows Update has already used. Anything still needed is downloaded again. Files from \
                 the last two days are kept so an update in progress is not disturbed."
                ),
                tl!("Windows"),
            )
        },
        vec![join(&windir, &["SoftwareDistribution", "Download"])],
    );
    let mut delivery = None;
    if real {
        let cache = join(
            &windir,
            &[
                "ServiceProfiles",
                "NetworkService",
                "AppData",
                "Local",
                "Microsoft",
                "Windows",
                "DeliveryOptimization",
                "Cache",
            ],
        );
        let module = join(
            &windir,
            &[
                "System32",
                "WindowsPowerShell",
                "v1.0",
                "Modules",
                "DeliveryOptimization",
            ],
        );
        if let (Some(cache), Some(module)) = (cache, module)
            && is_dir_following(&module)
            && exists_or_denied(&cache)
        {
            let spec = Spec {
                admin: true,
                ..Spec::new(
                    "delivery_optimization",
                    tl!("Delivery Optimization cache"),
                    tl!("Update pieces Windows keeps to share with other PCs. Cleared through Windows itself."),
                    tl!("Windows"),
                )
            };
            delivery = Some(spec.target(vec![display(&cache)], TargetKind::DeliveryOptimization));
        }
    }
    drop(add);
    if let Some(target) = delivery {
        out.push(target);
    }
    let mut add = |spec: Spec, roots: Vec<Option<PathBuf>>| {
        let roots = usable(roots);
        if !roots.is_empty() {
            out.push(spec.target(roots, TargetKind::Files));
        }
    };
    add(
        Spec {
            patterns: &["thumbcache_*.db"],
            note: tl!("Explorer keeps some of these files open; those are skipped."),
            ..Spec::new(
                "thumbnails",
                tl!("Thumbnail cache"),
                tl!("Picture and video previews Explorer stores. They are created again as you browse."),
                tl!("Windows"),
            )
        },
        vec![join(&local, &["Microsoft", "Windows", "Explorer"])],
    );
    add(
        Spec::new(
            "wer_user",
            tl!("Error reports (your account)"),
            tl!("Crash and problem reports already sent to Microsoft, or never going to be."),
            tl!("Windows"),
        ),
        vec![join(&local, &["Microsoft", "Windows", "WER"])],
    );
    add(
        Spec {
            admin: true,
            ..Spec::new(
                "wer_system",
                tl!("Error reports (Windows)"),
                tl!("System-wide crash and problem reports already sent to Microsoft, or never going to be."),
                tl!("Windows"),
            )
        },
        vec![
            join(&programdata, &["Microsoft", "Windows", "WER", "ReportArchive"]),
            join(&programdata, &["Microsoft", "Windows", "WER", "ReportQueue"]),
        ],
    );
    add(
        Spec::new(
            "crash_dumps_user",
            tl!("Crash dumps (your account)"),
            tl!("Memory snapshots saved when a program crashed. Only useful to investigate those crashes."),
            tl!("Windows"),
        ),
        vec![join(&local, &["CrashDumps"])],
    );
    add(
        Spec {
            admin: true,
            ..Spec::new(
                "crash_dumps_system",
                tl!("Crash dumps (Windows)"),
                tl!("Memory snapshots saved after a blue screen. Only useful to investigate that crash."),
                tl!("Windows"),
            )
        },
        vec![join(&windir, &["Minidump"]), join(&windir, &["MEMORY.DMP"])],
    );

    let graphics = |key, label, description| Spec {
        selected: false,
        note: GRAPHICS_NOTE,
        ..Spec::new(key, label, description, tl!("Graphics"))
    };
    add(
        graphics(
            "d3d_cache",
            "DirectX shader cache",
            "Compiled shaders that games and apps keep to start faster.",
        ),
        vec![join(&local, &["D3DSCache"])],
    );
    add(
        graphics(
            "nvidia_cache",
            "NVIDIA shader cache",
            "Compiled shaders the NVIDIA driver keeps.",
        ),
        vec![
            join(&local, &["NVIDIA", "DXCache"]),
            join(&local, &["NVIDIA", "GLCache"]),
            join(&local, &["NVIDIA Corporation", "NV_Cache"]),
        ],
    );
    add(
        graphics(
            "amd_cache",
            "AMD shader cache",
            "Compiled shaders the AMD driver keeps.",
        ),
        ["DxCache", "DxcCache", "GLCache", "VkCache"]
            .iter()
            .map(|name| join(&local, &["AMD", name]))
            .collect(),
    );
    add(
        graphics(
            "intel_cache",
            "Intel shader cache",
            "Compiled shaders the Intel driver keeps.",
        ),
        vec![join(&local, &["Intel", "ShaderCache"])],
    );

    for (key, name, parts) in CHROMIUM {
        let key = format!("browser_{key}");
        let label = tr!("{0} cache", name);
        add(
            Spec {
                selected: false,
                note: BROWSER_NOTE,
                ..Spec::new(&key, &label, BROWSER_DESCRIPTION, tl!("Browsers"))
            },
            chromium_roots(join(&local, parts)),
        );
    }
    for (key, name, folder) in OPERA {
        let key = format!("browser_{key}");
        let label = tr!("{0} cache", name);
        add(
            Spec {
                selected: false,
                note: BROWSER_NOTE,
                ..Spec::new(&key, &label, BROWSER_DESCRIPTION, tl!("Browsers"))
            },
            opera_roots(&local, &roaming, folder),
        );
    }
    add(
        Spec {
            selected: false,
            note: BROWSER_NOTE,
            ..Spec::new(
                "browser_firefox",
                tl!("Firefox cache"),
                tl!("Copies of web pages, scripts and images Firefox keeps to load sites faster."),
                tl!("Browsers"),
            )
        },
        firefox_roots(&local),
    );

    let app = |key, label, description| Spec {
        selected: false,
        note: APP_NOTE,
        ..Spec::new(key, label, description, tl!("Apps"))
    };
    add(
        app(
            "app_teams",
            tl!("Microsoft Teams (classic) cache"),
            tl!("Cached pictures, scripts and graphics."),
        ),
        ["Cache", "GPUCache", "Code Cache"]
            .iter()
            .map(|name| join(&roaming, &["Microsoft", "Teams", name]))
            .collect(),
    );
    add(
        app(
            "app_discord",
            tl!("Discord cache"),
            tl!("Cached pictures, scripts and graphics."),
        ),
        ["Cache", "Code Cache", "GPUCache"]
            .iter()
            .map(|name| join(&roaming, &["discord", name]))
            .collect(),
    );
    add(
        app(
            "app_vscode",
            tl!("Visual Studio Code cache"),
            tl!("Cached scripts and graphics of the editor."),
        ),
        ["Cache", "CachedData", "GPUCache"]
            .iter()
            .map(|name| join(&roaming, &["Code", name]))
            .collect(),
    );

    if real {
        let spec = Spec {
            selected: false,
            note: tl!("Check that nothing in it is still needed."),
            ..Spec::new(
                "recycle_bin",
                tl!("Recycle Bin"),
                tl!("Files you deleted. Emptying it is permanent."),
                tl!("Recycle Bin"),
            )
        };
        out.push(spec.target(Vec::new(), TargetKind::RecycleBin));
    }
    out
}

// --------------------------------------------------------------------------- walking

/// `fnmatch` for the simple patterns used here: `*` and `?`, case already folded.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Eligible files under one cleanup root, never entering a link.
struct Walk<'a> {
    root: &'a Path,
    patterns: Vec<String>,
    min_age: f64,
    now: f64,
    cancel: &'a dyn Cancel,
    /// (depth, path, old enough to remove once empty).
    dirs: Vec<(usize, PathBuf, bool)>,
    denied: usize,
    cancelled: bool,
}

impl<'a> Walk<'a> {
    fn new(root: &'a Path, target: &CleanupTarget, now: f64, cancel: &'a dyn Cancel) -> Self {
        Self {
            root,
            patterns: target.patterns.iter().map(|p| p.to_lowercase()).collect(),
            min_age: f64::from(target.min_age_hours) * 3600.0,
            now,
            cancel,
            dirs: Vec::new(),
            denied: 0,
            cancelled: false,
        }
    }

    /// A file copied or extracted keeps its old modification time but gets a new creation time;
    /// an installer that has just unpacked it may still need it.
    fn old(now: f64, min_age: f64, entry: &Entry) -> bool {
        now - entry.modified.max(entry.created) >= min_age
    }

    fn eligible(patterns: &[String], now: f64, min_age: f64, name: &str, entry: &Entry) -> bool {
        if entry.attributes & (ATTR_DIRECTORY | ATTR_REPARSE_POINT | ATTR_NOT_LOCAL) != 0 {
            return false;
        }
        let lower = name.to_lowercase();
        if !patterns.is_empty() && !patterns.iter().any(|p| glob_match(p, &lower)) {
            return false;
        }
        Self::old(now, min_age, entry)
    }

    /// Calls `found(path, size)` for every eligible file; `found` returns false to stop.
    fn files(&mut self, found: &mut dyn FnMut(&Path, u64) -> bool) {
        let root = match lstat(self.root) {
            Ok(entry) => entry,
            Err(StatError::Denied) => {
                self.denied += 1;
                return;
            }
            Err(_) => return,
        };
        if root.is_reparse() {
            return;
        }
        let (now, min_age, cancel) = (self.now, self.min_age, self.cancel);
        let patterns = self.patterns.clone();
        if !root.is_dir() {
            // A single-file root such as MEMORY.DMP.
            let name = self
                .root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if Self::eligible(&patterns, now, min_age, &name, &root) {
                found(self.root, root.size);
            }
            return;
        }
        let mut seen = 0usize;
        let mut dirs = Vec::new();
        let mut denied = 0usize;
        let mut cancelled = false;
        listings(self.root, &|entry: &Entry| !entry.is_reparse(), &mut |listing| {
            if listing.error == Some(StatError::Denied) {
                denied += 1;
            }
            for entry in &listing.entries {
                seen += 1;
                if seen.is_multiple_of(64) && cancel.cancelled() {
                    cancelled = true;
                    return false;
                }
                if entry.is_reparse() {
                    continue;
                }
                if entry.is_dir() {
                    dirs.push((listing.depth + 1, entry.path.clone(), Self::old(now, min_age, entry)));
                } else if Self::eligible(&patterns, now, min_age, &entry.name_lossy(), entry)
                    && !found(&entry.path, entry.size)
                {
                    return false;
                }
            }
            true
        });
        self.dirs = dirs;
        self.denied += denied;
        self.cancelled = cancelled;
    }
}

/// Fills in `size` and `files` of each target: what a clean would remove right now.
pub fn measure(targets: &mut [CleanupTarget], progress: &dyn Fn(&str), cancel: &dyn Cancel) {
    measure_at(targets, now_seconds(), progress, cancel);
}

pub(crate) fn measure_at(targets: &mut [CleanupTarget], now: f64, progress: &dyn Fn(&str), cancel: &dyn Cancel) {
    for target in targets.iter_mut() {
        if cancel.cancelled() {
            return;
        }
        progress(&format!("Measuring {}", target.label));
        if target.kind == TargetKind::RecycleBin {
            (target.size, target.files) = recycle_bin_size();
            continue;
        }
        let (mut size, mut count) = (0u64, 0u64);
        for root in target.roots.clone() {
            let root = PathBuf::from(root);
            if has_link(&root) {
                continue;
            }
            let mut walk = Walk::new(&root, target, now, cancel);
            walk.files(&mut |_path, file_size| {
                size += file_size;
                count += 1;
                true
            });
            if walk.cancelled {
                break;
            }
        }
        target.size = size;
        target.files = count;
    }
}

// --------------------------------------------------------------------------- cleaning

const DELETE: u32 = 0x0001_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
const FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_BASIC_INFO_CLASS: FILE_INFO_BY_HANDLE_CLASS = FILE_INFO_BY_HANDLE_CLASS(0);
const FILE_DISPOSITION_INFO_CLASS: FILE_INFO_BY_HANDLE_CLASS = FILE_INFO_BY_HANDLE_CLASS(4);
const FILE_DISPOSITION_INFO_EX_CLASS: FILE_INFO_BY_HANDLE_CLASS = FILE_INFO_BY_HANDLE_CLASS(21);
/// Delete now (POSIX semantics: the name goes away even if another program has it open with
/// delete sharing) and ignore the read-only attribute. Needs Windows 10 1809 and NTFS.
const DISPOSITION_EX_FLAGS: u32 = 0x1 | 0x2 | 0x10;

/// (real path, is a single file) of a root that is safe to clean.
type RootIdentity = (String, bool);

fn root_identity(root: &Path) -> Option<RootIdentity> {
    if has_link(root) {
        return None;
    }
    let handle = open(
        root,
        FILE_READ_ATTRIBUTES,
        FLAG_OPEN_REPARSE_POINT | FLAG_BACKUP_SEMANTICS,
    )
    .ok()?;
    let real = final_path(&handle)?;
    Some((real, !is_dir_following(root)))
}

fn inside(real: &str, root: &RootIdentity) -> bool {
    let (real_root, single) = root;
    if *single {
        return real == real_root;
    }
    real.starts_with(&format!("{}\\", real_root.trim_end_matches('\\')))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Deleted {
    Done,
    Gone,
    InUse,
    Readonly,
    Outside,
    Changed,
    Error(u32),
}

fn windows_code(error: &windows::core::Error) -> u32 {
    (error.code().0 as u32) & 0xFFFF
}

fn set_attributes(handle: &OwnedHandle, attributes: u32) -> Result<(), u32> {
    // Zero times leave them unchanged.
    let info = FILE_BASIC_INFO {
        FileAttributes: if attributes == 0 { ATTR_NORMAL } else { attributes },
        ..Default::default()
    };
    // SAFETY: `handle` is open with FILE_WRITE_ATTRIBUTES; `info` is a FILE_BASIC_INFO of the given size.
    unsafe {
        SetFileInformationByHandle(
            handle.0,
            FILE_BASIC_INFO_CLASS,
            (&info as *const FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    }
    .map_err(|e| windows_code(&e))
}

/// Deletes the open file. Returns the Windows error code on failure.
fn dispose(handle: &OwnedHandle) -> Result<(), u32> {
    let flags: u32 = DISPOSITION_EX_FLAGS;
    // SAFETY: `handle` is open with DELETE access; FILE_DISPOSITION_INFO_EX is a single ULONG.
    let result = unsafe {
        SetFileInformationByHandle(
            handle.0,
            FILE_DISPOSITION_INFO_EX_CLASS,
            (&flags as *const u32).cast(),
            4,
        )
    };
    let code = match result {
        Ok(()) => return Ok(()),
        Err(error) => windows_code(&error),
    };
    // ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED, ERROR_INVALID_PARAMETER: older Windows or a
    // file system without the extended call.
    if !matches!(code, 1 | 50 | 87) {
        return Err(code);
    }
    let delete: u8 = 1;
    // SAFETY: `handle` is open with DELETE access; FILE_DISPOSITION_INFO is a single BOOLEAN.
    unsafe { SetFileInformationByHandle(handle.0, FILE_DISPOSITION_INFO_CLASS, (&delete as *const u8).cast(), 1) }
        .map_err(|e| windows_code(&e))
}

fn delete_file(path: &Path, root: &RootIdentity, clear_readonly: bool) -> Deleted {
    let access = DELETE | FILE_READ_ATTRIBUTES | if clear_readonly { FILE_WRITE_ATTRIBUTES } else { 0 };
    let handle = match open(path, access, FLAG_OPEN_REPARSE_POINT) {
        Ok(handle) => handle,
        Err(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => return Deleted::Gone,
        Err(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION) => return Deleted::InUse,
        Err(code) => return Deleted::Error(code),
    };
    let mut info = FILE_BASIC_INFO::default();
    // SAFETY: `handle` is open with FILE_READ_ATTRIBUTES; `info` is writable and of the given size.
    let read = unsafe {
        GetFileInformationByHandleEx(
            handle.0,
            FILE_BASIC_INFO_CLASS,
            (&mut info as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if let Err(error) = read {
        return Deleted::Error(windows_code(&error));
    }
    let attributes = info.FileAttributes;
    if attributes & (ATTR_DIRECTORY | ATTR_REPARSE_POINT) != 0 {
        return Deleted::Changed; // swapped for a folder or a link since the walk
    }
    match final_path(&handle) {
        Some(real) if inside(&real, root) => {}
        _ => return Deleted::Outside,
    }
    if clear_readonly
        && attributes & ATTR_READONLY != 0
        && let Err(code) = set_attributes(&handle, attributes & !ATTR_READONLY)
    {
        return Deleted::Error(code);
    }
    match dispose(&handle) {
        Ok(()) => Deleted::Done,
        Err(ERROR_ACCESS_DENIED) if attributes & ATTR_READONLY != 0 && !clear_readonly => Deleted::Readonly,
        Err(ERROR_ACCESS_DENIED) => Deleted::InUse, // a running program, or a file already being deleted
        Err(code) => Deleted::Error(code),
    }
}

/// Deepest first; never the root (it is not in the list). A folder that turned into a link
/// meanwhile only loses the link itself: removing a directory never follows it.
fn remove_empty_dirs(dirs: &mut [(usize, PathBuf, bool)]) {
    dirs.sort_by_key(|dir| std::cmp::Reverse(dir.0));
    for (_depth, path, old) in dirs.iter() {
        if !old {
            continue;
        }
        let wide = wide_path(path);
        // SAFETY: `wide` is null-terminated; the call fails harmlessly if the folder is not empty.
        let _ = unsafe { RemoveDirectoryW(PCWSTR(wide.as_ptr())) };
    }
}

struct Cleaner<'a> {
    result: CleanResult,
    progress: &'a dyn Fn(&str),
    cancel: &'a dyn Cancel,
    cancelled: bool,
    next_report: Instant,
}

impl Cleaner<'_> {
    fn report(&mut self, label: &str) {
        let now = Instant::now();
        if now >= self.next_report {
            self.next_report = now + Duration::from_millis(250);
            (self.progress)(&format!(
                "Cleaning {label} · {} freed",
                format_size(self.result.freed as f64)
            ));
        }
    }

    fn error(&mut self, message: String) {
        let errors = &mut self.result.errors;
        if errors.len() < 50 {
            errors.push(message);
        } else if errors.len() == 50 {
            errors.push(tr!("… more errors not listed"));
        }
    }

    fn files(&mut self, target: &CleanupTarget, now: f64) -> u64 {
        let mut freed = 0u64;
        let cancel = self.cancel;
        for root_text in &target.roots {
            let root_path = PathBuf::from(root_text);
            let Some(root) = root_identity(&root_path) else {
                if exists(&root_path) {
                    self.result
                        .errors
                        .push(tr!("{0}: skipped, it is a link or cannot be opened", root_text));
                }
                continue;
            };
            let mut walk = Walk::new(&root_path, target, now, cancel);
            walk.files(&mut |path, size| {
                if cancel.cancelled() {
                    self.cancelled = true;
                    return false;
                }
                let mut status = delete_file(path, &root, false);
                if status == Deleted::Readonly {
                    status = delete_file(path, &root, true);
                }
                match status {
                    Deleted::Done => {
                        freed += size;
                        self.result.freed += size;
                        self.result.deleted += 1;
                    }
                    Deleted::InUse | Deleted::Changed | Deleted::Outside | Deleted::Readonly => {
                        self.result.skipped += 1;
                    }
                    Deleted::Gone => {}
                    Deleted::Error(code) => self.error(format!("{}: error {code}", display(path))),
                }
                self.report(&target.label);
                true
            });
            if walk.cancelled {
                self.cancelled = true;
            }
            if self.cancelled {
                break;
            }
            if target.patterns.is_empty() {
                remove_empty_dirs(&mut walk.dirs);
            }
        }
        freed
    }

    fn recycle_bin(&mut self) -> u64 {
        let (before, _items) = recycle_bin_size();
        if let Err(error) = empty_recycle_bin() {
            self.error(tr!("Recycle Bin: {0}", error));
        }
        let (after, _items) = recycle_bin_size();
        let freed = before.saturating_sub(after);
        self.result.freed += freed;
        freed
    }

    fn delivery_optimization(&mut self, target: &CleanupTarget, now: f64) -> u64 {
        let size = || -> u64 {
            let mut total = 0u64;
            for root in &target.roots {
                let root = PathBuf::from(root);
                let mut walk = Walk::new(&root, target, now, &NeverCancel);
                walk.files(&mut |_p, s| {
                    total += s;
                    true
                });
            }
            total
        };
        let before = size();
        let run = run_hidden(
            &powershell_path(),
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Delete-DeliveryOptimizationCache -Force",
            ],
            &[],
            None,
            Duration::from_secs(600),
        );
        match run {
            Ok(output) if output.code != Some(0) => {
                let text = if output.stderr.is_empty() {
                    &output.stdout
                } else {
                    &output.stderr
                };
                let text = String::from_utf8_lossy(text);
                let detail = text
                    .trim()
                    .lines()
                    .next()
                    .unwrap_or(&tr!("the cleanup failed"))
                    .to_string();
                self.error(tr!("Delivery Optimization: {0}", detail));
            }
            Ok(_) => {}
            Err(error) => self.error(tr!("Delivery Optimization: {0}", error)),
        }
        let freed = if before > 0 { before.saturating_sub(size()) } else { 0 };
        self.result.freed += freed;
        freed
    }
}

/// Deletes what the selected targets hold. Files in use are skipped, never forced.
pub fn clean(targets: &[CleanupTarget], progress: &dyn Fn(&str), cancel: &dyn Cancel) -> CleanResult {
    clean_at(targets, now_seconds(), progress, cancel)
}

pub(crate) fn clean_at(
    targets: &[CleanupTarget],
    now: f64,
    progress: &dyn Fn(&str),
    cancel: &dyn Cancel,
) -> CleanResult {
    let mut cleaner = Cleaner {
        result: CleanResult::default(),
        progress,
        cancel,
        cancelled: false,
        next_report: Instant::now(),
    };
    for target in targets {
        if !target.selected {
            continue;
        }
        if cleaner.cancelled || cancel.cancelled() {
            break;
        }
        progress(&format!("Cleaning {}", target.label));
        let freed = match target.kind {
            TargetKind::RecycleBin => cleaner.recycle_bin(),
            TargetKind::DeliveryOptimization => cleaner.delivery_optimization(target, now),
            TargetKind::Files => cleaner.files(target, now),
        };
        cleaner.result.per_target.insert(target.key.clone(), freed);
    }
    cleaner.result
}

// --------------------------------------------------------------------------- Recycle Bin

/// (bytes, items) in the Recycle Bins of every drive; (0, 0) if Windows cannot tell.
pub fn recycle_bin_size() -> (u64, u64) {
    let mut info = SHQUERYRBINFO {
        cbSize: size_of::<SHQUERYRBINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is writable and its cbSize is set; a null root means every drive.
    match unsafe { SHQueryRecycleBinW(PCWSTR::null(), &mut info) } {
        Ok(()) => (info.i64Size.max(0) as u64, info.i64NumItems.max(0) as u64),
        Err(_) => (0, 0),
    }
}

const E_UNEXPECTED: i32 = 0x8000_FFFFu32 as i32;

/// Empties every Recycle Bin, with no confirmation, progress window or sound.
pub fn empty_recycle_bin() -> Result<(), MaintError> {
    // SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND.
    // SAFETY: no window and a null root (every drive); the flags are plain integers.
    match unsafe { SHEmptyRecycleBinW(None, PCWSTR::null(), 0x1 | 0x2 | 0x4) } {
        Ok(()) => Ok(()),
        // What SHEmptyRecycleBin returns for an empty bin.
        Err(error) if error.code().0 == E_UNEXPECTED => Ok(()),
        Err(error) => {
            let code = error.code().0;
            Err(MaintError::windows(
                tr!(
                    "Windows could not empty the Recycle Bin (0x{0})",
                    format!("{:08X}", code as u32)
                ),
                i64::from(code),
            ))
        }
    }
}

fn drive_root(path: &Path) -> Option<String> {
    match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => Some(format!("{}:\\", letter as char)),
            _ => None,
        },
        _ => None,
    }
}

fn check_recyclable(path: &Path) -> Result<(), MaintError> {
    let text = display(path);
    if text.is_empty() || text.contains('\0') || !path.is_absolute() {
        return Err(MaintError::new(
            MaintErrorKind::InvalidPath,
            tr!("not a full path: '{0}'", text),
        ));
    }
    if text.starts_with(r"\\") {
        return Err(MaintError::new(
            MaintErrorKind::Unsupported,
            tr!("{0} is on a network location, which has no Recycle Bin", text),
        ));
    }
    if !exists(path) {
        return Err(MaintError::new(
            MaintErrorKind::NotFound,
            tr!("{0} does not exist", text),
        ));
    }
    let drive = drive_root(path).unwrap_or_default();
    let wide_drive = wide(&drive);
    // SAFETY: `wide_drive` is null-terminated.
    if unsafe { GetDriveTypeW(PCWSTR(wide_drive.as_ptr())) } != DRIVE_FIXED {
        return Err(MaintError::new(
            MaintErrorKind::Unsupported,
            tr!(
                "{0} has no Recycle Bin (removable or network drive); nothing was deleted",
                drive
            ),
        ));
    }
    Ok(())
}

const FO_DELETE: u32 = 3;
const FOF_SILENT: u16 = 0x4;
const FOF_NOCONFIRMATION: u16 = 0x10;
const FOF_ALLOWUNDO: u16 = 0x40;
const FOF_NOERRORUI: u16 = 0x400;
const FOF_WANTNUKEWARNING: u16 = 0x4000;

/// Moves files or folders to the Recycle Bin. Every path is checked before anything moves.
///
/// Windows deletes permanently, without asking, what does not fit in the Recycle Bin; the
/// nuke-warning flag makes it ask in exactly that case.
pub fn send_to_recycle_bin(paths: &[PathBuf]) -> Result<(), MaintError> {
    if paths.is_empty() {
        return Ok(());
    }
    for path in paths {
        check_recyclable(path)?;
    }
    // A double-NUL-terminated list of full paths (the shell does not take the \\?\ prefix).
    let mut list: Vec<u16> = Vec::new();
    for path in paths {
        list.extend(path.as_os_str().encode_wide());
        list.push(0);
    }
    list.push(0);
    let mut operation = SHFILEOPSTRUCTW {
        wFunc: FO_DELETE,
        pFrom: PCWSTR(list.as_ptr()),
        fFlags: FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI | FOF_WANTNUKEWARNING,
        ..Default::default()
    };
    // SAFETY: `operation` points at `list`, which outlives the call and is double-NUL terminated.
    let result = unsafe { SHFileOperationW(&mut operation) };
    if result != 0 {
        return Err(MaintError::windows(
            tr!(
                "Windows could not move the files to the Recycle Bin (code 0x{0})",
                format!("{:X}", result)
            ),
            i64::from(result),
        ));
    }
    if operation.fAnyOperationsAborted.as_bool() {
        return Err(MaintError::new(
            MaintErrorKind::Windows,
            tr!("Moving to the Recycle Bin was cancelled; some files were not moved"),
        ));
    }
    Ok(())
}
