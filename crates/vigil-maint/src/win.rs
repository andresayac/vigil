//! Small Win32 helpers shared by the modules: wide strings, attributes without following links,
//! fast folder listings (with reparse tags), real paths of open handles and hidden processes.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FIND_FIRST_EX_LARGE_FETCH, FindClose, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW, FindNextFileW,
    GetFileAttributesExW, GetFileExInfoStandard, GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_DOS,
    WIN32_FILE_ATTRIBUTE_DATA, WIN32_FIND_DATAW,
};
use windows::Win32::System::Diagnostics::Debug::{SetThreadErrorMode, THREAD_ERROR_MODE};
use windows::core::PCWSTR;

use crate::error::{MaintError, MaintErrorKind};
use vigil_i18n::tr;

pub(crate) const ATTR_READONLY: u32 = 0x1;
pub(crate) const ATTR_DIRECTORY: u32 = 0x10;
pub(crate) const ATTR_NORMAL: u32 = 0x80;
pub(crate) const ATTR_REPARSE_POINT: u32 = 0x400;
/// Cloud placeholders (OneDrive "online-only" and the like): their data is not on this disk.
/// OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS.
pub(crate) const ATTR_NOT_LOCAL: u32 = 0x1000 | 0x40000 | 0x400000;
/// Reparse tags of links (junctions, symbolic links) carry this bit.
pub(crate) const TAG_NAME_SURROGATE: u32 = 0x2000_0000;

pub(crate) const ERROR_FILE_NOT_FOUND: u32 = 2;
pub(crate) const ERROR_PATH_NOT_FOUND: u32 = 3;
pub(crate) const ERROR_ACCESS_DENIED: u32 = 5;
pub(crate) const ERROR_SHARING_VIOLATION: u32 = 32;
pub(crate) const ERROR_LOCK_VIOLATION: u32 = 33;

/// Seconds between 1601-01-01 (FILETIME) and 1970-01-01.
const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;

/// Null-terminated UTF-16 for a Win32 call. Long absolute paths get the `\\?\` prefix so that
/// folders deeper than MAX_PATH can still be read and cleaned.
pub(crate) fn wide_path(path: &Path) -> Vec<u16> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.len() >= 240 && path.is_absolute() && !wide.starts_with(&[92, 92, 63, 92]) {
        let text: Vec<u16> = wide.iter().map(|&c| if c == 47 { 92 } else { c }).collect();
        wide = if text.starts_with(&[92, 92]) {
            // \\server\share -> \\?\UNC\server\share
            let mut prefixed: Vec<u16> = r"\\?\UNC".encode_utf16().collect();
            prefixed.extend_from_slice(&text[1..]);
            prefixed
        } else {
            let mut prefixed: Vec<u16> = r"\\?\".encode_utf16().collect();
            prefixed.extend_from_slice(&text);
            prefixed
        };
    }
    wide.push(0);
    wide
}

pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn from_wide(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

fn filetime_seconds(low: u32, high: u32) -> f64 {
    let ticks = ((high as i64) << 32) | low as i64;
    (ticks - EPOCH_DIFF_100NS) as f64 / 1e7
}

fn error_code(error: &windows::core::Error) -> u32 {
    // HRESULT_FROM_WIN32 keeps the Win32 code in the low 16 bits.
    (error.code().0 as u32) & 0xFFFF
}

/// Attributes and times of a file or folder, as read from its directory entry.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub name: OsString,
    pub path: PathBuf,
    pub attributes: u32,
    pub size: u64,
    pub created: f64,
    pub modified: f64,
    /// Valid when `attributes` has ATTR_REPARSE_POINT.
    pub reparse_tag: u32,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.attributes & ATTR_DIRECTORY != 0
    }

    pub fn is_reparse(&self) -> bool {
        self.attributes & ATTR_REPARSE_POINT != 0
    }

    /// Junctions and symbolic links. Other reparse points (cloud placeholders, deduplicated
    /// files) hold real content.
    pub fn is_link(&self) -> bool {
        self.is_reparse() && (self.reparse_tag == 0 || self.reparse_tag & TAG_NAME_SURROGATE != 0)
    }

    pub fn name_lossy(&self) -> String {
        self.name.to_string_lossy().into_owned()
    }

    fn from_find(folder: &Path, data: &WIN32_FIND_DATAW) -> Option<Self> {
        let len = data
            .cFileName
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(data.cFileName.len());
        let name_units = &data.cFileName[..len];
        if name_units == [46] || name_units == [46, 46] {
            return None; // "." and ".."
        }
        let name = OsString::from_wide(name_units);
        Some(Self {
            path: folder.join(&name),
            name,
            attributes: data.dwFileAttributes,
            size: ((data.nFileSizeHigh as u64) << 32) | data.nFileSizeLow as u64,
            created: filetime_seconds(data.ftCreationTime.dwLowDateTime, data.ftCreationTime.dwHighDateTime),
            modified: filetime_seconds(data.ftLastWriteTime.dwLowDateTime, data.ftLastWriteTime.dwHighDateTime),
            reparse_tag: data.dwReserved0,
        })
    }
}

/// Why a path could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatError {
    NotFound,
    Denied,
    Other(u32),
}

impl StatError {
    fn from_code(code: u32) -> Self {
        match code {
            // Codes that mean "not found": missing file, folder, drive or share.
            2 | 3 | 15 | 53 | 67 | 123 | 161 => Self::NotFound,
            5 | 32 | 33 => Self::Denied,
            other => Self::Other(other),
        }
    }
}

/// The entry of `path` itself, never following a link at its end (like `os.lstat`).
pub(crate) fn lstat(path: &Path) -> Result<Entry, StatError> {
    let wide = wide_path(path);
    let mut data = WIN32_FILE_ATTRIBUTE_DATA::default();
    // SAFETY: `wide` is null-terminated and `data` is a valid, writable WIN32_FILE_ATTRIBUTE_DATA.
    let result = unsafe {
        GetFileAttributesExW(
            PCWSTR(wide.as_ptr()),
            GetFileExInfoStandard,
            (&mut data as *mut WIN32_FILE_ATTRIBUTE_DATA).cast(),
        )
    };
    match result {
        Ok(()) => {
            let mut entry = Entry {
                name: path.file_name().map(OsString::from).unwrap_or_default(),
                path: path.to_path_buf(),
                attributes: data.dwFileAttributes,
                size: ((data.nFileSizeHigh as u64) << 32) | data.nFileSizeLow as u64,
                created: filetime_seconds(data.ftCreationTime.dwLowDateTime, data.ftCreationTime.dwHighDateTime),
                modified: filetime_seconds(data.ftLastWriteTime.dwLowDateTime, data.ftLastWriteTime.dwHighDateTime),
                reparse_tag: 0,
            };
            if entry.is_reparse()
                && let Ok(found) = find_one(path)
            {
                entry.reparse_tag = found.reparse_tag;
            }
            Ok(entry)
        }
        Err(error) => {
            let code = error_code(&error);
            match StatError::from_code(code) {
                // Locked or protected files (pagefile.sys, hiberfil.sys): the directory entry
                // still answers.
                StatError::Denied => find_one(path),
                other => Err(other),
            }
        }
    }
}

/// The directory entry of one path (FindFirstFile on the name itself).
pub(crate) fn find_one(path: &Path) -> Result<Entry, StatError> {
    let wide = wide_path(path);
    let mut data = WIN32_FIND_DATAW::default();
    // SAFETY: `wide` is null-terminated; `data` is a writable WIN32_FIND_DATAW for FindExInfoBasic.
    let handle = unsafe {
        FindFirstFileExW(
            PCWSTR(wide.as_ptr()),
            FindExInfoBasic,
            (&mut data as *mut WIN32_FIND_DATAW).cast(),
            FindExSearchNameMatch,
            None,
            Default::default(),
        )
    };
    match handle {
        Ok(handle) => {
            // SAFETY: closes the search handle opened above, exactly once.
            let _ = unsafe { FindClose(handle) };
            let folder = path.parent().unwrap_or(path);
            let mut entry = Entry::from_find(folder, &data).ok_or(StatError::NotFound)?;
            entry.path = path.to_path_buf();
            Ok(entry)
        }
        Err(error) => Err(StatError::from_code(error_code(&error))),
    }
}

/// Every entry of a folder (without "." and ".."), with sizes, times and reparse tags read from
/// the listing itself: no file is opened.
pub(crate) fn read_folder(folder: &Path) -> Result<Vec<Entry>, StatError> {
    let pattern = folder.join("*");
    let wide = wide_path(&pattern);
    let mut data = WIN32_FIND_DATAW::default();
    // SAFETY: `wide` is null-terminated; `data` is a writable WIN32_FIND_DATAW for FindExInfoBasic.
    let handle = unsafe {
        FindFirstFileExW(
            PCWSTR(wide.as_ptr()),
            FindExInfoBasic,
            (&mut data as *mut WIN32_FIND_DATAW).cast(),
            FindExSearchNameMatch,
            None,
            FIND_FIRST_EX_LARGE_FETCH,
        )
    };
    let handle = match handle {
        Ok(handle) => handle,
        Err(error) => {
            let code = error_code(&error);
            // An empty drive root has no "." entries: nothing found is not an error there.
            return if code == ERROR_FILE_NOT_FOUND {
                Ok(Vec::new())
            } else {
                Err(StatError::from_code(code))
            };
        }
    };
    let mut out = Vec::new();
    loop {
        if let Some(entry) = Entry::from_find(folder, &data) {
            out.push(entry);
        }
        // SAFETY: `handle` is the open search handle; `data` is writable.
        if unsafe { FindNextFileW(handle, &mut data) }.is_err() {
            break;
        }
    }
    // SAFETY: closes the search handle opened above, exactly once.
    let _ = unsafe { FindClose(handle) };
    Ok(out)
}

/// A handle that closes itself.
pub(crate) struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateFileW and is closed only here.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Opens a file or folder with every share mode. Returns the Win32 error code on failure.
pub(crate) fn open(path: &Path, access: u32, flags: u32) -> Result<OwnedHandle, u32> {
    let wide = wide_path(path);
    // SAFETY: `wide` is null-terminated; no security attributes or template handle are passed.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(flags),
            None,
        )
    };
    handle.map(OwnedHandle).map_err(|error| error_code(&error))
}

/// Real path of an open file or folder (links resolved), normalised for comparison.
pub(crate) fn final_path(handle: &OwnedHandle) -> Option<String> {
    final_path_exact(handle.0).map(|path| normcase(&path))
}

/// Real path of an open handle as Windows writes it (links in its folders resolved, short names
/// expanded, the case on disk), without the `\\?\` prefix; `\\server\share\…` for a network path.
pub(crate) fn final_path_exact(handle: HANDLE) -> Option<String> {
    let mut buffer = vec![0u16; 32768];
    // SAFETY: `handle` is open and `buffer` is a writable slice of the given length.
    let length = unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, VOLUME_NAME_DOS) } as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    let path = String::from_utf16_lossy(&buffer[..length]);
    Some(if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        path
    })
}

/// `os.path.normcase` on Windows: forward slashes become backslashes, everything lower case.
pub(crate) fn normcase(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

/// Keeps Windows from asking to insert a disk while an empty drive is queried.
pub(crate) struct NoErrorDialogs(THREAD_ERROR_MODE);

impl NoErrorDialogs {
    pub fn new() -> Self {
        let mut old = THREAD_ERROR_MODE(0);
        // SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX.
        // SAFETY: changes only the calling thread's error mode; `old` is writable.
        let _ = unsafe { SetThreadErrorMode(THREAD_ERROR_MODE(0x1 | 0x8000), Some(&mut old)) };
        Self(old)
    }
}

impl Drop for NoErrorDialogs {
    fn drop(&mut self) {
        // SAFETY: restores the error mode saved in `new` for this same thread.
        let _ = unsafe { SetThreadErrorMode(self.0, None) };
    }
}

/// The Windows folder. From Windows (`GetSystemWindowsDirectoryW`), not `%SystemRoot%`, which a user's environment can override.
pub(crate) fn windows_dir() -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let mut buffer = [0u16; 520];
        // SAFETY: the buffer is writable for its whole length, which is the size passed.
        let len = unsafe { windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(Some(&mut buffer)) }
            as usize;
        if len == 0 || len >= buffer.len() {
            PathBuf::from(r"C:\Windows")
        } else {
            PathBuf::from(String::from_utf16_lossy(&buffer[..len]))
        }
    })
    .clone()
}

/// Windows PowerShell by absolute path, never resolved through PATH or the current folder. A
/// 32-bit process on 64-bit Windows would get the redirected 32-bit System32: use Sysnative.
pub(crate) fn powershell_path() -> PathBuf {
    let windir = windows_dir();
    let native = if cfg!(target_pointer_width = "32") && windir.join("Sysnative").is_dir() {
        "Sysnative"
    } else {
        "System32"
    };
    windir
        .join(native)
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

/// Output of a hidden child process.
pub(crate) struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Runs a program without a window, feeding `stdin`, and kills it after `timeout`.
pub(crate) fn run_hidden(
    program: &Path,
    args: &[&str],
    env: &[(&str, &str)],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> Result<Output, MaintError> {
    let mut command = Command::new(program);
    command
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    let name = program
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut child = command
        .spawn()
        .map_err(|e| MaintError::new(MaintErrorKind::Collector, tr!("could not run {0}: {1}", name, e)))?;
    if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let data = data.to_vec();
        thread::spawn(move || {
            let _ = pipe.write_all(&data);
        });
    }
    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let out_reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(pipe) = out_pipe.as_mut() {
            let _ = pipe.read_to_end(&mut buffer);
        }
        buffer
    });
    let err_reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(pipe) = err_pipe.as_mut() {
            let _ = pipe.read_to_end(&mut buffer);
        }
        buffer
    });
    let deadline = Instant::now() + timeout;
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(MaintError::new(
                    MaintErrorKind::Collector,
                    tr!("{0} did not finish within {1} seconds", name, timeout.as_secs()),
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(e) => {
                return Err(MaintError::new(MaintErrorKind::Collector, format!("{name}: {e}")));
            }
        }
    };
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    Ok(Output { code, stdout, stderr })
}
