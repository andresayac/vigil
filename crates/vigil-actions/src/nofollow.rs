//! Files and folders opened without following links (AGENTS.md rule 8), for the places where the
//! elevated copy writes or changes permissions: the data folder, quarantine restore, exports.
//!
//! - A starting folder is opened by path with `FILE_FLAG_OPEN_REPARSE_POINT`: a link is opened as
//!   itself, never followed, and the caller checks the attributes of what it got.
//! - Everything below it is opened relative to the parent's handle (`NtCreateFile` with a root
//!   directory, `OBJ_DONT_REPARSE`, `FILE_OPEN_REPARSE_POINT`): a junction, symbolic link or mount
//!   point on the way makes the open fail.
//! - Handles are held without delete sharing, so what was checked cannot be renamed away or
//!   replaced while it is used. There is no fallback that shares delete access: a folder someone
//!   else holds for deletion is refused.
//! - A file is written as a new temporary file relative to its folder's handle, then renamed over
//!   the name: an existing file, link or hard link at that name is replaced as an entry, never
//!   written through.

use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Write};
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformation, NTCREATEFILE_CREATE_DISPOSITION,
    NTCREATEFILE_CREATE_OPTIONS, NtCreateFile, NtSetInformationFile,
};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_FILES, HANDLE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError,
    UNICODE_STRING,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ACCESS_RIGHTS, FILE_ADD_FILE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FULL_DIR_INFO, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FileDispositionInfo,
    FileFullDirectoryInfo, FileFullDirectoryRestartInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetLongPathNameW, OPEN_EXISTING, SYNCHRONIZE, SetFileInformationByHandle,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::core::{HSTRING, PCWSTR, PWSTR};

/// Read and write sharing, never delete: nobody can rename or replace what is held.
pub(crate) const SHARE_NO_DELETE: FILE_SHARE_MODE = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0);

/// A handle closed when dropped.
#[derive(Debug)]
pub(crate) struct Handle(HANDLE);

impl Handle {
    pub(crate) fn raw(&self) -> HANDLE {
        self.0
    }

    /// The handle as a `File` (which closes it).
    pub(crate) fn into_file(self) -> File {
        let raw = self.0;
        std::mem::forget(self);
        // SAFETY: `raw` is a valid handle this value owned; `File` closes it from now on.
        unsafe { File::from_raw_handle(raw.0) }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by this module and is closed once, here.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn os_error(error: &windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error(error.code().0 & 0xFFFF)
}

/// One name inside a folder: no separators, no stream (`:`), not `.` or `..`.
pub(crate) fn plain_name(name: &str) -> bool {
    !(name.is_empty() || name == "." || name == ".." || name.contains(['\\', '/', ':', '\0']) || name.len() > 255)
}

/// Opens `path` by name without following a link at its end (a link is opened as itself).
pub(crate) fn open_path(path: &Path, access: FILE_ACCESS_RIGHTS, share: FILE_SHARE_MODE) -> io::Result<Handle> {
    let name = HSTRING::from(path.as_os_str());
    // SAFETY: plain call; the handle is owned by `Handle`.
    let handle = unsafe {
        CreateFileW(
            &name,
            (access | SYNCHRONIZE).0,
            share,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|e| os_error(&e))?;
    Ok(Handle(handle))
}

/// `NtCreateFile` of `name` relative to `root`, refusing every reparse point.
pub(crate) fn open_at(
    root: &Handle,
    name: &str,
    access: FILE_ACCESS_RIGHTS,
    share: FILE_SHARE_MODE,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
    options: NTCREATEFILE_CREATE_OPTIONS,
) -> io::Result<Handle> {
    if !plain_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid file name: {name}"),
        ));
    }
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let bytes = u16::try_from(wide.len() * 2).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let object_name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: PWSTR(wide.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root.0,
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        ..Default::default()
    };
    let mut handle = HANDLE::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: every pointer refers to a local that outlives the call (`wide` backs `object_name`);
    // the handle is owned by `Handle` from here on.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            None,
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT,
            None,
            0,
        )
    };
    if status.is_err() {
        // SAFETY: converts a status code; no pointers involved.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(Handle(handle))
}

/// What Windows knows about an open file or folder.
pub(crate) fn info(handle: &Handle) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `info` is a valid output structure; the handle is open.
    unsafe { GetFileInformationByHandle(handle.0, &mut info) }.map_err(|e| os_error(&e))?;
    Ok(info)
}

pub(crate) fn is_link(info: &BY_HANDLE_FILE_INFORMATION) -> bool {
    info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

pub(crate) fn is_dir(info: &BY_HANDLE_FILE_INFORMATION) -> bool {
    info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
}

/// The names in an open folder (opened with `FILE_LIST_DIRECTORY`) and their attributes, without
/// `.` and `..`.
pub(crate) fn entries(dir: &Handle) -> io::Result<Vec<(String, u32)>> {
    let mut found = Vec::new();
    let mut buffer = vec![0u64; 8192];
    let bytes = (buffer.len() * 8) as u32;
    let mut class = FileFullDirectoryRestartInfo;
    loop {
        // SAFETY: `buffer` is writable for `bytes` bytes and 8-byte aligned; the handle is open.
        let read = unsafe { GetFileInformationByHandleEx(dir.0, class, buffer.as_mut_ptr().cast::<c_void>(), bytes) };
        if let Err(error) = read {
            if error.code() == ERROR_NO_MORE_FILES.to_hresult() {
                return Ok(found);
            }
            return Err(os_error(&error));
        }
        class = FileFullDirectoryInfo;
        let base = buffer.as_ptr().cast::<u8>();
        let name_at = std::mem::offset_of!(FILE_FULL_DIR_INFO, FileName);
        let mut offset = 0usize;
        loop {
            if offset + name_at > bytes as usize {
                break;
            }
            // SAFETY: `offset` stays inside the buffer the call filled (checked above and below);
            // the records are 8-byte aligned as Windows writes them.
            let record = unsafe { &*base.add(offset).cast::<FILE_FULL_DIR_INFO>() };
            let length = record.FileNameLength as usize / 2;
            if offset + name_at + length * 2 > bytes as usize {
                break;
            }
            // SAFETY: the name has `length` UTF-16 units right after the header, inside the buffer.
            let name = unsafe { std::slice::from_raw_parts(base.add(offset + name_at).cast::<u16>(), length) };
            let name = String::from_utf16_lossy(name);
            if name != "." && name != ".." {
                found.push((name, record.FileAttributes));
            }
            if record.NextEntryOffset == 0 {
                break;
            }
            offset += record.NextEntryOffset as usize;
        }
    }
}

/// Renames an open file or folder (opened with `DELETE`) to `name` in the same folder; never
/// replaces what has that name.
pub(crate) fn rename_here(handle: &Handle, name: &str) -> io::Result<()> {
    rename(handle, None, name, false)
}

/// Renames an open file (opened with `DELETE`) to `name` in the folder `root` (its own folder when
/// `None`), replacing the entry with that name when `replace`.
fn rename(handle: &Handle, root: Option<&Handle>, name: &str, replace: bool) -> io::Result<()> {
    if !plain_name(name) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let wide: Vec<u16> = name.encode_utf16().collect();
    let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let size = header + (wide.len() + 1) * 2;
    let mut storage = vec![0u64; size.div_ceil(8)];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: `storage` is zeroed, 8-byte aligned and large enough for the header and the name
    // with its terminator. A name without separators: relative to `root`, or a rename in place.
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        if let Some(root) = root {
            (*info).RootDirectory = root.0;
        }
        (*info).FileNameLength = (wide.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            wide.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            wide.len(),
        );
    }
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the buffer holds a complete FILE_RENAME_INFORMATION of `size` bytes.
    let status = unsafe {
        NtSetInformationFile(
            handle.0,
            &mut status_block,
            storage.as_ptr().cast::<c_void>(),
            size as u32,
            FileRenameInformation,
        )
    };
    if status.is_err() {
        // SAFETY: converts a status code; no pointers involved.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

/// Marks an open file or empty folder (opened with `DELETE`) for deletion when its last handle
/// closes.
pub(crate) fn delete_on_close(handle: HANDLE) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the handle is open for the call; `info` outlives it.
    unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            std::ptr::from_ref(&info).cast::<c_void>(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(|e| os_error(&e))
}

/// `path` with short (8.3) names expanded and nothing else resolved: a junction keeps its name.
pub(crate) fn long_name(path: &str) -> String {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buffer = vec![0u16; 1024];
    // SAFETY: `wide` is NUL-terminated; `buffer` is writable for its whole length.
    let length = unsafe { GetLongPathNameW(PCWSTR(wide.as_ptr()), Some(&mut buffer)) } as usize;
    if length == 0 || length >= buffer.len() {
        return path.to_string();
    }
    String::from_utf16_lossy(&buffer[..length])
}

static TEMP_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Writes a file the user chose (an export): while Vigil is elevated, without following a link
/// (see [`write_no_follow`]); otherwise as any program of the user would.
pub fn write_user_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if vigil_sys::elevation::is_elevated() {
        write_no_follow(path, bytes)
    } else {
        std::fs::write(path, bytes)
    }
}

/// Writes `bytes` to `path` without following links: the folder is opened as itself and must be
/// reached through no link (its real path is the path asked for); the bytes go to a new temporary
/// file created relative to the folder's handle, which is then renamed over the name. An existing
/// file, symbolic link or hard link with that name is replaced as an entry, never written through.
pub(crate) fn write_no_follow(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, path.display().to_string());
    let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(invalid)?;
    if !plain_name(name) {
        return Err(invalid());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(invalid)?;
    let linked = || {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            vigil_i18n::tr!(
                "{0} is reached through a junction or symbolic link; Vigil does not write there while it runs as \
                 administrator",
                parent.display()
            ),
        )
    };
    let folder = open_path(
        parent,
        FILE_TRAVERSE | FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_READ_ATTRIBUTES,
        SHARE_NO_DELETE,
    )?;
    let found = info(&folder)?;
    if is_link(&found) || !is_dir(&found) {
        return Err(linked());
    }
    let real = final_path(folder.0).ok_or_else(linked)?;
    let asked = long_name(&parent.to_string_lossy());
    if !real
        .trim_end_matches('\\')
        .eq_ignore_ascii_case(asked.trim_end_matches('\\'))
    {
        return Err(linked());
    }
    let mut attempt = 0;
    let temp = loop {
        let temp = format!(
            "{name}.{}.{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        match open_at(
            &folder,
            &temp,
            FILE_GENERIC_WRITE | DELETE,
            FILE_SHARE_MODE(0),
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE,
        ) {
            Ok(handle) => break handle,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && attempt < 8 => attempt += 1,
            Err(error) => return Err(error),
        }
    };
    let written = (|| {
        let file = std::mem::ManuallyDrop::new(
            // SAFETY: borrows the handle as a `File` without taking it over (never dropped).
            unsafe { File::from_raw_handle(temp.0.0) },
        );
        let mut writer: &File = &file;
        writer.write_all(bytes)?;
        file.sync_all()?;
        rename(&temp, Some(&folder), name, true)
    })();
    if written.is_err() {
        let _ = delete_on_close(temp.0);
    }
    written
}

/// The path Windows has for an open handle (`C:\...`, long names); `None` for network paths.
pub(crate) fn final_path(handle: HANDLE) -> Option<String> {
    let mut buffer = vec![0u16; 1024];
    for _ in 0..2 {
        // SAFETY: the handle is open for the call; `buffer` is writable for its whole length.
        let length = unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, FILE_NAME_NORMALIZED) } as usize;
        if length == 0 {
            return None;
        }
        if length < buffer.len() {
            let text = String::from_utf16_lossy(&buffer[..length]);
            let text = text.strip_prefix(r"\\?\").unwrap_or(&text).to_string();
            return (!text.starts_with(r"UNC\")).then_some(text);
        }
        buffer.resize(length + 1, 0);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Temp(std::path::PathBuf);

    impl Temp {
        fn new(name: &str) -> Temp {
            let path = std::env::temp_dir().join(format!("vigil-nofollow-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).ok();
            Temp(path)
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            // Junctions are removed as links (their target stays).
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn junction(link: &Path, target: &Path) -> bool {
        let cmd = vigil_sys::paths::system_dir().join("cmd.exe");
        std::process::Command::new(cmd)
            .args(["/d", "/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    #[test]
    fn an_export_is_written_and_replaced_without_following_links() {
        let base = Temp::new("write");
        let path = base.0.join("report.html");
        write_no_follow(&path, b"first").expect("written");
        write_no_follow(&path, b"second").expect("replaced");
        assert_eq!(std::fs::read(&path).ok(), Some(b"second".to_vec()));
        // A hard link planted at the name is replaced as an entry: the other file keeps its bytes.
        let other = base.0.join("other.txt");
        std::fs::write(&other, b"not for Vigil").ok();
        std::fs::remove_file(&path).ok();
        std::fs::hard_link(&other, &path).expect("hard link");
        write_no_follow(&path, b"export").expect("replaced the link");
        assert_eq!(std::fs::read(&other).ok(), Some(b"not for Vigil".to_vec()));
        assert_eq!(std::fs::read(&path).ok(), Some(b"export".to_vec()));
        let names: Vec<String> = std::fs::read_dir(&base.0)
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
    }

    #[test]
    fn an_export_through_a_junction_is_refused() {
        let base = Temp::new("junction");
        let elsewhere = Temp::new("elsewhere");
        assert!(
            junction(&base.0.join("Reports"), &elsewhere.0),
            "the test junction was created"
        );
        let refused = write_no_follow(&base.0.join(r"Reports\report.html"), b"x");
        assert!(refused.is_err());
        // A junction higher up: the real path differs from the one asked for.
        std::fs::create_dir_all(elsewhere.0.join("Deep")).ok();
        let refused = write_no_follow(&base.0.join(r"Reports\Deep\report.html"), b"x");
        assert!(refused.is_err());
        assert!(!elsewhere.0.join("report.html").exists());
        assert!(!elsewhere.0.join(r"Deep\report.html").exists());
        assert!(write_no_follow(&base.0.join(".."), b"x").is_err());
    }
}
