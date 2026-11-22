//! Files in a folder of the user's own profile that an elevated Vigil also writes
//! (`%LOCALAPPDATA%\Vigil\watch`). Any program the user runs can change that folder, so below the
//! base folder nothing is ever opened by path (AGENTS.md rule 8):
//!
//! - The base folder (`%LOCALAPPDATA%`) is opened first, and its final path must lie inside the
//!   user's profile: a base turned into a junction to another place is refused.
//! - Each folder below it, and each file, is opened relative to the handle of its parent
//!   (`NtCreateFile` with a root directory), with `OBJ_DONT_REPARSE` and `FILE_OPEN_REPARSE_POINT`:
//!   a junction, symbolic link or mount point below the base makes the open fail, and what was
//!   opened is checked again by handle (no reparse attribute; a file has exactly one name).
//! - A file is replaced by creating a new temporary file (never opening an existing one), flushing
//!   it to disk, and renaming it over the old name relative to the folder handle. A rename replaces
//!   the folder entry; it never writes through a link the old name might be.
//!
//! Swapping a folder for a link after it was opened changes nothing: every later step uses the
//! handle, not the path.

use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformation, NTCREATEFILE_CREATE_DISPOSITION,
    NTCREATEFILE_CREATE_OPTIONS, NtCreateFile, NtSetInformationFile,
};
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ACCESS_RIGHTS, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FileDispositionInfo, GETFINALPATHNAMEBYHANDLE_FLAGS,
    GetFileInformationByHandle, GetFinalPathNameByHandleW, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    LockFileEx, OPEN_EXISTING, SYNCHRONIZE, SetFileInformationByHandle, UnlockFileEx,
};
use windows::Win32::System::IO::{IO_STATUS_BLOCK, OVERLAPPED};
use windows::core::{HSTRING, PWSTR};

/// A handle closed when dropped.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by this module and is closed once, here.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn os_error(error: &windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error(error.code().0 & 0xFFFF)
}

/// A folder opened by handle, inside a base folder the user owns.
pub struct Dir {
    handle: Owned,
    /// The path it was opened as (for messages only; never used to open anything).
    shown: PathBuf,
}

/// The names Vigil gives its own files: one component, no separators, no "." or "..".
fn check_name(name: &str) -> io::Result<()> {
    let bad =
        name.is_empty() || name == "." || name == ".." || name.contains(['\\', '/', ':', '\0']) || name.len() > 200;
    if bad {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid file name: {name}"),
        ));
    }
    Ok(())
}

/// Opens a folder by path (the base and the profile only), following what Windows follows.
fn open_path_dir(path: &Path) -> io::Result<Owned> {
    let name = HSTRING::from(path.as_os_str());
    // SAFETY: plain call; the handle is owned by `Owned`.
    let handle = unsafe {
        CreateFileW(
            &name,
            (FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE)
                .0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .map_err(|e| os_error(&e))?;
    Ok(Owned(handle))
}

/// The final path of an open handle, lower case, without the `\\?\` prefix.
fn final_path(handle: &Owned) -> io::Result<String> {
    let mut buffer = vec![0u16; 1024];
    loop {
        // SAFETY: the buffer is writable for its length.
        let written = unsafe { GetFinalPathNameByHandleW(handle.0, &mut buffer, GETFINALPATHNAMEBYHANDLE_FLAGS(0)) };
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        if (written as usize) < buffer.len() {
            let text = String::from_utf16_lossy(&buffer[..written as usize]);
            let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
            return Ok(text.trim_end_matches('\\').to_lowercase());
        }
        if buffer.len() > 65_536 {
            return Err(io::Error::other("path too long"));
        }
        buffer = vec![0u16; written as usize + 1];
    }
}

fn info(handle: HANDLE) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `info` is a valid output structure.
    unsafe { GetFileInformationByHandle(handle, &mut info) }.map_err(|e| os_error(&e))?;
    Ok(info)
}

fn refuse_link(shown: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{} is a link; Vigil does not go through links here.", shown.display()),
    )
}

/// `NtCreateFile` relative to `root`, refusing every reparse point on the way.
fn nt_open(
    root: HANDLE,
    name: &str,
    access: FILE_ACCESS_RIGHTS,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
    options: NTCREATEFILE_CREATE_OPTIONS,
) -> io::Result<Owned> {
    check_name(name)?;
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let bytes = u16::try_from(wide.len() * 2).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let object_name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: PWSTR(wide.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root,
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        ..Default::default()
    };
    let mut handle = HANDLE::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: every pointer refers to a local that outlives the call (`wide` backs `object_name`);
    // the handle is owned by `Owned` from here on.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            None,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            disposition,
            options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            None,
            0,
        )
    };
    if status.is_err() {
        // SAFETY: converts a status code; no pointers involved.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(Owned(handle))
}

static TEMP_COUNTER: AtomicU32 = AtomicU32::new(0);

impl Dir {
    /// Opens `base\parts...`, creating the folders that are missing. `inside`: the folder the base
    /// must be in once links are resolved (the user's profile); `None` skips that check (tests).
    pub fn open(base: &Path, parts: &[&str], inside: Option<&Path>) -> io::Result<Dir> {
        let mut current = open_path_dir(base)?;
        if let Some(inside) = inside {
            let root = final_path(&open_path_dir(inside)?)?;
            let at = final_path(&current)?;
            if !(at == root || at.starts_with(&format!("{root}\\"))) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{} is not inside {}", base.display(), inside.display()),
                ));
            }
        }
        let mut shown = base.to_path_buf();
        for part in parts {
            shown.push(part);
            let access =
                FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_READ_ATTRIBUTES;
            let next = nt_open(current.0, part, access, FILE_OPEN_IF, FILE_DIRECTORY_FILE)
                .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", shown.display())))?;
            if info(next.0)?.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                return Err(refuse_link(&shown));
            }
            current = next;
        }
        Ok(Dir { handle: current, shown })
    }

    /// Opens one file of this folder; it must be a plain file with a single name.
    fn file(
        &self,
        name: &str,
        access: FILE_ACCESS_RIGHTS,
        disposition: NTCREATEFILE_CREATE_DISPOSITION,
    ) -> io::Result<File> {
        // Reading the attributes is needed for the check below.
        let handle = nt_open(
            self.handle.0,
            name,
            access | FILE_READ_ATTRIBUTES,
            disposition,
            FILE_NON_DIRECTORY_FILE,
        )?;
        let found = info(handle.0)?;
        if found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 || found.nNumberOfLinks > 1 {
            return Err(refuse_link(&self.shown.join(name)));
        }
        let raw = handle.0;
        std::mem::forget(handle);
        // SAFETY: `raw` is a valid file handle this function owns; `File` closes it.
        Ok(unsafe { File::from_raw_handle(raw.0) })
    }

    /// The whole file (`NotFound` when it does not exist).
    pub fn read(&self, name: &str) -> io::Result<Vec<u8>> {
        let mut file = self.file(name, FILE_GENERIC_READ, FILE_OPEN)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    /// Replaces the file with `bytes`: a new temporary file, flushed, renamed over the old one.
    pub fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        check_name(name)?;
        let mut attempt = 0;
        let (temp, file) = loop {
            let temp = format!(
                "{name}.{}.{}.tmp",
                std::process::id(),
                TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            match self.file(&temp, FILE_GENERIC_WRITE | DELETE, FILE_CREATE) {
                Ok(file) => break (temp, file),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists && attempt < 8 => attempt += 1,
                Err(error) => return Err(error),
            }
        };
        let result = (|| {
            let mut writer = &file;
            writer.write_all(bytes)?;
            file.sync_all()?;
            self.rename(&file, name)
        })();
        if result.is_err() {
            delete_on_close(&file);
        }
        drop(file);
        result.map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", self.shown.join(&temp).display())))
    }

    /// Renames an open file of this folder to `name` (relative to the folder handle), replacing
    /// what has that name.
    fn rename(&self, file: &File, name: &str) -> io::Result<()> {
        let wide: Vec<u16> = name.encode_utf16().collect();
        let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
        let size = header + (wide.len() + 1) * 2;
        let mut storage = vec![0u64; size.div_ceil(8)];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        // SAFETY: `storage` is zeroed, 8-byte aligned and large enough for the header and the
        // name with its terminator; the name is copied right after the header.
        unsafe {
            (*info).Anonymous.ReplaceIfExists = true;
            (*info).RootDirectory = self.handle.0;
            (*info).FileNameLength = (wide.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(
                wide.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                wide.len(),
            );
        }
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: the buffer holds a complete FILE_RENAME_INFORMATION of `size` bytes; the file
        // handle was opened with DELETE access.
        let status = unsafe {
            NtSetInformationFile(
                HANDLE(file.as_raw_handle()),
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

    /// An exclusive lock on `name` (created when missing), shared with every process that locks
    /// the same file; waits up to `timeout`.
    pub fn lock(&self, name: &str, timeout: Duration) -> io::Result<FileLock> {
        let file = self.file(name, FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_OPEN_IF)?;
        let started = Instant::now();
        loop {
            let mut overlapped = OVERLAPPED::default();
            // SAFETY: valid handle; `overlapped` lives for the (synchronous) call.
            let locked = unsafe {
                LockFileEx(
                    HANDLE(file.as_raw_handle()),
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    None,
                    1,
                    0,
                    &mut overlapped,
                )
            };
            if locked.is_ok() {
                return Ok(FileLock { file });
            }
            if started.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} is busy", self.shown.join(name).display()),
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn delete_on_close(file: &File) {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: valid handle opened with DELETE access; the structure lives for the call.
    let _ = unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            std::ptr::addr_of!(info).cast::<c_void>(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
}

/// Held while a change is made; released when dropped (and by Windows if the process ends).
pub struct FileLock {
    file: File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let mut overlapped = OVERLAPPED::default();
        // SAFETY: valid handle; unlocks the byte locked in `Dir::lock`.
        let _ = unsafe { UnlockFileEx(HANDLE(self.file.as_raw_handle()), None, 1, 0, &mut overlapped) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Temp(PathBuf);

    impl Temp {
        fn new(name: &str) -> Temp {
            let path = std::env::temp_dir().join(format!("vigil-userdir-{name}-{}", std::process::id()));
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
        let cmd = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join(r"System32\cmd.exe");
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
    fn files_are_written_and_replaced_by_handle() {
        let base = Temp::new("write");
        let dir = Dir::open(&base.0, &["Vigil", "watch"], Some(&base.0)).expect("opened");
        assert!(base.0.join(r"Vigil\watch").is_dir());
        assert_eq!(
            dir.read("watch.json").map_err(|e| e.kind()),
            Err(io::ErrorKind::NotFound)
        );
        dir.write("watch.json", b"first").expect("written");
        dir.write("watch.json", b"second").expect("replaced");
        assert_eq!(dir.read("watch.json").expect("read"), b"second");
        dir.write("watch.json.bad", &dir.read("watch.json").expect("read"))
            .expect("copied");
        assert_eq!(
            std::fs::read(base.0.join(r"Vigil\watch\watch.json.bad")).ok(),
            Some(b"second".to_vec())
        );
        let names: Vec<String> = std::fs::read_dir(base.0.join(r"Vigil\watch"))
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
        for bad in ["..", r"..\x", "a/b", ""] {
            assert!(dir.write(bad, b"x").is_err(), "{bad}");
        }
    }

    #[test]
    fn links_below_the_base_are_refused() {
        let base = Temp::new("links");
        let elsewhere = Temp::new("elsewhere");
        assert!(
            junction(&base.0.join("Vigil"), &elsewhere.0),
            "the test junction was created"
        );
        let refused = Dir::open(&base.0, &["Vigil", "watch"], Some(&base.0));
        assert!(refused.is_err());
        assert!(
            !elsewhere.0.join("watch").exists(),
            "nothing was created through the link"
        );
        // A link as the last folder.
        std::fs::create_dir_all(base.0.join("Real")).ok();
        assert!(junction(&base.0.join(r"Real\watch"), &elsewhere.0));
        assert!(Dir::open(&base.0, &["Real", "watch"], Some(&base.0)).is_err());
        // A base that resolves outside the folder it must be in.
        assert!(Dir::open(&elsewhere.0, &["x"], Some(&base.0)).is_err());
    }

    #[test]
    fn a_file_with_several_names_is_not_read() {
        let base = Temp::new("hardlink");
        let dir = Dir::open(&base.0, &["watch"], None).expect("opened");
        std::fs::write(base.0.join("other.txt"), b"not for Vigil").ok();
        std::fs::hard_link(base.0.join("other.txt"), base.0.join(r"watch\watch.json")).ok();
        assert!(dir.read("watch.json").is_err());
        // Replacing it by rename leaves the other file alone.
        dir.write("watch.json", b"{}").expect("replaced");
        assert_eq!(
            std::fs::read(base.0.join("other.txt")).ok(),
            Some(b"not for Vigil".to_vec())
        );
    }

    #[test]
    fn the_lock_is_exclusive_and_released() {
        let base = Temp::new("lock");
        let dir = Dir::open(&base.0, &["watch"], None).expect("opened");
        let held = dir.lock("watch.lock", Duration::from_secs(1)).expect("locked");
        let other = Dir::open(&base.0, &["watch"], None).expect("opened again");
        let busy = other.lock("watch.lock", Duration::from_millis(100));
        assert_eq!(busy.map(|_| ()).map_err(|e| e.kind()), Err(io::ErrorKind::TimedOut));
        drop(held);
        assert!(other.lock("watch.lock", Duration::from_millis(500)).is_ok());
    }
}
