//! Whether programs running without administrator rights could change Vigil's own folder or
//! executable. A portable `vigil.exe` in Downloads, run as administrator, would load any DLL a
//! program puts next to it (and could be replaced by one): the window warns before asking for
//! rights from such a place.
//!
//! The check is Windows' own access check (`AccessCheck`) with the token of the programs the
//! person at the keyboard runs: when Vigil is elevated, the token of the shell (Explorer) of this
//! session, which is the interactive user's even when another account's password elevated Vigil;
//! the limited token linked to the elevated one only when the shell's can't be read; this
//! process's own token when it is not elevated. It includes the owner's implicit rights and
//! integrity labels, so it answers exactly "could malware running as that user, without elevation,
//! write here".
//!
//! It fails closed: a folder whose permissions can't be read, or a check that can't be made, counts
//! as unsafe. Only an elevated shell (UAC turned off) means there is no boundary to protect.

use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{
    AccessCheck, DACL_SECURITY_INFORMATION, DuplicateToken, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION,
    GetTokenInformation, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, PSECURITY_DESCRIPTOR,
    SecurityIdentification, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_LINKED_TOKEN, TOKEN_QUERY, TokenElevation,
    TokenLinkedToken,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};
use windows::core::{BOOL, PCWSTR};

use crate::util::wide;

/// Adding or deleting files in the folder, or taking it over.
const FOLDER_RISKY: u32 = 0x0002 | 0x0040 | 0x0004_0000 | 0x0008_0000;
/// Writing the executable, or taking it over.
const FILE_RISKY: u32 = 0x0002 | 0x0004 | 0x0004_0000 | 0x0008_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const FILE_MAPPING: GENERIC_MAPPING = GENERIC_MAPPING {
    GenericRead: 0x0012_0089,
    GenericWrite: 0x0012_0116,
    GenericExecute: 0x0012_00A0,
    GenericAll: 0x001F_01FF,
};

/// Vigil's own folder when programs without administrator rights can change it (or the
/// executable), or when that can't be checked: `Some(folder)`. `None` when it is protected, or
/// when the interactive user's programs run elevated anyway (UAC turned off: there is no boundary
/// to protect).
pub fn unsafe_own_folder() -> Option<String> {
    let Ok(exe) = std::env::current_exe() else {
        return Some("?".into());
    };
    let folder = exe.parent().unwrap_or(&exe);
    let shown = folder.to_string_lossy().into_owned();
    let token = match StandardToken::open() {
        Standard::Token(token) => token,
        Standard::NoBoundary => return None,
        Standard::Unknown => return Some(shown),
    };
    let folder_writable = writable(folder, FOLDER_RISKY, &token);
    let file_writable = writable(&exe, FILE_RISKY, &token);
    unsafe_verdict(folder_writable, file_writable).then_some(shown)
}

/// Unsafe unless both checks were made and both said "not writable".
fn unsafe_verdict(folder_writable: Option<bool>, file_writable: Option<bool>) -> bool {
    folder_writable != Some(false) || file_writable != Some(false)
}

/// Whether `token` holds any of `risky` on `path` (`None`: the check could not be made).
fn writable(path: &Path, risky: u32, token: &StandardToken) -> Option<bool> {
    let name = wide(&path.to_string_lossy());
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `name` is NUL-terminated; the descriptor returned in `sd` is LocalAlloc'd and freed
    // below. Reading a descriptor changes nothing.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut sd,
        )
    };
    if status.is_err() {
        return None;
    }
    let mut privileges = [0u8; 256];
    let mut privileges_len = privileges.len() as u32;
    let mut granted = 0u32;
    let mut allowed = BOOL(0);
    // SAFETY: `sd` is a valid self-relative descriptor; the token is an impersonation token at
    // identification level; every out pointer is valid for the call.
    let result = unsafe {
        AccessCheck(
            sd,
            token.0,
            MAXIMUM_ALLOWED,
            &FILE_MAPPING,
            Some(privileges.as_mut_ptr().cast::<PRIVILEGE_SET>()),
            &mut privileges_len,
            &mut granted,
            &mut allowed,
        )
    };
    // SAFETY: `sd` came from GetNamedSecurityInfoW and is freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    result.ok()?;
    Some(allowed.as_bool() && granted & risky != 0)
}

/// The token to check with (see the module notes).
enum Standard {
    Token(StandardToken),
    /// The interactive user's programs run elevated: there is no standard token to protect from.
    NoBoundary,
    /// No token could be read: the check fails closed.
    Unknown,
}

/// The token of a standard program of this user, as an identification-level impersonation token.
struct StandardToken(HANDLE);

fn token_elevated(token: HANDLE) -> Option<bool> {
    let mut elevation = TOKEN_ELEVATION::default();
    let mut needed = 0u32;
    // SAFETY: `elevation` is writable for its size; the token handle is valid for the call.
    unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut needed,
        )
    }
    .ok()?;
    Some(elevation.TokenIsElevated != 0)
}

impl StandardToken {
    fn open() -> Standard {
        if !crate::elevation::is_elevated() {
            return StandardToken::own().map_or(Standard::Unknown, Standard::Token);
        }
        match StandardToken::shell() {
            Some((_, true)) => Standard::NoBoundary,
            Some((token, false)) => Standard::Token(token),
            None => StandardToken::linked().map_or(Standard::Unknown, Standard::Token),
        }
    }

    /// The token of this session's shell (Explorer), and whether it is elevated.
    fn shell() -> Option<(StandardToken, bool)> {
        // SAFETY: plain calls; the window may be gone, which only makes them fail.
        let window = unsafe { GetShellWindow() };
        if window.is_invalid() {
            return None;
        }
        let mut pid = 0u32;
        // SAFETY: `pid` is writable; the window handle is only read.
        unsafe { GetWindowThreadProcessId(window, Some(&mut pid)) };
        if pid == 0 {
            return None;
        }
        // SAFETY: plain call; the handle is closed below.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let process = StandardToken(process);
        let mut token = HANDLE::default();
        // SAFETY: the process handle is valid; `token` is owned from here on.
        unsafe { OpenProcessToken(process.0, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token) }.ok()?;
        let token = StandardToken(token);
        let elevated = token_elevated(token.0)?;
        let mut duplicate = HANDLE::default();
        // SAFETY: the source token is valid and opened with TOKEN_DUPLICATE; `duplicate` is owned.
        unsafe { DuplicateToken(token.0, SecurityIdentification, &mut duplicate) }.ok()?;
        Some((StandardToken(duplicate), elevated))
    }

    /// This process's own token (not elevated).
    fn own() -> Option<StandardToken> {
        let mut own = HANDLE::default();
        // SAFETY: the pseudo handle of this process is always valid; `own` is closed by its owner.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut own) }.ok()?;
        let own = StandardToken(own);
        let mut duplicate = HANDLE::default();
        // SAFETY: the source token is valid and opened with TOKEN_DUPLICATE; `duplicate` is owned.
        unsafe { DuplicateToken(own.0, SecurityIdentification, &mut duplicate) }.ok()?;
        Some(StandardToken(duplicate))
    }

    /// The limited token linked to this elevated one.
    fn linked() -> Option<StandardToken> {
        let mut own = HANDLE::default();
        // SAFETY: the pseudo handle of this process is always valid; `own` is closed by its owner.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut own) }.ok()?;
        let own = StandardToken(own);
        // The limited token of the same sign-in: what programs started without elevation get.
        let mut linked = TOKEN_LINKED_TOKEN::default();
        let mut needed = 0u32;
        // SAFETY: `linked` is writable for its size; the token handle is valid. The linked
        // token returned is an identification-level impersonation token owned by us.
        unsafe {
            GetTokenInformation(
                own.0,
                TokenLinkedToken,
                Some((&mut linked as *mut TOKEN_LINKED_TOKEN).cast()),
                size_of::<TOKEN_LINKED_TOKEN>() as u32,
                &mut needed,
            )
        }
        .ok()?;
        (!linked.LinkedToken.is_invalid()).then_some(StandardToken(linked.LinkedToken))
    }
}

impl Drop for StandardToken {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by this module and is closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_that_cannot_be_made_counts_as_unsafe() {
        assert!(!unsafe_verdict(Some(false), Some(false)));
        assert!(unsafe_verdict(Some(true), Some(false)));
        assert!(unsafe_verdict(Some(false), Some(true)));
        assert!(unsafe_verdict(None, Some(false)), "unreadable folder permissions");
        assert!(unsafe_verdict(Some(false), None), "unreadable file permissions");
        let missing = std::env::temp_dir()
            .join("vigil-location-missing-7f3c")
            .join("vigil.exe");
        if let Standard::Token(token) = StandardToken::open() {
            assert_eq!(writable(&missing, FILE_RISKY, &token), None);
        }
    }

    #[test]
    fn a_temp_folder_is_writable_and_system32_is_not() {
        let Standard::Token(token) = StandardToken::open() else {
            // Elevated with UAC turned off (some CI machines): no standard token to check.
            return;
        };
        let temp = std::env::temp_dir();
        assert_eq!(
            writable(&temp, FOLDER_RISKY, &token),
            Some(true),
            "the temp folder is the user's"
        );
        let system = crate::paths::system_dir();
        assert_eq!(
            writable(&system, FOLDER_RISKY, &token),
            Some(false),
            "System32 is not writable by a standard program"
        );
        assert_eq!(writable(&system.join("kernel32.dll"), FILE_RISKY, &token), Some(false));
    }

    #[test]
    #[ignore = "live: prints whether this test executable's folder counts as unsafe"]
    fn live_own_folder() {
        println!("own folder unsafe: {}", unsafe_own_folder().is_some());
        // Any other folder to compare with, e.g. one an installer created in Program Files.
        if let (Some(folder), Standard::Token(token)) = (std::env::var_os("VIGIL_CHECK_FOLDER"), StandardToken::open())
        {
            println!(
                "that folder writable: {:?}",
                writable(Path::new(&folder), FOLDER_RISKY, &token)
            );
        }
    }
}
