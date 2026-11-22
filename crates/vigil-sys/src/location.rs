//! Whether programs running without administrator rights could change Vigil's own folder or
//! executable. A portable `vigil.exe` in Downloads, run as administrator, would load any DLL a
//! program puts next to it (and could be replaced by one): the window warns before asking for
//! rights from such a place.
//!
//! The check is Windows' own access check (`AccessCheck`) with the token a standard program of
//! this user gets: the limited token linked to the elevated one, or this process's own token when
//! it is not elevated. It includes the owner's implicit rights and integrity labels, so it answers
//! exactly "could malware running as this user, without elevation, write here".

use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{
    AccessCheck, DACL_SECURITY_INFORMATION, DuplicateToken, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION,
    GetTokenInformation, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, PSECURITY_DESCRIPTOR,
    SecurityIdentification, TOKEN_DUPLICATE, TOKEN_LINKED_TOKEN, TOKEN_QUERY, TokenLinkedToken,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
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
/// executable): `Some(folder)`. `None` when it is protected, or when it can't be told (no
/// separate standard token, for instance with UAC turned off: there is no boundary to protect).
pub fn unsafe_own_folder() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let folder = exe.parent()?;
    let token = StandardToken::open()?;
    let folder_writable = writable(folder, FOLDER_RISKY, &token)?;
    let file_writable = writable(&exe, FILE_RISKY, &token)?;
    (folder_writable || file_writable).then(|| folder.to_string_lossy().into_owned())
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

/// The token of a standard program of this user, as an identification-level impersonation token.
struct StandardToken(HANDLE);

impl StandardToken {
    fn open() -> Option<StandardToken> {
        let mut own = HANDLE::default();
        // SAFETY: the pseudo handle of this process is always valid; `own` is closed below.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut own) }.ok()?;
        let own = StandardToken(own);
        if crate::elevation::is_elevated() {
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
            return (!linked.LinkedToken.is_invalid()).then_some(StandardToken(linked.LinkedToken));
        }
        let mut duplicate = HANDLE::default();
        // SAFETY: the source token is valid and opened with TOKEN_DUPLICATE; `duplicate` is owned.
        unsafe { DuplicateToken(own.0, SecurityIdentification, &mut duplicate) }.ok()?;
        Some(StandardToken(duplicate))
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
    fn a_temp_folder_is_writable_and_system32_is_not() {
        let Some(token) = StandardToken::open() else {
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
        if let (Some(folder), Some(token)) = (std::env::var_os("VIGIL_CHECK_FOLDER"), StandardToken::open()) {
            println!(
                "that folder writable: {:?}",
                writable(Path::new(&folder), FOLDER_RISKY, &token)
            );
        }
    }
}
