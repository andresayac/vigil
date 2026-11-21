//! Administrator rights: whether this process has them, and starting an elevated copy.

use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::{SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::PCWSTR;

use crate::SysError;
use crate::util::wide;

/// True when the process runs with an elevated (administrator) token.
pub fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo handle of the current process is always valid; `token` is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut needed = 0u32;
    // SAFETY: `elevation` is writable for its size; the token handle is valid.
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut needed,
        )
    };
    // SAFETY: the handle was opened above and is closed once.
    unsafe {
        let _ = CloseHandle(token);
    }
    result.is_ok() && elevation.TokenIsElevated != 0
}

/// Starts this executable again with administrator rights (the UAC prompt) and `args`.
///
/// Ok(true): the elevated copy was started. Ok(false): the user declined the prompt.
pub fn relaunch_elevated(args: &[&str]) -> Result<bool, SysError> {
    let exe = std::env::current_exe().map_err(|e| SysError::new(format!("cannot find this program: {e}"), 0))?;
    let directory = exe
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let file = wide(&exe.to_string_lossy());
    let parameters = wide(&join_arguments(args));
    let directory = wide(&directory);
    let verb = wide("runas");
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOASYNC,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        lpDirectory: PCWSTR(directory.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: every string is NUL-terminated and outlives the call; `info` is fully initialized.
    match unsafe { ShellExecuteExW(&mut info) } {
        Ok(()) => Ok(true),
        Err(error) if error.code() == ERROR_CANCELLED.to_hresult() => Ok(false),
        Err(error) => Err(SysError::from_windows("starting the elevated copy", &error)),
    }
}

/// Builds a command line the way the C runtime parses it back into the same arguments.
fn join_arguments(args: &[&str]) -> String {
    args.iter().map(|arg| quote_argument(arg)).collect::<Vec<_>>().join(" ")
}

fn quote_argument(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(ch);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_quoted_for_the_c_runtime() {
        assert_eq!(join_arguments(&["--elevated"]), "--elevated");
        assert_eq!(
            join_arguments(&["--report", r"C:\My Files\a.json"]),
            r#"--report "C:\My Files\a.json""#
        );
        assert_eq!(quote_argument(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quote_argument(r"C:\dir with space\"), r#""C:\dir with space\\""#);
        assert_eq!(quote_argument(""), "\"\"");
    }

    #[test]
    fn elevation_state_is_readable() {
        // Either answer is valid; the call must simply not fail or panic.
        let _ = is_elevated();
    }
}
