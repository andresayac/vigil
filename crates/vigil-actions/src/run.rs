//! Run new task: starting a program the user typed or picked, like Task Manager's "Run new task".
//!
//! The page only asks. The program is resolved here to one existing file (a full path, or a bare name
//! found on PATH or in App Paths, never in the current folder), the arguments are checked, and the
//! exact command line is what the confirmation shows. The program starts with ShellExecuteExW: no
//! command line is built for a shell to parse.

use std::path::Path;

use serde_json::json;
use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE};
use windows::Win32::System::Threading::GetProcessId;
use windows::Win32::UI::Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{HSTRING, PCWSTR, w};

use crate::cmdline::{expand_env, in_dir, is_abs, normpath};
use crate::engine::Outcome;
use crate::error::{Result, fail};
use crate::params::Params;
use crate::registry::reg_read;
use crate::store::Store;
use vigil_i18n::tr;

/// What Run new task starts: programs, scripts Windows runs as programs, consoles and shortcuts.
pub const RUNNABLE: [&str; 6] = ["exe", "com", "bat", "cmd", "msc", "lnk"];
const MAX_PATH_TEXT: usize = 1024;
pub const MAX_ARGS: usize = 2048;

fn runnable(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| RUNNABLE.iter().any(|r| r.eq_ignore_ascii_case(e)))
}

fn only_programs() -> String {
    tr!("Only programs can be run (.exe, .com, .bat, .cmd, .msc, .lnk).")
}

/// An existing file of a runnable kind, as a normalized full path.
fn existing_program(path: &str) -> Result<String> {
    let path = normpath(path);
    if !runnable(Path::new(&path)) {
        return fail(only_programs());
    }
    if !Path::new(&path).is_file() {
        return fail(tr!("The file does not exist: {0}", path));
    }
    Ok(path)
}

/// The folders of PATH, full paths only (a relative entry would mean "the current folder").
fn path_dirs() -> Vec<String> {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(';')
        .map(|d| expand_env(d.trim().trim_matches('"')))
        .filter(|d| is_abs(d) && !d.starts_with(r"\\"))
        .collect()
}

/// The names to try for a bare name: itself when it has a runnable extension, else the name with each
/// runnable extension of PATHEXT, in that order.
fn candidate_names(name: &str) -> Result<Vec<String>> {
    let path = Path::new(name);
    if path.extension().is_some() && runnable(path) {
        return Ok(vec![name.to_string()]);
    }
    if path.extension().is_some() && !name.ends_with('.') {
        return fail(only_programs());
    }
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
    let mut names: Vec<String> = pathext
        .split(';')
        .map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|e| RUNNABLE.contains(&e.as_str()) && *e != "lnk" && *e != "msc")
        .map(|e| format!("{}.{e}", name.trim_end_matches('.')))
        .collect();
    names.dedup();
    Ok(names)
}

/// The program registered for a name under App Paths (how "chrome" or "winword" are found).
fn app_path(name: &str) -> Option<String> {
    let file = if Path::new(name).extension().is_some() {
        name.to_string()
    } else {
        format!("{name}.exe")
    };
    for hive in ["HKCU", "HKLM"] {
        let key = format!(r"{hive}\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{file}");
        let Ok(Some(value)) = reg_read(&key, "") else {
            continue;
        };
        let Some(text) = value.get("data").and_then(|d| d.as_str()) else {
            continue;
        };
        let path = expand_env(text.trim().trim_matches('"'));
        if is_abs(&path) && !path.starts_with(r"\\") && runnable(Path::new(&path)) && Path::new(&path).is_file() {
            return Some(normpath(&path));
        }
    }
    None
}

/// The one file `input` names: a full path to an existing program, or a bare name ("notepad",
/// "services.msc") found on PATH or in App Paths. Network and device paths, relative paths and the
/// current folder are refused.
pub fn resolve_program(input: &str) -> Result<String> {
    let text = input.trim();
    let text = text
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or(text)
        .trim();
    if text.is_empty() {
        return fail(tr!("Type the program to run."));
    }
    if text.len() > MAX_PATH_TEXT
        || text
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '<' | '>' | '|' | '*' | '?'))
    {
        return fail(tr!("This is not a valid program path."));
    }
    if text.starts_with(r"\\") || text.starts_with("//") {
        return fail(tr!("Network and device paths are not run from Vigil."));
    }
    if is_abs(text) {
        let program = existing_program(text)?;
        if let Ok(data) = crate::data_dir()
            && in_dir(&program, &data.to_string_lossy())
        {
            return fail(tr!("Files in Vigil's data folder are not run."));
        }
        return Ok(program);
    }
    if text.contains(['\\', '/', ':']) {
        return fail(tr!(
            "Type the full path of the program, or the name of a program such as notepad."
        ));
    }
    let names = candidate_names(text)?;
    let dirs = path_dirs();
    for name in &names {
        for dir in &dirs {
            let path = Path::new(dir).join(name);
            if path.is_file() {
                return Ok(normpath(&path.to_string_lossy()));
            }
        }
    }
    if let Some(found) = app_path(text) {
        return Ok(found);
    }
    fail(tr!("Windows cannot find {0}.", text))
}

/// Arguments travel exactly as typed (the program parses them); only their size and control
/// characters are checked.
pub fn check_args(args: &str) -> Result<()> {
    if args.chars().count() > MAX_ARGS {
        return fail(tr!("The arguments are too long."));
    }
    if args.chars().any(char::is_control) {
        return fail(tr!("The arguments cannot contain line breaks or control characters."));
    }
    Ok(())
}

/// The command line as the confirmation shows it.
pub fn command_line(program: &str, args: &str) -> String {
    let args = args.trim();
    if args.is_empty() {
        format!("\"{program}\"")
    } else {
        format!("\"{program}\" {args}")
    }
}

/// Starts the program; `elevate` asks Windows for administrator rights (UAC). Returns its PID when
/// Windows reports one (a shortcut or a console may hand over to another process).
fn start(program: &str, args: &str, elevate: bool) -> Result<Option<u32>> {
    let file = HSTRING::from(program);
    let parameters = HSTRING::from(args.trim());
    let folder = Path::new(program)
        .parent()
        .map(|d| HSTRING::from(d.as_os_str()))
        .unwrap_or_default();
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: if elevate { w!("runas") } else { w!("open") },
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: if args.trim().is_empty() {
            PCWSTR::null()
        } else {
            PCWSTR(parameters.as_ptr())
        },
        lpDirectory: if folder.is_empty() {
            PCWSTR::null()
        } else {
            PCWSTR(folder.as_ptr())
        },
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: every string outlives the call; `info` is fully initialized with its size.
    if let Err(error) = unsafe { ShellExecuteExW(&mut info) } {
        if error.code() == ERROR_CANCELLED.to_hresult() {
            return fail(tr!("The administrator prompt was cancelled."));
        }
        return fail(tr!("Windows could not start it: {0}", error.message()));
    }
    let process: HANDLE = info.hProcess;
    if process.is_invalid() {
        return Ok(None);
    }
    // SAFETY: the handle came from ShellExecuteExW with SEE_MASK_NOCLOSEPROCESS and is closed once.
    let pid = unsafe { GetProcessId(process) };
    // SAFETY: as above.
    unsafe {
        let _ = CloseHandle(process);
    }
    Ok((pid != 0).then_some(pid))
}

/// `process.run`: params `path` (resolved again here), `args`, `admin`.
pub(crate) fn op_run(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let path = p.req_str("path")?;
    if !is_abs(&path) {
        return fail(tr!(
            "Type the full path of the program, or the name of a program such as notepad."
        ));
    }
    let program = resolve_program(&path)?;
    let args = p.str_or_empty("args");
    check_args(&args)?;
    let elevate = p.flag("admin") && !crate::is_admin();
    let pid = start(&program, &args, elevate)?;
    let line = command_line(&program, &args);
    let message = match pid {
        Some(pid) => tr!("started {0} (PID {1})", line, pid),
        None => tr!("started {0}", line),
    };
    Ok(Outcome::new(
        message,
        Some(json!({ "path": program, "pid": pid, "elevated": elevate })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn windir() -> String {
        crate::runner::windir().to_string_lossy().into_owned()
    }

    #[test]
    fn bare_names_are_found_on_path() {
        let notepad = resolve_program("notepad").expect("notepad");
        assert!(notepad.to_lowercase().ends_with(r"\notepad.exe"), "{notepad}");
        assert!(Path::new(&notepad).is_file());
        let services = resolve_program("services.msc").expect("services.msc");
        assert!(services.to_lowercase().ends_with(r"\services.msc"), "{services}");
        let cmd = resolve_program("  \"cmd\"  ").expect("cmd");
        assert!(cmd.to_lowercase().ends_with(r"\cmd.exe"), "{cmd}");
    }

    #[test]
    fn full_paths_must_exist_and_be_programs() {
        let notepad = format!(r"{}\System32\notepad.exe", windir());
        assert_eq!(
            resolve_program(&notepad).map(|p| p.to_lowercase()).ok(),
            Some(notepad.to_lowercase())
        );
        let win_ini = format!(r"{}\win.ini", windir());
        assert!(resolve_program(&win_ini).is_err(), "not a program");
        assert!(resolve_program(r"C:\Vigil-does-not-exist\nothing.exe").is_err());
        let messages: Vec<String> = [
            "",
            "   ",
            r"\\203.0.113.5\share\tool.exe",
            r"\\?\C:\Windows\notepad.exe",
            r"..\tool.exe",
            r"bin\tool.exe",
            "notes.txt",
            "calc & whoami",
            "notepad\u{0}.exe",
            "a|b",
        ]
        .iter()
        .map(|input| {
            resolve_program(input)
                .map_err(|e| e.to_string())
                .err()
                .unwrap_or_default()
        })
        .collect();
        assert!(messages.iter().all(|m| !m.is_empty()), "{messages:?}");
        assert_eq!(messages[0], "Type the program to run.");
        assert_eq!(messages[2], "Network and device paths are not run from Vigil.");
        assert_eq!(
            messages[6],
            "Only programs can be run (.exe, .com, .bat, .cmd, .msc, .lnk)."
        );
    }

    #[test]
    fn arguments_are_checked_and_shown_as_typed() {
        assert!(check_args("").is_ok());
        assert!(
            check_args(r#"/c "dir C:\" & echo hi"#).is_ok(),
            "passed as typed, never parsed here"
        );
        assert!(check_args("line\nbreak").is_err());
        assert!(check_args(&"x".repeat(MAX_ARGS + 1)).is_err());
        assert_eq!(command_line(r"C:\Tools\a b.exe", "  -v  "), r#""C:\Tools\a b.exe" -v"#);
        assert_eq!(command_line(r"C:\Tools\a.exe", ""), r#""C:\Tools\a.exe""#);
    }

    #[test]
    fn the_run_operation_refuses_what_it_was_not_shown() {
        let store_dir = std::env::temp_dir().join(format!("vigil-run-{}", std::process::id()));
        let store = Store::open(&store_dir).expect("store");
        for params in [
            json!({"path": "notepad"}),
            json!({"path": r"C:\Vigil-does-not-exist\nothing.exe"}),
            json!({"path": format!(r"{}\System32\notepad.exe", windir()), "args": "a\r\nb"}),
        ] {
            assert!(op_run(Params::new(&params), &store, "").is_err(), "{params}");
        }
        let _ = std::fs::remove_dir_all(&store_dir);
    }
}
