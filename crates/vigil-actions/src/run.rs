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

/// How Run new task starts what it resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    /// Normal rights, started the usual way (Vigil itself has normal rights).
    Normal,
    /// Normal rights, started by Explorer for the signed-in user (Vigil runs as administrator, and
    /// whatever opens the file comes from the user's own registrations).
    AsUser,
    /// Administrator rights, started directly by Vigil, which runs as administrator.
    Elevated,
    /// Administrator rights once Windows asks for them (Vigil itself has normal rights).
    AskAdmin,
}

/// What exactly starts: the program, its arguments, its folder and how.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunPlan {
    pub mode: RunMode,
    pub program: String,
    pub args: String,
    pub folder: String,
}

impl RunPlan {
    /// The command line the confirmation shows; it is exactly what starts.
    pub fn command_line(&self) -> String {
        command_line(&self.program, &self.args)
    }
}

fn extension(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn joined(first: &str, second: &str) -> String {
    match (first.trim(), second.trim()) {
        ("", "") => String::new(),
        (a, "") => a.to_string(),
        ("", b) => b.to_string(),
        (a, b) => format!("{a} {b}"),
    }
}

/// With administrator rights, a file is never started through the user's own file-type
/// registrations (which any program can change): consoles go to mmc.exe and batch files to cmd.exe,
/// both from System32 by full path, and a shortcut is replaced by its target.
fn pinned(program: &str, args: &str, shortcut: &dyn Fn(&str) -> Result<(String, String)>) -> Result<(String, String)> {
    match extension(program).as_str() {
        "exe" | "com" => Ok((program.to_string(), args.trim().to_string())),
        "msc" => Ok((crate::runner::tool("mmc.exe"), joined(&format!("\"{program}\""), args))),
        "bat" | "cmd" => {
            // cmd.exe expands these even inside quotes: such a name could run something else.
            if program.contains(['%', '^', '!', '"']) {
                return fail(tr!(
                    "This batch file's name holds characters the command prompt would read as commands; it is not run with administrator rights."
                ));
            }
            let inner = joined(&format!("\"{program}\""), args);
            Ok((crate::runner::tool("cmd.exe"), format!("/d /s /c \"{inner}\"")))
        }
        "lnk" => {
            let (target, link_args) = shortcut(program)?;
            let target = normpath(&target);
            if !is_abs(&target) || target.starts_with(r"\\") || !Path::new(&target).is_file() {
                return fail(tr!(
                    "This shortcut does not point to a program on this computer; it is not run with administrator rights."
                ));
            }
            if !runnable(Path::new(&target)) || extension(&target) == "lnk" {
                return fail(only_programs());
            }
            pinned(&target, &joined(&link_args, args), shortcut)
        }
        _ => fail(only_programs()),
    }
}

/// How `program` (already resolved) starts with `args`: with the user's normal rights unless
/// `admin` is asked for, and never through the user's registrations while elevated.
pub fn plan(program: &str, args: &str, admin: bool, elevated: bool) -> Result<RunPlan> {
    plan_with(program, args, admin, elevated, &shortcut_target)
}

fn plan_with(
    program: &str,
    args: &str,
    admin: bool,
    elevated: bool,
    shortcut: &dyn Fn(&str) -> Result<(String, String)>,
) -> Result<RunPlan> {
    let folder = Path::new(program)
        .parent()
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !admin {
        let mode = if elevated { RunMode::AsUser } else { RunMode::Normal };
        return Ok(RunPlan {
            mode,
            program: program.to_string(),
            args: args.trim().to_string(),
            folder,
        });
    }
    let (exe, exe_args) = pinned(program, args, shortcut)?;
    Ok(RunPlan {
        mode: if elevated { RunMode::Elevated } else { RunMode::AskAdmin },
        program: exe,
        args: exe_args,
        folder,
    })
}

/// The target and arguments of a shortcut, read with the shell's own shortcut object.
fn shortcut_target(path: &str) -> Result<(String, String)> {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile,
        STGM_READ,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, SLGP_RAWPATH, ShellLink};
    use windows::core::Interface;

    fn read(path: &str) -> windows::core::Result<(String, String)> {
        // SAFETY: COM calls on interfaces owned here; the buffers outlive the calls that fill them.
        unsafe {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            let file: IPersistFile = link.cast()?;
            file.Load(&HSTRING::from(path), STGM_READ)?;
            let mut target = vec![0u16; 1024];
            link.GetPath(&mut target, std::ptr::null_mut(), SLGP_RAWPATH.0 as u32)?;
            let mut args = vec![0u16; 2048];
            link.GetArguments(&mut args)?;
            let text = |buffer: &[u16]| {
                let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
                String::from_utf16_lossy(&buffer[..end])
            };
            Ok((expand_env(&text(&target)), text(&args)))
        }
    }

    let path = path.to_string();
    let result = std::thread::spawn(move || {
        // SAFETY: initializes COM on this new thread; balanced below when it succeeded.
        let initialized = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_ok();
        let result = read(&path).map_err(|e| e.message());
        if initialized {
            // SAFETY: pairs the CoInitializeEx above on the same thread; nothing is still held.
            unsafe { CoUninitialize() };
        }
        result
    })
    .join();
    match result {
        Ok(Ok(found)) => Ok(found),
        Ok(Err(reason)) => fail(tr!("The shortcut could not be read: {0}", reason)),
        Err(_) => fail(tr!("The shortcut could not be read: {0}", "-")),
    }
}

/// Starts a program directly, with Vigil's own rights, by its full path: no file-type or protocol
/// registration is consulted. A console program gets its own window.
fn start_direct(program: &str, args: &str, folder: &str) -> Result<Option<u32>> {
    use windows::Win32::System::Threading::{
        CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
    };
    let application = HSTRING::from(program);
    let mut line: Vec<u16> = command_line(program, args).encode_utf16().chain(Some(0)).collect();
    let directory = HSTRING::from(folder);
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every string outlives the call; the command line buffer is writable and
    // NUL-terminated as CreateProcessW requires; `info` receives the handles, closed below.
    unsafe {
        CreateProcessW(
            &application,
            Some(windows::core::PWSTR(line.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
            None,
            if folder.is_empty() {
                PCWSTR::null()
            } else {
                PCWSTR(directory.as_ptr())
            },
            &startup,
            &mut info,
        )
    }
    .map_err(|e| crate::error::ActionError::new(tr!("Windows could not start it: {0}", e.message())))?;
    // SAFETY: both handles came from CreateProcessW and are closed once.
    unsafe {
        let _ = CloseHandle(info.hThread);
        let _ = CloseHandle(info.hProcess);
    }
    Ok((info.dwProcessId != 0).then_some(info.dwProcessId))
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

/// `process.run`: params `path` (resolved again here), `args`, `admin`, and `command`: the command
/// line the confirmation showed, which must still be the one that starts.
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
    let plan = plan(&program, &args, p.flag("admin"), crate::is_admin())?;
    let line = plan.command_line();
    let shown = p.str_or_empty("command");
    if !shown.is_empty() && shown != line {
        return fail(tr!(
            "What this would start changed after you confirmed it (now: {0}); nothing was started.",
            line
        ));
    }
    let pid = match plan.mode {
        RunMode::Normal => start(&plan.program, &plan.args, false)?,
        RunMode::AskAdmin => start(&plan.program, &plan.args, true)?,
        RunMode::Elevated => start_direct(&plan.program, &plan.args, &plan.folder)?,
        RunMode::AsUser => {
            crate::desktop::launch_as_user(&plan.program, &plan.args, &plan.folder)?;
            None
        }
    };
    let message = match pid {
        Some(pid) => tr!("started {0} (PID {1})", line, pid),
        None => tr!("started {0}", line),
    };
    let elevated = matches!(plan.mode, RunMode::Elevated | RunMode::AskAdmin);
    Ok(Outcome::new(
        message,
        Some(json!({ "path": plan.program, "pid": pid, "elevated": elevated })),
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

    fn no_shortcut(_: &str) -> Result<(String, String)> {
        fail("not a shortcut")
    }

    #[test]
    fn without_administrator_rights_asked_an_elevated_vigil_starts_it_as_the_user() {
        let program = r"C:\Tools\a b\viewer.exe";
        let normal = plan_with(program, " -v ", false, false, &no_shortcut).expect("plan");
        assert_eq!(normal.mode, RunMode::Normal);
        assert_eq!(normal.command_line(), r#""C:\Tools\a b\viewer.exe" -v"#);
        let as_user = plan_with(program, " -v ", false, true, &no_shortcut).expect("plan");
        assert_eq!(as_user.mode, RunMode::AsUser, "never Vigil's administrator rights");
        assert_eq!(as_user.program, program);
        assert_eq!(as_user.folder, r"C:\Tools\a b");
        // Consoles, batch files and shortcuts keep their own handling for the user.
        let console = plan_with(r"C:\Windows\System32\services.msc", "", false, true, &no_shortcut).expect("plan");
        assert_eq!(
            (console.mode, console.program.as_str()),
            (RunMode::AsUser, r"C:\Windows\System32\services.msc")
        );
    }

    #[test]
    fn with_administrator_rights_file_types_are_pinned_to_system_programs() {
        let mmc = crate::runner::tool("mmc.exe");
        let cmd = crate::runner::tool("cmd.exe");
        let console = plan_with(r"C:\Windows\System32\services.msc", "/s", true, true, &no_shortcut).expect("plan");
        assert_eq!(console.mode, RunMode::Elevated);
        assert_eq!(console.program, mmc);
        assert_eq!(console.args, r#""C:\Windows\System32\services.msc" /s"#);
        assert_eq!(
            console.command_line(),
            format!(r#""{mmc}" "C:\Windows\System32\services.msc" /s"#)
        );
        let batch = plan_with(r"C:\Jobs\nightly job.cmd", "", true, false, &no_shortcut).expect("plan");
        assert_eq!(batch.mode, RunMode::AskAdmin);
        assert_eq!(batch.program, cmd);
        assert_eq!(batch.args, r#"/d /s /c ""C:\Jobs\nightly job.cmd"""#);
        let with_args = plan_with(r"C:\Jobs\x.bat", "one two", true, true, &no_shortcut).expect("plan");
        assert_eq!(with_args.args, r#"/d /s /c ""C:\Jobs\x.bat" one two""#);
        for risky in [r"C:\Jobs\a%PATH%.bat", r"C:\Jobs\a^b.cmd", r"C:\Jobs\a!b.bat"] {
            assert!(plan_with(risky, "", true, true, &no_shortcut).is_err(), "{risky}");
        }
        let exe = plan_with(r"C:\Tools\setup.exe", "/quiet", true, true, &no_shortcut).expect("plan");
        assert_eq!(
            (exe.program.as_str(), exe.args.as_str()),
            (r"C:\Tools\setup.exe", "/quiet")
        );
        assert!(plan_with(r"C:\Tools\notes.txt", "", true, true, &no_shortcut).is_err());
    }

    #[test]
    fn an_administrator_shortcut_runs_its_checked_target() {
        let notepad = format!(r"{}\System32\notepad.exe", windir());
        let target = notepad.clone();
        let reader = move |_: &str| Ok((target.clone(), "C:\\notes.txt".to_string()));
        let shortcut = plan_with(r"C:\Users\jdoe\Desktop\Notes.lnk", "-x", true, true, &reader).expect("plan");
        assert_eq!(shortcut.mode, RunMode::Elevated);
        assert_eq!(shortcut.program.to_lowercase(), notepad.to_lowercase());
        assert_eq!(shortcut.args, r"C:\notes.txt -x");
        // A shortcut to a document, a network share, a missing file or another shortcut is refused.
        for target in [
            format!(r"{}\win.ini", windir()),
            r"\\203.0.113.5\share\tool.exe".to_string(),
            r"C:\Vigil-does-not-exist\tool.exe".to_string(),
        ] {
            let reader = move |_: &str| Ok((target.clone(), String::new()));
            assert!(plan_with(r"C:\Users\jdoe\Desktop\x.lnk", "", true, true, &reader).is_err());
        }
        assert!(plan_with(r"C:\Users\jdoe\Desktop\x.lnk", "", true, true, &no_shortcut).is_err());
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
