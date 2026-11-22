//! Read-only views that several pages and the request checks share: the process inspector
//! (modules and hosted services), scheduled tasks with their "user-writable" flag, and the test
//! for folders a standard user can write to. Each call is slow enough to keep off the UI thread.

use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleView {
    pub name: String,
    pub path: String,
    pub size: u64,
    /// Loaded from a folder a standard user can write to (profile, ProgramData, temp): where
    /// side-loaded DLLs usually come from.
    pub user_writable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessDetails {
    pub modules: Vec<ModuleView>,
    pub modules_error: Option<String>,
    pub services: Vec<vigil_sys::inspect::HostedService>,
}

/// Modules and hosted services of one process (read-only).
pub fn process_details(pid: u32) -> ProcessDetails {
    let (modules, modules_error) = match vigil_sys::inspect::modules(pid) {
        Ok(list) => (list, None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    let modules = modules
        .into_iter()
        .map(|m| ModuleView {
            user_writable: user_writable(&m.path),
            name: m.name,
            path: m.path,
            size: m.size,
        })
        .collect();
    let services = vigil_sys::inspect::hosted_services(pid).unwrap_or_default();
    ProcessDetails {
        modules,
        modules_error,
        services,
    }
}

/// Every scheduled task, read now, with its user-writable flag (read-only).
pub fn scheduled_tasks() -> Result<Vec<vigil_sys::tasks::ScheduledTask>, String> {
    let mut tasks = vigil_sys::tasks::list().map_err(|e| e.to_string())?;
    for task in &mut tasks {
        task.user_writable = task_writable(task);
    }
    Ok(tasks)
}

/// A program the task runs (or its COM DLL, or the script a Windows host such as PowerShell runs
/// for it) is in a folder a standard user can change.
fn task_writable(task: &vigil_sys::tasks::ScheduledTask) -> bool {
    task.actions.iter().any(|action| {
        !action.program.is_empty()
            && (user_writable(&action.program)
                || (vigil_sys::startup::is_host(&action.program)
                    && argument_paths(&action.arguments).iter().any(|p| user_writable(p))))
    })
}

/// The absolute paths (`C:\...`, `%LOCALAPPDATA%\...`) a command line's arguments name.
fn argument_paths(arguments: &str) -> Vec<String> {
    arguments
        .split(['"', '\'', ' ', '\t', '=', ','])
        .map(|word| {
            let expanded = word
                .strip_prefix('%')
                .and_then(|rest| rest.split_once('%'))
                .and_then(|(name, tail)| std::env::var(name).ok().map(|value| format!("{value}{tail}")));
            expanded.unwrap_or_else(|| word.to_string())
        })
        .filter(|word| {
            let bytes = word.as_bytes();
            bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
        })
        .collect()
}

/// A path inside a folder a standard user can write to (the profile, ProgramData, temp), and
/// outside the Windows and Program Files folders.
pub fn user_writable(path: &str) -> bool {
    let low = path.to_lowercase();
    let under = |var: &str| {
        std::env::var(var)
            .ok()
            .map(|dir| dir.trim_end_matches('\\').to_lowercase())
            .filter(|dir| !dir.is_empty())
            .is_some_and(|dir| low.starts_with(&format!("{dir}\\")))
    };
    let users = std::env::var("SystemDrive")
        .map(|d| format!(r"{}\users\", d.to_lowercase()))
        .unwrap_or_default();
    (under("USERPROFILE") || under("ProgramData") || under("TEMP") || (!users.is_empty() && low.starts_with(&users)))
        && !under("SystemRoot")
        && !under("ProgramFiles")
        && !under("ProgramFiles(x86)")
}

#[cfg(test)]
mod tests {
    use super::{argument_paths, task_writable, user_writable};

    #[test]
    fn writable_folders_are_flagged() {
        let profile = std::env::var("USERPROFILE").unwrap_or_default();
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        assert!(user_writable(&format!(r"{profile}\AppData\Local\Temp\x.dll")));
        assert!(!user_writable(&format!(r"{root}\System32\ntdll.dll")));
        assert!(!user_writable(r"C:\Program Files\App\app.dll"));
    }

    #[test]
    fn tasks_that_run_files_from_writable_folders_are_flagged() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let action = |program: &str, arguments: &str| vigil_sys::tasks::TaskAction {
            kind: "exec".into(),
            program: program.into(),
            arguments: arguments.into(),
            ..Default::default()
        };
        let task = |actions: Vec<vigil_sys::tasks::TaskAction>| vigil_sys::tasks::ScheduledTask {
            actions,
            ..Default::default()
        };
        let powershell = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
        assert!(task_writable(&task(vec![action(
            &powershell,
            r#"-NoProfile -File "%LOCALAPPDATA%\Vendor\sync.ps1""#
        )])));
        let profile = std::env::var("USERPROFILE").unwrap_or_default();
        assert!(task_writable(&task(vec![action(
            &format!(r"{profile}\AppData\Local\Temp\x.exe"),
            ""
        )])));
        assert!(!task_writable(&task(vec![action(&powershell, "-Command Get-Date")])));
        assert!(!task_writable(&task(vec![action(
            r"C:\Program Files\Vendor\updater.exe",
            "/check"
        )])));
        assert!(!task_writable(&task(Vec::new())));
        assert_eq!(
            argument_paths(r#"/a="C:\One Two\x.ps1",D:\y.dll -z"#),
            [r"C:\One", r"D:\y.dll"]
        );
    }
}
