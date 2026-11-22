//! The Installed programs page: the live list (read-only), the signatures of the programs' files,
//! and the requests that uninstall a program, remove a leftover entry or open an install folder.
//! A request names a program by its id (its Uninstall key); Rust reads that key again and builds
//! every text of the confirmation from what it finds there, never from the page.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};
use vigil_i18n::{tl, tr};
use vigil_sys::programs::{Program, is_microsoft};

use crate::cli::say;
use crate::planner::{SpecExt, spec};
use crate::requests::{Plan, size_text};
use crate::tools::{flags, print_json, table};

/// "Recently installed": within this many days.
pub const RECENT_DAYS: i64 = 7;

/// A program as the page shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramView {
    #[serde(flatten)]
    pub program: Program,
    /// A remote access, remote control or tunnelling tool (the list the scan uses).
    pub remote: bool,
    /// Published by Microsoft: Vigil never removes its entry.
    pub microsoft: bool,
}

pub fn view(program: Program) -> ProgramView {
    let text = [
        program.name.as_str(),
        program.publisher.as_str(),
        program.location.as_str(),
        program.executable.as_str(),
        program.uninstaller.as_str(),
    ]
    .join(" | ");
    ProgramView {
        remote: vigil_scan::rules::is_remote_access_tool(&text),
        microsoft: is_microsoft(&program.publisher),
        program,
    }
}

/// Every installed program, read now (read-only; call it off the UI thread).
pub fn list() -> Vec<ProgramView> {
    let programs = vigil_sys::programs::list();
    remember_files(&programs);
    programs.into_iter().map(view).collect()
}

/// The files of the list read last and when, so the signature checks that follow a refresh do
/// not read the whole list again for every batch.
static FILES: LazyLock<Mutex<Option<KnownFiles>>> = LazyLock::new(|| Mutex::new(None));

/// When the list was read, and the lower-case paths of its files.
type KnownFiles = (Instant, HashSet<String>);

/// How long the remembered files stand for the live list.
const FILES_FRESH: Duration = Duration::from_secs(300);

fn remember_files(programs: &[Program]) -> HashSet<String> {
    let files: HashSet<String> = programs
        .iter()
        .flat_map(checked_paths)
        .map(|p| p.to_lowercase())
        .collect();
    *FILES.lock().unwrap_or_else(PoisonError::into_inner) = Some((Instant::now(), files.clone()));
    files
}

/// The files of the live list whose signature may be checked.
fn known_files() -> HashSet<String> {
    if let Some((read, files)) = FILES.lock().unwrap_or_else(PoisonError::into_inner).as_ref()
        && read.elapsed() < FILES_FRESH
    {
        return files.clone();
    }
    remember_files(&vigil_sys::programs::list())
}

// ------------------------------------------------------------------------------------ signatures

/// The signature of one file, as the page shows it (the same shape as the Startup apps page).
#[derive(Debug, Clone, Serialize)]
pub struct ProgramSignature {
    /// "valid", "unsigned", "broken", "untrusted", "missing" or "unknown".
    status: String,
    signer: String,
}

fn signature_view(info: Option<&vigil_actions::SignatureInfo>) -> ProgramSignature {
    let Some(info) = info else {
        return ProgramSignature {
            status: "unknown".into(),
            signer: String::new(),
        };
    };
    let status = match (info.exists, info.sig_status.as_deref()) {
        (Some(false), _) => "missing",
        (_, Some("Valid")) => "valid",
        (_, Some("NotSigned")) => "unsigned",
        (_, Some("HashMismatch")) => "broken",
        (_, Some("NotTrusted")) => "untrusted",
        _ => "unknown",
    };
    ProgramSignature {
        status: status.into(),
        signer: info.signer.clone().unwrap_or_default(),
    }
}

/// The files of a program whose signature says something: its own executable and its uninstaller
/// (not a Windows host such as msiexec, whose signature is Microsoft's).
pub fn checked_paths(program: &Program) -> Vec<String> {
    let mut out = Vec::new();
    if !program.executable.is_empty() {
        out.push(program.executable.clone());
    }
    if program.uninstaller_exists
        && !program.uninstaller_host
        && !out.iter().any(|p| p.eq_ignore_ascii_case(&program.uninstaller))
    {
        out.push(program.uninstaller.clone());
    }
    out
}

/// Checked signatures by lower-case path, for this session.
static SIGNATURES: LazyLock<Mutex<HashMap<String, ProgramSignature>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// The Authenticode signatures of programs' files (read-only). Only files of the live list are
/// checked, in a few PowerShell batches at a time; results are kept for the session. Slow: call it
/// off the UI thread.
pub fn signatures(paths: Vec<String>) -> HashMap<String, ProgramSignature> {
    {
        let known = known_files();
        let mut out = HashMap::new();
        let mut todo: Vec<String> = Vec::new();
        {
            let cache = SIGNATURES.lock().unwrap_or_else(PoisonError::into_inner);
            for path in paths.into_iter().take(256) {
                let key = path.to_lowercase();
                if !known.contains(&key) {
                    continue;
                }
                if let Some(found) = cache.get(&key) {
                    out.insert(path, found.clone());
                } else if !todo.iter().any(|p| p.eq_ignore_ascii_case(&path)) {
                    todo.push(path);
                }
            }
        }
        let size = todo.len().div_ceil(4).max(1);
        let checked: Vec<(String, ProgramSignature)> = std::thread::scope(|scope| {
            let workers: Vec<_> = todo
                .chunks(size)
                .map(|chunk| {
                    scope.spawn(move || {
                        let found = vigil_actions::verify_signatures(chunk);
                        chunk
                            .iter()
                            .zip(found)
                            .map(|(path, info)| (path.clone(), signature_view(info.as_ref())))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap_or_default())
                .collect()
        });
        let mut cache = SIGNATURES.lock().unwrap_or_else(PoisonError::into_inner);
        for (path, signature) in checked {
            if signature.status != "unknown" {
                cache.insert(path.to_lowercase(), signature.clone());
            }
            out.insert(path, signature);
        }
        out
    }
}

// ------------------------------------------------------------------------------------ vigil programs

const PROGRAMS_HELP: &str = tl!("\
Installed programs, as Settings > Apps > Installed apps lists them.

Usage: vigil programs [--recent] [--json] [--lang CODE]

  --recent     only programs installed in the last 7 days, newest first
  --json       machine-readable output");

/// Installed within the last [`RECENT_DAYS`] days (`today` is `YYYY-MM-DD`).
pub fn is_recent(program: &Program, today: &str) -> bool {
    vigil_sys::programs::days_between(&program.installed, today).is_some_and(|days| (0..=RECENT_DAYS).contains(&days))
}

/// `vigil programs`: the installed programs (read-only).
pub fn cli(args: &[String]) -> Result<(), String> {
    let mut recent = false;
    let (json, help) = flags(args, |arg, _| {
        Ok(match arg {
            "--recent" => {
                recent = true;
                true
            }
            _ => false,
        })
    })?;
    if help {
        say(&tr!(PROGRAMS_HELP));
        return Ok(());
    }
    let today = vigil_sys::programs::today();
    let mut rows: Vec<ProgramView> = vigil_sys::programs::list().into_iter().map(view).collect();
    if recent {
        rows.retain(|p| is_recent(&p.program, &today));
        rows.sort_by(|a, b| b.program.installed.cmp(&a.program.installed));
    }
    if json {
        print_json(&serde_json::to_value(&rows).unwrap_or(Value::Null));
        return Ok(());
    }
    let headers = [
        tr!("Name"),
        tr!("Version"),
        tr!("Install date"),
        tr!("Size"),
        tr!("Publisher"),
        tr!("Notes"),
    ];
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|view| {
            let p = &view.program;
            let mut notes = Vec::new();
            if view.remote {
                notes.push(tr!("remote access"));
            }
            if p.leftover {
                notes.push(tr!("leftover entry"));
            }
            if !p.sid.is_empty() {
                notes.push(tr!("account {0}", p.account));
            }
            vec![
                p.name.clone(),
                p.version.clone(),
                p.installed.clone(),
                if p.size == 0 { String::new() } else { size_text(p.size) },
                p.publisher.clone(),
                notes.join(", "),
            ]
        })
        .collect();
    table(&headers, &body, &[40, 16, 10, 9, 28]);
    Ok(())
}

// ------------------------------------------------------------------------------------ requests

/// A request about a program: the program is read again from its Uninstall key.
pub fn plan(op: &str, id: &str) -> Result<Plan, String> {
    let program = vigil_sys::programs::read_entry(id.trim());
    plan_for(op, program.as_ref())
}

/// Uninstall it with its own uninstaller, remove its leftover entry, or open its install folder.
pub(crate) fn plan_for(op: &str, program: Option<&Program>) -> Result<Plan, String> {
    let program = program.ok_or(tr!("The program is no longer in the list. Refresh the list."))?;
    let quoted = format!("\"{}\"", program.name);
    if op == "folder" {
        if program.location.is_empty() || !program.location_exists {
            return Err(tr!("The install folder of {0} does not exist.", quoted));
        }
        return Ok(Plan::Shell(
            spec(
                "shell.folder",
                tr!("Open install folder"),
                program.location.clone(),
                tr!("Opens the folder."),
            )
            .params(json!({ "path": program.location }))
            .no_admin(),
        ));
    }
    if !program.sid.is_empty() {
        return Err(tr!(
            "{0} was installed for another account ({1}). Sign in as that account to change it.",
            quoted,
            program.account
        ));
    }
    let built = match op {
        "uninstall" => {
            if program.uninstall.is_empty() {
                return Err(tr!(
                    "{0} lists no uninstaller. Use Settings > Apps > Installed apps.",
                    quoted
                ));
            }
            if program.no_remove {
                return Err(tr!(
                    "The installer of {0} asks not to be uninstalled from here. Use Settings > Apps > Installed apps.",
                    quoted
                ));
            }
            if program.msi && !program.product_code.is_empty() && !program.msi_known {
                return Err(tr!(
                    "Windows Installer no longer knows {0}, so it cannot uninstall it. If its files are gone, remove its leftover entry instead.",
                    quoted
                ));
            }
            if !program.msi && !program.uninstaller_exists {
                return Err(tr!(
                    "The uninstaller of {0} no longer exists. If its files are gone too, remove its leftover entry instead.",
                    quoted
                ));
            }
            spec(
                "program.uninstall",
                tr!("Uninstall {0}", quoted),
                program.uninstall.clone(),
                tr!(
                    "Starts the program's own uninstaller, as Settings does; follow its window to finish. Vigil cannot undo an uninstall: to get the program back, install it again."
                ),
            )
            // The command shown is pinned: the uninstall refuses to start a different one.
            .params(json!({ "registry_key": program.id, "name": program.name, "command": program.uninstall.trim() }))
            .group("remove")
            .destructive()
            .irreversible()
        }
        "remove_entry" => {
            if is_microsoft(&program.publisher) {
                return Err(tr!(
                    "{0} is published by Microsoft; Vigil does not remove its entry.",
                    quoted
                ));
            }
            if program.msi && program.msi_known {
                return Err(tr!("Windows Installer still knows {0}: uninstall it instead.", quoted));
            }
            if !program.leftover {
                return Err(tr!(
                    "The uninstaller or the files of {0} are still there: uninstall it instead of removing its entry.",
                    quoted
                ));
            }
            spec(
                "program.remove_entry",
                tr!("Remove the leftover entry {0}", quoted),
                program.id.clone(),
                tr!(
                    "The program's uninstaller and files are already gone; only its line in Installed apps is left. This removes that line (its registry key). The key is saved first, so you can bring the entry back from History. Nothing else is changed."
                ),
            )
            .params(json!({ "key": program.id, "name": program.name }))
            .group("remove")
            .destructive()
        }
        _ => return Err(tr!("Unknown request: {0}", op)),
    };
    // This account's programs live in its own part of the registry: no administrator rights needed.
    let built = if program.scope == "user" {
        built.no_admin()
    } else {
        built
    };
    Ok(Plan::Run {
        spec: built,
        item: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requests::Request;

    fn program(name: &str) -> Program {
        Program {
            id: format!(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\{name}"),
            key_name: name.into(),
            name: name.into(),
            publisher: "Contoso Ltd.".into(),
            uninstall: format!(r#""C:\Program Files\{name}\uninstall.exe" /remove"#),
            uninstaller: format!(r"C:\Program Files\{name}\uninstall.exe"),
            uninstaller_exists: true,
            location: format!(r"C:\Program Files\{name}"),
            location_exists: true,
            scope: "machine".into(),
            ..Program::default()
        }
    }

    fn leftover(name: &str) -> Program {
        Program {
            uninstaller_exists: false,
            location_exists: false,
            leftover: true,
            ..program(name)
        }
    }

    fn run_spec(op: &str, p: &Program) -> Result<vigil_actions::ActionSpec, String> {
        match plan_for(op, Some(p))? {
            Plan::Run { spec, .. } => Ok(spec),
            Plan::Shell(spec) => Ok(spec),
            _ => Err("unexpected plan".into()),
        }
    }

    #[test]
    fn uninstall_uses_the_programs_own_uninstaller() {
        let notes = program("Contoso Notes");
        let spec = run_spec("uninstall", &notes).expect("uninstall");
        assert_eq!(spec.op, "program.uninstall");
        assert_eq!(spec.params["registry_key"], notes.id);
        assert_eq!(spec.params["name"], "Contoso Notes");
        assert_eq!(
            spec.target, notes.uninstall,
            "the confirmation shows the command that runs"
        );
        assert!(spec.destructive && !spec.reversible && spec.admin);

        let mine = Program {
            scope: "user".into(),
            ..program("Fabrikam Viewer")
        };
        assert!(
            !run_spec("uninstall", &mine).expect("user").admin,
            "this account's programs"
        );

        let msi = Program {
            msi: true,
            msi_known: true,
            product_code: "{11111111-2222-3333-4444-555555555555}".into(),
            uninstall: "MsiExec.exe /X{11111111-2222-3333-4444-555555555555}".into(),
            uninstaller_exists: true,
            uninstaller_host: true,
            ..program("Northwind Agent")
        };
        assert!(run_spec("uninstall", &msi).is_ok());
    }

    #[test]
    fn uninstall_is_refused_when_it_cannot_work() {
        let refused = |p: Program, words: &str| {
            let error = run_spec("uninstall", &p).expect_err("refused");
            assert!(error.contains(words), "{error}");
        };
        refused(
            Program {
                uninstall: String::new(),
                ..program("A")
            },
            "no uninstaller",
        );
        refused(
            Program {
                no_remove: true,
                ..program("B")
            },
            "asks not to",
        );
        refused(leftover("C"), "leftover entry");
        refused(
            Program {
                msi: true,
                product_code: "{11111111-2222-3333-4444-555555555555}".into(),
                msi_known: false,
                ..program("D")
            },
            "Windows Installer no longer knows",
        );
        refused(
            Program {
                sid: "S-1-5-21-1-2-3-1001".into(),
                account: r"DESKTOP-ABC123\jdoe".into(),
                scope: "user".into(),
                ..program("E")
            },
            "another account",
        );
        assert!(plan_for("uninstall", None).is_err());
        assert!(run_spec("format", &program("F")).is_err());
    }

    #[test]
    fn only_leftover_entries_are_removed() {
        let gone = leftover("Fabrikam Viewer");
        let spec = run_spec("remove_entry", &gone).expect("remove");
        assert_eq!(spec.op, "program.remove_entry");
        assert_eq!(spec.params["key"], gone.id);
        assert!(spec.destructive && spec.reversible && spec.admin);
        let mine = Program {
            scope: "user".into(),
            ..leftover("Woodgrove")
        };
        assert!(!run_spec("remove_entry", &mine).expect("user").admin);

        let refused = |p: Program, words: &str| {
            let error = run_spec("remove_entry", &p).expect_err("refused");
            assert!(error.contains(words), "{error}");
        };
        refused(program("Contoso Notes"), "still there");
        refused(
            Program {
                publisher: "Microsoft Corporation".into(),
                ..leftover("Runtime")
            },
            "Microsoft",
        );
        refused(
            Program {
                msi: true,
                msi_known: true,
                ..leftover("Agent")
            },
            "still knows",
        );
    }

    #[test]
    fn folders_open_without_confirmation() {
        let notes = program("Contoso Notes");
        match plan_for("folder", Some(&notes)) {
            Ok(Plan::Shell(spec)) => {
                assert_eq!(spec.op, "shell.folder");
                assert_eq!(spec.params["path"], notes.location);
            }
            _ => panic!("a shell plan"),
        }
        assert!(plan_for("folder", Some(&leftover("Gone"))).is_err());
    }

    #[test]
    fn remote_tools_and_microsoft_are_marked() {
        let remote = view(Program {
            name: "AnyDesk".into(),
            ..program("AnyDesk")
        });
        assert!(remote.remote && !remote.microsoft);
        let office = view(Program {
            publisher: "Microsoft Corporation".into(),
            ..program("Office")
        });
        assert!(office.microsoft && !office.remote);
        let json = serde_json::to_value(&office).expect("json");
        assert_eq!(json["name"], "Office", "the program's fields are flattened");
        assert_eq!(json["microsoft"], true);
        assert!(json.get("locationExists").is_some());
    }

    #[test]
    fn the_request_kind_is_program() {
        let parsed: Request =
            serde_json::from_value(json!({"kind": "program", "op": "uninstall", "id": "HKLM\\x\\y"})).expect("request");
        assert!(matches!(parsed, Request::Program { ref op, .. } if op == "uninstall"));
        let unknown = plan(
            "uninstall",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Vigil Tests Nothing",
        );
        assert!(unknown.is_err(), "a missing entry is refused");
        assert!(plan("uninstall", r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip").is_err());
    }

    #[test]
    fn recent_means_the_last_seven_days() {
        let on = |day: &str| Program {
            installed: day.into(),
            ..program("A")
        };
        assert!(is_recent(&on("2026-02-15"), "2026-02-22"));
        assert!(is_recent(&on("2026-02-22"), "2026-02-22"));
        assert!(!is_recent(&on("2026-02-14"), "2026-02-22"));
        assert!(!is_recent(&on("2026-03-01"), "2026-02-22"), "a date in the future");
        assert!(!is_recent(&on(""), "2026-02-22"));
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(cli(&args(&["--bogus"])).is_err());
        assert!(cli(&args(&["--help"])).is_ok());
    }

    #[test]
    fn signature_paths_skip_windows_hosts() {
        let notes = Program {
            executable: r"C:\Program Files\Contoso Notes\notes.exe".into(),
            ..program("Contoso Notes")
        };
        assert_eq!(
            checked_paths(&notes),
            [notes.executable.clone(), notes.uninstaller.clone()]
        );
        let msi = Program {
            uninstaller: r"C:\Windows\System32\msiexec.exe".into(),
            uninstaller_host: true,
            ..program("Agent")
        };
        assert!(checked_paths(&msi).is_empty());
        let status = |sig: &str, exists| {
            signature_view(Some(&vigil_actions::SignatureInfo {
                exists: Some(exists),
                sig_status: Some(sig.into()),
                ..Default::default()
            }))
            .status
        };
        assert_eq!(status("Valid", true), "valid");
        assert_eq!(status("NotSigned", true), "unsigned");
        assert_eq!(status("Valid", false), "missing");
        assert_eq!(signature_view(None).status, "unknown");
    }
}
