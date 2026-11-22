//! Per-user COM registrations that take the place of the computer's own (COM hijacking).
//! READ-ONLY: registry reads, nothing is changed.
//!
//! Windows looks a COM class up in `HKCU\Software\Classes` before `HKLM\SOFTWARE\Classes`, so a
//! per-user `CLSID\{...}\InprocServer32` makes every program of that user that creates the object
//! load the user's DLL instead of Windows'. No administrator rights are needed to set it, which is
//! why malware uses it to live inside Explorer, Task Scheduler or any program that plays sound.
//!
//! Only registrations that **shadow** one registered for the whole computer are listed: a
//! per-user class Windows does not know is just a program installed for one user. Each entry has
//! the shape of the other startup entries (`source` = `com_hijack`, `location`, `name`,
//! `command`, `file`), plus `kind` (inproc, local, treat_as, progid, scriptlet), `machine` (what
//! the computer registers) and `target` (a well-known class abused this way). The analysis judges
//! the file like any other startup file: a signed vendor server in its own folder (per-user
//! installs of cloud storage or chat apps register per-user COM) gives no signal.

use serde_json::{Value, json};

use crate::cmdline::{expand_env, normalize_path, parse_command};
use crate::lenient::{lower, strip};
use crate::winreg::{self, Hive, RegData, View};

/// Per-user classes read at most (one listing per root). A normal profile has a few dozen to a
/// few hundred; more than this is noted and the rest is not read.
pub(crate) const MAX_KEYS: usize = 3000;

/// Classes that public reports describe as hijacked this way, with what loads them. A shadow of
/// one of these weighs more: the DLL runs inside Explorer or a Windows task at every sign-in.
pub(crate) const KNOWN_TARGETS: &[(&str, &str)] = &[
    ("{42aedc87-2188-41fd-b9a3-0c966feabec1}", "MruPidlList (Explorer)"),
    ("{ab8902b4-09ca-4bb6-b78d-a8f59079a8d5}", "Thumbnail cache (Explorer)"),
    ("{9ba05972-f6a8-11cf-a442-00a0c90a8f39}", "ShellWindows (Explorer)"),
    (
        "{c08afd90-f2a1-11d1-8455-00a0c91f3880}",
        "ShellBrowserWindow (Explorer)",
    ),
    (
        "{bcde0395-e52f-467c-8e3d-c4579291692e}",
        "MMDeviceEnumerator (every program that plays sound)",
    ),
    (
        "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}",
        "CAccPropServicesClass (accessibility, many programs)",
    ),
    (
        "{0358b920-0ac7-461f-98f4-58e32cd89148}",
        "Wininet cache task (Task Scheduler)",
    ),
];

/// The well-known target a class id names, if any.
pub(crate) fn known_target(clsid: &str) -> Option<&'static str> {
    let clsid = lower(clsid);
    KNOWN_TARGETS
        .iter()
        .find(|(id, _)| *id == clsid)
        .map(|(_, label)| *label)
}

/// What one hive registers for a class.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Registration {
    /// The class key exists in this hive.
    pub(crate) exists: bool,
    pub(crate) name: String,
    pub(crate) inproc: String,
    pub(crate) local: String,
    pub(crate) treat_as: String,
    pub(crate) scriptlet: String,
}

impl Registration {
    fn has_server(&self) -> bool {
        !(self.inproc.is_empty() && self.local.is_empty() && self.treat_as.is_empty() && self.scriptlet.is_empty())
    }
}

/// A path as it should be compared: expanded, without quotes, lower case.
fn comparable(path: &str) -> String {
    lower(&normalize_path(&expand_env(strip(path).trim_matches('"'))))
}

/// The program a LocalServer32 command line starts.
fn local_program(command: &str) -> String {
    parse_command(strip(command), None).program.unwrap_or_default()
}

/// The file an InprocServer32 value names.
fn inproc_file(value: &str) -> String {
    let value = strip(value).trim_matches('"');
    if value.is_empty() {
        String::new()
    } else {
        normalize_path(&expand_env(value))
    }
}

/// The server file of a registration (in-process DLL first, then the local server program).
fn server_file(reg: &Registration) -> String {
    if !reg.inproc.is_empty() {
        inproc_file(&reg.inproc)
    } else if !reg.local.is_empty() {
        local_program(&reg.local)
    } else {
        String::new()
    }
}

/// The startup entry for a per-user class that shadows the computer's, or `None` when it does not
/// (nothing registered for the computer, or the same server). `resolve` finds the registration a
/// `TreatAs` points to (the user's first, then the computer's).
pub(crate) fn judge(
    clsid: &str,
    location: &str,
    user: &Registration,
    machine: &Registration,
    resolve: &dyn Fn(&str) -> Registration,
) -> Option<Value> {
    if !machine.exists || !user.has_server() {
        return None;
    }
    let target = known_target(clsid).unwrap_or("");
    let name = if user.name.is_empty() {
        machine.name.clone()
    } else {
        user.name.clone()
    };
    let base = |kind: &str, command: &str, file: String, machine_server: &str| {
        json!({
            "source": "com_hijack",
            "location": location,
            "name": clsid,
            "class_name": name,
            "command": strip(command),
            "file": file,
            "kind": kind,
            "machine": strip(machine_server),
            "target": target,
            "enabled": true,
        })
    };
    // A scriptlet runs script code (often from the internet) whenever the object is created.
    if !user.scriptlet.is_empty() && comparable(&user.scriptlet) != comparable(&machine.scriptlet) {
        return Some(base("scriptlet", &user.scriptlet, String::new(), &machine.scriptlet));
    }
    if !user.inproc.is_empty() {
        let machine_file = server_file(machine);
        let file = inproc_file(&user.inproc);
        if comparable(&file) == comparable(&machine_file) {
            return None;
        }
        let machine_server = if machine.inproc.is_empty() {
            &machine.local
        } else {
            &machine.inproc
        };
        return Some(base("inproc", &user.inproc, file, machine_server));
    }
    if !user.local.is_empty() {
        let file = local_program(&user.local);
        if comparable(&file) == comparable(&server_file(machine)) {
            return None;
        }
        let machine_server = if machine.local.is_empty() {
            &machine.inproc
        } else {
            &machine.local
        };
        return Some(base("local", &user.local, file, machine_server));
    }
    if !user.treat_as.is_empty() && lower(strip(&user.treat_as)) != lower(strip(&machine.treat_as)) {
        let redirected = resolve(strip(&user.treat_as));
        let file = server_file(&redirected);
        let shown = format!("TreatAs {}", strip(&user.treat_as));
        return Some(base("treat_as", &shown, file, &machine.treat_as));
    }
    None
}

/// The entry for a per-user ProgID that sends a name the computer knows to another class.
pub(crate) fn judge_progid(
    progid: &str,
    location: &str,
    user_clsid: &str,
    machine_clsid: &str,
    redirected: &Registration,
) -> Option<Value> {
    let (user_clsid, machine_clsid) = (strip(user_clsid), strip(machine_clsid));
    if user_clsid.is_empty() || machine_clsid.is_empty() || lower(user_clsid) == lower(machine_clsid) {
        return None;
    }
    let file = server_file(redirected);
    if file.is_empty() {
        return None;
    }
    Some(json!({
        "source": "com_hijack",
        "location": location,
        "name": progid,
        "class_name": progid,
        "command": format!("CLSID {user_clsid}"),
        "file": file,
        "kind": "progid",
        "machine": format!("CLSID {machine_clsid}"),
        "target": known_target(user_clsid).or_else(|| known_target(machine_clsid)).unwrap_or(""),
        "enabled": true,
    }))
}

// --------------------------------------------------------------------------- live reads

fn default_of(hive: Hive, key: &str) -> String {
    winreg::value(hive, key, "", View::V64)
        .map(|d| strip(&d.as_text()).to_string())
        .unwrap_or_default()
}

fn read(hive: Hive, root: &str, clsid: &str) -> Registration {
    let key = format!(r"{root}\{clsid}");
    let values = winreg::values(hive, &key, View::V64);
    let subkeys = winreg::subkeys(hive, &key, View::V64);
    if values.is_empty() && subkeys.is_empty() {
        return Registration::default();
    }
    let has = |name: &str| subkeys.iter().any(|s| s.eq_ignore_ascii_case(name));
    let sub = |name: &str| {
        if has(name) {
            default_of(hive, &format!(r"{key}\{name}"))
        } else {
            String::new()
        }
    };
    Registration {
        exists: true,
        name: winreg::get(&values, "").map(RegData::as_text).unwrap_or_default(),
        inproc: sub("InprocServer32"),
        local: sub("LocalServer32"),
        treat_as: sub("TreatAs"),
        scriptlet: sub("ScriptletURL"),
    }
}

const USER_ROOTS: [(&str, &str); 2] = [
    (r"Software\Classes\CLSID", r"SOFTWARE\Classes\CLSID"),
    (
        r"Software\Classes\Wow6432Node\CLSID",
        r"SOFTWARE\Classes\WOW6432Node\CLSID",
    ),
];

/// The per-user COM registrations that shadow the computer's, and how many classes were read
/// (`capped` when the limit was reached).
pub(crate) fn collect() -> (Vec<Value>, Value) {
    let mut out = Vec::new();
    let mut read_count = 0usize;
    let mut capped = false;
    for (user_root, machine_root) in USER_ROOTS {
        let resolve = |target: &str| {
            let user = read(Hive::Hkcu, user_root, target);
            if user.has_server() {
                user
            } else {
                read(Hive::Hklm, machine_root, target)
            }
        };
        let keys = winreg::subkeys(Hive::Hkcu, user_root, View::V64);
        for clsid in keys.iter().filter(|k| k.starts_with('{')) {
            if read_count >= MAX_KEYS {
                capped = true;
                break;
            }
            read_count += 1;
            let user = read(Hive::Hkcu, user_root, clsid);
            if !user.has_server() {
                continue;
            }
            let machine = read(Hive::Hklm, machine_root, clsid);
            let location = format!(r"HKCU\{user_root}\{clsid}");
            if let Some(entry) = judge(clsid, &location, &user, &machine, &resolve) {
                out.push(entry);
            }
        }
    }
    // Per-user ProgIDs ("Shell.Application") that point a name the computer knows elsewhere.
    let mut progids = 0usize;
    for name in winreg::subkeys(Hive::Hkcu, r"Software\Classes", View::V64) {
        if name.starts_with('.') || name.starts_with('{') || name.contains('\\') {
            continue;
        }
        if matches!(
            lower(&name).as_str(),
            "clsid" | "wow6432node" | "appid" | "interface" | "typelib"
        ) {
            continue;
        }
        if progids >= MAX_KEYS {
            capped = true;
            break;
        }
        progids += 1;
        let user_clsid = default_of(Hive::Hkcu, &format!(r"Software\Classes\{name}\CLSID"));
        if user_clsid.is_empty() {
            continue;
        }
        let machine_clsid = default_of(Hive::Hklm, &format!(r"SOFTWARE\Classes\{name}\CLSID"));
        let redirected = {
            let user = read(Hive::Hkcu, USER_ROOTS[0].0, &user_clsid);
            if user.has_server() {
                user
            } else {
                read(Hive::Hklm, USER_ROOTS[0].1, &user_clsid)
            }
        };
        let location = format!(r"HKCU\Software\Classes\{name}");
        if let Some(entry) = judge_progid(&name, &location, &user_clsid, &machine_clsid, &redirected) {
            out.push(entry);
        }
    }
    let summary =
        json!({ "classes_read": read_count, "progids_read": progids, "capped": capped, "shadowing": out.len() });
    (out, summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(inproc: &str, local: &str) -> Registration {
        Registration {
            exists: true,
            inproc: inproc.into(),
            local: local.into(),
            ..Registration::default()
        }
    }

    fn none(_: &str) -> Registration {
        Registration::default()
    }

    const CLSID: &str = "{11111111-2222-3333-4444-555555555555}";
    const LOC: &str = r"HKCU\Software\Classes\CLSID\{11111111-2222-3333-4444-555555555555}";

    #[test]
    fn only_shadows_of_the_computers_classes_are_listed() {
        let user = reg(r"C:\Users\jdoe\AppData\Roaming\x.dll", "");
        // Nothing registered for the computer: a per-user install, not a hijack.
        assert!(judge(CLSID, LOC, &user, &Registration::default(), &none).is_none());
        // The same server in both hives (a program that registers itself twice).
        let same = reg(r"%APPDATA%\x.dll", "");
        let entry = judge(
            CLSID,
            LOC,
            &same,
            &reg(r"C:\Users\jdoe\AppData\Roaming\x.dll", ""),
            &none,
        );
        if std::env::var("APPDATA").is_ok_and(|a| lower(&a) == lower(r"C:\Users\jdoe\AppData\Roaming")) {
            assert!(entry.is_none());
        }
        let machine = reg(r"%SystemRoot%\System32\shell32.dll", "");
        let entry = judge(CLSID, LOC, &user, &machine, &none).expect("shadow");
        assert_eq!(entry["source"], "com_hijack");
        assert_eq!(entry["kind"], "inproc");
        assert_eq!(entry["file"], r"C:\Users\jdoe\AppData\Roaming\x.dll");
        assert_eq!(entry["machine"], r"%SystemRoot%\System32\shell32.dll");
        assert_eq!(entry["target"], "");
        // A user registration with no server at all is ignored.
        assert!(
            judge(
                CLSID,
                LOC,
                &Registration {
                    exists: true,
                    ..Registration::default()
                },
                &machine,
                &none
            )
            .is_none()
        );
    }

    #[test]
    fn known_targets_local_servers_scriptlets_and_treat_as() {
        let explorer = "{42AEDC87-2188-41FD-B9A3-0C966FEABEC1}";
        let machine = reg(r"C:\Windows\System32\shell32.dll", "");
        let user = reg(r#""C:\Users\Public\m.dll""#, "");
        let entry = judge(explorer, LOC, &user, &machine, &none).expect("shadow");
        assert_eq!(entry["target"], "MruPidlList (Explorer)");
        assert_eq!(entry["file"], r"C:\Users\Public\m.dll");

        let local = reg("", r#""C:\Users\jdoe\AppData\Local\Temp\srv.exe" -Embedding"#);
        let entry = judge(
            CLSID,
            LOC,
            &local,
            &reg("", r"C:\Windows\System32\wbem\unsecapp.exe"),
            &none,
        )
        .expect("local");
        assert_eq!(entry["kind"], "local");
        assert_eq!(entry["file"], r"C:\Users\jdoe\AppData\Local\Temp\srv.exe");

        let scriptlet = Registration {
            exists: true,
            scriptlet: "https://203.0.113.5/x.sct".into(),
            ..Registration::default()
        };
        let entry = judge(CLSID, LOC, &scriptlet, &machine, &none).expect("scriptlet");
        assert_eq!(entry["kind"], "scriptlet");
        assert_eq!(entry["file"], "");

        let treat = Registration {
            exists: true,
            treat_as: "{99999999-0000-0000-0000-000000000000}".into(),
            ..Registration::default()
        };
        let resolve = |target: &str| {
            assert_eq!(target, "{99999999-0000-0000-0000-000000000000}");
            reg(r"C:\ProgramData\t.dll", "")
        };
        let entry = judge(CLSID, LOC, &treat, &machine, &resolve).expect("treat as");
        assert_eq!(entry["kind"], "treat_as");
        assert_eq!(entry["file"], r"C:\ProgramData\t.dll");
    }

    #[test]
    fn progids_that_point_elsewhere() {
        let redirected = reg(r"C:\Users\jdoe\AppData\Roaming\p.dll", "");
        let loc = r"HKCU\Software\Classes\Shell.Application";
        assert!(judge_progid("Shell.Application", loc, "{AAA}", "{aaa}", &redirected).is_none());
        assert!(judge_progid("Shell.Application", loc, "{AAA}", "", &redirected).is_none());
        let entry = judge_progid("Shell.Application", loc, "{BBB}", "{AAA}", &redirected).expect("progid");
        assert_eq!(entry["kind"], "progid");
        assert_eq!(entry["file"], r"C:\Users\jdoe\AppData\Roaming\p.dll");
        // A redirection to a class with no server loads nothing.
        assert!(judge_progid("Shell.Application", loc, "{BBB}", "{AAA}", &Registration::default()).is_none());
    }

    /// Counts only: `cargo test -p vigil-scan com::tests::live_counts -- --ignored --nocapture`
    #[test]
    #[ignore = "reads this computer's registry"]
    fn live_counts() {
        let started = std::time::Instant::now();
        let (entries, summary) = collect();
        let kinds = |kind: &str| entries.iter().filter(|e| e["kind"] == kind).count();
        println!(
            "com: {} classes, {} progids read, capped {}, {} shadowing (inproc {}, local {}, treat_as {}, progid {}, scriptlet {}), {} known targets, {:?}",
            summary["classes_read"],
            summary["progids_read"],
            summary["capped"],
            entries.len(),
            kinds("inproc"),
            kinds("local"),
            kinds("treat_as"),
            kinds("progid"),
            kinds("scriptlet"),
            entries.iter().filter(|e| e["target"] != "").count(),
            started.elapsed()
        );
    }
}
