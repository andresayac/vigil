//! Persistence in PowerShell profiles and Microsoft Office. Everything here is READ-ONLY: registry
//! reads, folder listings and the first 64 KB of a few text files; nothing is changed.
//!
//! Code that loads into a program (the "Office test" DLL, COM add-ins, `.wll` / `.xll` files in the
//! Office startup folders) becomes a startup entry in `autoruns`, so the file is judged by its
//! signature and folder like every other autorun. What is not a program (PowerShell profiles, VSTO
//! manifests, macro workbooks and templates, Outlook's VBA project and folder home pages) goes to
//! `sysconfig.persistence` and is judged in `posture.rs`.

use std::fs;
use std::io::Read;
use std::path::Path;

use serde_json::{Value, json};

use crate::cmdline::{normalize_path, parse_command};
use crate::lenient::{lower, strip};
use crate::ntpath::{WINDIR, basename, isabs, join};
use crate::rules::is_user_writable;
use crate::winreg::{self, Hive, RegData, View};

/// The most of a profile script that is read and kept.
pub(crate) const PROFILE_LIMIT: usize = 64 * 1024;
/// The most files listed per Office startup folder.
const FOLDER_LIMIT: usize = 50;

/// Office programs that load add-ins listed under `Software\Microsoft\Office\<program>\Addins`.
const OFFICE_APPS: &[&str] = &[
    "Word",
    "Excel",
    "PowerPoint",
    "Outlook",
    "Access",
    "MS Project",
    "Visio",
    "OneNote",
    "Publisher",
];

/// Where Office add-ins and settings live: the user's key, and the machine's in both views (32-bit
/// Office on 64-bit Windows registers under WOW6432Node).
const PLACES: &[(Hive, View)] = &[
    (Hive::Hkcu, View::V64),
    (Hive::Hklm, View::V64),
    (Hive::Hklm, View::V32),
];

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

fn text_of(data: Option<&RegData>) -> String {
    data.map(RegData::as_text).unwrap_or_default()
}

fn is_file(path: &str) -> bool {
    Path::new(path).is_file()
}

// ------------------------------------------------------------------------------ PowerShell

/// The user's Documents folder as Windows resolves it (OneDrive or a redirected folder included).
#[cfg(windows)]
pub(crate) fn documents_folder() -> Option<String> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_Documents, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

    // SAFETY: the GUID is a static; the returned buffer is read once and freed with CoTaskMemFree,
    // as the API requires, on success.
    unsafe {
        let path = SHGetKnownFolderPath(&FOLDERID_Documents, KF_FLAG_DEFAULT, None).ok()?;
        let text = path.to_string().ok();
        CoTaskMemFree(Some(path.0 as *const core::ffi::c_void));
        text.filter(|t| !t.is_empty())
    }
}

#[cfg(not(windows))]
pub(crate) fn documents_folder() -> Option<String> {
    None
}

/// Every profile script PowerShell may run at start: Windows PowerShell 5.1 (both bitnesses) and
/// each PowerShell 7 installation for every user, then the user's own in Documents. The second
/// element is "all_users" or "current_user".
pub(crate) fn profile_paths(windir: &str, program_files: &str, documents: Option<&str>) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    let windows_names = [
        "profile.ps1",
        "Microsoft.PowerShell_profile.ps1",
        "Microsoft.PowerShellISE_profile.ps1",
    ];
    for system in ["System32", "SysWOW64"] {
        let home = join(windir, &[system, r"WindowsPowerShell\v1.0"]);
        for name in windows_names {
            out.push((join(&home, &[name]), "all_users"));
        }
    }
    if !program_files.is_empty() {
        let root = join(program_files, &["PowerShell"]);
        let mut homes: Vec<String> = fs::read_dir(&root)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.path().to_string_lossy().into_owned())
                    .filter(|home| is_file(&join(home, &["pwsh.exe"])))
                    .collect()
            })
            .unwrap_or_default();
        homes.sort();
        for home in homes {
            for name in ["profile.ps1", "Microsoft.PowerShell_profile.ps1"] {
                out.push((join(&home, &[name]), "all_users"));
            }
        }
    }
    if let Some(documents) = documents.filter(|d| !d.is_empty()) {
        for (folder, names) in [
            ("WindowsPowerShell", &windows_names[..]),
            ("PowerShell", &["profile.ps1", "Microsoft.PowerShell_profile.ps1"][..]),
        ] {
            for name in names.iter().chain(["Microsoft.VSCode_profile.ps1"].iter()) {
                out.push((join(documents, &[folder, name]), "current_user"));
            }
        }
    }
    out
}

/// The first `limit` bytes of a text file, decoded (UTF-16 or UTF-8, with or without a byte order
/// mark), whether it was cut, and its size.
pub(crate) fn read_head(path: &str, limit: usize) -> Option<(String, bool, u64)> {
    let file = fs::File::open(path).ok()?;
    let size = file.metadata().ok()?.len();
    let mut bytes = Vec::new();
    file.take(limit as u64).read_to_end(&mut bytes).ok()?;
    Some((decode(&bytes), size > limit as u64, size))
}

pub(crate) fn decode(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        return String::from_utf16_lossy(&units);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
        return String::from_utf16_lossy(&units);
    }
    let rest = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(rest).into_owned()
}

fn ps_profiles() -> Vec<Value> {
    let windir = WINDIR.clone();
    let documents = documents_folder().or_else(|| {
        let profile = env("USERPROFILE");
        (!profile.is_empty()).then(|| join(&profile, &["Documents"]))
    });
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for (path, scope) in profile_paths(&windir, &env("ProgramFiles"), documents.as_deref()) {
        if !seen.insert(lower(&path)) || !is_file(&path) {
            continue;
        }
        let Some((content, truncated, size)) = read_head(&path, PROFILE_LIMIT) else {
            continue;
        };
        out.push(json!({
            "path": path,
            "scope": scope,
            "size": size,
            "truncated": truncated,
            "content": content,
        }));
    }
    out
}

// ------------------------------------------------------------------------------ Office

/// A VSTO manifest value (`file:///C:/Program%20Files/x/y.vsto|vstolocal`) as a path, or the address
/// when the add-in is installed from the web.
pub(crate) fn manifest_location(manifest: &str) -> String {
    let value = strip(manifest).trim_matches('"');
    let value = value.split('|').next().unwrap_or("").trim();
    let low = lower(value);
    if low.starts_with("http://") || low.starts_with("https://") {
        return value.to_string();
    }
    let Some(rest) = value
        .get(..8)
        .filter(|p| p.eq_ignore_ascii_case("file:///"))
        .map(|_| &value[8..])
    else {
        return normalize_path(value);
    };
    normalize_path(&percent_decode(rest).replace('/', "\\"))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = text.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// An add-in loads when its program starts: LoadBehavior has both "load at startup" and "loaded"
/// bits (3, or 3 with other bits). 9 and 16 load on demand, 0 and 2 are switched off.
pub(crate) fn loads_at_startup(load_behavior: u64) -> bool {
    load_behavior & 3 == 3
}

/// The server a COM class runs: `InprocServer32` (for .NET classes run by mscoree.dll, the assembly
/// in `CodeBase`), else the program of `LocalServer32`. Per-user classes win, as in Windows.
fn class_server(progid: &str) -> String {
    let classes = |hive: Hive| match hive {
        Hive::Hkcu => r"Software\Classes".to_string(),
        Hive::Hklm => r"SOFTWARE\Classes".to_string(),
    };
    let clsid = PLACES.iter().find_map(|(hive, view)| {
        let id = text_of(winreg::value(*hive, &format!(r"{}\{progid}\CLSID", classes(*hive)), "", *view).as_ref());
        (!strip(&id).is_empty()).then(|| strip(&id).to_string())
    });
    let Some(clsid) = clsid else { return String::new() };
    for (hive, view) in PLACES {
        let base = format!(r"{}\CLSID\{clsid}", classes(*hive));
        let inproc = winreg::values(*hive, &format!(r"{base}\InprocServer32"), *view);
        let server = strip(&text_of(winreg::get(&inproc, ""))).to_string();
        if !server.is_empty() {
            let code_base = strip(&text_of(winreg::get(&inproc, "CodeBase"))).to_string();
            if lower(basename(&server)) == "mscoree.dll" && !code_base.is_empty() {
                return manifest_location(&code_base);
            }
            return server;
        }
        let local = text_of(winreg::value(*hive, &format!(r"{base}\LocalServer32"), "", *view).as_ref());
        if !strip(&local).is_empty() {
            return parse_command(strip(&local), None).program.unwrap_or_default();
        }
    }
    String::new()
}

/// A path a COM registration names: quotes removed, variables expanded; a bare name is looked up
/// in System32 (where Windows' loader looks first for these).
fn server_path(server: &str) -> String {
    let path = normalize_path(strip(server).trim_matches('"'));
    if path.is_empty() || isabs(&path) {
        path
    } else {
        join(&crate::ntpath::SYSTEM32, &[&path])
    }
}

fn entry(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Office add-ins that load when their program starts: COM add-ins as startup entries (their DLL
/// is judged as a file), VSTO add-ins (a manifest, not a program) as configuration.
fn office_addins() -> (Vec<Value>, Vec<Value>) {
    let mut dlls = Vec::new();
    let mut vsto = Vec::new();
    for (hive, view) in PLACES {
        let software = if *hive == Hive::Hkcu { "Software" } else { "SOFTWARE" };
        for app in OFFICE_APPS {
            let key = format!(r"{software}\Microsoft\Office\{app}\Addins");
            for progid in winreg::subkeys(*hive, &key, *view) {
                let sub = format!(r"{key}\{progid}");
                let values = winreg::values(*hive, &sub, *view);
                let load = match winreg::get(&values, "LoadBehavior") {
                    Some(RegData::Int(n)) => *n,
                    _ => continue,
                };
                if !loads_at_startup(load) {
                    continue;
                }
                let friendly = strip(&text_of(winreg::get(&values, "FriendlyName"))).to_string();
                let shown = if friendly.is_empty() || friendly.starts_with('@') {
                    progid.clone()
                } else {
                    friendly
                };
                let location = winreg::display(*hive, &sub, *view);
                let manifest = strip(&text_of(winreg::get(&values, "Manifest"))).to_string();
                if !manifest.is_empty() {
                    let target = manifest_location(&manifest);
                    let web = lower(&target).starts_with("http");
                    vsto.push(json!({
                        "app": app,
                        "name": shown,
                        "location": location,
                        "manifest": manifest,
                        "path": target,
                        "web": web,
                        "user_writable": !web && is_user_writable(&target),
                    }));
                    continue;
                }
                let server = class_server(&progid);
                let file = server_path(&server);
                if file.is_empty() {
                    continue;
                }
                dlls.push(entry(vec![
                    ("source", json!("office_addin")),
                    ("location", json!(location)),
                    ("name", json!(format!("{app}: {shown}"))),
                    ("command", json!(server)),
                    ("file", json!(file)),
                    ("enabled", json!(true)),
                ]));
            }
        }
    }
    (dlls, vsto)
}

/// "Office test": a DLL here is loaded by every Office program when it starts. Office itself never
/// uses this key; only its own test tools once did.
fn office_test() -> Vec<Value> {
    let mut out = Vec::new();
    for (hive, view) in PLACES {
        let software = if *hive == Hive::Hkcu { "Software" } else { "SOFTWARE" };
        let key = format!(r"{software}\Microsoft\Office test\Special\Perf");
        let value = text_of(winreg::value(*hive, &key, "", *view).as_ref());
        let file = server_path(&value);
        if file.is_empty() {
            continue;
        }
        out.push(entry(vec![
            ("source", json!("office_test")),
            ("location", json!(winreg::display(*hive, &key, *view))),
            ("name", json!("(Default)")),
            ("command", json!(strip(&value))),
            ("file", json!(file)),
            ("enabled", json!(true)),
        ]));
    }
    out
}

/// Office versions with settings for the user (`16.0`, `15.0`...).
fn office_versions() -> Vec<String> {
    winreg::subkeys(Hive::Hkcu, r"Software\Microsoft\Office", View::V64)
        .into_iter()
        .filter(|v| {
            v.split_once('.')
                .is_some_and(|(a, b)| !a.is_empty() && a.bytes().all(|c| c.is_ascii_digit()) && b == "0")
        })
        .collect()
}

/// Folders where Office installed itself (`...\root\Office16` and the like).
fn office_roots() -> Vec<String> {
    let mut roots = Vec::new();
    for view in [View::V64, View::V32] {
        let c2r = text_of(
            winreg::value(
                Hive::Hklm,
                r"SOFTWARE\Microsoft\Office\ClickToRun\Configuration",
                "InstallationPath",
                view,
            )
            .as_ref(),
        );
        if !strip(&c2r).is_empty() {
            roots.push(join(strip(&c2r), &[r"root\Office16"]));
        }
        for version in ["16.0", "15.0", "14.0"] {
            let path = text_of(
                winreg::value(
                    Hive::Hklm,
                    &format!(r"SOFTWARE\Microsoft\Office\{version}\Common\InstallRoot"),
                    "Path",
                    view,
                )
                .as_ref(),
            );
            if !strip(&path).is_empty() {
                roots.push(strip(&path).trim_end_matches('\\').to_string());
            }
        }
    }
    roots
}

/// The folders Word and Excel open every file of at start: the user's STARTUP / XLSTART, the
/// ones next to the Office installation and the alternative folders set in the options.
fn startup_folders() -> Vec<(&'static str, String)> {
    let mut folders = Vec::new();
    let appdata = env("APPDATA");
    if !appdata.is_empty() {
        folders.push(("Word", join(&appdata, &[r"Microsoft\Word\STARTUP"])));
        folders.push(("Excel", join(&appdata, &[r"Microsoft\Excel\XLSTART"])));
    }
    for root in office_roots() {
        folders.push(("Word", join(&root, &["STARTUP"])));
        folders.push(("Excel", join(&root, &["XLSTART"])));
    }
    for version in office_versions() {
        let options = |app: &str| format!(r"Software\Microsoft\Office\{version}\{app}\Options");
        let word = text_of(winreg::value(Hive::Hkcu, &options("Word"), "STARTUP-PATH", View::V64).as_ref());
        if !strip(&word).is_empty() {
            folders.push(("Word", normalize_path(strip(&word))));
        }
        let excel = text_of(winreg::value(Hive::Hkcu, &options("Excel"), "AltStartup", View::V64).as_ref());
        if !strip(&excel).is_empty() {
            folders.push(("Excel", normalize_path(strip(&excel))));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    folders.retain(|(_, f)| !f.is_empty() && seen.insert(lower(f.trim_end_matches('\\'))));
    folders
}

/// What a file in an Office startup folder is: "dll" for Word and Excel add-in DLLs (`.wll`,
/// `.xll`), "macros" for documents that can carry macros and that Office opens at start, `None` for
/// the rest (plain templates, and PERSONAL.XLSB, the user's own macro workbook that Excel creates).
pub(crate) fn startup_kind(app: &str, file_name: &str) -> Option<&'static str> {
    let low = lower(file_name);
    if matches!(low.as_str(), "personal.xlsb" | "personal.xls") {
        return None;
    }
    let ext = low.rsplit_once('.').map_or("", |(_, e)| e);
    match (app, ext) {
        (_, "wll" | "xll") => Some("dll"),
        ("Word", "dotm" | "dot" | "docm") => Some("macros"),
        ("Excel", "xlam" | "xla" | "xlsm" | "xlsb" | "xls" | "xltm" | "xlt") => Some("macros"),
        _ => None,
    }
}

fn office_startup() -> (Vec<Value>, Vec<Value>) {
    let mut dlls = Vec::new();
    let mut macros = Vec::new();
    for (app, folder) in startup_folders() {
        let Ok(entries) = fs::read_dir(&folder) else { continue };
        for found in entries.flatten().take(FOLDER_LIMIT) {
            let Ok(kind) = found.file_type() else { continue };
            if !kind.is_file() {
                continue;
            }
            let name = found.file_name().to_string_lossy().into_owned();
            let path = join(&folder, &[&name]);
            match startup_kind(app, &name) {
                Some("dll") => dlls.push(entry(vec![
                    ("source", json!("office_startup")),
                    ("location", json!(folder)),
                    ("name", json!(format!("{app}: {name}"))),
                    ("command", json!(path)),
                    ("file", json!(path)),
                    ("enabled", json!(true)),
                ])),
                Some(_) => {
                    let size = found.metadata().map_or(0, |m| m.len());
                    macros.push(json!({"app": app, "folder": folder, "file": path, "size": size}));
                }
                None => {}
            }
        }
    }
    (dlls, macros)
}

/// Outlook: the VBA project it loads at start, and web pages set as the home page of Outlook Today
/// or of a folder (Outlook shows them inside the program, where they can run code).
fn outlook() -> Value {
    let appdata = env("APPDATA");
    let project = if appdata.is_empty() {
        String::new()
    } else {
        join(&appdata, &[r"Microsoft\Outlook\VbaProject.OTM"])
    };
    let vba = if !project.is_empty() && is_file(&project) {
        let size = fs::metadata(&project).map_or(0, |m| m.len());
        json!({"path": project, "size": size})
    } else {
        Value::Null
    };
    let mut pages = Vec::new();
    for version in office_versions() {
        let base = format!(r"Software\Microsoft\Office\{version}\Outlook");
        let mut keys = vec![format!(r"{base}\Today")];
        keys.extend(
            winreg::subkeys(Hive::Hkcu, &format!(r"{base}\WebView"), View::V64)
                .into_iter()
                .map(|folder| format!(r"{base}\WebView\{folder}")),
        );
        for key in keys {
            let url = text_of(winreg::value(Hive::Hkcu, &key, "URL", View::V64).as_ref());
            if !strip(&url).is_empty() {
                pages.push(json!({"key": format!(r"HKCU\{key}"), "url": strip(&url)}));
            }
        }
    }
    json!({"vba_project": vba, "home_pages": pages})
}

/// Startup entries: the Office test DLL, COM add-ins and add-in DLLs in the startup folders.
pub(crate) fn collect_autoruns() -> Vec<Value> {
    let mut out = office_test();
    out.extend(office_addins().0);
    out.extend(office_startup().0);
    out
}

/// What is judged as configuration (`sysconfig.persistence`).
pub(crate) fn collect_config() -> Value {
    json!({
        "ps_profiles": ps_profiles(),
        "office": {
            "vsto_addins": office_addins().1,
            "startup_macros": office_startup().1,
            "outlook": outlook(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_paths_cover_every_host_and_scope() {
        let root = std::env::temp_dir().join(format!("vigil-ps7-{}", std::process::id()));
        let seven = root.join("PowerShell").join("7");
        fs::create_dir_all(&seven).expect("folder");
        fs::write(seven.join("pwsh.exe"), b"MZ").expect("exe");
        // A folder without pwsh.exe is not a PowerShell installation.
        fs::create_dir_all(root.join("PowerShell").join("Modules")).expect("folder");
        let paths = profile_paths(
            r"C:\Windows",
            &root.to_string_lossy(),
            Some(r"C:\Users\jdoe\OneDrive\Documents"),
        );
        let _ = fs::remove_dir_all(&root);
        let has = |needle: &str, scope: &str| {
            paths
                .iter()
                .any(|(p, s)| lower(p).ends_with(&lower(needle)) && *s == scope)
        };
        assert!(has(r"System32\WindowsPowerShell\v1.0\profile.ps1", "all_users"));
        assert!(has(
            r"SysWOW64\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
            "all_users"
        ));
        assert!(has(r"PowerShell\7\Microsoft.PowerShell_profile.ps1", "all_users"));
        assert!(!paths.iter().any(|(p, _)| p.contains("Modules")));
        assert!(has(
            r"OneDrive\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
            "current_user"
        ));
        assert!(has(r"OneDrive\Documents\PowerShell\profile.ps1", "current_user"));
        assert!(has(
            r"OneDrive\Documents\PowerShell\Microsoft.VSCode_profile.ps1",
            "current_user"
        ));
        assert!(
            !profile_paths(r"C:\Windows", "", None)
                .iter()
                .any(|(_, s)| *s == "current_user")
        );
    }

    #[test]
    fn profile_text_is_decoded_and_cut() {
        assert_eq!(decode(b"\xEF\xBB\xBFWrite-Host hi"), "Write-Host hi");
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("iex $x".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(decode(&utf16), "iex $x");
        let dir = std::env::temp_dir().join(format!("vigil-profile-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("folder");
        let file = dir.join("profile.ps1");
        fs::write(&file, "a".repeat(100)).expect("write");
        let (text, cut, size) = read_head(&file.to_string_lossy(), 64).expect("read");
        let _ = fs::remove_dir_all(&dir);
        assert_eq!((text.len(), cut, size), (64, true, 100));
    }

    #[test]
    fn vsto_manifests_become_paths() {
        assert_eq!(
            manifest_location("file:///C:/Program%20Files/Contoso/Addin.vsto|vstolocal"),
            r"C:\Program Files\Contoso\Addin.vsto"
        );
        assert_eq!(
            manifest_location("https://updates.contoso.example/addin.vsto|vstolocal"),
            "https://updates.contoso.example/addin.vsto"
        );
        assert_eq!(
            manifest_location(r"C:\Users\jdoe\AppData\Local\Fabrikam\fab.vsto"),
            r"C:\Users\jdoe\AppData\Local\Fabrikam\fab.vsto"
        );
    }

    #[test]
    fn load_behavior_and_startup_files() {
        assert!(loads_at_startup(3) && loads_at_startup(0x13));
        assert!(!loads_at_startup(9) && !loads_at_startup(16) && !loads_at_startup(2) && !loads_at_startup(0));
        assert_eq!(startup_kind("Word", "Contoso.wll"), Some("dll"));
        assert_eq!(startup_kind("Excel", "fab.XLL"), Some("dll"));
        assert_eq!(startup_kind("Word", "Template.dotm"), Some("macros"));
        assert_eq!(startup_kind("Excel", "tools.xlam"), Some("macros"));
        assert_eq!(
            startup_kind("Excel", "PERSONAL.XLSB"),
            None,
            "the user's own macro workbook"
        );
        assert_eq!(startup_kind("Word", "Letter.dotx"), None, "no macros");
        assert_eq!(startup_kind("Excel", "desktop.ini"), None);
    }

    /// Reads this computer (read-only) and prints counts only:
    /// `cargo test -p vigil-scan persist::tests::live_counts -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_counts() {
        let started = std::time::Instant::now();
        let entries = collect_autoruns();
        let cfg = collect_config();
        let count = |source: &str| {
            entries
                .iter()
                .filter(|e| e.get("source").and_then(Value::as_str) == Some(source))
                .count()
        };
        let len = |v: &Value| v.as_array().map_or(0, Vec::len);
        println!(
            "in {:?}: office test {}, COM add-ins {}, add-in DLLs in startup folders {}",
            started.elapsed(),
            count("office_test"),
            count("office_addin"),
            count("office_startup")
        );
        println!(
            "profiles {}, VSTO add-ins {}, macro files {}, Outlook VBA project: {}, home pages {}",
            len(&cfg["ps_profiles"]),
            len(&cfg["office"]["vsto_addins"]),
            len(&cfg["office"]["startup_macros"]),
            !cfg["office"]["outlook"]["vba_project"].is_null(),
            len(&cfg["office"]["outlook"]["home_pages"]),
        );
    }
}
