//! Less common places that make Windows run or load something, and settings that blind the
//! defences. Everything here is READ-ONLY: registry reads, nothing is changed.
//!
//! The entries use the same shape as the other startup entries (`source`, `location`, `name`,
//! `command`, `enabled`), plus `file` when the value names a DLL that this module resolves itself
//! (a bare `winprint.dll` lives in the spooler folder, not in PATH). The analysis in
//! `analyze.rs` judges them; the configuration values go to `sysconfig.hooks` and
//! `sysconfig.evasion`, judged in `posture.rs`.

use serde_json::{Map, Value, json};

use crate::cmdline::normalize_path;
use crate::lenient::{lower, strip};
use crate::ntpath::{SYSTEM32, isabs, join};
use crate::rules::{in_windows_dir, is_user_writable};
use crate::winreg::{self, Hive, RegData, View};

fn entry(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn text_of(data: Option<&RegData>) -> String {
    data.map(RegData::as_text).unwrap_or_default()
}

/// A DLL as a hook names it: a bare name is looked up in `folder` (System32 unless the hook has its
/// own folder), anything else is expanded and normalized.
pub(crate) fn resolve_dll(value: &str, folder: &str) -> String {
    let value = strip(value).trim_matches('"').to_string();
    if value.is_empty() {
        return value;
    }
    let path = normalize_path(&value);
    if isabs(&path) || path.starts_with("\\\\") {
        path
    } else {
        join(folder, &[&path])
    }
}

/// Programs Windows starts from the sign-in screen, with SYSTEM rights, before anyone signs in.
/// Replacing one with a copy of cmd.exe gives a command prompt without a password. The second
/// element lists the original file names Windows' own copies declare (version resource,
/// "OriginalFilename", without ".mui").
pub(crate) const ACCESSIBILITY: &[(&str, &[&str])] = &[
    ("sethc.exe", &["sethc.exe"]),
    ("utilman.exe", &["utilman.exe", "utilman2.exe"]),
    ("osk.exe", &["osk.exe"]),
    ("magnify.exe", &["magnify.exe", "screenmagnifier.exe"]),
    ("narrator.exe", &["narrator.exe", "sr.exe"]),
    ("displayswitch.exe", &["displayswitch.exe", "displayswitch"]),
    ("atbroker.exe", &["atbroker.exe"]),
];

/// Full paths of the accessibility programs (their signature and version data is needed).
pub(crate) fn accessibility_paths() -> Vec<String> {
    ACCESSIBILITY.iter().map(|(name, _)| join(&SYSTEM32, &[name])).collect()
}

/// Startup sources whose target is a DLL loaded into a Windows process (Print Spooler, LSA,
/// Windows Time, every program using the network...). An unsigned DLL there weighs more.
pub(crate) const HOOK_SOURCES: &[&str] = &[
    "print_monitor",
    "print_processor",
    "time_provider",
    "netsh_helper",
    "network_provider",
    "winsock_provider",
    "known_dll",
    "ifeo_verifier",
    "clr_profiler",
    "amsi_provider",
];

/// Per-user handlers that Windows' auto-elevating programs open (fodhelper and computerdefaults
/// open ms-settings, eventvwr opens mscfile, sdclt opens Folder and exefile, wsreset opens the
/// AppX class). Nothing installs these under HKCU in normal use.
pub(crate) const UAC_BYPASS_CLASSES: &[&str] = &[
    "ms-settings",
    "mscfile",
    "exefile",
    "Folder",
    "Launcher.SystemSettings",
    "AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2",
];

const SESSION: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager";
const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";

/// The startup entries of the hooks: DLL registrations, one-value tricks and class hijacks.
pub(crate) fn collect_autoruns() -> Vec<Value> {
    let mut out = Vec::new();
    class_hijacks(&mut out);
    dll_hooks(&mut out);
    one_value_tricks(&mut out);
    out
}

fn class_hijacks(out: &mut Vec<Value>) {
    for class in UAC_BYPASS_CLASSES {
        for (verb, extra) in [("open", None), ("runas", Some("IsolatedCommand"))] {
            let key = format!(r"Software\Classes\{class}\shell\{verb}\command");
            let values = winreg::values(Hive::Hkcu, &key, View::V64);
            if values.is_empty() {
                continue;
            }
            let mut command = strip(&text_of(winreg::get(&values, ""))).to_string();
            if command.is_empty()
                && let Some(name) = extra
            {
                command = strip(&text_of(winreg::get(&values, name))).to_string();
            }
            let delegate = strip(&text_of(winreg::get(&values, "DelegateExecute"))).to_string();
            if command.is_empty() && delegate.is_empty() {
                continue;
            }
            out.push(entry(vec![
                ("source", json!("class_hijack")),
                ("location", json!(format!("HKCU\\{key}"))),
                ("name", json!(class)),
                ("command", json!(command)),
                ("delegate", json!(delegate)),
                ("enabled", json!(true)),
            ]));
        }
    }
}

fn hook(out: &mut Vec<Value>, source: &str, location: String, name: &str, value: &str, file: String, enabled: bool) {
    if file.is_empty() {
        return;
    }
    out.push(entry(vec![
        ("source", json!(source)),
        ("location", json!(location)),
        ("name", json!(name)),
        ("command", json!(strip(value))),
        ("file", json!(file)),
        ("enabled", json!(enabled)),
    ]));
}

fn dll_hooks(out: &mut Vec<Value>) {
    // Print monitors: loaded by the Print Spooler (SYSTEM). Driver names a DLL in System32.
    let monitors = r"SYSTEM\CurrentControlSet\Control\Print\Monitors";
    for sub in winreg::subkeys(Hive::Hklm, monitors, View::V64) {
        let key = format!("{monitors}\\{sub}");
        let driver = text_of(winreg::value(Hive::Hklm, &key, "Driver", View::V64).as_ref());
        hook(
            out,
            "print_monitor",
            format!("HKLM\\{key}"),
            &sub,
            &driver,
            resolve_dll(&driver, &SYSTEM32),
            true,
        );
    }
    // Print processors: their DLL lives in the spooler's own folder.
    let environments = r"SYSTEM\CurrentControlSet\Control\Print\Environments";
    for (environment, folder) in [("Windows x64", "x64"), ("Windows NT x86", "w32x86")] {
        let processors = format!(r"{environments}\{environment}\Print Processors");
        let home = join(&SYSTEM32, &[r"spool\prtprocs", folder]);
        for sub in winreg::subkeys(Hive::Hklm, &processors, View::V64) {
            let key = format!("{processors}\\{sub}");
            let driver = text_of(winreg::value(Hive::Hklm, &key, "Driver", View::V64).as_ref());
            hook(
                out,
                "print_processor",
                format!("HKLM\\{key}"),
                &sub,
                &driver,
                resolve_dll(&driver, &home),
                true,
            );
        }
    }
    // Windows Time providers: loaded by the W32Time service.
    let providers = format!(r"{SERVICES}\W32Time\TimeProviders");
    for sub in winreg::subkeys(Hive::Hklm, &providers, View::V64) {
        let key = format!("{providers}\\{sub}");
        let values = winreg::values(Hive::Hklm, &key, View::V64);
        let dll = text_of(winreg::get(&values, "DllName"));
        let enabled = winreg::get(&values, "Enabled").is_none_or(RegData::truthy);
        hook(
            out,
            "time_provider",
            format!("HKLM\\{key}"),
            &sub,
            &dll,
            resolve_dll(&dll, &SYSTEM32),
            enabled,
        );
    }
    // netsh helpers: loaded every time netsh.exe runs (often as an administrator).
    let netsh = r"SOFTWARE\Microsoft\NetSh";
    for view in [View::V64, View::V32] {
        for (name, data) in winreg::values(Hive::Hklm, netsh, view) {
            let dll = data.as_text();
            hook(
                out,
                "netsh_helper",
                winreg::display(Hive::Hklm, netsh, view),
                &name,
                &dll,
                resolve_dll(&dll, &SYSTEM32),
                true,
            );
        }
    }
    // Network providers: each one receives the user's password in clear text at sign-in
    // (NPLogonNotify), which is why stealing tools register one.
    let order = text_of(
        winreg::value(
            Hive::Hklm,
            r"SYSTEM\CurrentControlSet\Control\NetworkProvider\Order",
            "ProviderOrder",
            View::V64,
        )
        .as_ref(),
    );
    for name in order.split(',').map(strip).filter(|n| !n.is_empty()) {
        let key = format!(r"{SERVICES}\{name}\NetworkProvider");
        let path = text_of(winreg::value(Hive::Hklm, &key, "ProviderPath", View::V64).as_ref());
        hook(
            out,
            "network_provider",
            format!("HKLM\\{key}"),
            name,
            &path,
            resolve_dll(&path, &SYSTEM32),
            true,
        );
    }
    // LSA packages set through OSConfig (the same role as Lsa\Security Packages, less watched).
    let osconfig = r"SYSTEM\CurrentControlSet\Control\Lsa\OSConfig";
    let packages = match winreg::value(Hive::Hklm, osconfig, "Security Packages", View::V64) {
        Some(RegData::Multi(items)) => items,
        Some(other) if other.truthy() => vec![other.as_text()],
        _ => Vec::new(),
    };
    for package in packages {
        let package = strip(&package).trim_matches('"').to_string();
        if !package.is_empty() {
            out.push(entry(vec![
                ("source", json!("lsa_package")),
                ("location", json!(format!("HKLM\\{osconfig}"))),
                ("name", json!("Security Packages")),
                ("command", json!(package)),
                ("enabled", json!(true)),
            ]));
        }
    }
    // Winsock providers and KnownDLLs: dozens of Windows entries, all in System32. Only entries
    // that point outside the Windows folder are listed (a DLL placed there to be loaded into
    // every program that uses the network, or before the real system DLL).
    for catalog in ["Catalog_Entries64", "Catalog_Entries"] {
        let protocols = format!(r"{SERVICES}\WinSock2\Parameters\Protocol_Catalog9\{catalog}");
        for sub in winreg::subkeys(Hive::Hklm, &protocols, View::V64) {
            let key = format!("{protocols}\\{sub}");
            if let Some(RegData::Bytes(bytes)) = winreg::value(Hive::Hklm, &key, "PackedCatalogItem", View::V64) {
                let dll = packed_path(&bytes);
                let file = resolve_dll(&dll, &SYSTEM32);
                if !file.is_empty() && !in_windows_dir(&file) {
                    hook(out, "winsock_provider", format!("HKLM\\{key}"), &sub, &dll, file, true);
                }
            }
        }
        let names = format!(r"{SERVICES}\WinSock2\Parameters\NameSpace_Catalog5\{catalog}");
        for sub in winreg::subkeys(Hive::Hklm, &names, View::V64) {
            let key = format!("{names}\\{sub}");
            let values = winreg::values(Hive::Hklm, &key, View::V64);
            let dll = text_of(winreg::get(&values, "LibraryPath"));
            let file = resolve_dll(&dll, &SYSTEM32);
            if !file.is_empty() && !in_windows_dir(&file) {
                let enabled = winreg::get(&values, "Enabled").is_none_or(RegData::truthy);
                hook(
                    out,
                    "winsock_provider",
                    format!("HKLM\\{key}"),
                    &sub,
                    &dll,
                    file,
                    enabled,
                );
            }
        }
    }
    let known = format!(r"{SESSION}\KnownDLLs");
    for (name, data) in winreg::values(Hive::Hklm, &known, View::V64) {
        if name.eq_ignore_ascii_case("DllDirectory") || name.eq_ignore_ascii_case("DllDirectory32") {
            continue;
        }
        let dll = data.as_text();
        let file = resolve_dll(&dll, &SYSTEM32);
        if !file.is_empty() && !in_windows_dir(&file) {
            hook(out, "known_dll", format!("HKLM\\{known}"), &name, &dll, file, true);
        }
    }
}

/// The DLL path at the start of a Winsock `PackedCatalogItem`: an ANSI string, NUL-terminated,
/// at most MAX_PATH bytes.
pub(crate) fn packed_path(bytes: &[u8]) -> String {
    let head = &bytes[..bytes.len().min(260)];
    let end = head.iter().position(|b| *b == 0).unwrap_or(head.len());
    String::from_utf8_lossy(&head[..end]).trim().to_string()
}

/// `NAME=value` pairs of an environment block (REG_MULTI_SZ of a service) or of a key's values.
fn env_pairs(values: &[(String, RegData)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(name, data)| (name.clone(), data.as_text()))
        .collect()
}

fn block_pairs(lines: &[String]) -> Vec<(String, String)> {
    lines
        .iter()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// A .NET profiler set through environment variables: `(enabled, target)`. The target is the
/// profiler DLL (`*_PROFILER_PATH*`) or, without a path, its CLSID resolved through the registry.
pub(crate) fn clr_profiler(pairs: &[(String, String)]) -> Option<(bool, String)> {
    let find = |name: &str| {
        pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| strip(v).to_string())
            .filter(|v| !v.is_empty())
    };
    let enabled = ["COR_ENABLE_PROFILING", "CORECLR_ENABLE_PROFILING"]
        .iter()
        .any(|n| find(n).is_some_and(|v| v == "1"));
    let path = [
        "COR_PROFILER_PATH_64",
        "COR_PROFILER_PATH",
        "CORECLR_PROFILER_PATH_64",
        "CORECLR_PROFILER_PATH",
        "COR_PROFILER_PATH_32",
        "CORECLR_PROFILER_PATH_32",
    ]
    .iter()
    .find_map(|n| find(n));
    if let Some(path) = path {
        return Some((enabled, path));
    }
    let clsid = find("COR_PROFILER").or_else(|| find("CORECLR_PROFILER"))?;
    let server = [Hive::Hkcu, Hive::Hklm].into_iter().find_map(|hive| {
        let key = format!(r"Software\Classes\CLSID\{clsid}\InprocServer32");
        winreg::value(hive, &key, "", View::V64)
            .map(|d| d.as_text())
            .filter(|t| !strip(t).is_empty())
    });
    Some((enabled, server.unwrap_or(clsid)))
}

fn one_value_tricks(out: &mut Vec<Value>) {
    // Screensaver: Windows starts it on its own after the idle time.
    for (key, location) in [
        (r"Control Panel\Desktop", r"HKCU\Control Panel\Desktop"),
        (
            r"Software\Policies\Microsoft\Windows\Control Panel\Desktop",
            r"HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop",
        ),
    ] {
        let saver = strip(&text_of(
            winreg::value(Hive::Hkcu, key, "SCRNSAVE.EXE", View::V64).as_ref(),
        ))
        .to_string();
        if !saver.is_empty() {
            out.push(entry(vec![
                ("source", json!("screensaver")),
                ("location", json!(location)),
                ("name", json!("SCRNSAVE.EXE")),
                ("command", json!(saver)),
                ("file", json!(resolve_dll(&saver, &SYSTEM32))),
                ("enabled", json!(true)),
            ]));
        }
    }

    // .NET profilers in the user's and the machine's environment.
    let machine_env = format!(r"{SESSION}\Environment");
    for (hive, key, location) in [
        (Hive::Hkcu, "Environment".to_string(), r"HKCU\Environment".to_string()),
        (Hive::Hklm, machine_env.clone(), format!(r"HKLM\{machine_env}")),
    ] {
        let pairs = env_pairs(&winreg::values(hive, &key, View::V64));
        if let Some((enabled, target)) = clr_profiler(&pairs) {
            out.push(profiler_entry(&location, "environment", &target, enabled));
        }
    }

    // Per service: its own environment (a profiler for one service) and the program run when
    // it fails.
    for service in winreg::subkeys(Hive::Hklm, SERVICES, View::V64) {
        let key = format!("{SERVICES}\\{service}");
        let values = winreg::values(Hive::Hklm, &key, View::V64);
        if let Some(RegData::Multi(lines)) = winreg::get(&values, "Environment")
            && let Some((enabled, target)) = clr_profiler(&block_pairs(lines))
        {
            out.push(profiler_entry(&format!("HKLM\\{key}"), &service, &target, enabled));
        }
        let failure = strip(&text_of(winreg::get(&values, "FailureCommand"))).to_string();
        if !failure.is_empty() {
            out.push(entry(vec![
                ("source", json!("service_failure")),
                ("location", json!(format!("HKLM\\{key}"))),
                ("name", json!(service)),
                ("command", json!(failure)),
                ("enabled", json!(true)),
            ]));
        }
    }

    // Application Verifier DLLs attached to a program through IFEO.
    let ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    for view in [View::V64, View::V32] {
        for sub in winreg::subkeys(Hive::Hklm, ifeo, view) {
            let key = format!("{ifeo}\\{sub}");
            let dlls = strip(&text_of(winreg::value(Hive::Hklm, &key, "VerifierDlls", view).as_ref())).to_string();
            for dll in dlls.split_whitespace() {
                out.push(entry(vec![
                    ("source", json!("ifeo_verifier")),
                    ("location", json!(winreg::display(Hive::Hklm, &key, view))),
                    ("name", json!(sub)),
                    ("command", json!(dll)),
                    ("file", json!(resolve_dll(dll, &SYSTEM32))),
                    ("enabled", json!(true)),
                ]));
            }
        }
    }

    // RunOnceEx: runs (or loads DLLs) at the next sign-in, then deletes itself.
    let once_ex = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx";
    for view in [View::V64, View::V32] {
        for sub in winreg::subkeys(Hive::Hklm, once_ex, view) {
            let key = format!("{once_ex}\\{sub}");
            for (name, data) in winreg::values(Hive::Hklm, &key, view) {
                let command = strip(&data.as_text()).to_string();
                if name.is_empty() || name.eq_ignore_ascii_case("Flags") || command.is_empty() {
                    continue;
                }
                out.push(entry(vec![
                    ("source", json!("runonceex")),
                    ("location", json!(winreg::display(Hive::Hklm, &key, view))),
                    ("name", json!(name)),
                    ("command", json!(command)),
                    ("enabled", json!(true)),
                ]));
            }
        }
    }

    // The debugger Windows starts when a program crashes.
    let aedebug = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug";
    for view in [View::V64, View::V32] {
        let values = winreg::values(Hive::Hklm, aedebug, view);
        let debugger = strip(&text_of(winreg::get(&values, "Debugger"))).to_string();
        if !debugger.is_empty() {
            let auto = winreg::get(&values, "Auto").is_some_and(|d| strip(&d.as_text()) == "1");
            out.push(entry(vec![
                ("source", json!("aedebug")),
                ("location", json!(winreg::display(Hive::Hklm, aedebug, view))),
                ("name", json!("Debugger")),
                ("command", json!(debugger)),
                ("auto", json!(auto)),
                ("enabled", json!(true)),
            ]));
        }
    }

    // A program Remote Desktop runs instead of the desktop.
    for (key, location) in [
        (
            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        ),
        (
            r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        ),
    ] {
        let program = strip(&text_of(
            winreg::value(Hive::Hklm, key, "InitialProgram", View::V64).as_ref(),
        ))
        .to_string();
        if !program.is_empty() {
            out.push(entry(vec![
                ("source", json!("rdp_initial_program")),
                ("location", json!(location)),
                ("name", json!("InitialProgram")),
                ("command", json!(program)),
                ("enabled", json!(true)),
            ]));
        }
    }
}

fn profiler_entry(location: &str, name: &str, target: &str, enabled: bool) -> Value {
    entry(vec![
        ("source", json!("clr_profiler")),
        ("location", json!(location)),
        ("name", json!(name)),
        ("command", json!(target)),
        ("file", json!(resolve_dll(target, &SYSTEM32))),
        ("enabled", json!(enabled)),
    ])
}

/// Session Manager values that run native programs before Windows starts, besides BootExecute.
pub(crate) const BOOT_VALUES: &[&str] = &["BootExecute", "SetupExecute", "Execute"];

/// One-value settings judged as configuration (`sysconfig.hooks`).
pub(crate) fn collect_config() -> Value {
    let mut cfg = Map::new();

    // %windir% / %SystemRoot% redefined for the user: Windows' own scheduled tasks and
    // auto-elevating programs then run files from another folder.
    let mut overrides = Map::new();
    for name in ["windir", "SystemRoot"] {
        if let Some(data) = winreg::value(Hive::Hkcu, "Environment", name, View::V64) {
            overrides.insert(name.to_string(), json!(data.as_text()));
        }
    }
    cfg.insert("env_override".into(), Value::Object(overrides));

    // The shell of "Safe mode with command prompt" (cmd.exe on every Windows).
    let shell = text_of(
        winreg::value(
            Hive::Hklm,
            r"SYSTEM\CurrentControlSet\Control\SafeBoot",
            "AlternateShell",
            View::V64,
        )
        .as_ref(),
    );
    cfg.insert("alternate_shell".into(), json!(strip(&shell)));

    // Accounts hidden from the sign-in screen (value 0).
    let hidden: Vec<Value> = winreg::values(
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList",
        View::V64,
    )
    .into_iter()
    .filter(|(_, data)| data.eq_int(0))
    .map(|(name, _)| json!(name))
    .collect();
    cfg.insert("hidden_accounts".into(), json!(hidden));

    // Machine PATH folders searched before System32 that a standard user can change.
    let path = text_of(winreg::value(Hive::Hklm, &format!(r"{SESSION}\Environment"), "Path", View::V64).as_ref());
    cfg.insert("path_before_system32".into(), json!(writable_before_system32(&path)));
    Value::Object(cfg)
}

/// The machine PATH entries before System32 that a standard user can write to.
pub(crate) fn writable_before_system32(path: &str) -> Vec<String> {
    let system32 = lower(&SYSTEM32);
    let mut out = Vec::new();
    for raw in path.split(';') {
        let folder = normalize_path(raw);
        if folder.is_empty() {
            continue;
        }
        let low = lower(folder.trim_end_matches('\\'));
        if low == system32 {
            break;
        }
        if isabs(&folder) && is_user_writable(&format!("{}\\", folder.trim_end_matches('\\'))) {
            out.push(folder);
        }
    }
    out
}

/// Event log channels whose "Enabled = 0" would hide an intrusion. Task Scheduler's
/// Operational log is not here: Windows ships it turned off.
pub(crate) const WATCHED_CHANNELS: &[&str] = &[
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
];

/// Settings that blind the defences, only when explicitly set (`sysconfig.evasion`).
pub(crate) fn collect_evasion() -> Value {
    let mut cfg = Map::new();
    let channels = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels";
    let off: Vec<Value> = WATCHED_CHANNELS
        .iter()
        .filter(|c| {
            winreg::value(Hive::Hklm, &format!("{channels}\\{c}"), "Enabled", View::V64).is_some_and(|d| d.eq_int(0))
        })
        .map(|c| json!(c))
        .collect();
    cfg.insert("channels_off".into(), json!(off));

    let autologger = r"SYSTEM\CurrentControlSet\Control\WMI\Autologger";
    let loggers: Vec<Value> = ["EventLog-Security", "EventLog-System", "EventLog-Application"]
        .iter()
        .filter(|l| {
            winreg::value(Hive::Hklm, &format!("{autologger}\\{l}"), "Start", View::V64).is_some_and(|d| d.eq_int(0))
        })
        .map(|l| json!(l))
        .collect();
    cfg.insert("autologgers_off".into(), json!(loggers));

    let explicit =
        |key: &str, name: &str| winreg::value(Hive::Hklm, key, name, View::V64).map_or(Value::Null, |d| d.to_value());
    cfg.insert(
        "run_as_ppl".into(),
        explicit(r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL"),
    );
    cfg.insert(
        "driver_blocklist".into(),
        explicit(
            r"SYSTEM\CurrentControlSet\Control\CI\Config",
            "VulnerableDriverBlocklistEnable",
        ),
    );
    Value::Object(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntpath::WINDIR;

    #[test]
    fn packed_catalog_paths() {
        let mut bytes = b"%SystemRoot%\\system32\\mswsock.dll".to_vec();
        bytes.extend([0, 0, 1, 2, 3]);
        assert_eq!(packed_path(&bytes), r"%SystemRoot%\system32\mswsock.dll");
        assert_eq!(packed_path(&[]), "");
        assert_eq!(packed_path(&[b'a'; 400]).len(), 260);
    }

    #[test]
    fn dlls_resolve_in_their_folder() {
        let spool = join(&SYSTEM32, &[r"spool\prtprocs\x64"]);
        assert_eq!(
            lower(&resolve_dll("winprint.dll", &spool)),
            lower(&join(&spool, &["winprint.dll"]))
        );
        assert_eq!(resolve_dll(r"C:\Vendor\mon.dll", &SYSTEM32), r"C:\Vendor\mon.dll");
        assert_eq!(
            lower(&resolve_dll(r"%SystemRoot%\System32\w32time.dll", &SYSTEM32)),
            lower(&join(&SYSTEM32, &["w32time.dll"]))
        );
        assert_eq!(resolve_dll("  ", &SYSTEM32), "");
    }

    #[test]
    fn profilers_from_environment_variables() {
        let pairs = |items: &[(&str, &str)]| -> Vec<(String, String)> {
            items.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        assert_eq!(
            clr_profiler(&pairs(&[
                ("COR_ENABLE_PROFILING", "1"),
                ("COR_PROFILER_PATH", r"C:\Users\jdoe\p.dll")
            ])),
            Some((true, r"C:\Users\jdoe\p.dll".to_string()))
        );
        assert_eq!(
            clr_profiler(&pairs(&[("CORECLR_PROFILER_PATH_64", r"C:\apm\x.dll")])),
            Some((false, r"C:\apm\x.dll".to_string()))
        );
        assert_eq!(clr_profiler(&pairs(&[("PATH", r"C:\Windows")])), None);
        assert_eq!(
            block_pairs(&["COR_ENABLE_PROFILING=1".into(), "junk".into()]),
            vec![("COR_ENABLE_PROFILING".to_string(), "1".to_string())]
        );
    }

    #[test]
    fn writable_path_entries_before_system32() {
        let windir = WINDIR.clone();
        let path = format!(r"C:\Tools;C:\Program Files\Vendor;{windir}\system32;C:\Users\jdoe\bin");
        assert_eq!(writable_before_system32(&path), vec![r"C:\Tools".to_string()]);
        let path = r"%SystemRoot%\system32;C:\Tools".to_string();
        assert!(writable_before_system32(&path).is_empty());
    }

    #[test]
    fn accessibility_names_are_lower_case() {
        for (name, originals) in ACCESSIBILITY {
            assert_eq!(*name, lower(name));
            assert!(originals.iter().all(|o| *o == lower(o)));
        }
        assert_eq!(accessibility_paths().len(), ACCESSIBILITY.len());
    }

    /// Reads this computer (read-only) and prints counts only:
    /// `cargo test -p vigil-scan hooks::tests::live_counts -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_counts() {
        let started = std::time::Instant::now();
        let entries = collect_autoruns();
        let mut by_source = std::collections::BTreeMap::new();
        for e in &entries {
            *by_source
                .entry(e.get("source").and_then(Value::as_str).unwrap_or("").to_string())
                .or_insert(0) += 1;
        }
        let outside = entries
            .iter()
            .filter(|e| {
                e.get("file")
                    .and_then(Value::as_str)
                    .is_some_and(|f| !f.is_empty() && !in_windows_dir(f))
            })
            .count();
        let cfg = collect_config();
        let evasion = collect_evasion();
        let len = |v: &Value| v.as_array().map_or(0, Vec::len);
        println!(
            "hook entries {} in {:?}: {by_source:?}",
            entries.len(),
            started.elapsed()
        );
        println!("files outside the Windows folder: {outside}");
        println!(
            "env overrides {}, alternate shell default: {}, hidden accounts {}, writable PATH before System32 {}",
            cfg["env_override"].as_object().map_or(0, Map::len),
            lower(cfg["alternate_shell"].as_str().unwrap_or("")) == "cmd.exe",
            len(&cfg["hidden_accounts"]),
            len(&cfg["path_before_system32"]),
        );
        println!(
            "channels off {}, autologgers off {}, RunAsPPL set: {}, blocklist set: {}",
            len(&evasion["channels_off"]),
            len(&evasion["autologgers_off"]),
            !evasion["run_as_ppl"].is_null(),
            !evasion["driver_blocklist"].is_null(),
        );
    }
}
