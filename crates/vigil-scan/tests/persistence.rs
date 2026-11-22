//! PowerShell profiles, Office persistence, and firewall rules and changes in the scan, end to end on
//! fictitious inventories (jdoe, Contoso, Fabrikam, PC-VICTIM, 203.0.113.x).
//!
//! No test changes the system or calls external services.

mod support;

use serde_json::{Value, json};
use support::*;
use vigil_scan::model::{Analysis, Item};
use vigil_scan::run_analysis;

/// An inventory with only what a test sets (the rest of the analysis sees an empty computer).
fn mini(extra: Value) -> Value {
    let mut raw = json!({"meta": {"is_admin": true}, "system": {"defender": {"realtime": true, "antivirus": true}}});
    if let (Some(base), Some(add)) = (raw.as_object_mut(), extra.as_object()) {
        for (k, v) in add {
            base.insert(k.clone(), v.clone());
        }
    }
    raw
}

fn with_flag<'a>(analysis: &'a Analysis, code: &str) -> Vec<&'a Item> {
    analysis
        .items
        .iter()
        .filter(|i| i.flags.iter().any(|f| f.code == code))
        .collect()
}

fn weight(item: &Item, code: &str) -> i64 {
    item.flags.iter().find(|f| f.code == code).map_or(0, |f| f.weight)
}

fn scripts() -> Value {
    serde_json::from_str(&data("persistence.json")).expect("persistence.json")
}

fn profile(path: &str, scope: &str, content: &Value) -> Value {
    json!({"path": path, "scope": scope, "size": 300, "truncated": false, "content": content})
}

#[test]
fn powershell_profiles_only_when_they_look_like_an_attack() {
    let s = scripts();
    let raw = mini(json!({"sysconfig": {"persistence": {"ps_profiles": [
        profile(r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1", "all_users", &s["suspicious_profile"]),
        profile(r"C:\Users\jdoe\OneDrive\Documents\PowerShell\Microsoft.PowerShell_profile.ps1", "current_user", &s["conda_profile"]),
        profile(r"C:\Users\jdoe\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1", "current_user", &s["theme_profile"]),
    ]}}}));
    let analysis = run_analysis(&raw, false);
    let hits = with_flag(&analysis, "ps_profile");
    assert_eq!(hits.len(), 1, "conda and prompt-theme profiles stay quiet");
    let hit = hits[0];
    assert!(hit.title.contains("profile.ps1"), "{}", hit.title);
    assert_eq!(weight(hit, "ps_profile"), 20, "a profile for every user");
    assert!(hit.score >= 50, "{}", hit.score);
    assert!(hit.facts["patterns"].as_array().is_some_and(|p| !p.is_empty()));
    assert!(!hit.facts["snippet"].as_str().unwrap_or("").is_empty());
}

#[test]
fn office_dlls_are_judged_as_files() {
    let test_dll = r"C:\ProgramData\Contoso\perf.dll".to_string();
    let vendor = r"C:\Program Files\Fabrikam\Office\FabAddin.dll".to_string();
    let user_dll = r"C:\Users\jdoe\AppData\Roaming\Contoso\addin.dll".to_string();
    let wll = r"C:\Users\jdoe\AppData\Roaming\Microsoft\Word\STARTUP\Contoso.wll".to_string();
    let mut files = serde_json::Map::new();
    let unsigned = json!({"exists": true, "sig_status": "NotSigned"});
    files.insert(test_dll.to_lowercase(), unsigned.clone());
    files.insert(user_dll.to_lowercase(), unsigned.clone());
    files.insert(wll.to_lowercase(), unsigned);
    files.insert(
        vendor.to_lowercase(),
        json!({"exists": true, "sig_status": "Valid", "signer": "Fabrikam, Inc.", "issuer": "DigiCert"}),
    );
    let raw = mini(json!({
        "autoruns": [
            {"source": "office_test", "location": r"HKCU\Software\Microsoft\Office test\Special\Perf",
             "name": "(Default)", "command": test_dll, "file": test_dll, "enabled": true},
            {"source": "office_addin", "location": r"HKLM\SOFTWARE\Microsoft\Office\Outlook\Addins\Fabrikam.Connect",
             "name": "Outlook: Fabrikam Connect", "command": vendor, "file": vendor, "enabled": true},
            {"source": "office_addin", "location": r"HKCU\Software\Microsoft\Office\Excel\Addins\Contoso.Helper",
             "name": "Excel: Contoso.Helper", "command": user_dll, "file": user_dll, "enabled": true},
            {"source": "office_startup", "location": r"C:\Users\jdoe\AppData\Roaming\Microsoft\Word\STARTUP",
             "name": "Word: Contoso.wll", "command": wll, "file": wll, "enabled": true},
        ],
        "files": files,
    }));
    let analysis = run_analysis(&raw, false);
    let item = |path: &str| {
        analysis
            .items
            .iter()
            .find(|i| i.path.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(path)))
    };
    let perf = item(&test_dll).expect("Office test DLL");
    assert_eq!(weight(perf, "office_test"), 70);
    assert!(perf.score >= 70, "{}", perf.score);
    // A signed vendor add-in in its own folder carries no signal.
    assert_eq!(item(&vendor).expect("vendor add-in").score, 0);
    assert!(
        item(&user_dll).expect("user add-in").score >= 30,
        "unsigned, in a user folder"
    );
    assert_eq!(weight(item(&wll).expect("Word add-in DLL"), "office_startup_dll"), 20);
}

#[test]
fn office_configuration_findings() {
    let raw = mini(json!({"sysconfig": {"persistence": {"office": {
        "vsto_addins": [
            {"app": "Excel", "name": "Contoso Sheets", "location": r"HKCU\Software\Microsoft\Office\Excel\Addins\Contoso.Sheets",
             "manifest": "https://updates.contoso.example/sheets.vsto|vstolocal",
             "path": "https://updates.contoso.example/sheets.vsto", "web": true, "user_writable": false},
            {"app": "Word", "name": "Fabrikam Writer", "location": r"HKLM\SOFTWARE\Microsoft\Office\Word\Addins\Fabrikam.Writer",
             "manifest": "file:///C:/Program%20Files/Fabrikam/Writer.vsto|vstolocal",
             "path": r"C:\Program Files\Fabrikam\Writer.vsto", "web": false, "user_writable": false},
        ],
        "startup_macros": [
            {"app": "Excel", "folder": r"C:\Users\jdoe\AppData\Roaming\Microsoft\Excel\XLSTART",
             "file": r"C:\Users\jdoe\AppData\Roaming\Microsoft\Excel\XLSTART\tools.xlam", "size": 20480},
        ],
        "outlook": {
            "vba_project": {"path": r"C:\Users\jdoe\AppData\Roaming\Microsoft\Outlook\VbaProject.OTM", "size": 4096},
            "home_pages": [{"key": r"HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox", "url": "http://203.0.113.9/home.html"}],
        },
    }}}}));
    let analysis = run_analysis(&raw, false);
    let vsto = with_flag(&analysis, "office_vsto_addin");
    assert_eq!(vsto.len(), 1, "the add-in in Program Files is normal");
    assert_eq!(weight(vsto[0], "office_vsto_addin"), 20);
    let macros = with_flag(&analysis, "office_startup_macros");
    assert_eq!(macros.len(), 1);
    assert!(macros[0].title.contains("tools.xlam"));
    assert_eq!(with_flag(&analysis, "outlook_vba").len(), 1);
    let home = with_flag(&analysis, "outlook_home_page");
    assert_eq!(home.len(), 1);
    assert_eq!(home[0].score, 60);

    // Office not installed: nothing to report.
    let empty = mini(json!({"sysconfig": {"persistence": {"ps_profiles": [], "office": {
        "vsto_addins": [], "startup_macros": [], "outlook": {"vba_project": null, "home_pages": []}}}}}));
    let analysis = run_analysis(&empty, false);
    for code in [
        "office_vsto_addin",
        "office_startup_macros",
        "outlook_vba",
        "outlook_home_page",
        "ps_profile",
    ] {
        assert!(with_flag(&analysis, code).is_empty(), "{code}");
    }
}

fn rule(name: &str, flags: &[&str], extra: Value) -> Value {
    let mut r = json!({
        "name": name, "group": "", "builtin": false, "direction": "in", "action": "allow",
        "profiles": ["private"], "program": "", "program_exists": true, "service": "",
        "protocol": "TCP", "local_ports": "", "remote_addresses": "", "edge_traversal": false,
        "flags": flags, "port": 0,
    });
    if let (Some(base), Some(add)) = (r.as_object_mut(), extra.as_object()) {
        for (k, v) in add {
            base.insert(k.clone(), v.clone());
        }
    }
    r
}

#[test]
fn flagged_firewall_rules_become_findings() {
    let raw = mini(
        json!({"sysconfig": {"firewall_rules": {"total": 400, "inbound_allow": 120, "flagged": [
            rule("Contoso Game Server", &["open_public"], json!({"profiles": ["public", "private"]})),
            rule("OpenSSH", &["remote_access"], json!({"profiles": ["public"], "local_ports": "22", "port": 22})),
            rule("Fabrikam VNC", &["remote_access"], json!({"local_ports": "5900", "remote_addresses": "192.168.1.0/24", "port": 5900})),
            rule("Contoso Sync", &["writable_program"], json!({"program": r"C:\Users\jdoe\AppData\Local\Contoso\sync.exe"})),
            rule("Fabrikam Chat", &["writable_program"], json!({"program": r"C:\Users\jdoe\AppData\Local\Fabrikam\chat.exe"})),
            rule("Contoso Remote", &["remote_access", "writable_program"],
                 json!({"local_ports": "5985", "port": 5985, "program": r"C:\ProgramData\Contoso\remote.exe"})),
            rule("Old Fabrikam Tool", &["missing_program"], json!({"program": r"C:\Program Files\Fabrikam\old.exe", "program_exists": false})),
            rule("Old Contoso Tool", &["missing_program"], json!({"program": r"C:\Program Files\Contoso\old.exe", "program_exists": false})),
        ]}}}),
    );
    let analysis = run_analysis(&raw, false);
    assert_eq!(with_flag(&analysis, "firewall_open_public").len(), 1);
    let remote = with_flag(&analysis, "firewall_remote_access");
    assert_eq!(remote.len(), 3);
    // A remote-access rule for a program anyone can replace: one finding with both marks.
    let both = remote
        .iter()
        .find(|i| i.title.contains("Contoso Remote"))
        .expect("both");
    assert_eq!(weight(both, "firewall_writable_program"), 30);
    let ssh = remote.iter().find(|i| i.title.contains("OpenSSH")).expect("ssh");
    assert_eq!(
        weight(ssh, "firewall_remote_access"),
        45,
        "any address on public networks"
    );
    let vnc = remote.iter().find(|i| i.title.contains("VNC")).expect("vnc");
    assert_eq!(
        weight(vnc, "firewall_remote_access"),
        30,
        "limited to the local network"
    );
    // Rules for programs in user folders on their own: one low summary, not a finding per rule.
    let writable: Vec<_> = with_flag(&analysis, "firewall_writable_program")
        .into_iter()
        .filter(|i| i.title.contains("folders anyone can change") && i.kind == "config")
        .filter(|i| i.facts.get("rules").is_some())
        .collect();
    assert_eq!(writable.len(), 1);
    assert_eq!(writable[0].score, 15);
    assert_eq!(writable[0].facts["rules"].as_array().map(Vec::len), Some(2));
    let missing = with_flag(&analysis, "firewall_missing_programs");
    assert_eq!(missing.len(), 1, "one low summary");
    assert_eq!(missing[0].score, 5);
    assert_eq!(missing[0].facts["rules"].as_array().map(Vec::len), Some(2));

    // The firewall could not be read, or nothing is flagged: no finding.
    for cfg in [
        json!({"error": "timeout"}),
        json!({"total": 10, "inbound_allow": 2, "flagged": []}),
    ] {
        let analysis = run_analysis(&mini(json!({"sysconfig": {"firewall_rules": cfg}})), false);
        assert!(
            analysis
                .items
                .iter()
                .all(|i| !i.flags.iter().any(|f| f.code.starts_with("firewall_")))
        );
    }
}

#[test]
fn firewall_changes_skip_windows_own_churn() {
    let sys = system32();
    let svchost = format!(r"{sys}\svchost.exe");
    let netsh = format!(r"{sys}\netsh.exe");
    let change = |id: i64, rule: &str, program: &str, by: &str, extra: Value| {
        let mut c = json!({"time": "2026-11-20T10:00:00", "id": id, "rule": rule, "program": program,
            "service": "", "direction": "1", "action": "3", "local_ports": "", "remote_addresses": "",
            "setting": "", "value": "", "by_app": by});
        if let (Some(base), Some(add)) = (c.as_object_mut(), extra.as_object()) {
            for (k, v) in add {
                base.insert(k.clone(), v.clone());
            }
        }
        c
    };
    let raw = mini(json!({"events": {"days": 30, "firewall_changes": [
        // Windows' own churn: a Windows program changing rules for Windows or for no program.
        change(2097, "Core Networking - DHCP", &format!(r"{sys}\svchost.exe"), &svchost, json!({})),
        change(2097, "Contoso Store App", "", &svchost, json!({})),
        change(2052, "Contoso Store App", "", &svchost, json!({})),
        // A rule added from the command line for Remote Desktop.
        change(2097, "Open RDP", "", &netsh, json!({"local_ports": "3389"})),
        // An installer adding an outbound rule for its own program: only the summary.
        change(2004, "Fabrikam Updater", r"C:\Program Files\Fabrikam\update.exe",
               r"C:\Program Files\Fabrikam\setup.exe", json!({"direction": "2"})),
        // A block rule from the command line is not a risk.
        change(2097, "Block Contoso", r"C:\Program Files\Contoso\c.exe", &netsh, json!({"action": "2"})),
        change(2006, "Old Fabrikam rule", "", r"C:\Program Files\Fabrikam\setup.exe", json!({})),
        change(2003, "", "", &netsh, json!({"setting": "1", "value": "No"})),
        change(2003, "", "", &svchost, json!({"setting": "1", "value": "Yes"})),
    ]}}));
    let analysis = run_analysis(&raw, false);
    let scripted = with_flag(&analysis, "firewall_rule_scripted");
    assert_eq!(scripted.len(), 1, "only the inbound allow rule from netsh");
    assert!(scripted[0].title.contains("Open RDP"));
    assert_eq!(weight(scripted[0], "firewall_rule_remote_port"), 35);
    assert_eq!(scripted[0].facts["changed_by"], json!(netsh));
    assert_eq!(with_flag(&analysis, "firewall_settings_scripted").len(), 1);
    let summary = with_flag(&analysis, "firewall_rules_added");
    assert_eq!(summary.len(), 1);
    let listed = summary[0].facts["rules"].as_array().cloned().unwrap_or_default();
    let names: Vec<&str> = listed.iter().filter_map(|r| r["rule"].as_str()).collect();
    assert_eq!(
        names,
        ["Fabrikam Updater", "Block Contoso"],
        "programs outside Windows only"
    );
    assert_eq!(summary[0].facts["deleted_by_programs"], json!(1));
    assert_eq!(summary[0].score, 5);
    assert!(
        analysis
            .items
            .iter()
            .all(|i| !i.title.contains("DHCP") && !i.title.contains("Store App"))
    );
}
