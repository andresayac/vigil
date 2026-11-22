//! Per-user COM classes that shadow Windows' own, and remote access agents, judged end to end on
//! fictitious inventories. No test reads or changes the system.

use serde_json::{Map, Value, json};
use vigil_scan::model::{Analysis, Item};
use vigil_scan::run_analysis;

/// An inventory with only what a test sets (the rest of the analysis sees an empty computer).
fn mini(extra: Value) -> Value {
    let mut raw = json!({
        "meta": {"is_admin": true, "started": "2026-03-10T10:00:00"},
        "system": {"defender": {"realtime": true, "antivirus": true}},
    });
    if let (Some(base), Some(add)) = (raw.as_object_mut(), extra.as_object()) {
        for (k, v) in add {
            base.insert(k.clone(), v.clone());
        }
    }
    raw
}

fn by_path<'a>(analysis: &'a Analysis, path: &str) -> Option<&'a Item> {
    analysis
        .items
        .iter()
        .find(|i| i.path.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(path)))
}

fn weight(item: &Item, code: &str) -> Option<i64> {
    item.flags.iter().find(|f| f.code == code).map(|f| f.weight)
}

fn com(clsid: &str, file: &str, target: &str) -> Value {
    json!({
        "source": "com_hijack",
        "location": format!(r"HKCU\Software\Classes\CLSID\{clsid}"),
        "name": clsid, "class_name": "", "command": file, "file": file,
        "kind": "inproc", "machine": r"%SystemRoot%\System32\shell32.dll", "target": target, "enabled": true,
    })
}

#[test]
fn per_user_com_classes_are_judged_by_their_file() {
    let unsigned_known = r"C:\Users\jdoe\AppData\Roaming\mru.dll";
    let unsigned_plain = r"C:\Users\jdoe\AppData\Local\Contoso\helper.dll";
    let vendor = r"C:\Users\jdoe\AppData\Local\Fabrikam Cloud\fabsync.dll";
    let missing = r"C:\Users\jdoe\AppData\Local\Gone\gone.dll";
    let mut files = Map::new();
    files.insert(
        unsigned_known.to_lowercase(),
        json!({"exists": true, "sig_status": "NotSigned"}),
    );
    files.insert(
        unsigned_plain.to_lowercase(),
        json!({"exists": true, "sig_status": "NotSigned"}),
    );
    files.insert(
        vendor.to_lowercase(),
        json!({"exists": true, "sig_status": "Valid", "signer": "Fabrikam, Inc.", "issuer": "DigiCert"}),
    );
    files.insert(missing.to_lowercase(), json!({"exists": false}));
    let raw = mini(json!({
        "autoruns": [
            com("{42aedc87-2188-41fd-b9a3-0c966feabec1}", unsigned_known, "MruPidlList (Explorer)"),
            com("{11111111-0000-0000-0000-000000000001}", unsigned_plain, ""),
            com("{11111111-0000-0000-0000-000000000002}", vendor, ""),
            com("{11111111-0000-0000-0000-000000000003}", missing, ""),
            {"source": "com_hijack", "location": r"HKCU\Software\Classes\CLSID\{11111111-0000-0000-0000-000000000004}",
             "name": "{11111111-0000-0000-0000-000000000004}", "command": "https://203.0.113.5/x.sct", "file": "",
             "kind": "scriptlet", "machine": "", "target": "", "enabled": true},
        ],
        "files": files,
    }));
    let analysis = run_analysis(&raw, false);
    let known = by_path(&analysis, unsigned_known).expect("known target");
    assert_eq!(weight(known, "com_hijack"), Some(70));
    assert!(known.verdict != "trusted" && known.verdict != "safe");
    let plain = by_path(&analysis, unsigned_plain).expect("plain");
    assert_eq!(weight(plain, "com_hijack"), Some(50));
    // A signed vendor server in its own folder gives no signal.
    let signed = by_path(&analysis, vendor).expect("vendor");
    assert_eq!(weight(signed, "com_hijack"), None);
    let gone = by_path(&analysis, missing).expect("missing");
    assert_eq!(weight(gone, "com_hijack"), Some(30));
    let scriptlet = analysis
        .items
        .iter()
        .find(|i| i.kind == "config" && i.facts.get("topic").and_then(Value::as_str) == Some("com_scriptlet"))
        .expect("scriptlet finding");
    assert!(scriptlet.score >= 60);
    // The report gives a way back: remove the per-user key, Windows' own class takes over again.
    let steps = vigil_scan::remedy::build_remediation(known);
    assert!(
        steps.iter().any(|s| s["command"]
            .as_str()
            .is_some_and(|c| c.starts_with("Remove-Item -LiteralPath 'Registry::HKEY_CURRENT_USER"))),
        "{steps:?}"
    );
}

#[test]
fn remote_access_agents_in_the_analysis() {
    let agent = r"C:\Program Files\Contoso RMM\AteraAgent.exe";
    let renamed = r"C:\ProgramData\cache\svcupd.exe";
    let mut files = Map::new();
    files.insert(
        agent.to_lowercase(),
        json!({"exists": true, "sig_status": "Valid", "signer": "Atera Networks Ltd", "issuer": "DigiCert", "created": "2024-06-01T09:00:00"}),
    );
    files.insert(
        renamed.to_lowercase(),
        json!({"exists": true, "sig_status": "Valid", "signer": "Fabrikam, Inc.", "issuer": "DigiCert",
               "product": "AnyDesk", "original": "AnyDesk.exe", "created": "2026-03-09T23:00:00"}),
    );
    let raw = mini(json!({
        "services": [
            {"name": "AteraAgent", "display": "AteraAgent", "state": "Running", "start": "Auto",
             "path": format!("\"{agent}\""), "account": "LocalSystem", "pid": 2100, "desc": "", "dll": null},
            {"name": "CacheSvc", "display": "Cache Service", "state": "Running", "start": "Auto",
             "path": format!("\"{renamed}\" --service"), "account": "LocalSystem", "pid": 2200, "desc": "", "dll": null},
        ],
        "network": {"tcp": [
            {"state": "Established", "laddr": "192.168.1.5", "lport": 50300, "raddr": "198.51.100.20", "rport": 443, "pid": 2200}
        ]},
        "files": files,
    }));
    let analysis = run_analysis(&raw, false);
    let agents: Vec<&Item> = analysis
        .items
        .iter()
        .filter(|i| i.facts.get("topic").and_then(Value::as_str) == Some("rmm_agent"))
        .collect();
    assert_eq!(
        agents.len(),
        2,
        "{:?}",
        agents.iter().map(|i| &i.title).collect::<Vec<_>>()
    );
    let atera = agents.iter().find(|i| i.facts["agent"] == "Atera").expect("atera");
    assert_eq!(atera.facts["signed_by_maker"], true);
    assert_eq!(atera.facts["starts_with_windows"], true);
    assert!(atera.score <= 20, "information only: {}", atera.score);
    let anydesk = agents
        .iter()
        .find(|i| i.facts["agent"] == "AnyDesk")
        .expect("renamed anydesk");
    assert!(weight(anydesk, "rmm_renamed").is_some());
    assert!(weight(anydesk, "rmm_signature").is_some());
    assert!(weight(anydesk, "rmm_recent").is_some());
    assert_eq!(anydesk.facts["connected"], true);
    assert!(anydesk.score >= 60, "{}", anydesk.score);
    // The service's own finding names it a remote access tool too.
    let file = by_path(&analysis, agent).expect("agent file");
    assert!(weight(file, "remote_access").is_some());
}
