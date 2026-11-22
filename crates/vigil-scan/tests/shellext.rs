//! Explorer shell extensions judged end to end on a fictitious inventory. No test reads or
//! changes the system.

use serde_json::{Map, Value, json};
use vigil_scan::model::{Analysis, Item};
use vigil_scan::run_analysis;

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

fn ext(kind: &str, clsid: &str, file: &str, startup: bool, shadowed: bool) -> Value {
    let location = if startup {
        format!(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{clsid}")
    } else {
        r"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\Contoso".to_string()
    };
    json!({
        "source": "shell_extension", "location": location, "name": "Contoso", "kind": kind,
        "clsid": clsid, "class_name": "Contoso Shell", "command": file, "file": file,
        "startup": startup, "user_registration": shadowed, "shadowed": shadowed, "enabled": true,
    })
}

#[test]
fn explorer_extensions_are_judged_by_their_dll() {
    let startup_unsigned = r"C:\Users\jdoe\AppData\Roaming\Contoso\sso.dll";
    let menu_unsigned = r"C:\Program Files\Contoso Tools\menu.dll";
    let vendor = r"C:\Program Files\Fabrikam Archiver\fabshell.dll";
    let writable_startup = r"C:\Users\Public\Tailspin\hook.dll";
    let missing = r"C:\Program Files\Gone\gone.dll";
    let replaced = r"C:\Program Files\Northwind\thumbs.dll";
    let windows = r"C:\Windows\System32\shell32.dll";
    let mut files = Map::new();
    let mut put = |path: &str, info: Value| {
        files.insert(path.to_lowercase(), info);
    };
    put(startup_unsigned, json!({"exists": true, "sig_status": "NotSigned"}));
    put(menu_unsigned, json!({"exists": true, "sig_status": "NotSigned"}));
    let signed = |signer: &str| json!({"exists": true, "sig_status": "Valid", "signer": signer, "issuer": "DigiCert"});
    put(vendor, signed("Fabrikam, Inc."));
    put(writable_startup, signed("Tailspin Toys"));
    put(missing, json!({"exists": false}));
    put(replaced, signed("Northwind Traders"));
    put(
        windows,
        json!({"exists": true, "sig_status": "Valid", "signer": "Microsoft Windows", "issuer": "Microsoft Windows Production PCA 2011"}),
    );
    let raw = mini(json!({
        "autoruns": [
            ext("shell_service_object", "{aaaaaaaa-0000-0000-0000-000000000001}", startup_unsigned, true, false),
            ext("context_menu", "{aaaaaaaa-0000-0000-0000-000000000002}", menu_unsigned, false, false),
            ext("context_menu", "{aaaaaaaa-0000-0000-0000-000000000003}", vendor, false, false),
            ext("execute_hook", "{aaaaaaaa-0000-0000-0000-000000000004}", writable_startup, true, false),
            ext("icon_overlay", "{aaaaaaaa-0000-0000-0000-000000000005}", missing, false, false),
            ext("thumbnail_provider", "{aaaaaaaa-0000-0000-0000-000000000006}", replaced, false, true),
            ext("context_menu", "{aaaaaaaa-0000-0000-0000-000000000007}", windows, false, false),
        ],
        "files": files,
    }));
    let analysis = run_analysis(&raw, false);

    // Loaded when Explorer starts, unsigned: weighs most.
    let sso = by_path(&analysis, startup_unsigned).expect("startup object");
    assert_eq!(weight(sso, "shell_extension_unsigned"), Some(50));
    assert!(sso.verdict != "trusted" && sso.verdict != "safe");
    // An unsigned context menu handler only loads when a menu opens.
    let menu = by_path(&analysis, menu_unsigned).expect("menu");
    assert_eq!(weight(menu, "shell_extension_unsigned"), Some(30));
    // A signed vendor DLL in its own folder: no signal.
    let archiver = by_path(&analysis, vendor).expect("vendor");
    assert!(archiver.flags.iter().all(|f| !f.code.starts_with("shell_extension")));
    // Signed, but in a folder any user can change, and loaded at Explorer start.
    let hook = by_path(&analysis, writable_startup).expect("hook");
    assert_eq!(weight(hook, "shell_extension_user_folder"), Some(45));
    // A leftover: barely a signal.
    let gone = by_path(&analysis, missing).expect("missing");
    assert_eq!(weight(gone, "shell_extension_missing"), Some(5));
    // The user's registration replaces the computer's with another vendor's DLL.
    let thumbs = by_path(&analysis, replaced).expect("replaced");
    assert_eq!(weight(thumbs, "shell_extension_replaced"), Some(20));
    // Windows' own handler: no signal, trusted.
    let shell = by_path(&analysis, windows).expect("windows");
    assert!(shell.flags.iter().all(|f| !f.code.starts_with("shell_extension")));
    assert_eq!(shell.verdict, "trusted");

    // The way back is the program's own setting or its uninstaller, never a registry edit.
    let steps = vigil_scan::remedy::build_remediation(sso);
    assert!(
        steps.iter().any(|s| s["title"]
            .as_str()
            .is_some_and(|t| t.contains("Turn the extension off"))),
        "{steps:?}"
    );
    assert!(
        steps
            .iter()
            .all(|s| !s["command"].as_str().is_some_and(|c| c.contains("Registry::"))),
        "{steps:?}"
    );
}
