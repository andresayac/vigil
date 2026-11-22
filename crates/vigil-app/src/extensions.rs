//! The Browser extensions page: the extensions of every browser profile and the browser policies,
//! read live (read-only), their icons, and the requests that open a browser's extensions page or an
//! extension's folder, or remove a policy. A request names an extension by its key or a policy by
//! its id; Rust reads everything again and builds the confirmation from what it finds, never from
//! the page. Extensions themselves are removed in the browser: browsers restore deleted folders and
//! keep their extension settings protected.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{LazyLock, Mutex, PoisonError};

use serde_json::json;
use vigil_i18n::tr;
use vigil_scan::browsers::{BrowserData, Extension, Policy, Sources};

use crate::planner::{SpecExt, spec};
use crate::requests::Plan;

/// What this account may read: every account's profiles when elevated, its own otherwise.
fn sources() -> Sources {
    Sources::live(vigil_sys::elevation::is_elevated())
}

/// Icons of the list read last, by extension key.
static ICONS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn remember_icons(data: &BrowserData) {
    let icons: HashMap<String, String> = data
        .extensions
        .iter()
        .filter(|e| !e.icon.is_empty())
        .map(|e| (e.key.clone(), e.icon.clone()))
        .collect();
    *ICONS.lock().unwrap_or_else(PoisonError::into_inner) = icons;
}

/// Every browser extension and browser policy, read now (read-only).
#[tauri::command]
pub async fn extensions_list() -> Result<BrowserData, String> {
    let data = tauri::async_runtime::spawn_blocking(|| vigil_scan::browsers::read(&sources()))
        .await
        .map_err(|e| e.to_string())?;
    remember_icons(&data);
    Ok(data)
}

/// The icons (PNG data URLs) of extensions of the list read last, by key. Only the icon files that
/// list named are read; keys without an icon are left out.
#[tauri::command]
pub async fn extension_icons(keys: Vec<String>) -> Result<HashMap<String, String>, String> {
    let known = ICONS.lock().unwrap_or_else(PoisonError::into_inner).clone();
    tauri::async_runtime::spawn_blocking(move || {
        keys.into_iter()
            .take(512)
            .filter_map(|key| {
                let path = known.get(&key)?;
                let url = vigil_sys::apps::logo_data_url(Path::new(path))?;
                Some((key, url))
            })
            .collect()
    })
    .await
    .map_err(|e| e.to_string())
}

// ------------------------------------------------------------------------------------ requests

/// A request about an extension, checked against a fresh read.
pub async fn plan_extension(op: String, key: String, browser: String) -> Result<Plan, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let data = if op == "page" && !browser.is_empty() {
            BrowserData::default()
        } else {
            vigil_scan::browsers::read(&sources())
        };
        extension_plan(&op, &key, &browser, &data.extensions)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// A request about a browser policy, checked against a fresh read of the policies.
pub async fn plan_policy(op: String, id: String) -> Result<Plan, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let live = sources();
        let policies = vigil_scan::browsers::read_policies(&live.policy_roots, &live.firefox_dirs);
        policy_plan(&op, &id, &policies)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Open the browser's extensions page (of an extension's browser, or of a browser by name), or the
/// extension's folder.
pub(crate) fn extension_plan(op: &str, key: &str, browser: &str, extensions: &[Extension]) -> Result<Plan, String> {
    let find = || {
        extensions
            .iter()
            .find(|e| e.key == key.trim())
            .ok_or(tr!("The extension is no longer there. Refresh the list."))
    };
    match op {
        "page" => {
            let name = if browser.is_empty() {
                find()?.browser.clone()
            } else {
                browser.to_string()
            };
            if !vigil_actions::shell::known_browser(&name) {
                return Err(tr!("Unknown browser."));
            }
            Ok(Plan::Shell(
                spec(
                    "shell.browser",
                    tr!("Open {0} extensions page", name),
                    name.clone(),
                    tr!(
                        "Opens the browser's extensions page so you can remove it there (browsers protect their extension settings, so removal happens in the browser)."
                    ),
                )
                .params(json!({ "browser": name }))
                .no_admin(),
            ))
        }
        "folder" => {
            let ext = find()?;
            let path = Path::new(&ext.path);
            if ext.path.is_empty() || !path.is_absolute() || !path.exists() {
                return Err(tr!("The folder of {0} does not exist.", format!("\"{}\"", ext.name)));
            }
            // Firefox keeps most extensions as one .xpi file: show it selected in its folder.
            let (op, label) = if path.is_dir() {
                ("shell.folder", tr!("Open extension folder"))
            } else {
                ("shell.location", tr!("Open file location"))
            };
            Ok(Plan::Shell(
                spec(op, label, ext.path.clone(), tr!("Opens the folder."))
                    .params(json!({ "path": ext.path }))
                    .no_admin(),
            ))
        }
        _ => Err(tr!("Unknown request: {0}", op)),
    }
}

/// What removing a policy does, in the confirmation.
fn policy_explain(policy: &Policy) -> String {
    let what = match policy.kind.as_str() {
        "force_install" | "extension_settings" => tr!(
            "This policy makes {0} install an extension and stops you from removing it. Removing the policy does not uninstall the extension: afterwards you can remove it on the browser's extensions page.",
            policy.browser
        ),
        "install_sources" => tr!(
            "This policy lets websites install extensions in {0} from outside the store.",
            policy.browser
        ),
        "search" => tr!("This policy sets the search engine of {0}.", policy.browser),
        "homepage" | "startup" | "new_tab" => tr!(
            "This policy sets the pages {0} opens (home page, startup pages or new tab).",
            policy.browser
        ),
        "proxy" => tr!("This policy sends the traffic of {0} through a proxy.", policy.browser),
        "devtools" => tr!("This policy turns off the developer tools of {0}.", policy.browser),
        "safe_browsing" => tr!(
            "This policy turns off the protection of {0} against dangerous sites and downloads.",
            policy.browser
        ),
        _ => tr!("This is a policy of {0}.", policy.browser),
    };
    format!(
        "{what}\n\n{}",
        tr!(
            "The setting is saved first, so you can put it back from History. The browser applies the change when it restarts."
        )
    )
}

/// Remove a browser policy (registry values only; Firefox's policies.json is only shown).
pub(crate) fn policy_plan(op: &str, id: &str, policies: &[Policy]) -> Result<Plan, String> {
    if op != "remove" {
        return Err(tr!("Unknown request: {0}", op));
    }
    let policy = policies
        .iter()
        .find(|p| p.id.eq_ignore_ascii_case(id.trim()))
        .ok_or(tr!("The policy is no longer set. Refresh the list."))?;
    if policy.scope == "file" || !policy.removable {
        return Err(tr!("Vigil does not remove this policy."));
    }
    let built = spec(
        "browser.policy_remove",
        tr!("Remove the browser policy {0}", policy.name),
        format!(r"{}\{} = {}", policy.key, policy.value, policy.data),
        policy_explain(policy),
    )
    .params(json!({
        "key": policy.key,
        "value": policy.value,
        "browser": policy.browser,
        "name": policy.name,
    }))
    .warning(&tr!(
        "Companies and schools set browser policies on the computers they manage. If this computer is managed, the policy may come back; ask the people who manage it."
    ));
    // This user's own policies need no administrator rights.
    let built = if policy.scope == "user" {
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
    use vigil_scan::browsers::{PolicyRoot, read_policies};

    fn policy(kind: &str, scope: &str, removable: bool) -> Policy {
        let root = if scope == "user" { "HKCU" } else { "HKLM" };
        let key = format!(r"{root}\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist");
        Policy {
            id: format!("{key}|1"),
            key,
            value: "1".into(),
            browser: "Chrome".into(),
            scope: scope.into(),
            name: "ExtensionInstallForcelist".into(),
            data: "ppppoooonnnnmmmmllllkkkkjjjjiiii;https://updates.fabrikam.example/crx".into(),
            kind: kind.into(),
            flagged: true,
            removable,
            ..Policy::default()
        }
    }

    fn spec_of(plan: Result<Plan, String>) -> vigil_actions::ActionSpec {
        match plan {
            Ok(Plan::Run { spec, .. } | Plan::Shell(spec)) => spec,
            Ok(_) => panic!("unexpected plan"),
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn removable_policies_become_actions() {
        let machine = policy("force_install", "machine", true);
        let built = spec_of(policy_plan("remove", &machine.id, std::slice::from_ref(&machine)));
        assert_eq!(built.op, "browser.policy_remove");
        assert_eq!(built.params["key"], machine.key);
        assert_eq!(built.params["value"], "1");
        assert!(built.admin && built.reversible && !built.destructive);
        assert!(built.target.contains("fabrikam"), "the confirmation shows the value");
        assert!(built.explain.contains("does not uninstall"), "{}", built.explain);

        let user = policy("homepage", "user", true);
        assert!(
            !spec_of(policy_plan(
                "remove",
                &user.id.to_uppercase(),
                std::slice::from_ref(&user)
            ))
            .admin
        );

        let refused = |p: Policy, op: &str| policy_plan(op, &p.id.clone(), &[p]).is_err();
        assert!(refused(policy("allow", "machine", false), "remove"));
        assert!(refused(
            Policy {
                scope: "file".into(),
                ..policy("force_install", "machine", true)
            },
            "remove"
        ));
        assert!(refused(machine.clone(), "edit"));
        assert!(
            policy_plan("remove", "HKLM\\x|1", &[machine]).is_err(),
            "not in the live list"
        );
    }

    #[test]
    fn extension_requests_open_the_browser_or_the_folder() {
        let dir = std::env::temp_dir().join(format!("vigil-ext-folder-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("folder");
        let notes = Extension {
            key: "Chrome||Default|aaaabbbbccccddddeeeeffffgggghhhh".into(),
            browser: "Chrome".into(),
            name: "Contoso Notes".into(),
            path: dir.to_string_lossy().into_owned(),
            path_exists: true,
            ..Extension::default()
        };
        let gone = Extension {
            key: "Firefox||abcd.default|notes@contoso.example".into(),
            browser: "Firefox".into(),
            path: r"C:\nowhere\notes.xpi".into(),
            ..Extension::default()
        };
        let list = [notes.clone(), gone.clone()];
        let page = spec_of(extension_plan("page", &notes.key, "", &list));
        assert_eq!(
            (page.op.as_str(), page.params["browser"].as_str()),
            ("shell.browser", Some("Chrome"))
        );
        let by_name = spec_of(extension_plan("page", "", "Opera GX", &[]));
        assert_eq!(by_name.params["browser"], "Opera GX");
        assert!(extension_plan("page", "", "calc", &[]).is_err());
        assert!(extension_plan("page", "nothing", "", &list).is_err());
        let folder = spec_of(extension_plan("folder", &notes.key, "", &list));
        assert_eq!(folder.op, "shell.folder");
        assert_eq!(folder.params["path"], notes.path);
        assert!(extension_plan("folder", &gone.key, "", &list).is_err());
        assert!(extension_plan("delete", &notes.key, "", &list).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_request_kinds_parse() {
        let ext: Request =
            serde_json::from_value(json!({"kind": "extension", "op": "folder", "key": "Chrome||Default|x"}))
                .expect("extension request");
        assert!(matches!(ext, Request::Extension { ref op, .. } if op == "folder"));
        let page: Request = serde_json::from_value(json!({"kind": "extension", "op": "page", "browser": "Edge"}))
            .expect("page request");
        assert!(matches!(page, Request::Extension { ref browser, .. } if browser == "Edge"));
        let policy: Request =
            serde_json::from_value(json!({"kind": "browser-policy", "op": "remove", "id": "HKLM\\x|1"}))
                .expect("policy request");
        assert!(matches!(policy, Request::BrowserPolicy { .. }));
    }

    /// The reader, the request and the action agree on paths: a policy written under the tests'
    /// scratch key is listed, removed through the action engine, listed no more, and put back.
    #[test]
    fn a_listed_policy_is_removed_and_put_back() {
        let sub = format!(r"Software\VigilTests\extensions-{}\Policies", std::process::id());
        let root = format!(r"HKCU\{sub}");
        let list_key = format!(r"{root}\Google\Chrome\ExtensionInstallForcelist");
        let forced = "ppppoooonnnnmmmmllllkkkkjjjjiiii;https://updates.fabrikam.example/crx";
        vigil_actions::reg_write(&list_key, "1", &json!({"type": "REG_SZ", "data": forced})).expect("scratch policy");
        let roots = [PolicyRoot {
            machine: false,
            key: sub.clone(),
        }];
        let listed = read_policies(&roots, &[]);
        let found = listed
            .iter()
            .find(|p| p.key == list_key && p.value == "1")
            .expect("the policy is listed")
            .clone();
        assert_eq!((found.kind.as_str(), found.scope.as_str()), ("force_install", "user"));
        assert!(found.flagged && found.removable);
        assert_eq!(found.extension_ids, ["ppppoooonnnnmmmmllllkkkkjjjjiiii"]);

        let built = spec_of(policy_plan("remove", &found.id, &listed));
        let dir = std::env::temp_dir().join(format!("vigil-ext-store-{}", std::process::id()));
        let store = vigil_actions::Store::open(&dir).expect("store");
        vigil_actions::testing::set_policy_root(Some(&root));
        let record = vigil_actions::execute(&built, &store, None, "");
        assert!(record.ok(), "{}", record.message());
        assert!(!read_policies(&roots, &[]).iter().any(|p| p.id == found.id), "removed");
        vigil_actions::undo(record.id(), &store).expect("undo");
        assert!(read_policies(&roots, &[]).iter().any(|p| p.id == found.id), "put back");

        vigil_actions::testing::reset();
        let _ = vigil_actions::testing::delete_scratch_key(&format!(
            r"Software\VigilTests\extensions-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
