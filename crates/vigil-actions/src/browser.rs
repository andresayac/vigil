//! Removing a browser policy that forces an extension, redirects search, the home page, the startup
//! pages or the new tab, sets a proxy, or turns Safe Browsing, SmartScreen or the developer tools
//! off. Only values of the policies Vigil knows, under `HKLM` / `HKCU\SOFTWARE\Policies` of Chrome,
//! Edge, Brave and Firefox, are accepted; the value is read again and saved first, and undo writes
//! it back. Policies that keep protection on are never removed.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

use crate::datadir::is_admin;
use crate::engine::{Builtin, Outcome, run_fn, undo_fn};
use crate::error::{Result, fail};
use crate::params::Params;
use crate::registry::{reg_delete, reg_read, reg_write};
use vigil_i18n::tr;

/// The browsers' policy keys below `SOFTWARE\Policies` (Chromium ones may have `\Recommended`).
const CHROMIUM: &str = r"(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave)(\\Recommended)?";

/// (key below `SOFTWARE\Policies`, value name) pairs that may be removed.
static REMOVABLE: LazyLock<Vec<(Regex, Regex)>> = LazyLock::new(|| {
    let rules: Vec<(String, &str)> = vec![
        (
            format!(r"(?i)^{CHROMIUM}$"),
            r"(?i)^(ExtensionSettings|DefaultSearchProvider\w+|HomepageLocation|HomepageIsNewTabPage|NewTabPageLocation|RestoreOnStartup|ProxySettings|ProxyMode|ProxyServer|ProxyPacUrl|ProxyServerMode|ProxyBypassList|DeveloperToolsAvailability|SafeBrowsingEnabled|SafeBrowsingProtectionLevel|SmartScreenEnabled|SmartScreenPuaEnabled)$",
        ),
        (
            format!(r"(?i)^{CHROMIUM}\\(ExtensionInstallForcelist|ExtensionInstallSources|RestoreOnStartupURLs)$"),
            r"^\d+$",
        ),
        (
            r"(?i)^Mozilla\\Firefox$".into(),
            r"(?i)^(ExtensionSettings|DisableDeveloperTools)$",
        ),
        (r"(?i)^Mozilla\\Firefox\\Extensions\\(Install|Locked)$".into(), r"^\d+$"),
        (
            r"(?i)^Mozilla\\Firefox\\Homepage$".into(),
            r"(?i)^(URL|StartPage|Locked)$",
        ),
        (r"(?i)^Mozilla\\Firefox\\Homepage\\Additional$".into(), r"^\d+$"),
        (r"(?i)^Mozilla\\Firefox\\SearchEngines$".into(), r"(?i)^Default$"),
        (r"(?i)^Mozilla\\Firefox\\Proxy$".into(), r"(?i)^\w+$"),
    ];
    rules
        .iter()
        .filter_map(|(key, value)| Some((Regex::new(key).ok()?, Regex::new(value).ok()?)))
        .collect()
});

/// `HKLM\SOFTWARE\Policies\<rest>` -> (machine, rest). In the tests, the scratch root stands in for
/// `HKCU\SOFTWARE\Policies` and is the only root accepted.
fn split_policy_key(key: &str) -> Option<(bool, String)> {
    let key = key.trim();
    let strip = |prefix: &str| -> Option<String> {
        let head = key.get(..prefix.len())?;
        let rest = key.get(prefix.len()..)?;
        (head.eq_ignore_ascii_case(prefix) && !rest.is_empty()).then(|| rest.to_string())
    };
    if let Some(root) = crate::testing::policy_root() {
        return strip(&format!("{root}\\")).map(|rest| (false, rest));
    }
    if let Some(rest) = strip(r"HKLM\SOFTWARE\Policies\") {
        return Some((true, rest));
    }
    strip(r"HKCU\SOFTWARE\Policies\").map(|rest| (false, rest))
}

/// A browser policy value Vigil may remove.
fn allowed(rest: &str, value: &str) -> bool {
    !rest.contains("..")
        && REMOVABLE
            .iter()
            .any(|(key, name)| key.is_match(rest) && name.is_match(value))
}

/// The number a policy is set to (DWORD, or text that holds a number).
fn number(snapshot: &Value) -> Option<u64> {
    let data = snapshot.get("data")?;
    data.as_u64()
        .or_else(|| data.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Policies that turn protection off are removed only while they do: one that keeps Safe Browsing,
/// SmartScreen or the developer tools on stays.
fn weakens(value: &str, snapshot: &Value) -> bool {
    let name = value.to_ascii_lowercase();
    match name.as_str() {
        "safebrowsingenabled" | "safebrowsingprotectionlevel" | "smartscreenenabled" | "smartscreenpuaenabled" => {
            number(snapshot) == Some(0)
        }
        "developertoolsavailability" => number(snapshot) == Some(2),
        "disabledevelopertools" => number(snapshot) == Some(1),
        "extensionsettings" => {
            let text = snapshot.get("data").map(Value::to_string).unwrap_or_default();
            text.contains("force_installed") || text.contains("normal_installed")
        }
        _ => true,
    }
}

fn op_policy_remove(p: Params<'_>, _store: &crate::store::Store, _id: &str) -> Result<Outcome> {
    let key = p.req_str("key")?;
    let value = p.req_str("value")?;
    let Some((machine, _)) = split_policy_key(&key).filter(|(_, rest)| allowed(rest, &value)) else {
        return fail(tr!(
            "Vigil only removes browser policies it knows; {0}\\{1} is not one of them",
            key,
            value
        ));
    };
    if machine && !is_admin() {
        return fail(tr!(
            "removing a policy set for every user of this computer needs administrator rights"
        ));
    }
    let Some(snapshot) = reg_read(&key, &value)? else {
        return fail(tr!("the policy is no longer set"));
    };
    if !weakens(&value, &snapshot) {
        return fail(tr!(
            "this policy keeps the browser's protection on; Vigil does not remove it"
        ));
    }
    reg_delete(&key, &value)?;
    if reg_read(&key, &value)?.is_some() {
        return fail(tr!("the policy could not be removed"));
    }
    let browser = p.str_or_empty("browser");
    let name = p.str_or_empty("name");
    Ok(Outcome::new(
        tr!(
            "removed the browser policy {0} ({1}); it takes effect when the browser restarts",
            if name.is_empty() { value.clone() } else { name.clone() },
            if browser.is_empty() {
                key.clone()
            } else {
                browser.clone()
            }
        ),
        Some(json!({ "key": key, "value": value, "snapshot": snapshot, "name": name, "browser": browser })),
    ))
}

fn undo_policy_remove(u: Params<'_>, _store: &crate::store::Store) -> Result<String> {
    let key = u.req_str("key")?;
    let value = u.req_str("value")?;
    let Some((machine, rest)) = split_policy_key(&key) else {
        return fail(tr!("the saved policy is not a browser policy"));
    };
    if !allowed(&rest, &value) {
        return fail(tr!("the saved policy is not a browser policy"));
    }
    if machine && !is_admin() {
        return fail(tr!(
            "putting back a policy set for every user of this computer needs administrator rights"
        ));
    }
    let snapshot = u.get("snapshot").clone();
    if snapshot.is_null() {
        return fail(tr!("the saved value of this policy is missing"));
    }
    reg_write(&key, &value, &snapshot)?;
    let name = u.str_or_empty("name");
    Ok(tr!(
        "put the browser policy {0} back",
        if name.is_empty() { value } else { name }
    ))
}

pub(crate) fn builtin() -> Vec<Builtin> {
    // This user's policies need no administrator rights; the machine's are checked in the op.
    vec![(
        "browser.policy_remove",
        run_fn(op_policy_remove),
        Some(undo_fn(undo_policy_remove)),
        true,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(key: &str, value: &str) -> bool {
        split_policy_key(key).is_some_and(|(_, rest)| allowed(&rest, value))
    }

    #[test]
    fn only_known_policies_are_accepted() {
        crate::testing::reset();
        for (key, value) in [
            (r"HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", "1"),
            (r"HKCU\Software\Policies\Microsoft\Edge", "HomepageLocation"),
            (
                r"HKLM\SOFTWARE\Policies\BraveSoftware\Brave\Recommended",
                "DefaultSearchProviderSearchURL",
            ),
            (
                r"HKLM\SOFTWARE\Policies\Google\Chrome\Recommended\RestoreOnStartupURLs",
                "3",
            ),
            (r"HKLM\SOFTWARE\Policies\Google\Chrome", "SafeBrowsingEnabled"),
            (r"HKLM\SOFTWARE\Policies\Mozilla\Firefox\Extensions\Install", "1"),
            (r"HKLM\SOFTWARE\Policies\Mozilla\Firefox\Homepage", "URL"),
            (r"HKCU\SOFTWARE\Policies\Mozilla\Firefox\Proxy", "HTTPProxy"),
            (r"HKLM\SOFTWARE\Policies\Mozilla\Firefox", "DisableDeveloperTools"),
        ] {
            assert!(ok(key, value), "{key} {value}");
        }
        assert_eq!(
            split_policy_key(r"HKLM\SOFTWARE\Policies\Google\Chrome").map(|(m, _)| m),
            Some(true)
        );
        assert_eq!(
            split_policy_key(r"HKCU\SOFTWARE\Policies\Google\Chrome").map(|(m, _)| m),
            Some(false)
        );
        for (key, value) in [
            (r"HKLM\SOFTWARE\Policies\Google\Chrome", "PasswordManagerEnabled"),
            (r"HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist", "1"),
            (r"HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", "x"),
            (
                r"HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist\Sub",
                "1",
            ),
            (
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
                "DisableAntiSpyware",
            ),
            (r"HKLM\SOFTWARE\Policies", "HomepageLocation"),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HomepageLocation",
            ),
            (
                r"HKLM\SOFTWARE\Policies\Mozilla\Firefox\SearchEngines\Add\1",
                "URLTemplate",
            ),
            (
                r"HKU\S-1-5-21-1-2-3-1001\SOFTWARE\Policies\Google\Chrome",
                "HomepageLocation",
            ),
            (r"HKCU\Software\VigilTests\Google\Chrome", "HomepageLocation"),
        ] {
            assert!(!ok(key, value), "{key} {value}");
        }
    }

    #[test]
    fn protection_policies_stay() {
        let dword = |n: u64| json!({"type": "REG_DWORD", "data": n});
        assert!(weakens("SafeBrowsingEnabled", &dword(0)));
        assert!(!weakens("SafeBrowsingEnabled", &dword(1)));
        assert!(!weakens("SmartScreenEnabled", &dword(1)));
        assert!(weakens("DeveloperToolsAvailability", &dword(2)));
        assert!(!weakens("DeveloperToolsAvailability", &dword(0)));
        assert!(weakens("DisableDeveloperTools", &dword(1)));
        assert!(!weakens("DisableDeveloperTools", &dword(0)));
        let settings = |text: &str| json!({"type": "REG_SZ", "data": text});
        assert!(weakens(
            "ExtensionSettings",
            &settings(r#"{"x":{"installation_mode":"force_installed"}}"#)
        ));
        assert!(!weakens(
            "ExtensionSettings",
            &settings(r#"{"*":{"installation_mode":"blocked"}}"#)
        ));
        assert!(weakens("HomepageLocation", &settings("https://start.example")));
    }
}
