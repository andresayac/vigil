//! Script scanning (AMSI) and PowerShell's own safeguards, in the scan. READ-ONLY: registry reads.
//!
//! AMSI is how Windows shows scripts to the antivirus before they run (PowerShell, Windows Script
//! Host, Office macros). Each antivirus registers an AMSI provider, a DLL loaded into every
//! program that runs scripts: an unknown provider sees every script and can hide some, and
//! `AmsiEnable = 0` turns the scanning off for Windows Script Host. The providers become startup
//! entries (`amsi_provider`), so their DLL is judged by signature and folder like every other
//! hook; the settings go to `sysconfig.script_security` and are judged here.
//!
//! PowerShell's logging policies (script block logging, module logging, transcription) are
//! reported as information: they help investigate an attack afterwards and are normally off on a
//! home computer. An execution policy forced to Bypass or Unrestricted by policy, and an explicit
//! `__PSLockdownPolicy`, are reported too.

use serde_json::{Map, Value, json};
use vigil_i18n::tr;

use crate::hooks::resolve_dll;
use crate::lenient::{Get, list, lower, strip, text};
use crate::model::{Flag, Item};
use crate::ntpath::SYSTEM32;
use crate::winreg::{self, Hive, RegData, View};

/// Where collection stores its settings in the inventory.
pub(crate) const SECTION: &str = "script_security";

/// The registry places read; [`Places::windows`] on a real computer, scratch keys in the tests.
pub(crate) struct Places {
    /// `...\AMSI\Providers` (each subkey is a provider's CLSID).
    pub(crate) providers: (Hive, String),
    /// `...\Classes\CLSID` (where a provider's DLL is registered).
    pub(crate) classes: (Hive, String),
    /// `...\Windows Script\Settings`, per user and for the computer.
    pub(crate) script_settings: Vec<(Hive, String)>,
    /// PowerShell policy keys: (hive, key, "Windows PowerShell" or "PowerShell 7").
    pub(crate) policies: Vec<(Hive, String, &'static str)>,
    /// The Session Manager environment (`__PSLockdownPolicy`).
    pub(crate) environment: (Hive, String),
}

impl Places {
    pub(crate) fn windows() -> Self {
        Self {
            providers: (Hive::Hklm, r"SOFTWARE\Microsoft\AMSI\Providers".into()),
            classes: (Hive::Hklm, r"SOFTWARE\Classes\CLSID".into()),
            script_settings: vec![
                (Hive::Hkcu, r"Software\Microsoft\Windows Script\Settings".into()),
                (Hive::Hklm, r"SOFTWARE\Microsoft\Windows Script\Settings".into()),
            ],
            policies: vec![
                (
                    Hive::Hklm,
                    r"SOFTWARE\Policies\Microsoft\Windows\PowerShell".into(),
                    "Windows PowerShell",
                ),
                (
                    Hive::Hkcu,
                    r"Software\Policies\Microsoft\Windows\PowerShell".into(),
                    "Windows PowerShell",
                ),
                (
                    Hive::Hklm,
                    r"SOFTWARE\Policies\Microsoft\PowerShellCore".into(),
                    "PowerShell 7",
                ),
                (
                    Hive::Hkcu,
                    r"Software\Policies\Microsoft\PowerShellCore".into(),
                    "PowerShell 7",
                ),
            ],
            environment: (
                Hive::Hklm,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment".into(),
            ),
        }
    }
}

fn text_of(data: Option<&RegData>) -> String {
    data.map(RegData::as_text).unwrap_or_default()
}

/// The AMSI providers as startup entries (source `amsi_provider`), from both registry views.
pub(crate) fn collect_autoruns() -> Vec<Value> {
    providers(&Places::windows())
}

pub(crate) fn providers(places: &Places) -> Vec<Value> {
    let (hive, key) = &places.providers;
    let (class_hive, classes) = &places.classes;
    let mut out = Vec::new();
    let mut seen = Vec::new();
    for view in [View::V64, View::V32] {
        for clsid in winreg::subkeys(*hive, key, view) {
            let id = lower(&clsid);
            if seen.contains(&id) {
                continue;
            }
            seen.push(id);
            let name = text_of(winreg::value(*hive, &format!(r"{key}\{clsid}"), "", view).as_ref());
            let server = format!(r"{classes}\{clsid}\InprocServer32");
            let dll = text_of(winreg::value(*class_hive, &server, "", view).as_ref());
            let file = resolve_dll(&dll, &SYSTEM32);
            out.push(json!({
                "source": "amsi_provider",
                "location": winreg::display(*hive, &format!(r"{key}\{clsid}"), view),
                "name": if name.is_empty() { clsid.clone() } else { format!("{name} {clsid}") },
                "command": strip(&dll),
                "file": file,
                "enabled": true,
            }));
        }
    }
    out
}

/// The settings judged in [`items`].
pub(crate) fn collect_config() -> Value {
    config(&Places::windows())
}

pub(crate) fn config(places: &Places) -> Value {
    let mut amsi = Vec::new();
    for (hive, key) in &places.script_settings {
        if let Some(value) = winreg::value(*hive, key, "AmsiEnable", View::V64) {
            amsi.push(json!({"location": winreg::display(*hive, key, View::V64), "value": value.to_value()}));
        }
    }
    let mut powershell = Vec::new();
    for (hive, key, product) in &places.policies {
        let mut entry = Map::new();
        let read = |sub: &str, name: &str| winreg::value(*hive, &format!(r"{key}\{sub}"), name, View::V64);
        let flag = |data: Option<RegData>| data.map(|d| d.truthy());
        let script_block = flag(read("ScriptBlockLogging", "EnableScriptBlockLogging"));
        let module = flag(read("ModuleLogging", "EnableModuleLogging"));
        let transcription = flag(read("Transcription", "EnableTranscripting"));
        let policy = winreg::values(*hive, key, View::V64);
        let execution = winreg::get(&policy, "EnableScripts")
            .filter(|d| d.truthy())
            .map(|_| text_of(winreg::get(&policy, "ExecutionPolicy")));
        if script_block.is_none() && module.is_none() && transcription.is_none() && execution.is_none() {
            continue;
        }
        entry.insert("product".into(), json!(product));
        entry.insert("location".into(), json!(winreg::display(*hive, key, View::V64)));
        entry.insert("script_block_logging".into(), json!(script_block));
        entry.insert("module_logging".into(), json!(module));
        entry.insert("transcription".into(), json!(transcription));
        entry.insert("execution_policy".into(), json!(execution));
        powershell.push(Value::Object(entry));
    }
    let (hive, key) = &places.environment;
    let lockdown = winreg::value(*hive, key, "__PSLockdownPolicy", View::V64).map(|d| d.as_text());
    json!({
        "amsi_enable": amsi,
        "providers": winreg::subkeys(places.providers.0, &places.providers.1, View::V64).len(),
        "powershell_policies": powershell,
        "lockdown_policy": lockdown,
    })
}

fn item(topic: &str, title: String, score: i64, summary: String, facts: Map<String, Value>) -> Item {
    let mut item = Item::new("config", title, summary.clone());
    let mut all = Map::new();
    all.insert("topic".into(), json!(topic));
    all.extend(facts);
    item.facts = all;
    item.add_flag(Flag::new(topic, score, summary));
    item.rescore();
    item
}

fn facts(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

/// The findings for `sysconfig.script_security`. `other_av_active`: another antivirus protects
/// the computer (then Defender's provider may be missing on purpose).
pub(crate) fn items(raw: &Value) -> Vec<Item> {
    let section = raw.at("sysconfig").at(SECTION);
    if section.as_object().is_none_or(|m| m.is_empty()) {
        return Vec::new();
    }
    let mut out = Vec::new();

    // AmsiEnable = 0: Windows Script Host stops showing scripts to the antivirus.
    for setting in list(section.at("amsi_enable")) {
        if setting.at("value").as_u64() == Some(0) {
            let location = text(setting.at("location"));
            out.push(item(
                "amsi_disabled",
                tr!("Script scanning turned off for Windows Script Host"),
                60,
                tr!(
                    "AmsiEnable is 0 in {0}: .vbs and .js scripts run without being shown to the antivirus first. Malware sets it before running its scripts; nothing normal needs it.",
                    location
                ),
                facts(vec![("location", json!(location)), ("value", json!(0))]),
            ));
        }
    }
    if section.at("providers").as_u64() == Some(0) {
        out.push(item(
            "amsi_no_provider",
            tr!("No antivirus scans scripts before they run"),
            20,
            tr!(
                "No AMSI provider is registered, so PowerShell, Windows Script Host and Office macros run scripts without showing them to an antivirus. Microsoft Defender registers one when it is on; so do most other antivirus programs."
            ),
            Map::new(),
        ));
    }

    // PowerShell policies.
    let mut logging = Vec::new();
    for policy in list(section.at("powershell_policies")) {
        let product = text(policy.at("product"));
        let location = text(policy.at("location"));
        let execution = lower(&text(policy.at("execution_policy")));
        if matches!(execution.as_str(), "bypass" | "unrestricted") {
            out.push(item(
                "powershell_policy_bypass",
                tr!("{0} scripts allowed without checks by policy", product),
                20,
                tr!(
                    "A policy in {0} sets the execution policy to {1}: any script runs, downloaded or not, without the usual check. Companies rarely need this; attackers set it to run their scripts.",
                    location,
                    text(policy.at("execution_policy"))
                ),
                facts(vec![
                    ("location", json!(location)),
                    ("execution_policy", policy.at("execution_policy").clone()),
                ]),
            ));
        }
        for (key, label) in [
            ("script_block_logging", tr!("script block logging")),
            ("module_logging", tr!("module logging")),
            ("transcription", tr!("transcription")),
        ] {
            if policy.at(key).as_bool() == Some(true) {
                logging.push(format!("{label} ({product})"));
            }
        }
    }
    out.push(item(
        "powershell_logging",
        if logging.is_empty() {
            tr!("PowerShell logging is off")
        } else {
            tr!("PowerShell logging: {0}", logging.join(", "))
        },
        0,
        if logging.is_empty() {
            tr!(
                "Script block logging, module logging and transcription record what PowerShell runs, which helps to understand an attack afterwards. They are normally off on a home computer and turned on by a company or by Group Policy."
            )
        } else {
            tr!(
                "PowerShell records what it runs ({0}); the records are in the PowerShell Operational log or the transcription folder. This helps to understand an attack afterwards.",
                logging.join(", ")
            )
        },
        facts(vec![("logging", json!(logging))]),
    ));

    if let Some(value) = section.at("lockdown_policy").as_str() {
        let constrained = strip(value) == "4";
        out.push(item(
            "powershell_lockdown",
            if constrained {
                tr!("PowerShell is limited to constrained language mode")
            } else {
                tr!("PowerShell language mode is set by __PSLockdownPolicy")
            },
            0,
            if constrained {
                tr!(
                    "__PSLockdownPolicy is 4: PowerShell runs in constrained language mode for everyone, which blocks much of what attack scripts use. Microsoft documents it as a test setting; App Control for Business (WDAC) enforces this properly."
                )
            } else {
                tr!(
                    "__PSLockdownPolicy is {0} in the system environment. Microsoft documents it as a test setting; it does not protect by itself.",
                    value
                )
            },
            facts(vec![("lockdown_policy", json!(value))]),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(section: Value) -> Vec<Item> {
        items(&json!({"sysconfig": {"script_security": section}}))
    }

    fn topics(items: &[Item]) -> Vec<(String, i64)> {
        items.iter().map(|i| (text(i.facts.at("topic")), i.score)).collect()
    }

    #[test]
    fn the_defaults_are_quiet() {
        let found = run(json!({"amsi_enable": [], "providers": 1, "powershell_policies": [], "lockdown_policy": null}));
        assert_eq!(topics(&found), [("powershell_logging".to_string(), 0)]);
        // AmsiEnable = 1 is the default.
        let found = run(json!({"amsi_enable": [{"location": "HKCU\\x", "value": 1}], "providers": 1}));
        assert!(found.iter().all(|i| i.score == 0));
    }

    #[test]
    fn turned_off_scanning_and_permissive_policies() {
        let found = run(json!({
            "amsi_enable": [{"location": r"HKCU\Software\Microsoft\Windows Script\Settings", "value": 0}],
            "providers": 0,
            "powershell_policies": [{
                "product": "Windows PowerShell", "location": "HKLM\\x",
                "script_block_logging": true, "module_logging": null, "transcription": false,
                "execution_policy": "Bypass",
            }],
            "lockdown_policy": "4",
        }));
        assert_eq!(
            topics(&found),
            [
                ("amsi_disabled".to_string(), 60),
                ("amsi_no_provider".to_string(), 20),
                ("powershell_policy_bypass".to_string(), 20),
                ("powershell_logging".to_string(), 0),
                ("powershell_lockdown".to_string(), 0),
            ]
        );
        assert_eq!(list(found[3].facts.at("logging")).len(), 1);
    }

    /// Scratch keys under HKCU\Software\VigilTests (deleted afterwards, with the parent when empty).
    #[cfg(windows)]
    mod scratch {
        use windows::Win32::System::Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
            RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegSetValueExW,
        };
        use windows::core::PCWSTR;

        fn wide(text: &str) -> Vec<u16> {
            text.encode_utf16().chain(std::iter::once(0)).collect()
        }

        pub(super) struct Scratch(pub(super) String);

        impl Scratch {
            pub(super) fn new(name: &str) -> Self {
                Self(format!(r"Software\VigilTests\amsi-{name}-{}", std::process::id()))
            }

            pub(super) fn set(&self, sub: &str, name: &str, value: Option<&str>, dword: Option<u32>) {
                let path = wide(&format!(r"{}\{sub}", self.0));
                let mut key = HKEY::default();
                // SAFETY: the path is NUL-terminated; the key is closed below.
                let status = unsafe {
                    RegCreateKeyExW(
                        HKEY_CURRENT_USER,
                        PCWSTR(path.as_ptr()),
                        None,
                        None,
                        REG_OPTION_NON_VOLATILE,
                        KEY_WRITE,
                        None,
                        &mut key,
                        None,
                    )
                };
                assert!(status.is_ok(), "scratch key");
                let name_w = wide(name);
                let data: Vec<u8> = match (value, dword) {
                    (Some(text), _) => wide(text).iter().flat_map(|u| u.to_le_bytes()).collect(),
                    (None, Some(n)) => n.to_le_bytes().to_vec(),
                    (None, None) => Vec::new(),
                };
                if value.is_some() || dword.is_some() {
                    let kind = if value.is_some() { REG_SZ } else { REG_DWORD };
                    // SAFETY: the key is open; name and data are valid for the call.
                    let set = unsafe { RegSetValueExW(key, PCWSTR(name_w.as_ptr()), None, kind, Some(&data)) };
                    assert!(set.is_ok(), "scratch value");
                }
                // SAFETY: the key was opened above and is closed once.
                unsafe {
                    let _ = RegCloseKey(key);
                }
            }
        }

        impl Drop for Scratch {
            fn drop(&mut self) {
                let path = wide(&self.0);
                // SAFETY: deletes only this test's scratch key, then the shared parent if no other
                // test still uses it (RegDeleteKeyW refuses a key that has subkeys).
                unsafe {
                    let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
                    let _ = RegDeleteKeyW(HKEY_CURRENT_USER, windows::core::w!(r"Software\VigilTests"));
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn providers_and_settings_are_read_from_their_keys() {
        let s = scratch::Scratch::new("read");
        let clsid = "{11111111-2222-3333-4444-555555555555}";
        s.set(&format!(r"Providers\{clsid}"), "", Some("Contoso AMSI"), None);
        s.set(
            &format!(r"Classes\{clsid}\InprocServer32"),
            "",
            Some(r#""C:\Users\jdoe\AppData\Local\Contoso\amsi.dll""#),
            None,
        );
        s.set("Script", "AmsiEnable", None, Some(0));
        s.set(r"Policy\ScriptBlockLogging", "EnableScriptBlockLogging", None, Some(1));
        s.set("Policy", "EnableScripts", None, Some(1));
        s.set("Policy", "ExecutionPolicy", Some("Unrestricted"), None);
        s.set("Env", "__PSLockdownPolicy", Some("4"), None);
        let places = Places {
            providers: (Hive::Hkcu, format!(r"{}\Providers", s.0)),
            classes: (Hive::Hkcu, format!(r"{}\Classes", s.0)),
            script_settings: vec![(Hive::Hkcu, format!(r"{}\Script", s.0))],
            policies: vec![(Hive::Hkcu, format!(r"{}\Policy", s.0), "Windows PowerShell")],
            environment: (Hive::Hkcu, format!(r"{}\Env", s.0)),
        };
        let entries = providers(&places);
        assert_eq!(entries.len(), 1);
        assert_eq!(text(entries[0].at("source")), "amsi_provider");
        assert_eq!(
            text(entries[0].at("file")),
            r"C:\Users\jdoe\AppData\Local\Contoso\amsi.dll"
        );
        assert!(text(entries[0].at("name")).starts_with("Contoso AMSI"));

        let section = config(&places);
        assert_eq!(section.at("providers").as_u64(), Some(1));
        assert_eq!(list(section.at("amsi_enable"))[0].at("value").as_u64(), Some(0));
        let policy = &list(section.at("powershell_policies"))[0];
        assert_eq!(policy.at("script_block_logging").as_bool(), Some(true));
        assert_eq!(text(policy.at("execution_policy")), "Unrestricted");
        assert_eq!(text(section.at("lockdown_policy")), "4");
        let found = items(&json!({"sysconfig": {"script_security": section}}));
        assert!(found.iter().any(|i| text(i.facts.at("topic")) == "amsi_disabled"));
        assert!(
            found
                .iter()
                .any(|i| text(i.facts.at("topic")) == "powershell_policy_bypass")
        );
    }

    /// Run by hand: what this computer has (counts and states only).
    #[cfg(windows)]
    #[test]
    #[ignore = "reads this computer's registry"]
    fn live_counts() {
        let entries = collect_autoruns();
        let section = collect_config();
        let found = items(&json!({"sysconfig": {"script_security": section.clone()}}));
        println!(
            "providers {} (entries {}), amsi_enable values {}, powershell policies {}, lockdown {}, findings {:?}",
            section.at("providers"),
            entries.len(),
            list(section.at("amsi_enable")).len(),
            list(section.at("powershell_policies")).len(),
            !section.at("lockdown_policy").is_null(),
            found
                .iter()
                .map(|i| (text(i.facts.at("topic")), i.score))
                .collect::<Vec<_>>()
        );
    }
}
