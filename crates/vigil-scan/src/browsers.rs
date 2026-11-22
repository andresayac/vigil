//! Browser extensions and browser policies, read live for the Browser extensions page.
//!
//! READ-ONLY: files are only read, the registry only queried, and nothing goes over the network.
//!
//! Chromium-family browsers (Chrome, Edge, Brave, Vivaldi, Chromium, Opera, Opera GX) keep each
//! profile's extensions in `Preferences` / `Secure Preferences` (`extensions.settings`) and in
//! `Extensions\<id>\<version>\manifest.json`; Firefox keeps them in each profile's
//! `extensions.json`. Browser policies live under `SOFTWARE\Policies` (for the machine and for the
//! user) and, for Firefox, in `distribution\policies.json` next to the browser.
//!
//! The scan reads extensions on its own (`collect.rs`) for the report; this module adds what the
//! page shows: the profiles' names, where each extension came from, why it is turned off, when it
//! was installed, what its permissions allow, and the policies that force or redirect things.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value};

use crate::collect::{localized, read_json, read_text};
use crate::lenient::{Get, as_integral, list, text};
use crate::winreg::{self, Hive, RegData, View};

/// Chromium-family browsers: (name, kept under %APPDATA% rather than %LOCALAPPDATA%, user data folder).
const CHROMIUM: [(&str, bool, &str); 7] = [
    ("Chrome", false, r"Google\Chrome\User Data"),
    ("Edge", false, r"Microsoft\Edge\User Data"),
    ("Brave", false, r"BraveSoftware\Brave-Browser\User Data"),
    ("Vivaldi", false, r"Vivaldi\User Data"),
    ("Chromium", false, r"Chromium\User Data"),
    ("Opera", true, r"Opera Software\Opera Stable"),
    ("Opera GX", true, r"Opera Software\Opera GX Stable"),
];

/// Browsers that read policies, and their key under `SOFTWARE\Policies`.
pub const POLICY_VENDORS: [(&str, &str); 4] = [
    ("Chrome", r"Google\Chrome"),
    ("Edge", r"Microsoft\Edge"),
    ("Brave", r"BraveSoftware\Brave"),
    ("Firefox", r"Mozilla\Firefox"),
];

/// Update addresses of the official extension stores (Chrome Web Store, Edge Add-ons, Opera add-ons).
const STORE_UPDATES: [&str; 5] = [
    "clients2.google.com/service/update2/crx",
    "update.googleapis.com/service/update2",
    "edge.microsoft.com/extensionwebstorebase/",
    "extension-updates.opera.com/",
    "addons.opera.com/",
];

const MAX_JSON: u64 = 64 * 1024 * 1024;
const MAX_HOSTS: usize = 40;
const MAX_POLICY_VALUES: usize = 600;
const MAX_DATA: usize = 500;

// --------------------------------------------------------------------------- data

/// One extension of one browser profile.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Extension {
    /// `browser|account|profile folder|id`: names the extension in requests.
    pub key: String,
    pub browser: String,
    /// The profile's name as the browser shows it ("Person 1", "Work", "default-release").
    pub profile: String,
    /// The profile's folder ("Default", "Profile 1", "abcd1234.default-release").
    pub profile_dir: String,
    /// Empty for the account Vigil runs as; another account's profile folder name otherwise.
    pub account: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub enabled: bool,
    /// Why the browser turned it off: "user", "permissions", "not_verified", "flagged", "corrupted",
    /// "sideload", "external", "policy", "unsupported_manifest", "incompatible", "other".
    pub disable_reasons: Vec<String>,
    /// When it was installed (Unix ms; 0 when unknown).
    pub installed_ms: i64,
    /// "store", "outside_store", "external", "policy", "unpacked", "component" or "unknown".
    pub source: String,
    pub update_url: String,
    /// 2 or 3 for Chromium browsers; 0 when unknown.
    pub manifest_version: u32,
    /// API permissions ("tabs", "cookies"...).
    pub permissions: Vec<String>,
    /// Sites it may read and change (`<all_urls>`, `https://*.example.com/*`...), at most 40.
    pub hosts: Vec<String>,
    /// What deserves a look: "all_sites", "history", "tabs", "cookies", "web_request", "native",
    /// "debugger", "proxy", "management", "policy", "outside_store", "external", "unpacked", "mv2",
    /// "not_signed", "store_flagged", "delisted".
    pub flags: Vec<String>,
    /// Its folder (Chromium) or its file or folder (Firefox).
    pub path: String,
    pub path_exists: bool,
    /// A PNG icon from its own folder, when there is one.
    pub icon: String,
    /// Part of the browser itself (hidden on the page unless asked for).
    pub component: bool,
}

/// One browser policy value.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    /// `key|value`: names the policy in requests.
    pub id: String,
    /// The registry key (`HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist`), or the
    /// path of Firefox's policies.json.
    pub key: String,
    /// The value name ("1", "HomepageLocation"), or where it sits in policies.json.
    pub value: String,
    pub browser: String,
    /// "machine", "user" or "file".
    pub scope: String,
    /// The policy's name ("ExtensionInstallForcelist", "Homepage.URL").
    pub name: String,
    /// What it is set to, as text (at most 500 characters).
    pub data: String,
    /// "force_install", "extension_settings", "install_sources", "allow", "block", "search",
    /// "homepage", "startup", "new_tab", "proxy", "devtools", "safe_browsing" or "other".
    pub kind: String,
    /// What adware and malware set: forcing extensions, redirecting search, home page, startup pages
    /// or the new tab, a proxy, no developer tools, no Safe Browsing / SmartScreen.
    pub flagged: bool,
    /// Extensions it forces (ids), when it names them.
    pub extension_ids: Vec<String>,
    /// A forced extension that updates from the official store.
    pub store: bool,
    /// Vigil can remove it (a registry value it knows, set to the value that weakens the browser).
    pub removable: bool,
}

/// A browser that has at least one profile on this computer.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BrowserInfo {
    pub name: String,
    pub profiles: usize,
    /// Extensions, browser components left out.
    pub extensions: usize,
}

/// What the page shows.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BrowserData {
    pub extensions: Vec<Extension>,
    pub policies: Vec<Policy>,
    pub browsers: Vec<BrowserInfo>,
    /// Other accounts' profiles were read too (only when elevated).
    pub other_accounts: bool,
}

// --------------------------------------------------------------------------- sources

/// The folders of one account: `%LOCALAPPDATA%` and `%APPDATA%`.
#[derive(Debug, Clone, Default)]
pub struct Home {
    pub local: PathBuf,
    pub roaming: PathBuf,
    /// Empty for the account Vigil runs as; the account's profile folder name otherwise.
    pub account: String,
}

impl Home {
    /// The account Vigil runs as.
    pub fn current() -> Option<Home> {
        let local = std::env::var_os("LOCALAPPDATA")?;
        let roaming = std::env::var_os("APPDATA")?;
        Some(Home {
            local: local.into(),
            roaming: roaming.into(),
            account: String::new(),
        })
    }
}

/// A key whose subkeys are the browsers' policies (`SOFTWARE\Policies`).
#[derive(Debug, Clone)]
pub struct PolicyRoot {
    /// HKLM (every user) or HKCU (this user).
    pub machine: bool,
    pub key: String,
}

impl PolicyRoot {
    fn hive(&self) -> Hive {
        if self.machine { Hive::Hklm } else { Hive::Hkcu }
    }

    /// `HKLM\SOFTWARE\Policies`.
    pub fn path(&self) -> String {
        format!(r"{}\{}", self.hive().short(), self.key)
    }
}

/// Where to read from.
#[derive(Debug, Clone, Default)]
pub struct Sources {
    pub homes: Vec<Home>,
    pub policy_roots: Vec<PolicyRoot>,
    /// Firefox install folders whose `distribution\policies.json` is read.
    pub firefox_dirs: Vec<PathBuf>,
}

impl Sources {
    /// This computer: the account Vigil runs as (and the other accounts when asked, which needs
    /// administrator rights to read their folders), the machine's and this user's policies, and
    /// the usual Firefox install folders.
    pub fn live(other_accounts: bool) -> Sources {
        let mut homes: Vec<Home> = Home::current().into_iter().collect();
        if other_accounts {
            homes.extend(other_homes());
        }
        let policies = r"SOFTWARE\Policies".to_string();
        let mut firefox_dirs: Vec<PathBuf> = Vec::new();
        for var in ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(dir) = std::env::var_os(var).map(|p| PathBuf::from(p).join("Mozilla Firefox"))
                && !firefox_dirs.iter().any(|d| same_path(d, &dir))
            {
                firefox_dirs.push(dir);
            }
        }
        Sources {
            homes,
            policy_roots: vec![
                PolicyRoot {
                    machine: true,
                    key: policies.clone(),
                },
                PolicyRoot {
                    machine: false,
                    key: policies,
                },
            ],
            firefox_dirs,
        }
    }
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}

/// `%SystemDrive%\Users\jdoe` -> `C:\Users\jdoe` (the scan's own expansion: Windows' folders, not
/// the environment).
fn expand_env(text: &str) -> String {
    crate::cmdline::expand_env(text)
}

/// The profile folders of the other accounts of this computer (from ProfileList).
pub fn other_homes() -> Vec<Home> {
    #[cfg(windows)]
    let own = vigil_sys::paths::profile()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    #[cfg(not(windows))]
    let own = std::env::var("USERPROFILE").unwrap_or_default();
    let list_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    let mut out = Vec::new();
    for sid in winreg::subkeys(Hive::Hklm, list_key, View::V64) {
        if !sid.starts_with("S-1-5-21-") || sid.ends_with(".bak") {
            continue;
        }
        let key = format!(r"{list_key}\{sid}");
        let Some(RegData::Str(raw)) = winreg::value(Hive::Hklm, &key, "ProfileImagePath", View::V64) else {
            continue;
        };
        let path = expand_env(raw.trim());
        if path.is_empty() || path.eq_ignore_ascii_case(&own) || !Path::new(&path).is_dir() {
            continue;
        }
        let base = PathBuf::from(&path);
        let account = base
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| sid.clone());
        out.push(Home {
            local: base.join(r"AppData\Local"),
            roaming: base.join(r"AppData\Roaming"),
            account,
        });
    }
    out
}

// --------------------------------------------------------------------------- reading

/// Everything the page shows, read now.
pub fn read(sources: &Sources) -> BrowserData {
    let policies = read_policies(&sources.policy_roots, &sources.firefox_dirs);
    let mut extensions = Vec::new();
    let mut browsers: BTreeMap<&'static str, BrowserInfo> = BTreeMap::new();
    for home in &sources.homes {
        for (browser, roaming, folder) in CHROMIUM {
            let root = (if roaming { &home.roaming } else { &home.local }).join(folder);
            if !root.is_dir() {
                continue;
            }
            for (dir, folder_name, display) in chromium_profiles(&root) {
                let found = chromium_profile(browser, &dir, &folder_name, &display, &home.account);
                let info = browsers.entry(browser).or_default();
                info.profiles += 1;
                info.extensions += found.iter().filter(|e| !e.component).count();
                extensions.extend(found);
            }
        }
        for (dir, folder_name, display) in firefox_profiles(&home.roaming.join(r"Mozilla\Firefox")) {
            let found = firefox_profile(&dir, &folder_name, &display, &home.account);
            let info = browsers.entry("Firefox").or_default();
            info.profiles += 1;
            info.extensions += found.iter().filter(|e| !e.component).count();
            extensions.extend(found);
        }
    }
    mark_forced(&mut extensions, &policies);
    extensions.sort_by(|a, b| {
        (
            a.browser.as_str(),
            a.account.as_str(),
            a.profile_dir.as_str(),
            a.name.to_lowercase(),
        )
            .cmp(&(
                b.browser.as_str(),
                b.account.as_str(),
                b.profile_dir.as_str(),
                b.name.to_lowercase(),
            ))
            .then(a.id.cmp(&b.id))
    });
    BrowserData {
        extensions,
        policies,
        browsers: browsers
            .into_iter()
            .map(|(name, info)| BrowserInfo {
                name: name.to_string(),
                ..info
            })
            .collect(),
        other_accounts: sources.homes.iter().any(|h| !h.account.is_empty()),
    }
}

/// Extensions a policy forces get the "policy" flag, whatever their own record says.
fn mark_forced(extensions: &mut [Extension], policies: &[Policy]) {
    let forced: BTreeSet<(String, String)> = policies
        .iter()
        .filter(|p| p.kind == "force_install" || p.kind == "extension_settings")
        .flat_map(|p| p.extension_ids.iter().map(|id| (p.browser.clone(), id.to_lowercase())))
        .collect();
    for ext in extensions {
        if forced.contains(&(ext.browser.clone(), ext.id.to_lowercase())) && !ext.flags.iter().any(|f| f == "policy") {
            ext.flags.insert(0, "policy".into());
        }
    }
}

/// Text items of a JSON list.
fn strings(value: &Value) -> Vec<String> {
    list(value)
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// A Chromium extension id: 32 letters from a to p.
fn chrome_id(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// Numbers of a version folder name ("1.10.2_0" -> [1, 10, 2, 0]), for picking the newest.
fn version_key(name: &str) -> Vec<u64> {
    name.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap_or(0))
        .collect()
}

/// A host pattern that matches every site.
pub fn all_sites(host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    if host == "<all_urls>" {
        return true;
    }
    let Some((scheme, rest)) = host.split_once("://") else {
        return false;
    };
    matches!(scheme, "*" | "http" | "https" | "ws" | "wss") && rest.starts_with("*/")
}

/// A permission entry that names sites rather than an API.
fn is_host(permission: &str) -> bool {
    permission.contains("://") || permission == "<all_urls>"
}

/// The update address of an official extension store.
pub fn store_update(url: &str) -> bool {
    let url = url.trim().to_ascii_lowercase();
    STORE_UPDATES.iter().any(|known| url.contains(known))
}

/// Windows FILETIME microseconds since 1601 (as Chromium writes them) -> Unix ms.
fn chromium_time(value: &Value) -> i64 {
    let micros = match value {
        Value::String(s) => s.trim().parse::<i64>().unwrap_or(0),
        other => as_integral(other).unwrap_or(0),
    };
    if micros <= 0 {
        return 0;
    }
    (micros / 1000 - 11_644_473_600_000).max(0)
}

/// What a permission set allows, as flags (most worrying first).
fn permission_flags(permissions: &BTreeSet<String>, hosts: &BTreeSet<String>) -> Vec<String> {
    let has = |name: &str| permissions.iter().any(|p| p.eq_ignore_ascii_case(name));
    let every_site = hosts.iter().any(|h| all_sites(h));
    let mut out = Vec::new();
    if every_site {
        out.push("all_sites");
    }
    if has("history") || has("topSites") || has("sessions") {
        out.push("history");
    }
    if has("tabs") || has("webNavigation") {
        out.push("tabs");
    }
    if has("cookies") {
        out.push("cookies");
    }
    let dnr = has("declarativeNetRequest") || has("declarativeNetRequestWithHostAccess");
    if has("webRequest") || has("webRequestBlocking") || (dnr && every_site) {
        out.push("web_request");
    }
    if has("nativeMessaging") {
        out.push("native");
    }
    if has("debugger") {
        out.push("debugger");
    }
    if has("proxy") {
        out.push("proxy");
    }
    if has("management") {
        out.push("management");
    }
    out.into_iter().map(str::to_string).collect()
}

/// The flags of where an extension came from.
fn source_flags(source: &str, update_url: &str) -> Vec<String> {
    let out: &[&str] = match source {
        "policy" => &["policy"],
        "outside_store" => &["outside_store"],
        "unpacked" => &["unpacked"],
        "external" if !update_url.is_empty() && !store_update(update_url) => &["external", "outside_store"],
        "external" => &["external"],
        _ => &[],
    };
    out.iter().map(|s| s.to_string()).collect()
}

// --------------------------------------------------------------------------- Chromium

/// The profiles of a Chromium user data folder: (folder, folder name, name shown by the browser).
fn chromium_profiles(root: &Path) -> Vec<(PathBuf, String, String)> {
    let state = read_json(&root.join("Local State").to_string_lossy(), MAX_JSON);
    let names = state
        .as_ref()
        .map(|s| s.at("profile").at("info_cache").clone())
        .unwrap_or(Value::Null);
    let display = |folder: &str| {
        let name = text(names.at(folder).at("name"));
        if name.is_empty() { folder.to_string() } else { name }
    };
    let mut out = Vec::new();
    // Opera keeps its only profile in the user data folder itself.
    if root.join("Preferences").is_file() {
        out.push((root.to_path_buf(), file_name(root), "Default".to_string()));
    }
    let mut folders: BTreeSet<String> = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "Default" || name.to_ascii_lowercase().starts_with("profile ") {
                folders.insert(name);
            }
        }
    }
    if let Some(cache) = names.as_object() {
        folders.extend(cache.keys().cloned());
    }
    for folder in folders {
        let dir = root.join(&folder);
        let lower = folder.to_ascii_lowercase();
        if lower == "system profile" || lower == "guest profile" || !dir.join("Preferences").is_file() {
            continue;
        }
        let shown = display(&folder);
        out.push((dir, folder, shown));
    }
    out
}

/// `extensions.settings` of a profile, Secure Preferences and Preferences merged.
fn chromium_settings(dir: &Path) -> BTreeMap<String, Map<String, Value>> {
    let mut settings: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    for prefs in ["Secure Preferences", "Preferences"] {
        let Some(found) = read_json(&dir.join(prefs).to_string_lossy(), MAX_JSON) else {
            continue;
        };
        if let Some(entries) = found.at("extensions").at("settings").as_object() {
            for (id, info) in entries {
                if let Some(info) = info.as_object() {
                    settings.entry(id.clone()).or_default().extend(info.clone());
                }
            }
        }
    }
    settings
}

/// Disable reasons as Chromium records them: a bit mask, or (newer versions) a list of the bits.
fn chromium_disable_mask(value: &Value) -> u64 {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(as_integral)
            .fold(0u64, |mask, bit| mask | bit.max(0) as u64),
        other => as_integral(other).map_or(0, |n| n.max(0) as u64),
    }
}

/// Chromium's `disable_reason` bits as keys.
pub fn chromium_disable_reasons(mask: u64) -> Vec<String> {
    const KNOWN: [(u64, &str); 10] = [
        (1, "user"),
        (1 << 1, "permissions"),
        (1 << 4, "sideload"),
        (1 << 5, "not_verified"),
        (1 << 6, "not_verified"),
        (1 << 7, "flagged"),
        (1 << 8, "corrupted"),
        (1 << 11, "external"),
        (1 << 14, "policy"),
        (1 << 19, "unsupported_manifest"),
    ];
    let mut out: Vec<String> = Vec::new();
    let mut rest = mask;
    for (bit, key) in KNOWN {
        if mask & bit != 0 {
            rest &= !bit;
            if !out.iter().any(|k| k == key) {
                out.push(key.to_string());
            }
        }
    }
    if rest != 0 {
        out.push("other".into());
    }
    out
}

/// Chromium's ManifestLocation as a source ("store", "external", "policy"...).
pub fn chromium_source(location: Option<i64>, from_store: bool, update_url: &str) -> &'static str {
    match location {
        Some(1) if from_store || store_update(update_url) => "store",
        Some(1) => "outside_store",
        Some(2 | 3 | 6) => "external",
        Some(4 | 8) => "unpacked",
        Some(5 | 10) => "component",
        Some(7 | 9) => "policy",
        _ => "unknown",
    }
}

/// The best icon of a manifest: the smallest PNG of at least 32 pixels (else the largest), when it
/// is a file inside the extension's folder.
fn chromium_icon(manifest: &Map<String, Value>, ext_dir: &Path) -> String {
    let Some(icons) = manifest.at("icons").as_object() else {
        return String::new();
    };
    let mut sizes: Vec<(u32, String)> = icons
        .iter()
        .filter_map(|(size, path)| Some((size.parse::<u32>().ok()?, path.as_str()?.to_string())))
        .collect();
    sizes.sort();
    let pick = sizes
        .iter()
        .find(|(size, _)| *size >= 32)
        .or_else(|| sizes.last())
        .map(|(_, path)| path.clone());
    let Some(relative) = pick else {
        return String::new();
    };
    let relative = relative.trim_start_matches(['/', '\\']);
    if relative.contains("..") || relative.contains(':') || !relative.to_ascii_lowercase().ends_with(".png") {
        return String::new();
    }
    let path = ext_dir.join(relative.replace('/', "\\"));
    if path.is_file() {
        path.to_string_lossy().into_owned()
    } else {
        String::new()
    }
}

/// What the browser recorded about the store listing: (flagged by the store, no longer listed).
fn chromium_store_state(info: &Map<String, Value>) -> (bool, bool) {
    let blocked = ["blacklist_state", "blocklist_state"]
        .iter()
        .any(|k| as_integral(info.at(k)).is_some_and(|n| (1..=4).contains(&n)));
    let cws = if info.at("cws-info").is_object() {
        info.at("cws-info")
    } else {
        info.at("cws_info")
    };
    let violation = as_integral(cws.at("violation_type")).is_some_and(|n| n > 0);
    let gone = cws.is_object()
        && (cws.at("is_present") == &Value::Bool(false)
            || cws.at("is_live") == &Value::Bool(false)
            || cws.at("unpublished_long_ago") == &Value::Bool(true));
    (blocked || violation, gone)
}

fn chromium_profile(browser: &str, dir: &Path, folder: &str, profile: &str, account: &str) -> Vec<Extension> {
    let settings = chromium_settings(dir);
    let ext_root = dir.join("Extensions");
    let mut ids: BTreeSet<String> = settings.keys().cloned().collect();
    if let Ok(entries) = std::fs::read_dir(&ext_root) {
        ids.extend(entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()));
    }
    let empty = Map::new();
    let mut out = Vec::new();
    for id in ids {
        if !chrome_id(&id) {
            continue;
        }
        let info = settings.get(&id).unwrap_or(&empty);
        let location = as_integral(info.at("location"));
        // The newest version folder; unpacked extensions name their own folder.
        let mut versions: Vec<PathBuf> = std::fs::read_dir(ext_root.join(&id))
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir() && !file_name(p).starts_with('.'))
                    .collect()
            })
            .unwrap_or_default();
        versions.sort_by_key(|p| version_key(&file_name(p)));
        let ext_dir = versions
            .pop()
            .or_else(|| info.at("path").as_str().map(PathBuf::from).filter(|p| p.is_absolute()));
        let manifest = ext_dir
            .as_ref()
            .and_then(|d| read_json(&d.join("manifest.json").to_string_lossy(), 4 * 1024 * 1024))
            .and_then(|m| m.as_object().cloned())
            .or_else(|| info.at("manifest").as_object().cloned())
            .unwrap_or_default();
        if manifest.is_empty() && location.is_none() {
            continue; // what is left of an extension already removed
        }
        let dir_text = ext_dir
            .as_ref()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = localized(&manifest, &dir_text, &text(manifest.at("name")));
        let description = localized(&manifest, &dir_text, &text(manifest.at("description")));

        let mut permissions: BTreeSet<String> = BTreeSet::new();
        let mut hosts: BTreeSet<String> = BTreeSet::new();
        for p in strings(manifest.at("permissions")) {
            if is_host(&p) {
                hosts.insert(p);
            } else {
                permissions.insert(p);
            }
        }
        hosts.extend(strings(manifest.at("host_permissions")));
        for script in list(manifest.at("content_scripts")) {
            hosts.extend(strings(script.at("matches")));
        }
        let active = info.at("active_permissions");
        permissions.extend(strings(active.at("api")));
        hosts.extend(strings(active.at("explicit_host")));
        hosts.extend(strings(active.at("scriptable_host")));

        let mask = chromium_disable_mask(info.at("disable_reasons"));
        let state_off = as_integral(info.at("state")) == Some(0);
        let mut disable_reasons = chromium_disable_reasons(mask);
        if state_off && disable_reasons.is_empty() {
            disable_reasons.push("user".into());
        }
        let update_url = text(manifest.at("update_url"));
        let from_store = info.at("from_webstore") == &Value::Bool(true);
        let source = chromium_source(location, from_store, &update_url);
        let manifest_version = as_integral(manifest.at("manifest_version")).map_or(0, |n| n.clamp(0, 9) as u32);
        let (store_flagged, delisted) = chromium_store_state(info);

        let mut flags = source_flags(source, &update_url);
        flags.extend(permission_flags(&permissions, &hosts));
        if manifest_version == 2 {
            flags.push("mv2".into());
        }
        if store_flagged || mask & (1 << 7) != 0 {
            flags.insert(0, "store_flagged".into());
        }
        if delisted {
            flags.push("delisted".into());
        }
        let installed_ms = {
            let first = chromium_time(info.at("first_install_time"));
            if first > 0 {
                first
            } else {
                chromium_time(info.at("install_time"))
            }
        };
        let icon = ext_dir
            .as_ref()
            .map(|d| chromium_icon(&manifest, d))
            .unwrap_or_default();
        out.push(Extension {
            key: format!("{browser}|{account}|{folder}|{id}"),
            browser: browser.to_string(),
            profile: profile.to_string(),
            profile_dir: folder.to_string(),
            account: account.to_string(),
            name: if name.trim().is_empty() { id.clone() } else { name },
            id,
            version: text(manifest.at("version")),
            description: crate::lenient::take(&description, 300).to_string(),
            enabled: mask == 0 && !state_off,
            disable_reasons,
            installed_ms,
            source: source.to_string(),
            update_url,
            manifest_version,
            permissions: permissions.into_iter().collect(),
            hosts: hosts.into_iter().take(MAX_HOSTS).collect(),
            flags,
            path_exists: ext_dir.as_ref().is_some_and(|d| d.is_dir()),
            path: dir_text,
            icon,
            component: source == "component",
        });
    }
    out
}

// --------------------------------------------------------------------------- Firefox

/// The profiles listed in Firefox's profiles.ini (or found in its Profiles folder): (folder,
/// folder name, profile name).
fn firefox_profiles(base: &Path) -> Vec<(PathBuf, String, String)> {
    let mut out: Vec<(PathBuf, String, String)> = Vec::new();
    if let Ok(ini) = read_text(&base.join("profiles.ini")) {
        let mut section: BTreeMap<String, String> = BTreeMap::new();
        let mut sections: Vec<BTreeMap<String, String>> = Vec::new();
        for line in ini.lines().map(str::trim) {
            if line.starts_with('[') {
                if !section.is_empty() {
                    sections.push(std::mem::take(&mut section));
                }
                section.insert("[".into(), line.to_ascii_lowercase());
            } else if let Some((k, v)) = line.split_once('=') {
                section.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        sections.push(section);
        for s in sections {
            if !s.get("[").is_some_and(|h| h.starts_with("[profile")) {
                continue;
            }
            let Some(path) = s.get("path") else { continue };
            let dir = if s.get("isrelative").is_some_and(|v| v == "1") {
                base.join(path.replace('/', "\\"))
            } else {
                PathBuf::from(path)
            };
            if dir.is_dir() && !out.iter().any(|(d, _, _)| same_path(d, &dir)) {
                let folder = file_name(&dir);
                let name = s.get("name").cloned().unwrap_or_else(|| folder.clone());
                out.push((dir, folder, name));
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(base.join("Profiles")) {
        for entry in entries.flatten() {
            let dir = entry.path();
            if dir.is_dir() && !out.iter().any(|(d, _, _)| same_path(d, &dir)) {
                let folder = file_name(&dir);
                out.push((dir, folder.clone(), folder));
            }
        }
    }
    out
}

/// Firefox's install location as a source.
pub fn firefox_source(location: &str, hidden: bool, policy: bool, signed: bool, from_amo: bool) -> &'static str {
    let location = location.to_ascii_lowercase();
    if hidden
        || location == "app-builtin"
        || location.starts_with("app-system-defaults")
        || location == "app-system-addons"
    {
        return "component";
    }
    if policy {
        return "policy";
    }
    if location == "app-temporary" {
        return "unpacked";
    }
    if location.starts_with("winreg-") || location.starts_with("app-system-") || location == "app-global" {
        return "external";
    }
    if signed && from_amo { "store" } else { "outside_store" }
}

fn firefox_profile(dir: &Path, folder: &str, profile: &str, account: &str) -> Vec<Extension> {
    let Some(data) = read_json(&dir.join("extensions.json").to_string_lossy(), MAX_JSON) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for addon in list(data.at("addons")) {
        if addon.at("type").as_str() != Some("extension") {
            continue;
        }
        let id = text(addon.at("id"));
        if id.is_empty() {
            continue;
        }
        let locale = addon.at("defaultLocale");
        let name = text(locale.at("name"));
        let signed_state = as_integral(addon.at("signedState")).unwrap_or(0);
        let signed = signed_state > 0;
        let source_uri = text(addon.at("sourceURI"));
        let install_source = text(addon.at("installTelemetryInfo").at("source"));
        let from_amo = source_uri.to_ascii_lowercase().contains("addons.mozilla.org") || install_source == "amo";
        let hidden = addon.at("hidden") == &Value::Bool(true);
        let source = firefox_source(
            &text(addon.at("location")),
            hidden,
            install_source == "enterprise-policy",
            signed,
            from_amo,
        );

        let permissions: BTreeSet<String> = strings(addon.at("userPermissions").at("permissions"))
            .into_iter()
            .collect();
        let hosts: BTreeSet<String> = strings(addon.at("userPermissions").at("origins")).into_iter().collect();
        let user_off = addon.at("userDisabled") == &Value::Bool(true);
        let app_off = addon.at("appDisabled") == &Value::Bool(true);
        let soft_off = addon.at("softDisabled") == &Value::Bool(true);
        let blocked = as_integral(addon.at("blocklistState")).is_some_and(|n| n > 0);
        let mut disable_reasons = Vec::new();
        if user_off {
            disable_reasons.push("user".to_string());
        }
        if app_off {
            disable_reasons.push(if signed { "incompatible" } else { "not_verified" }.to_string());
        }
        if soft_off || blocked {
            disable_reasons.push("flagged".to_string());
        }
        let active = addon.at("active") != &Value::Bool(false);

        let mut flags = source_flags(source, &source_uri);
        flags.extend(permission_flags(&permissions, &hosts));
        if !signed && source != "component" {
            flags.push("not_signed".into());
        }
        if soft_off || blocked {
            flags.insert(0, "store_flagged".into());
        }
        let path = text(addon.at("path"));
        out.push(Extension {
            key: format!("Firefox|{account}|{folder}|{id}"),
            browser: "Firefox".into(),
            profile: profile.to_string(),
            profile_dir: folder.to_string(),
            account: account.to_string(),
            name: if name.trim().is_empty() { id.clone() } else { name },
            id,
            version: text(addon.at("version")),
            description: crate::lenient::take(&text(locale.at("description")), 300).to_string(),
            enabled: active && !user_off && !app_off && !soft_off,
            disable_reasons,
            installed_ms: as_integral(addon.at("installDate")).unwrap_or(0).max(0),
            source: source.to_string(),
            update_url: source_uri,
            manifest_version: as_integral(addon.at("manifestVersion")).map_or(0, |n| n.clamp(0, 9) as u32),
            permissions: permissions.into_iter().collect(),
            hosts: hosts.into_iter().take(MAX_HOSTS).collect(),
            flags,
            path_exists: !path.is_empty() && Path::new(&path).exists(),
            path,
            icon: String::new(),
            component: source == "component",
        });
    }
    out
}

// --------------------------------------------------------------------------- policies

/// How a policy is shown and whether Vigil may remove it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Class {
    pub kind: &'static str,
    pub flagged: bool,
    pub removable: bool,
    pub extension_ids: Vec<String>,
    pub store: bool,
}

impl Class {
    fn of(kind: &'static str, flagged: bool, removable: bool) -> Class {
        Class {
            kind,
            flagged,
            removable,
            ..Class::default()
        }
    }
}

/// Extensions an ExtensionSettings policy installs (`installation_mode` force_installed or
/// normal_installed), by id.
pub fn installed_by_settings(data: &str) -> Vec<String> {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(data) else {
        return Vec::new();
    };
    map.iter()
        .filter(|(id, _)| id.as_str() != "*")
        .filter(|(_, cfg)| {
            matches!(
                cfg.at("installation_mode").as_str(),
                Some("force_installed" | "normal_installed")
            )
        })
        .map(|(id, _)| id.clone())
        .collect()
}

fn numeric(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// A Chrome, Edge or Brave policy, by its key below the browser's policy key (`""`,
/// `ExtensionInstallForcelist`, `Recommended`...), value name and data.
pub fn classify_chromium(rel: &str, value: &str, data: &str, number: Option<u64>) -> Class {
    let rel = rel.to_ascii_lowercase();
    let rel = rel
        .strip_prefix("recommended\\")
        .unwrap_or(if rel == "recommended" { "" } else { &rel });
    let name = value.to_ascii_lowercase();
    if numeric(value) {
        return match rel {
            "extensioninstallforcelist" => {
                let (id, url) = data.split_once(';').unwrap_or((data, ""));
                Class {
                    extension_ids: vec![id.trim().to_string()],
                    store: url.trim().is_empty() || store_update(url),
                    ..Class::of("force_install", true, true)
                }
            }
            "extensioninstallsources" => Class::of("install_sources", true, true),
            "extensioninstallallowlist" | "extensioninstallwhitelist" => Class::of("allow", false, false),
            "extensioninstallblocklist" | "extensioninstallblacklist" => Class::of("block", false, false),
            "restoreonstartupurls" => Class::of("startup", true, true),
            _ => Class::of("other", false, false),
        };
    }
    if !rel.is_empty() {
        return Class::of("other", false, false);
    }
    match name.as_str() {
        "extensionsettings" => {
            let ids = installed_by_settings(data);
            Class {
                flagged: !ids.is_empty(),
                removable: !ids.is_empty(),
                extension_ids: ids,
                ..Class::of("extension_settings", false, false)
            }
        }
        "defaultsearchproviderenabled" => Class::of("search", false, true),
        n if n.starts_with("defaultsearchprovider") => Class::of("search", true, true),
        "homepagelocation" => Class::of("homepage", true, true),
        "homepageisnewtabpage" => Class::of("homepage", false, true),
        "restoreonstartup" => Class::of("startup", number == Some(4), true),
        "newtabpagelocation" => Class::of("new_tab", true, true),
        "proxysettings" => {
            let lower = data.to_ascii_lowercase();
            Class::of(
                "proxy",
                lower.contains("fixed_servers") || lower.contains("pac_script"),
                true,
            )
        }
        "proxymode" => Class::of(
            "proxy",
            !matches!(
                data.trim().to_ascii_lowercase().as_str(),
                "direct" | "system" | "auto_detect"
            ),
            true,
        ),
        "proxyserver" | "proxypacurl" | "proxybypasslist" => Class::of("proxy", !data.trim().is_empty(), true),
        "proxyservermode" => Class::of("proxy", number == Some(2), true),
        "developertoolsavailability" => {
            let off = number == Some(2);
            Class::of("devtools", off, off)
        }
        "safebrowsingenabled" | "safebrowsingprotectionlevel" | "smartscreenenabled" | "smartscreenpuaenabled" => {
            let off = number == Some(0);
            Class::of("safe_browsing", off, off)
        }
        _ => Class::of("other", false, false),
    }
}

/// A Firefox policy in the registry, by its key below `Mozilla\Firefox`, value name and data.
pub fn classify_firefox(rel: &str, value: &str, data: &str, number: Option<u64>) -> Class {
    let rel = rel.to_ascii_lowercase();
    let name = value.to_ascii_lowercase();
    match (rel.as_str(), name.as_str()) {
        ("extensions\\install", _) if numeric(value) => Class {
            store: data.to_ascii_lowercase().contains("addons.mozilla.org"),
            ..Class::of("force_install", true, true)
        },
        ("extensions\\locked", _) if numeric(value) => Class {
            extension_ids: vec![data.trim().to_string()],
            ..Class::of("force_install", true, true)
        },
        ("", "extensionsettings") => {
            let ids = installed_by_settings(data);
            Class {
                flagged: !ids.is_empty(),
                removable: !ids.is_empty(),
                extension_ids: ids,
                ..Class::of("extension_settings", false, false)
            }
        }
        ("homepage", "url") => Class::of("homepage", true, true),
        ("homepage", "startpage" | "locked") => Class::of("homepage", false, true),
        ("homepage\\additional", _) if numeric(value) => Class::of("startup", true, true),
        ("searchengines", "default") => Class::of("search", true, true),
        (r, _) if r.starts_with("searchengines\\add") => Class::of("search", true, false),
        ("proxy", "mode") => Class::of(
            "proxy",
            !matches!(
                data.trim().to_ascii_lowercase().as_str(),
                "none" | "system" | "autodetect"
            ),
            true,
        ),
        ("proxy", "locked") => Class::of("proxy", false, true),
        ("proxy", _) => Class::of("proxy", !data.trim().is_empty(), true),
        ("", "disabledevelopertools") => {
            let off = number == Some(1);
            Class::of("devtools", off, off)
        }
        _ => Class::of("other", false, false),
    }
}

/// The policy's name as the browsers document it ("ExtensionInstallForcelist", "Homepage.URL").
fn policy_name(rel: &str, value: &str) -> String {
    let rel = if rel.eq_ignore_ascii_case("recommended") {
        ""
    } else if rel
        .get(..12)
        .is_some_and(|head| head.eq_ignore_ascii_case("recommended\\"))
    {
        rel.get(12..).unwrap_or("")
    } else {
        rel
    };
    let dotted = rel.replace('\\', ".");
    if numeric(value) && !dotted.is_empty() {
        dotted
    } else if dotted.is_empty() {
        value.to_string()
    } else {
        format!("{dotted}.{value}")
    }
}

fn clip(text: &str) -> String {
    crate::lenient::take(text, MAX_DATA).to_string()
}

/// Registry data as text.
fn data_text(data: &RegData) -> (String, Option<u64>) {
    match data {
        RegData::Int(n) => (n.to_string(), Some(*n)),
        RegData::Multi(items) => (items.join("; "), None),
        other => (other.as_text(), None),
    }
}

/// Every value below a key, with its path below `base` ("" for the key itself), at most 3 levels down.
fn walk(hive: Hive, key: &str, rel: &str, depth: usize, out: &mut Vec<(String, String, RegData)>) {
    for (name, data) in winreg::values(hive, key, View::V64) {
        if out.len() >= MAX_POLICY_VALUES {
            return;
        }
        if name.is_empty() && data == RegData::None {
            continue;
        }
        out.push((rel.to_string(), name, data));
    }
    if depth >= 3 {
        return;
    }
    for sub in winreg::subkeys(hive, key, View::V64) {
        let child_rel = if rel.is_empty() {
            sub.clone()
        } else {
            format!(r"{rel}\{sub}")
        };
        walk(hive, &format!(r"{key}\{sub}"), &child_rel, depth + 1, out);
    }
}

/// The browsers' policies: registry values under each root, then Firefox's policies.json files.
pub fn read_policies(roots: &[PolicyRoot], firefox_dirs: &[PathBuf]) -> Vec<Policy> {
    let mut out = Vec::new();
    for root in roots {
        for (browser, vendor) in POLICY_VENDORS {
            let base = format!(r"{}\{vendor}", root.key);
            let mut values = Vec::new();
            walk(root.hive(), &base, "", 0, &mut values);
            for (rel, value, data) in values {
                let (shown, number) = data_text(&data);
                let class = if browser == "Firefox" {
                    classify_firefox(&rel, &value, &shown, number)
                } else {
                    classify_chromium(&rel, &value, &shown, number)
                };
                let key = if rel.is_empty() {
                    format!(r"{}\{vendor}", root.path())
                } else {
                    format!(r"{}\{vendor}\{rel}", root.path())
                };
                out.push(Policy {
                    id: format!("{key}|{value}"),
                    key,
                    name: policy_name(&rel, &value),
                    value,
                    browser: browser.to_string(),
                    scope: if root.machine { "machine" } else { "user" }.to_string(),
                    data: clip(&shown),
                    kind: class.kind.to_string(),
                    flagged: class.flagged,
                    extension_ids: class.extension_ids,
                    store: class.store,
                    removable: class.removable,
                });
            }
        }
    }
    for dir in firefox_dirs {
        out.extend(firefox_file_policies(&dir.join(r"distribution\policies.json")));
    }
    out
}

/// Firefox's policies.json. Shown only: Vigil does not edit this file (it sits in Program Files,
/// and a mistake there stops Firefox from starting).
pub fn firefox_file_policies(path: &Path) -> Vec<Policy> {
    let file = path.to_string_lossy().into_owned();
    let Some(root) = read_json(&file, 4 * 1024 * 1024) else {
        return Vec::new();
    };
    let Some(policies) = root.at("policies").as_object() else {
        return Vec::new();
    };
    let compact = |value: &Value| match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let mut out = Vec::new();
    let mut add = |where_: String, name: &str, data: &Value, class: Class| {
        out.push(Policy {
            id: format!("{file}|{where_}"),
            key: file.clone(),
            value: where_,
            browser: "Firefox".into(),
            scope: "file".into(),
            name: name.to_string(),
            data: clip(&compact(data)),
            kind: class.kind.to_string(),
            flagged: class.flagged,
            extension_ids: class.extension_ids,
            store: class.store,
            removable: false,
        });
    };
    for (name, value) in policies {
        match name.as_str() {
            "Extensions" => {
                for (part, ids) in [("Install", false), ("Locked", true)] {
                    for (i, item) in list(value.at(part)).iter().enumerate() {
                        let item_text = compact(item);
                        let class = Class {
                            extension_ids: if ids { vec![item_text.clone()] } else { Vec::new() },
                            store: !ids && item_text.to_ascii_lowercase().contains("addons.mozilla.org"),
                            ..Class::of("force_install", true, false)
                        };
                        add(
                            format!("Extensions.{part}[{i}]"),
                            &format!("Extensions.{part}"),
                            item,
                            class,
                        );
                    }
                }
                if value.at("Uninstall").is_array() {
                    add(
                        "Extensions.Uninstall".into(),
                        "Extensions.Uninstall",
                        value.at("Uninstall"),
                        Class::of("other", false, false),
                    );
                }
            }
            "ExtensionSettings" => {
                let ids = installed_by_settings(&value.to_string());
                let class = Class {
                    flagged: !ids.is_empty(),
                    extension_ids: ids,
                    ..Class::of("extension_settings", false, false)
                };
                add(name.clone(), name, value, class);
            }
            "Homepage" => {
                if !value.at("URL").is_null() {
                    add(
                        "Homepage.URL".into(),
                        "Homepage.URL",
                        value.at("URL"),
                        Class::of("homepage", true, false),
                    );
                }
                for (i, item) in list(value.at("Additional")).iter().enumerate() {
                    add(
                        format!("Homepage.Additional[{i}]"),
                        "Homepage.Additional",
                        item,
                        Class::of("startup", true, false),
                    );
                }
                if !value.at("StartPage").is_null() {
                    add(
                        "Homepage.StartPage".into(),
                        "Homepage.StartPage",
                        value.at("StartPage"),
                        Class::of("homepage", false, false),
                    );
                }
            }
            "SearchEngines" => {
                if !value.at("Default").is_null() {
                    add(
                        "SearchEngines.Default".into(),
                        "SearchEngines.Default",
                        value.at("Default"),
                        Class::of("search", true, false),
                    );
                }
                for (i, item) in list(value.at("Add")).iter().enumerate() {
                    add(
                        format!("SearchEngines.Add[{i}]"),
                        "SearchEngines.Add",
                        item,
                        Class::of("search", true, false),
                    );
                }
            }
            "Proxy" => {
                let mode = text(value.at("Mode")).to_ascii_lowercase();
                let flagged = !matches!(mode.as_str(), "" | "none" | "system" | "autodetect")
                    || !value.at("HTTPProxy").is_null()
                    || !value.at("AutoConfigURL").is_null();
                add(name.clone(), name, value, Class::of("proxy", flagged, false));
            }
            "DisableDeveloperTools" => {
                let off = value == &Value::Bool(true);
                add(name.clone(), name, value, Class::of("devtools", off, false));
            }
            _ => add(name.clone(), name, value, Class::of("other", false, false)),
        }
    }
    out
}

// --------------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A folder in %TEMP%, deleted when dropped.
    struct Temp(PathBuf);

    impl Temp {
        fn new(name: &str) -> Temp {
            let path = std::env::temp_dir().join(format!("vigil-browsers-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("temp folder");
            Temp(path)
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().expect("parent")).expect("folder");
        fs::write(path, text).expect("file");
    }

    const NOTES: &str = "aaaabbbbccccddddeeeeffffgggghhhh";
    const COUPONS: &str = "ppppoooonnnnmmmmllllkkkkjjjjiiii";
    const DEV: &str = "abcdefghijklmnopabcdefghijklmnop";
    const DOCS: &str = "ghbmnnjooekpmoecnnnilnnbdlolhkhi";

    /// One account with Chrome (two profiles), Opera and Firefox.
    fn fake_home(base: &Path) -> Home {
        let local = base.join("Local");
        let roaming = base.join("Roaming");
        let chrome = local.join(r"Google\Chrome\User Data");
        write(
            &chrome.join("Local State"),
            r#"{"profile":{"info_cache":{"Default":{"name":"Person 1"},"Profile 1":{"name":"Work"}}}}"#,
        );
        let default = chrome.join("Default");
        // Contoso Notes: from the store, localized name, an icon, every site.
        let notes = default.join(format!(r"Extensions\{NOTES}"));
        write(
            &notes.join(r"1.9.0_0\manifest.json"),
            r#"{"name":"old","version":"1.9.0","manifest_version":3}"#,
        );
        write(
            &notes.join(r"1.10.0_0\manifest.json"),
            r#"{"name":"__MSG_appName__","description":"__MSG_appDesc__","version":"1.10.0","manifest_version":3,
                "default_locale":"en","permissions":["storage","tabs","history"],"host_permissions":["<all_urls>"],
                "icons":{"16":"img/16.png","48":"img/48.png","128":"img/128.png"},
                "update_url":"https://clients2.google.com/service/update2/crx"}"#,
        );
        write(
            &notes.join(r"1.10.0_0\_locales\en\messages.json"),
            r#"{"appName":{"message":"Contoso Notes"},"appDesc":{"message":"Takes notes."}}"#,
        );
        write(&notes.join(r"1.10.0_0\img\48.png"), "png");
        // Fabrikam Coupons: an old (MV2) extension added outside the store, web requests, turned off by the browser.
        let coupons = default.join(format!(r"Extensions\{COUPONS}\2.0.1_0"));
        write(
            &coupons.join("manifest.json"),
            r#"{"name":"Fabrikam Coupons","version":"2.0.1","manifest_version":2,
                "permissions":["webRequest","webRequestBlocking","*://*/*","cookies","nativeMessaging"],
                "update_url":"https://updates.fabrikam.example/crx"}"#,
        );
        let dev_dir = base.join("unpacked-dev");
        write(
            &dev_dir.join("manifest.json"),
            r#"{"name":"Dev Helper","version":"0.1","manifest_version":3,"permissions":["debugger"]}"#,
        );
        let prefs = format!(
            r#"{{"extensions":{{"settings":{{
                "{NOTES}":{{"location":1,"from_webstore":true,"state":1,"install_time":"13350000000000000"}},
                "{COUPONS}":{{"location":3,"disable_reasons":[1,128],"first_install_time":"13360000000000000"}},
                "{DEV}":{{"location":4,"path":{path},"disable_reasons":0}},
                "{DOCS}":{{"location":10,"manifest":{{"name":"Docs","version":"1"}}}}
            }}}}}}"#,
            path = serde_json::to_string(&dev_dir.to_string_lossy()).expect("json")
        );
        write(&default.join("Preferences"), &prefs);
        // Secure Preferences adds the store's verdict on the coupons extension.
        write(
            &default.join("Secure Preferences"),
            &format!(r#"{{"extensions":{{"settings":{{"{COUPONS}":{{"blacklist_state":4}}}}}}}}"#),
        );
        // Profile 1: forced by policy; a guest profile is ignored.
        let work = chrome.join("Profile 1");
        write(
            &work.join(format!(r"Extensions\{NOTES}\1.0_0\manifest.json")),
            r#"{"name":"Contoso Notes","version":"1.0","manifest_version":3}"#,
        );
        write(
            &work.join("Preferences"),
            &format!(r#"{{"extensions":{{"settings":{{"{NOTES}":{{"location":1,"from_webstore":true}}}}}}}}"#),
        );
        write(&chrome.join(r"Guest Profile\Preferences"), "{}");
        // Opera: its only profile is the user data folder.
        let opera = roaming.join(r"Opera Software\Opera Stable");
        write(
            &opera.join(format!(r"Extensions\{NOTES}\3_0\manifest.json")),
            r#"{"name":"Contoso Notes","version":"3","manifest_version":3}"#,
        );
        write(
            &opera.join("Preferences"),
            &format!(r#"{{"extensions":{{"settings":{{"{NOTES}":{{"location":1,"from_webstore":false}}}}}}}}"#),
        );
        // Firefox: one profile listed in profiles.ini.
        let firefox = roaming.join(r"Mozilla\Firefox");
        write(
            &firefox.join("profiles.ini"),
            "[General]\nStartWithLastProfile=1\n\n[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/abcd1234.default-release\nDefault=1\n",
        );
        let profile = firefox.join(r"Profiles\abcd1234.default-release");
        write(
            &profile.join("extensions.json"),
            r#"{"addons":[
                {"id":"notes@contoso.example","type":"extension","location":"app-profile","active":true,"userDisabled":false,
                 "signedState":2,"sourceURI":"https://addons.mozilla.org/firefox/downloads/file/1/notes.xpi","installDate":1767225600000,
                 "version":"4.0","defaultLocale":{"name":"Contoso Notes","description":"Notes."},
                 "userPermissions":{"permissions":["storage"],"origins":["<all_urls>"]},"path":"C:\\nowhere\\notes.xpi"},
                {"id":"helper@fabrikam.example","type":"extension","location":"winreg-app-global","active":false,"userDisabled":false,
                 "appDisabled":true,"signedState":0,"version":"1.0","defaultLocale":{"name":"Fabrikam Helper"},
                 "userPermissions":{"permissions":["proxy","management"],"origins":[]}},
                {"id":"forced@northwind.example","type":"extension","location":"app-profile","active":true,"signedState":2,
                 "installTelemetryInfo":{"source":"enterprise-policy"},"version":"2.0","defaultLocale":{"name":"Northwind Agent"}},
                {"id":"screenshots@mozilla.org","type":"extension","location":"app-builtin","active":true,"signedState":3,"hidden":true,
                 "defaultLocale":{"name":"Screenshots"}},
                {"id":"theme@contoso.example","type":"theme","location":"app-profile"}
            ]}"#,
        );
        Home {
            local,
            roaming,
            account: String::new(),
        }
    }

    fn find<'a>(data: &'a BrowserData, browser: &str, profile_dir: &str, id: &str) -> &'a Extension {
        data.extensions
            .iter()
            .find(|e| e.browser == browser && e.profile_dir == profile_dir && e.id == id)
            .unwrap_or_else(|| panic!("{browser} {profile_dir} {id}"))
    }

    fn has(ext: &Extension, flag: &str) -> bool {
        ext.flags.iter().any(|f| f == flag)
    }

    #[test]
    fn chromium_and_firefox_profiles_are_read() {
        let temp = Temp::new("profiles");
        let home = fake_home(&temp.0);
        let data = read(&Sources {
            homes: vec![home],
            policy_roots: Vec::new(),
            firefox_dirs: Vec::new(),
        });
        assert!(!data.other_accounts);
        let names: Vec<(&str, usize, usize)> = data
            .browsers
            .iter()
            .map(|b| (b.name.as_str(), b.profiles, b.extensions))
            .collect();
        assert_eq!(names, [("Chrome", 2, 4), ("Firefox", 1, 3), ("Opera", 1, 1)]);

        let notes = find(&data, "Chrome", "Default", NOTES);
        assert_eq!(notes.name, "Contoso Notes", "__MSG_ names come from _locales");
        assert_eq!(notes.description, "Takes notes.");
        assert_eq!(notes.version, "1.10.0", "the newest version folder (1.10 after 1.9)");
        assert_eq!(notes.profile, "Person 1");
        assert_eq!(notes.key, format!("Chrome||Default|{NOTES}"));
        assert_eq!(notes.source, "store");
        assert!(notes.enabled && notes.disable_reasons.is_empty());
        assert_eq!(notes.installed_ms, 13_350_000_000_000 - 11_644_473_600_000);
        assert!(notes.icon.ends_with(r"img\48.png"), "{}", notes.icon);
        assert_eq!(notes.flags, ["all_sites", "history", "tabs"]);
        assert!(notes.path_exists && notes.path.ends_with("1.10.0_0"));

        let coupons = find(&data, "Chrome", "Default", COUPONS);
        assert_eq!(coupons.source, "external");
        assert!(!coupons.enabled);
        assert_eq!(coupons.disable_reasons, ["user", "flagged"]);
        assert_eq!(coupons.manifest_version, 2);
        for flag in [
            "store_flagged",
            "external",
            "outside_store",
            "all_sites",
            "cookies",
            "web_request",
            "native",
            "mv2",
        ] {
            assert!(has(coupons, flag), "{flag}: {:?}", coupons.flags);
        }
        assert!(coupons.hosts.contains(&"*://*/*".to_string()));
        assert!(!coupons.permissions.iter().any(|p| p.contains("://")));

        let dev = find(&data, "Chrome", "Default", DEV);
        assert_eq!(dev.source, "unpacked");
        assert!(has(dev, "unpacked") && has(dev, "debugger"));
        assert!(dev.path.ends_with("unpacked-dev"));

        let docs = find(&data, "Chrome", "Default", DOCS);
        assert!(docs.component && docs.source == "component");

        let work = find(&data, "Chrome", "Profile 1", NOTES);
        assert_eq!((work.profile.as_str(), work.version.as_str()), ("Work", "1.0"));
        assert!(!data.extensions.iter().any(|e| e.profile_dir == "Guest Profile"));

        let opera = find(&data, "Opera", "Opera Stable", NOTES);
        assert_eq!(opera.profile, "Default");
        assert_eq!(
            opera.source, "outside_store",
            "an Opera install without the store's mark"
        );

        let ff_notes = find(&data, "Firefox", "abcd1234.default-release", "notes@contoso.example");
        assert_eq!(ff_notes.profile, "default-release");
        assert_eq!(ff_notes.source, "store");
        assert_eq!(ff_notes.installed_ms, 1_767_225_600_000);
        assert_eq!(ff_notes.flags, ["all_sites"]);
        assert!(!ff_notes.path_exists);
        let helper = find(&data, "Firefox", "abcd1234.default-release", "helper@fabrikam.example");
        assert_eq!(helper.source, "external");
        assert!(!helper.enabled);
        assert_eq!(helper.disable_reasons, ["not_verified"]);
        for flag in ["external", "proxy", "management", "not_signed"] {
            assert!(has(helper, flag), "{flag}: {:?}", helper.flags);
        }
        let agent = find(&data, "Firefox", "abcd1234.default-release", "forced@northwind.example");
        assert_eq!(agent.source, "policy");
        assert!(has(agent, "policy"));
        assert!(find(&data, "Firefox", "abcd1234.default-release", "screenshots@mozilla.org").component);
        assert!(
            !data.extensions.iter().any(|e| e.id == "theme@contoso.example"),
            "themes are not extensions"
        );
    }

    #[test]
    fn other_accounts_get_their_own_keys() {
        let temp = Temp::new("accounts");
        let mut home = fake_home(&temp.0);
        home.account = "jdoe".into();
        let data = read(&Sources {
            homes: vec![home],
            ..Sources::default()
        });
        assert!(data.other_accounts);
        let notes = find(&data, "Chrome", "Default", NOTES);
        assert_eq!(notes.account, "jdoe");
        assert_eq!(notes.key, format!("Chrome|jdoe|Default|{NOTES}"));
    }

    #[test]
    fn disable_reasons_and_sources_are_named() {
        assert_eq!(chromium_disable_reasons(0), Vec::<String>::new());
        assert_eq!(chromium_disable_reasons(1 | 64), ["user", "not_verified"]);
        assert_eq!(chromium_disable_reasons(1 << 14 | 1 << 3), ["policy", "other"]);
        assert_eq!(chromium_disable_reasons(1 << 19), ["unsupported_manifest"]);
        assert_eq!(chromium_disable_mask(&serde_json::json!([1, 128])), 129);
        assert_eq!(chromium_disable_mask(&serde_json::json!(6)), 6);
        assert_eq!(
            chromium_source(Some(1), false, "https://clients2.google.com/service/update2/crx"),
            "store"
        );
        assert_eq!(
            chromium_source(
                Some(1),
                false,
                "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
            ),
            "store"
        );
        assert_eq!(chromium_source(Some(1), false, ""), "outside_store");
        assert_eq!(chromium_source(Some(9), true, ""), "policy");
        assert_eq!(chromium_source(Some(8), false, ""), "unpacked");
        assert_eq!(chromium_source(None, false, ""), "unknown");
        assert_eq!(firefox_source("app-profile", false, false, true, true), "store");
        assert_eq!(
            firefox_source("app-profile", false, false, true, false),
            "outside_store"
        );
        assert_eq!(firefox_source("app-temporary", false, false, false, false), "unpacked");
        assert_eq!(
            firefox_source("app-system-share", false, false, true, false),
            "external"
        );
        assert_eq!(firefox_source("app-builtin", false, false, true, false), "component");
        assert!(all_sites("<all_urls>") && all_sites("*://*/*") && all_sites("https://*/"));
        assert!(!all_sites("https://*.contoso.example/*") && !all_sites("file:///*"));
        assert_eq!(version_key("1.10.2_0"), [1, 10, 2, 0]);
        assert!(chrome_id(NOTES) && !chrome_id("zzzzbbbbccccddddeeeeffffgggghhhh") && !chrome_id("abc"));
        assert_eq!(expand_env("%VIGIL_TEST_NOT_SET%\\x"), "%VIGIL_TEST_NOT_SET%\\x");
    }

    #[test]
    fn chromium_policies_are_classified() {
        let force = classify_chromium(
            "ExtensionInstallForcelist",
            "1",
            &format!("{COUPONS};https://updates.fabrikam.example/crx"),
            None,
        );
        assert_eq!(
            (force.kind, force.flagged, force.removable, force.store),
            ("force_install", true, true, false)
        );
        assert_eq!(force.extension_ids, [COUPONS]);
        let store = classify_chromium("ExtensionInstallForcelist", "2", NOTES, None);
        assert!(store.store, "no update address means the store");
        assert_eq!(
            classify_chromium("Recommended", "HomepageLocation", "https://contoso.example", None).kind,
            "homepage"
        );
        assert!(
            classify_chromium(
                "",
                "DefaultSearchProviderSearchURL",
                "https://search.example/?q={searchTerms}",
                None
            )
            .flagged
        );
        let enabled = classify_chromium("", "DefaultSearchProviderEnabled", "1", Some(1));
        assert!(!enabled.flagged && enabled.removable);
        assert!(classify_chromium("", "RestoreOnStartup", "4", Some(4)).flagged);
        assert!(!classify_chromium("", "RestoreOnStartup", "1", Some(1)).flagged);
        assert!(classify_chromium("RestoreOnStartupURLs", "1", "https://start.example", None).flagged);
        assert!(classify_chromium("", "ProxyMode", "fixed_servers", None).flagged);
        assert!(!classify_chromium("", "ProxyMode", "system", None).flagged);
        // Weakening values only: a policy that keeps protection on is neither flagged nor removable.
        let sb_off = classify_chromium("", "SafeBrowsingEnabled", "0", Some(0));
        assert!(sb_off.flagged && sb_off.removable && sb_off.kind == "safe_browsing");
        let sb_on = classify_chromium("", "SafeBrowsingEnabled", "1", Some(1));
        assert!(!sb_on.flagged && !sb_on.removable);
        assert!(classify_chromium("", "SmartScreenEnabled", "0", Some(0)).removable);
        assert!(classify_chromium("", "DeveloperToolsAvailability", "2", Some(2)).removable);
        assert!(!classify_chromium("", "DeveloperToolsAvailability", "1", Some(1)).removable);
        let settings = classify_chromium(
            "",
            "ExtensionSettings",
            &format!(
                r#"{{"*":{{"installation_mode":"blocked"}},"{COUPONS}":{{"installation_mode":"force_installed","update_url":"x"}}}}"#
            ),
            None,
        );
        assert!(settings.flagged && settings.removable);
        assert_eq!(settings.extension_ids, [COUPONS]);
        let blocks_only = classify_chromium(
            "",
            "ExtensionSettings",
            r#"{"*":{"installation_mode":"blocked"}}"#,
            None,
        );
        assert!(!blocks_only.flagged && !blocks_only.removable);
        let allow = classify_chromium("ExtensionInstallAllowlist", "1", NOTES, None);
        assert!(!allow.flagged && !allow.removable);
        assert_eq!(
            classify_chromium("", "PasswordManagerEnabled", "0", Some(0)),
            Class::of("other", false, false)
        );
        assert_eq!(
            policy_name("Recommended\\RestoreOnStartupURLs", "1"),
            "RestoreOnStartupURLs"
        );
        assert_eq!(policy_name("", "HomepageLocation"), "HomepageLocation");
        assert_eq!(policy_name("Homepage", "URL"), "Homepage.URL");
    }

    #[test]
    fn firefox_policies_are_classified() {
        let install = classify_firefox("Extensions\\Install", "1", "https://addons.mozilla.org/x.xpi", None);
        assert!(install.flagged && install.removable && install.store);
        let locked = classify_firefox("Extensions\\Locked", "1", "helper@fabrikam.example", None);
        assert_eq!(locked.extension_ids, ["helper@fabrikam.example"]);
        assert!(classify_firefox("Homepage", "URL", "https://contoso.example", None).flagged);
        assert!(classify_firefox("SearchEngines", "Default", "Fabrikam Search", None).removable);
        let added = classify_firefox(
            "SearchEngines\\Add\\1",
            "URLTemplate",
            "https://search.example/?q={searchTerms}",
            None,
        );
        assert!(added.flagged && !added.removable);
        assert!(!classify_firefox("Proxy", "Mode", "system", None).flagged);
        assert!(classify_firefox("Proxy", "HTTPProxy", "203.0.113.5:8080", None).flagged);
        assert!(classify_firefox("", "DisableDeveloperTools", "1", Some(1)).removable);
        assert!(!classify_firefox("", "DisableDeveloperTools", "0", Some(0)).removable);
        assert_eq!(classify_firefox("", "DisableTelemetry", "1", Some(1)).kind, "other");
    }

    #[test]
    fn policies_json_is_shown_but_never_removable() {
        let temp = Temp::new("policiesjson");
        let dir = temp.0.join("Mozilla Firefox");
        write(
            &dir.join(r"distribution\policies.json"),
            r#"{"policies":{
                "Extensions":{"Install":["https://addons.mozilla.org/notes.xpi","C:\\Users\\jdoe\\helper.xpi"],"Locked":["helper@fabrikam.example"]},
                "Homepage":{"URL":"https://start.fabrikam.example","Additional":["https://news.example"],"StartPage":"homepage"},
                "SearchEngines":{"Default":"Fabrikam Search","Add":[{"Name":"Fabrikam Search","URLTemplate":"https://search.example/?q={searchTerms}"}]},
                "Proxy":{"Mode":"manual","HTTPProxy":"203.0.113.5:8080"},
                "DisableDeveloperTools":true,
                "DisableTelemetry":true
            }}"#,
        );
        let found = read_policies(&[], &[dir]);
        assert!(
            found
                .iter()
                .all(|p| p.scope == "file" && !p.removable && p.browser == "Firefox")
        );
        let by = |value: &str| {
            found
                .iter()
                .find(|p| p.value == value)
                .unwrap_or_else(|| panic!("{value}"))
        };
        assert!(by("Extensions.Install[0]").store && by("Extensions.Install[0]").flagged);
        assert!(!by("Extensions.Install[1]").store);
        assert_eq!(by("Extensions.Locked[0]").extension_ids, ["helper@fabrikam.example"]);
        assert!(
            by("Homepage.URL").flagged && by("Homepage.Additional[0]").flagged && !by("Homepage.StartPage").flagged
        );
        assert!(by("SearchEngines.Default").flagged && by("SearchEngines.Add[0]").flagged);
        assert!(by("Proxy").flagged && by("DisableDeveloperTools").flagged);
        assert_eq!(by("DisableTelemetry").kind, "other");
        assert!(read_policies(&[], &[temp.0.join("missing")]).is_empty());
    }

    #[test]
    fn forced_extensions_are_marked_for_their_browser_only() {
        let mut list = vec![
            Extension {
                browser: "Chrome".into(),
                id: COUPONS.into(),
                flags: vec!["all_sites".into()],
                ..Extension::default()
            },
            Extension {
                browser: "Edge".into(),
                id: COUPONS.into(),
                ..Extension::default()
            },
        ];
        let policy = Policy {
            browser: "Chrome".into(),
            kind: "force_install".into(),
            extension_ids: vec![COUPONS.to_uppercase()],
            ..Policy::default()
        };
        mark_forced(&mut list, &[policy]);
        assert_eq!(list[0].flags, ["policy", "all_sites"]);
        assert!(list[1].flags.is_empty());
    }

    /// Preferences, manifests, locale messages, Firefox's extensions.json and policies.json are
    /// written by the browser, its extensions or anything running as the user: any content, even
    /// broken JSON, deep nesting or huge numbers, must be read or skipped without a panic.
    #[test]
    fn hostile_profile_files_never_break_the_reader() {
        use crate::fuzz::{Rng, check_text};
        let mut rng = Rng::new(28);
        let temp = Temp::new("fuzz");
        let tokens = &[
            "{",
            "}",
            "[",
            "]",
            "\"",
            ":",
            ",",
            "null",
            "1e999",
            "-1",
            "18446744073709551616",
            "\"extensions\"",
            "\"settings\"",
            "\"manifest\"",
            "\"__MSG_name__\"",
            "\"default_locale\"",
            "\"permissions\"",
            "\"<all_urls>\"",
            "\"location\"",
            "\"addons\"",
            "\"id\"",
            "[[[[[[[[",
            "\\u0000",
            "\"..\\\\..\\\\x\"",
        ];
        let prefs = r#"{"extensions":{"settings":{"aaaabbbbccccddddeeeeffffgggghhhh":{"location":1,"state":1,"disable_reasons":[1,2],"install_time":"13300000000000000","manifest":{"name":"__MSG_name__","version":"1.0","permissions":["<all_urls>","tabs"]}}}}}"#;
        let manifest = r#"{"name":"__MSG_name__","default_locale":"en","version":"1.0","manifest_version":2,"permissions":["<all_urls>"],"host_permissions":["*://*/*"],"icons":{"48":"i.png"}}"#;
        let messages = r#"{"name":{"message":"Contoso Notes"}}"#;
        let firefox = r#"{"addons":[{"id":"x@contoso","type":"extension","active":true,"location":"app-profile","defaultLocale":{"name":"Contoso"},"userPermissions":{"permissions":["tabs"],"origins":["<all_urls>"]},"signedState":2,"path":"C:\\x.xpi"}]}"#;
        let policies = r#"{"policies":{"ExtensionSettings":{"*":{"installation_mode":"force_installed","install_url":"https://example.com/x.xpi"}},"Proxy":{"Mode":"manual"}}}"#;
        for case in 0..120 {
            let dir = temp.0.join(format!("p{}", case % 4));
            let ext = dir.join("Extensions").join(NOTES).join("1.0_0");
            let mut pick = |sample: &str| {
                if rng.chance(30) {
                    rng.text(30, tokens)
                } else {
                    rng.mutate_text(sample, tokens)
                }
            };
            let files = [
                (dir.join("Preferences"), pick(prefs)),
                (dir.join("Secure Preferences"), pick(prefs)),
                (ext.join("manifest.json"), pick(manifest)),
                (ext.join("_locales").join("en").join("messages.json"), pick(messages)),
                (dir.join("extensions.json"), pick(firefox)),
                (dir.join("policies.json"), pick(policies)),
            ];
            for (path, text) in &files {
                write(path, text);
            }
            let shown: Vec<&str> = files.iter().map(|(_, text)| text.as_str()).collect();
            check_text("browser profile", &shown.join("\n"), || {
                let _ = chromium_profile("Chrome", &dir, "p", "Default", "jdoe");
                let _ = firefox_profile(&dir, "p", "default-release", "jdoe");
                let _ = firefox_file_policies(&dir.join("policies.json"));
            });
        }
    }
}
