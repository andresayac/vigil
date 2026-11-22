//! Explorer shell extensions: DLLs Explorer (and every program that shows a file dialog) loads to
//! add context-menu entries, icon overlays, property pages, previews and thumbnails, plus the
//! objects Explorer starts with it (Shell Service Objects, SharedTaskScheduler, ShellExecute
//! hooks). READ-ONLY: registry reads, nothing is changed.
//!
//! Each registered handler names a COM class; the class's `InprocServer32` is the DLL that loads.
//! The user's own registration (`HKCU\Software\Classes\CLSID`) wins over the computer's, so it is
//! read first and a user registration that replaces the computer's is noted (`shadowed`).
//!
//! Entries have the shape of the other startup entries (`source` = `shell_extension`,
//! `location`, `name`, `command`, `file`) plus `kind`, `clsid`, `class_name`, `startup` (loaded
//! when Explorer starts, for every user who signs in) and `shadowed`. The analysis judges the DLL
//! like any startup file: Microsoft-signed in the Windows folder is trusted, a signed vendor DLL
//! in its own folder gives no signal (cloud drives, archivers, Git clients, Office and graphics
//! panels all register these), an unsigned DLL or one in a folder users can change is worth a
//! look, and a missing DLL is a leftover.
//!
//! The work is bounded: only the locations below are read, class ids are resolved once, and at
//! most [`MAX_ENTRIES`] handlers are listed.

use std::collections::{HashMap, HashSet};

use serde_json::{Value, json};

use crate::cmdline::normalize_path;
use crate::lenient::{lower, strip};
use crate::ntpath::{SYSTEM32, SYSWOW64, basename, join};
use crate::winreg::{self, Hive, RegData, View};

pub(crate) const SOURCE: &str = "shell_extension";
pub(crate) const SECTION: &str = "shell_extensions";

/// Handlers listed at most; a normal computer has a few hundred.
pub(crate) const MAX_ENTRIES: usize = 2000;
/// Subkeys or values read at most under one registry key.
const MAX_PER_KEY: usize = 500;

/// How a location lists its handlers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// Each subkey is a handler; its default value is the class id (or its name is).
    SubkeyDefault,
    /// Each subkey name is a class id.
    SubkeyNames,
    /// Each value name is a class id (the data is a description).
    ValueNames,
    /// Each value's data is a class id (the name is a description).
    ValueData,
    /// The key's own default value is a class id.
    KeyDefault,
}

/// Explorer loads these when it starts, for every user who signs in.
fn startup_kind(kind: &str) -> bool {
    matches!(
        kind,
        "shell_service_object" | "delay_load" | "shared_task_scheduler" | "execute_hook"
    )
}

/// Where each kind lives: relative to `SOFTWARE\Classes` (`classes`) or to `SOFTWARE`.
struct Place {
    kind: &'static str,
    path: String,
    shape: Shape,
    classes: bool,
}

const CONTEXT_TYPES: &[&str] = &[
    "*",
    "AllFilesystemObjects",
    "Directory",
    "Directory\\Background",
    "DesktopBackground",
    "Folder",
    "Drive",
    "lnkfile",
    "exefile",
];
const PROPERTY_TYPES: &[&str] = &[
    "*",
    "AllFilesystemObjects",
    "Directory",
    "Drive",
    "Folder",
    "lnkfile",
    "exefile",
];
const DRAG_DROP_TYPES: &[&str] = &["Directory", "Directory\\Background", "Drive", "Folder"];
const COPY_HOOK_TYPES: &[&str] = &["Directory", "Printers"];
/// File types whose preview and thumbnail handlers are read (the common ones people open).
const PREVIEW_TYPES: &[&str] = &[
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".md", ".rtf", ".epub", ".jpg", ".jpeg", ".png",
    ".gif", ".webp", ".heic", ".avif", ".svg", ".psd", ".mp3", ".flac", ".mp4", ".mkv", ".avi", ".mov", ".zip", ".7z",
    ".rar", ".stl", ".3mf",
];
const THUMBNAIL_SHELLEX: &str = "{e357fccd-a995-4576-b01f-234630154e96}";
const PREVIEW_SHELLEX: &str = "{8895b1c6-b41f-4c1c-a562-0d564250836f}";
const EXPLORER: &str = r"Microsoft\Windows\CurrentVersion\Explorer";

fn places() -> Vec<Place> {
    let mut out = Vec::new();
    let mut classes = |kind: &'static str, path: String, shape: Shape| {
        out.push(Place {
            kind,
            path,
            shape,
            classes: true,
        });
    };
    for t in CONTEXT_TYPES {
        classes(
            "context_menu",
            format!(r"{t}\shellex\ContextMenuHandlers"),
            Shape::SubkeyDefault,
        );
    }
    for t in PROPERTY_TYPES {
        classes(
            "property_sheet",
            format!(r"{t}\shellex\PropertySheetHandlers"),
            Shape::SubkeyDefault,
        );
    }
    for t in DRAG_DROP_TYPES {
        classes(
            "drag_drop",
            format!(r"{t}\shellex\DragDropHandlers"),
            Shape::SubkeyDefault,
        );
    }
    for t in COPY_HOOK_TYPES {
        classes(
            "copy_hook",
            format!(r"{t}\shellex\CopyHookHandlers"),
            Shape::SubkeyDefault,
        );
    }
    classes(
        "column_handler",
        r"Folder\shellex\ColumnHandlers".into(),
        Shape::SubkeyNames,
    );
    for ext in PREVIEW_TYPES {
        for root in [String::new(), r"SystemFileAssociations\".to_string()] {
            classes(
                "thumbnail_provider",
                format!(r"{root}{ext}\shellex\{THUMBNAIL_SHELLEX}"),
                Shape::KeyDefault,
            );
            classes(
                "preview_handler",
                format!(r"{root}{ext}\shellex\{PREVIEW_SHELLEX}"),
                Shape::KeyDefault,
            );
        }
    }
    let mut software = |kind: &'static str, path: String, shape: Shape| {
        out.push(Place {
            kind,
            path,
            shape,
            classes: false,
        });
    };
    software(
        "icon_overlay",
        format!(r"{EXPLORER}\ShellIconOverlayIdentifiers"),
        Shape::SubkeyDefault,
    );
    software(
        "shell_service_object",
        format!(r"{EXPLORER}\ShellServiceObjects"),
        Shape::SubkeyNames,
    );
    software(
        "delay_load",
        r"Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad".into(),
        Shape::ValueData,
    );
    software(
        "shared_task_scheduler",
        format!(r"{EXPLORER}\SharedTaskScheduler"),
        Shape::ValueNames,
    );
    software(
        "execute_hook",
        format!(r"{EXPLORER}\ShellExecuteHooks"),
        Shape::ValueNames,
    );
    software(
        "preview_handler",
        r"Microsoft\Windows\CurrentVersion\PreviewHandlers".into(),
        Shape::ValueNames,
    );
    software(
        "browser_helper",
        format!(r"{EXPLORER}\Browser Helper Objects"),
        Shape::SubkeyNames,
    );
    out
}

// --------------------------------------------------------------------------- registry access

/// What the collector needs from the registry, so tests can read a snapshot instead.
pub(crate) trait Registry {
    fn subkeys(&self, hive: Hive, key: &str, view: View) -> Vec<String>;
    fn values(&self, hive: Hive, key: &str, view: View) -> Vec<(String, RegData)>;
    fn default_value(&self, hive: Hive, key: &str, view: View) -> String {
        self.values(hive, key, view)
            .into_iter()
            .find(|(name, _)| name.is_empty())
            .map(|(_, data)| strip(&data.as_text()).to_string())
            .unwrap_or_default()
    }
}

struct Live;

impl Registry for Live {
    fn subkeys(&self, hive: Hive, key: &str, view: View) -> Vec<String> {
        winreg::subkeys(hive, key, view)
    }
    fn values(&self, hive: Hive, key: &str, view: View) -> Vec<(String, RegData)> {
        winreg::values(hive, key, view)
    }
}

/// One of the four places handlers are registered: the computer's 64-bit and 32-bit views, and
/// the user's classes (64-bit, and the 32-bit `Wow6432Node` copy).
#[derive(Clone, Copy, Debug)]
struct Scope {
    hive: Hive,
    view: View,
    /// 32-bit COM (WOW6432Node): bare DLL names live in SysWOW64.
    bits32: bool,
}

const SCOPES: [Scope; 4] = [
    Scope {
        hive: Hive::Hklm,
        view: View::V64,
        bits32: false,
    },
    Scope {
        hive: Hive::Hklm,
        view: View::V32,
        bits32: true,
    },
    Scope {
        hive: Hive::Hkcu,
        view: View::V64,
        bits32: false,
    },
    Scope {
        hive: Hive::Hkcu,
        view: View::V64,
        bits32: true,
    },
];

impl Scope {
    /// The classes root this scope reads (`None`: the user's 32-bit scope only has classes).
    fn root(&self, classes: bool) -> Option<String> {
        match (self.hive, self.bits32, classes) {
            (Hive::Hklm, _, true) => Some(r"SOFTWARE\Classes".into()),
            (Hive::Hklm, _, false) => Some("SOFTWARE".into()),
            (Hive::Hkcu, false, true) => Some(r"Software\Classes".into()),
            (Hive::Hkcu, false, false) => Some("Software".into()),
            (Hive::Hkcu, true, true) => Some(r"Software\Classes\Wow6432Node".into()),
            (Hive::Hkcu, true, false) => None,
        }
    }

    fn display(&self, key: &str) -> String {
        winreg::display(self.hive, key, self.view)
    }
}

/// What a class registers, from the user's or the computer's classes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Server {
    name: String,
    /// The InprocServer32 value as written.
    raw: String,
    /// The DLL it loads.
    file: String,
}

/// The DLL an InprocServer32 value loads: quotes and variables removed; a bare name is found in
/// System32 (SysWOW64 for 32-bit classes) like Windows does; a .NET class served by mscoree.dll
/// loads the assembly its CodeBase names.
fn server_file(raw: &str, codebase: &str, bits32: bool) -> String {
    let value = strip(raw).trim_matches('"').trim();
    if value.is_empty() {
        return String::new();
    }
    let mut path = normalize_path(value);
    if !path.contains('\\') {
        path = join(if bits32 { &SYSWOW64 } else { &SYSTEM32 }, &[&path]);
    }
    if lower(basename(&path)) == "mscoree.dll" {
        let code = strip(codebase).trim();
        let low = lower(code);
        if let Some(rest) = low
            .strip_prefix("file:///")
            .map(|_| &code["file:///".len()..])
            .or_else(|| (!low.starts_with("file:") && !code.is_empty()).then_some(code))
        {
            return normalize_path(&rest.replace("%20", " ").replace('/', "\\"));
        }
    }
    path
}

fn read_server(reg: &dyn Registry, hive: Hive, view: View, root: &str, clsid: &str, bits32: bool) -> Option<Server> {
    let key = format!(r"{root}\{clsid}");
    let inproc_key = format!(r"{key}\InprocServer32");
    let values = reg.values(hive, &inproc_key, view);
    let raw = values
        .iter()
        .find(|(n, _)| n.is_empty())
        .map(|(_, d)| strip(&d.as_text()).to_string())
        .unwrap_or_default();
    if raw.is_empty() {
        return None;
    }
    let codebase = values
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("CodeBase"))
        .map(|(_, d)| d.as_text())
        .unwrap_or_default();
    Some(Server {
        name: reg.default_value(hive, &key, view),
        file: server_file(&raw, &codebase, bits32),
        raw,
    })
}

/// A class id in the canonical form, or `None` when the text is not one.
fn clsid(text: &str) -> Option<String> {
    let text = strip(text).trim();
    let ok = text.len() == 38
        && text.starts_with('{')
        && text.ends_with('}')
        && text[1..37].chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    ok.then(|| lower(text))
}

/// The handlers registered at one place of one scope: (handler name, class id, key shown).
fn handlers(reg: &dyn Registry, scope: Scope, place: &Place) -> Vec<(String, String, String)> {
    let Some(root) = scope.root(place.classes) else {
        return vec![];
    };
    let key = format!(r"{root}\{}", place.path);
    let shown = scope.display(&key);
    let mut out = Vec::new();
    match place.shape {
        Shape::SubkeyDefault => {
            for name in reg.subkeys(scope.hive, &key, scope.view).into_iter().take(MAX_PER_KEY) {
                let default = reg.default_value(scope.hive, &format!(r"{key}\{name}"), scope.view);
                if let Some(id) = clsid(&default).or_else(|| clsid(&name)) {
                    out.push((name.clone(), id, format!(r"{shown}\{name}")));
                }
            }
        }
        Shape::SubkeyNames => {
            for name in reg.subkeys(scope.hive, &key, scope.view).into_iter().take(MAX_PER_KEY) {
                if let Some(id) = clsid(&name) {
                    out.push((name.clone(), id, format!(r"{shown}\{name}")));
                }
            }
        }
        Shape::ValueNames | Shape::ValueData => {
            for (name, data) in reg.values(scope.hive, &key, scope.view).into_iter().take(MAX_PER_KEY) {
                let (label, id) = if place.shape == Shape::ValueNames {
                    (strip(&data.as_text()).to_string(), clsid(&name))
                } else {
                    (name.clone(), clsid(&data.as_text()))
                };
                if let Some(id) = id {
                    let label = if label.is_empty() { name.clone() } else { label };
                    out.push((label, id, shown.clone()));
                }
            }
        }
        Shape::KeyDefault => {
            if let Some(id) = clsid(&reg.default_value(scope.hive, &key, scope.view)) {
                // The file type is the handler's name ("*.pdf thumbnails").
                let name = place
                    .path
                    .split('\\')
                    .find(|part| part.starts_with('.'))
                    .unwrap_or(&place.path)
                    .to_string();
                out.push((name, id, shown));
            }
        }
    }
    out
}

/// The shell extensions registered on this computer and for this user, and a summary
/// (`capped` when the limit was reached).
pub(crate) fn collect() -> (Vec<Value>, Value) {
    collect_from(&Live)
}

pub(crate) fn collect_from(reg: &dyn Registry) -> (Vec<Value>, Value) {
    let mut out = Vec::new();
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    // (class id, 32-bit) -> (user's server, computer's server)
    let mut servers: HashMap<(String, bool), (Option<Server>, Option<Server>)> = HashMap::new();
    let mut unregistered = 0usize;
    let mut capped = false;
    let mut places_read = 0usize;
    'all: for place in places() {
        for scope in SCOPES {
            places_read += 1;
            for (name, id, location) in handlers(reg, scope, &place) {
                let (user, machine) = servers
                    .entry((id.clone(), scope.bits32))
                    .or_insert_with(|| {
                        let user_root = if scope.bits32 {
                            r"Software\Classes\Wow6432Node\CLSID"
                        } else {
                            r"Software\Classes\CLSID"
                        };
                        let machine_view = if scope.bits32 { View::V32 } else { View::V64 };
                        (
                            read_server(reg, Hive::Hkcu, View::V64, user_root, &id, scope.bits32),
                            read_server(
                                reg,
                                Hive::Hklm,
                                machine_view,
                                r"SOFTWARE\Classes\CLSID",
                                &id,
                                scope.bits32,
                            ),
                        )
                    })
                    .clone();
                let Some(server) = user.clone().or_else(|| machine.clone()) else {
                    unregistered += 1;
                    continue;
                };
                let key = (place.kind.to_string(), id.clone(), lower(&server.file));
                if !seen.insert(key) {
                    continue;
                }
                if out.len() >= MAX_ENTRIES {
                    capped = true;
                    break 'all;
                }
                let shadowed = matches!((&user, &machine), (Some(u), Some(m)) if lower(&u.file) != lower(&m.file));
                out.push(json!({
                    "source": SOURCE,
                    "location": location,
                    "name": name,
                    "kind": place.kind,
                    "clsid": id,
                    "class_name": server.name,
                    "command": server.raw,
                    "file": server.file,
                    "startup": startup_kind(place.kind),
                    "user_registration": user.is_some(),
                    "shadowed": shadowed,
                    "enabled": true,
                }));
            }
        }
    }
    let summary = json!({
        "places_read": places_read,
        "classes": servers.len(),
        "entries": out.len(),
        "unregistered": unregistered,
        "capped": capped,
    });
    (out, summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Key = (String, String, String);
    type Contents = (Vec<String>, Vec<(String, RegData)>);

    /// A registry snapshot: (hive, view, lower-case key) -> (subkeys, values).
    #[derive(Default)]
    struct Snapshot(HashMap<Key, Contents>);

    fn tag(hive: Hive, view: View) -> (String, String) {
        (hive.short().to_string(), format!("{view:?}"))
    }

    impl Snapshot {
        fn key(&mut self, hive: Hive, view: View, key: &str) -> &mut (Vec<String>, Vec<(String, RegData)>) {
            let (h, v) = tag(hive, view);
            // Register the key in its parent's subkeys, all the way up.
            if let Some((parent, name)) = key.rsplit_once('\\') {
                let entry = self.key(hive, view, parent);
                if !entry.0.iter().any(|s| s.eq_ignore_ascii_case(name)) {
                    entry.0.push(name.to_string());
                }
            }
            self.0.entry((h, v, lower(key))).or_default()
        }
        fn set_default(&mut self, hive: Hive, view: View, key: &str, data: &str) -> &mut Self {
            self.key(hive, view, key)
                .1
                .push((String::new(), RegData::Str(data.into())));
            self
        }
        fn set_value(&mut self, hive: Hive, view: View, key: &str, name: &str, data: &str) -> &mut Self {
            self.key(hive, view, key)
                .1
                .push((name.into(), RegData::Str(data.into())));
            self
        }
    }

    impl Registry for Snapshot {
        fn subkeys(&self, hive: Hive, key: &str, view: View) -> Vec<String> {
            let (h, v) = tag(hive, view);
            self.0.get(&(h, v, lower(key))).map(|e| e.0.clone()).unwrap_or_default()
        }
        fn values(&self, hive: Hive, key: &str, view: View) -> Vec<(String, RegData)> {
            let (h, v) = tag(hive, view);
            self.0.get(&(h, v, lower(key))).map(|e| e.1.clone()).unwrap_or_default()
        }
    }

    const A: &str = "{AAAAAAAA-1111-2222-3333-444444444444}";
    const B: &str = "{BBBBBBBB-1111-2222-3333-444444444444}";
    const C: &str = "{CCCCCCCC-1111-2222-3333-444444444444}";
    const D: &str = "{DDDDDDDD-1111-2222-3333-444444444444}";
    const LM: Hive = Hive::Hklm;
    const CU: Hive = Hive::Hkcu;
    const V64: View = View::V64;

    fn machine_class(s: &mut Snapshot, id: &str, name: &str, dll: &str) {
        s.set_default(LM, V64, &format!(r"SOFTWARE\Classes\CLSID\{id}"), name);
        s.set_default(LM, V64, &format!(r"SOFTWARE\Classes\CLSID\{id}\InprocServer32"), dll);
    }

    fn find<'a>(entries: &'a [Value], kind: &str, id: &str) -> Option<&'a Value> {
        entries.iter().find(|e| e["kind"] == kind && e["clsid"] == lower(id))
    }

    #[test]
    fn handlers_are_read_from_every_place_and_resolved_to_their_dll() {
        let mut s = Snapshot::default();
        machine_class(&mut s, A, "Contoso Archive", r"C:\Program Files\Contoso\archive.dll");
        machine_class(&mut s, B, "Fabrikam Sync", r#""%ProgramFiles%\Fabrikam\overlay.dll""#);
        machine_class(&mut s, C, "Windows handler", "shell32.dll");
        // Context menu on every file, by class id in the default value.
        s.set_default(
            LM,
            V64,
            r"SOFTWARE\Classes\*\shellex\ContextMenuHandlers\ContosoArchive",
            A,
        );
        // The same handler on folders: one entry per kind and class, not per file type.
        s.set_default(
            LM,
            V64,
            r"SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\ContosoArchive",
            A,
        );
        s.set_default(
            LM,
            V64,
            r"SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\ContosoArchive",
            A,
        );
        // A handler whose subkey name is the class id.
        s.key(LM, V64, &format!(r"SOFTWARE\Classes\Folder\shellex\ColumnHandlers\{C}"));
        // An icon overlay (note the leading spaces some vendors use to sort first).
        s.set_default(
            LM,
            V64,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\   FabrikamSynced",
            B,
        );
        // A thumbnail provider for PDF.
        s.set_default(
            LM,
            V64,
            &format!(r"SOFTWARE\Classes\.pdf\shellex\{THUMBNAIL_SHELLEX}"),
            A,
        );
        // A handler that names a class nobody registers (a leftover) is not listed.
        s.set_default(LM, V64, r"SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\Gone", D);

        let (entries, summary) = collect_from(&s);
        let archive = find(&entries, "context_menu", A).expect("context menu");
        assert_eq!(archive["file"], r"C:\Program Files\Contoso\archive.dll");
        assert_eq!(archive["class_name"], "Contoso Archive");
        assert_eq!(archive["startup"], false);
        assert_eq!(archive["shadowed"], false);
        assert_eq!(entries.iter().filter(|e| e["kind"] == "context_menu").count(), 1);
        let overlay = find(&entries, "icon_overlay", B).expect("overlay");
        assert!(
            overlay["file"]
                .as_str()
                .is_some_and(|f| f.ends_with(r"\Fabrikam\overlay.dll"))
        );
        assert_eq!(overlay["name"], "   FabrikamSynced");
        let column = find(&entries, "column_handler", C).expect("column");
        assert_eq!(
            lower(column["file"].as_str().unwrap_or("")),
            lower(&join(&SYSTEM32, &["shell32.dll"]))
        );
        let thumb = find(&entries, "thumbnail_provider", A).expect("thumbnail");
        assert_eq!(thumb["name"], ".pdf");
        assert!(find(&entries, "context_menu", D).is_none());
        assert_eq!(summary["unregistered"], 1);
        assert_eq!(summary["capped"], false);
        assert!(entries.iter().all(|e| e["source"] == SOURCE));
    }

    #[test]
    fn startup_objects_and_value_lists() {
        let mut s = Snapshot::default();
        machine_class(&mut s, A, "Updater", r"C:\Users\Public\sso.dll");
        machine_class(&mut s, B, "Hook", r"C:\ProgramData\hook.dll");
        machine_class(&mut s, C, "Scheduler", r"C:\Program Files\Tailspin\sts.dll");
        machine_class(&mut s, D, "Delay", r"C:\Program Files\Tailspin\delay.dll");
        s.key(
            LM,
            V64,
            &format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{A}"),
        );
        s.set_value(
            LM,
            V64,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
            B,
            "Hook",
        );
        s.set_value(
            LM,
            V64,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
            C,
            "Tailspin scheduler",
        );
        // Delay-load lists the class id in the data, the name is a description.
        s.set_value(
            LM,
            V64,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
            "TailspinDelay",
            D,
        );
        let (entries, _) = collect_from(&s);
        for (kind, id) in [
            ("shell_service_object", A),
            ("execute_hook", B),
            ("shared_task_scheduler", C),
            ("delay_load", D),
        ] {
            let entry = find(&entries, kind, id).unwrap_or_else(|| panic!("{kind}"));
            assert_eq!(entry["startup"], true, "{kind}");
        }
        assert_eq!(
            find(&entries, "shared_task_scheduler", C).map(|e| e["name"].clone()),
            Some(json!("Tailspin scheduler"))
        );
        assert_eq!(
            find(&entries, "delay_load", D).map(|e| e["name"].clone()),
            Some(json!("TailspinDelay"))
        );
    }

    #[test]
    fn the_users_registration_wins_and_a_replacement_is_noted() {
        let mut s = Snapshot::default();
        machine_class(&mut s, A, "Windows thumbnails", r"C:\Windows\System32\thumbcache.dll");
        s.set_default(
            CU,
            V64,
            &format!(r"Software\Classes\CLSID\{A}\InprocServer32"),
            r"C:\Users\jdoe\AppData\Local\t.dll",
        );
        // Registered by the user only (a per-user app install): not a replacement.
        s.set_default(
            CU,
            V64,
            &format!(r"Software\Classes\CLSID\{B}\InprocServer32"),
            r"C:\Users\jdoe\AppData\Local\Contoso\cm.dll",
        );
        s.set_default(CU, V64, r"Software\Classes\*\shellex\ContextMenuHandlers\Contoso", B);
        s.set_default(
            LM,
            V64,
            &format!(r"SOFTWARE\Classes\.png\shellex\{THUMBNAIL_SHELLEX}"),
            A,
        );
        let (entries, _) = collect_from(&s);
        let thumb = find(&entries, "thumbnail_provider", A).expect("thumbnail");
        assert_eq!(thumb["file"], r"C:\Users\jdoe\AppData\Local\t.dll");
        assert_eq!(thumb["shadowed"], true);
        assert_eq!(thumb["user_registration"], true);
        let menu = find(&entries, "context_menu", B).expect("user menu");
        assert_eq!(menu["shadowed"], false);
        assert_eq!(menu["user_registration"], true);
        assert!(menu["location"].as_str().is_some_and(|l| l.starts_with("HKCU\\")));
    }

    #[test]
    fn dll_paths_and_class_ids() {
        assert_eq!(clsid(" {AAAAAAAA-1111-2222-3333-444444444444} "), Some(lower(A)));
        assert_eq!(clsid("ContosoArchive"), None);
        assert_eq!(clsid("{not-a-class-id}"), None);
        assert_eq!(server_file("", "", false), "");
        assert_eq!(
            lower(&server_file("shell32.dll", "", true)),
            lower(&join(&SYSWOW64, &["shell32.dll"]))
        );
        // A .NET extension: mscoree.dll hosts the assembly its CodeBase names.
        assert_eq!(
            server_file("mscoree.dll", "file:///C:/Program Files/Contoso/Shell%20Ext.dll", false),
            r"C:\Program Files\Contoso\Shell Ext.dll"
        );
        assert_eq!(
            lower(&server_file("mscoree.dll", "", false)),
            lower(&join(&SYSTEM32, &["mscoree.dll"]))
        );
    }

    #[test]
    fn the_list_is_bounded() {
        let mut s = Snapshot::default();
        machine_class(&mut s, A, "x", r"C:\Program Files\Contoso\x.dll");
        for i in 0..(MAX_PER_KEY + 50) {
            // Each handler a distinct class id, all pointing to registered classes.
            let id = format!("{{AAAAAAAA-1111-2222-3333-{i:012}}}");
            machine_class(&mut s, &id, "x", &format!(r"C:\Program Files\Contoso\x{i}.dll"));
            s.set_default(
                LM,
                V64,
                &format!(r"SOFTWARE\Classes\*\shellex\ContextMenuHandlers\h{i}"),
                &id,
            );
        }
        let (entries, _) = collect_from(&s);
        // At most MAX_PER_KEY handlers are read under one key.
        assert_eq!(entries.len(), MAX_PER_KEY);
    }

    /// Counts only: `cargo test -p vigil-scan shellext::tests::live_counts -- --ignored --nocapture`
    #[test]
    #[ignore = "reads this computer's registry"]
    fn live_counts() {
        let started = std::time::Instant::now();
        let (entries, summary) = collect();
        let elapsed = started.elapsed();
        let mut kinds: Vec<(String, usize)> = Vec::new();
        for e in &entries {
            let kind = e["kind"].as_str().unwrap_or("").to_string();
            match kinds.iter_mut().find(|(k, _)| *k == kind) {
                Some((_, n)) => *n += 1,
                None => kinds.push((kind, 1)),
            }
        }
        let files: HashSet<String> = entries
            .iter()
            .map(|e| lower(e["file"].as_str().unwrap_or("")))
            .collect();
        let windows = files
            .iter()
            .filter(|f| f.starts_with(&lower(&crate::ntpath::WINDIR)))
            .count();
        println!(
            "shell extensions: {} entries, {} distinct files ({} in the Windows folder), {} startup, {} shadowed, {} user, summary {summary}, kinds {kinds:?}, {elapsed:?}",
            entries.len(),
            files.len(),
            windows,
            entries.iter().filter(|e| e["startup"] == true).count(),
            entries.iter().filter(|e| e["shadowed"] == true).count(),
            entries.iter().filter(|e| e["user_registration"] == true).count(),
        );
    }
}
