//! Removing a leftover entry from the list of installed programs: its uninstaller and its files
//! are already gone and only its Uninstall key is left. The key is read again and checked first,
//! then exported, so undo imports it back. Microsoft's entries, products Windows Installer still
//! knows and anything that is not directly under an Uninstall key are refused.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::json;
use vigil_sys::programs::{Root, Source, UNINSTALL, UNINSTALL_32, is_microsoft, read_entry_in};

use crate::engine::{Builtin, Outcome, run_fn, undo_fn};
use crate::error::{Result, fail};
use crate::ops::export_key;
use crate::params::Params;
use crate::quarantine::new_id;
use crate::runner::{first_line, run, tool};
use crate::store::Store;
use vigil_i18n::tr;

/// An entry directly under the machine's or this account's Uninstall keys.
static UNINSTALL_ENTRY: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)^HK(LM|CU)\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$").ok()
});

/// The keys an entry may be read from: the real Uninstall keys, or the tests' scratch key.
fn sources() -> Vec<Source> {
    let source = |root, key: &str, scope| Source {
        root,
        key: key.to_string(),
        scope,
        sid: String::new(),
    };
    if let Some(root) = crate::testing::uninstall_root() {
        let key = root.split_once('\\').map_or("", |(_, rest)| rest);
        return vec![source(Root::CurrentUser, key, "user")];
    }
    vec![
        source(Root::LocalMachine, UNINSTALL, "machine"),
        source(Root::LocalMachine, UNINSTALL_32, "machine32"),
        source(Root::CurrentUser, UNINSTALL, "user"),
        source(Root::CurrentUser, UNINSTALL_32, "user"),
    ]
}

/// The key is one entry of an Uninstall key (of the scratch key, in the tests).
fn allowed_key(key: &str) -> bool {
    if let Some(root) = crate::testing::uninstall_root() {
        let low = key.trim().to_lowercase();
        let prefix = format!("{}\\", root.to_lowercase());
        return low
            .strip_prefix(&prefix)
            .is_some_and(|name| !name.is_empty() && !name.contains('\\'));
    }
    UNINSTALL_ENTRY.as_ref().is_some_and(|re| re.is_match(key.trim()))
}

fn op_remove_entry(p: Params<'_>, store: &Store, record_id: &str) -> Result<Outcome> {
    let key = p.req_str("key")?;
    if !allowed_key(&key) {
        return fail(tr!(
            "Vigil only removes entries from the list of installed programs; {0} is not one of them",
            key
        ));
    }
    let Some(entry) = read_entry_in(&key, &sources()) else {
        return fail(tr!("the entry is no longer in the list of installed programs"));
    };
    if is_microsoft(&entry.publisher) {
        return fail(tr!("entries published by Microsoft are not removed from Vigil"));
    }
    if entry.msi && entry.msi_known {
        return fail(tr!("Windows Installer still knows this program: uninstall it instead"));
    }
    if !entry.leftover {
        return fail(tr!(
            "the program's uninstaller or files are still there: uninstall it instead of removing its entry"
        ));
    }
    let id = if record_id.is_empty() {
        new_id()
    } else {
        record_id.to_string()
    };
    let backup = export_key(&entry.id, store, &id)?;
    let result = run(
        vec![tool("reg.exe"), "delete".into(), entry.id.clone(), "/f".into()],
        60,
    )?;
    if result.code != 0 {
        return fail(tr!("could not remove {0}: {1}", entry.id, first_line(&result.text())));
    }
    Ok(Outcome::new(
        tr!(
            "removed the leftover entry of \"{0}\" from the installed programs (backup of its registry key saved)",
            entry.name
        ),
        Some(json!({ "key": entry.id, "name": entry.name, "backup": backup })),
    ))
}

fn undo_remove_entry(u: Params<'_>, _store: &Store) -> Result<String> {
    let backup = u.str_or_empty("backup");
    if backup.is_empty() || !Path::new(&backup).is_file() {
        return fail(tr!("the registry backup of this entry is missing"));
    }
    let result = run(vec![tool("reg.exe"), "import".into(), backup], 60)?;
    if result.code != 0 {
        return fail(tr!("could not import the backup: {0}", first_line(&result.text())));
    }
    Ok(tr!(
        "restored the entry of \"{0}\" in the installed programs",
        u.str_or_empty("name")
    ))
}

pub(crate) fn builtin() -> Vec<Builtin> {
    vec![(
        "program.remove_entry",
        run_fn(op_remove_entry),
        Some(undo_fn(undo_remove_entry)),
        false,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_uninstall_entries_are_accepted() {
        let ok = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Contoso",
            r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{11111111-2222-3333-4444-555555555555}",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Fabrikam Viewer_is1",
        ];
        for key in ok {
            assert!(allowed_key(key), "{key}");
        }
        let refused = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Contoso\Sub",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Contoso",
            r"HKLM\SYSTEM\CurrentControlSet\Services\Contoso",
            r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Uninstall\Contoso",
            r"HKCU\Software\VigilTests\Contoso",
        ];
        for key in refused {
            assert!(!allowed_key(key), "{key}");
        }
    }
}
