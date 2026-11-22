//! Opening things for the user (Explorer, properties, Registry Editor, consoles...). Nothing here
//! changes the system, except Registry Editor's own "last key" preference.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::json;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Shell::{SHOP_FILEPATH, SHObjectProperties, ShellExecuteW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{HSTRING, PCWSTR, w};

use crate::cmdline::{dirname, normalize_path};
use crate::error::{Result, fail};
use crate::registry::{Hive, Key, decode_value, reg_write, split_key};
use crate::runner::{launch, system32, tool, windir};
use vigil_i18n::tr;

fn explorer() -> String {
    windir().join("explorer.exe").to_string_lossy().into_owned()
}

/// Shows a file selected in Explorer (or its folder when the file is gone).
pub fn open_location(path: &str) -> Result<()> {
    let path = normalize_path(path);
    if !path.is_empty() && Path::new(&path).exists() {
        return launch(&explorer(), &[&format!("/select,{path}")]);
    }
    let folder = dirname(&path);
    if !folder.is_empty() && Path::new(&folder).is_dir() {
        return launch(&explorer(), &[&folder]);
    }
    fail(tr!("neither the file nor its folder exists"))
}

/// Opens a folder in Explorer.
pub fn open_folder(path: &str) -> Result<()> {
    let path = normalize_path(path);
    if path.is_empty() || !Path::new(&path).is_dir() {
        return fail(tr!("the folder does not exist"));
    }
    launch(&explorer(), &[&path])
}

/// The Windows Properties dialog of a file (`hwnd` = owner window, 0 for none).
pub fn show_properties(path: &str, hwnd: isize) -> Result<()> {
    let path = normalize_path(path);
    if path.is_empty() || !Path::new(&path).exists() {
        return fail(tr!("the file does not exist"));
    }
    let wide = HSTRING::from(path.as_str());
    let owner = (hwnd != 0).then_some(HWND(hwnd as *mut core::ffi::c_void));
    // SAFETY: `wide` outlives the call; the dialog is modeless and copies the path.
    if !unsafe { SHObjectProperties(owner, SHOP_FILEPATH, &wide, PCWSTR::null()) }.as_bool() {
        return fail(tr!("Windows could not show the file properties"));
    }
    Ok(())
}

/// Opens Registry Editor at a key (through its LastKey preference).
pub fn open_regedit(key: &str) -> Result<()> {
    let (hive, sub) = split_key(key)?;
    let full = format!("Computer\\{}\\{sub}", hive.long());
    reg_write(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit",
        "LastKey",
        &json!({ "type": "REG_SZ", "data": full }),
    )?;
    launch(&windir().join("regedit.exe").to_string_lossy(), &["/m"])
}

static URL_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)^(https://|windowsdefender://|ms-settings:)").ok());

/// Opens a link in the default browser or app (only https, Windows Security and Settings links).
/// The program that opens a link is the one the user's own registrations name, which any program
/// can change: while Vigil runs as administrator it is started with the user's normal rights,
/// through Explorer (see `desktop`).
pub fn open_url(url: &str) -> Result<()> {
    if !URL_RE.as_ref().is_some_and(|re| re.is_match(url)) {
        return fail(tr!("only https, Windows Security and Settings links are opened"));
    }
    crate::desktop::launch_unelevated(url, "", "", || {
        let wide = HSTRING::from(url);
        // SAFETY: `wide` outlives the call.
        let result = unsafe { ShellExecuteW(None, w!("open"), &wide, PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL) };
        if (result.0 as isize) <= 32 {
            return fail(tr!("Windows could not open the link"));
        }
        Ok(())
    })
}

const CONSOLES: [&str; 6] = [
    "taskschd.msc",
    "services.msc",
    "eventvwr.msc",
    "compmgmt.msc",
    "wf.msc",
    "lusrmgr.msc",
];

/// Opens one of the management consoles (Task Scheduler, Services, Event Viewer, Computer
/// Management, Windows Defender Firewall with Advanced Security, Local Users and Groups).
pub fn open_console(name: &str) -> Result<()> {
    if !CONSOLES.contains(&name) {
        return fail(tr!("unknown console"));
    }
    launch(&tool("mmc.exe"), &[&tool(name)])
}

const TOOLS: [&str; 10] = [
    "SystemPropertiesPerformance.exe",
    "SystemPropertiesProtection.exe",
    "rstrui.exe",
    "cleanmgr.exe",
    "dfrgui.exe",
    "resmon.exe",
    "perfmon.exe",
    "taskmgr.exe",
    "msinfo32.exe",
    "powercfg.cpl",
];

/// Reliability Monitor: Performance Monitor's `/rel` view, asked for by this name.
const RELIABILITY_MONITOR: &str = "reliability";

/// BitLocker Drive Encryption in Control Panel, asked for by this name.
const BITLOCKER: &str = "bitlocker";

/// Opens one of a few Windows tools (performance options, disk cleanup, defragmenter, Reliability
/// Monitor, BitLocker...).
pub fn open_tool(name: &str) -> Result<()> {
    if name == RELIABILITY_MONITOR {
        return launch(&tool("perfmon.exe"), &["/rel"]);
    }
    if name == BITLOCKER {
        return launch(&tool("control.exe"), &["/name", "Microsoft.BitLockerDriveEncryption"]);
    }
    if !TOOLS.contains(&name) {
        return fail(tr!("unknown tool"));
    }
    if name.ends_with(".cpl") {
        return launch(&tool("control.exe"), &[name]);
    }
    launch(&tool(name), &[])
}

/// Opens the hosts file in Notepad.
pub fn edit_hosts() -> Result<()> {
    let hosts = system32().join(r"drivers\etc\hosts");
    launch(&tool("notepad.exe"), &[&hosts.to_string_lossy()])
}

const BROWSERS: [(&str, &str, &str); 8] = [
    ("Chrome", "chrome.exe", "chrome://extensions"),
    ("Edge", "msedge.exe", "edge://extensions"),
    ("Brave", "brave.exe", "brave://extensions"),
    ("Vivaldi", "vivaldi.exe", "vivaldi://extensions"),
    ("Opera", "opera.exe", "opera://extensions"),
    ("Opera GX", "opera.exe", "opera://extensions"),
    ("Firefox", "firefox.exe", "about:addons"),
    ("Chromium", "chrome.exe", "chrome://extensions"),
];

/// Where browsers install themselves: (browser, base folder variable, folder below it).
const BROWSER_FOLDERS: [(&str, &str, &str); 17] = [
    ("Chrome", "ProgramFiles", r"Google\Chrome\Application"),
    ("Chrome", "ProgramFiles(x86)", r"Google\Chrome\Application"),
    ("Chrome", "LOCALAPPDATA", r"Google\Chrome\Application"),
    ("Edge", "ProgramFiles(x86)", r"Microsoft\Edge\Application"),
    ("Edge", "ProgramFiles", r"Microsoft\Edge\Application"),
    ("Brave", "ProgramFiles", r"BraveSoftware\Brave-Browser\Application"),
    ("Brave", "LOCALAPPDATA", r"BraveSoftware\Brave-Browser\Application"),
    ("Vivaldi", "LOCALAPPDATA", r"Vivaldi\Application"),
    ("Vivaldi", "ProgramFiles", r"Vivaldi\Application"),
    ("Opera", "LOCALAPPDATA", r"Programs\Opera"),
    ("Opera", "ProgramFiles", "Opera"),
    ("Opera GX", "LOCALAPPDATA", r"Programs\Opera GX"),
    ("Opera GX", "ProgramFiles", "Opera GX"),
    ("Firefox", "ProgramFiles", "Mozilla Firefox"),
    ("Firefox", "ProgramFiles(x86)", "Mozilla Firefox"),
    ("Chromium", "LOCALAPPDATA", r"Chromium\Application"),
    ("Chromium", "ProgramFiles", r"Chromium\Application"),
];

/// The browser's own program: its install folders first for the browsers whose App Paths entry is
/// shared with another one (Opera and Opera GX both register opera.exe; Chromium's chrome.exe would
/// be Chrome's), App Paths first for the others.
fn browser_exe(browser: &str, exe: &str) -> Option<String> {
    let from_folders = || {
        BROWSER_FOLDERS
            .iter()
            .filter(|(name, _, _)| *name == browser)
            .filter_map(|(_, var, folder)| std::env::var_os(var).map(|base| Path::new(&base).join(folder).join(exe)))
            .find(|path| path.is_file())
            .map(|path| path.to_string_lossy().into_owned())
    };
    let from_app_paths = || {
        let sub = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}");
        [Hive::LocalMachine, Hive::CurrentUser].into_iter().find_map(|hive| {
            let key = Key::open(hive, &sub, windows::Win32::System::Registry::KEY_READ).ok()?;
            let (kind, data) = key.query("").ok()??;
            let text = decode_value(kind, &data).as_str()?.trim_matches('"').to_string();
            Path::new(&text).is_file().then_some(text)
        })
    };
    if matches!(browser, "Opera" | "Opera GX" | "Chromium") {
        from_folders()
    } else {
        from_app_paths().or_else(from_folders)
    }
}

/// Opens a browser's extensions page. A browser is the user's own program (it may live in the
/// user's folders and be replaced by any program they run): while Vigil runs as administrator it
/// is started with the user's normal rights, through Explorer, never with Vigil's.
pub fn open_browser_extensions(browser: &str) -> Result<()> {
    let Some((_, exe, page)) = BROWSERS.iter().find(|(name, _, _)| *name == browser) else {
        return fail(tr!("unknown browser {0}", browser));
    };
    match browser_exe(browser, exe) {
        Some(path) => crate::desktop::launch_unelevated(&path, page, "", || launch(&path, &[page])),
        None => fail(tr!("{0} was not found; open {1} in it yourself", browser, page)),
    }
}

/// Whether Vigil knows how to open this browser's extensions page.
pub fn known_browser(browser: &str) -> bool {
    BROWSERS.iter().any(|(name, _, _)| *name == browser)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn links_open_with_the_users_rights_while_vigil_is_elevated() {
        let calls: Rc<RefCell<Vec<String>>> = Rc::default();
        let seen = calls.clone();
        crate::testing::set_user_launch(Some(Rc::new(move |file: &str, args: &str, _: &str| {
            seen.borrow_mut().push(format!("{file}|{args}"));
            Ok(())
        })));
        crate::testing::set_admin(Some(true));
        open_url("ms-settings:windowsupdate").expect("opened");
        open_url("windowsdefender://threat").expect("opened");
        assert_eq!(
            calls.borrow().as_slice(),
            ["ms-settings:windowsupdate|", "windowsdefender://threat|"]
        );
        // Anything else is refused before any launch.
        for bad in [
            "http://example.com",
            "file:///C:/Windows/notepad.exe",
            "mscfile:x",
            r"C:\Tools\x.exe",
        ] {
            assert!(open_url(bad).is_err(), "{bad}");
        }
        assert_eq!(calls.borrow().len(), 2);
        crate::testing::reset();
    }
}
