//! The last line of defence: files and services that are never touched, whatever the app asks.

use crate::cmdline::{in_dir, is_abs, normalize_path, split_command};
use crate::error::{Result, fail};
use crate::params::text_of;
use crate::runner::windir;
use crate::signature::{is_microsoft_signed, signature_info};
use serde_json::{Map, Value};
use vigil_i18n::tr;

/// Where Vigil itself runs from.
fn own_locations() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(folder) = exe.parent() {
            out.push(folder.to_string_lossy().into_owned());
        }
        out.push(exe.to_string_lossy().into_owned());
    }
    out
}

/// Refuses files that belong to Windows, Defender, Store apps or Vigil, and Microsoft-signed files.
pub fn guard_file(path: &str, check_signature: bool) -> Result<()> {
    if path.is_empty() || !is_abs(path) {
        return fail(tr!("the file path is not absolute"));
    }
    let windir = windir().to_string_lossy().into_owned();
    if in_dir(path, &windir) && !in_dir(path, &format!("{windir}\\Temp")) {
        return fail(tr!(
            "files inside the Windows folder are never quarantined: disable what starts it instead"
        ));
    }
    for name in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"] {
        let Ok(root) = std::env::var(name) else {
            continue;
        };
        if root.is_empty() {
            continue;
        }
        if in_dir(path, &format!("{root}\\WindowsApps")) {
            return fail(tr!("Store app files are managed by Windows: uninstall the app instead"));
        }
        if in_dir(path, &format!("{root}\\Windows Defender")) {
            return fail(tr!("Microsoft Defender files are protected"));
        }
    }
    if own_locations().iter().any(|own| !own.is_empty() && in_dir(path, own)) {
        return fail(tr!("this file belongs to Vigil"));
    }
    if check_signature && is_microsoft_signed(signature_info(path).as_ref()) {
        return fail(tr!("the file is signed by Microsoft; it is a Windows component"));
    }
    Ok(())
}

pub const ESSENTIAL_SERVICES: [&str; 67] = [
    "rpcss",
    "dcomlaunch",
    "rpceptmapper",
    "lsm",
    "samss",
    "eventlog",
    "plugplay",
    "power",
    "schedule",
    "bfe",
    "mpssvc",
    "windefend",
    "wdnissvc",
    "wdfilter",
    "wdboot",
    "wdnisdrv",
    "sense",
    "securityhealthservice",
    "wscsvc",
    "cryptsvc",
    "winmgmt",
    "profsvc",
    "gpsvc",
    "usermanager",
    "brokerinfrastructure",
    "systemeventsbroker",
    "coremessagingregistrar",
    "dhcp",
    "dnscache",
    "nsi",
    "lanmanworkstation",
    "audiosrv",
    "audioendpointbuilder",
    "themes",
    "tokenbroker",
    "staterepository",
    "appxsvc",
    "clipsvc",
    "wuauserv",
    "trustedinstaller",
    "msiserver",
    "vss",
    "sgrmbroker",
    "keyiso",
    "netlogon",
    "netprofm",
    "nlasvc",
    "wlansvc",
    "eaphost",
    "tcpip",
    "afd",
    "ndis",
    "disk",
    "volmgr",
    "partmgr",
    "ntfs",
    "acpi",
    "pci",
    "storahci",
    "stornvme",
    "ksecdd",
    "cng",
    "fltmgr",
    "mountmgr",
    "volsnap",
    "msrpc",
    "netbt",
];

/// Refuses essential services and Windows services signed by Microsoft.
pub fn guard_service(name: &str, values: &Map<String, Value>) -> Result<()> {
    if ESSENTIAL_SERVICES.contains(&name.to_lowercase().as_str()) {
        return fail(tr!("\"{0}\" is an essential Windows service", name));
    }
    let text = |key: &str| match values.get(key) {
        None | Some(Value::Null) => String::new(),
        Some(value) => text_of(value),
    };
    let image = text("ImagePath");
    let program = if image.is_empty() {
        None
    } else {
        split_command(&image).0
    };
    let binary = normalize_path(&program.filter(|p| !p.is_empty()).unwrap_or_else(|| image.clone()));
    let dll = normalize_path(&text("ServiceDll"));
    // For services hosted in svchost what runs is the DLL, not svchost itself.
    let target = if dll.is_empty() { binary } else { dll };
    let windir = windir().to_string_lossy().into_owned();
    if !target.is_empty()
        && is_abs(&target)
        && in_dir(&target, &windir)
        && is_microsoft_signed(signature_info(&target).as_ref())
    {
        return fail(tr!("\"{0}\" is a Windows service signed by Microsoft", name));
    }
    Ok(())
}
