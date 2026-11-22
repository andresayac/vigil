//! The Windows services: every Win32 service with its state, startup type, process, binary,
//! account and description. Read-only: the Service Control Manager is opened for enumeration and
//! each service for configuration queries only. Changes go through the action engine.

use std::ffi::c_void;

use serde::Serialize;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA};
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW,
    QUERY_SERVICE_CONFIGW, QueryServiceConfig2W, QueryServiceConfigW, SC_ENUM_PROCESS_INFO, SC_HANDLE,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DESCRIPTIONW, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

use crate::error::SysError;

/// One Win32 service.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// The key name (`Dnscache`): what `sc.exe` and the actions use.
    pub name: String,
    pub display_name: String,
    pub description: String,
    /// "running", "stopped", "start_pending", "stop_pending", "continue_pending", "pause_pending", "paused".
    pub state: String,
    /// "auto", "delayed-auto", "demand", "disabled", "boot" or "system"; "" when its configuration
    /// could not be read (standard users cannot query every service).
    pub start_type: String,
    /// The hosting process while it runs, 0 otherwise.
    pub pid: u32,
    /// "own" (its own process) or "share" (a shared host such as svchost.exe).
    pub service_type: String,
    /// The binary with its arguments, environment variables expanded.
    pub path: String,
    /// The executable alone (the first part of `path`).
    pub executable: String,
    /// For services hosted by svchost: the DLL that really runs (`Parameters\ServiceDll`), expanded.
    pub dll: String,
    /// The account it runs as (`LocalSystem`, `NT AUTHORITY\LocalService`...).
    pub account: String,
    /// The svchost group (`-k netsvcs`), empty when not hosted by svchost.
    pub group: String,
}

struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW/OpenServiceW and is closed only here.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

fn state_name(state: u32) -> &'static str {
    match state {
        1 => "stopped",
        2 => "start_pending",
        3 => "stop_pending",
        4 => "running",
        5 => "continue_pending",
        6 => "pause_pending",
        7 => "paused",
        _ => "unknown",
    }
}

fn start_name(start: u32, delayed: bool) -> &'static str {
    match start {
        0 => "boot",
        1 => "system",
        2 if delayed => "delayed-auto",
        2 => "auto",
        4 => "disabled",
        _ => "demand",
    }
}

/// SAFETY contract: `ptr` is null or a NUL-terminated wide string that lives while it is read.
unsafe fn wide_text(ptr: PWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: guaranteed by the caller.
    unsafe { ptr.to_string() }.unwrap_or_default()
}

fn expand(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let source = HSTRING::from(text);
    // SAFETY: a size query (no buffer).
    let needed = unsafe { ExpandEnvironmentStringsW(&source, None) };
    if needed == 0 {
        return text.to_string();
    }
    let mut buffer = vec![0u16; needed as usize];
    // SAFETY: the buffer has the size the first call asked for.
    let written = unsafe { ExpandEnvironmentStringsW(&source, Some(&mut buffer)) };
    if written == 0 || written as usize > buffer.len() {
        return text.to_string();
    }
    crate::util::from_wide(&buffer)
}

/// The executable of a service command line: the quoted part, or everything up to `.exe`.
pub fn executable_of(path: &str) -> String {
    let path = path.trim();
    if let Some(rest) = path.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("").to_string();
    }
    let lower = path.to_ascii_lowercase();
    match lower.find(".exe") {
        Some(end) => path[..end + 4].to_string(),
        None => path.split_whitespace().next().unwrap_or("").to_string(),
    }
}

/// The DLL a svchost-hosted service loads, from its registry key.
fn service_dll(name: &str) -> String {
    let dll = crate::util::hklm_string(
        &format!(r"SYSTEM\CurrentControlSet\Services\{name}\Parameters"),
        "ServiceDll",
    );
    if dll.is_empty() { dll } else { expand(&dll) }
}

/// The svchost group of a binary path (`...\svchost.exe -k netsvcs -p` -> `netsvcs`).
pub fn svchost_group(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if !lower.contains("svchost.exe") {
        return String::new();
    }
    let mut words = path.split_whitespace();
    while let Some(word) = words.next() {
        if word.eq_ignore_ascii_case("-k") || word.eq_ignore_ascii_case("/k") {
            return words.next().unwrap_or("").trim_matches('"').to_string();
        }
    }
    String::new()
}

/// Reads one service's configuration: (start type, delayed, path, account, own/share), description.
/// `full` false skips the delayed-start flag and the description (two more queries per service).
fn config(manager: SC_HANDLE, name: &str, full: bool) -> Option<(u32, bool, String, String, u32, String)> {
    let wide = HSTRING::from(name);
    // SAFETY: valid manager handle; `wide` outlives the call; the handle is owned by `Handle`.
    let service = Handle(unsafe { OpenServiceW(manager, &wide, SERVICE_QUERY_CONFIG) }.ok()?);
    // Configuration: ask for the size, then read into an 8-byte aligned buffer.
    let mut needed = 0u32;
    // SAFETY: a size query with no buffer.
    let first = unsafe { QueryServiceConfigW(service.0, None, 0, &mut needed) };
    if first.is_ok() || needed == 0 {
        return None;
    }
    let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
    let config = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    // SAFETY: the buffer is at least `needed` bytes and aligned for QUERY_SERVICE_CONFIGW.
    unsafe { QueryServiceConfigW(service.0, Some(config), (storage.len() * 8) as u32, &mut needed) }.ok()?;
    // SAFETY: on success the buffer holds a QUERY_SERVICE_CONFIGW whose strings point inside it.
    let (start, path, account, service_type) = unsafe {
        let c = &*config;
        (
            c.dwStartType.0,
            wide_text(c.lpBinaryPathName),
            wide_text(c.lpServiceStartName),
            c.dwServiceType.0,
        )
    };
    if !full {
        return Some((start, false, expand(&path), account, service_type, String::new()));
    }
    let delayed = optional_config(service.0, SERVICE_CONFIG_DELAYED_AUTO_START_INFO.0, |bytes| {
        // SAFETY: the buffer holds a SERVICE_DELAYED_AUTO_START_INFO on success.
        unsafe {
            (*bytes.cast::<SERVICE_DELAYED_AUTO_START_INFO>())
                .fDelayedAutostart
                .as_bool()
        }
    })
    .unwrap_or(false);
    let description = optional_config(service.0, SERVICE_CONFIG_DESCRIPTION.0, |bytes| {
        // SAFETY: the buffer holds a SERVICE_DESCRIPTIONW whose string points inside it.
        unsafe { wide_text((*bytes.cast::<SERVICE_DESCRIPTIONW>()).lpDescription) }
    })
    .unwrap_or_default();
    Some((start, delayed, expand(&path), account, service_type, description))
}

/// QueryServiceConfig2W for one info level, read by `read` from an aligned buffer.
fn optional_config<T>(service: SC_HANDLE, level: u32, read: impl FnOnce(*const c_void) -> T) -> Option<T> {
    let mut needed = 0u32;
    // SAFETY: a size query with no buffer.
    let first = unsafe {
        QueryServiceConfig2W(
            service,
            windows::Win32::System::Services::SERVICE_CONFIG(level),
            None,
            &mut needed,
        )
    };
    if first.is_ok() || needed == 0 {
        return None;
    }
    let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: the slice covers the aligned storage; its length is what the first call asked for.
    let bytes = unsafe { std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), storage.len() * 8) };
    // SAFETY: valid handle and buffer.
    unsafe {
        QueryServiceConfig2W(
            service,
            windows::Win32::System::Services::SERVICE_CONFIG(level),
            Some(bytes),
            &mut needed,
        )
    }
    .ok()?;
    Some(read(storage.as_ptr().cast::<c_void>()))
}

/// One enumerated service: (name, display name, state, process id, service type bits).
type Enumerated = (String, String, u32, u32, u32);

fn open_manager() -> Result<Handle, SysError> {
    // SAFETY: plain call; the handle is owned by `Handle`.
    let manager = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) };
    manager.map(Handle).map_err(|e| {
        SysError::new(
            format!("the service list could not be read ({})", e.message()),
            e.code().0,
        )
    })
}

/// Every Win32 service the Service Control Manager lists, with its state.
fn enumerate(manager: &Handle) -> Result<Vec<Enumerated>, SysError> {
    let mut needed = 0u32;
    let mut count = 0u32;
    let mut buffer: Vec<u64> = vec![0; 256 * 1024 / 8];
    loop {
        let bytes = buffer.len() * 8;
        let mut resume = 0u32;
        // SAFETY: the buffer is writable for `bytes` bytes and 8-byte aligned; out pointers are locals.
        let result = unsafe {
            EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), bytes)),
                &mut needed,
                &mut count,
                Some(&mut resume),
                PCWSTR::null(),
            )
        };
        match result {
            Ok(()) => break,
            Err(error)
                if error.code() == ERROR_MORE_DATA.to_hresult()
                    || error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() =>
            {
                buffer = vec![0; (bytes + needed as usize).div_ceil(8) + 1024];
            }
            Err(error) => {
                return Err(SysError::new(
                    format!("the service list could not be read ({})", error.message()),
                    error.code().0,
                ));
            }
        }
    }
    // SAFETY: on success the buffer starts with `count` entries whose strings point inside it.
    let entries =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(), count as usize) };
    Ok(entries
        .iter()
        .map(|entry| {
            let status = &entry.ServiceStatusProcess;
            (
                // SAFETY: NUL-terminated strings inside the buffer (or null).
                unsafe { wide_text(entry.lpServiceName) },
                // SAFETY: as above.
                unsafe { wide_text(entry.lpDisplayName) },
                status.dwCurrentState.0,
                status.dwProcessId,
                status.dwServiceType.0,
            )
        })
        .collect())
}

/// SERVICE_WIN32_SHARE_PROCESS (possibly combined with the user-service flags).
const SHARE_PROCESS: u32 = 0x20;
/// SERVICE_USERSERVICE_INSTANCE: the copy of a per-user service made for one sign-in session
/// (`CDPUserSvc_4a5b2`); its name changes at every sign-in.
pub const USER_SERVICE_INSTANCE: u32 = 0x80;

/// Every Win32 service (drivers are not listed), sorted by display name.
pub fn list() -> Result<Vec<Service>, SysError> {
    let manager = open_manager()?;
    let mut out = Vec::new();
    for (name, display_name, state, pid, listed_type) in enumerate(&manager)? {
        let (start_type, path, account, kind, description) = match config(manager.0, &name, true) {
            Some((start, delayed, path, account, kind, description)) => {
                (start_name(start, delayed), path, account, kind, description)
            }
            // Not readable with these rights: nothing is claimed about how it starts.
            None => ("", String::new(), String::new(), listed_type, String::new()),
        };
        let service_type = if kind & SHARE_PROCESS != 0 { "share" } else { "own" };
        let dll = if service_type == "share" {
            service_dll(&name)
        } else {
            String::new()
        };
        out.push(Service {
            group: svchost_group(&path),
            executable: executable_of(&path),
            dll,
            name,
            display_name,
            description,
            state: state_name(state).to_string(),
            start_type: start_type.to_string(),
            pid,
            service_type: service_type.to_string(),
            path,
            account,
        });
    }
    out.sort_by_key(|s| s.display_name.to_lowercase());
    Ok(out)
}

/// What the background watch compares about a service, read cheaply: one configuration query per
/// service (no description, no delayed-start flag: both "auto" kinds count as automatic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    pub name: String,
    pub display_name: String,
    /// "auto", "demand", "disabled", "boot" or "system"; "" when it could not be read.
    pub start_type: String,
    /// "" when it could not be read.
    pub path: String,
    /// The DLL svchost loads for it ("" for other services).
    pub dll: String,
    /// A per-sign-in copy of a per-user service (its name changes at every sign-in).
    pub user_instance: bool,
}

/// Every Win32 service with its start type, program and svchost DLL, for the background watch.
pub fn list_light() -> Result<Vec<ServiceConfig>, SysError> {
    let manager = open_manager()?;
    let mut out = Vec::new();
    for (name, display_name, _, _, listed_type) in enumerate(&manager)? {
        let (start_type, path, kind) = match config(manager.0, &name, false) {
            Some((start, _, path, _, kind, _)) => (start_name(start, false), path, kind),
            None => ("", String::new(), listed_type),
        };
        let dll = if kind & SHARE_PROCESS != 0 {
            service_dll(&name)
        } else {
            String::new()
        };
        out.push(ServiceConfig {
            user_instance: (kind | listed_type) & USER_SERVICE_INSTANCE != 0,
            name,
            display_name,
            start_type: start_type.to_string(),
            path,
            dll,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_installation_lists_its_core_services() {
        let started = std::time::Instant::now();
        let services = list().expect("services");
        assert!(services.len() > 50, "{} services", services.len());
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
        let rpc = services
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("RpcSs"))
            .expect("RpcSs");
        assert_eq!(rpc.state, "running");
        assert!(rpc.pid > 0);
        assert_eq!(rpc.service_type, "share");
        assert!(rpc.path.to_ascii_lowercase().contains("svchost.exe"), "{}", rpc.path);
        assert!(!rpc.path.contains('%'), "expanded: {}", rpc.path);
        assert_eq!(rpc.group, "rpcss");
        assert!(
            rpc.executable.to_ascii_lowercase().ends_with("svchost.exe"),
            "{}",
            rpc.executable
        );
        assert!(rpc.dll.to_ascii_lowercase().ends_with(".dll"), "{}", rpc.dll);
        assert!(!rpc.description.is_empty());
        assert!(services.iter().all(|s| !s.name.is_empty()));
        assert!(services.iter().any(|s| s.state == "stopped"));
        assert!(services.iter().any(|s| s.start_type == "demand"));
    }

    #[test]
    fn the_light_list_agrees_with_the_full_one() {
        let full = list().expect("services");
        let light = list_light().expect("services");
        assert_eq!(full.len(), light.len());
        let rpc = light
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("RpcSs"))
            .expect("RpcSs");
        assert!(rpc.path.to_ascii_lowercase().contains("svchost.exe"), "{}", rpc.path);
        assert!(rpc.dll.to_ascii_lowercase().ends_with(".dll"), "{}", rpc.dll);
        assert!(!rpc.user_instance);
        // Per-user service instances carry the session's suffix (`CDPUserSvc_4a5b2`).
        for instance in light.iter().filter(|s| s.user_instance) {
            assert!(instance.name.contains('_'), "{}", instance.name);
        }
        // The delayed flag is not read: those services count as plain automatic.
        assert!(light.iter().all(|s| s.start_type != "delayed-auto"));
    }

    #[test]
    fn svchost_groups_are_read_from_the_command_line() {
        assert_eq!(
            svchost_group(r"C:\Windows\system32\svchost.exe -k netsvcs -p"),
            "netsvcs"
        );
        assert_eq!(
            svchost_group(r"C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork"),
            "LocalServiceNoNetwork"
        );
        assert_eq!(svchost_group(r"C:\Program Files\App\svc.exe -k x"), "");
        assert_eq!(start_name(2, true), "delayed-auto");
        assert_eq!(start_name(3, false), "demand");
        assert_eq!(
            executable_of(r#""C:\Program Files\App\svc.exe" --run"#),
            r"C:\Program Files\App\svc.exe"
        );
        assert_eq!(
            executable_of(r"C:\Windows\system32\svchost.exe -k netsvcs -p"),
            r"C:\Windows\system32\svchost.exe"
        );
        assert_eq!(executable_of(r"C:\Tools\agent.EXE /service"), r"C:\Tools\agent.EXE");
    }
}
