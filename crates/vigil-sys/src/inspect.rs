//! A closer look at one process: the modules (DLLs) it has loaded and the Windows services it
//! hosts. Read-only. Used by the process inspector; modules loaded from user-writable folders are a
//! classic sign of DLL side-loading, and `svchost.exe` rows mean little without their services.

use serde::Serialize;
use windows::Win32::Foundation::{CloseHandle, ERROR_MORE_DATA, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
};

use crate::error::SysError;
use crate::util::from_wide;

/// One loaded module.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Module {
    pub name: String,
    pub path: String,
    /// Bytes of address space the module image occupies.
    pub size: u64,
}

/// A running service hosted by a process.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostedService {
    pub name: String,
    pub display_name: String,
}

struct Snapshot(HANDLE);

impl Drop for Snapshot {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateToolhelp32Snapshot and is closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// The modules loaded by a process, sorted by path. Protected processes and processes of other
/// users without administrator rights return an error (access denied).
pub fn modules(pid: u32) -> Result<Vec<Module>, SysError> {
    if pid <= 4 {
        return Ok(Vec::new());
    }
    // SAFETY: plain call; the handle is owned by `Snapshot`.
    let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }.map_err(|e| {
        SysError::new(
            format!("the modules of process {pid} could not be read ({})", e.message()),
            e.code().0,
        )
    })?;
    let snapshot = Snapshot(handle);
    let mut entry = MODULEENTRY32W {
        dwSize: size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };
    let mut out = Vec::new();
    // SAFETY: `entry` is a MODULEENTRY32W with dwSize set, as the API requires.
    let mut more = unsafe { Module32FirstW(snapshot.0, &mut entry) }.is_ok();
    while more {
        out.push(Module {
            name: from_wide(&entry.szModule),
            path: from_wide(&entry.szExePath),
            size: u64::from(entry.modBaseSize),
        });
        // SAFETY: as above.
        more = unsafe { Module32NextW(snapshot.0, &mut entry) }.is_ok();
    }
    out.sort_by_key(|m| m.path.to_lowercase());
    out.dedup_by(|a, b| a.path.eq_ignore_ascii_case(&b.path));
    Ok(out)
}

struct ServiceManager(windows::Win32::System::Services::SC_HANDLE);

impl Drop for ServiceManager {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW and is closed once.
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

/// Running Win32 services by hosting process id: (pid, service).
pub fn running_services() -> Result<Vec<(u32, HostedService)>, SysError> {
    // SAFETY: plain call; the handle is owned by `ServiceManager`.
    let manager = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) }.map_err(|e| {
        SysError::new(
            format!("the service list could not be read ({})", e.message()),
            e.code().0,
        )
    })?;
    let manager = ServiceManager(manager);
    let mut needed = 0u32;
    let mut count = 0u32;
    let mut resume = 0u32;
    let mut buffer: Vec<u64> = vec![0; 64 * 1024 / 8];
    loop {
        let bytes = buffer.len() * 8;
        // SAFETY: the buffer is writable for `bytes` bytes and 8-byte aligned (u64 storage); the
        // out pointers are valid locals.
        let result = unsafe {
            EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                Some(std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), bytes)),
                &mut needed,
                &mut count,
                Some(&mut resume),
                None,
            )
        };
        match result {
            Ok(()) => break,
            Err(error) if error.code() == ERROR_MORE_DATA.to_hresult() && resume == 0 => {
                buffer = vec![0; (needed as usize).div_ceil(8) + 1];
            }
            Err(error) if error.code() == ERROR_MORE_DATA.to_hresult() => {
                // Partial result with a resume handle: start over with a buffer that fits.
                resume = 0;
                buffer = vec![0; (needed as usize).div_ceil(8) * 2 + 1024];
            }
            Err(error) => {
                return Err(SysError::new(
                    format!("the service list could not be read ({})", error.message()),
                    error.code().0,
                ));
            }
        }
    }
    // SAFETY: on success the buffer starts with `count` ENUM_SERVICE_STATUS_PROCESSW entries whose
    // string pointers point inside the same buffer, which outlives this loop.
    let entries =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(), count as usize) };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        // SAFETY: both strings are NUL-terminated wide strings inside the buffer (or null).
        let name = unsafe { entry.lpServiceName.to_string() }.unwrap_or_default();
        // SAFETY: as above.
        let display_name = unsafe { entry.lpDisplayName.to_string() }.unwrap_or_default();
        out.push((
            entry.ServiceStatusProcess.dwProcessId,
            HostedService { name, display_name },
        ));
    }
    Ok(out)
}

/// The running services hosted by one process, sorted by name.
pub fn hosted_services(pid: u32) -> Result<Vec<HostedService>, SysError> {
    let mut list: Vec<HostedService> = running_services()?
        .into_iter()
        .filter(|(p, _)| *p == pid)
        .map(|(_, service)| service)
        .collect();
    list.sort_by_key(|s| s.name.to_lowercase());
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_modules_include_the_executable_and_ntdll() {
        let list = modules(std::process::id()).unwrap_or_default();
        assert!(
            list.iter().any(|m| m.name.eq_ignore_ascii_case("ntdll.dll")),
            "{list:?}"
        );
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        assert!(list.iter().any(|m| m.path.eq_ignore_ascii_case(&exe)));
    }

    #[test]
    fn kernel_processes_have_no_modules() {
        assert_eq!(modules(4).map(|m| m.len()).ok(), Some(0));
    }

    #[test]
    fn services_are_listed_with_their_host() {
        let all = running_services().unwrap_or_default();
        // Every Windows installation runs at least a few services (RPC, Event Log...).
        assert!(all.len() > 5, "{} services", all.len());
        assert!(all.iter().all(|(pid, s)| *pid > 0 && !s.name.is_empty()));
    }
}
