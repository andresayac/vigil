//! Who may change a service, and entries hidden from the lists Windows shows. READ-ONLY: security
//! descriptors, registry values and folder listings are read, nothing is changed.
//!
//! - **Permissions.** A service that runs as SYSTEM (or LocalService, NetworkService, a driver)
//!   is a way to administrator rights when a standard user can change it: its configuration
//!   (the service object), its program or the folder it runs from, its registry key, or a folder
//!   where an unquoted path with spaces lets Windows run another program first.
//! - **Hidden services.** A service key the Service Control Manager does not list: its security
//!   descriptor denies even reading it, or it was written to the registry behind the SCM's back.
//! - **Hidden scheduled tasks.** A task in the task cache or in `System32\Tasks` that the Task
//!   Scheduler API does not return, typically because its `SD` value was deleted.
//!
//! The evaluation of a DACL ([`granted`]) is a pure function over [`Ace`] lists, so it is tested
//! with security descriptors built from SDDL strings, never with the real system's.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    GetSecurityInfo, SE_FILE_OBJECT, SE_OBJECT_TYPE, SE_REGISTRY_KEY,
};
use windows::Win32::Security::{
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, REG_BINARY, REG_DWORD};
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, ENUM_SERVICE_TYPE, EnumServicesStatusExW, OpenSCManagerW,
    OpenServiceW, QueryServiceObjectSecurity, SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_STATUS, SERVICE_STATE_ALL,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

use crate::hooks::{Key, text};
use crate::util::wide;

// --------------------------------------------------------------------------- access rights

/// The groups every standard user's token holds: Everyone, Authenticated Users, Users, INTERACTIVE.
pub const STANDARD_USERS: [&str; 4] = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4"];

const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;

/// Files: write data (folders: add a file).
const FILE_WRITE_DATA: u32 = 0x0002;
/// Files: append data (folders: add a subfolder).
const FILE_APPEND_DATA: u32 = 0x0004;
/// Folders: delete any file inside, whatever its own permissions.
const FILE_DELETE_CHILD: u32 = 0x0040;
const KEY_SET_VALUE: u32 = 0x0002;
const KEY_CREATE_SUB_KEY: u32 = 0x0004;
const SERVICE_QUERY_CONFIG: u32 = 0x0001;
const SERVICE_CHANGE_CONFIG: u32 = 0x0002;
const SERVICE_QUERY_STATUS_RIGHT: u32 = 0x0004;

const INHERIT_ONLY_ACE: u8 = 0x08;

/// What a security descriptor protects: the generic rights map differently for each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Object {
    File,
    Folder,
    Key,
    Service,
}

impl Object {
    /// GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE and GENERIC_ALL, as Windows maps them.
    fn generic(self) -> [u32; 4] {
        match self {
            Object::File | Object::Folder => [0x0012_0089, 0x0012_0116, 0x0012_00A0, 0x001F_01FF],
            Object::Key => [0x0002_0019, 0x0002_0006, 0x0002_0019, 0x000F_003F],
            Object::Service => [0x0002_008D, 0x0002_0002, 0x0002_0170, 0x000F_01FF],
        }
    }

    /// The rights that let a standard user take over what runs.
    pub fn risky(self) -> u32 {
        match self {
            // Overwrite the program, or replace its permissions or owner. Deleting it alone is
            // not enough: putting a new file there needs the folder.
            Object::File => FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER,
            // Put a file next to the program (a DLL it loads, or a new copy after deleting the
            // old one) or take the folder over.
            Object::Folder => FILE_WRITE_DATA | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER,
            // Change ImagePath, ServiceDll or the account, or add a Parameters/Performance subkey.
            Object::Key => KEY_SET_VALUE | KEY_CREATE_SUB_KEY | WRITE_DAC | WRITE_OWNER,
            // Point the service at another program.
            Object::Service => SERVICE_CHANGE_CONFIG | WRITE_DAC | WRITE_OWNER,
        }
    }
}

/// One access control entry, as far as this module needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ace {
    pub allow: bool,
    /// The SID in string form ("S-1-5-32-545").
    pub sid: String,
    pub mask: u32,
    /// Applies only to objects created inside (folders, keys), not to this object.
    pub inherit_only: bool,
}

/// A discretionary ACL. `Null` means no DACL at all: everyone has full access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dacl {
    Null,
    Aces(Vec<Ace>),
}

/// A mask with its generic rights replaced by the specific rights they stand for.
pub fn map_generic(mask: u32, object: Object) -> u32 {
    let [read, write, execute, all] = object.generic();
    let mut out = mask & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
    if mask & GENERIC_READ != 0 {
        out |= read;
    }
    if mask & GENERIC_WRITE != 0 {
        out |= write;
    }
    if mask & GENERIC_EXECUTE != 0 {
        out |= execute;
    }
    if mask & GENERIC_ALL != 0 {
        out |= all;
    }
    out
}

/// The rights a token holding `sids` gets from `dacl`, walked in order like Windows' access check:
/// a right denied before it is granted stays denied. The owner's implicit rights are left out.
pub fn granted(dacl: &Dacl, sids: &[&str], object: Object) -> u32 {
    let aces = match dacl {
        Dacl::Null => return object.generic()[3],
        Dacl::Aces(aces) => aces,
    };
    let (mut allowed, mut denied) = (0u32, 0u32);
    for ace in aces.iter().filter(|a| !a.inherit_only) {
        if !sids.iter().any(|s| s.eq_ignore_ascii_case(&ace.sid)) {
            continue;
        }
        let bits = map_generic(ace.mask, object);
        if ace.allow {
            allowed |= bits & !denied;
        } else {
            denied |= bits & !allowed;
        }
    }
    allowed
}

/// The risky rights standard users hold on an object.
pub fn risky_rights(dacl: &Dacl, object: Object) -> u32 {
    granted(dacl, &STANDARD_USERS, object) & object.risky()
}

/// Readable names of the risky rights in a mask (stable keys, translated by the scan).
pub fn right_names(mask: u32, object: Object) -> Vec<&'static str> {
    let mut out = Vec::new();
    let named: &[(u32, &'static str)] = match object {
        Object::File => &[(FILE_WRITE_DATA, "write"), (FILE_APPEND_DATA, "append")],
        Object::Folder => &[(FILE_WRITE_DATA, "add_file"), (FILE_DELETE_CHILD, "delete_child")],
        Object::Key => &[(KEY_SET_VALUE, "set_value"), (KEY_CREATE_SUB_KEY, "create_subkey")],
        Object::Service => &[(SERVICE_CHANGE_CONFIG, "change_config")],
    };
    for (bit, name) in named {
        if mask & bit != 0 {
            out.push(*name);
        }
    }
    if mask & WRITE_DAC != 0 {
        out.push("change_permissions");
    }
    if mask & WRITE_OWNER != 0 {
        out.push("take_ownership");
    }
    out
}

/// Whether a service's DACL denies reading it (its status, configuration or permissions) to
/// Everyone, Administrators, SYSTEM or interactive users: the way to hide a service from `sc
/// query`, Services and every tool that lists them.
pub fn denies_query(dacl: &Dacl) -> bool {
    const WHO: [&str; 6] = [
        "S-1-1-0",
        "S-1-5-32-544",
        "S-1-5-18",
        "S-1-5-4",
        "S-1-5-11",
        "S-1-5-32-545",
    ];
    let Dacl::Aces(aces) = dacl else { return false };
    aces.iter().any(|a| {
        !a.allow
            && !a.inherit_only
            && WHO.iter().any(|w| w.eq_ignore_ascii_case(&a.sid))
            && map_generic(a.mask, Object::Service) & (SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS_RIGHT | READ_CONTROL)
                != 0
    })
}

// --------------------------------------------------------------------------- reading descriptors

/// Owns a security descriptor Windows allocated with LocalAlloc.
struct LocalSd(PSECURITY_DESCRIPTOR);

impl Drop for LocalSd {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            // SAFETY: the descriptor was allocated by the API that returned it and is freed once.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }
}

fn sid_string(sid: PSID) -> String {
    let mut out = PWSTR::null();
    // SAFETY: `sid` points inside a live ACE; `out` receives a LocalAlloc'd string freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut out) }.is_err() {
        return String::new();
    }
    // SAFETY: Windows returned a NUL-terminated string.
    let text = unsafe { out.to_string() }.unwrap_or_default();
    // SAFETY: allocated by ConvertSidToStringSidW, freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(out.0.cast())));
    }
    text
}

/// The DACL of a security descriptor; `None` when it cannot be read.
fn sd_dacl(sd: PSECURITY_DESCRIPTOR) -> Option<Dacl> {
    let mut present = BOOL(0);
    let mut defaulted = BOOL(0);
    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `sd` is a valid descriptor for the call; the out values are locals.
    unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted) }.ok()?;
    if !present.as_bool() || acl.is_null() {
        return Some(Dacl::Null);
    }
    acl_entries(acl).map(Dacl::Aces)
}

/// The entries of an ACL. Object and conditional ACEs (other than the plain callback kinds) do not
/// grant or deny the rights checked here and are skipped.
fn acl_entries(acl: *const ACL) -> Option<Vec<Ace>> {
    // SAFETY: `acl` points to a valid ACL inside a live security descriptor.
    let count = unsafe { (*acl).AceCount };
    let mut out = Vec::with_capacity(count as usize);
    for index in 0..u32::from(count) {
        let mut entry: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `index` is below the ACE count; `entry` receives a pointer inside the ACL.
        unsafe { GetAce(acl, index, &mut entry) }.ok()?;
        if entry.is_null() {
            continue;
        }
        // SAFETY: every ACE starts with an ACE_HEADER.
        let header = unsafe { *(entry as *const ACE_HEADER) };
        // 0 allowed, 1 denied, 9 allowed callback, 10 denied callback: header, mask, SID.
        let allow = match header.AceType {
            0 | 9 => true,
            1 | 10 => false,
            _ => continue,
        };
        if header.AceSize < 12 {
            continue;
        }
        // SAFETY: these ACE kinds hold the access mask right after the 4-byte header and the SID
        // right after the mask, inside the ACE's declared size (checked above for the mask).
        let mask = unsafe { std::ptr::read_unaligned((entry as *const u8).add(4) as *const u32) };
        // SAFETY: as above; the SID starts at offset 8 of the ACE.
        let sid = sid_string(PSID(unsafe { (entry as *mut u8).add(8) }.cast()));
        out.push(Ace {
            allow,
            sid,
            mask,
            inherit_only: header.AceFlags & INHERIT_ONLY_ACE != 0,
        });
    }
    Some(out)
}

/// The DACL described by an SDDL string (tests build their descriptors this way).
pub fn parse_sddl(sddl: &str) -> Option<Dacl> {
    let text = wide(sddl);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `text` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor owned by `LocalSd`.
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(text.as_ptr()), 1, &mut sd, None) }.ok()?;
    let owned = LocalSd(sd);
    sd_dacl(owned.0)
}

/// The owner (SID string) and DACL of an object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// Empty when the descriptor has no owner.
    pub owner: String,
    pub dacl: Dacl,
}

fn sd_descriptor(sd: PSECURITY_DESCRIPTOR) -> Option<Descriptor> {
    let mut owner = PSID::default();
    let mut defaulted = BOOL(0);
    // SAFETY: `sd` is a valid descriptor for the call; `owner` points inside it afterwards.
    unsafe { GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) }.ok()?;
    let owner = if owner.is_invalid() {
        String::new()
    } else {
        sid_string(owner)
    };
    Some(Descriptor {
        owner,
        dacl: sd_dacl(sd)?,
    })
}

/// The owner and DACL described by an SDDL string (tests build their descriptors this way).
pub fn parse_descriptor(sddl: &str) -> Option<Descriptor> {
    let text = wide(sddl);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `text` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor owned by `LocalSd`.
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(text.as_ptr()), 1, &mut sd, None) }.ok()?;
    let owned = LocalSd(sd);
    sd_descriptor(owned.0)
}

/// The owner and DACL of a file or folder; `None` when they cannot be read. Windows follows a
/// junction at `path`, so callers that care refuse reparse points first.
pub fn file_descriptor(path: &Path) -> Option<Descriptor> {
    let text = wide(&path.to_string_lossy());
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `text` is NUL-terminated; the descriptor returned in `sd` is owned (and freed) by
    // `LocalSd`. Reading a descriptor changes nothing.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(text.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut sd,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let owned = LocalSd(sd);
    sd_descriptor(owned.0)
}

/// The owner and DACL of an open file or folder (the handle needs `READ_CONTROL`). Unlike
/// [`file_descriptor`], nothing is looked up by name, so a link swapped in afterwards changes nothing.
pub fn handle_descriptor(handle: HANDLE) -> Option<Descriptor> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the caller keeps `handle` open for the call; the descriptor returned in `sd` is
    // owned (and freed) by `LocalSd`. Reading a descriptor changes nothing.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut sd),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let owned = LocalSd(sd);
    sd_descriptor(owned.0)
}

/// The DACL of a file, folder or registry key (`MACHINE\SYSTEM\...` for keys).
fn named_dacl(name: &str, kind: SE_OBJECT_TYPE) -> Option<Dacl> {
    let text = wide(name);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `text` is NUL-terminated; only the DACL is requested and the descriptor returned in
    // `sd` is owned (and freed) by `LocalSd`. Reading a descriptor changes nothing.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(text.as_ptr()),
            kind,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut sd,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let owned = LocalSd(sd);
    sd_dacl(owned.0)
}

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW/OpenServiceW and is closed once.
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

fn manager(access: u32) -> Option<ScHandle> {
    // SAFETY: plain call; the handle is owned by `ScHandle`.
    unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }
        .ok()
        .map(ScHandle)
}

/// The DACL of a service object; `None` when it cannot be read.
fn service_dacl(manager: &ScHandle, name: &str) -> Option<Dacl> {
    let text = wide(name);
    // SAFETY: `text` is NUL-terminated; READ_CONTROL only reads the descriptor.
    let service = ScHandle(unsafe { OpenServiceW(manager.0, PCWSTR(text.as_ptr()), READ_CONTROL) }.ok()?);
    let mut needed = 0u32;
    // SAFETY: a size query with no buffer.
    let _ = unsafe { QueryServiceObjectSecurity(service.0, DACL_SECURITY_INFORMATION.0, None, 0, &mut needed) };
    if needed == 0 || needed > 64 * 1024 {
        return None;
    }
    // 8-byte aligned storage for the self-relative descriptor.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: the buffer holds `needed` bytes and outlives the parsing below.
    unsafe {
        QueryServiceObjectSecurity(
            service.0,
            DACL_SECURITY_INFORMATION.0,
            Some(PSECURITY_DESCRIPTOR(buffer.as_mut_ptr().cast())),
            needed,
            &mut needed,
        )
    }
    .ok()?;
    sd_dacl(PSECURITY_DESCRIPTOR(buffer.as_mut_ptr().cast()))
}

/// How the Service Control Manager answers for a name found in the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// It can be opened: listed.
    Listed,
    /// It exists but its security descriptor refuses even a status query.
    Denied,
    /// The SCM does not know it: written to the registry after Windows started, without the SCM.
    Unknown,
    /// Another error.
    Error,
}

fn presence(manager: &ScHandle, name: &str) -> Presence {
    let text = wide(name);
    // SAFETY: `text` is NUL-terminated; the handle (if any) is closed right away.
    match unsafe { OpenServiceW(manager.0, PCWSTR(text.as_ptr()), SERVICE_QUERY_STATUS) } {
        Ok(handle) => {
            drop(ScHandle(handle));
            Presence::Listed
        }
        Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => Presence::Denied,
        Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => Presence::Unknown,
        Err(_) => Presence::Error,
    }
}

/// The names (lower case) of every service and driver the SCM lists to this account.
fn listed_services(manager: &ScHandle) -> Option<HashSet<String>> {
    // SERVICE_TYPE_ALL includes user and package services; older systems only know the first six
    // bits.
    for kind in [0x3FF_u32, 0x3F] {
        if let Some(names) = enumerate(manager, ENUM_SERVICE_TYPE(kind)) {
            return Some(names);
        }
    }
    None
}

fn enumerate(manager: &ScHandle, kind: ENUM_SERVICE_TYPE) -> Option<HashSet<String>> {
    let mut buffer: Vec<u64> = vec![0; 256 * 1024 / 8];
    let mut names = HashSet::new();
    let mut resume = 0u32;
    for _ in 0..64 {
        let (mut needed, mut count) = (0u32, 0u32);
        let bytes = buffer.len() * 8;
        // SAFETY: the buffer is writable for `bytes` bytes and 8-byte aligned; out values are locals.
        let result = unsafe {
            EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                kind,
                SERVICE_STATE_ALL,
                Some(std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), bytes)),
                &mut needed,
                &mut count,
                Some(&mut resume),
                None,
            )
        };
        // SAFETY: the buffer starts with `count` entries whose strings point inside it.
        let entries = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(), count as usize)
        };
        for entry in entries {
            // SAFETY: a NUL-terminated string inside the buffer.
            if let Ok(name) = unsafe { entry.lpServiceName.to_string() } {
                names.insert(name.to_lowercase());
            }
        }
        match result {
            Ok(()) => return Some(names),
            Err(e) if e.code() == windows::Win32::Foundation::ERROR_MORE_DATA.to_hresult() => {
                if needed as usize > bytes {
                    buffer = vec![0; (needed as usize).div_ceil(8) + 1024];
                }
            }
            Err(_) => return None,
        }
    }
    None
}

// --------------------------------------------------------------------------- service keys

const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";

/// A service as its registry key describes it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceKey {
    pub name: String,
    /// Type: 1 kernel driver, 2 file system driver, 0x10 own process, 0x20 shared process,
    /// 0x50/0x60 user service templates (+0x100 interactive).
    pub kind: u32,
    pub start: u32,
    /// ImagePath as written (unexpanded).
    pub image: String,
    /// ObjectName: the account ("" for drivers and LocalSystem).
    pub account: String,
    /// `Parameters\ServiceDll` (or ServiceDll on the key), for shared services.
    pub service_dll: String,
    /// Marked for deletion: gone after the next restart.
    pub pending_delete: bool,
}

impl ServiceKey {
    pub fn is_driver(&self) -> bool {
        self.kind & 0x3 != 0
    }

    pub fn is_win32(&self) -> bool {
        self.kind & 0x30 != 0
    }

    /// Runs with rights a standard user does not have.
    pub fn privileged(&self) -> bool {
        if self.is_driver() {
            return true;
        }
        let account = self.account.trim().to_lowercase();
        matches!(
            account.as_str(),
            "" | "localsystem"
                | ".\\localsystem"
                | "nt authority\\system"
                | "nt authority\\localservice"
                | "nt authority\\local service"
                | "nt authority\\networkservice"
                | "nt authority\\network service"
        )
    }
}

fn dword(values: &[(String, windows::Win32::System::Registry::REG_VALUE_TYPE, Vec<u8>)], name: &str) -> Option<u32> {
    values
        .iter()
        .find(|(n, kind, _)| n.eq_ignore_ascii_case(name) && *kind == REG_DWORD)
        .and_then(|(_, _, data)| data.get(..4))
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn string(values: &[(String, windows::Win32::System::Registry::REG_VALUE_TYPE, Vec<u8>)], name: &str) -> String {
    values
        .iter()
        .find(|(n, _, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, kind, data)| text(*kind, data))
        .unwrap_or_default()
}

/// Every service key with a service type (drivers, Win32 and user services) and an ImagePath;
/// `None` when the service database cannot be listed.
pub fn service_keys() -> Option<Vec<ServiceKey>> {
    let root = Key::open(HKEY_LOCAL_MACHINE, SERVICES, KEY_WOW64_64KEY).ok()??;
    let mut out = Vec::new();
    for name in root.subkeys()? {
        let Ok(Some(key)) = Key::open(root.0, &name, KEY_WOW64_64KEY) else {
            continue;
        };
        let Some(values) = key.raw_values() else { continue };
        let Some(kind) = dword(&values, "Type") else { continue };
        if kind & 0x33 == 0 {
            continue;
        }
        let image = string(&values, "ImagePath");
        if image.trim().is_empty() {
            continue;
        }
        let mut service_dll = String::new();
        if let Ok(Some(parameters)) = Key::open(key.0, "Parameters", KEY_WOW64_64KEY)
            && let Some(p) = parameters.raw_values()
        {
            service_dll = string(&p, "ServiceDll");
        }
        if service_dll.is_empty() {
            service_dll = string(&values, "ServiceDll");
        }
        out.push(ServiceKey {
            name,
            kind,
            start: dword(&values, "Start").unwrap_or(3),
            image,
            account: string(&values, "ObjectName"),
            service_dll,
            pending_delete: dword(&values, "DeleteFlag").unwrap_or(0) != 0,
        });
    }
    Some(out)
}

// --------------------------------------------------------------------------- paths

/// The file a service or driver ImagePath runs, expanded and absolute when it can be.
pub fn image_file(key: &ServiceKey) -> String {
    let raw = key.image.trim();
    let windir = crate::startup::expand("%SystemRoot%");
    let mut path = raw.to_string();
    for prefix in [r"\??\", r"\\?\"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            path = rest.to_string();
        }
    }
    if path.len() >= 12 && path[..12].eq_ignore_ascii_case(r"\SystemRoot\") {
        path = format!(r"{windir}\{}", &path[12..]);
    }
    let path = crate::startup::expand(&path);
    let file = if key.is_win32() {
        crate::services::executable_of(&path)
    } else {
        path
    };
    let lower = file.to_ascii_lowercase();
    if lower.starts_with(r"system32\") || lower.starts_with(r"syswow64\") {
        format!(r"{windir}\{file}")
    } else {
        file
    }
}

fn parent(path: &str) -> Option<&str> {
    let index = path.rfind('\\')?;
    // "C:\x.exe" -> "C:\" (the root keeps its backslash).
    Some(if index == 2 { &path[..3] } else { &path[..index] })
}

fn absolute(path: &str) -> bool {
    let b = path.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

/// The programs Windows tries before the real one when an ImagePath with spaces is not quoted:
/// `C:\Program Files\A B\svc.exe -k` tries `C:\Program.exe` and `C:\Program Files\A.exe` first.
/// Empty when the path is quoted, has no space before the program, or is not absolute.
pub fn unquoted_candidates(image: &str) -> Vec<String> {
    let image = image.trim();
    if image.starts_with('"') || !absolute(image) {
        return Vec::new();
    }
    let lower = image.to_ascii_lowercase();
    // The program ends at the first ".exe" followed by a space or the end.
    let end = lower
        .match_indices(".exe")
        .map(|(i, _)| i + 4)
        .find(|&i| lower.len() == i || lower.as_bytes()[i] == b' ')
        .unwrap_or(lower.len());
    let mut out = Vec::new();
    for (index, ch) in image[..end].char_indices() {
        if ch != ' ' {
            continue;
        }
        let prefix = image[..index].trim_end();
        if prefix.ends_with('\\') || prefix.len() < 4 {
            continue;
        }
        let candidate = if prefix.to_ascii_lowercase().ends_with(".exe") {
            prefix.to_string()
        } else {
            format!("{prefix}.exe")
        };
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    out
}

// --------------------------------------------------------------------------- permissions

/// One way a standard user could take over a privileged service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Weakness {
    /// "service" (the service object), "binary", "dll", "folder", "key" or "unquoted".
    pub kind: &'static str,
    /// What it concerns: a path, a registry key or the service name.
    pub target: String,
    /// The rights standard users hold ([`right_names`] keys).
    pub rights: Vec<&'static str>,
    /// Unquoted paths: a program already sits where Windows looks first.
    pub exists: bool,
}

/// A privileged service and what standard users can change about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeakService {
    pub name: String,
    pub account: String,
    pub image: String,
    pub driver: bool,
    pub issues: Vec<Weakness>,
}

/// The permission check over every privileged service.
#[derive(Clone, Debug, Default)]
pub struct Permissions {
    /// Privileged services checked.
    pub checked: usize,
    /// Descriptors that could not be read (needs administrator rights, or the object is gone).
    pub unreadable: usize,
    pub weak: Vec<WeakService>,
    /// Services whose unquoted path with spaces cannot be used here (the folders are protected).
    pub unquoted_safe: Vec<String>,
    /// Lower-case program paths whose permissions were read, with whether standard users can
    /// change the program or its folder.
    pub binaries: Vec<(String, bool)>,
}

/// Caches descriptor reads: many services share a program (svchost) or a folder.
#[derive(Default)]
struct Cache {
    files: HashMap<(String, bool), Option<u32>>,
}

impl Cache {
    fn risky(&mut self, path: &str, folder: bool) -> Option<u32> {
        let key = (path.to_lowercase(), folder);
        if let Some(found) = self.files.get(&key) {
            return *found;
        }
        let object = if folder { Object::Folder } else { Object::File };
        let found = if folder || Path::new(path).is_file() {
            named_dacl(path, SE_FILE_OBJECT).map(|d| risky_rights(&d, object))
        } else {
            None
        };
        self.files.insert(key, found);
        found
    }
}

/// Reads the permissions of every privileged service: one pass, folder results cached.
pub fn permissions(keys: &[ServiceKey]) -> Permissions {
    let mut out = Permissions::default();
    let mut cache = Cache::default();
    let manager = manager(SC_MANAGER_CONNECT);
    for key in keys.iter().filter(|k| k.privileged() && !k.pending_delete) {
        out.checked += 1;
        let mut issues = Vec::new();
        let mut unreadable = false;

        if let Some(manager) = &manager {
            match service_dacl(manager, &key.name) {
                Some(dacl) => {
                    let risky = risky_rights(&dacl, Object::Service);
                    if risky != 0 {
                        issues.push(Weakness {
                            kind: "service",
                            target: key.name.clone(),
                            rights: right_names(risky, Object::Service),
                            exists: false,
                        });
                    }
                }
                None => unreadable = true,
            }
        }

        let key_path = format!(r"MACHINE\{SERVICES}\{}", key.name);
        match named_dacl(&key_path, SE_REGISTRY_KEY) {
            Some(dacl) => {
                let risky = risky_rights(&dacl, Object::Key);
                if risky != 0 {
                    issues.push(Weakness {
                        kind: "key",
                        target: format!(r"HKLM\{SERVICES}\{}", key.name),
                        rights: right_names(risky, Object::Key),
                        exists: false,
                    });
                }
            }
            None => unreadable = true,
        }

        let binary = image_file(key);
        let mut files = vec![("binary", binary.clone())];
        if !key.service_dll.trim().is_empty() {
            files.push(("dll", crate::startup::expand(key.service_dll.trim())));
        }
        for (kind, file) in files {
            if !absolute(&file) {
                continue;
            }
            let mut writable = false;
            match cache.risky(&file, false) {
                Some(0) => {}
                Some(risky) => {
                    writable = true;
                    issues.push(Weakness {
                        kind,
                        target: file.clone(),
                        rights: right_names(risky, Object::File),
                        exists: false,
                    });
                }
                None => unreadable |= Path::new(&file).is_file(),
            }
            if let Some(folder) = parent(&file) {
                match cache.risky(folder, true) {
                    Some(0) => {}
                    Some(risky) => {
                        writable = true;
                        issues.push(Weakness {
                            kind: "folder",
                            target: folder.to_string(),
                            rights: right_names(risky, Object::Folder),
                            exists: false,
                        });
                    }
                    None => {}
                }
            }
            if kind == "binary" {
                out.binaries.push((file.to_lowercase(), writable));
            }
        }

        if key.is_win32() {
            let expanded = crate::startup::expand(key.image.trim());
            let candidates = unquoted_candidates(&expanded);
            let mut usable = false;
            for candidate in &candidates {
                let exists = Path::new(candidate).is_file();
                let folder = parent(candidate).unwrap_or_default().to_string();
                let creatable = cache.risky(&folder, true).unwrap_or(0) & (FILE_WRITE_DATA | WRITE_DAC | WRITE_OWNER);
                if exists || creatable != 0 {
                    usable = true;
                    issues.push(Weakness {
                        kind: "unquoted",
                        target: candidate.clone(),
                        rights: right_names(creatable, Object::Folder),
                        exists,
                    });
                }
            }
            if !candidates.is_empty() && !usable {
                out.unquoted_safe.push(key.name.clone());
            }
        }

        if unreadable {
            out.unreadable += 1;
        }
        if !issues.is_empty() {
            out.weak.push(WeakService {
                name: key.name.clone(),
                account: key.account.clone(),
                image: key.image.clone(),
                driver: key.is_driver(),
                issues,
            });
        }
    }
    out
}

// --------------------------------------------------------------------------- hidden services

/// A service key the Service Control Manager does not show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenService {
    pub name: String,
    pub image: String,
    pub file: String,
    pub account: String,
    pub driver: bool,
    pub start: u32,
    /// "denied" (its descriptor refuses even a status query), "unregistered" (unknown to the
    /// SCM) or "query_denied" (listed, but its descriptor denies reading it to administrators or
    /// everyone).
    pub reason: &'static str,
}

/// Service keys missing from the SCM's list, classified with `presence` (pure: tests pass fakes).
/// Keys marked for deletion are left out.
pub fn compare_services(
    keys: &[ServiceKey],
    listed: &HashSet<String>,
    mut presence: impl FnMut(&str) -> Presence,
) -> Vec<HiddenService> {
    let mut out = Vec::new();
    for key in keys {
        if key.pending_delete || listed.contains(&key.name.to_lowercase()) {
            continue;
        }
        let reason = match presence(&key.name) {
            Presence::Denied => "denied",
            Presence::Unknown => "unregistered",
            Presence::Listed | Presence::Error => continue,
        };
        out.push(HiddenService {
            name: key.name.clone(),
            image: key.image.clone(),
            file: image_file(key),
            account: key.account.clone(),
            driver: key.is_driver(),
            start: key.start,
            reason,
        });
    }
    out
}

/// Services hidden from the SCM's list or whose descriptor denies reading them; `None` when the
/// lists cannot be read.
pub fn hidden_services(keys: &[ServiceKey]) -> Option<Vec<HiddenService>> {
    let manager = manager(SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)?;
    let listed = listed_services(&manager)?;
    let mut out = compare_services(keys, &listed, |name| presence(&manager, name));
    for key in keys
        .iter()
        .filter(|k| k.is_win32() && listed.contains(&k.name.to_lowercase()))
    {
        if let Some(dacl) = service_dacl(&manager, &key.name)
            && denies_query(&dacl)
        {
            out.push(HiddenService {
                name: key.name.clone(),
                image: key.image.clone(),
                file: image_file(key),
                account: key.account.clone(),
                driver: false,
                start: key.start,
                reason: "query_denied",
            });
        }
    }
    Some(out)
}

// --------------------------------------------------------------------------- hidden tasks

const TREE: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
const CACHE_TASKS: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks";

/// A task as the task cache registers it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TreeEntry {
    /// `\Folder\Name`.
    pub path: String,
    pub id: String,
    /// Has its `SD` value: without it the Task Scheduler API does not return the task.
    pub has_sd: bool,
    pub index: Option<u32>,
}

/// A task the Task Scheduler API does not return.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HiddenTask {
    pub path: String,
    /// "no_security_descriptor", "index_zero", "not_listed", "file_only".
    pub reasons: Vec<&'static str>,
    pub command: String,
    pub arguments: String,
    pub account: String,
}

/// The result of the task comparison.
#[derive(Clone, Debug, Default)]
pub struct HiddenTasks {
    /// The task cache could be read (it needs administrator rights).
    pub registry_read: bool,
    /// `System32\Tasks` could be listed (it needs administrator rights).
    pub files_read: bool,
    /// The Task Scheduler API answered.
    pub api_read: bool,
    pub tasks: Vec<HiddenTask>,
}

/// Compares the task cache and the task files with what the API lists (pure; paths compared case
/// insensitively). Returns each hidden path with its reasons.
pub fn compare_tasks(
    tree: &[TreeEntry],
    files: &[String],
    listed: &HashSet<String>,
) -> Vec<(String, Vec<&'static str>)> {
    let mut out: Vec<(String, Vec<&'static str>)> = Vec::new();
    let in_tree: HashSet<String> = tree.iter().map(|t| t.path.to_lowercase()).collect();
    for entry in tree {
        let mut reasons = Vec::new();
        if !listed.contains(&entry.path.to_lowercase()) {
            reasons.push("not_listed");
        }
        if reasons.is_empty() {
            continue;
        }
        if !entry.has_sd {
            reasons.push("no_security_descriptor");
        }
        if entry.index == Some(0) {
            reasons.push("index_zero");
        }
        out.push((entry.path.clone(), reasons));
    }
    for file in files {
        let lower = file.to_lowercase();
        if !in_tree.contains(&lower) && !listed.contains(&lower) {
            out.push((file.clone(), vec!["file_only"]));
        }
    }
    out
}

fn tree_entries(key: &Key, prefix: &str, depth: usize, out: &mut Vec<TreeEntry>) {
    if depth > 16 {
        return;
    }
    let Some(names) = key.subkeys() else { return };
    for name in names {
        let Ok(Some(child)) = Key::open(key.0, &name, KEY_WOW64_64KEY) else {
            continue;
        };
        let path = format!(r"{prefix}\{name}");
        if let Some(values) = child.raw_values() {
            let id = string(&values, "Id");
            if !id.is_empty() {
                out.push(TreeEntry {
                    path: path.clone(),
                    id,
                    has_sd: values
                        .iter()
                        .any(|(n, kind, data)| n.eq_ignore_ascii_case("SD") && *kind == REG_BINARY && !data.is_empty()),
                    index: dword(&values, "Index"),
                });
            }
        }
        tree_entries(&child, &path, depth + 1, out);
    }
}

fn task_files(dir: &Path, prefix: &str, depth: usize, out: &mut Vec<String>) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    if depth > 16 {
        return true;
    }
    for entry in entries.flatten() {
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        // Links are never followed.
        if meta.file_type().is_symlink() || std::os::windows::fs::MetadataExt::file_attributes(&meta) & 0x400 != 0 {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let path = format!(r"{prefix}\{name}");
        if meta.is_dir() {
            task_files(&entry.path(), &path, depth + 1, out);
        } else {
            out.push(path);
        }
    }
    true
}

/// The program and arguments of the first "exec" action in a task cache `Actions` value. The
/// layout is undocumented: a version word, optionally the context ("Author") as a length-prefixed
/// UTF-16 string, then actions tagged 0x6666 (exec) with length-prefixed id, program, arguments and
/// working folder. Anything that does not fit gives `None`.
pub fn parse_actions(blob: &[u8]) -> Option<(String, String)> {
    fn read_string(blob: &[u8], at: &mut usize) -> Option<String> {
        let len = u32::from_le_bytes(blob.get(*at..*at + 4)?.try_into().ok()?) as usize;
        if !len.is_multiple_of(2) || len > 8192 {
            return None;
        }
        let bytes = blob.get(*at + 4..*at + 4 + len)?;
        *at += 4 + len;
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        Some(String::from_utf16_lossy(&units).trim_end_matches('\0').to_string())
    }
    let mut at = 2;
    while at + 2 <= blob.len() {
        if blob[at] == 0x66 && blob[at + 1] == 0x66 {
            let mut cursor = at + 2;
            if let (Some(_id), Some(program), Some(arguments)) = (
                read_string(blob, &mut cursor),
                read_string(blob, &mut cursor),
                read_string(blob, &mut cursor),
            ) && !program.trim().is_empty()
            {
                return Some((program, arguments));
            }
        }
        at += 1;
    }
    None
}

/// Tasks present in the task cache or `System32\Tasks` that the Task Scheduler API does not
/// return. Without administrator rights neither source can be read and the result says so.
pub fn hidden_tasks() -> HiddenTasks {
    let mut out = HiddenTasks::default();
    let listed: HashSet<String> = match crate::tasks::list() {
        Ok(tasks) => {
            out.api_read = true;
            tasks.into_iter().map(|t| t.path.to_lowercase()).collect()
        }
        Err(_) => return out,
    };
    let mut tree = Vec::new();
    if let Ok(Some(root)) = Key::open(HKEY_LOCAL_MACHINE, TREE, KEY_WOW64_64KEY)
        && root.subkeys().is_some()
    {
        out.registry_read = true;
        tree_entries(&root, "", 0, &mut tree);
    }
    let windir = crate::startup::expand("%SystemRoot%");
    let tasks_dir = format!(r"{windir}\System32\Tasks");
    let mut files = Vec::new();
    out.files_read = task_files(Path::new(&tasks_dir), "", 0, &mut files);
    if !out.registry_read && !out.files_read {
        return out;
    }
    let ids: HashMap<String, String> = tree.iter().map(|t| (t.path.to_lowercase(), t.id.clone())).collect();
    for (path, reasons) in compare_tasks(&tree, &files, &listed) {
        let mut task = HiddenTask {
            path: path.clone(),
            reasons,
            ..HiddenTask::default()
        };
        // The definition file first (it has the account too), then the cache's Actions value.
        if let Some(bytes) = read_at_most(&format!("{tasks_dir}{path}"), 1024 * 1024) {
            let parsed = crate::tasks::from_xml(&path, &crate::tasks::decode_task_file(&bytes));
            task.account = parsed.account.clone();
            if let Some(action) = parsed.actions.iter().find(|a| a.kind == "exec") {
                task.command = action.command.clone();
                task.arguments = action.arguments.clone();
            }
        }
        if task.command.is_empty()
            && let Some(id) = ids.get(&path.to_lowercase())
            && let Ok(Some(key)) = Key::open(HKEY_LOCAL_MACHINE, &format!(r"{CACHE_TASKS}\{id}"), KEY_WOW64_64KEY)
            && let Some(values) = key.raw_values()
            && let Some((_, _, blob)) = values.iter().find(|(n, _, _)| n.eq_ignore_ascii_case("Actions"))
            && let Some((program, arguments)) = parse_actions(blob)
        {
            task.command = program;
            task.arguments = arguments;
        }
        out.tasks.push(task);
    }
    out
}

/// A file of at most `limit` bytes (`None` when it is larger or cannot be read), read without ever
/// holding more than `limit + 1` bytes.
fn read_at_most(path: &str, limit: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= limit).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dacl(sddl: &str) -> Dacl {
        parse_sddl(sddl).expect("valid SDDL")
    }

    #[test]
    fn sddl_entries_are_read() {
        let d = dacl("D:(A;;GA;;;SY)(D;;WD;;;WD)(A;OICIIO;GW;;;AU)");
        let Dacl::Aces(aces) = d else { panic!("aces expected") };
        assert_eq!(aces.len(), 3);
        assert!(aces[0].allow && aces[0].sid == "S-1-5-18" && aces[0].mask == GENERIC_ALL);
        assert!(!aces[1].allow && aces[1].sid == "S-1-1-0" && aces[1].mask == WRITE_DAC);
        assert!(aces[2].inherit_only && aces[2].sid == "S-1-5-11");
        assert_eq!(dacl("D:NO_ACCESS_CONTROL"), Dacl::Null);
    }

    #[test]
    fn standard_users_rights_are_evaluated_in_order() {
        // Program Files style: users read and execute only; inherit-only write does not apply.
        let protected = dacl("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GW;;;AU)");
        assert_eq!(risky_rights(&protected, Object::Folder), 0);
        assert_eq!(risky_rights(&protected, Object::File), 0);
        // A folder created at the root of the drive: Authenticated Users may modify it.
        let modify = dacl("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;AU)");
        assert_ne!(risky_rights(&modify, Object::Folder) & FILE_WRITE_DATA, 0);
        assert_eq!(
            right_names(risky_rights(&modify, Object::File), Object::File),
            vec!["write", "append"]
        );
        // An explicit deny before the allow wins.
        let denied = dacl("D:(D;;0x2;;;WD)(A;;FA;;;WD)");
        assert_eq!(risky_rights(&denied, Object::Folder) & FILE_WRITE_DATA, 0);
        assert_ne!(risky_rights(&denied, Object::Folder) & FILE_DELETE_CHILD, 0);
        // An allow before the deny wins (non-canonical order, evaluated as Windows does).
        let late_deny = dacl("D:(A;;FA;;;WD)(D;;0x2;;;WD)");
        assert_ne!(risky_rights(&late_deny, Object::Folder) & FILE_WRITE_DATA, 0);
        // No DACL: everyone has every right.
        assert_eq!(risky_rights(&Dacl::Null, Object::Key), Object::Key.risky());
        // Rights for Administrators only never count.
        assert_eq!(risky_rights(&dacl("D:(A;;GA;;;BA)"), Object::Key), 0);
    }

    #[test]
    fn service_object_rights_and_hiding() {
        // Windows' default for a service: interactive users query and start, nothing more.
        let default = dacl("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)");
        assert_eq!(risky_rights(&default, Object::Service), 0);
        assert!(!denies_query(&default));
        // Users may change the configuration (DC = SERVICE_CHANGE_CONFIG).
        let weak = dacl("D:(A;;CCDCLCSWRPWPDTLOCRRC;;;BU)");
        assert_eq!(
            right_names(risky_rights(&weak, Object::Service), Object::Service),
            vec!["change_config"]
        );
        // Generic write maps to SERVICE_CHANGE_CONFIG.
        let generic = dacl("D:(A;;GW;;;AU)");
        assert_ne!(risky_rights(&generic, Object::Service) & SERVICE_CHANGE_CONFIG, 0);
        // The hiding technique: deny query and read to everyone, administrators and SYSTEM.
        let hidden = dacl("D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)");
        assert!(denies_query(&hidden));
    }

    #[test]
    fn registry_key_rights() {
        let weak = dacl("D:(A;;KA;;;SY)(A;;0x20006;;;BU)");
        assert_eq!(
            right_names(risky_rights(&weak, Object::Key), Object::Key),
            vec!["set_value", "create_subkey"]
        );
        let read_only = dacl("D:(A;;KA;;;SY)(A;;KR;;;BU)");
        assert_eq!(risky_rights(&read_only, Object::Key), 0);
    }

    #[test]
    fn unquoted_candidates_follow_windows_search() {
        assert_eq!(
            unquoted_candidates(r"C:\Program Files\Contoso Sync\Sync Agent\agent.exe -service"),
            vec![
                r"C:\Program.exe".to_string(),
                r"C:\Program Files\Contoso.exe".to_string(),
                r"C:\Program Files\Contoso Sync\Sync.exe".to_string(),
            ]
        );
        // Quoted, no space before the program, or relative: nothing to hijack.
        assert!(unquoted_candidates(r#""C:\Program Files\Contoso\agent.exe" -k"#).is_empty());
        assert!(unquoted_candidates(r"C:\Windows\System32\svchost.exe -k netsvcs").is_empty());
        assert!(unquoted_candidates(r"system32\drivers\x.sys").is_empty());
        // A path without .exe: every space counts.
        assert_eq!(
            unquoted_candidates(r"C:\Tools\My Svc\run"),
            vec![r"C:\Tools\My.exe".to_string()]
        );
        assert_eq!(parent(r"C:\Program.exe"), Some(r"C:\"));
        assert_eq!(parent(r"C:\Program Files\Contoso.exe"), Some(r"C:\Program Files"));
    }

    fn key(name: &str, kind: u32, image: &str, account: &str) -> ServiceKey {
        ServiceKey {
            name: name.into(),
            kind,
            start: 2,
            image: image.into(),
            account: account.into(),
            ..ServiceKey::default()
        }
    }

    #[test]
    fn hidden_services_are_classified() {
        let keys = vec![
            key("Spooler", 0x10, r"%SystemRoot%\System32\spoolsv.exe", "LocalSystem"),
            key(
                "FabrikamHidden",
                0x10,
                r"C:\ProgramData\Fabrikam\svc.exe",
                "LocalSystem",
            ),
            key("ContosoNew", 0x10, r"C:\Contoso\agent.exe", "LocalSystem"),
            ServiceKey {
                pending_delete: true,
                ..key("OldUpdater", 0x10, r"C:\Old\upd.exe", "LocalSystem")
            },
        ];
        let listed: HashSet<String> = ["spooler".to_string()].into();
        let hidden = compare_services(&keys, &listed, |name| match name {
            "FabrikamHidden" => Presence::Denied,
            "ContosoNew" => Presence::Unknown,
            _ => Presence::Error,
        });
        let found: Vec<(&str, &str)> = hidden.iter().map(|h| (h.name.as_str(), h.reason)).collect();
        assert_eq!(
            found,
            vec![("FabrikamHidden", "denied"), ("ContosoNew", "unregistered")]
        );
    }

    #[test]
    fn privileged_accounts() {
        assert!(key("a", 0x10, "x", "").privileged());
        assert!(key("a", 0x10, "x", "NT AUTHORITY\\NetworkService").privileged());
        assert!(key("a", 0x1, "x", "").privileged());
        assert!(!key("a", 0x10, "x", r".\jdoe").privileged());
        assert!(!key("a", 0x10, "x", r"NT SERVICE\Contoso").privileged());
    }

    #[test]
    fn hidden_tasks_are_found_three_ways() {
        let tree = vec![
            TreeEntry {
                path: r"\Microsoft\Windows\Defrag\ScheduledDefrag".into(),
                id: "{1}".into(),
                has_sd: true,
                index: Some(3),
            },
            TreeEntry {
                path: r"\ContosoUpdate".into(),
                id: "{2}".into(),
                has_sd: false,
                index: Some(0),
            },
        ];
        let files = vec![
            r"\Microsoft\Windows\Defrag\ScheduledDefrag".to_string(),
            r"\ContosoUpdate".to_string(),
            r"\Leftover".to_string(),
        ];
        let listed: HashSet<String> = [r"\microsoft\windows\defrag\scheduleddefrag".to_string()].into();
        let found = compare_tasks(&tree, &files, &listed);
        assert_eq!(
            found,
            vec![
                (
                    r"\ContosoUpdate".to_string(),
                    vec!["not_listed", "no_security_descriptor", "index_zero"]
                ),
                (r"\Leftover".to_string(), vec!["file_only"]),
            ]
        );
    }

    fn utf16(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let bytes: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        out.extend((bytes.len() as u32).to_le_bytes());
        out.extend(bytes);
        out
    }

    #[test]
    fn task_cache_actions_are_parsed() {
        let mut blob = vec![0x03, 0x00];
        blob.extend(utf16("Author"));
        blob.extend([0x66, 0x66]);
        blob.extend(utf16(""));
        blob.extend(utf16(r"C:\Users\Public\contoso.exe"));
        blob.extend(utf16("--quiet"));
        blob.extend(utf16(""));
        assert_eq!(
            parse_actions(&blob),
            Some((r"C:\Users\Public\contoso.exe".to_string(), "--quiet".to_string()))
        );
        assert_eq!(parse_actions(&[0x03, 0x00, 0x66, 0x66, 0xff]), None);
    }

    /// Prints counts only (run by hand): `cargo test -p vigil-sys svcsec_live -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn svcsec_live_counts() {
        let started = std::time::Instant::now();
        let keys = service_keys().expect("service keys");
        let hidden = hidden_services(&keys).expect("service lists");
        let perms = permissions(&keys);
        let tasks = hidden_tasks();
        println!(
            "keys {} hidden services {} | privileged checked {} unreadable {} weak {} (issues {}) unquoted safe {} | tasks api {} registry {} files {} hidden {} | {:?}",
            keys.len(),
            hidden.len(),
            perms.checked,
            perms.unreadable,
            perms.weak.len(),
            perms.weak.iter().map(|w| w.issues.len()).sum::<usize>(),
            perms.unquoted_safe.len(),
            tasks.api_read,
            tasks.registry_read,
            tasks.files_read,
            tasks.tasks.len(),
            started.elapsed()
        );
        let mut kinds: HashMap<&str, usize> = HashMap::new();
        for issue in perms.weak.iter().flat_map(|w| &w.issues) {
            *kinds.entry(issue.kind).or_default() += 1;
        }
        println!("issue kinds {kinds:?}");
        let mut reasons: HashMap<&str, usize> = HashMap::new();
        for h in &hidden {
            *reasons.entry(h.reason).or_default() += 1;
        }
        println!("hidden reasons {reasons:?}");
    }
}
