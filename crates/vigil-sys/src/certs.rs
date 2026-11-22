//! The certificates Windows trusts: the root stores (the computer's, your account's, and those set
//! by Group Policy or an enterprise), the intermediate CA stores and Trusted Publishers.
//! Read-only: every store is opened with `CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG`
//! through `CERT_STORE_PROV_SYSTEM_REGISTRY`, which reads one registry store and not the merged
//! view, so a root your account added is told apart from the computer's.
//!
//! Whether a root belongs to Microsoft's Trusted Root Program is decided offline, from the list
//! Windows itself keeps: automatic root update caches the signed list (`authroot.stl`) in
//! `HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate\EncodedCtl`. It is a
//! certificate trust list (CTL); `CertCreateCTLContext` decodes it and each entry's
//! `SubjectIdentifier` is the SHA-1 thumbprint of a root in the program. Roots Windows downloaded
//! from that program also sit in the AuthRoot store and carry the root-program property
//! (`CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID`); both count as well, so the check still works on a
//! computer whose cached list is missing.

use std::collections::BTreeSet;

use windows::Win32::Foundation::FILETIME;
use windows::Win32::Security::Cryptography::{
    CERT_BASIC_CONSTRAINTS2_INFO, CERT_CONTEXT, CERT_FIND_SHA1_HASH, CERT_FRIENDLY_NAME_PROP_ID, CERT_NAME_ISSUER_FLAG,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
    CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID, CERT_SHA1_HASH_PROP_ID, CERT_SHA256_HASH_PROP_ID,
    CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_REGISTRY_W, CERT_STORE_READONLY_FLAG,
    CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_INTEGER_BLOB, CTL_USAGE, CertCloseStore,
    CertCompareCertificateName, CertCreateCTLContext, CertEnumCertificatesInStore, CertFindCertificateInStore,
    CertFindExtension, CertFreeCTLContext, CertFreeCertificateContext, CertGetCertificateContextProperty,
    CertGetEnhancedKeyUsage, CertGetNameStringW, CertOpenStore, CryptDecodeObjectEx, HCERTSTORE, PKCS_7_ASN_ENCODING,
    X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2, szOID_BASIC_CONSTRAINTS2,
};
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, REG_BINARY};

use crate::hooks::Key;
use crate::util::{filetime_to_unix_ms, from_wide, wide};

/// The most certificates read from one store (a bound, not an expected size).
const MAX_PER_STORE: usize = 2_000;

/// `CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY` and `..._ENTERPRISE` (location id << 16).
const LOCAL_MACHINE_GROUP_POLICY: u32 = 8 << 16;
const LOCAL_MACHINE_ENTERPRISE: u32 = 9 << 16;

/// Where a store lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The computer's stores (`HKLM\SOFTWARE\Microsoft\SystemCertificates`).
    Machine,
    /// Your account's stores (`HKCU\Software\Microsoft\SystemCertificates`).
    User,
    /// Set by Group Policy (`HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates`).
    Policy,
    /// Set by an Active Directory enterprise (`HKLM\SOFTWARE\Microsoft\EnterpriseCertificates`).
    Enterprise,
}

impl Scope {
    pub fn id(self) -> &'static str {
        match self {
            Self::Machine => "machine",
            Self::User => "user",
            Self::Policy => "policy",
            Self::Enterprise => "enterprise",
        }
    }

    fn location(self) -> u32 {
        match self {
            Self::Machine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
            Self::User => CERT_SYSTEM_STORE_CURRENT_USER,
            Self::Policy => LOCAL_MACHINE_GROUP_POLICY,
            Self::Enterprise => LOCAL_MACHINE_ENTERPRISE,
        }
    }

    /// The registry key of a store's certificates, relative to the hive [`Scope::hive_is_user`].
    pub fn registry_path(self, store: &str) -> String {
        match self {
            Self::Machine => format!(r"SOFTWARE\Microsoft\SystemCertificates\{store}\Certificates"),
            Self::User => format!(r"Software\Microsoft\SystemCertificates\{store}\Certificates"),
            Self::Policy => format!(r"SOFTWARE\Policies\Microsoft\SystemCertificates\{store}\Certificates"),
            Self::Enterprise => format!(r"SOFTWARE\Microsoft\EnterpriseCertificates\{store}\Certificates"),
        }
    }

    pub fn hive_is_user(self) -> bool {
        self == Self::User
    }
}

/// The stores read, in order. AuthRoot holds the roots Windows downloaded from Microsoft's program
/// on demand (dozens to hundreds): it is read for its thumbprints only (see [`root_program`]).
pub const STORES: &[(Scope, &str)] = &[
    (Scope::Machine, "Root"),
    (Scope::User, "Root"),
    (Scope::Policy, "Root"),
    (Scope::Enterprise, "Root"),
    (Scope::Machine, "CA"),
    (Scope::User, "CA"),
    (Scope::Machine, "TrustedPublisher"),
    (Scope::User, "TrustedPublisher"),
    (Scope::Policy, "TrustedPublisher"),
];

/// One certificate as a store holds it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Certificate {
    /// "machine", "user", "policy" or "enterprise".
    pub scope: String,
    /// "Root", "CA" or "TrustedPublisher".
    pub store: String,
    pub subject: String,
    pub issuer: String,
    /// The friendly name the store gives it ("" when none).
    pub friendly_name: String,
    /// SHA-1 thumbprint, upper-case hex (the name Windows files it under).
    pub sha1: String,
    pub sha256: String,
    /// Validity, Unix ms.
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    /// Issuer and subject are the same name.
    pub self_signed: bool,
    /// The basic-constraints "CA" bit; `None` when the certificate has no such extension (old
    /// roots often have none, and then Windows treats a root as a CA).
    pub ca: Option<bool>,
    /// Enhanced key usages (OIDs); empty means every usage.
    pub usages: Vec<String>,
    /// When its registry key was last written (Unix ms): close to when it was added.
    pub added_ms: Option<i64>,
    /// Carries the Microsoft root-program property (set by automatic root update).
    pub program_property: bool,
}

/// What [`read`] found.
#[derive(Debug, Clone, Default)]
pub struct Stores {
    pub certificates: Vec<Certificate>,
    /// Stores that exist but could not be opened, as "scope\Store".
    pub unreadable: Vec<String>,
}

/// Reads every store in [`STORES`]. A store that does not exist is simply empty.
pub fn read() -> Stores {
    let mut out = Stores::default();
    for &(scope, store) in STORES {
        match open_store(scope, store) {
            Ok(Some(handle)) => {
                let mut list = certificates_in(handle.0, scope.id(), store);
                for cert in &mut list {
                    cert.added_ms = added_ms(scope, store, &cert.sha1);
                }
                out.certificates.extend(list);
            }
            Ok(None) => {}
            Err(()) => out.unreadable.push(format!(r"{}\{store}", scope.id())),
        }
    }
    out
}

/// The SHA-1 thumbprints (upper-case hex) of Microsoft's Trusted Root Program as this computer
/// knows them offline: the cached root list (`EncodedCtl`) plus the AuthRoot store. `None` when
/// neither could be read.
pub fn root_program() -> Option<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let mut known = false;
    if let Ok(Some(key)) = Key::open(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate",
        KEY_WOW64_64KEY,
    ) && let Some(values) = key.raw_values()
        && let Some((_, _, data)) = values
            .iter()
            .find(|(name, kind, _)| name.eq_ignore_ascii_case("EncodedCtl") && *kind == REG_BINARY)
        && let Some(list) = ctl_thumbprints(data)
    {
        known = true;
        out.extend(list);
    }
    if let Ok(Some(key)) = Key::open(
        HKEY_LOCAL_MACHINE,
        &Scope::Machine.registry_path("AuthRoot"),
        KEY_WOW64_64KEY,
    ) && let Some(names) = key.subkeys()
    {
        known = true;
        out.extend(names.into_iter().map(|n| n.to_uppercase()));
    }
    known.then_some(out)
}

/// The SHA-1 thumbprints listed by an encoded certificate trust list; `None` when it does not
/// decode.
pub fn ctl_thumbprints(encoded: &[u8]) -> Option<Vec<String>> {
    if encoded.is_empty() {
        return None;
    }
    // SAFETY: `encoded` is a valid slice for the call; the returned context is freed below and
    // only read in between.
    let context = unsafe { CertCreateCTLContext((X509_ASN_ENCODING | PKCS_7_ASN_ENCODING).0, encoded) };
    if context.is_null() {
        return None;
    }
    let mut out = Vec::new();
    // SAFETY: `context` is a live CTL context; `pCtlInfo` and its entry array belong to it.
    unsafe {
        let info = (*context).pCtlInfo;
        if !info.is_null() && !(*info).rgCTLEntry.is_null() {
            let entries = std::slice::from_raw_parts((*info).rgCTLEntry, (*info).cCTLEntry as usize);
            for entry in entries {
                out.push(hex(blob(&entry.SubjectIdentifier)));
            }
        }
        let _ = CertFreeCTLContext(Some(context));
    }
    Some(out)
}

/// The subject of a root by thumbprint, read from the machine's or your account's Root store
/// (for an alert about a root that just appeared). `None` when it is not there.
pub fn root_subject(scope: Scope, sha1: &str) -> Option<String> {
    let bytes = unhex(sha1)?;
    let handle = open_store(scope, "Root").ok()??;
    let mut hash = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    // SAFETY: the store is open; `hash` points to `bytes`, alive for the call; the found context
    // is read and freed here.
    unsafe {
        let found = CertFindCertificateInStore(
            handle.0,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SHA1_HASH,
            Some((&mut hash as *mut CRYPT_INTEGER_BLOB).cast()),
            None,
        );
        if found.is_null() {
            return None;
        }
        let subject = name_of(found, false);
        let _ = CertFreeCertificateContext(Some(found));
        Some(subject)
    }
}

// ------------------------------------------------------------------------------- stores

struct Store(pub(crate) HCERTSTORE);

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: the handle came from CertOpenStore and is closed once.
        unsafe {
            let _ = CertCloseStore(Some(self.0), 0);
        }
    }
}

/// `Ok(None)`: the store does not exist; `Err`: it exists and cannot be opened.
fn open_store(scope: Scope, store: &str) -> Result<Option<Store>, ()> {
    // Tell "missing" from "no access" by the registry key first: CertOpenStore reports both as a
    // failure.
    let hive = if scope.hive_is_user() {
        HKEY_CURRENT_USER
    } else {
        HKEY_LOCAL_MACHINE
    };
    let key = scope.registry_path(store);
    let parent = key.trim_end_matches(r"\Certificates");
    match Key::open(hive, parent, KEY_WOW64_64KEY) {
        Ok(Some(_)) => {}
        Ok(None) => return Ok(None),
        Err(()) => return Err(()),
    }
    let name = wide(store);
    let flags = CERT_OPEN_STORE_FLAGS(scope.location()) | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG;
    // SAFETY: `name` is a NUL-terminated UTF-16 store name alive for the call; the handle is
    // owned by `Store`, which closes it.
    let handle = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_REGISTRY_W,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            flags,
            Some(name.as_ptr().cast()),
        )
    };
    match handle {
        Ok(h) if !h.is_invalid() => Ok(Some(Store(h))),
        _ => Err(()),
    }
}

/// The certificates of an open store (also used on a memory store by the tests).
fn certificates_in(store: HCERTSTORE, scope: &str, store_name: &str) -> Vec<Certificate> {
    let mut out = Vec::new();
    let mut previous: *mut CERT_CONTEXT = std::ptr::null_mut();
    loop {
        // SAFETY: `previous` is null or the context the last call returned; the enumeration frees
        // it and returns the next one (or null at the end, which frees nothing further).
        let context = unsafe {
            CertEnumCertificatesInStore(store, (!previous.is_null()).then_some(previous as *const CERT_CONTEXT))
        };
        if context.is_null() {
            break;
        }
        previous = context;
        // SAFETY: `context` is a live certificate context from the enumeration.
        out.push(unsafe { describe(context, scope, store_name) });
        if out.len() >= MAX_PER_STORE {
            // SAFETY: the enumeration did not free the last context it returned.
            unsafe {
                let _ = CertFreeCertificateContext(Some(context));
            }
            break;
        }
    }
    out
}

/// # Safety
/// `context` must be a live certificate context.
unsafe fn describe(context: *const CERT_CONTEXT, scope: &str, store: &str) -> Certificate {
    // SAFETY: the caller guarantees `context`; `pCertInfo` belongs to it.
    unsafe {
        let info = (*context).pCertInfo;
        let mut cert = Certificate {
            scope: scope.to_string(),
            store: store.to_string(),
            subject: name_of(context, false),
            issuer: name_of(context, true),
            friendly_name: friendly_name(context),
            sha1: hex(&property(context, CERT_SHA1_HASH_PROP_ID).unwrap_or_default()),
            sha256: hex(&property(context, CERT_SHA256_HASH_PROP_ID).unwrap_or_default()),
            usages: usages(context),
            program_property: property(context, CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID).is_some(),
            ..Certificate::default()
        };
        if !info.is_null() {
            cert.not_before_ms = filetime_ms(&(*info).NotBefore);
            cert.not_after_ms = filetime_ms(&(*info).NotAfter);
            cert.self_signed =
                CertCompareCertificateName((*context).dwCertEncodingType, &(*info).Subject, &(*info).Issuer).as_bool();
            cert.ca = basic_ca(info);
        }
        cert
    }
}

/// # Safety
/// `context` must be a live certificate context.
unsafe fn name_of(context: *const CERT_CONTEXT, issuer: bool) -> String {
    let flags = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };
    // SAFETY: the first call asks for the length, the second fills a buffer of that length.
    unsafe {
        let len = CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, None);
        if len <= 1 {
            return String::new();
        }
        let mut buffer = vec![0u16; len as usize];
        CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, Some(&mut buffer));
        from_wide(&buffer)
    }
}

/// # Safety
/// `context` must be a live certificate context.
unsafe fn property(context: *const CERT_CONTEXT, id: u32) -> Option<Vec<u8>> {
    let mut size = 0u32;
    // SAFETY: the first call asks for the size, the second fills a buffer of that size.
    unsafe {
        CertGetCertificateContextProperty(context, id, None, &mut size).ok()?;
        let mut data = vec![0u8; size as usize];
        CertGetCertificateContextProperty(context, id, Some(data.as_mut_ptr().cast()), &mut size).ok()?;
        data.truncate(size as usize);
        Some(data)
    }
}

/// # Safety
/// `context` must be a live certificate context.
unsafe fn friendly_name(context: *const CERT_CONTEXT) -> String {
    // SAFETY: forwarded from the caller.
    let Some(data) = (unsafe { property(context, CERT_FRIENDLY_NAME_PROP_ID) }) else {
        return String::new();
    };
    let units: Vec<u16> = data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    from_wide(&units)
}

/// # Safety
/// `context` must be a live certificate context.
unsafe fn usages(context: *const CERT_CONTEXT) -> Vec<String> {
    let mut size = 0u32;
    // SAFETY: the first call asks for the size; the buffer is u64-aligned (the structure holds
    // pointers) and at least that large; the strings it points to live inside the buffer.
    unsafe {
        if CertGetEnhancedKeyUsage(context, 0, None, &mut size).is_err() || size == 0 {
            return Vec::new();
        }
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let usage = buffer.as_mut_ptr().cast::<CTL_USAGE>();
        if CertGetEnhancedKeyUsage(context, 0, Some(usage), &mut size).is_err() {
            return Vec::new();
        }
        let usage = &*usage;
        if usage.rgpszUsageIdentifier.is_null() {
            return Vec::new();
        }
        std::slice::from_raw_parts(usage.rgpszUsageIdentifier, usage.cUsageIdentifier as usize)
            .iter()
            .filter_map(|p| p.to_string().ok())
            .collect()
    }
}

/// # Safety
/// `info` must be the `CERT_INFO` of a live certificate context.
unsafe fn basic_ca(info: *const windows::Win32::Security::Cryptography::CERT_INFO) -> Option<bool> {
    // SAFETY: the extension array belongs to `info`; the decoded structure is written into a
    // local of the right type, its size checked by the call.
    unsafe {
        if (*info).rgExtension.is_null() || (*info).cExtension == 0 {
            return None;
        }
        let extensions = std::slice::from_raw_parts((*info).rgExtension, (*info).cExtension as usize);
        let extension = CertFindExtension(szOID_BASIC_CONSTRAINTS2, extensions);
        if extension.is_null() {
            return None;
        }
        let mut decoded = CERT_BASIC_CONSTRAINTS2_INFO::default();
        let mut size = std::mem::size_of::<CERT_BASIC_CONSTRAINTS2_INFO>() as u32;
        CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_BASIC_CONSTRAINTS2,
            blob(&(*extension).Value),
            0,
            None,
            Some((&mut decoded as *mut CERT_BASIC_CONSTRAINTS2_INFO).cast()),
            &mut size,
        )
        .ok()?;
        Some(decoded.fCA.as_bool())
    }
}

/// When the registry key of a certificate was last written (close to when it was added).
fn added_ms(scope: Scope, store: &str, sha1: &str) -> Option<i64> {
    if sha1.is_empty() {
        return None;
    }
    let hive = if scope.hive_is_user() {
        HKEY_CURRENT_USER
    } else {
        HKEY_LOCAL_MACHINE
    };
    let path = format!(r"{}\{sha1}", scope.registry_path(store));
    Key::open(hive, &path, KEY_WOW64_64KEY).ok()??.last_write_ms()
}

// ------------------------------------------------------------------------------- helpers

/// # Safety
/// `blob` must describe `cbData` readable bytes at `pbData` (or be empty).
unsafe fn blob_raw(blob: &CRYPT_INTEGER_BLOB) -> &[u8] {
    if blob.pbData.is_null() || blob.cbData == 0 {
        &[]
    } else {
        // SAFETY: forwarded from the caller.
        unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) }
    }
}

fn blob(value: &CRYPT_INTEGER_BLOB) -> &[u8] {
    // SAFETY: every blob passed here belongs to a context or structure CryptoAPI filled.
    unsafe { blob_raw(value) }
}

fn filetime_ms(time: &FILETIME) -> i64 {
    filetime_to_unix_ms((i64::from(time.dwHighDateTime) << 32) | i64::from(time.dwLowDateTime))
}

/// Upper-case hex, as Windows names certificates in the registry.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::Cryptography::{
        CERT_STORE_ADD_ALWAYS, CERT_STORE_PROV_MEMORY, CertAddEncodedCertificateToStore,
    };

    const ROOT: &[u8] = include_bytes!("../tests/data/certs/contoso-test-root.der");
    const LEAF: &[u8] = include_bytes!("../tests/data/certs/localhost-leaf.der");

    /// A memory store holding the two test certificates: nothing touches the real stores.
    fn memory_store() -> Store {
        // SAFETY: a memory store needs no parameter; the handle is owned by `Store`.
        let handle = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_MEMORY,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                CERT_OPEN_STORE_FLAGS(0),
                None,
            )
        }
        .expect("memory store");
        let store = Store(handle);
        for der in [ROOT, LEAF] {
            // SAFETY: the store is open; `der` is a valid slice for the call.
            unsafe {
                CertAddEncodedCertificateToStore(
                    Some(store.0),
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    der,
                    CERT_STORE_ADD_ALWAYS,
                    None,
                )
            }
            .expect("add");
        }
        store
    }

    #[test]
    fn certificates_are_read_from_a_store() {
        let store = memory_store();
        let mut list = certificates_in(store.0, "user", "Root");
        list.sort_by(|a, b| a.subject.cmp(&b.subject));
        assert_eq!(list.len(), 2);
        let root = &list[0];
        assert_eq!(root.subject, "Contoso Test Root");
        assert_eq!(root.issuer, "Contoso Test Root");
        assert!(root.self_signed);
        assert_eq!(root.ca, Some(true));
        assert_eq!(root.sha1, "EA6B10C39587F72CB5A924652B2C5A6302763F53");
        assert_eq!(root.sha256.len(), 64);
        assert!(root.not_after_ms > root.not_before_ms && root.not_before_ms > 0);
        assert!(root.usages.is_empty());
        assert!(!root.program_property);
        assert_eq!((root.scope.as_str(), root.store.as_str()), ("user", "Root"));
        let leaf = &list[1];
        assert_eq!(leaf.subject, "localhost");
        assert_eq!(leaf.ca, Some(false));
        assert_eq!(leaf.usages, vec!["1.3.6.1.5.5.7.3.1".to_string()]);
        assert_eq!(leaf.sha1, "01432D2E5BE99A0D459077B34319AA1BD8449A57");
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex(&[0x0a, 0xff, 0x00]), "0AFF00");
        assert_eq!(unhex("0AFF00"), Some(vec![0x0a, 0xff, 0x00]));
        assert_eq!(unhex("0AF"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn a_bad_trust_list_does_not_decode() {
        assert_eq!(ctl_thumbprints(&[]), None);
        assert_eq!(ctl_thumbprints(&[0x30, 0x03, 0x01, 0x02, 0x03]), None);
    }

    #[test]
    fn store_paths() {
        assert_eq!(
            Scope::User.registry_path("Root"),
            r"Software\Microsoft\SystemCertificates\Root\Certificates"
        );
        assert_eq!(
            Scope::Enterprise.registry_path("Root"),
            r"SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates"
        );
    }

    /// Run by hand: counts of what this computer's stores hold (no names).
    #[test]
    #[ignore = "reads this computer's certificate stores"]
    fn live_counts() {
        let started = std::time::Instant::now();
        let stores = read();
        let program = root_program();
        let mut counts = std::collections::BTreeMap::new();
        for c in &stores.certificates {
            *counts.entry(format!("{}\\{}", c.scope, c.store)).or_insert(0) += 1;
        }
        let roots_outside = stores
            .certificates
            .iter()
            .filter(|c| c.store == "Root")
            .filter(|c| !c.program_property && !program.as_ref().is_some_and(|p| p.contains(&c.sha1)))
            .count();
        println!(
            "stores {counts:?} unreadable {:?} program {:?} roots outside the program {roots_outside} in {:?}",
            stores.unreadable,
            program.as_ref().map(BTreeSet::len),
            started.elapsed()
        );
    }
}
