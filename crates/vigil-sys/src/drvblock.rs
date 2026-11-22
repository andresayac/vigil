//! Microsoft's vulnerable driver blocklist, read offline from the copy Windows keeps.
//!
//! Attackers bring a signed but flawed driver along, load it, and use its flaw to switch off
//! security software ("bring your own vulnerable driver"). Microsoft lists such drivers in a code
//! integrity policy that Windows ships and updates: `System32\CodeIntegrity\driversipolicy.p7b`.
//! It is a PKCS#7 signed message whose content is a binary SIPolicy. The format is not documented
//! by Microsoft, but its layout is stable and well studied; the reader below is bounded and
//! refuses anything that does not look exactly like it.
//!
//! What is used:
//! - the deny rules that name a file by hash: the Authenticode SHA-1 and SHA-256 of the driver
//!   (the policy also lists page hashes, which never match a whole-file hash and are harmless);
//! - the deny rules that name a file by its original file name, with no hash.
//!
//! What is not used: the rules that deny a signer for some file names and versions. Matching them
//! needs the certificates' TBS hashes and version ranges kept in later parts of the policy, and a
//! wrong reading would accuse a fixed version of a driver. The counts are still reported.
//!
//! Nothing is sent anywhere and nothing is executed: the policy is parsed as data, its signature
//! is checked with the certificates it carries and the local stores only (no URL retrieval), and
//! driver files are only read to hash them.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::UNIX_EPOCH;

use serde::Serialize;
use sha2::{Digest, Sha256};
use windows::Win32::Security::Cryptography::{
    CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CHAIN_POLICY_FLAGS,
    CERT_CHAIN_POLICY_MICROSOFT_ROOT, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS, CERT_CONTEXT,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CRYPT_VERIFY_MESSAGE_PARA, CertFreeCertificateChain, CertFreeCertificateContext,
    CertGetCertificateChain, CertGetNameStringW, CertVerifyCertificateChainPolicy, CryptVerifyMessageSignature,
    MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW};

use crate::reliability::{LogReader, Record};
use crate::util::from_wide;

/// The policy file, relative to the Windows folder.
pub const POLICY_FILE: &str = r"System32\CodeIntegrity\driversipolicy.p7b";

const MAX_POLICY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DRIVER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RULES: u32 = 200_000;
const MAX_NAME_BYTES: u32 = 64 * 1024;
const MAX_HASH_BYTES: u32 = 64;
/// At most this many driver files are hashed in one scan.
const MAX_DRIVERS: usize = 4000;
/// At most this many blocked-driver events are kept.
const MAX_EVENTS: usize = 50;

// --------------------------------------------------------------------------- the policy

/// The rules of the blocklist that Vigil can check, and what the policy says about itself.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    /// SIPolicy format version (11 on current Windows).
    pub format: u32,
    /// The policy's own version ("10.0.27600.0").
    pub version: String,
    /// File rules in the policy (every kind).
    pub file_rules: u32,
    /// Deny rules by hash (Authenticode and page hashes, SHA-1 and SHA-256).
    pub hash_rules: usize,
    /// Deny rules by original file name.
    pub name_rules: usize,
    /// File attributes used by signer rules (not checked).
    pub attribute_rules: usize,
    /// Signer rules (not checked).
    pub signer_rules: u32,
    sha1: HashSet<[u8; 20]>,
    sha256: HashSet<[u8; 32]>,
    names: HashSet<String>,
}

/// How a driver matched the blocklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Hit {
    /// Its Authenticode hash is listed: this exact file is a known vulnerable driver.
    Hash,
    /// Its original file name is listed (every version of that driver is denied).
    Name,
}

impl Rules {
    /// Whether a driver with these hashes and this original file name is on the list.
    pub fn check(&self, hashes: &AuthHashes, original_name: Option<&str>) -> Option<Hit> {
        if self.sha256.contains(&hashes.sha256) || self.sha1.contains(&hashes.sha1) {
            return Some(Hit::Hash);
        }
        original_name
            .map(|n| n.trim().to_lowercase())
            .filter(|n| !n.is_empty() && self.names.contains(n))
            .map(|_| Hit::Name)
    }

    /// Whether the policy names files by original file name (only then is a file's version
    /// resource worth reading).
    pub fn has_name_rules(&self) -> bool {
        !self.names.is_empty()
    }
}

/// A little-endian reader that never reads past the end.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn bytes(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        self.bytes(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// `n` bytes, then the padding that keeps the next field on a 4-byte boundary.
    fn padded(&mut self, n: u32) -> Option<&[u8]> {
        let n = n as usize;
        let start = self.pos;
        self.bytes(n)?;
        self.bytes((4 - n % 4) % 4)?;
        self.data.get(start..start + n)
    }
}

/// The rules of a binary SIPolicy (the content of the `.p7b`); `None` when it does not have the
/// expected layout, rather than half-reading it.
pub fn parse_policy(bin: &[u8]) -> Option<Rules> {
    let mut r = Reader { data: bin, pos: 0 };
    let format = r.u32()?;
    if !(1..=64).contains(&format) {
        return None;
    }
    r.bytes(32)?; // policy type and platform GUIDs
    let _options = r.u32()?;
    let ekus = r.u32()?;
    let files = r.u32()?;
    let signers = r.u32()?;
    let _scenarios = r.u32()?;
    let (revision, build, minor, major) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
    let _header_length = r.u32()?;
    if ekus > MAX_RULES || files > MAX_RULES || signers > MAX_RULES {
        return None;
    }
    for _ in 0..ekus {
        let n = r.u32()?;
        if n > MAX_NAME_BYTES {
            return None;
        }
        r.padded(n)?;
    }
    let mut rules = Rules {
        format,
        version: format!("{major}.{minor}.{build}.{revision}"),
        file_rules: files,
        signer_rules: signers,
        ..Rules::default()
    };
    for _ in 0..files {
        let kind = r.u32()?;
        let name_len = r.u32()?;
        if name_len > MAX_NAME_BYTES || name_len % 2 != 0 {
            return None;
        }
        let name_bytes = r.padded(name_len)?;
        let name = String::from_utf16_lossy(
            &name_bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>(),
        );
        let _reserved = r.u32()?;
        r.bytes(8)?; // minimum file version
        let hash_len = r.u32()?;
        if hash_len > MAX_HASH_BYTES {
            return None;
        }
        let hash = r.padded(hash_len)?;
        // Only the sizes of SHA-1, SHA-256, SHA-384 and SHA-512 appear in a real policy.
        if !matches!(hash.len(), 0 | 20 | 32 | 48 | 64) || kind > 3 {
            return None;
        }
        match kind {
            0 => {
                if let Ok(h) = <[u8; 20]>::try_from(hash) {
                    rules.sha1.insert(h);
                    rules.hash_rules += 1;
                } else if let Ok(h) = <[u8; 32]>::try_from(hash) {
                    rules.sha256.insert(h);
                    rules.hash_rules += 1;
                } else if hash.is_empty() && !name.trim().is_empty() && name.trim() != "*" {
                    rules.names.insert(name.trim().to_lowercase());
                    rules.name_rules += 1;
                }
            }
            2 => rules.attribute_rules += 1,
            _ => {}
        }
    }
    Some(rules)
}

/// One DER element: its tag, where its content starts and how long it is.
fn element(buf: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    let tag = *buf.get(pos)?;
    let first = *buf.get(pos + 1)?;
    let (len, start) = if first & 0x80 == 0 {
        (first as usize, pos + 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let bytes = buf.get(pos + 2..pos + 2 + count)?;
        (
            bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize),
            pos + 2 + count,
        )
    };
    (start.checked_add(len)? <= buf.len()).then_some((tag, start, len))
}

/// `1.2.840.113549.1.7.2`, PKCS#7 signed data.
const SIGNED_DATA: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

/// The content of a PKCS#7 signed message (`ContentInfo` → `SignedData` → encapsulated content);
/// `None` when the structure is not exactly that.
pub fn pkcs7_content(der: &[u8]) -> Option<&[u8]> {
    let (tag, outer, _) = element(der, 0)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, oid, oid_len) = element(der, outer)?;
    if tag != 0x06 || der.get(oid..oid + oid_len)? != SIGNED_DATA {
        return None;
    }
    let (tag, explicit, _) = element(der, oid + oid_len)?;
    if tag != 0xa0 {
        return None;
    }
    let (tag, signed, _) = element(der, explicit)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, version, version_len) = element(der, signed)?;
    if tag != 0x02 {
        return None;
    }
    let (tag, algorithms, algorithms_len) = element(der, version + version_len)?;
    if tag != 0x31 {
        return None;
    }
    let (tag, info, _) = element(der, algorithms + algorithms_len)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, content_type, content_type_len) = element(der, info)?;
    if tag != 0x06 {
        return None;
    }
    let (tag, wrapped, _) = element(der, content_type + content_type_len)?;
    if tag != 0xa0 {
        return None;
    }
    let (tag, content, content_len) = element(der, wrapped)?;
    if tag != 0x04 {
        return None;
    }
    der.get(content..content + content_len)
}

/// What the signature of the policy shows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Signature {
    /// "microsoft": the signature is valid and its chain ends at a Microsoft root;
    /// "intact": the signature is valid, but its chain cannot be completed offline (the
    /// intermediate certificate is neither in the file nor in the local stores);
    /// "invalid": the signature does not verify; "unknown": the check could not run.
    pub state: String,
    /// The signing certificate's name ("Microsoft Windows").
    pub signer: String,
}

/// The signature of a PKCS#7 signed message. Only the certificates in the message and the local
/// stores are used: no URL is ever fetched, so a chain whose intermediate is not on the computer
/// stays partial and the result is "intact", not "microsoft".
pub fn signature(der: &[u8]) -> Signature {
    let para = CRYPT_VERIFY_MESSAGE_PARA {
        cbSize: std::mem::size_of::<CRYPT_VERIFY_MESSAGE_PARA>() as u32,
        dwMsgAndCertEncodingType: (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING).0,
        ..Default::default()
    };
    let mut signer: *mut CERT_CONTEXT = std::ptr::null_mut();
    // SAFETY: `para` and `der` outlive the call; no decoded output is asked for; `signer` receives
    // a certificate context that is freed below.
    let verified = unsafe { CryptVerifyMessageSignature(&para, 0, der, None, None, Some(&mut signer)) };
    if verified.is_err() || signer.is_null() {
        return Signature {
            state: "invalid".into(),
            signer: String::new(),
        };
    }
    let mut name = [0u16; 256];
    // SAFETY: `signer` is a live certificate context; `name` is writable for its length.
    let len = unsafe { CertGetNameStringW(signer, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut name)) };
    let signer_name = from_wide(&name[..(len as usize).saturating_sub(1).min(name.len())]);
    let chained = (|| {
        let chain_para = CERT_CHAIN_PARA {
            cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
            ..Default::default()
        };
        let mut chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
        // SAFETY: `signer` is a live context whose own store (the message's certificates) is used
        // as the additional store; cache-only retrieval keeps the call offline; `chain` is freed.
        let built = unsafe {
            CertGetCertificateChain(
                None,
                signer,
                None,
                Some((*signer).hCertStore),
                &chain_para,
                CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
                None,
                &mut chain,
            )
        };
        if built.is_err() || chain.is_null() {
            return None;
        }
        // Microsoft's product roots, then its application root (2011).
        let mut ok = false;
        for flags in [
            CERT_CHAIN_POLICY_FLAGS(0),
            MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG,
        ] {
            let policy = CERT_CHAIN_POLICY_PARA {
                cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
                dwFlags: flags,
                ..Default::default()
            };
            let mut status = CERT_CHAIN_POLICY_STATUS {
                cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
                ..Default::default()
            };
            // SAFETY: `chain` is the live chain built above; both structures outlive the call.
            let ran = unsafe {
                CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT, chain, &policy, &mut status)
            };
            if ran.as_bool() && status.dwError == 0 {
                ok = true;
                break;
            }
        }
        // SAFETY: `chain` came from CertGetCertificateChain and is not used afterwards.
        unsafe { CertFreeCertificateChain(chain) };
        Some(ok)
    })();
    // SAFETY: `signer` came from CryptVerifyMessageSignature and is not used afterwards.
    unsafe {
        let _ = CertFreeCertificateContext(Some(signer));
    }
    Signature {
        state: match chained {
            Some(true) => "microsoft",
            Some(false) => "intact",
            None => "unknown",
        }
        .into(),
        signer: signer_name,
    }
}

/// What the scan says about the installed policy.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PolicyInfo {
    pub path: String,
    pub version: String,
    pub format: u32,
    pub modified_ms: i64,
    /// What the policy's signature shows.
    pub signature: Signature,
    pub file_rules: u32,
    pub hash_rules: usize,
    pub name_rules: usize,
    pub attribute_rules: usize,
    pub signer_rules: u32,
}

/// The installed policy: its rules and what is known about it.
#[derive(Debug, Clone)]
pub struct Policy {
    pub info: PolicyInfo,
    pub rules: Rules,
}

/// The Windows folder.
pub fn windows_dir() -> String {
    std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| r"C:\Windows".to_string())
}

fn modified_ms(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Reads, checks and parses the blocklist Windows keeps. `Ok(None)` when there is none.
pub fn read_policy() -> Result<Option<Policy>, String> {
    read_policy_at(&Path::new(&windows_dir()).join(POLICY_FILE))
}

/// [`read_policy`] for a given file (tests use a temporary one).
pub fn read_policy_at(path: &Path) -> Result<Option<Policy>, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if !meta.is_file() || meta.len() > MAX_POLICY_BYTES {
        return Err("not a regular file of a plausible size".into());
    }
    let mut der = Vec::new();
    File::open(path)
        .and_then(|f| f.take(MAX_POLICY_BYTES).read_to_end(&mut der))
        .map_err(|e| e.to_string())?;
    let content = pkcs7_content(&der).ok_or("not a signed policy")?;
    let rules = parse_policy(content).ok_or("the policy has a layout Vigil does not know")?;
    let info = PolicyInfo {
        path: path.display().to_string(),
        version: rules.version.clone(),
        format: rules.format,
        modified_ms: modified_ms(&meta),
        signature: signature(&der),
        file_rules: rules.file_rules,
        hash_rules: rules.hash_rules,
        name_rules: rules.name_rules,
        attribute_rules: rules.attribute_rules,
        signer_rules: rules.signer_rules,
    };
    Ok(Some(Policy { info, rules }))
}

static POLICY_CACHE: Mutex<Option<(i64, Arc<Policy>)>> = Mutex::new(None);

/// The installed policy, parsed once and again only when the file changes (for the watch).
pub fn installed_policy() -> Option<Arc<Policy>> {
    let path = Path::new(&windows_dir()).join(POLICY_FILE);
    let stamp = std::fs::metadata(&path).ok().map(|m| modified_ms(&m))?;
    let mut cache = POLICY_CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((when, policy)) = cache.as_ref()
        && *when == stamp
    {
        return Some(Arc::clone(policy));
    }
    let policy = Arc::new(read_policy_at(&path).ok()??);
    *cache = Some((stamp, Arc::clone(&policy)));
    Some(policy)
}

// --------------------------------------------------------------------------- Authenticode hashes

/// The Authenticode hashes of a PE file: what code integrity policies list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthHashes {
    pub sha1: [u8; 20],
    pub sha256: [u8; 32],
}

fn le_u16(buf: &[u8], at: usize) -> Option<u16> {
    buf.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn le_u32(buf: &[u8], at: usize) -> Option<u32> {
    buf.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The Authenticode hashes of a PE image: the whole file except its checksum field, the
/// certificate table entry and the certificate table itself. `None` when it is not a PE file.
pub fn authenticode(pe: &[u8]) -> Option<AuthHashes> {
    if pe.get(..2)? != b"MZ" {
        return None;
    }
    let header = le_u32(pe, 0x3c)? as usize;
    if pe.get(header..header + 4)? != b"PE\0\0" {
        return None;
    }
    let optional = header + 24;
    let directories = match le_u16(pe, optional)? {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => return None,
    };
    let checksum = optional + 64;
    let count = le_u32(pe, directories.checked_sub(4)?)?;
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    if count > 4 {
        let security = directories + 4 * 8;
        let offset = le_u32(pe, security)? as usize;
        let size = le_u32(pe, security + 4)? as usize;
        let end = if offset != 0 && size != 0 && offset.checked_add(size)? <= pe.len() && offset > security + 8 {
            offset
        } else {
            pe.len()
        };
        if security + 8 > end || checksum + 4 > security {
            return None;
        }
        ranges.extend([(0, checksum), (checksum + 4, security), (security + 8, end)]);
    } else {
        if checksum + 4 > pe.len() {
            return None;
        }
        ranges.extend([(0, checksum), (checksum + 4, pe.len())]);
    }
    let mut sha1 = sha1_smol::Sha1::new();
    let mut sha256 = Sha256::new();
    for (start, end) in ranges {
        let part = pe.get(start..end)?;
        sha1.update(part);
        sha256.update(part);
    }
    Some(AuthHashes {
        sha1: sha1.digest().bytes(),
        sha256: sha256.finalize().into(),
    })
}

/// A driver file read and hashed: `None` when it cannot be read or is not a PE file. Links are
/// not followed to a file of another size than the one checked, and very large files are skipped.
pub fn file_hashes(path: &str) -> Option<AuthHashes> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_DRIVER_BYTES {
        return None;
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    File::open(path)
        .ok()?
        .take(MAX_DRIVER_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    authenticode(&bytes)
}

/// A file's original name from its version resource.
pub fn original_name(path: &str) -> Option<String> {
    crate::apps::version_string(path, "OriginalFilename")
}

/// What the watch keeps about one driver file: its hashes (`None`: not a readable PE file) and its
/// original file name (read only when the policy has name rules).
type Fingerprinted = (Option<AuthHashes>, Option<String>);

/// The blocklist verdict for one driver file, cached by path, size and time (for the watch, so a
/// driver is hashed and its version resource read again only when it changes). `None` when the
/// file cannot be read.
pub fn check_cached(rules: &Rules, path: &str) -> Option<Option<Hit>> {
    type Key = (String, u64, i64, bool);
    static CACHE: Mutex<Option<HashMap<Key, Fingerprinted>>> = Mutex::new(None);
    let meta = std::fs::metadata(path).ok()?;
    let with_name = rules.has_name_rules();
    let key = (path.to_lowercase(), meta.len(), modified_ms(&meta), with_name);
    let cached = CACHE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .get(&key)
        .cloned();
    let (hashes, name) = match cached {
        Some(found) => found,
        None => {
            let found = (file_hashes(path), if with_name { original_name(path) } else { None });
            let mut guard = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
            let map = guard.get_or_insert_with(HashMap::new);
            if map.len() > 8 * MAX_DRIVERS {
                map.clear();
            }
            map.insert(key, found.clone());
            found
        }
    };
    Some(rules.check(&hashes?, name.as_deref()))
}

// --------------------------------------------------------------------------- drivers on this computer

/// The files of the drivers loaded now, as full paths; `None` when Windows does not tell (recent
/// Windows versions keep this from processes that are not elevated).
pub fn loaded_drivers() -> Option<Vec<String>> {
    let mut bases = vec![std::ptr::null_mut(); 1024];
    let mut needed = 0u32;
    for _ in 0..3 {
        let bytes = (bases.len() * std::mem::size_of::<*mut core::ffi::c_void>()) as u32;
        // SAFETY: `bases` is writable for `bytes` bytes; `needed` receives the size required.
        unsafe { EnumDeviceDrivers(bases.as_mut_ptr(), bytes, &mut needed) }.ok()?;
        let count = needed as usize / std::mem::size_of::<*mut core::ffi::c_void>();
        if count <= bases.len() {
            bases.truncate(count);
            break;
        }
        bases.resize(count.min(16_384), std::ptr::null_mut());
    }
    let windows = windows_dir();
    let mut out = Vec::new();
    for base in bases.iter().filter(|b| !b.is_null()) {
        let mut name = [0u16; 1024];
        // SAFETY: `base` came from EnumDeviceDrivers; `name` is writable for its length.
        let len = unsafe { GetDeviceDriverFileNameW(*base, &mut name) } as usize;
        if len == 0 {
            continue;
        }
        out.push(crate::netcfg::driver_file(
            &from_wide(&name[..len.min(name.len())]),
            &windows,
        ));
    }
    (!out.is_empty()).then_some(out)
}

/// A driver the blocklist names.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Match {
    /// Full path of the file.
    pub path: String,
    /// The driver service that loads it ("" when only seen loaded).
    pub service: String,
    /// The service's start type ("boot", "system", "auto", "demand", "disabled" or "").
    pub start: String,
    /// Loaded now (`None`: unknown).
    pub loaded: Option<bool>,
    /// "hash" or "name".
    pub rule: String,
    /// Authenticode SHA-256 (hex).
    pub sha256: String,
}

/// A driver Windows refused to load (or would have, in audit mode), from the code integrity log.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BlockedEvent {
    pub time_ms: i64,
    pub event_id: u32,
    pub file: String,
    pub process: String,
    pub policy: String,
    /// The event was written in audit mode: the driver loaded, but would have been blocked.
    pub audit: bool,
}

/// The blocklist check of the drivers on this computer.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    /// The installed policy (`None`: there is none, or it could not be read; see `policy_error`).
    pub policy: Option<PolicyInfo>,
    pub policy_error: String,
    /// Driver files hashed.
    pub checked: usize,
    /// Driver files that could not be read.
    pub unreadable: usize,
    /// Whether the list of loaded drivers was readable.
    pub loaded_known: bool,
    pub matches: Vec<Match>,
    pub events: Vec<BlockedEvent>,
    /// Whether the code integrity log was readable.
    pub events_readable: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every driver file the service database names, plus the loaded ones, with their services.
fn driver_files(loaded: Option<&[String]>) -> BTreeMap<String, (String, String, String)> {
    let windows = windows_dir();
    let mut files: BTreeMap<String, (String, String, String)> = BTreeMap::new();
    for driver in crate::hooks::drivers().unwrap_or_default() {
        let path = if driver.path.trim().is_empty() {
            format!(r"{windows}\System32\drivers\{}.sys", driver.name)
        } else {
            crate::netcfg::driver_file(&driver.path, &windows)
        };
        files
            .entry(path.to_lowercase())
            .or_insert((path, driver.name.clone(), driver.start.clone()));
    }
    for path in loaded.unwrap_or_default() {
        files
            .entry(path.to_lowercase())
            .or_insert((path.clone(), String::new(), String::new()));
    }
    files
}

/// One hashed driver file: its index in the list, and its hashes and verdict (`None`: unreadable).
type Checked = (usize, Option<(AuthHashes, Option<Hit>)>);

/// Hashes every driver file in parallel (bounded) and checks it against the rules.
pub fn check_drivers(rules: &Rules) -> Report {
    let loaded = loaded_drivers();
    let loaded_set: Option<HashSet<String>> = loaded
        .as_ref()
        .map(|list| list.iter().map(|p| p.to_lowercase()).collect());
    let files: Vec<(String, (String, String, String))> =
        driver_files(loaded.as_deref()).into_iter().take(MAX_DRIVERS).collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results: Mutex<Vec<Checked>> = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some((_, (path, _, _))) = files.get(index) else {
                        break;
                    };
                    let outcome = file_hashes(path).map(|hashes| {
                        let name = if rules.has_name_rules() {
                            original_name(path)
                        } else {
                            None
                        };
                        (hashes, rules.check(&hashes, name.as_deref()))
                    });
                    results
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push((index, outcome));
                }
            });
        }
    });
    let mut results = results.into_inner().unwrap_or_else(PoisonError::into_inner);
    results.sort_by_key(|(index, _)| *index);
    let mut report = Report {
        loaded_known: loaded_set.is_some(),
        ..Report::default()
    };
    for (index, outcome) in results {
        let Some((key, (path, service, start))) = files.get(index) else {
            continue;
        };
        match outcome {
            None => report.unreadable += 1,
            Some((hashes, hit)) => {
                report.checked += 1;
                if let Some(hit) = hit {
                    report.matches.push(Match {
                        path: path.clone(),
                        service: service.clone(),
                        start: start.clone(),
                        loaded: loaded_set.as_ref().map(|set| set.contains(key)),
                        rule: match hit {
                            Hit::Hash => "hash".into(),
                            Hit::Name => "name".into(),
                        },
                        sha256: hex(&hashes.sha256),
                    });
                }
            }
        }
    }
    report
}

/// The code integrity events of the last `days` days about drivers blocked by a policy (3023: a
/// revoked or listed driver; 3077 enforced, 3076 audit). `None` when the log cannot be read.
pub fn blocked_events(days: u32) -> Option<Vec<BlockedEvent>> {
    let ms = u64::from(days.max(1)) * 86_400_000;
    let query = format!(
        "*[System[(EventID=3023 or EventID=3076 or EventID=3077) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    );
    let mut reader = LogReader::default();
    let (events, _) = reader
        .query("Microsoft-Windows-CodeIntegrity/Operational", &query, false)
        .ok()?;
    Some(
        events
            .iter()
            .filter_map(|(xml, _)| blocked_event(xml))
            .take(MAX_EVENTS)
            .collect(),
    )
}

/// One code integrity event about a driver; `None` for events about other files.
pub fn blocked_event(xml: &str) -> Option<BlockedEvent> {
    let record = Record::parse(xml)?;
    let field = |names: &[&str]| {
        names
            .iter()
            .map(|n| record.get(n, usize::MAX))
            .find(|v| !v.is_empty())
            .unwrap_or("")
            .to_string()
    };
    let file = field(&["File Name", "FileNameBuffer", "FileName"]);
    let event_id = record.event_id;
    // 3076/3077 are written for any file a policy checks; keep the drivers.
    if event_id != 3023 && !file.to_lowercase().ends_with(".sys") {
        return None;
    }
    Some(BlockedEvent {
        time_ms: record.time_ms,
        event_id,
        file,
        process: field(&["Process Name", "ProcessNameBuffer", "ProcessName"]),
        policy: field(&["PolicyName", "Policy Name"]),
        audit: event_id == 3076,
    })
}

/// The whole check for a scan: the policy, the drivers and the log.
pub fn scan(days: u32) -> Report {
    let policy = read_policy();
    let mut report = match &policy {
        Ok(Some(policy)) => {
            let mut report = check_drivers(&policy.rules);
            report.policy = Some(policy.info.clone());
            report
        }
        Ok(None) => Report {
            policy_error: "missing".into(),
            ..Report::default()
        },
        Err(e) => Report {
            policy_error: e.clone(),
            ..Report::default()
        },
    };
    match blocked_events(days) {
        Some(events) => {
            report.events = events;
            report.events_readable = true;
        }
        None => report.events_readable = false,
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn put_padded(out: &mut Vec<u8>, bytes: &[u8]) {
        put_u32(out, bytes.len() as u32);
        out.extend_from_slice(bytes);
        out.extend(std::iter::repeat_n(0u8, (4 - bytes.len() % 4) % 4));
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// A synthetic SIPolicy with the layout of the real one: a SHA-1 and a SHA-256 deny rule, a
    /// deny-by-name rule, an allow rule and a file attribute.
    fn synthetic(sha1: [u8; 20], sha256: [u8; 32]) -> Vec<u8> {
        let mut p = Vec::new();
        put_u32(&mut p, 11); // format
        p.extend_from_slice(&[0x11; 32]); // GUIDs
        put_u32(&mut p, 0x8088_0000); // options
        put_u32(&mut p, 0); // EKUs
        put_u32(&mut p, 5); // file rules
        put_u32(&mut p, 2); // signers
        put_u32(&mut p, 2); // scenarios
        for part in [4u16, 3, 2, 1] {
            p.extend_from_slice(&part.to_le_bytes()); // version 1.2.3.4
        }
        put_u32(&mut p, 64);
        let mut rule = |kind: u32, name: &str, hash: &[u8]| {
            put_u32(&mut p, kind);
            put_padded(&mut p, &utf16(name));
            put_u32(&mut p, 0);
            p.extend_from_slice(&[0xff; 8]);
            put_padded(&mut p, hash);
        };
        rule(0, "", &sha1);
        rule(0, "", &sha256);
        rule(0, "Contoso.sys", &[]);
        rule(1, "*", &[]);
        rule(2, "fabrikam.sys", &[]);
        p
    }

    #[test]
    fn a_synthetic_policy_is_parsed() {
        let rules = parse_policy(&synthetic([1; 20], [2; 32])).expect("parsed");
        assert_eq!(rules.format, 11);
        assert_eq!(rules.version, "1.2.3.4");
        assert_eq!(rules.file_rules, 5);
        assert_eq!(rules.hash_rules, 2);
        assert_eq!(rules.name_rules, 1);
        assert_eq!(rules.attribute_rules, 1);
        assert_eq!(rules.signer_rules, 2);
        let by_sha256 = AuthHashes {
            sha1: [9; 20],
            sha256: [2; 32],
        };
        assert_eq!(rules.check(&by_sha256, None), Some(Hit::Hash));
        let by_sha1 = AuthHashes {
            sha1: [1; 20],
            sha256: [9; 32],
        };
        assert_eq!(rules.check(&by_sha1, None), Some(Hit::Hash));
        let other = AuthHashes {
            sha1: [9; 20],
            sha256: [9; 32],
        };
        assert_eq!(rules.check(&other, Some("CONTOSO.SYS")), Some(Hit::Name));
        assert_eq!(
            rules.check(&other, Some("fabrikam.sys")),
            None,
            "attribute rules are not checked"
        );
        assert_eq!(rules.check(&other, None), None);
    }

    #[test]
    fn broken_policies_are_refused() {
        let good = synthetic([1; 20], [2; 32]);
        assert!(parse_policy(&good[..good.len() - 3]).is_none(), "truncated");
        assert!(parse_policy(&[]).is_none());
        let mut bad_format = good.clone();
        bad_format[..4].copy_from_slice(&999u32.to_le_bytes());
        assert!(parse_policy(&bad_format).is_none());
        let mut huge = good.clone();
        huge[44..48].copy_from_slice(&u32::MAX.to_le_bytes()); // file rule count
        assert!(parse_policy(&huge).is_none());
        let mut odd_hash = good;
        // The first rule's hash length (after kind, name length, reserved and version).
        let at = 68 + 4 + 4 + 4 + 8;
        odd_hash[at..at + 4].copy_from_slice(&7u32.to_le_bytes());
        assert!(parse_policy(&odd_hash).is_none());
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            let len = (content.len() as u32).to_be_bytes();
            let skip = len.iter().take_while(|b| **b == 0).count();
            out.push(0x80 | (4 - skip) as u8);
            out.extend_from_slice(&len[skip..]);
        }
        out.extend_from_slice(content);
        out
    }

    #[test]
    fn the_content_of_a_signed_message_is_found() {
        let policy = synthetic([1; 20], [2; 32]);
        let econtent = [der(0x06, &[0x2b, 0x06, 0x01]), der(0xa0, &der(0x04, &policy))].concat();
        let signed = [
            der(0x02, &[1]),
            der(0x31, &der(0x30, &[])),
            der(0x30, &econtent),
            der(0x31, &[]),
        ]
        .concat();
        let message = der(
            0x30,
            &[der(0x06, &SIGNED_DATA), der(0xa0, &der(0x30, &signed))].concat(),
        );
        assert_eq!(pkcs7_content(&message), Some(policy.as_slice()));
        assert!(pkcs7_content(&message[..message.len() - 1]).is_none(), "truncated");
        let mut wrong_oid = message.clone();
        let at = wrong_oid.iter().position(|b| *b == 0x2a).expect("oid");
        wrong_oid[at] = 0x2b;
        assert!(pkcs7_content(&wrong_oid).is_none());
        // The signature check refuses a message nobody signed.
        assert_eq!(signature(&message).state, "invalid");
    }

    /// A minimal PE32+ image with a certificate table at the end.
    fn pe(with_certificate: bool) -> Vec<u8> {
        let mut image = vec![0u8; 0x400];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        let optional = 0x80 + 24;
        image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes()); // directories
        for (i, b) in image.iter_mut().enumerate().skip(0x300) {
            *b = (i % 251) as u8;
        }
        if with_certificate {
            let security = optional + 112 + 4 * 8;
            image[security..security + 4].copy_from_slice(&0x400u32.to_le_bytes());
            image[security + 4..security + 8].copy_from_slice(&16u32.to_le_bytes());
            image.extend_from_slice(&[0xee; 16]);
        }
        image
    }

    #[test]
    fn authenticode_skips_the_checksum_and_the_signature() {
        let signed = pe(true);
        let base = authenticode(&signed).expect("hashed");
        // The checksum field does not count.
        let mut other_checksum = signed.clone();
        other_checksum[0x80 + 24 + 64] ^= 0xff;
        assert_eq!(authenticode(&other_checksum), Some(base));
        // Neither does the certificate table.
        let mut other_certificate = signed.clone();
        let last = other_certificate.len() - 1;
        other_certificate[last] ^= 0xff;
        assert_eq!(authenticode(&other_certificate), Some(base));
        // The code does.
        let mut other_code = signed;
        other_code[0x350] ^= 0xff;
        assert_ne!(authenticode(&other_code), Some(base));
        // Unsigned images hash to their end; anything else is not a PE file.
        assert!(authenticode(&pe(false)).is_some());
        assert!(authenticode(b"not a program").is_none());
        assert!(authenticode(&pe(true)[..0x90]).is_none());
    }

    const BLOCKED: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-CodeIntegrity"/><EventID>3077</EventID><Level>2</Level><TimeCreated SystemTime="2026-11-20T10:00:00.0000000Z"/><EventRecordID>42</EventRecordID><Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel></System><EventData><Data Name="File Name">\Device\HarddiskVolume3\Users\jdoe\Downloads\contoso\RTCore64.sys</Data><Data Name="Process Name">System</Data><Data Name="PolicyName">Microsoft Windows Driver Policy</Data></EventData></Event>"#;

    #[test]
    fn blocked_driver_events_are_read() {
        let event = blocked_event(BLOCKED).expect("a driver event");
        assert_eq!(event.event_id, 3077);
        assert!(event.file.ends_with("RTCore64.sys"));
        assert_eq!(event.process, "System");
        assert_eq!(event.policy, "Microsoft Windows Driver Policy");
        assert!(!event.audit);
        let audit = BLOCKED.replace("<EventID>3077", "<EventID>3076");
        assert!(blocked_event(&audit).expect("audit").audit);
        // Events about other files (a DLL checked by a policy) are left out.
        let dll = BLOCKED.replace("RTCore64.sys", "contoso.dll");
        assert!(blocked_event(&dll).is_none());
    }

    /// Reads the real policy and checks the drivers on this computer; prints counts only.
    #[test]
    #[ignore = "reads this computer's code integrity policy and drivers"]
    fn live_counts() {
        let started = std::time::Instant::now();
        let report = scan(30);
        if let Some(info) = &report.policy {
            println!(
                "policy format {} version {} signature {} ({}): {} file rules ({} hash, {} name, {} attribute), {} signers",
                info.format,
                info.version,
                info.signature.state,
                info.signature.signer,
                info.file_rules,
                info.hash_rules,
                info.name_rules,
                info.attribute_rules,
                info.signer_rules
            );
        } else {
            println!("no policy: {}", report.policy_error);
        }
        println!(
            "drivers checked {}, unreadable {}, loaded list {}, matches {}, events {} (readable {}), {:?}",
            report.checked,
            report.unreadable,
            report.loaded_known,
            report.matches.len(),
            report.events.len(),
            report.events_readable,
            started.elapsed()
        );
    }
}
