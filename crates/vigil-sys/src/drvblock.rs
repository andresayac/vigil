//! Microsoft's vulnerable driver blocklist, read offline from the copy Windows keeps.
//!
//! Attackers bring a signed but flawed driver along, load it, and use its flaw to switch off
//! security software ("bring your own vulnerable driver"). Microsoft lists such drivers in a code
//! integrity policy that Windows ships and updates: `System32\CodeIntegrity\driversipolicy.p7b`.
//! It is a PKCS#7 signed message whose content is a binary SIPolicy. The format is not documented
//! by Microsoft, but its layout is stable and well studied; the reader below is bounded and
//! refuses anything that does not look exactly like it.
//!
//! The list is used only when its signature verifies and its certificate chain ends, offline, at
//! one of Microsoft's product roots (state "microsoft"). Anything else ("intact", "invalid",
//! "unknown") is reported and never used to accuse a driver: a policy file planted by someone
//! with write access to the Windows folder must not make Vigil offer to disable a security
//! product's driver. The rules are read from the content the signature check returns, so they
//! are exactly the signed bytes.
//!
//! What is used:
//! - the deny rules that name a file by hash: the Authenticode SHA-1 and SHA-256 of the driver
//!   (the policy also lists page hashes, which never match a whole-file hash and are harmless);
//! - the deny rules that name a file by its original file name with the version
//!   65535.65535.65535.65535, which the list uses for "every version of this file".
//!
//! What is not used, only counted: deny-by-name rules with another version (they cover a range of
//! versions whose exact reading is not documented; matching them by name alone would accuse a
//! fixed version), and the rules that deny a signer for some file names and versions (matching
//! them needs the certificates' TBS hashes and version ranges kept in later parts of the policy).
//!
//! Nothing is sent anywhere and nothing is executed: the policy is parsed as data, its signature
//! is checked with the certificates it carries and the local stores only (no URL retrieval), and
//! driver files are only read, a bounded piece at a time, to hash them.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::UNIX_EPOCH;

use serde::Serialize;
use sha2::{Digest, Sha256};
use windows::Win32::Security::Cryptography::{
    CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CONTEXT,
    CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_OPEN_STORE_FLAGS, CERT_STORE_PROV_PKCS7,
    CRYPT_INTEGER_BLOB, CRYPT_VERIFY_MESSAGE_PARA, CTL_USAGE, CertCloseStore, CertFreeCertificateChain,
    CertFreeCertificateContext, CertGetCertificateChain, CertGetEnhancedKeyUsage, CertGetNameStringW, CertOpenStore,
    CryptVerifyMessageSignature, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
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
    /// Deny rules by original file name that cover every version (checked).
    pub name_rules: usize,
    /// Deny rules by original file name limited to some versions (counted, not checked).
    pub versioned_name_rules: usize,
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
    /// Its original file name is listed for every version of that file.
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
        // The file version (revision, build, minor, major); all 65535 means every version.
        let every_version = r.bytes(8)?.iter().all(|b| *b == 0xff);
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
                    if every_version {
                        rules.names.insert(name.trim().to_lowercase());
                        rules.name_rules += 1;
                    } else {
                        rules.versioned_name_rules += 1;
                    }
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

/// One DER element of `tag` at `pos` that ends within `end` (its parent's end): where its content
/// starts and where it ends.
fn child(buf: &[u8], pos: usize, end: usize, tag: u8) -> Option<(usize, usize)> {
    let (found, start, len) = element(buf, pos)?;
    let stop = start.checked_add(len)?;
    (found == tag && stop <= end).then_some((start, stop))
}

/// The content of a PKCS#7 signed message (`ContentInfo` → `SignedData` → encapsulated content);
/// `None` when the structure is not exactly that. Every element must lie within its parent.
///
/// This walk does not verify anything: it is only used to tell the version and counts of a policy
/// whose signature does not verify. The rules Vigil checks drivers against come from the content
/// the signature check itself returns (see [`verify`]).
pub fn pkcs7_content(der: &[u8]) -> Option<&[u8]> {
    let (outer, outer_end) = child(der, 0, der.len(), 0x30)?;
    let (oid, oid_end) = child(der, outer, outer_end, 0x06)?;
    if der.get(oid..oid_end)? != SIGNED_DATA {
        return None;
    }
    let (explicit, explicit_end) = child(der, oid_end, outer_end, 0xa0)?;
    let (signed, signed_end) = child(der, explicit, explicit_end, 0x30)?;
    let (_, version_end) = child(der, signed, signed_end, 0x02)?;
    let (_, algorithms_end) = child(der, version_end, signed_end, 0x31)?;
    let (info, info_end) = child(der, algorithms_end, signed_end, 0x30)?;
    let (_, content_type_end) = child(der, info, info_end, 0x06)?;
    let (wrapped, wrapped_end) = child(der, content_type_end, info_end, 0xa0)?;
    let (content, content_end) = child(der, wrapped, wrapped_end, 0x04)?;
    der.get(content..content_end)
}

/// Microsoft's product root certificates (SHA-1 thumbprints) that Windows and its code integrity
/// policies chain to. The development, test, time-stamping and identity roots are left out on
/// purpose: a policy signed under them is not Windows' own list.
const MICROSOFT_ROOTS: [(&str, &str); 5] = [
    (
        "3b1efd3a66ea28b16697394703a72ca340a05bd5",
        "Microsoft Root Certificate Authority 2010",
    ),
    (
        "8f43288ad272f3103b6fb1428485ea3014c0bcfe",
        "Microsoft Root Certificate Authority 2011",
    ),
    (
        "cdd4eeae6000ac7f40c3802c171e30148030c072",
        "Microsoft Root Certificate Authority",
    ),
    ("a43489159a520f0d93d032ccaf37e7fe20a8b419", "Microsoft Root Authority"),
    (
        "06f1aa330b927b753a40e68cdf22e34bcbef3352",
        "Microsoft ECC Product Root Certificate Authority 2018",
    ),
];

/// Chain errors that do not make a Microsoft signature less Microsoft's: an expired certificate
/// (policies are signed with certificates that later expire), and revocation that cannot be
/// checked offline. Anything else (a partial chain, an untrusted or unknown root, a bad signature
/// between certificates, a revoked certificate) refuses the list.
const TOLERATED_CHAIN_ERRORS: u32 = 0x0000_0001 // CERT_TRUST_IS_NOT_TIME_VALID
    | 0x0000_0002 // CERT_TRUST_IS_NOT_TIME_NESTED
    | 0x0000_0040 // CERT_TRUST_REVOCATION_STATUS_UNKNOWN
    | 0x0100_0000; // CERT_TRUST_IS_OFFLINE_REVOCATION

/// What the signature of the policy shows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Signature {
    /// "microsoft": the signature verifies, its chain is complete offline and ends at one of
    /// Microsoft's product roots, and the signer is Microsoft's: the list is used.
    /// "intact": the signature verifies against the certificate the message carries, but no such
    /// chain could be built offline (an intermediate is missing, the root is unknown, untrusted or
    /// not a Microsoft product root, or the signer is not Microsoft's). A self-signed message is
    /// "intact" too: the list is not used.
    /// "invalid": the signature does not verify, or nobody signed the message: not used.
    /// "unknown": the check could not run: not used.
    pub state: String,
    /// The signing certificate's name ("Microsoft Windows").
    pub signer: String,
    /// The root the chain ended at ("Microsoft Root Certificate Authority 2010"), when one was
    /// built.
    pub root: String,
    /// Why the list was not used, in short English (empty when it was).
    pub reason: String,
}

impl Signature {
    fn refused(state: &str, signer: String, root: String, reason: &str) -> Self {
        Signature {
            state: state.into(),
            signer,
            root,
            reason: reason.into(),
        }
    }
}

/// A certificate's display name.
///
/// # Safety
/// `cert` must be a live certificate context.
unsafe fn cert_name(cert: *const CERT_CONTEXT) -> String {
    let mut name = [0u16; 256];
    // SAFETY: the caller passes a live context; `name` is writable for its length.
    let len = unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut name)) };
    from_wide(&name[..(len as usize).saturating_sub(1).min(name.len())])
}

/// The SHA-1 thumbprint (hex, lower case) of a certificate.
///
/// # Safety
/// `cert` must be a live certificate context.
unsafe fn thumbprint(cert: *const CERT_CONTEXT) -> String {
    // SAFETY: a live context holds `cbCertEncoded` readable bytes at `pbCertEncoded`.
    let encoded = unsafe {
        if (*cert).pbCertEncoded.is_null() {
            return String::new();
        }
        std::slice::from_raw_parts((*cert).pbCertEncoded, (*cert).cbCertEncoded as usize)
    };
    let mut sha1 = sha1_smol::Sha1::new();
    sha1.update(encoded);
    hex(&sha1.digest().bytes())
}

/// What the chain of `signer` shows, built offline with the message's own certificates as the
/// additional store (Windows' `.p7b` policies carry their intermediate certificate). Returns the
/// root's name and thumbprint and the chain's error bits, or `None` when no chain could be built.
///
/// # Safety
/// `signer` must be a live certificate context from a verified message, and `message` the open
/// store of that message's certificates.
unsafe fn offline_chain(signer: *const CERT_CONTEXT, message: HCERTSTORE) -> Option<(String, String, u32)> {
    // SAFETY: the caller passes a live context and an open store.
    unsafe { chain_with(signer, message) }
}

/// One offline chain of `signer` with `store` as the additional store.
///
/// # Safety
/// `signer` must be a live certificate context and `store` an open store.
unsafe fn chain_with(signer: *const CERT_CONTEXT, store: HCERTSTORE) -> Option<(String, String, u32)> {
    let chain_para = CERT_CHAIN_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
        ..Default::default()
    };
    let mut chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
    // SAFETY: `signer` and `store` are live (caller); cache-only retrieval keeps the call offline;
    // `chain` is freed below.
    let built = unsafe {
        CertGetCertificateChain(
            None,
            signer,
            None,
            Some(store),
            &chain_para,
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
            None,
            &mut chain,
        )
    };
    if built.is_err() || chain.is_null() {
        return None;
    }
    // SAFETY: `chain` is the live context built above; its first simple chain and that chain's
    // elements are owned by it and read before it is freed.
    let found = unsafe {
        let errors = (*chain).TrustStatus.dwErrorStatus;
        let simple = if (*chain).cChain == 0 || (*chain).rgpChain.is_null() {
            std::ptr::null_mut()
        } else {
            *(*chain).rgpChain
        };
        if simple.is_null() || (*simple).cElement == 0 || (*simple).rgpElement.is_null() {
            None
        } else {
            let last = *(*simple).rgpElement.add((*simple).cElement as usize - 1);
            if last.is_null() || (*last).pCertContext.is_null() {
                None
            } else {
                let root = (*last).pCertContext;
                Some((cert_name(root), thumbprint(root), errors))
            }
        }
    };
    // SAFETY: `chain` came from CertGetCertificateChain and is not used afterwards.
    unsafe { CertFreeCertificateChain(chain) };
    found
}

/// The certificates a PKCS#7 message carries, as a store (closed by the caller).
fn message_store(der: &[u8]) -> Option<HCERTSTORE> {
    let blob = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(der.len()).ok()?,
        pbData: der.as_ptr().cast_mut(),
    };
    // SAFETY: `blob` points into `der`, which outlives the call; the store copies what it needs.
    unsafe {
        CertOpenStore(
            CERT_STORE_PROV_PKCS7,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            None,
            CERT_OPEN_STORE_FLAGS(0),
            Some((&raw const blob).cast()),
        )
    }
    .ok()
}

/// Windows System Component Verification: the extended key usage of the certificates that sign
/// Windows' own components, code integrity policies among them.
const WINDOWS_COMPONENT_EKU: &str = "1.3.6.1.4.1.311.10.3.6";

/// The extended key usages a certificate lists in its own extension (empty when it has none).
///
/// # Safety
/// `cert` must be a live certificate context.
unsafe fn ekus(cert: *const CERT_CONTEXT) -> Vec<String> {
    let mut size = 0u32;
    // SAFETY: the caller passes a live context; first only the size is asked for.
    if unsafe { CertGetEnhancedKeyUsage(cert, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG.0, None, &mut size) }.is_err()
        || size == 0
    {
        return Vec::new();
    }
    let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
    let usage = buffer.as_mut_ptr().cast::<CTL_USAGE>();
    // SAFETY: `buffer` is 8-byte aligned and at least `size` bytes; the usage it receives points
    // into the same buffer and is read before the buffer is dropped.
    unsafe {
        if CertGetEnhancedKeyUsage(cert, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG.0, Some(usage), &mut size).is_err() {
            return Vec::new();
        }
        let count = (*usage).cUsageIdentifier as usize;
        if count == 0 || (*usage).rgpszUsageIdentifier.is_null() {
            return Vec::new();
        }
        (0..count)
            .filter_map(|i| {
                let oid = *(*usage).rgpszUsageIdentifier.add(i);
                (!oid.is_null()).then(|| oid.to_string().unwrap_or_default())
            })
            .collect()
    }
}

/// The decision on a chain: "microsoft" only when nothing but tolerated errors is set, the root is
/// one of Microsoft's product roots and the signer is Microsoft's. Separate from the Windows calls
/// so it can be tested.
fn judge_chain(signer: &str, signer_ekus: &[String], root_thumbprint: &str, errors: u32) -> Result<(), &'static str> {
    if errors & !TOLERATED_CHAIN_ERRORS != 0 {
        return Err(if errors & 0x0001_0000 != 0 {
            "the certificate chain could not be completed offline"
        } else if errors & 0x0000_0020 != 0 {
            "the certificate chain ends at a root this computer does not trust"
        } else {
            "the certificate chain does not verify"
        });
    }
    if !MICROSOFT_ROOTS
        .iter()
        .any(|(thumb, _)| thumb.eq_ignore_ascii_case(root_thumbprint))
    {
        return Err("the certificate chain does not end at a Microsoft product root");
    }
    if !signer.starts_with("Microsoft ") {
        return Err("the signer is not Microsoft");
    }
    // A signer whose certificate names its uses must be allowed to sign Windows' components.
    if !signer_ekus.is_empty() && !signer_ekus.iter().any(|eku| eku == WINDOWS_COMPONENT_EKU) {
        return Err("the signer's certificate is not one that signs Windows components");
    }
    Ok(())
}

/// Verifies a PKCS#7 signed message and returns what its signature shows, with the content the
/// signature covers. Only the certificates in the message and the local stores are used: no URL is
/// ever fetched. The content is returned whenever the signature itself verifies; whether it may be
/// trusted is `state == "microsoft"`.
pub fn verify(der: &[u8]) -> (Signature, Option<Vec<u8>>) {
    let para = CRYPT_VERIFY_MESSAGE_PARA {
        cbSize: std::mem::size_of::<CRYPT_VERIFY_MESSAGE_PARA>() as u32,
        dwMsgAndCertEncodingType: (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING).0,
        ..Default::default()
    };
    // First the size of the signed content, then the content itself.
    let mut size = 0u32;
    // SAFETY: `para` and `der` outlive the call; only the decoded size is asked for.
    let sized = unsafe { CryptVerifyMessageSignature(&para, 0, der, None, Some(&mut size), None) };
    if sized.is_err() || size as u64 > MAX_POLICY_BYTES {
        return (
            Signature::refused("invalid", String::new(), String::new(), "the signature does not verify"),
            None,
        );
    }
    let mut content = vec![0u8; size as usize];
    let mut signer: *mut CERT_CONTEXT = std::ptr::null_mut();
    // SAFETY: `content` is writable for `size` bytes, which is passed in `size`; `signer`
    // receives a certificate context that is freed below.
    let verified = unsafe {
        CryptVerifyMessageSignature(
            &para,
            0,
            der,
            Some(content.as_mut_ptr()),
            Some(&mut size),
            Some(&mut signer),
        )
    };
    if verified.is_err() || signer.is_null() {
        return (
            Signature::refused("invalid", String::new(), String::new(), "the signature does not verify"),
            None,
        );
    }
    content.truncate(size as usize);
    // A content type other than plain data comes back as its DER OCTET STRING: the policy is its
    // bytes. Unwrapped only when that element is exactly the whole content.
    if let Some((0x04, start, len)) = element(&content, 0)
        && start.checked_add(len) == Some(content.len())
    {
        content = content[start..].to_vec();
    }
    // SAFETY: `signer` is the live context returned above.
    let signer_name = unsafe { cert_name(signer) };
    // SAFETY: as above.
    let signer_ekus = unsafe { ekus(signer) };
    let chain = message_store(der).and_then(|store| {
        // SAFETY: `signer` is live and `store` open; the store is closed right after.
        let chain = unsafe { offline_chain(signer, store) };
        // SAFETY: `store` came from `message_store` and is not used afterwards.
        unsafe {
            let _ = CertCloseStore(Some(store), 0);
        }
        chain
    });
    // SAFETY: `signer` came from CryptVerifyMessageSignature and is not used afterwards.
    unsafe {
        let _ = CertFreeCertificateContext(Some(signer));
    }
    let signature = match chain {
        None => Signature::refused(
            "unknown",
            signer_name,
            String::new(),
            "no certificate chain could be built",
        ),
        Some((root, thumb, errors)) => match judge_chain(&signer_name, &signer_ekus, &thumb, errors) {
            Ok(()) => Signature {
                state: "microsoft".into(),
                signer: signer_name,
                root,
                reason: String::new(),
            },
            Err(reason) => Signature::refused("intact", signer_name, root, reason),
        },
    };
    (signature, Some(content))
}

/// What the signature of a message shows (see [`verify`]).
pub fn signature(der: &[u8]) -> Signature {
    verify(der).0
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
    /// Whether its rules were used to check drivers (only when the signature is "microsoft").
    pub used: bool,
    pub file_rules: u32,
    pub hash_rules: usize,
    pub name_rules: usize,
    /// Deny-by-name rules limited to some versions (counted, not checked).
    pub versioned_name_rules: usize,
    pub attribute_rules: usize,
    pub signer_rules: u32,
}

/// The installed policy: its rules and what is known about it.
#[derive(Debug, Clone)]
pub struct Policy {
    pub info: PolicyInfo,
    pub rules: Rules,
}

impl Policy {
    /// The rules to check drivers against: only those of a list signed by Microsoft. A policy whose
    /// signature is not "microsoft" never accuses a driver.
    pub fn trusted_rules(&self) -> Option<&Rules> {
        self.info.used.then_some(&self.rules)
    }
}

/// The Windows folder, from Windows itself (`GetSystemWindowsDirectoryW`), never from the
/// `SystemRoot` / `windir` variables a user's environment can override.
pub fn windows_dir() -> String {
    crate::paths::windows_dir().display().to_string()
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
    Ok(Some(policy_from(&der, path, modified_ms(&meta))?))
}

/// The policy in a `.p7b` file's bytes. The rules come from the content the signature check
/// returns; a message whose signature does not verify is still described (version, counts) from
/// its raw content, but never used.
fn policy_from(der: &[u8], path: &Path, modified_ms: i64) -> Result<Policy, String> {
    let (signature, signed) = verify(der);
    let rules = match &signed {
        Some(content) => parse_policy(content),
        None => pkcs7_content(der).and_then(parse_policy),
    }
    .ok_or_else(|| {
        if signed.is_some() || pkcs7_content(der).is_some() {
            "the policy has a layout Vigil does not know".to_string()
        } else {
            "not a signed policy".to_string()
        }
    })?;
    Ok(Policy {
        info: info_of(&rules, path, modified_ms, signature),
        rules,
    })
}

fn info_of(rules: &Rules, path: &Path, modified_ms: i64, signature: Signature) -> PolicyInfo {
    PolicyInfo {
        path: path.display().to_string(),
        version: rules.version.clone(),
        format: rules.format,
        modified_ms,
        used: signature.state == "microsoft",
        signature,
        file_rules: rules.file_rules,
        hash_rules: rules.hash_rules,
        name_rules: rules.name_rules,
        versioned_name_rules: rules.versioned_name_rules,
        attribute_rules: rules.attribute_rules,
        signer_rules: rules.signer_rules,
    }
}

/// The installed policy as last read, by the file's modification time: a policy that could not be
/// read is remembered too, so the watch does not read and verify a broken file every round.
type PolicyCacheEntry = (i64, Option<Arc<Policy>>);
static POLICY_CACHE: Mutex<Option<PolicyCacheEntry>> = Mutex::new(None);

/// The installed policy, parsed once and again only when the file changes (for the watch). `None`
/// when there is none or it cannot be read.
pub fn installed_policy() -> Option<Arc<Policy>> {
    let path = Path::new(&windows_dir()).join(POLICY_FILE);
    let stamp = std::fs::metadata(&path).ok().map(|m| modified_ms(&m))?;
    let mut cache = POLICY_CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((when, policy)) = cache.as_ref()
        && *when == stamp
    {
        return policy.clone();
    }
    let policy = read_policy_at(&path).ok().flatten().map(Arc::new);
    *cache = Some((stamp, policy.clone()));
    policy
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

/// The byte ranges the Authenticode hash covers in a PE file of `len` bytes whose first bytes are
/// `head`: the whole file except its checksum field, the certificate table entry and the
/// certificate table itself. `None` when it is not a PE file, or its headers are not within `head`.
fn authenticode_ranges(head: &[u8], len: usize) -> Option<Vec<(usize, usize)>> {
    if head.get(..2)? != b"MZ" {
        return None;
    }
    let header = le_u32(head, 0x3c)? as usize;
    if head.get(header..header.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let optional = header.checked_add(24)?;
    let directories = match le_u16(head, optional)? {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => return None,
    };
    let checksum = optional + 64;
    let count = le_u32(head, directories.checked_sub(4)?)?;
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    if count > 4 {
        let security = directories + 4 * 8;
        let offset = le_u32(head, security)? as usize;
        let size = le_u32(head, security + 4)? as usize;
        let end = if offset != 0 && size != 0 && offset.checked_add(size)? <= len && offset > security + 8 {
            offset
        } else {
            len
        };
        if security + 8 > end || checksum + 4 > security {
            return None;
        }
        ranges.extend([(0, checksum), (checksum + 4, security), (security + 8, end)]);
    } else {
        if checksum + 4 > len {
            return None;
        }
        ranges.extend([(0, checksum), (checksum + 4, len)]);
    }
    Some(ranges)
}

/// The Authenticode hashes of a PE image held in memory. `None` when it is not a PE file.
pub fn authenticode(pe: &[u8]) -> Option<AuthHashes> {
    let mut sha1 = sha1_smol::Sha1::new();
    let mut sha256 = Sha256::new();
    for (start, end) in authenticode_ranges(pe, pe.len())? {
        let part = pe.get(start..end)?;
        sha1.update(part);
        sha256.update(part);
    }
    Some(AuthHashes {
        sha1: sha1.digest().bytes(),
        sha256: sha256.finalize().into(),
    })
}

/// The first bytes of a driver file that are read to find its headers.
const HEAD_BYTES: usize = 64 * 1024;
/// The rest of the file is hashed this many bytes at a time, so memory does not grow with it.
const CHUNK_BYTES: usize = 256 * 1024;

/// A driver file hashed a piece at a time: `None` when it cannot be read, is not a PE file, or
/// changed size while it was read. Very large files are skipped.
pub fn file_hashes(path: &str) -> Option<AuthHashes> {
    use std::io::{Seek, SeekFrom};
    let mut file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_DRIVER_BYTES {
        return None;
    }
    let len = meta.len() as usize;
    let mut head = vec![0u8; len.min(HEAD_BYTES)];
    file.read_exact(&mut head).ok()?;
    let ranges = authenticode_ranges(&head, len)?;
    let mut sha1 = sha1_smol::Sha1::new();
    let mut sha256 = Sha256::new();
    let mut buffer = vec![0u8; CHUNK_BYTES];
    for (start, end) in ranges {
        file.seek(SeekFrom::Start(start as u64)).ok()?;
        let mut left = end.checked_sub(start)?;
        while left > 0 {
            let want = left.min(buffer.len());
            file.read_exact(&mut buffer[..want]).ok()?;
            sha1.update(&buffer[..want]);
            sha256.update(&buffer[..want]);
            left -= want;
        }
    }
    (file.metadata().ok()?.len() as usize == len).then(|| AuthHashes {
        sha1: sha1.digest().bytes(),
        sha256: sha256.finalize().into(),
    })
}

/// A file's original name from its version resource.
pub fn original_name(path: &str) -> Option<String> {
    crate::apps::version_string(path, "OriginalFilename")
}

/// What the watch keeps about one driver file: its hashes (`None`: not a readable PE file) and its
/// original file name (read only when the policy has name rules).
type Fingerprinted = (Option<AuthHashes>, Option<String>);
/// A driver file as the watch knows it: lower-case path, size, time, and whether its name was read.
type FileKey = (String, u64, i64, bool);

/// The watch's driver files already hashed, by path, size and time.
static WATCH_CACHE: Mutex<Option<HashMap<FileKey, Fingerprinted>>> = Mutex::new(None);
/// Whether the background hashing thread is running.
static WARMING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn file_key(path: &str, with_name: bool) -> Option<FileKey> {
    let meta = std::fs::metadata(path).ok()?;
    Some((path.to_lowercase(), meta.len(), modified_ms(&meta), with_name))
}

/// The blocklist verdict for each driver file, for the watch, or `None` while some of them are
/// still being hashed. Hashing never runs on the caller's thread: files not hashed yet (new ones,
/// or ones that changed since) are handed to one background thread that hashes them one at a time,
/// a bounded piece at a time; the watch reads the verdicts on a later round. A file that cannot be
/// read gives `None` in its place.
pub fn watch_hits(rules: &Rules, paths: &[String]) -> Option<Vec<Option<Hit>>> {
    let with_name = rules.has_name_rules();
    let keys: Vec<Option<FileKey>> = paths.iter().map(|p| file_key(p, with_name)).collect();
    let missing: Vec<(String, FileKey)> = {
        let mut cache = WATCH_CACHE.lock().unwrap_or_else(PoisonError::into_inner);
        let map = cache.get_or_insert_with(HashMap::new);
        paths
            .iter()
            .zip(&keys)
            .filter_map(|(path, key)| key.as_ref().map(|k| (path, k)))
            .filter(|(_, key)| !map.contains_key(*key))
            .map(|(path, key)| (path.clone(), key.clone()))
            .collect()
    };
    if !missing.is_empty() {
        warm(missing);
        return None;
    }
    let cache = WATCH_CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    let map = cache.as_ref()?;
    Some(
        keys.iter()
            .map(|key| {
                let (hashes, name) = map.get(key.as_ref()?)?;
                rules.check(hashes.as_ref()?, name.as_deref())
            })
            .collect(),
    )
}

/// Starts the background thread that hashes `missing`, unless one is already running (it will be
/// asked again on the next round for whatever it did not do).
fn warm(missing: Vec<(String, FileKey)>) {
    use std::sync::atomic::Ordering;
    if WARMING.swap(true, Ordering::AcqRel) {
        return;
    }
    let started = std::thread::Builder::new()
        .name("vigil-driver-hashes".into())
        .spawn(move || {
            for (path, key) in missing.into_iter().take(MAX_DRIVERS) {
                let found = (file_hashes(&path), if key.3 { original_name(&path) } else { None });
                let mut cache = WATCH_CACHE.lock().unwrap_or_else(PoisonError::into_inner);
                let map = cache.get_or_insert_with(HashMap::new);
                if map.len() > 8 * MAX_DRIVERS {
                    map.clear();
                }
                map.insert(key, found);
            }
            WARMING.store(false, Ordering::Release);
        });
    if started.is_err() {
        WARMING.store(false, Ordering::Release);
    }
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
        // Only a list signed by Microsoft accuses drivers; any other one is described, not used.
        Ok(Some(policy)) => {
            let mut report = match policy.trusted_rules() {
                Some(rules) => check_drivers(rules),
                None => Report::default(),
            };
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
    /// deny-by-name rule for every version, one for some versions, an allow rule and a file
    /// attribute.
    fn synthetic(sha1: [u8; 20], sha256: [u8; 32]) -> Vec<u8> {
        let mut p = Vec::new();
        put_u32(&mut p, 11); // format
        p.extend_from_slice(&[0x11; 32]); // GUIDs
        put_u32(&mut p, 0x8088_0000); // options
        put_u32(&mut p, 0); // EKUs
        put_u32(&mut p, 6); // file rules
        put_u32(&mut p, 2); // signers
        put_u32(&mut p, 2); // scenarios
        for part in [4u16, 3, 2, 1] {
            p.extend_from_slice(&part.to_le_bytes()); // version 1.2.3.4
        }
        put_u32(&mut p, 64);
        let mut rule = |kind: u32, name: &str, hash: &[u8], version: [u8; 8]| {
            put_u32(&mut p, kind);
            put_padded(&mut p, &utf16(name));
            put_u32(&mut p, 0);
            p.extend_from_slice(&version);
            put_padded(&mut p, hash);
        };
        let every = [0xff; 8];
        rule(0, "", &sha1, every);
        rule(0, "", &sha256, every);
        rule(0, "Contoso.sys", &[], every);
        // Version 3.2.1.0: some versions only.
        rule(0, "Tailspin.sys", &[], [0, 0, 1, 0, 2, 0, 3, 0]);
        rule(1, "*", &[], every);
        rule(2, "fabrikam.sys", &[], every);
        p
    }

    #[test]
    fn a_synthetic_policy_is_parsed() {
        let rules = parse_policy(&synthetic([1; 20], [2; 32])).expect("parsed");
        assert_eq!(rules.format, 11);
        assert_eq!(rules.version, "1.2.3.4");
        assert_eq!(rules.file_rules, 6);
        assert_eq!(rules.hash_rules, 2);
        assert_eq!(rules.name_rules, 1);
        assert_eq!(rules.versioned_name_rules, 1);
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
        assert_eq!(
            rules.check(&other, Some("Tailspin.sys")),
            None,
            "a name rule for some versions only never accuses a driver"
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
                "policy format {} version {} signature {} (signer {}, root {}, reason {:?}), used {}: {} file rules ({} hash, {} name for every version, {} name for some versions, {} attribute), {} signers",
                info.format,
                info.version,
                info.signature.state,
                info.signature.signer,
                info.signature.root,
                info.signature.reason,
                info.used,
                info.file_rules,
                info.hash_rules,
                info.name_rules,
                info.versioned_name_rules,
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
    #[test]
    fn only_a_chain_to_a_microsoft_product_root_is_trusted() {
        let ekus = vec![WINDOWS_COMPONENT_EKU.to_string(), "1.3.6.1.5.5.7.3.3".to_string()];
        let root = "3B1EFD3A66EA28B16697394703A72CA340A05BD5";
        // Windows' own list: complete, Microsoft root, Microsoft signer; expired and offline
        // revocation are tolerated (the real file's certificate has expired).
        assert_eq!(judge_chain("Microsoft Windows", &ekus, root, 0), Ok(()));
        assert_eq!(judge_chain("Microsoft Windows", &ekus, root, 0x0100_0041), Ok(()));
        // A self-signed or unknown root: refused, whatever the signer is called.
        assert!(
            judge_chain(
                "Microsoft Windows",
                &ekus,
                "1111111111111111111111111111111111111111",
                0x20
            )
            .is_err()
        );
        assert!(
            judge_chain(
                "Microsoft Windows",
                &ekus,
                "1111111111111111111111111111111111111111",
                0
            )
            .is_err()
        );
        // A chain that stops short, or whose signatures do not verify.
        assert!(judge_chain("Microsoft Windows", &ekus, root, 0x0001_0000).is_err());
        assert!(judge_chain("Microsoft Windows", &ekus, root, 0x08).is_err());
        // Microsoft's development root is not a product root.
        assert!(
            judge_chain(
                "Microsoft Windows",
                &ekus,
                "F8DB7E1C16F1FFD4AAAD4AAD8DFF0F2445184AEB",
                0
            )
            .is_err()
        );
        // Not Microsoft's signer, or a certificate not meant for Windows components.
        assert!(judge_chain("Contoso Ltd", &ekus, root, 0).is_err());
        assert!(judge_chain("Microsoft Windows", &["1.3.6.1.5.5.7.3.1".to_string()], root, 0).is_err());
    }

    #[test]
    fn a_policy_nobody_signed_is_described_but_never_used() {
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
        let found = policy_from(&message, Path::new("driversipolicy.p7b"), 0).expect("described");
        assert_eq!(found.info.signature.state, "invalid");
        assert!(!found.info.used);
        assert!(found.trusted_rules().is_none(), "an unsigned list accuses nothing");
        assert_eq!(found.info.hash_rules, 2, "its counts are still told");
        // The same rules, once the signature is Microsoft's (the test seam), are checked.
        let mut trusted = found;
        trusted.info.used = true;
        let rules = trusted.trusted_rules().expect("used");
        let hashes = AuthHashes {
            sha1: [9; 20],
            sha256: [2; 32],
        };
        assert_eq!(rules.check(&hashes, None), Some(Hit::Hash));
    }

    #[test]
    fn an_element_may_not_reach_past_its_parent() {
        // An OCTET STRING that claims more bytes than its parent SEQUENCE holds.
        let inner = [0x04, 0x05, 1, 2, 3, 4, 5];
        let mut message = der(0x30, &inner);
        message[1] = 3; // the SEQUENCE now ends inside the OCTET STRING
        assert!(child(&message, 2, 2 + 3, 0x04).is_none());
        assert!(child(&message, 2, message.len(), 0x04).is_some());
    }

    #[test]
    fn a_file_is_hashed_in_pieces_like_in_memory() {
        let dir = std::env::temp_dir().join(format!("vigil-drvblock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        for (name, image) in [("signed.sys", pe(true)), ("plain.sys", pe(false))] {
            let path = dir.join(name);
            std::fs::write(&path, &image).expect("write");
            assert_eq!(file_hashes(&path.display().to_string()), authenticode(&image), "{name}");
        }
        // Bigger than one piece.
        let mut big = pe(false);
        big.extend((0..(CHUNK_BYTES * 2 + 123)).map(|i| (i % 253) as u8));
        let path = dir.join("big.sys");
        std::fs::write(&path, &big).expect("write");
        assert_eq!(file_hashes(&path.display().to_string()), authenticode(&big));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_watch_waits_for_the_background_hashing() {
        let dir = std::env::temp_dir().join(format!("vigil-drvblock-watch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let listed = dir.join("listed.sys");
        let other = dir.join("other.sys");
        let mut image = pe(true);
        std::fs::write(&listed, &image).expect("write");
        image[0x360] ^= 0xff;
        std::fs::write(&other, &image).expect("write");
        let listed_hashes = file_hashes(&listed.display().to_string()).expect("hashed");
        let mut rules = parse_policy(&synthetic([1; 20], [2; 32])).expect("rules");
        rules.sha256.insert(listed_hashes.sha256);
        let paths = vec![
            listed.display().to_string(),
            other.display().to_string(),
            dir.join("missing.sys").display().to_string(),
        ];
        // The first call only starts the background thread.
        let mut hits = watch_hits(&rules, &paths);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while hits.is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
            hits = watch_hits(&rules, &paths);
        }
        assert_eq!(hits, Some(vec![Some(Hit::Hash), None, None]));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
