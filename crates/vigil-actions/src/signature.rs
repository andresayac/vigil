//! Live Authenticode checks (the scan data may be stale): the same fields as the scan's signature check.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{ActionError, Result};
use crate::runner;
use vigil_i18n::tr;

/// Signature and version information of one file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct SignatureInfo {
    pub path: String,
    /// `None` when it could not be checked (access denied).
    pub exists: Option<bool>,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub company: Option<String>,
    pub description: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub original: Option<String>,
    /// `Valid`, `NotSigned`, `HashMismatch`, `Error`...
    pub sig_status: Option<String>,
    pub sig_type: Option<String>,
    pub os_binary: bool,
    pub signer: Option<String>,
    pub signer_subject: Option<String>,
    pub issuer: Option<String>,
    pub cert_not_after: Option<String>,
    pub error: Option<String>,
}

/// `Get-SignatureInfo $path`: the fields of [`SignatureInfo`] for one file.
const CHECK: &str = r#"
function ConvertTo-Iso($Value) {
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToString('yyyy-MM-ddTHH:mm:ss') } catch { return $null }
}
function Get-SignatureInfo($p) {
$r = [ordered]@{ path = $p; exists = $null }
$item = $null
try {
    $item = Get-Item -LiteralPath $p -Force -ErrorAction Stop
} catch [System.Management.Automation.ItemNotFoundException] {
    $r.exists = $false
} catch {
    $r.error = $_.Exception.Message
}
if ($item -and -not $item.PSIsContainer) {
    $r.exists = $true
    $r.size = $item.Length
    $r.created = ConvertTo-Iso $item.CreationTime
    $r.modified = ConvertTo-Iso $item.LastWriteTime
    $vi = $item.VersionInfo
    if ($vi) {
        $r.company = $vi.CompanyName
        $r.description = $vi.FileDescription
        $r.product = $vi.ProductName
        $r.version = $vi.FileVersion
        $r.original = $vi.OriginalFilename
    }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
        $r.sig_status = [string]$sig.Status
        $r.sig_type = [string]$sig.SignatureType
        $r.os_binary = [bool]$sig.IsOSBinary
        $cert = $sig.SignerCertificate
        if ($cert) {
            $r.signer = $cert.GetNameInfo('SimpleName', $false)
            $r.signer_subject = $cert.Subject
            $r.issuer = $cert.GetNameInfo('SimpleName', $true)
            $r.cert_not_after = ConvertTo-Iso $cert.NotAfter
        }
    } catch {
        $r.sig_status = 'Error'
        $r.error = $_.Exception.Message
    }
} elseif ($item) {
    $r.exists = $true
    $r.is_dir = $true
}
$r
}
"#;

const ONE: &str = "ConvertTo-Json -InputObject (Get-SignatureInfo $env:PC_PATH) -Compress -Depth 4";

/// Several files, one per line of `PC_PATHS`, answered as one JSON array in the same order.
const MANY: &str = r#"
$list = @(foreach ($p in ("$env:PC_PATHS" -split "`n")) { if ($p) { [pscustomobject](Get-SignatureInfo $p) } })
ConvertTo-Json -InputObject $list -Compress -Depth 4
"#;

/// The most files one PowerShell checks (their paths travel in one environment variable).
const BATCH: usize = 40;

/// The live check, or `None` when it could not run.
pub(crate) fn signature_info(path: &str) -> Option<SignatureInfo> {
    if let Some(check) = crate::testing::signature() {
        return check(path);
    }
    let (args, env) = runner::ps_command(&format!("{CHECK}\n{ONE}"), &[("path", path)]);
    let result = runner::run_system(&args, 120, Some(&env)).ok()?;
    if result.code != 0 {
        return None;
    }
    let line = result
        .out
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))?;
    serde_json::from_str(line.trim()).ok()
}

/// Checks a file's signature now.
pub fn verify_signature(path: &Path) -> Result<SignatureInfo> {
    signature_info(&path.to_string_lossy()).ok_or_else(|| ActionError::new(tr!("the signature could not be checked")))
}

/// Checks many files at once: one PowerShell per few dozen files instead of one per file. The
/// answer has one entry per path, in order; `None` for a file that could not be checked.
pub fn verify_signatures(paths: &[String]) -> Vec<Option<SignatureInfo>> {
    if let Some(check) = crate::testing::signature() {
        return paths.iter().map(|p| check(p)).collect();
    }
    let mut out = Vec::with_capacity(paths.len());
    for chunk in paths.chunks(BATCH) {
        // A path with a line break cannot be passed this way (and names no real file).
        let clean: Vec<&str> = chunk
            .iter()
            .map(|p| if p.contains(['\r', '\n']) { "" } else { p.as_str() })
            .collect();
        let found = batch(&clean).unwrap_or_default();
        for path in &clean {
            out.push(
                found
                    .iter()
                    .find(|info| !path.is_empty() && info.path == *path)
                    .cloned(),
            );
        }
    }
    out
}

fn batch(paths: &[&str]) -> Option<Vec<SignatureInfo>> {
    let joined = paths
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    if joined.is_empty() {
        return Some(Vec::new());
    }
    let (args, env) = runner::ps_command(&format!("{CHECK}\n{MANY}"), &[("paths", &joined)]);
    let result = runner::run_system(&args, 300, Some(&env)).ok()?;
    if result.code != 0 {
        return None;
    }
    let line = result
        .out
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('['))?;
    serde_json::from_str(line.trim()).ok()
}

const MICROSOFT_SIGNERS: [&str; 10] = [
    "microsoft windows",
    "microsoft corporation",
    "microsoft windows publisher",
    "microsoft windows kits publisher",
    ".net",
    "microsoft windows early launch anti-malware publisher",
    "microsoft windows tcb publisher",
    "microsoft windows software compatibility publisher",
    "microsoft azure code sign",
    "microsoft dynamic code publisher",
];

/// Microsoft signature on THIRD-PARTY code: it does not mean Microsoft is the author.
const THIRD_PARTY_ATTESTATION: [&str; 3] = [
    "microsoft windows hardware compatibility publisher",
    "microsoft windows third party component",
    "microsoft 3rd party application component",
];

/// A valid Microsoft signature on Microsoft's own software.
pub fn is_microsoft_signed(info: Option<&SignatureInfo>) -> bool {
    let Some(info) = info else {
        return false;
    };
    if info.sig_status.as_deref() != Some("Valid") {
        return false;
    }
    if info.os_binary {
        return true;
    }
    let signer = info.signer.as_deref().unwrap_or("").to_lowercase();
    let issuer = info.issuer.as_deref().unwrap_or("").to_lowercase();
    if THIRD_PARTY_ATTESTATION.contains(&signer.as_str()) {
        return false;
    }
    MICROSOFT_SIGNERS.contains(&signer.as_str()) && issuer.starts_with("microsoft")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(signer: &str, issuer: &str) -> SignatureInfo {
        SignatureInfo {
            sig_status: Some("Valid".into()),
            signer: Some(signer.into()),
            issuer: Some(issuer.into()),
            ..SignatureInfo::default()
        }
    }

    #[test]
    fn microsoft_signers() {
        assert!(is_microsoft_signed(Some(&signed(
            "Microsoft Corporation",
            "Microsoft Code Signing PCA 2011"
        ))));
        assert!(!is_microsoft_signed(Some(&signed(
            "Microsoft Windows Hardware Compatibility Publisher",
            "Microsoft"
        ))));
        assert!(!is_microsoft_signed(Some(&signed("Microsoft Corporation", "Fake CA"))));
        assert!(!is_microsoft_signed(Some(&signed("Vendor Inc.", "DigiCert"))));
        assert!(!is_microsoft_signed(None));
    }

    #[test]
    fn reads_the_script_output() {
        let info: SignatureInfo = serde_json::from_str(
            r#"{"path":"C:\\x.exe","exists":true,"size":12,"sig_status":"Valid","os_binary":true,"signer":null}"#,
        )
        .unwrap_or_default();
        assert_eq!(info.size, Some(12));
        assert!(info.os_binary && is_microsoft_signed(Some(&info)));
        let ui = serde_json::to_value(&info).unwrap_or_default();
        assert!(ui.get("sigStatus").is_some() && ui.get("osBinary").is_some());
    }
}
