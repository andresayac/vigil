# Authenticode signature and version information for a list of files (read-only).
# InPath: UTF-8 text file with one path per line.
param(
    [Parameter(Mandatory = $true)][string]$InPath,
    [Parameter(Mandatory = $true)][string]$OutPath
)
. "$PSScriptRoot\_common.ps1"

$paths = [System.IO.File]::ReadAllLines($InPath, [System.Text.Encoding]::UTF8)
$files = New-Object System.Collections.ArrayList

foreach ($p in $paths) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    # exists: $true / $false / $null (could not be checked, e.g. access denied)
    $r = @{ path = $p; exists = $null }

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

    [void]$files.Add($r)
}

Write-JsonFile $OutPath @{ files = @($files) }
