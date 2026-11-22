# Helpers shared by the collectors.
# IMPORTANT: keep these .ps1 files pure ASCII. Windows PowerShell 5.1 reads scripts
# without a BOM using the ANSI code page, which would corrupt non-ASCII characters.
# Every collector is READ-ONLY: none of them changes anything on the system.

$ProgressPreference = 'SilentlyContinue'
$script:Notes = New-Object System.Collections.ArrayList

function Add-Note {
    param([string]$Area, [string]$Message)
    [void]$script:Notes.Add(@{ area = $Area; message = $Message })
}

function ConvertTo-Iso {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToString('yyyy-MM-ddTHH:mm:ss') } catch { return $null }
}

# The result goes to standard output after a marker, as raw UTF-8 bytes on their own line: no
# file is written (the collectors run elevated, and a file in a folder the user can write could be
# changed before Vigil reads it), and the console code page cannot alter the text.
function Write-Result {
    param($Data)
    $json = ConvertTo-Json -InputObject $Data -Depth 8 -Compress
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes("`nVIGIL-JSON:" + $json + "`n")
    $out = [Console]::OpenStandardOutput()
    $out.Write($bytes, 0, $bytes.Length)
    $out.Flush()
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Limit-Text {
    param([string]$Text, [int]$Max)
    if ($null -eq $Text) { return $null }
    if ($Text.Length -le $Max) { return $Text }
    return $Text.Substring(0, $Max)
}
