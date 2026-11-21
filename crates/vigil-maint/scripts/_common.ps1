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

function Write-JsonFile {
    param([string]$Path, $Data)
    $json = ConvertTo-Json -InputObject $Data -Depth 8 -Compress
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
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
