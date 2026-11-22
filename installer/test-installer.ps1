# Installs Vigil's setup silently, checks what it put where, upgrades over it, and uninstalls it.
# Needs administrator rights without a UAC prompt (a CI runner): it changes Program Files, the Start
# menu and HKLM. -ChecksOnly runs only the checks that need no rights (the command line and the MCP
# handshake of an executable, the shortcut reader on a temporary shortcut).
#
#   installer\test-installer.ps1 -Setup <setup.exe> -Version 2.0.0 [-OldSetup <1.x setup.exe>]
#   installer\test-installer.ps1 -ChecksOnly -Exe target\release\vigil.exe
param(
    [string]$Setup,
    [string]$Version,
    [string]$OldSetup,
    [switch]$ChecksOnly,
    [string]$Exe
)
$ErrorActionPreference = "Stop"
$failures = [System.Collections.Generic.List[string]]::new()
function Check([bool]$ok, [string]$what) {
    if ($ok) { Write-Output "ok    $what" } else { Write-Output "FAIL  $what"; $failures.Add($what) }
}

$installDir = Join-Path $env:ProgramFiles "Vigil"
$shortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Vigil.lnk"
$publicDesktop = Join-Path $env:PUBLIC "Desktop\Vigil.lnk"
$uninstallKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Vigil"
$vendorKey = "HKLM:\Software\andresayac\Vigil"
$aumid = "com.andresayac.vigil"

# A shortcut's target and AppUserModelID, read through the Shell's property system. The path travels
# in an environment variable, never inside script text.
function Read-Shortcut([string]$path) {
    $env:VIGIL_TEST_LNK = $path
    $shell = New-Object -ComObject Shell.Application
    $folder = $shell.Namespace((Split-Path $env:VIGIL_TEST_LNK))
    $item = $folder.ParseName((Split-Path $env:VIGIL_TEST_LNK -Leaf))
    $wsh = New-Object -ComObject WScript.Shell
    [pscustomobject]@{
        Target = $wsh.CreateShortcut($env:VIGIL_TEST_LNK).TargetPath
        Aumid  = [string]$item.ExtendedProperty("System.AppUserModel.ID")
    }
}

# `vigil --help` and an MCP initialize + tools/list handshake over stdio.
function Test-CommandLines([string]$exe) {
    $help = & $exe --help | Out-String
    Check ($LASTEXITCODE -eq 0 -and $help -match "Usage") "vigil --help prints the usage"
    $requests = @(
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"installer-test","version":"1"}}}',
        '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
    ) -join "`n"
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $exe
    $info.Arguments = "mcp"
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($info)
    # Raw UTF-8 bytes: the stream writer would put a byte order mark before the first request.
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($requests + "`n")
    $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
    $process.StandardInput.Close()
    $output = $process.StandardOutput.ReadToEnd()
    if (-not $process.WaitForExit(30000)) { $process.Kill() }
    $answers = @($output -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
    $init = $answers | Where-Object { $_.id -eq 1 }
    $tools = $answers | Where-Object { $_.id -eq 2 }
    Check ($null -ne $init -and $init.result.serverInfo.name -eq "vigil") "vigil mcp answers initialize"
    Check ($null -ne $tools -and @($tools.result.tools).Count -gt 0) "vigil mcp lists its tools ($(@($tools.result.tools).Count))"
}

if ($ChecksOnly) {
    Test-CommandLines (Resolve-Path $Exe).Path
    $dir = Join-Path $env:TEMP ("vigil-lnk-" + [guid]::NewGuid())
    New-Item -ItemType Directory $dir | Out-Null
    try {
        $lnk = Join-Path $dir "Test.lnk"
        $s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
        $s.TargetPath = (Join-Path $env:SystemRoot "System32\notepad.exe")
        $s.Save()
        $read = Read-Shortcut $lnk
        Check ($read.Target -like "*notepad.exe") "the shortcut reader reads a target"
        Check ($read.Aumid -eq "") "a shortcut without an AppUserModelID reads empty"
    }
    finally { Remove-Item -Recurse -Force $dir }
    if ($failures.Count) { exit 1 } else { exit 0 }
}

function Invoke-Setup([string]$path, [string]$what) {
    $p = Start-Process -FilePath $path -ArgumentList "/S" -PassThru -Wait
    Check ($p.ExitCode -eq 0) "$what exits with 0 ($($p.ExitCode))"
}

function Show-State([string]$title) {
    Write-Output "--- $title"
    if (Test-Path $installDir) { Get-ChildItem -Recurse -Force $installDir | ForEach-Object { "  file  $($_.FullName)" } }
    foreach ($path in @($shortcut, $publicDesktop, (Join-Path ([Environment]::GetFolderPath("Desktop")) "Vigil.lnk"))) {
        if (Test-Path $path) { "  link  $path" }
    }
    foreach ($key in @($uninstallKey, $vendorKey, "HKCU:\Software\andresayac\Vigil")) {
        if (Test-Path $key) {
            "  key   $key"
            (Get-ItemProperty $key).PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } |
                ForEach-Object { "        $($_.Name) = $($_.Value)" }
        }
    }
}

function Test-Installed([string]$what) {
    $exe = Join-Path $installDir "vigil.exe"
    Check (Test-Path $exe) "$what`: vigil.exe in Program Files"
    Check (Test-Path (Join-Path $installDir "uninstall.exe")) "$what`: uninstall.exe in Program Files"
    $others = @(Get-ChildItem -Force $installDir | Where-Object { $_.Name -notin @("vigil.exe", "uninstall.exe") })
    Check ($others.Count -eq 0) "$what`: nothing else in the folder ($($others.Name -join ', '))"
    if (Test-Path $exe) {
        Check ((Get-Item $exe).VersionInfo.ProductVersion -eq $Version) "$what`: vigil.exe is version $Version"
    }
    Check (Test-Path $shortcut) "$what`: Start menu shortcut"
    if (Test-Path $shortcut) {
        $read = Read-Shortcut $shortcut
        Check ($read.Target -eq $exe) "$what`: the shortcut starts $exe ($($read.Target))"
        Check ($read.Aumid -eq $aumid) "$what`: the shortcut's AppUserModelID is $aumid ($($read.Aumid))"
    }
    Check (Test-Path $uninstallKey) "$what`: uninstall entry"
    if (Test-Path $uninstallKey) {
        $entry = Get-ItemProperty $uninstallKey
        Check ($entry.DisplayVersion -eq $Version) "$what`: uninstall entry version $Version"
        Check ($entry.InstallLocation -eq $installDir) "$what`: uninstall entry location"
    }
    Check (-not (Test-Path $vendorKey)) "$what`: no vendor key left from an earlier installer"
    if (Test-Path $exe) { Test-CommandLines $exe }
}

if ($OldSetup) {
    Invoke-Setup $OldSetup "the earlier setup"
    # An earlier installer may start the app at the end; it must not hold the file.
    Start-Sleep -Seconds 3
    Get-Process vigil -ErrorAction SilentlyContinue | Stop-Process -Force
    Show-State "after the earlier setup"
}

Invoke-Setup $Setup "the setup"
Show-State "after the setup"
Test-Installed "install"

Invoke-Setup $Setup "the setup over itself"
Test-Installed "upgrade"

# Vigil's data folder must survive the uninstall.
$data = Join-Path $env:ProgramData "Vigil"
New-Item -ItemType Directory -Force $data | Out-Null
$marker = Join-Path $data "installer-test.txt"
Set-Content -Path $marker -Value "kept"

$uninstaller = Join-Path $installDir "uninstall.exe"
Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait
# The uninstaller runs from a temporary copy so it can remove itself: wait for it.
for ($i = 0; $i -lt 60 -and (Test-Path $installDir); $i++) { Start-Sleep -Seconds 1 }
Show-State "after the uninstall"
Check (-not (Test-Path $installDir)) "uninstall: the install folder is gone"
Check (-not (Test-Path $shortcut)) "uninstall: the Start menu shortcut is gone"
Check (-not (Test-Path $publicDesktop)) "uninstall: no desktop shortcut is left"
Check (-not (Test-Path $uninstallKey)) "uninstall: the uninstall entry is gone"
Check (-not (Test-Path $vendorKey)) "uninstall: no vendor key is left"
Check (Test-Path $marker) "uninstall: Vigil's data folder is kept"
Remove-Item -Force $marker

if ($failures.Count) {
    Write-Output "$($failures.Count) check(s) failed"
    exit 1
}
Write-Output "every check passed"
