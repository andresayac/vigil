# Smoke test of Vigil's window: every page and dialog in demo mode (fictitious data; nothing is
# read from or changed on the computer), in the chosen themes and languages.
#
#   installer\smoke-window.ps1 -Exe target\debug\vigil.exe [-Out C:\temp\smoke] [-Themes light,dark]
#                              [-Languages en,es,fr,pt,zh] [-Full]
#
# For each run it checks that the window appears, that the process is still alive a few seconds
# later, that nothing panicked (stderr), and that UI Automation sees the window's controls, none of
# the focusable ones without a name. With -Out it also saves a capture of each window (PrintWindow).
# By default every page and dialog runs in every theme in English, and in one theme in the other
# languages (alternating light and dark); -Full runs every theme in every language.
# Exits with 1 when any run failed. Runs in Windows PowerShell 5.1 (UI Automation for .NET).

param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [string]$Out = "",
    [string[]]$Themes = @("light", "dark"),
    [string[]]$Languages = @("en", "es", "fr", "pt", "zh"),
    [switch]$Full,
    # Only these pages or dialogs (page keys, or dialog-<name>); all when empty.
    [string[]]$Only = @(),
    [int]$StartSeconds = 30,
    [int]$SettleSeconds = 3
)

$ErrorActionPreference = "Stop"
# `-File` passes "a,b" as one string: split lists here.
$Only = @($Only | ForEach-Object { $_ -split "," } | Where-Object { $_ })
$Themes = @($Themes | ForEach-Object { $_ -split "," } | Where-Object { $_ })
$Languages = @($Languages | ForEach-Object { $_ -split "," } | Where-Object { $_ })
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class SmokeWin {
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
"@
[SmokeWin]::SetProcessDPIAware() | Out-Null

$Exe = (Resolve-Path $Exe).Path
if ($Out) { New-Item -ItemType Directory -Force $Out | Out-Null }
$logs = Join-Path ([IO.Path]::GetTempPath()) ("vigil-smoke-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $logs | Out-Null

# The pages in the window's order (crates/vigil-app/src/shell.rs PAGES) and the previewable dialogs.
$pages = @("overview", "findings", "alerts", "protection", "posture", "firewall", "accounts", "extensions",
    "quarantine", "history", "performance", "processes", "network", "services", "optimize", "startup",
    "tasks", "programs", "storage", "restore", "system", "updates", "power", "reliability")
$dialogs = @("settings", "scan", "run", "search", "welcome")
$targets = @($pages | ForEach-Object { @{ Name = $_; Args = @("--page", $_) } }) +
    @($dialogs | ForEach-Object { @{ Name = "dialog-$_"; Args = @("--dialog", $_) } })
if ($Only.Count -gt 0) { $targets = @($targets | Where-Object { $Only -contains $_.Name }) }

function Save-Capture([IntPtr]$hwnd, [string]$path) {
    $rect = New-Object SmokeWin+RECT
    [SmokeWin]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
    $width = $rect.Right - $rect.Left; $height = $rect.Bottom - $rect.Top
    if ($width -le 0 -or $height -le 0) { return $false }
    $bitmap = New-Object System.Drawing.Bitmap $width, $height
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $dc = $graphics.GetHdc()
    $ok = [SmokeWin]::PrintWindow($hwnd, $dc, 2)
    $graphics.ReleaseHdc($dc); $graphics.Dispose()
    if ($ok) { $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png) }
    $bitmap.Dispose()
    return $ok
}

# Named and unnamed focusable controls under the window (UI Automation). The tree is built
# lazily by some frameworks, so it is read twice when the first read finds nothing.
function Read-Automation([IntPtr]$hwnd) {
    $result = @{ Controls = 0; Focusable = 0; Unnamed = @(); Hosts = 0 }
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        $root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
        $all = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants,
            [System.Windows.Automation.Condition]::TrueCondition)
        $result.Controls = $all.Count
        $result.Focusable = 0
        $result.Unnamed = @()
        $result.Hosts = 0
        foreach ($element in $all) {
            try {
                $current = $element.Current
                if ($current.IsKeyboardFocusable -and $current.IsEnabled) {
                    $result.Focusable++
                    if ([string]::IsNullOrWhiteSpace($current.Name)) {
                        if ($current.ControlType -eq [System.Windows.Automation.ControlType]::Window) {
                            # The container a dialog opens in (the UI toolkit's own dialog host,
                            # whose accessible name the toolkit does not let the app set). Its
                            # title is the first named element inside; counted, not failed.
                            $result.Hosts++
                        } else {
                            $result.Unnamed += $current.ControlType.ProgrammaticName
                        }
                    }
                }
            } catch { }
        }
        if ($result.Controls -gt 0) { break }
        Start-Sleep -Seconds 1
    }
    return $result
}

function Invoke-Run($target, [string]$theme, [string]$language) {
    $name = "$($target.Name)-$theme-$language"
    $stderr = Join-Path $logs "$name.err"
    $arguments = @("--demo") + $target.Args + @("--theme", $theme, "--lang", $language, "--size", "1280x800")
    $row = [ordered]@{ Run = $name; Window = "no"; Alive = "no"; Panic = "no"; Controls = 0; Focusable = 0; Unnamed = 0; DialogHost = 0; Capture = "-"; Result = "FAIL" }
    $process = Start-Process -FilePath $Exe -ArgumentList $arguments -PassThru -RedirectStandardError $stderr -WindowStyle Normal
    try {
        $deadline = (Get-Date).AddSeconds($StartSeconds)
        do { Start-Sleep -Milliseconds 250; $process.Refresh() } while ($process.MainWindowHandle -eq 0 -and -not $process.HasExited -and (Get-Date) -lt $deadline)
        if ($process.MainWindowHandle -ne 0) { $row.Window = "yes" }
        Start-Sleep -Seconds $SettleSeconds
        $process.Refresh()
        if (-not $process.HasExited) { $row.Alive = "yes" }
        if ($row.Window -eq "yes" -and $row.Alive -eq "yes") {
            $hwnd = $process.MainWindowHandle
            $automation = Read-Automation $hwnd
            $row.Controls = $automation.Controls
            $row.Focusable = $automation.Focusable
            $row.Unnamed = $automation.Unnamed.Count
            $row.DialogHost = $automation.Hosts
            if ($automation.Unnamed.Count -gt 0) {
                Write-Host ("  {0}: focusable controls without a name: {1}" -f $name, (($automation.Unnamed | Group-Object | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ", "))
            }
            if ($Out) {
                $row.Capture = if (Save-Capture $hwnd (Join-Path $Out "$name.png")) { "yes" } else { "no" }
            }
        }
    } finally {
        if (-not $process.HasExited) {
            $process.CloseMainWindow() | Out-Null
            if (-not $process.WaitForExit(5000)) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        }
    }
    $errors = if (Test-Path $stderr) { Get-Content $stderr -Raw } else { "" }
    if ($errors -match "panicked at|RUST_BACKTRACE|stack backtrace") {
        $row.Panic = "yes"
        Write-Host "  ${name}: $($errors.Trim())"
    }
    if ($row.Window -eq "yes" -and $row.Alive -eq "yes" -and $row.Panic -eq "no" -and $row.Controls -gt 0 -and $row.Unnamed -eq 0) {
        $row.Result = "ok"
    }
    return [pscustomobject]$row
}

$rows = @()
$index = 0
foreach ($language in $Languages) {
    foreach ($target in $targets) {
        if ($Full -or $language -eq "en") {
            $runThemes = $Themes
        } else {
            # One theme per run in the other languages, alternating, so each page is seen in both.
            $runThemes = @($Themes[$index % $Themes.Count])
            $index++
        }
        foreach ($theme in $runThemes) {
            $row = Invoke-Run $target $theme $language
            Write-Host ("{0,-40} window {1,-3} alive {2,-3} panic {3,-3} controls {4,4} focusable {5,3} unnamed {6,2} host {7}  {8}" -f `
                $row.Run, $row.Window, $row.Alive, $row.Panic, $row.Controls, $row.Focusable, $row.Unnamed, $row.DialogHost, $row.Result)
            $rows += $row
        }
    }
}

Remove-Item -Recurse -Force $logs -ErrorAction SilentlyContinue
$failed = @($rows | Where-Object { $_.Result -ne "ok" })
if ($Out) { $rows | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Out "summary.csv") }
Write-Host ""
Write-Host ("{0} runs: {1} ok, {2} failed" -f $rows.Count, ($rows.Count - $failed.Count), $failed.Count)
$hosts = @($rows | Where-Object { $_.DialogHost -gt 0 }).Count
if ($hosts -gt 0) {
    Write-Host "$hosts runs had a dialog container without an accessible name (the UI toolkit's dialog host; not counted as a failure)."
}
if ($failed.Count -gt 0) {
    $failed | ForEach-Object { Write-Host "FAILED  $($_.Run)" }
    exit 1
}
exit 0
