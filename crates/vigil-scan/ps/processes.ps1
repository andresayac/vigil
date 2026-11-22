# Running processes (read-only).
. "$PSScriptRoot\_common.ps1"

$processes = @()
try {
    $processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
        @{
            pid     = [int]$_.ProcessId
            ppid    = [int]$_.ParentProcessId
            name    = $_.Name
            path    = $_.ExecutablePath
            cmd     = $_.CommandLine
            started = (ConvertTo-Iso $_.CreationDate)
            session = $_.SessionId
            mem_mb  = [math]::Round($_.WorkingSetSize / 1MB, 1)
        }
    })
} catch { Add-Note 'processes' $_.Exception.Message }

Write-Result @{ processes = $processes; notes = @($script:Notes) }
