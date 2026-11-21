# Registered services and drivers (read-only).
param([Parameter(Mandatory = $true)][string]$OutPath)
. "$PSScriptRoot\_common.ps1"

$services = @()
try {
    $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
        # Services hosted in svchost declare their real DLL in Parameters\ServiceDll.
        $base = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($_.Name)"
        $dll = $null
        try { $dll = [Microsoft.Win32.Registry]::GetValue("$base\Parameters", 'ServiceDll', $null) } catch { }
        if (-not $dll) {
            try { $dll = [Microsoft.Win32.Registry]::GetValue($base, 'ServiceDll', $null) } catch { }
        }
        @{
            name    = $_.Name
            display = $_.DisplayName
            state   = $_.State
            start   = $_.StartMode
            path    = $_.PathName
            account = $_.StartName
            pid     = [int]$_.ProcessId
            desc    = $_.Description
            dll     = $dll
        }
    })
} catch { Add-Note 'services' $_.Exception.Message }

$drivers = @()
try {
    $drivers = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | ForEach-Object {
        @{
            name    = $_.Name
            display = $_.DisplayName
            state   = $_.State
            start   = $_.StartMode
            path    = $_.PathName
            desc    = $_.Description
        }
    })
} catch { Add-Note 'drivers' $_.Exception.Message }

Write-JsonFile $OutPath @{ services = $services; drivers = $drivers; notes = @($script:Notes) }
