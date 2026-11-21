# Hardware inventory for the Performance page: CPU, memory modules, GPUs, physical disks and
# their health counters, board, BIOS, OS, battery, page file and TRIM (read-only).
# Works without administrator rights; what Windows refuses is left empty and noted.
# PRIVACY: no serial numbers, MAC addresses, device instance IDs or user names are written.
param(
    [Parameter(Mandatory = $true)][string]$OutPath
)
. "$PSScriptRoot\_common.ps1"

function ConvertTo-IsoDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToString('yyyy-MM-dd') } catch { return $null }
}

function ConvertTo-NullableLong {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return [long]$Value } catch { return $null }
}

function Get-CleanText {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = ([string]$Value).Trim()
    if ($text) { return $text }
    return $null
}

$r = @{}
$r.is_admin = Test-IsAdmin

# --- Processor ---
try {
    $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
    $c = $cpus[0]
    $r.cpu = @{
        name           = (Get-CleanText $c.Name)
        manufacturer   = (Get-CleanText $c.Manufacturer)
        sockets        = $cpus.Count
        cores          = [int](($cpus | Measure-Object -Property NumberOfCores -Sum).Sum)
        logical        = [int](($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum)
        max_mhz        = [int]$c.MaxClockSpeed
        l2_kb          = [int]$c.L2CacheSize
        l3_kb          = [int]$c.L3CacheSize
        socket         = (Get-CleanText $c.SocketDesignation)
        virtualization = [bool]$c.VirtualizationFirmwareEnabled
    }
} catch { Add-Note 'cpu' $_.Exception.Message }

# --- Memory modules ---
$formFactors = @{ 8 = 'DIMM'; 12 = 'SODIMM'; 13 = 'SRIMM'; 0 = 'Unknown' }
$memoryTypes = @{ 20 = 'DDR'; 21 = 'DDR2'; 24 = 'DDR3'; 26 = 'DDR4'; 27 = 'LPDDR'; 28 = 'LPDDR2';
                  29 = 'LPDDR3'; 30 = 'LPDDR4'; 34 = 'DDR5'; 35 = 'LPDDR5' }
try {
    $modules = @(Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop | ForEach-Object {
        $ff = [int]$_.FormFactor
        $mt = [int]$_.SMBIOSMemoryType
        @{
            capacity         = [long]$_.Capacity
            speed            = [int]$_.Speed
            configured_speed = [int]$_.ConfiguredClockSpeed
            manufacturer     = (Get-CleanText $_.Manufacturer)
            part_number      = (Get-CleanText $_.PartNumber)
            slot             = (Get-CleanText $_.DeviceLocator)
            bank             = (Get-CleanText $_.BankLabel)
            form_factor      = $(if ($formFactors.ContainsKey($ff)) { $formFactors[$ff] } else { [string]$ff })
            type             = $(if ($memoryTypes.ContainsKey($mt)) { $memoryTypes[$mt] } else { $null })
        }
    })
    $slots = 0
    $maxBytes = 0
    foreach ($array in @(Get-CimInstance -ClassName Win32_PhysicalMemoryArray -ErrorAction SilentlyContinue)) {
        if ([int]$array.Use -ne 3) { continue }   # 3 = system memory (skip cache / flash arrays)
        $slots += [int]$array.MemoryDevices
        # Both properties are in KB; MaxCapacityEx exists because MaxCapacity overflows above 4 TB.
        $kb = [long]$array.MaxCapacityEx
        if ($kb -le 0) { $kb = [long]$array.MaxCapacity }
        $maxBytes += $kb * 1024
    }
    $r.memory = @{ modules = $modules; slots = $slots; max_capacity = $maxBytes }
} catch { Add-Note 'memory' $_.Exception.Message }

# --- Graphics adapters ---
try {
    $r.gpus = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | ForEach-Object {
        $vendor = $null
        $device = $null
        if ([string]$_.PNPDeviceID -match 'VEN_([0-9A-Fa-f]{4})') { $vendor = $Matches[1].ToUpper() }
        if ([string]$_.PNPDeviceID -match 'DEV_([0-9A-Fa-f]{4})') { $device = $Matches[1].ToUpper() }
        @{
            name           = (Get-CleanText $_.Name)
            driver_version = (Get-CleanText $_.DriverVersion)
            driver_date    = (ConvertTo-IsoDate $_.DriverDate)
            vendor_id      = $vendor
            device_id      = $device
            refresh_rate   = [int]$_.CurrentRefreshRate
            width          = [int]$_.CurrentHorizontalResolution
            height         = [int]$_.CurrentVerticalResolution
            status         = (Get-CleanText $_.Status)
        }
    })
} catch { Add-Note 'gpu' $_.Exception.Message }

# --- Physical disks, their drive letters and health counters ---
$letters = @{}
try {
    foreach ($p in @(Get-Partition -ErrorAction Stop)) {
        if (-not $p.DriveLetter -or [int][char]$p.DriveLetter -eq 0) { continue }
        $key = [string]$p.DiskNumber
        if (-not $letters.ContainsKey($key)) { $letters[$key] = New-Object System.Collections.ArrayList }
        [void]$letters[$key].Add(([string]$p.DriveLetter) + ':')
    }
} catch { Add-Note 'disks' ("partitions: " + $_.Exception.Message) }
try {
    $r.disks = @(Get-PhysicalDisk -ErrorAction Stop | Sort-Object { [int]$_.DeviceId } | ForEach-Object {
        $key = [string]$_.DeviceId
        # Assigned through a variable: $(...) would unroll a one-item list into a plain string.
        $diskLetters = @()
        if ($letters -and $letters.ContainsKey($key)) { $diskLetters = @($letters[$key]) }
        $d = @{
            number      = [int]$_.DeviceId
            name        = (Get-CleanText $_.FriendlyName)
            media       = [string]$_.MediaType
            bus         = [string]$_.BusType
            size        = [long]$_.Size
            health      = [string]$_.HealthStatus
            status      = (@($_.OperationalStatus) | ForEach-Object { [string]$_ }) -join ', '
            letters     = $diskLetters
            temperature = $null; temperature_max = $null; wear = $null; power_on_hours = $null
            read_errors = $null; write_errors = $null
        }
        try {
            # Usually needs administrator rights; without them these values stay empty.
            $rc = $_ | Get-StorageReliabilityCounter -ErrorAction Stop
            if ($rc) {
                $d.temperature = (ConvertTo-NullableLong $rc.Temperature)
                $d.temperature_max = (ConvertTo-NullableLong $rc.TemperatureMax)
                $d.wear = (ConvertTo-NullableLong $rc.Wear)
                $d.power_on_hours = (ConvertTo-NullableLong $rc.PowerOnHours)
                $d.read_errors = (ConvertTo-NullableLong $rc.ReadErrorsUncorrected)
                $d.write_errors = (ConvertTo-NullableLong $rc.WriteErrorsUncorrected)
            }
        } catch { Add-Note 'disks' ("health counters of disk " + $key + ": " + $_.Exception.Message) }
        $d
    })
} catch { Add-Note 'disks' $_.Exception.Message }

# --- Board, BIOS, computer model ---
try {
    $b = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop | Select-Object -First 1
    $r.board = @{ manufacturer = (Get-CleanText $b.Manufacturer); product = (Get-CleanText $b.Product) }
} catch { Add-Note 'board' $_.Exception.Message }
try {
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop | Select-Object -First 1
    $r.bios = @{
        manufacturer = (Get-CleanText $bios.Manufacturer)
        version      = (Get-CleanText $bios.SMBIOSBIOSVersion)
        date         = (ConvertTo-IsoDate $bios.ReleaseDate)
    }
} catch { Add-Note 'bios' $_.Exception.Message }
try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $r.computer = @{
        manufacturer      = (Get-CleanText $cs.Manufacturer)
        model             = (Get-CleanText $cs.Model)
        auto_pagefile     = [bool]$cs.AutomaticManagedPagefile
        hypervisor        = [bool]$cs.HypervisorPresent
    }
} catch { Add-Note 'computer' $_.Exception.Message }

# --- Operating system ---
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $r.os = @{
        caption   = (Get-CleanText $os.Caption)
        version   = $os.Version
        build     = $os.BuildNumber
        arch      = $os.OSArchitecture
        installed = (ConvertTo-Iso $os.InstallDate)
        last_boot = (ConvertTo-Iso $os.LastBootUpTime)
    }
} catch { Add-Note 'os' $_.Exception.Message }

# --- Battery (laptops only) ---
$r.battery = $null
try {
    $bat = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop)
    if ($bat.Count -gt 0) {
        $battery = @{
            charge = [int]$bat[0].EstimatedChargeRemaining
            status = [int]$bat[0].BatteryStatus
            designed_capacity = $null; full_capacity = $null; cycles = $null
        }
        try {
            $static = Get-CimInstance -Namespace 'root/wmi' -ClassName BatteryStaticData -ErrorAction Stop | Select-Object -First 1
            if ($static) { $battery.designed_capacity = (ConvertTo-NullableLong $static.DesignedCapacity) }
        } catch { Add-Note 'battery' ("design capacity: " + $_.Exception.Message) }
        try {
            $full = Get-CimInstance -Namespace 'root/wmi' -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1
            if ($full) { $battery.full_capacity = (ConvertTo-NullableLong $full.FullChargedCapacity) }
        } catch { Add-Note 'battery' ("full charge capacity: " + $_.Exception.Message) }
        try {
            $cycles = Get-CimInstance -Namespace 'root/wmi' -ClassName BatteryCycleCount -ErrorAction Stop | Select-Object -First 1
            if ($cycles) { $battery.cycles = (ConvertTo-NullableLong $cycles.CycleCount) }
        } catch { Add-Note 'battery' ("cycle count: " + $_.Exception.Message) }
        $r.battery = $battery
    }
} catch { Add-Note 'battery' $_.Exception.Message }

# --- Page file (sizes in MB) ---
try {
    $r.pagefiles = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop | ForEach-Object {
        @{ path = $_.Name; allocated_mb = [long]$_.AllocatedBaseSize; current_mb = [long]$_.CurrentUsage; peak_mb = [long]$_.PeakUsage }
    })
} catch { Add-Note 'pagefile' $_.Exception.Message }

# --- TRIM (0 = TRIM commands are sent to SSDs) ---
$trim = @{ ntfs = $null; refs = $null; source = $null }
try {
    $fsutil = Join-Path $env:SystemRoot 'System32\fsutil.exe'
    $text = (& $fsutil behavior query DisableDeleteNotify 2>$null) -join "`n"
    if ($LASTEXITCODE -eq 0 -and $text -match 'NTFS DisableDeleteNotify\s*=\s*(\d)') {
        $trim.ntfs = ($Matches[1] -eq '0')
        if ($text -match 'ReFS DisableDeleteNotify\s*=\s*(\d)') { $trim.refs = ($Matches[1] -eq '0') }
        $trim.source = 'fsutil'
    }
} catch { }
if ($null -eq $trim.ntfs) {
    # fsutil needs administrator rights; the same setting is readable in the registry.
    try {
        $fs = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -ErrorAction Stop
        if ($null -ne $fs.DisableDeleteNotification) { $trim.ntfs = ([int]$fs.DisableDeleteNotification -eq 0) }
        if ($null -ne $fs.RefsDisableDeleteNotification) { $trim.refs = ([int]$fs.RefsDisableDeleteNotification -eq 0) }
        $trim.source = 'registry'
    } catch { Add-Note 'trim' $_.Exception.Message }
}
$r.trim = $trim

$r.notes = @($script:Notes)
Write-JsonFile $OutPath $r
