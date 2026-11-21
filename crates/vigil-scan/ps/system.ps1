# System security state: Defender, antivirus, firewall, users, shared folders,
# WMI subscriptions, startup shortcuts and packaged apps (read-only).
param(
    [Parameter(Mandatory = $true)][string]$OutPath,
    [string]$LnkListPath = ''
)
. "$PSScriptRoot\_common.ps1"

$r = @{}
$r.is_admin = Test-IsAdmin

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $r.os = @{
        caption   = $os.Caption
        version   = $os.Version
        build     = $os.BuildNumber
        arch      = $os.OSArchitecture
        installed = (ConvertTo-Iso $os.InstallDate)
        last_boot = (ConvertTo-Iso $os.LastBootUpTime)
    }
} catch { Add-Note 'system' $_.Exception.Message }

try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $r.computer = @{ manufacturer = $cs.Manufacturer; model = $cs.Model; domain_joined = [bool]$cs.PartOfDomain }
} catch { Add-Note 'system' $_.Exception.Message }

# --- Microsoft Defender ---
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $r.defender = @{
        service_enabled     = [bool]$mp.AMServiceEnabled
        antivirus           = [bool]$mp.AntivirusEnabled
        antispyware         = [bool]$mp.AntispywareEnabled
        realtime            = [bool]$mp.RealTimeProtectionEnabled
        behavior            = [bool]$mp.BehaviorMonitorEnabled
        ioav                = [bool]$mp.IoavProtectionEnabled
        tamper              = [bool]$mp.IsTamperProtected
        mode                = [string]$mp.AMRunningMode
        sig_updated         = (ConvertTo-Iso $mp.AntivirusSignatureLastUpdated)
        sig_age_days        = [long]$mp.AntivirusSignatureAge
        quick_scan          = (ConvertTo-Iso $mp.QuickScanEndTime)
        quick_scan_age_days = [long]$mp.QuickScanAge
        full_scan           = (ConvertTo-Iso $mp.FullScanEndTime)
        full_scan_age_days  = [long]$mp.FullScanAge
    }
} catch { Add-Note 'defender' ("status not available: " + $_.Exception.Message) }

try {
    $pref = Get-MpPreference -ErrorAction Stop
    $r.defender_pref = @{
        exclusion_path          = @($pref.ExclusionPath | Where-Object { $_ })
        exclusion_process       = @($pref.ExclusionProcess | Where-Object { $_ })
        exclusion_extension     = @($pref.ExclusionExtension | Where-Object { $_ })
        disable_realtime        = [bool]$pref.DisableRealtimeMonitoring
        disable_behavior        = [bool]$pref.DisableBehaviorMonitoring
        disable_ioav            = [bool]$pref.DisableIOAVProtection
        disable_script_scanning = [bool]$pref.DisableScriptScanning
        pua_protection          = [int]$pref.PUAProtection
    }
} catch { Add-Note 'defender' ("preferences not available: " + $_.Exception.Message) }

try {
    $threatInfo = @{}
    foreach ($t in @(Get-MpThreat -ErrorAction Stop)) {
        $threatInfo[[string]$t.ThreatID] = @{
            name = $t.ThreatName; severity = [int]$t.SeverityID
            active = [bool]$t.IsActive; executed = [bool]$t.DidThreatExecute
        }
    }
    $r.defender_detections = @(Get-MpThreatDetection -ErrorAction Stop |
        Sort-Object InitialDetectionTime -Descending | Select-Object -First 60 | ForEach-Object {
            $info = $threatInfo[[string]$_.ThreatID]
            $d = @{
                threat_id      = [string]$_.ThreatID
                time           = (ConvertTo-Iso $_.InitialDetectionTime)
                resources      = @($_.Resources | Where-Object { $_ })
                process        = $_.ProcessName
                action_success = [bool]$_.ActionSuccess
            }
            if ($info) {
                $d.name = $info.name; $d.severity = $info.severity
                $d.active = $info.active; $d.executed = $info.executed
            }
            $d
        })
} catch { Add-Note 'defender' ("threat history not available: " + $_.Exception.Message) }

# --- Other antivirus products registered in Security Center ---
try {
    $r.av_products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
        ForEach-Object { @{ name = $_.displayName; state = [long]$_.productState; exe = $_.pathToSignedProductExe } })
} catch { Add-Note 'antivirus' $_.Exception.Message }

# --- Firewall ---
try {
    $r.firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
        @{ name = $_.Name; enabled = ([string]$_.Enabled -eq 'True') }
    })
} catch { Add-Note 'firewall' $_.Exception.Message }

# --- Local users and administrators ---
try {
    $r.users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
        @{
            name              = $_.Name
            enabled           = [bool]$_.Enabled
            last_logon        = (ConvertTo-Iso $_.LastLogon)
            password_set      = (ConvertTo-Iso $_.PasswordLastSet)
            password_required = [bool]$_.PasswordRequired
            desc              = $_.Description
            sid               = [string]$_.SID
            source            = [string]$_.PrincipalSource
        }
    })
} catch { Add-Note 'users' $_.Exception.Message }

try {
    # S-1-5-32-544 = Administrators group (its name changes with the Windows display language).
    $r.admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
        @{ name = $_.Name; class = $_.ObjectClass; source = [string]$_.PrincipalSource; sid = [string]$_.SID }
    })
} catch { Add-Note 'users' ("Administrators group members: " + $_.Exception.Message) }

try {
    # S-1-5-32-555 = Remote Desktop Users.
    $r.rdp_users = @(Get-LocalGroupMember -SID 'S-1-5-32-555' -ErrorAction Stop | ForEach-Object {
        @{ name = $_.Name; class = $_.ObjectClass; sid = [string]$_.SID }
    })
} catch { Add-Note 'users' ("Remote Desktop Users group members: " + $_.Exception.Message) }

# --- Shared folders ---
try {
    $r.shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special } | ForEach-Object {
        @{ name = $_.Name; path = $_.Path; desc = $_.Description }
    })
} catch { Add-Note 'shares' $_.Exception.Message }

# --- Persistence through WMI subscriptions ---
try {
    $filters = @(Get-CimInstance -Namespace 'root/subscription' -ClassName __EventFilter -ErrorAction Stop | ForEach-Object {
        @{ name = $_.Name; query = $_.Query; ns = $_.EventNamespace }
    })
    $consumers = @(Get-CimInstance -Namespace 'root/subscription' -ClassName __EventConsumer -ErrorAction Stop | ForEach-Object {
        @{
            name        = $_.Name
            class       = $_.CimClass.CimClassName
            command     = $_.CommandLineTemplate
            exe         = $_.ExecutablePath
            script      = (Limit-Text ([string]$_.ScriptText) 3000)
            script_file = $_.ScriptFileName
            engine      = $_.ScriptingEngine
        }
    })
    $bindings = @(Get-CimInstance -Namespace 'root/subscription' -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object {
        @{ filter = [string]$_.Filter; consumer = [string]$_.Consumer }
    })
    $r.wmi = @{ filters = $filters; consumers = $consumers; bindings = $bindings }
} catch { Add-Note 'wmi' ("WMI subscriptions not accessible: " + $_.Exception.Message) }

# --- Most recent Windows update installed ---
try {
    $hf = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } |
        Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($hf) { $r.last_hotfix = @{ id = $hf.HotFixID; date = (ConvertTo-Iso $hf.InstalledOn) } }
} catch { Add-Note 'updates' $_.Exception.Message }

# --- Targets of the shortcuts in the Startup folders ---
$shortcuts = New-Object System.Collections.ArrayList
if ($LnkListPath -and (Test-Path -LiteralPath $LnkListPath)) {
    try {
        $shell = New-Object -ComObject WScript.Shell
        foreach ($p in [System.IO.File]::ReadAllLines($LnkListPath, [System.Text.Encoding]::UTF8)) {
            if ([string]::IsNullOrWhiteSpace($p)) { continue }
            try {
                # CreateShortcut on an existing .lnk only loads it; Save() is never called.
                $s = $shell.CreateShortcut($p)
                [void]$shortcuts.Add(@{ lnk = $p; target = $s.TargetPath; args = $s.Arguments; cwd = $s.WorkingDirectory })
            } catch {
                [void]$shortcuts.Add(@{ lnk = $p; error = $_.Exception.Message })
            }
        }
    } catch { Add-Note 'startup' $_.Exception.Message }
}
$r.shortcuts = @($shortcuts)

# --- Packaged apps not published by Microsoft ---
try {
    $r.appx = @(Get-AppxPackage -ErrorAction Stop | Where-Object {
            -not $_.IsFramework -and ([string]$_.SignatureKind -ne 'System') -and
            ($_.Publisher -notmatch 'O=Microsoft Corporation')
        } | ForEach-Object {
            @{
                name      = $_.Name
                publisher = $_.Publisher
                version   = [string]$_.Version
                kind      = [string]$_.SignatureKind
                location  = $_.InstallLocation
                dev_mode  = [bool]$_.IsDevelopmentMode
            }
        })
} catch { Add-Note 'appx' $_.Exception.Message }

$r.notes = @($script:Notes)
Write-JsonFile $OutPath $r
