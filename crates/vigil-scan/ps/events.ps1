# Scan of the Windows event logs (read-only).
# Looks for traces of persistence, antivirus detections, suspicious PowerShell,
# remote access and account changes over the last $Days days.
param(
    [Parameter(Mandatory = $true)][string]$OutPath,
    [int]$Days = 30,
    [string]$SelfDir = ''
)
. "$PSScriptRoot\_common.ps1"

$since = (Get-Date).AddDays(-$Days)
$r = @{ days = $Days }

function Get-EventList {
    param([hashtable]$Filter, [int]$Max = 500)
    try {
        return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        Add-Note 'events' ("{0}: {1}" -f $Filter.LogName, $_.Exception.Message)
        return @()
    }
}

function Get-EventFields {
    # Named fields of the event (independent of the Windows display language).
    param($Record)
    $h = @{}
    try {
        $x = [xml]$Record.ToXml()
        $i = 0
        if ($x.Event.EventData) {
            foreach ($d in $x.Event.EventData.ChildNodes) {
                if ($d.NodeType -ne 'Element') { continue }
                $name = $d.GetAttribute('Name')
                if (-not $name) { $name = "_$i" }
                $h[$name] = [string]$d.InnerText
                $i++
            }
        }
        if ($x.Event.UserData) {
            foreach ($child in $x.Event.UserData.ChildNodes) {
                foreach ($n in $child.ChildNodes) {
                    if ($n.NodeType -eq 'Element') { $h[[string]$n.LocalName] = [string]$n.InnerText }
                }
            }
        }
    } catch { }
    return $h
}

# --- System: installed services (7045) and cleared logs (104) ---
$r.service_installs = @(Get-EventList -Filter @{ LogName = 'System'; Id = 7045; StartTime = $since } -Max 300 | ForEach-Object {
    $f = Get-EventFields $_
    @{
        time    = (ConvertTo-Iso $_.TimeCreated)
        service = $f['ServiceName']
        image   = (Limit-Text $f['ImagePath'] 3000)
        type    = $f['ServiceType']
        start   = $f['StartType']
        account = $f['AccountName']
    }
})

$r.log_cleared = @(Get-EventList -Filter @{ LogName = 'System'; Id = 104; StartTime = $since } -Max 50 | ForEach-Object {
    $f = Get-EventFields $_
    @{ time = (ConvertTo-Iso $_.TimeCreated); log = $f['Channel']; source = 'System' }
})

# --- Windows Firewall: rules added (2004, 2097) or deleted (2006, 2052), profile settings (2003) ---
$fwLog = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
$r.firewall_changes = @(Get-EventList -Filter @{ LogName = $fwLog; Id = 2004, 2097, 2006, 2052, 2003; StartTime = $since } -Max 300 | ForEach-Object {
    $f = Get-EventFields $_
    @{
        time             = (ConvertTo-Iso $_.TimeCreated)
        id               = [int]$_.Id
        rule             = (Limit-Text $f['RuleName'] 300)
        program          = (Limit-Text $f['ApplicationPath'] 1000)
        service          = $f['ServiceName']
        direction        = $f['Direction']
        action           = $f['Action']
        local_ports      = (Limit-Text $f['LocalPorts'] 200)
        remote_addresses = (Limit-Text $f['RemoteAddresses'] 300)
        setting          = $f['SettingType']
        value            = (Limit-Text $f['SettingValueString'] 200)
        by_app           = (Limit-Text $f['ModifyingApplication'] 1000)
    }
})

# --- Microsoft Defender ---
$defLog = 'Microsoft-Windows-Windows Defender/Operational'
$r.defender_detections = @(Get-EventList -Filter @{ LogName = $defLog; Id = 1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119; StartTime = $since } -Max 200 | ForEach-Object {
    $f = Get-EventFields $_
    @{
        time     = (ConvertTo-Iso $_.TimeCreated)
        id       = [int]$_.Id
        threat   = $f['Threat Name']
        severity = $f['Severity Name']
        category = $f['Category Name']
        path     = (Limit-Text $f['Path'] 1500)
        process  = $f['Process Name']
        action   = $f['Action Name']
    }
})

$r.defender_disabled = @(Get-EventList -Filter @{ LogName = $defLog; Id = 5001, 5010, 5012; StartTime = $since } -Max 100 | ForEach-Object {
    @{ time = (ConvertTo-Iso $_.TimeCreated); id = [int]$_.Id }
})

$configPattern = 'Exclusions\\|DisableRealtimeMonitoring|DisableAntiSpyware|DisableAntiVirus|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning|TamperProtection'
$r.defender_config = @(Get-EventList -Filter @{ LogName = $defLog; Id = 5007; StartTime = $since } -Max 2000 | ForEach-Object {
    $f = Get-EventFields $_
    $old = [string]$f['Old Value']
    $new = [string]$f['New Value']
    if (($old -match $configPattern) -or ($new -match $configPattern)) {
        @{ time = (ConvertTo-Iso $_.TimeCreated); old = (Limit-Text $old 600); new = (Limit-Text $new 600) }
    }
})

# --- Classic PowerShell: event 400 records the command line (HostApplication) ---
$cmds = @{}
foreach ($e in @(Get-EventList -Filter @{ LogName = 'Windows PowerShell'; Id = 400; StartTime = $since } -Max 5000)) {
    $text = ''
    try { $text = [string]$e.Properties[2].Value } catch { }
    $m = [regex]::Match($text, '(?s)HostApplication=(.*?)\r?\n\s*EngineVersion=')
    if (-not $m.Success) { continue }
    $cmd = $m.Groups[1].Value.Trim()
    if (-not $cmd) { continue }
    if ($SelfDir -and ($cmd.IndexOf($SelfDir, [StringComparison]::OrdinalIgnoreCase) -ge 0)) { continue }
    $cmd = Limit-Text $cmd 8000
    if ($cmds.ContainsKey($cmd)) {
        $cmds[$cmd]['n'] = $cmds[$cmd]['n'] + 1
    } else {
        # Events arrive newest first: the first one seen is the most recent use.
        $cmds[$cmd] = @{ cmd = $cmd; n = 1; last = (ConvertTo-Iso $e.TimeCreated) }
    }
}
$r.ps_commands = @($cmds.Values | Sort-Object { $_['last'] } -Descending | Select-Object -First 800)

# --- PowerShell: script blocks the engine itself flagged as suspicious (4104, Warning level) ---
$seen = @{}
$r.ps_scriptblocks = @(Get-EventList -Filter @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; Level = 3; StartTime = $since } -Max 600 | ForEach-Object {
    $f = Get-EventFields $_
    if ($f['MessageNumber'] -ne '1') { return }
    $path = [string]$f['Path']
    if ($SelfDir -and $path -and $path.StartsWith($SelfDir, [StringComparison]::OrdinalIgnoreCase)) { return }
    $text = [string]$f['ScriptBlockText']
    $key = $path + '|' + (Limit-Text $text 200)
    if ($seen.ContainsKey($key)) { return }
    $seen[$key] = 1
    @{ time = (ConvertTo-Iso $_.TimeCreated); path = $path; text = (Limit-Text $text 4000) }
})

# --- Incoming Remote Desktop sessions ---
$rdp = @{}
foreach ($e in @(Get-EventList -Filter @{ LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id = 21, 25; StartTime = $since } -Max 2000)) {
    $f = Get-EventFields $e
    $addr = [string]$f['Address']
    if (-not $addr -or $addr -eq 'LOCAL') { continue }
    $k = "{0}|{1}" -f $f['User'], $addr
    if ($rdp.ContainsKey($k)) {
        $rdp[$k]['n'] = $rdp[$k]['n'] + 1
        $rdp[$k]['first'] = (ConvertTo-Iso $e.TimeCreated)
    } else {
        $t = ConvertTo-Iso $e.TimeCreated
        $rdp[$k] = @{ user = $f['User']; address = $addr; n = 1; first = $t; last = $t }
    }
}
$r.rdp_sessions = @($rdp.Values)

# --- Permanent WMI consumers registered (5861) ---
$r.wmi_consumers = @(Get-EventList -Filter @{ LogName = 'Microsoft-Windows-WMI-Activity/Operational'; Id = 5861; StartTime = $since } -Max 50 | ForEach-Object {
    $f = Get-EventFields $_
    @{
        time     = (ConvertTo-Iso $_.TimeCreated)
        ns       = $f['Namespace']
        filter   = (Limit-Text $f['ESS'] 500)
        consumer = (Limit-Text $f['CONSUMER'] 500)
        cause    = (Limit-Text $f['PossibleCause'] 2500)
    }
})

# --- Scheduled tasks registered or deleted (only when that log is enabled) ---
$r.task_changes = @(Get-EventList -Filter @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 106, 141; StartTime = $since } -Max 400 | ForEach-Object {
    $f = Get-EventFields $_
    $name = [string]$f['TaskName']
    if ($name -like '\Microsoft\*') { return }
    @{ time = (ConvertTo-Iso $_.TimeCreated); id = [int]$_.Id; task = $name }
})

# --- Security log: requires administrator ---
$r.security_log = $false
if (Test-IsAdmin) {
    $r.security_log = $true

    foreach ($e in @(Get-EventList -Filter @{ LogName = 'Security'; Id = 1102; StartTime = $since } -Max 50)) {
        $r.log_cleared += @{ time = (ConvertTo-Iso $e.TimeCreated); log = 'Security'; source = 'Security' }
    }

    # Failed logons, grouped by source address and logon type.
    $fail = @{}
    foreach ($e in @(Get-EventList -Filter @{ LogName = 'Security'; Id = 4625; StartTime = $since } -Max 5000)) {
        $f = Get-EventFields $e
        $k = "{0}|{1}" -f $f['IpAddress'], $f['LogonType']
        $t = ConvertTo-Iso $e.TimeCreated
        if (-not $fail.ContainsKey($k)) {
            $fail[$k] = @{ ip = $f['IpAddress']; logon_type = $f['LogonType']; n = 0; users = @{}; first = $t; last = $t }
        }
        $fail[$k]['n'] = $fail[$k]['n'] + 1
        $fail[$k]['first'] = $t
        if ($fail[$k]['users'].Count -lt 8) { $fail[$k]['users'][[string]$f['TargetUserName']] = 1 }
    }
    $r.failed_logons = @($fail.Values | ForEach-Object {
        @{ ip = $_['ip']; logon_type = $_['logon_type']; n = $_['n']; users = @($_['users'].Keys); first = $_['first']; last = $_['last'] }
    })

    # Successful network (3) or Remote Desktop (10) logons from another address.
    $ok = @{}
    try {
        $ms = [long]$Days * 86400000
        $xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]] and EventData[Data[@Name='LogonType']='10' or Data[@Name='LogonType']='3']]"
        foreach ($e in @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 4000 -ErrorAction Stop)) {
            $f = Get-EventFields $e
            $ip = [string]$f['IpAddress']
            if (-not $ip -or $ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') { continue }
            $k = "{0}|{1}|{2}" -f $ip, $f['LogonType'], $f['TargetUserName']
            $t = ConvertTo-Iso $e.TimeCreated
            if (-not $ok.ContainsKey($k)) {
                $ok[$k] = @{ ip = $ip; logon_type = $f['LogonType']; user = $f['TargetUserName']; n = 0; first = $t; last = $t }
            }
            $ok[$k]['n'] = $ok[$k]['n'] + 1
            $ok[$k]['first'] = $t
        }
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            Add-Note 'events' ("Security 4624: " + $_.Exception.Message)
        }
    }
    $r.remote_logons = @($ok.Values)

    $r.accounts_created = @(Get-EventList -Filter @{ LogName = 'Security'; Id = 4720; StartTime = $since } -Max 50 | ForEach-Object {
        $f = Get-EventFields $_
        @{ time = (ConvertTo-Iso $_.TimeCreated); user = $f['TargetUserName']; by = $f['SubjectUserName'] }
    })

    $r.admin_added = @(Get-EventList -Filter @{ LogName = 'Security'; Id = 4732; StartTime = $since } -Max 200 | ForEach-Object {
        $f = Get-EventFields $_
        if ($f['TargetSid'] -ne 'S-1-5-32-544') { return }
        @{ time = (ConvertTo-Iso $_.TimeCreated); member_sid = $f['MemberSid']; by = $f['SubjectUserName'] }
    })

    $r.tasks_created = @(Get-EventList -Filter @{ LogName = 'Security'; Id = 4698; StartTime = $since } -Max 200 | ForEach-Object {
        $f = Get-EventFields $_
        @{ time = (ConvertTo-Iso $_.TimeCreated); task = $f['TaskName']; by = $f['SubjectUserName']; content = (Limit-Text $f['TaskContent'] 2500) }
    })
} else {
    Add-Note 'events' 'Security log: requires running as administrator (logons, created accounts, audit log clearing).'
}

$r.notes = @($script:Notes)
Write-JsonFile $OutPath $r
