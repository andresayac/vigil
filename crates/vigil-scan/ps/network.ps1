# Connections and ports per process, configured DNS servers and names in the DNS cache (read-only).
param([Parameter(Mandatory = $true)][string]$OutPath)
. "$PSScriptRoot\_common.ps1"

$tcp = @()
try {
    $tcp = @(Get-NetTCPConnection -ErrorAction Stop |
        Where-Object { $_.State -eq 'Listen' -or $_.State -eq 'Established' } |
        ForEach-Object {
            @{
                state = [string]$_.State
                laddr = $_.LocalAddress
                lport = [int]$_.LocalPort
                raddr = $_.RemoteAddress
                rport = [int]$_.RemotePort
                pid   = [int]$_.OwningProcess
            }
        })
} catch { Add-Note 'network' ("TCP: " + $_.Exception.Message) }

$udp = @()
try {
    $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
        @{ laddr = $_.LocalAddress; lport = [int]$_.LocalPort; pid = [int]$_.OwningProcess }
    })
} catch { Add-Note 'network' ("UDP: " + $_.Exception.Message) }

$dnsServers = @()
try {
    $dnsServers = @(Get-DnsClientServerAddress -ErrorAction Stop |
        Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 } |
        ForEach-Object {
            @{ iface = $_.InterfaceAlias; family = [string]$_.AddressFamily; servers = @($_.ServerAddresses) }
        })
} catch { Add-Note 'network' ("DNS: " + $_.Exception.Message) }

# Names only. The analysis compares them locally against known patterns;
# names that do not match are never sent anywhere.
$dnsCache = @()
try {
    $dnsCache = @(Get-DnsClientCache -ErrorAction Stop | ForEach-Object { $_.Entry } | Sort-Object -Unique)
} catch { Add-Note 'network' ("DNS cache: " + $_.Exception.Message) }

Write-JsonFile $OutPath @{
    tcp = $tcp; udp = $udp; dns_servers = $dnsServers; dns_cache = $dnsCache; notes = @($script:Notes)
}
