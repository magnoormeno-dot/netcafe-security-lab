#requires -Version 5.1
<#
.SYNOPSIS
  [Run inside each Windows guest/server] Configure a static IP on the isolated subnet, deliberately omitting gateway/DNS.
.DESCRIPTION
  The isolated network has no DHCP, no gateway, no DNS (by design). Not setting a default gateway is itself an isolation safeguard.
  Ubuntu (Wazuh) is configured with netplan; see the header comments in scripts\wazuh\install-wazuh-manager.sh.
.PARAMETER IPAddress
  This host's address within 10.10.10.0/24, for example 10.10.10.31
.EXAMPLE
  .\Set-StaticIP.ps1 -IPAddress 10.10.10.31
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$IPAddress,
    [int]$Prefix = 24,
    [string]$InterfaceAlias,   # On multi-NIC hosts, explicitly specify the isolated NIC to avoid picking the wrong one or missing a second NIC that is still reaching outside
    [string]$DnsServer         # Domain mode: domain member/DC DNS should point to the DC (e.g. 10.10.10.20); empty = no DNS (isolation default)
)
$ErrorActionPreference = 'Stop'

# Select the target NIC: an explicit specification takes priority; otherwise require exactly one Up physical NIC.
# On ambiguity, throw (rather than blindly picking with -First 1) -- otherwise you might configure the isolated NIC
# but miss another NIC still reaching outside, leaving a default gateway and external access on that NIC while
# Set-StaticIP reports "no gateway", which actually masks the leak.
if ($InterfaceAlias) {
    $nic = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop
} else {
    $candidates = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
    if ($candidates.Count -eq 0) { throw 'No physical NIC in Up status was found.' }
    if ($candidates.Count -gt 1) {
        throw "Detected $($candidates.Count) Up NICs: $($candidates.Name -join ', '). Please remove the extra NICs first (Remove-VMNetworkAdapter), or use -InterfaceAlias to specify the isolated NIC."
    }
    $nic = $candidates[0]
}
Write-Host "Target NIC: $($nic.Name) ($($nic.InterfaceDescription))"

# Clear out any old IP/gateway/DNS to ensure a clean state
Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceIndex $nic.ifIndex -ErrorAction SilentlyContinue |
    Where-Object DestinationPrefix -eq '0.0.0.0/0' |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

# Configure the static IP -- note: [do NOT set -DefaultGateway], this is part of the isolation
New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $IPAddress -PrefixLength $Prefix | Out-Null

# DNS: not set by default (the isolated network has no DNS; for host-name resolution between VMs, edit the hosts file instead).
# In domain mode, pass -DnsServer <DC IP> to point this host at the internal AD DNS (that DNS has no forwarders/root hints, so it stays air-gapped).
if ($DnsServer) {
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $DnsServer
} else {
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ResetServerAddresses
}

# IPv6 hardening: disable router discovery / stateless autoconfiguration to avoid accidentally obtaining an IPv6 default route
# (isolation should not rely solely on "there just happens to be no IPv6 router").
Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv6 -RouterDiscovery Disabled -ErrorAction SilentlyContinue
Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv6 -ManagedAddressConfiguration Disabled -OtherStatefulConfiguration Disabled -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

# Turn "no default gateway" from a verbal claim into a system-level test: if any interface still has a default route (IPv4/IPv6),
# it most likely means a second NIC has not been switched/removed -- throw outright to force the operator to investigate first.
$stale = Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue
if ($stale) {
    throw "This host still has a default gateway (possibly a second NIC not switched/removed): $(($stale | ForEach-Object { '{0} via {1}' -f $_.DestinationPrefix, $_.NextHop }) -join '; '). Please investigate before retrying."
}

$dnsMsg = if ($DnsServer) { "DNS=$DnsServer" } else { "no DNS" }
Write-Host "[ OK ] Set $IPAddress/$Prefix, no default gateway, $dnsMsg, IPv6 autoconfiguration disabled." -ForegroundColor Green
Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 | Format-Table IPAddress, PrefixLength

Write-Host "It is recommended to run Test-GuestIsolation.ps1 next to verify this host truly cannot reach the network." -ForegroundColor Gray
