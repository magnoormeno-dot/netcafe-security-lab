#requires -Version 5.1
<#
.SYNOPSIS
  Host-side isolation verification. Confirms the isolation switch is configured correctly and the host cannot reach the isolated network segment.
.DESCRIPTION
  This provides the host-side evidence for "is the isolation actually in effect". Verification inside the guest (failed pings to the internet, etc.)
  is handled by guest\Test-GuestIsolation.ps1 -- both sides must pass to be considered compliant.
.NOTES
  Read-only; makes no changes. Recommended to run after every structural change.
#>
[CmdletBinding()]
param()
. "$PSScriptRoot\lib\Common.ps1"
$cfg  = Get-LabConfig
$name = $cfg.Network.SwitchName
$fail = 0

Write-Step "Host-side isolation verification: $name"

# 1) Switch exists and is Private
$sw = Get-VMSwitch -Name $name -ErrorAction SilentlyContinue
if (-not $sw) { Write-Fail "Switch '$name' does not exist."; return }
if ($sw.SwitchType -eq 'Private') { Write-Ok "Switch type = Private (VM-only, no host access, no internet access)" }
else { Write-Fail "Switch type = $($sw.SwitchType), should be Private!"; $fail++ }

# 2) Switch is not bound to any physical NIC (no external uplink)
if ([string]::IsNullOrEmpty($sw.NetAdapterInterfaceDescription)) {
    Write-Ok "Switch is not bound to a physical NIC (no external uplink -> cannot reach the internet)"
} else {
    Write-Fail "Switch is bound to a physical NIC: $($sw.NetAdapterInterfaceDescription) -- an internet path exists!"; $fail++
}

# 3) The host has no vEthernet adapter corresponding to this switch
$hostNic = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like "*$name*" -or $_.Name -like "*$name*" }
if ($hostNic) { Write-Fail "Host has an associated virtual NIC '$($hostNic.Name)' -- the host may be able to reach the isolated network!"; $fail++ }
else { Write-Ok "Host has no vEthernet adapter for this switch (the host cannot ping VMs on the isolated network)" }

# 4) The host cannot reach the isolated segment at layer 3 either: use Find-NetRoute for a real longest-prefix match test,
#    which can catch summary/covering routes (such as 10.0.0.0/8, 10.10.0.0/16, /32), covering the blind spots of exact string matching.
$probeIp = ($cfg.VMs | Where-Object { $_.IP } | Select-Object -First 1 -ExpandProperty IP)
if (-not $probeIp) { $probeIp = '10.10.10.10' }
$nr = Find-NetRoute -RemoteIPAddress $probeIp -ErrorAction SilentlyContinue
# Find-NetRoute returns both the route object and the source NetIPAddress object; the latter has no DestinationPrefix.
# We must first require DestinationPrefix to be non-empty (otherwise that object always passes the filter -> a permanent false FAIL),
# then exclude every form of the default route (including /1 split default routes) and loopback.
$reach = $nr | Where-Object {
    $_.DestinationPrefix -and
    ($_.DestinationPrefix -notin @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1','::/0','::/1','8000::/1')) -and
    ($_.DestinationPrefix -notlike '127.*') -and
    ($_.DestinationPrefix -ne '::1/128')
}
if ($reach) { Write-Fail "Host has a specific route toward $probeIp ($(($reach.DestinationPrefix) -join ', ')) -- the isolated network may be reachable at layer 3!"; $fail++ }
else { Write-Ok "Host has no specific route toward the isolated segment (cannot reach $probeIp at layer 3)" }

# 5) Every CSL VM's NIC is connected to the isolation switch (none "leaked" onto another network)
Write-Step "VM NIC connection check"
foreach ($vm in $cfg.VMs) {
    $g = Get-VM -Name $vm.Name -ErrorAction SilentlyContinue
    if (-not $g) { Write-Warn2 "$($vm.Name): not yet created, skipping"; continue }
    $adapters = Get-VMNetworkAdapter -VMName $vm.Name
    foreach ($a in $adapters) {
        if ($a.SwitchName -eq $name) { Write-Ok "$($vm.Name): NIC is connected to '$name' [OK]" }
        elseif ([string]::IsNullOrEmpty($a.SwitchName)) { Write-Warn2 "$($vm.Name): has a disconnected NIC (acceptable)" }
        else { Write-Fail "$($vm.Name): NIC is connected to '$($a.SwitchName)' instead of the isolation switch!"; $fail++ }
    }
}

Write-Step "Conclusion"
if ($fail -eq 0) {
    Write-Ok "All host-side checks passed -- the isolation prerequisites hold."
    Write-Host "Please also run guest\Test-GuestIsolation.ps1 inside any Windows guest to complete the guest-side verification." -ForegroundColor Gray
} else {
    Write-Fail "Found $fail issue(s). DO NOT perform any research activity in this environment until they are fixed."
}
exit $fail
