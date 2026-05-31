#requires -Version 5.1
<#
.SYNOPSIS
  [Run inside the Windows guest/server] Guest-side isolation verification.
  Proves: can ping VMs on the same subnet, but [absolutely] cannot reach the internet or touch the host's real LAN.
.DESCRIPTION
  Expected results:
    - Other VMs on the same isolated network -> reachable (PASS)
    - Public IP (1.1.1.1/8.8.8.8)            -> unreachable (PASS = egress blocked)
    - Public domain DNS resolution           -> fails  (PASS)
    - Common home/enterprise subnet gateways -> unreachable (PASS)
    - Default gateway                        -> absent (PASS)
  Any check that "should have failed but succeeded" indicates a broken isolation boundary; take the environment offline and investigate immediately.
.PARAMETER PeerIP
  IP of another VM on the same isolated network, used for the positive connectivity test. Default 10.10.10.10 (Wazuh).
.PARAMETER PublicProbeV4
  Public IPv4 probe targets: deliberately fixed public IPs, used to prove [egress is blocked] (reachable means the isolation is broken). Default 1.1.1.1 / 8.8.8.8.
.PARAMETER PublicProbeV6
  Public IPv6 probe target, same purpose. Default Cloudflare 2606:4700:4700::1111.
#>
[CmdletBinding()]
param(
    [string]$PeerIP = '10.10.10.10',
    [string[]]$PublicProbeV4 = @('1.1.1.1', '8.8.8.8'),
    [string]$PublicProbeV6 = '2606:4700:4700::1111'
)

$pass = 0; $fail = 0
function Check {
    param([string]$Desc,[scriptblock]$Test,[bool]$Expect)
    $got = [bool](& $Test)
    if ($got -eq $Expect) { Write-Host "[PASS] $Desc" -ForegroundColor Green; $script:pass++ }
    else { Write-Host "[FAIL] $Desc  (expected=$Expect actual=$got)" -ForegroundColor Red; $script:fail++ }
}

Write-Host "`n=== Guest isolation verification (this host: $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -like '10.10.10.*'}).IPAddress)) ===`n" -ForegroundColor Cyan

# 1) Positive (informational): peer reachability -- failure only WARNs, not counted toward the isolation-breach verdict.
#    The peer may be powered off / have no IP / drop ICMP (Linux firewalls often drop ping), so fall back to a TCP probe when ICMP fails.
#    This is the only "positive connectivity" evidence in the whole script; misjudging it as FAIL would make people think isolation is broken, so it is decoupled from $fail.
$peerOk = [bool](Test-Connection -ComputerName $PeerIP -Count 2 -Quiet)
if (-not $peerOk) {
    foreach ($p in 1514,1515,22,443) {
        if ((Test-NetConnection -ComputerName $PeerIP -Port $p -WarningAction SilentlyContinue).TcpTestSucceeded) { $peerOk = $true; break }
    }
}
if ($peerOk) { Write-Host "[PASS] Peer on the isolated network ($PeerIP) reachable -- VM-to-VM connectivity confirmed" -ForegroundColor Green; $pass++ }
else { Write-Host "[WARN] Peer ($PeerIP) unreachable -- may be powered off / have no IP / drop ICMP; VM<->VM connectivity unconfirmed, unrelated to whether isolation is broken" -ForegroundColor Yellow }

# 2) Reverse: public IPs must be unreachable (targets are deliberately fixed public IPs, see -PublicProbeV4)
foreach ($ip in $PublicProbeV4) {
    Check "Public IP $ip unreachable (no internet egress)" { Test-Connection -ComputerName $ip -Count 2 -Quiet } $false
}

# 3) Resolution against a public DNS resolver (UDP/53) must fail -- a genuine egress probe, not the tautology of "no DNS configured".
#    First clear the local cache and skip HOSTS, then force the query to 1.1.1.1; otherwise a cache/HOSTS hit would let "resolved"
#    fake a success without sending a packet, falsely reporting an already-isolated machine as broken. The isolated network has no route to 1.1.1.1, so it should time out and fail.
Check "Resolution against public DNS resolver (1.1.1.1) fails (UDP/53 egress blocked)" {
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    try { Resolve-DnsName 'www.microsoft.com' -Server '1.1.1.1' -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Out-Null; $true }
    catch { $false }
} $false

# 4) Common real-LAN gateways unreachable (confirm the host's real LAN cannot be touched)
foreach ($gw in '192.168.1.1','192.168.0.1','192.168.31.1','10.0.0.1') {
    Check "Real LAN gateway $gw unreachable" { Test-Connection -ComputerName $gw -Count 1 -Quiet } $false
}

# 5) This host should have no default gateway (no IPv4 0.0.0.0/0 or IPv6 ::/0 route)
Check "No default gateway on this host (no 0.0.0.0/0 or ::/0 route)" {
    [bool](Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue) -or
    [bool](Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue)
} $false

# 5b) IPv6 must also have no egress: testing only IPv4 throughout would let an IPv6 path be misjudged as isolated (false PASS).
Check "Public IPv6 $PublicProbeV6 unreachable" { Test-Connection -ComputerName $PublicProbeV6 -Count 2 -Quiet } $false
Check "No global/ULA IPv6 address (only fe80:: link-local is acceptable)" {
    [bool](Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike 'fe80:*' })
} $false

# 6) Outbound TCP 443 to the internet should fail
Check "TCP 443 -> internet fails" {
    (Test-NetConnection -ComputerName $PublicProbeV4[0] -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded
} $false

Write-Host "`n=== Result: PASS=$pass  FAIL=$fail ===" -ForegroundColor Cyan
if ($fail -eq 0) {
    Write-Host "Isolation is in effect: this host can reach VMs on the same subnet, but cannot reach the internet or touch the real LAN. Compliant." -ForegroundColor Green
} else {
    Write-Host "Isolation breach detected! Stop all research activity immediately and check the NIC/switch configuration." -ForegroundColor Red
}
exit $fail
