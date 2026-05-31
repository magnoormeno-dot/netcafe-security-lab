#requires -Version 5.1
<#
.SYNOPSIS
  [Run on the domain controller CSL-Server, after promotion and reboot] Lock AD DNS down to "resolve internal domain only, never recurse outward",
  to maintain a complete air gap in the domain environment (defense in depth).
.DESCRIPTION
  The domain controller's DNS ships with root hints by default, which in theory would try to recurse to the public root servers. This lab's network layer
  already has no egress (private switch + no gateway), so those queries will simply fail; but for cleanliness, and to avoid any outbound attempt, this script:
    * Removes all DNS forwarders (ensures queries are not forwarded to any upstream).
    * Clears the root hints (so DNS no longer attempts external recursion).
    * Disables recursion (optional; within the isolated network only local domain records need to be resolved).
    * Validates: resolving a public domain name should fail, and resolving a local-domain FQDN should succeed.
  Purely defensive; it does not change the isolation topology, only tightens DNS behavior.
.NOTES
  Requires administrator, and this host must already be a domain controller (the DNS role is in place). Idempotent and safe to run repeatedly.
#>
[CmdletBinding()]
param([string]$DomainName = 'cafesec.lab')
. "$PSScriptRoot\..\lib\Common.ps1"
Assert-Admin

Write-Step "Locking AD DNS into air-gap mode (no forwarders, no root hints)"

if (-not (Get-Command Get-DnsServerForwarder -ErrorAction SilentlyContinue)) {
    Write-Fail "DNS Server module not found. Confirm this host is already a domain controller with the DNS role installed."; return
}

# 1) Remove all forwarders
$fwd = (Get-DnsServerForwarder -ErrorAction SilentlyContinue).IPAddress
if ($fwd) {
    foreach ($ip in $fwd) { Remove-DnsServerForwarder -IPAddress $ip -Force -ErrorAction SilentlyContinue }
    Write-Ok "Removed DNS forwarders: $($fwd -join ', ')"
} else { Write-Ok "No DNS forwarders (as expected)." }

# 2) Clear the root hints to avoid recursing to the public root servers.
#    Note: the two parameter sets of Remove-DnsServerRootHint require either -InputObject (pipeline) or -NameServer respectively;
#    a bare call with `-Force` binds to no parameter set -> silent failure/no-op (then swallowed by SilentlyContinue).
#    You must [pipe] the Get'd objects in (the documented "delete all" idiom), and assert by re-querying, to avoid a false success report.
$hints = Get-DnsServerRootHint -ErrorAction SilentlyContinue
if ($hints) {
    try { $hints | Remove-DnsServerRootHint -Force -ErrorAction Stop }
    catch { Write-Warn2 "Failed to clear root hints (non-fatal): $($_.Exception.Message)" }
    $remaining = Get-DnsServerRootHint -ErrorAction SilentlyContinue
    if (-not $remaining) { Write-Ok "Cleared the DNS root hints." }
    else { Write-Fail "Root hints still present ($(@($remaining).Count) entries); clearing did not take effect." }
} else { Write-Ok "No root hints (already cleared)." }

# 3) Disable recursion (within the isolated network only the local domain is resolved; disabling further reduces outbound attempts)
try {
    Set-DnsServerRecursion -Enable $false -ErrorAction Stop
    Write-Ok "Disabled DNS recursion."
} catch { Write-Warn2 "Failed to disable recursion (non-fatal): $($_.Exception.Message)" }

# 4) Validate
Write-Step "Validating"
# 4a The local domain should be resolvable
try {
    Resolve-DnsName -Name $DomainName -Server 127.0.0.1 -ErrorAction Stop | Out-Null
    Write-Ok "Local domain $DomainName is resolvable (internal DNS working)."
} catch { Write-Warn2 "Local domain $DomainName failed to resolve; check the AD DNS zone." }

# 4b A public domain name should fail to resolve (air gap)
$ext = $false
try { Resolve-DnsName -Name 'www.microsoft.com' -Server 127.0.0.1 -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; $ext = $true } catch { $ext = $false }
if ($ext) { Write-Fail "A public domain name actually resolved! Check whether forwarders/root hints still remain." }
else { Write-Ok "Public domain name failed to resolve (air gap maintained)." }

Write-Step "Done. Next step: ..\guest\Configure-WEC-Collector.ps1 (configure the WEF collector)"
