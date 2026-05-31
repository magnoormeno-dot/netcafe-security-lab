#requires -Version 5.1
<#
.SYNOPSIS
  [Run on each Windows client machine (CSL-Client01/02)] Joins the local machine to the cafesec.lab domain.
  First points DNS at the domain controller, then joins the domain and reboots.
.DESCRIPTION
  Domain-join prerequisite: the client's DNS must be able to resolve the domain controller (otherwise the domain cannot be located). The isolated network has no standalone DNS,
  so this script points the isolated NIC's DNS at the domain controller CSL-Server (10.10.10.20, which runs AD-integrated DNS).
  This does [not break the air gap]: that DNS has no forwarders and no root hints (see Set-DcDnsAirgap.ps1), and resolves only the internal domain;
  Test-GuestIsolation.ps1 still forces a probe to 1.1.1.1 and confirms egress is blocked.
  After joining the domain, WEF/Sysmon/audit policy can then be distributed uniformly via domain GPO (New-WefGpo.ps1).
.PARAMETER DomainName
  Target domain FQDN, defaults to cafesec.lab.
.PARAMETER DcIp
  Domain controller IP (also the DNS), defaults to 10.10.10.20.
.PARAMETER DomainCredential
  A domain account with domain-join rights (e.g. CAFESEC\Administrator). Required, PSCredential.
.PARAMETER InterfaceAlias
  Explicitly specifies the isolated NIC when multiple NICs are present.
.EXAMPLE
  $cred = Get-Credential CAFESEC\Administrator
  .\Join-LabDomain.ps1 -DomainCredential $cred
.NOTES
  Requires administrator. After a successful domain join, the machine [reboots automatically]. After the reboot, log in with a domain account.
#>
[CmdletBinding()]
param(
    [string]$DomainName = 'cafesec.lab',
    [string]$DcIp       = '10.10.10.20',
    [Parameter(Mandatory)][System.Management.Automation.PSCredential]$DomainCredential,
    [string]$InterfaceAlias
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\Common.ps1"
Assert-Admin

Write-Step "Joining domain: $DomainName (domain controller/DNS = $DcIp)"

# Select the isolated NIC (explicit takes priority; otherwise require exactly one Up NIC)
if ($InterfaceAlias) {
    $nic = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop
} else {
    $candidates = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
    if ($candidates.Count -eq 0) { throw 'No physical NIC in Up status found.' }
    if ($candidates.Count -gt 1) { throw "Detected $($candidates.Count) Up NICs: $($candidates.Name -join ', '). Use -InterfaceAlias to specify the isolated NIC." }
    $nic = $candidates[0]
}

# 1) Point DNS at the domain controller (otherwise the domain cannot be located)
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $DcIp
Write-Ok "Set DNS for $($nic.Name) to $DcIp."

# 2) Preflight: can the domain be resolved
try {
    Resolve-DnsName -Name $DomainName -Server $DcIp -ErrorAction Stop | Out-Null
    Write-Ok "Domain $DomainName can now be resolved."
} catch {
    Write-Fail "Unable to resolve domain $DomainName via $DcIp. Confirm the domain controller is ready (Install-DomainController.ps1 + Set-DcDnsAirgap.ps1) and that the network is reachable."
    return
}

# 3) Join the domain and reboot
Write-Step "Add-Computer (will reboot automatically)"
Add-Computer -DomainName $DomainName -Credential $DomainCredential -Restart -Force
