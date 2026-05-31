#requires -Version 5.1
<#
.SYNOPSIS
  [Run on CSL-Server (10.10.10.20)] Promotes this host to the first domain controller (DC)
  of the new forest cafesec.lab, and installs AD-integrated DNS. Reboots automatically when done.
.DESCRIPTION
  Why a domain is needed: between workgroup (non-domain) machines, [source-initiated WEF over Kerberos cannot work].
  Once a domain is established:
    * WEF source -> collector works natively over Kerberos (HTTP/5985), with no certificates required.
    * Sysmon / audit policy / WEF subscriptions can be deployed uniformly via GPO (matching the GPO requirements in step five).

  Air-gap preservation: the DC runs AD-integrated DNS that resolves only the internal domain cafesec.lab.
  This script does [NOT] configure any DNS forwarders; after promotion and reboot, run Set-DcDnsAirgap.ps1
  to clear the root hints, ensuring DNS never attempts to recurse externally -- the network layer already has no egress, so this is defense in depth.

  Prerequisites (must be satisfied first):
    * This host already has the static IP 10.10.10.20/24 set, with no default gateway (guest\Set-StaticIP.ps1).
    * This host's [hostname] has already been changed to CSL-Server and the machine rebooted once (the computer name should be finalized before DC promotion).
    * This host's preferred DNS points to itself (the script automatically sets it to 127.0.0.1).
.PARAMETER DomainName
  FQDN of the new forest, default cafesec.lab (a purely internal domain that does not conflict with any real domain).
.PARAMETER NetbiosName
  NetBIOS domain name, default CAFESEC.
.PARAMETER SafeModePassword
  DSRM (Directory Services Restore Mode) administrator password. Required, SecureString. Please store it safely.
.EXAMPLE
  $dsrm = Read-Host -AsSecureString "Set the DSRM password"
  .\Install-DomainController.ps1 -SafeModePassword $dsrm
.NOTES
  Requires administrator. The promotion process will [reboot automatically]. After the reboot:
    1) Run Set-DcDnsAirgap.ps1 (clear root hints / confirm no forwarders).
    2) Run ..\guest\Configure-WEC-Collector.ps1 (configure the WEF collector).
    3) Run New-WefGpo.ps1 (deploy the WEF/audit-policy GPO).
  Windows Server evaluation editions can act as a DC normally.
#>
[CmdletBinding()]
param(
    [string]$DomainName  = 'cafesec.lab',
    [string]$NetbiosName = 'CAFESEC',
    [Parameter(Mandatory)][System.Security.SecureString]$SafeModePassword,
    [string]$InterfaceAlias    # Explicitly specify the isolated NIC when there are multiple NICs
)
. "$PSScriptRoot\..\lib\Common.ps1"
Assert-Admin

Write-Step "Promoting to domain controller: new forest $DomainName ($NetbiosName)"

# 0) Validate the static IP (the DC must be fixed at 10.10.10.20; all other scripts hardcode this address). Abort immediately if not met, to avoid installing with the wrong address.
$ipOk = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object IPAddress -eq '10.10.10.20'
if (-not $ipOk) { Write-Fail "Did not detect this host's IPv4 = 10.10.10.20. Please first run guest\Set-StaticIP.ps1 -IPAddress 10.10.10.20 -DnsServer 127.0.0.1 and then retry."; return }

# 1) Point the preferred DNS at itself. Multiple NICs in the Up state may mean an externally connected NIC is still attached (an air-gap hazard):
#    either use -InterfaceAlias to specify the isolated NIC, or abort -- never promote a DC under an uncertain NIC layout (it is irreversible).
if ($InterfaceAlias) {
    $nic = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop
} else {
    $cands = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
    if ($cands.Count -eq 0) { Write-Fail "No physical NIC in the Up state was found."; return }
    if ($cands.Count -gt 1) { Write-Fail "Detected $($cands.Count) NICs in the Up state: $($cands.Name -join ', '). Please remove the extra NICs first, or use -InterfaceAlias to specify the isolated NIC."; return }
    $nic = $cands[0]
}
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses '127.0.0.1'
Write-Ok "Set this host's preferred DNS to 127.0.0.1 (the DC itself)."

# 2) Install the AD DS + DNS roles
Write-Step "Installing the AD DS / DNS roles"
$feat = Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools
if (-not $feat.Success) { Write-Fail "Role installation failed; aborting."; return }
Write-Ok "The AD-Domain-Services + DNS roles have been installed."

# 3) Promote to the first domain controller of the new forest (including AD-integrated DNS). Reboots automatically when done.
Write-Step "Install-ADDSForest (will reboot automatically)"
Import-Module ADDSDeployment
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetbiosName `
    -SafeModeAdministratorPassword $SafeModePassword `
    -InstallDns:$true `
    -DatabasePath 'C:\Windows\NTDS' `
    -SysvolPath  'C:\Windows\SYSVOL' `
    -LogPath     'C:\Windows\NTDS' `
    -Force `
    -NoRebootOnCompletion:$false

# Note: After Install-ADDSForest succeeds it reboots on its own, so the message below usually will not be shown.
Write-Host "If it does not reboot automatically, reboot manually. After the reboot, run in order: Set-DcDnsAirgap.ps1 -> ..\guest\Configure-WEC-Collector.ps1 -> New-WefGpo.ps1" -ForegroundColor Gray
