#requires -Version 5.1
<#
.SYNOPSIS
  [Run on the domain controller CSL-Server] Creates and deploys a GPO that configures
  client machines as WEF event sources: sets the SubscriptionManager (pointing to the
  collector) + enables the WinRM remote management policy, and links it to the domain.
.DESCRIPTION
  Corresponds to the "GPO configuration points" required in step five. This script uses the
  GroupPolicy module to handle the [scriptable] high-confidence parts:
    1) Registry policy: Configure target Subscription Manager
       HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
       Value "1" = Server=http://<collector FQDN>:5985/wsman/SubscriptionManager/WEC,Refresh=<seconds>
       -- Inside the domain this uses Kerberos, so no certificate/IssuerCA is needed (this is exactly the point of building the domain).
    2) Registry policy: Allow remote server management through WinRM
       HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service  AllowAutoConfig=1 / IPv4Filter=* / IPv6Filter=*
       -- Configures WinRM listener auto-configuration (AllowAutoConfig) + sets the service startup type to automatic (takes effect on each subsequent reboot);
          note: this does not immediately start the WinRM service in the current session; that must be ensured separately (see "needs manual completion" below).
    3) Links the GPO to the domain root (can be changed to link to a specific OU to narrow the scope as needed).

  [Three items that need manual/GPP completion] (cannot be fully expressed with Set-GPRegistryValue alone, see docs\03-domain-and-wef.md):
    * Ensure the source-side WinRM service is [running]: this script already sets the startup-type policy to automatic (takes effect after each subsequent reboot),
      but it does not immediately start the service in the current session. To take effect immediately, run ..\guest\Configure-WEF-Source.ps1 on each source machine
      (includes winrm quickconfig + service restart), or use GPP "Services" set to automatic + started.
    * Add NT AUTHORITY\NETWORK SERVICE to the local "Event Log Readers" group on each source machine
      (required to forward the Security log) -- use GPP "Local Users and Groups", or run ..\guest\Configure-WEF-Source.ps1 on each machine.
    * Advanced audit policy (4688 process creation with command line, logon events, etc.) -- see the GUI path provided in the documentation.
.PARAMETER CollectorFqdn
  The FQDN of the WEF collector (= domain controller), which must match its Kerberos name. Defaults to CSL-Server.cafesec.lab.
.PARAMETER RefreshSeconds
  The interval in seconds at which the source pulls the subscription configuration. Defaults to 60.
.PARAMETER GpoName
  The GPO name, defaults to 'CafeSec-WEF-Source'.
.PARAMETER TargetOU
  The distinguished name (DN) of the GPO link target. Defaults to the domain root (derived from the domain FQDN).
.EXAMPLE
  .\New-WefGpo.ps1
.EXAMPLE
  .\New-WefGpo.ps1 -CollectorFqdn CSL-Server.cafesec.lab -RefreshSeconds 60
.NOTES
  Requires administrator privileges and must be run on the domain controller (requires the GroupPolicy module, installed with RSAT/AD DS). Idempotent: if the GPO already exists, its values are updated.
#>
[CmdletBinding()]
param(
    [string]$CollectorFqdn  = 'CSL-Server.cafesec.lab',
    [int]   $RefreshSeconds = 60,
    [string]$GpoName        = 'CafeSec-WEF-Source',
    [string]$TargetOU
)
. "$PSScriptRoot\..\lib\Common.ps1"
Assert-Admin

if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    Write-Fail "GroupPolicy module not found. Please run on the domain controller (AD DS/RSAT provides this module)."; return
}
Import-Module GroupPolicy -ErrorAction Stop

# Derive the domain root DN (if -TargetOU is not explicitly specified)
if (-not $TargetOU) {
    try { $TargetOU = (Get-ADDomain -ErrorAction Stop).DistinguishedName }
    catch {
        # Fallback: build the DN from the computer's DNS domain name
        $dns = (Get-CimInstance Win32_ComputerSystem).Domain
        if (-not $dns) { Write-Fail "Unable to determine the domain DN; please specify it with -TargetOU."; return }
        $TargetOU = ($dns.Split('.') | ForEach-Object { "DC=$_" }) -join ','
    }
}

Write-Step "Creating/updating GPO: $GpoName"
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) { $gpo = New-GPO -Name $GpoName -Comment 'CafeSec Lab: configure WEF event source (SubscriptionManager + WinRM)'; Write-Ok "Created GPO '$GpoName'." }
else { Write-Ok "GPO '$GpoName' already exists; updating its settings." }

# 1) SubscriptionManager (source-initiated, Kerberos/HTTP/5985)
$subValue = "Server=http://$CollectorFqdn`:5985/wsman/SubscriptionManager/WEC,Refresh=$RefreshSeconds"
$subKey   = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
Set-GPRegistryValue -Name $GpoName -Key $subKey -ValueName '1' -Type String -Value $subValue | Out-Null
Write-Ok "SubscriptionManager = $subValue"

# 2) Allow remote server management through WinRM (allow WinRM to auto-configure the listener at runtime)
#    Note: this is only the policy to "allow auto-configuration of the listener"; by itself it [does not start] the WinRM service.
$winrmKey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
Set-GPRegistryValue -Name $GpoName -Key $winrmKey -ValueName 'AllowAutoConfig' -Type DWord  -Value 1   | Out-Null
Set-GPRegistryValue -Name $GpoName -Key $winrmKey -ValueName 'IPv4Filter'      -Type String -Value '*' | Out-Null
Set-GPRegistryValue -Name $GpoName -Key $winrmKey -ValueName 'IPv6Filter'      -Type String -Value '*' | Out-Null
Write-Ok "Configured the WinRM listener auto-configuration policy (AllowAutoConfig=1)."

# 2b) Set the WinRM service startup type to [automatic]. On Windows 11 desktop editions, WinRM defaults to manual (trigger start);
#     AllowAutoConfig alone will not keep the service running, and source-initiated WEF requires the WinRM service to actually be running.
#     Use a registry policy to set the service Start value to 2 (automatic) -- this takes effect [after the client's next reboot]
#     (joining the domain itself triggers a reboot). Note: this [does not immediately start] the service in the current session; see "still needs completion" at the end.
$winrmSvcKey = 'HKLM\SYSTEM\CurrentControlSet\Services\WinRM'
Set-GPRegistryValue -Name $GpoName -Key $winrmSvcKey -ValueName 'Start' -Type DWord -Value 2 | Out-Null
Write-Ok "Set the WinRM service startup-type policy to automatic (takes effect on each subsequent reboot)."

# 3) Link to the target (domain root or specified OU)
$linked = (Get-GPInheritance -Target $TargetOU -ErrorAction SilentlyContinue).GpoLinks | Where-Object DisplayName -eq $GpoName
if (-not $linked) {
    New-GPLink -Name $GpoName -Target $TargetOU -LinkEnabled Yes | Out-Null
    Write-Ok "Linked the GPO to $TargetOU"
} else { Write-Ok "GPO is already linked to $TargetOU (skipping)." }

Write-Step "GPO deployment complete"
Write-Host "After running 'gpupdate /force' on the client [and once the WinRM service is running], the source will push events to $CollectorFqdn." -ForegroundColor Gray
Write-Host "Still needs completion (see docs\03-domain-and-wef.md):" -ForegroundColor Yellow
Write-Host "  * The WinRM service must be running: this GPO sets it to automatic (takes effect on each subsequent reboot); to take effect immediately, run ..\guest\Configure-WEF-Source.ps1 on each source machine." -ForegroundColor Yellow
Write-Host "  * Add NETWORK SERVICE to the 'Event Log Readers' group on each source machine (required to forward the Security log)." -ForegroundColor Yellow
Write-Host "  * Advanced audit policy (4688 with command line / logon events, etc.)." -ForegroundColor Yellow
Write-Host "On the collector side, confirm that ..\guest\Configure-WEC-Collector.ps1 has been run and the subscription imported." -ForegroundColor Gray
