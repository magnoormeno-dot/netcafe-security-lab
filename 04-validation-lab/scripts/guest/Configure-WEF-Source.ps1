#requires -Version 5.1
<#
.SYNOPSIS
  [Run on each Windows guest machine (10.10.10.31/32)] Configures the local machine as a WEF event source
  that pushes key security events to the collector CSL-Server.
.DESCRIPTION
  Source-initiated subscription: the guest machine periodically contacts the collector to pull subscriptions and push events.
  Requires: WinRM enabled + SubscriptionManager configured to point at the collector + the NETWORK SERVICE account having read access to the logs.
  Purely defensive configuration; it does not change any business behavior.
  [Domain mode] This machine has already joined cafesec.lab, and WEF uses Kerberos (HTTP/5985), so no certificate is needed.
  This script is the [manual, per-machine] configuration method; using ..\domain\New-WefGpo.ps1 on the domain controller to deploy uniformly via GPO is recommended instead.
  Key point: Kerberos must use the collector's [FQDN] (matching its SPN); a bare IP cannot be used.
.PARAMETER CollectorFqdn
  Collector (= domain controller) FQDN, defaulting to CSL-Server.cafesec.lab. The guest is already domain-joined with DNS pointing at the domain controller, so it can resolve this.
#>
[CmdletBinding()]
param(
    [string]$CollectorFqdn = 'CSL-Server.cafesec.lab'
)
$ErrorActionPreference = 'Stop'
function Test-Admin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not (Test-Admin)) { throw "Administrator privileges are required." }

Write-Host "=== Configuring WEF event source -> collector $CollectorFqdn ===" -ForegroundColor Cyan

# 1) Enable WinRM (the source side also needs the WinRM service running)
winrm quickconfig -quiet

# 2) Configure SubscriptionManager (source-initiated). 5985 = WinRM HTTP; within the domain it uses Kerberos.
#    Refresh=60 pulls the subscription configuration once per 60 seconds. Use the FQDN (not the IP) to match the collector's Kerberos SPN.
$server = "Server=http://$CollectorFqdn`:5985/wsman/SubscriptionManager/WEC,Refresh=60"
$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name '1' -Value $server
Write-Host "[ OK ] SubscriptionManager = $server" -ForegroundColor Green

# 3) Allow the NETWORK SERVICE account to read the security log (required to forward security events)
#    Add NETWORK SERVICE to the local 'Event Log Readers' group.
try {
    $grp = [ADSI]"WinNT://./Event Log Readers,group"
    $grp.Add("WinNT://NT AUTHORITY/NETWORK SERVICE")
    Write-Host "[ OK ] Added NETWORK SERVICE to 'Event Log Readers'." -ForegroundColor Green
} catch {
    if ($_.Exception.Message -match 'already a member|already is') { Write-Host "[ OK ] NETWORK SERVICE is already in Event Log Readers." -ForegroundColor Green }
    else { Write-Host "[WARN] Failed to add to Event Log Readers: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# 4) Restart WinRM so the configuration takes effect
Restart-Service WinRM

Write-Host "`nOn the collector, run 'wecutil gr CafeSec-Security' to view this source's runtime status (this machine should appear)." -ForegroundColor Gray
Write-Host "Troubleshooting: on the source, run eventvwr -> Applications and Services Logs\Microsoft\Windows\Eventlog-ForwardingPlugin\Operational" -ForegroundColor Gray
