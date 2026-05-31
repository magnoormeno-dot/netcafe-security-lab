#requires -Version 5.1
<#
.SYNOPSIS
  [Run on CSL-Server (10.10.10.20)] Configures this server as a Windows Event Collector (WEC).
.DESCRIPTION
  WEF = Windows Event Forwarding. Client machines (WEF sources) push key security events
  to this collector for centralized archival. This is a purely defensive log-aggregation
  mechanism that complements Wazuh: WEF uses native WinRM and requires no third-party agent.
  This script enables WinRM, initializes the collector service, and imports the
  source-initiated subscription.
  [Domain mode] This host is already a member/domain controller of the cafesec.lab domain, so
  source-initiated WEF uses Kerberos (HTTP/5985) and needs no certificate. Source-side
  configuration is delivered via GPO by ..\domain\New-WefGpo.ps1 (or run Configure-WEF-Source.ps1
  manually on each machine).
.PARAMETER SubscriptionXml
  Path to the subscription definition XML; defaults to the in-project config\wef\cafesec-subscription.xml.
#>
[CmdletBinding()]
param(
    [string]$SubscriptionXml = "$PSScriptRoot\..\..\config\wef\cafesec-subscription.xml"
)
$ErrorActionPreference = 'Stop'
function Test-Admin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not (Test-Admin)) { throw "Administrator privileges are required." }

Write-Host "=== Configure Windows Event Collector (WEC) ===" -ForegroundColor Cyan

# 1) WinRM (the collector must listen in order to receive pushes)
Write-Host "Enabling WinRM..." -ForegroundColor Cyan
winrm quickconfig -quiet

# 2) Initialize the Windows Event Collector service (idempotent)
Write-Host "Initializing the wecutil collector service..." -ForegroundColor Cyan
wecutil qc /q

Set-Service -Name Wecsvc -StartupType Automatic
Start-Service -Name Wecsvc -ErrorAction SilentlyContinue

# 3) Import the subscription
if (Test-Path $SubscriptionXml) {
    $resolved = (Resolve-Path $SubscriptionXml).Path
    Write-Host "Importing subscription: $resolved" -ForegroundColor Cyan
    # If it already exists, delete then recreate to stay idempotent.
    # Note: under PS 5.1, applying 2>$null to a native command wraps each stderr line in a NativeCommandError;
    # with $ErrorActionPreference='Stop' this is a [terminating] error -- on the first run (when the subscription
    # does not yet exist) wecutil gs reports "does not exist" to stderr, which throws and aborts the script
    # [before] the subscription is imported.
    # So use a local Continue scope + $LASTEXITCODE to decide whether it already exists, and never let the
    # redirection bubble up into an exception.
    $subName = ([xml](Get-Content $resolved)).Subscription.SubscriptionId
    $exists = $false
    if ($subName) {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & wecutil gs $subName 1>$null 2>$null
        $exists = ($LASTEXITCODE -eq 0)
        $ErrorActionPreference = $prevEAP
    }
    if ($exists) { wecutil ds $subName }
    wecutil cs $resolved
    Write-Host "[ OK ] Subscription imported." -ForegroundColor Green
    wecutil es
} else {
    Write-Host "[WARN] Subscription XML not found: $SubscriptionXml" -ForegroundColor Yellow
}

Write-Host "`nCollector is ready. Forwarded events land in the log: 'Forwarded Events' (ForwardedEvents)." -ForegroundColor Gray
Write-Host "Source-side configuration (choose one):" -ForegroundColor Gray
Write-Host "  * Recommended: run ..\domain\New-WefGpo.ps1 on the domain controller to deliver the SubscriptionManager to all client machines via GPO." -ForegroundColor Gray
Write-Host "  * Or: run Configure-WEF-Source.ps1 -CollectorFqdn CSL-Server.cafesec.lab manually on each client machine" -ForegroundColor Gray
Write-Host "Use 'wecutil gr CafeSec-Security' to check whether each source is Active." -ForegroundColor Gray
