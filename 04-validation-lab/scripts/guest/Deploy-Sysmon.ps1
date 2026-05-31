#requires -Version 5.1
<#
.SYNOPSIS
  [Run inside the Windows guest/server] Install Sysmon and apply the SwiftOnSecurity baseline configuration.
.DESCRIPTION
  Purely defensive: Sysmon is the endpoint logger from Microsoft Sysinternals. It generates rich process/network/file
  /registry events into the event log for use by Sigma rules and Wazuh detection.
  The isolated network has no internet access for downloads, so this script pulls Sysmon and the config file from a [local path].
  First inject the following files into the VM with Copy-VMFile (see docs), or place them on a mounted ISO:
    - Sysmon64.exe extracted from Sysmon.zip
    - sysmonconfig-export.xml (SwiftOnSecurity config)
.PARAMETER SysmonExe
  Full local path to Sysmon64.exe.
.PARAMETER ConfigXml
  Full local path to the Sysmon configuration XML.
.EXAMPLE
  .\Deploy-Sysmon.ps1 -SysmonExe C:\CafeSec\Sysmon64.exe -ConfigXml C:\CafeSec\sysmonconfig-export.xml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SysmonExe,
    [Parameter(Mandatory)][string]$ConfigXml
)
$ErrorActionPreference = 'Stop'
function Test-Admin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not (Test-Admin)) { throw "Administrator privileges are required." }

foreach ($f in @($SysmonExe,$ConfigXml)) { if (-not (Test-Path $f)) { throw "File not found: $f" } }

$svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Sysmon is already installed, updating configuration..." -ForegroundColor Yellow
    & $SysmonExe -c $ConfigXml
} else {
    Write-Host "Installing Sysmon and applying configuration..." -ForegroundColor Cyan
    & $SysmonExe -accepteula -i $ConfigXml
}

Start-Sleep -Seconds 2
$svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "[ OK ] Sysmon64 service is running." -ForegroundColor Green
} else {
    throw "Sysmon is not running after installation, please check."
}

# Verify that events are being written
$log = 'Microsoft-Windows-Sysmon/Operational'
$cnt = (Get-WinEvent -LogName $log -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "[ OK ] Event log '$log' recent event count (sample): $cnt" -ForegroundColor Green
Write-Host "Active configuration version:" -ForegroundColor Gray
& $SysmonExe -c
