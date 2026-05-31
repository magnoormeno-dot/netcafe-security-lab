#requires -Version 5.1
<#
  Common.ps1 — Shared helper functions and configuration loading for all CafeSec scripts.
  Load it at the top of a script with:  . "$PSScriptRoot\lib\Common.ps1"   (or a relative path).
#>

function Get-LabConfig {
    [CmdletBinding()]
    param(
        # Note: when dot-sourced, $PSScriptRoot binds to the directory containing Common.ps1 itself (...\scripts\lib),
        # not the caller's directory. Project root = two levels up: <root>\scripts\lib -> <root>; config lives in <root>\config.
        [string]$ConfigPath = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'config\lab.psd1')
    )
    if (-not (Test-Path $ConfigPath)) {
        throw "Configuration file lab.psd1 not found ($ConfigPath). Use -ConfigPath to specify its absolute path."
    }
    return Import-PowerShellDataFile -Path $ConfigPath
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    if (-not (Test-IsAdmin)) {
        throw "This script requires administrator privileges. Right-click PowerShell -> 'Run as administrator' and try again."
    }
}

function Write-Step  { param([string]$m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok    { param([string]$m) Write-Host "[ OK ]  $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Fail  { param([string]$m) Write-Host "[FAIL]  $m" -ForegroundColor Red }
