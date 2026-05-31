#requires -Version 5.1
<#
.SYNOPSIS
  Enable the Hyper-V platform and management tools. Requires administrator privileges; a restart is usually needed afterward.
.NOTES
  This machine detected HypervisorPresent=True, so Hyper-V/VBS/WSL2 may already be present.
  Even so, explicitly enabling Microsoft-Hyper-V-All ensures the PowerShell module,
  the vmms service, and virtual switch management are all complete. The script is idempotent -- it skips anything already enabled.
#>
[CmdletBinding()]
param([switch]$NoPrompt)
. "$PSScriptRoot\lib\Common.ps1"
Assert-Admin

Write-Step "Enabling Hyper-V"

$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
if ($feature.State -eq 'Enabled') {
    Write-Ok "Hyper-V is already enabled; no action required."
} else {
    Write-Host "About to enable feature: Microsoft-Hyper-V-All (including management tools)"
    if (-not $NoPrompt) {
        $ans = Read-Host "Continue? A restart may be required afterward [y/N]"
        if ($ans -notmatch '^(y|Y)') { Write-Warn2 "Cancelled."; return }
    }
    $r = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
    Write-Ok "Hyper-V feature enabled."
    if ($r.RestartNeeded) {
        Write-Warn2 "A restart is required to take effect. After restarting, run 02-New-IsolatedSwitch.ps1"
    }
}

# Confirm core services/modules
$svc = Get-Service vmms -ErrorAction SilentlyContinue
if ($svc) { Write-Ok "Hyper-V management service vmms status: $($svc.Status)" }
if (Get-Command New-VMSwitch -ErrorAction SilentlyContinue) { Write-Ok "Hyper-V PowerShell module available (New-VMSwitch is ready)" }
else { Write-Warn2 "Hyper-V PowerShell module not detected; a restart may be needed before retrying." }

Write-Step "Done. After restarting (if required), run: 02-New-IsolatedSwitch.ps1"
