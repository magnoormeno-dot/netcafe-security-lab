#requires -Version 5.1
<#
.SYNOPSIS
  [DESTRUCTIVE] Tears down the CafeSec Lab: removes the 4 CSL VMs, their VHDXs, and the isolated switch.
.DESCRIPTION
  This is a teardown script that [PERMANENTLY DELETES] data. It is designed with layered safeguards to ensure only the intended objects are removed:

    * Deletion scope is strictly limited to the CSL VMs listed in config\lab.psd1, their virtual hard disks
      (under Paths.VmRoot, default E:\CafeSec-Lab\VMs), and the isolated switch
      (Network.SwitchName, default CafeSec-Isolated).
    * It [NEVER] touches any non-CSL VM and [NEVER] deletes any switch other than the isolated switch
      (for example, the NAT/External switch you used in Stage 1 is left untouched).
    * Before deleting, it shuts down any running target VMs (graceful shutdown first, forced shutdown on timeout).
    * After removing a VM, it deletes its VHDX separately -- because Remove-VM only removes the config/registration; the VHDX file is not deleted along with it.
    * It only removes empty VM subdirectories; non-empty directories (which may contain things you added yourself) are kept and reported.

  Confirmation mechanism (pick exactly one, one is required):
    -WhatIf         Only previews the list of objects to be deleted, making no changes (can be used on its own; the safest "quick look").
    -Force          Explicitly states "I confirm the deletion", skipping interactive input (suitable for scripting/unattended runs).
    Interactive     When none of the above is given, the script lists the objects and requires you to [manually type DELETE in uppercase] before it proceeds.
.PARAMETER WhatIf
  Dry-run mode: prints all objects that would be deleted, but does not actually delete them. Highest priority (if given, it only previews).
.PARAMETER Force
  Non-interactive confirmation switch. Passing -Force is treated as consent to delete, and DELETE is no longer requested.
  (Renamed from -Confirm: -Confirm is a PowerShell reserved common parameter whose conventional semantics are "prompt for each item before deletion",
   which is the opposite of this script's "skip the prompt and delete directly"; this is easily misused, so -Force is used instead.)
.PARAMETER ShutdownTimeoutSec
  Seconds to wait for a graceful shutdown before forcing it off (Stop-VM -Force). Default 120.
.EXAMPLE
  # Take a look at what would be deleted first (strongly recommended as the first step)
  .\Reset-Lab.ps1 -WhatIf
.EXAMPLE
  # Interactive confirmation: the script lists the objects and then requires you to type DELETE
  .\Reset-Lab.ps1
.EXAMPLE
  # Unattended: you already understand the consequences, execute directly
  .\Reset-Lab.ps1 -Force
.NOTES
  Requires administrator. Follows the Get-LabConfig / Write-* conventions from lib\Common.ps1.
  This script does [NOT] use CmdletBinding's SupportsShouldProcess; it manages -WhatIf / -Force itself,
  in order to strictly implement the dual-confirmation semantics of "explicit -Force or interactive DELETE input" per the spec.
#>
[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,            # Non-interactive confirmation: passing it is treated as consent to delete. Renamed from -Confirm to avoid taking the reserved name and inverting its semantics.
    [int]$ShutdownTimeoutSec = 120
)

. "$PSScriptRoot\lib\Common.ps1"
Assert-Admin
$cfg = Get-LabConfig

$vmRoot         = $cfg.Paths.VmRoot
$isolatedSwitch = $cfg.Network.SwitchName
$cslNames       = @($cfg.VMs | ForEach-Object { $_.Name })

Write-Step "CafeSec Lab teardown (Reset-Lab) -- destructive operation"
Write-Warn2 "This operation will [PERMANENTLY DELETE] the objects below. Please review the list carefully."

# =====================================================================
# 1) Inventory the objects to be deleted (read-only, no changes)
# =====================================================================

# --- 1a. Target VMs: only CSL VMs that are in the config list and actually exist on the host ---
$targetVMs = @()
foreach ($name in $cslNames) {
    $vm = Get-VM -Name $name -ErrorAction SilentlyContinue
    if ($vm) { $targetVMs += $vm }
}

# --- 1b. The VHDXs currently attached to these VMs (Remove-VM will not delete them, so they must be deleted separately) ---
$targetVhds = @()
foreach ($vm in $targetVMs) {
    foreach ($hd in (Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue)) {
        if ($hd.Path) { $targetVhds += $hd.Path }
    }
}

# --- 1c. Fallback: scan for *.vhdx / *.avhdx in each CSL VM subdirectory under Paths.VmRoot (including checkpoint differencing disks, to prevent leftovers) ---
if (Test-Path $vmRoot) {
    foreach ($name in $cslNames) {
        $vmDir = Join-Path $vmRoot $name
        if (Test-Path $vmDir) {
            Get-ChildItem -Path $vmDir -Recurse -File -Include *.vhdx,*.avhdx -ErrorAction SilentlyContinue |
                ForEach-Object { $targetVhds += $_.FullName }
        }
    }
}
# Deduplicate (the same disk may be matched both by being attached and by the directory scan)
$targetVhds = @($targetVhds | Sort-Object -Unique)

# --- 1d. Isolated switch (this one only; NAT/External etc. are never in this list) ---
$targetSwitch = Get-VMSwitch -Name $isolatedSwitch -ErrorAction SilentlyContinue

# --- 1e. [Empty] subdirectories that can be cleaned up after removing the VMs ---
$targetDirs = @()
if (Test-Path $vmRoot) {
    foreach ($name in $cslNames) {
        $vmDir = Join-Path $vmRoot $name
        if (Test-Path $vmDir) { $targetDirs += $vmDir }
    }
}

# =====================================================================
# 2) Print the list
# =====================================================================
Write-Step "[Virtual machines] to be deleted (CSL only, in the config list and existing)"
if ($targetVMs.Count -gt 0) {
    $targetVMs | Format-Table Name, State,
        @{n = 'MemGB'; e = { [math]::Round($_.MemoryStartup / 1GB, 0) } },
        @{n = 'Switch'; e = { (Get-VMNetworkAdapter -VMName $_.Name | Select-Object -First 1).SwitchName } } -AutoSize
} else {
    Write-Host "  (none: none of these CSL VMs currently exist)" -ForegroundColor Gray
}

Write-Step "[Virtual hard disks (VHDX)] to be deleted (under $vmRoot)"
if ($targetVhds.Count -gt 0) {
    $targetVhds | ForEach-Object {
        $size = if (Test-Path $_) { '{0:N1} GB' -f ((Get-Item $_).Length / 1GB) } else { '?' }
        Write-Host ("  - {0}  [{1}]" -f $_, $size)
    }
} else {
    Write-Host "  (none)" -ForegroundColor Gray
}

Write-Step "[Isolated switch] to be deleted (this one only)"
if ($targetSwitch) {
    Write-Host ("  - {0}  (type {1})" -f $targetSwitch.Name, $targetSwitch.SwitchType)
} else {
    Write-Host "  (none: '$isolatedSwitch' does not currently exist)" -ForegroundColor Gray
}

Write-Step "[Empty directories] to be cleaned up (only if they become empty after the disks are deleted)"
if ($targetDirs.Count -gt 0) {
    $targetDirs | ForEach-Object { Write-Host ("  - {0}" -f $_) }
} else {
    Write-Host "  (none)" -ForegroundColor Gray
}

# Explicitly state what will not be touched.
Write-Host ""
Write-Warn2 "The following will [NOT] be touched: any non-CSL virtual machine, any switch other than the isolated switch (including your NAT/External), and any non-empty/unrelated directories under $vmRoot."

# Nothing to delete, finish right away.
if ($targetVMs.Count -eq 0 -and $targetVhds.Count -eq 0 -and -not $targetSwitch) {
    Write-Ok "No deletable CafeSec objects were found; the environment is already clean. No action needed."
    return
}

# =====================================================================
# 3) -WhatIf: preview only, never change anything
# =====================================================================
if ($WhatIf) {
    Write-Step "WhatIf dry-run mode"
    Write-Ok "The above is the complete list of objects that would be deleted. This is a -WhatIf run; nothing was changed."
    Write-Host "Once confirmed, remove -WhatIf and rerun (typing DELETE interactively), or add -Force to execute directly." -ForegroundColor Gray
    return
}

# =====================================================================
# 4) Confirmation gate: -Confirm for explicit consent, otherwise require typing DELETE in uppercase interactively
# =====================================================================
if (-not $Force) {
    Write-Step "Final confirmation"
    Write-Warn2 "This will [PERMANENTLY DELETE] the VMs, VHDXs, and isolated switch listed above, and is not recoverable."
    $answer = Read-Host "To confirm deletion, [type DELETE in full uppercase] and press Enter (any other input will cancel)"
    if ($answer -cne 'DELETE') {
        Write-Fail "DELETE was not entered (received: '$answer'). Cancelled, no changes made."
        return
    }
    Write-Ok "DELETE confirmation received."
} else {
    Write-Warn2 "Explicitly confirmed via -Force; skipping interactive input and starting the deletion."
}

# =====================================================================
# 5) Perform the deletion
# =====================================================================

# --- 5a. Shut down first (only the target VMs) ---
Write-Step "Stopping running target VMs"
foreach ($vm in $targetVMs) {
    $live = Get-VM -Name $vm.Name -ErrorAction SilentlyContinue
    if ($live -and $live.State -ne 'Off') {
        Write-Host "  Shutting down $($vm.Name) (currently $($live.State))..."
        # Try a graceful shutdown first (via integration services), allowing some wait time.
        Stop-VM -Name $vm.Name -ErrorAction SilentlyContinue
        $deadline = (Get-Date).AddSeconds($ShutdownTimeoutSec)
        while ((Get-Date) -lt $deadline) {
            $st = (Get-VM -Name $vm.Name -ErrorAction SilentlyContinue).State
            if ($st -eq 'Off') { break }
            Start-Sleep -Seconds 3
        }
        if ((Get-VM -Name $vm.Name -ErrorAction SilentlyContinue).State -ne 'Off') {
            Write-Warn2 "  $($vm.Name) graceful shutdown timed out ($ShutdownTimeoutSec s); forcing it off instead."
            Stop-VM -Name $vm.Name -TurnOff -Force -ErrorAction SilentlyContinue
        }
        Write-Ok "  $($vm.Name) stopped."
    } else {
        Write-Ok "  $($vm.Name) is already off."
    }
}

# --- 5b. Remove the VMs (note: Remove-VM only removes the config/registration, not the VHDX) ---
Write-Step "Removing virtual machines (CSL only)"
foreach ($vm in $targetVMs) {
    # Use try/catch: report and continue if a single removal fails, so the whole teardown is not aborted midway (consistent with the disk-deletion logic in 5c).
    try {
        Remove-VM -Name $vm.Name -Force -ErrorAction Stop
        Write-Ok "  Removed VM '$($vm.Name)' (its VHDX will be deleted separately in the next step)."
    } catch {
        Write-Fail "  Failed to remove VM '$($vm.Name)': $($_.Exception.Message)"
    }
}

# --- 5c. Delete the VHDX files ---
Write-Step "Deleting virtual hard disks (VHDX)"
foreach ($path in $targetVhds) {
    if (Test-Path $path) {
        try {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            Write-Ok "  Deleted $path"
        } catch {
            Write-Fail "  Failed to delete $path : $($_.Exception.Message)"
        }
    } else {
        Write-Warn2 "  Skipped (file no longer exists): $path"
    }
}

# --- 5d. Clean up empty VM subdirectories (keep non-empty ones) ---
Write-Step "Cleaning up empty directories"
foreach ($dir in $targetDirs) {
    if (Test-Path $dir) {
        $remaining = @(Get-ChildItem -LiteralPath $dir -Force -Recurse -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })
        if ($remaining.Count -eq 0) {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Ok "  Removed empty directory $dir"
        } else {
            Write-Warn2 "  Keeping $dir (still has $($remaining.Count) file(s); content not created by CafeSec will not be deleted)."
        }
    }
}

# --- 5e. Remove the isolated switch (and only this one) ---
Write-Step "Removing the isolated switch"
if ($targetSwitch) {
    Remove-VMSwitch -Name $targetSwitch.Name -Force -ErrorAction Stop
    Write-Ok "  Removed switch '$($targetSwitch.Name)'."
} else {
    Write-Host "  (no isolated switch to remove)" -ForegroundColor Gray
}

# =====================================================================
# 6) Wrap-up
# =====================================================================
Write-Step "Teardown complete"
Write-Ok "CafeSec Lab has been cleaned up. Non-CSL VMs and switches other than the isolated switch were left unaffected."
Write-Host "To rebuild: 02-New-IsolatedSwitch.ps1  ->  03-New-LabVMs.ps1." -ForegroundColor Gray
