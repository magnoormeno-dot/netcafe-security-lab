#requires -Version 5.1
<#
.SYNOPSIS
  CafeSec Lab preflight: confirm the host meets the build prerequisites before you start. Read-only, makes no changes.
.NOTES
  Most checks run without administrator rights; querying the Hyper-V feature state requires administrator.
#>
[CmdletBinding()]
param()
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Get-LabConfig
Write-Step "CafeSec Lab Preflight (Preflight Check)"

# 1. Operating system / version
# Use EditionID (independent of the UI language) for the decision instead of Caption -- on a Chinese system the
# Caption reads "Professional Edition" rather than "Pro", so Caption -match 'Pro' would misidentify it as Home on a
# Chinese machine. The Home edition's EditionID starts with Core.
$os = Get-CimInstance Win32_OperatingSystem
$edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
Write-Host "OS          : $($os.Caption) [$edition] (Build $($os.BuildNumber), $($os.OSArchitecture))"
if ($edition -and $edition -notmatch '^Core') { Write-Ok "Windows edition supports Hyper-V (EditionID=$edition)" }
elseif ($edition -match '^Core') { Write-Fail "Home edition ($edition) does not include Hyper-V. Requires Pro/Enterprise/Education/Server." }
else { Write-Warn2 "Unable to read EditionID, skipping version check (Caption: $($os.Caption))." }

# 2. Memory
$ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1)
Write-Host "RAM         : $ramGB GB"
$needGB = ($cfg.VMs.MemoryGB | Measure-Object -Sum).Sum
if ($ramGB -ge ($needGB + 8)) { Write-Ok "Sufficient memory: VMs need ${needGB}GB, host headroom >= 8GB" }
else { Write-Warn2 "Memory is tight: VMs need ${needGB}GB, total memory ${ramGB}GB" }

# 3. CPU virtualization
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$hvPresent = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
Write-Host "CPU         : $($cpu.Name) ($($cpu.NumberOfLogicalProcessors) logical cores)"
Write-Host "HypervisorPresent      : $hvPresent"
Write-Host "VirtFirmwareEnabled    : $($cpu.VirtualizationFirmwareEnabled)"
if ($hvPresent) {
    Write-Ok "A hypervisor is already running -> VT-x must already be enabled in the BIOS (no need to enter the BIOS)"
} elseif ($cpu.VirtualizationFirmwareEnabled) {
    Write-Ok "VT-x is enabled in firmware"
} else {
    Write-Fail "VT-x appears to be disabled. Enter the BIOS/UEFI to enable Intel VT-x, then retry."
}

# 4. Disk space (check the drive that stores the VMs)
$vmDrive = (Split-Path -Qualifier $cfg.Paths.VmRoot)   # e.g. 'E:'
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$vmDrive'"
if ($disk) {
    $freeGB = [math]::Round($disk.FreeSpace/1GB,1)
    $needDisk = ($cfg.VMs.DiskGB | Measure-Object -Sum).Sum
    Write-Host "VM disk     : $vmDrive $freeGB GB free (dynamic disk cap total ${needDisk}GB)"
    if ($freeGB -ge 200) { Write-Ok "Sufficient disk space (>=200GB)" }
    else { Write-Warn2 "Free space < 200GB, watch for dynamic disk growth" }
} else {
    Write-Fail "Drive $vmDrive not found, check Paths.VmRoot in config\lab.psd1"
}

# 5. Whether the Hyper-V feature is enabled (requires administrator)
if (Test-IsAdmin) {
    $hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if ($hv) {
        Write-Host "Hyper-V feature : $($hv.State)"
        if ($hv.State -eq 'Enabled') { Write-Ok "Hyper-V is enabled" }
        else { Write-Warn2 "Hyper-V is not enabled -> run 01-Enable-HyperV.ps1" }
    }
} else {
    Write-Warn2 "Not running as administrator, skipping the Hyper-V feature state check (non-blocking)"
}

# 6. Whether the ISOs are in place
Write-Step "Image (ISO) check"
foreach ($vm in $cfg.VMs) {
    $isoPath = Join-Path $cfg.Paths.IsoRoot $vm.IsoFile
    if (Test-Path $isoPath) { Write-Ok "$($vm.Name): found $($vm.IsoFile)" }
    else { Write-Warn2 "$($vm.Name): missing $($vm.IsoFile)  (place it in $($cfg.Paths.IsoRoot), download URLs in docs\downloads.md)" }
}

Write-Step "Preflight complete"
Write-Host "Resolve any FAIL items first; WARN items are mostly hints (such as an ISO not yet downloaded). Next step: 01-Enable-HyperV.ps1" -ForegroundColor Gray
