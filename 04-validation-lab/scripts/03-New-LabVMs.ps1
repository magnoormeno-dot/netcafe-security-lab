#requires -Version 5.1
<#
.SYNOPSIS
  Creates 4 Gen2 virtual machines per config\lab.psd1, all attached to the isolated private switch.
.DESCRIPTION
  What gets created: dynamic VHDX, specified memory/vCPU, connection to the CafeSec-Isolated switch, mounted installation ISO.
  Linux (Ubuntu) uses the MicrosoftUEFICertificateAuthority Secure Boot template;
  Windows uses the default MicrosoftWindows template.
  Idempotent: if a VM with the same name already exists, it is skipped (this will not overwrite a system you have already installed).
.PARAMETER WhatIf
  Only prints the actions that would be taken, without actually creating anything.
#>
[CmdletBinding(SupportsShouldProcess)]
param()
. "$PSScriptRoot\lib\Common.ps1"
Assert-Admin
$cfg = Get-LabConfig

# Make sure the storage directories exist
foreach ($p in @($cfg.Paths.VmRoot, $cfg.Paths.IsoRoot)) {
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null; Write-Ok "Created directory $p" }
}

$switch = Get-VMSwitch -Name $cfg.Network.SwitchName -ErrorAction SilentlyContinue
if (-not $switch) { Write-Fail "Isolated switch '$($cfg.Network.SwitchName)' does not exist. Please run 02-New-IsolatedSwitch.ps1 first"; return }

foreach ($vm in $cfg.VMs) {
    Write-Step "VM: $($vm.Name)  [$($vm.Role)]  $($vm.OS)"

    if (Get-VM -Name $vm.Name -ErrorAction SilentlyContinue) {
        Write-Warn2 "VM '$($vm.Name)' already exists, skipping creation."
        continue
    }

    $vmDir   = Join-Path $cfg.Paths.VmRoot $vm.Name
    $vhdPath = Join-Path $vmDir "$($vm.Name).vhdx"
    $isoPath = Join-Path $cfg.Paths.IsoRoot $vm.IsoFile

    if ($PSCmdlet.ShouldProcess($vm.Name, "Create Gen$($vm.Generation) VM, $($vm.MemoryGB)GB memory, $($vm.CPU) vCPU, $($vm.DiskGB)GB dynamic disk")) {

        New-VM -Name $vm.Name -Generation $vm.Generation `
               -MemoryStartupBytes ($vm.MemoryGB * 1GB) `
               -NewVHDPath $vhdPath -NewVHDSizeBytes ($vm.DiskGB * 1GB) `
               -SwitchName $cfg.Network.SwitchName -Path $cfg.Paths.VmRoot | Out-Null

        Set-VMProcessor   -VMName $vm.Name -Count $vm.CPU
        # Fixed memory (the lab environment favors stability and predictability; adjust yourself if you need dynamic memory)
        Set-VMMemory      -VMName $vm.Name -DynamicMemoryEnabled $false -StartupBytes ($vm.MemoryGB * 1GB)

        # Secure Boot template
        if ($vm.SecureBoot -eq 'Linux') {
            Set-VMFirmware -VMName $vm.Name -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
        } else {
            Set-VMFirmware -VMName $vm.Name -EnableSecureBoot On
        }

        # vTPM: Windows 11 installation requires TPM 2.0, but a Gen2 VM has [no] TPM by default and it must be explicitly enabled,
        # otherwise the two Win11 guests will get stuck at "This PC can't run Windows 11" and fail to install.
        # Order matters: run Set-VMKeyProtector (local key protector) first, then Enable-VMTPM; doing it the other way around fails.
        # A standalone host (no HGS/domain) can use the local key protector; a Win11/Server 2022 host will automatically generate the required certificates.
        if ($vm.Generation -eq 2 -and $vm.SecureBoot -eq 'Windows') {
            Set-VMKeyProtector -VMName $vm.Name -NewLocalKeyProtector
            Enable-VMTPM       -VMName $vm.Name
            Write-Ok "$($vm.Name) vTPM enabled (Win11 installation prerequisite)"
        }

        # Always add a DVD drive and set it as the preferred boot device; the image can be mounted now or manually later.
        # (An empty VHDX cannot boot, and Gen2 has no legacy BIOS fallback -- if the boot entry were only set when an ISO is present,
        #  then the "create the VM first, mount the image later" path would have no boot entry and the VM would not power on.)
        Add-VMDvdDrive -VMName $vm.Name
        $dvd = Get-VMDvdDrive -VMName $vm.Name
        Set-VMFirmware -VMName $vm.Name -FirstBootDevice $dvd
        if (Test-Path $isoPath) {
            Set-VMDvdDrive -VMName $vm.Name -Path $isoPath
            Write-Ok "Mounted installation image and set as preferred boot device: $($vm.IsoFile)"
        } else {
            Write-Warn2 "ISO not found: $isoPath  -- the VM has been created and the DVD drive is set as the preferred boot device; later you only need to run Set-VMDvdDrive -VMName $($vm.Name) -Path <iso> to power it on."
        }

        # Enable the Guest Service Interface: makes it easy to inject files with Copy-VMFile while isolated (no network needed)
        Enable-VMIntegrationService -VMName $vm.Name -Name 'Guest Service Interface' -ErrorAction SilentlyContinue

        Write-Ok "$($vm.Name) created -> planned static IP $($vm.IP)/$($cfg.Network.Prefix)"
    }
}

Write-Step "All VMs processed"
Get-VM | Where-Object Name -like 'CSL-*' |
    Format-Table Name, State, ProcessorCount, @{n='MemGB';e={[math]::Round($_.MemoryStartup/1GB,0)}}, @{n='Switch';e={(Get-VMNetworkAdapter $_.Name).SwitchName}} -AutoSize

Write-Host "Tip: the VM network adapters are now attached to the isolated switch. After the OS is installed, run guest\Set-StaticIP.ps1 inside each VM to configure 10.10.10.x." -ForegroundColor Gray
Write-Host "Important: for OS and defensive tool installation, see the [Two-Phase Setup] section in docs\02-network-isolation.md." -ForegroundColor Yellow
