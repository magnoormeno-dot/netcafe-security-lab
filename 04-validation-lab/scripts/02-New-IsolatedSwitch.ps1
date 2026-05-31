#requires -Version 5.1
<#
.SYNOPSIS
  Creates a fully isolated Hyper-V private (Private) virtual switch. This is the foundation of the entire environment's compliance.
.DESCRIPTION
  Why use Private instead of Internal:
    - Private  : Only VM <-> VM connectivity. The host [does NOT] get a vEthernet virtual adapter,
                 so at the network-stack level the host has no interface into this subnet at all -- the strongest isolation.
    - Internal : VM <-> VM and VM <-> host. The host gains an extra vEthernet adapter (can ping the VMs).
    - External : Bridges a physical adapter and can reach the internet. [Strictly forbidden in this lab.]
  This corresponds to the VirtualBox "Internal Network" (VM-only, does not touch the host) in your original plan;
  the equivalent and stricter Hyper-V option is Private.
.NOTES
  Requires administrator. The script is idempotent: if a switch of the same name already exists, it validates its type instead of recreating it.
#>
[CmdletBinding()]
param()
. "$PSScriptRoot\lib\Common.ps1"
Assert-Admin
$cfg = Get-LabConfig
$name = $cfg.Network.SwitchName

Write-Step "Creating isolated private switch: $name ($($cfg.Network.Subnet))"

$existing = Get-VMSwitch -Name $name -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.SwitchType -eq 'Private') {
        Write-Ok "Switch '$name' already exists and is of type Private."
    } else {
        Write-Fail "Switch '$name' already exists but is of type $($existing.SwitchType) (not Private)!"
        Write-Fail "This breaks isolation. Please delete it first: Remove-VMSwitch -Name '$name' -Force, then rerun this script."
        return
    }
} else {
    New-VMSwitch -Name $name -SwitchType Private | Out-Null
    Write-Ok "Created Private switch '$name'."
}

# --- Immediate self-check: confirm the host did not gain a virtual adapter into the isolated subnet ---
Write-Step "Self-check: confirm the host is not exposed on the isolated subnet"
$hostAdapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$name*" -or $_.InterfaceDescription -like "*$name*" }
if ($hostAdapter) {
    Write-Fail "The host has a virtual adapter associated with this switch: $($hostAdapter.Name)"
    Write-Fail "A Private switch should not produce a host vNIC -- please verify the switch type!"
} else {
    Write-Ok "The host has [no] vEthernet adapter for this switch -- the isolation precondition holds."
    Write-Ok "That is: at the network layer the host cannot ping any VM on the isolated network."
}

Write-Host ""
Get-VMSwitch -Name $name | Format-Table Name, SwitchType, AllowManagementOS -AutoSize
Write-Step "Next step: 03-New-LabVMs.ps1  (create the 4 VMs and attach them to this switch)"
