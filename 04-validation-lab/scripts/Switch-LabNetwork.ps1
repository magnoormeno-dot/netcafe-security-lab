#requires -Version 5.1
<#
.SYNOPSIS
  Safely switch the NIC connections of all CSL-* virtual machines between the two build phases.
.DESCRIPTION
  Implements the two-phase model described in docs\02-network-isolation.md:

    Phase 1 Provisioning (temporary connectivity): connect each CSL VM's NIC to a temporary
        switch (NAT/External, which you create beforehand), used to install the OS / apply patches / install defensive tools / download rules.
    Phase 2 Isolated (full isolation): reconnect each CSL VM's NIC back to CafeSec-Isolated (Private),
        only after which any research activity is allowed.

  This script only changes the SwitchName of the NICs of the CSL VMs listed in config\lab.psd1.
  It does NOT create, delete, or modify any switch itself, and does NOT touch any non-CSL VM.

  -Phase Provisioning:
      Connect each CSL VM's NIC to the temporary switch specified by -ProvisioningSwitch.
      That switch MUST already exist. If it does not, the script only prints creation instructions and aborts --
      it will NEVER silently create an External switch for you (that would bridge a physical NIC and break the air gap).

  -Phase Isolated:
      Reconnect each CSL VM's NIC back to CafeSec-Isolated (read from config Network.SwitchName).
      When done, reminds you to run 04-Verify-Isolation.ps1 for host-side verification.

  Idempotent: NICs already connected to the target switch are skipped (reported as "already in place"), and the script can be run repeatedly.
.PARAMETER Phase
  Provisioning = temporary connectivity phase; Isolated = full isolation phase. Required.
.PARAMETER ProvisioningSwitch
  The name of the temporary switch to connect to in Phase 1 (your NAT/External switch).
  Only used with -Phase Provisioning; defaults to the placeholder name 'CafeSec-Provisioning'.
.PARAMETER WhatIf
  Only print the NIC switching actions that would be performed, without making any actual changes.
.EXAMPLE
  # Phase 1: connect to your already-built NAT switch to get online and install things
  .\Switch-LabNetwork.ps1 -Phase Provisioning -ProvisioningSwitch 'CafeSec-NAT'
.EXAMPLE
  # Phase 2: switch everything back to the isolated switch, then verify
  .\Switch-LabNetwork.ps1 -Phase Isolated
  .\04-Verify-Isolation.ps1
.NOTES
  Requires administrator. Only reads config\lab.psd1, following the Get-LabConfig convention from lib\Common.ps1.
  Connect-VMNetworkAdapter -SwitchName is used to reconnect a NIC to the specified switch (equivalent to the approach in README phase E).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Provisioning', 'Isolated')]
    [string]$Phase,

    # Name of the temporary connectivity switch (your NAT/External); only used in Phase 1.
    [string]$ProvisioningSwitch = 'CafeSec-Provisioning'
)

. "$PSScriptRoot\lib\Common.ps1"
Assert-Admin
$cfg = Get-LabConfig

$isolatedSwitch = $cfg.Network.SwitchName   # 'CafeSec-Isolated'

# ---- Resolve the target switch for this phase ----
if ($Phase -eq 'Isolated') {
    $targetSwitch = $isolatedSwitch
} else {
    $targetSwitch = $ProvisioningSwitch
}

Write-Step "Phase switch: -Phase $Phase  ->  target switch '$targetSwitch'"

# =====================================================================
# 1) Verify the target switch exists (never silently create an External switch)
# =====================================================================
$sw = Get-VMSwitch -Name $targetSwitch -ErrorAction SilentlyContinue
if (-not $sw) {
    if ($Phase -eq 'Isolated') {
        # The isolated switch missing = phase 02 has not been run yet; just point to the existing script, do not create it here.
        Write-Fail "Isolated switch '$targetSwitch' does not exist. Please run 02-New-IsolatedSwitch.ps1 first to create the Private switch."
        return
    }

    # Phase 1: temporary switch missing -- only print instructions, firmly refuse to create an External switch for the user (to avoid accidentally bridging a physical NIC).
    Write-Fail "Temporary connectivity switch '$targetSwitch' does not exist."
    Write-Warn2 "For isolation safety, this script will NOT automatically create an External/NAT switch for you (to avoid accidentally bridging a physical NIC and breaking the air gap)."
    Write-Host  ""
    Write-Host  "Please manually create one of the following as needed, then re-run this script specifying it with -ProvisioningSwitch:" -ForegroundColor Gray
    Write-Host  ""
    Write-Host  "  Option A -- Internal + NAT (recommended: temporary connectivity only while installing, controlled)" -ForegroundColor Gray
    Write-Host  "    New-VMSwitch -Name '$targetSwitch' -SwitchType Internal" -ForegroundColor Gray
    Write-Host  "    # Assign a gateway address to that vNIC on the host (example subnet 172.31.250.0/24, must not overlap the isolated subnet 10.10.10.0/24):" -ForegroundColor Gray
    Write-Host  "    New-NetIPAddress -IPAddress 172.31.250.1 -PrefixLength 24 -InterfaceAlias 'vEthernet ($targetSwitch)'" -ForegroundColor Gray
    Write-Host  "    New-NetNat -Name '${targetSwitch}-NAT' -InternalIPInterfaceAddressPrefix '172.31.250.0/24'" -ForegroundColor Gray
    Write-Host  "    # Inside the VM, configure manually: IP 172.31.250.x / mask 24 / gateway 172.31.250.1 / DNS your upstream (e.g. 1.1.1.1)" -ForegroundColor Gray
    Write-Host  ""
    Write-Host  "  Option B -- External (bridges a physical NIC, easiest but largest exposure; be sure to switch back to isolated when done)" -ForegroundColor Gray
    Write-Host  "    Get-NetAdapter | ft Name,InterfaceDescription,Status   # First confirm the name of the physical NIC to bridge" -ForegroundColor Gray
    Write-Host  "    New-VMSwitch -Name '$targetSwitch' -NetAdapterName '<your physical NIC name>' -AllowManagementOS `$true" -ForegroundColor Gray
    Write-Host  ""
    Write-Warn2 "Reminder: the temporary switch subnet must never overlap the isolated subnet $($cfg.Network.Subnet). After installing everything, be sure to immediately:"
    Write-Warn2 "  .\Switch-LabNetwork.ps1 -Phase Isolated   then   .\04-Verify-Isolation.ps1"
    return
}

# Phase 1 connecting to External gives an explicit safety warning (known to break isolation, for temporary connectivity only).
if ($Phase -eq 'Provisioning' -and $sw.SwitchType -eq 'External') {
    Write-Warn2 "Target '$targetSwitch' is an External switch: in this phase the VMs WILL have access to the real network/internet, for installing the OS and tools only."
    Write-Warn2 "When done, switch back to isolated immediately:  .\Switch-LabNetwork.ps1 -Phase Isolated"
}

# Safeguard: in Phase 1, if someone passes the isolated switch itself as the temporary switch, block it outright.
if ($Phase -eq 'Provisioning' -and $targetSwitch -eq $isolatedSwitch) {
    Write-Fail "You passed the isolated switch '$isolatedSwitch' as the temporary connectivity switch. The isolated switch cannot reach the network; please specify a real NAT/External switch."
    return
}

Write-Ok "Target switch '$targetSwitch' exists, type = $($sw.SwitchType)."

# =====================================================================
# 2) Switch NICs for each CSL VM (only the VMs in the config manifest)
# =====================================================================
$switched = 0    # number of NICs actually reconnected
$already  = 0    # number of NICs already in place and skipped
$missing  = 0    # number of VMs present in the config but not on the host

foreach ($vmDef in $cfg.VMs) {
    $vmName = $vmDef.Name
    Write-Step "VM: $vmName  [$($vmDef.Role)]"

    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Warn2 "${vmName}: this VM has not been created on the host yet, skipping (run 03-New-LabVMs.ps1 first)."
        $missing++
        continue
    }

    $adapters = @(Get-VMNetworkAdapter -VMName $vmName)
    if ($adapters.Count -eq 0) {
        Write-Warn2 "${vmName}: has no NICs, skipping."
        continue
    }

    foreach ($a in $adapters) {
        $current = if ([string]::IsNullOrEmpty($a.SwitchName)) { '<not connected>' } else { $a.SwitchName }

        if ($a.SwitchName -eq $targetSwitch) {
            Write-Ok "$vmName / NIC '$($a.Name)': already connected to '$targetSwitch', no change needed."
            $already++
            continue
        }

        if ($PSCmdlet.ShouldProcess("$vmName / NIC '$($a.Name)'", "reconnect from '$current' to '$targetSwitch'")) {
            # Connect-VMNetworkAdapter connects the NIC (regardless of which switch it was previously on, or none) directly to the target switch.
            Connect-VMNetworkAdapter -VMNetworkAdapter $a -SwitchName $targetSwitch
            Write-Ok "$vmName / NIC '$($a.Name)': '$current'  ->  '$targetSwitch'"
            $switched++
        }
    }
}

# =====================================================================
# 3) Summary + overview of current connection status
# =====================================================================
Write-Step "Switch summary"
Write-Host "  NICs reconnected: $switched   already in place: $already   VMs not created: $missing"

Write-Host ""
Get-VM | Where-Object Name -like 'CSL-*' | ForEach-Object {
    $vmName = $_.Name
    Get-VMNetworkAdapter -VMName $vmName | Select-Object `
        @{n = 'VM'; e = { $vmName } }, `
        @{n = 'Adapter'; e = { $_.Name } }, `
        @{n = 'Switch'; e = { if ([string]::IsNullOrEmpty($_.SwitchName)) { '<not connected>' } else { $_.SwitchName } } }, `
        @{n = 'State'; e = { $_.Status } }
} | Format-Table -AutoSize

# =====================================================================
# 4) Next-step guidance
# =====================================================================
if ($Phase -eq 'Isolated') {
    Write-Step "Now in [Phase 2: Full Isolation]"
    Write-Warn2 "Run the host-side isolation verification immediately:  .\04-Verify-Isolation.ps1"
    Write-Host  "Then run guest\Test-GuestIsolation.ps1 inside each Windows guest for guest-side verification." -ForegroundColor Gray
    Write-Host  "Only when both host-side and guest-side fully PASS is isolation compliant, after which research may proceed." -ForegroundColor Gray
} else {
    Write-Step "Now in [Phase 1: Temporary Connectivity (Provisioning)]"
    Write-Host  "You can now install the OS/patches/defensive tools and download rules inside each VM (see docs\downloads.md)." -ForegroundColor Gray
    Write-Warn2 "Once everything is installed, you MUST switch back to isolated:  .\Switch-LabNetwork.ps1 -Phase Isolated"
}
