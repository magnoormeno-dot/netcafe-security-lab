#requires -Version 5.1
<#
.SYNOPSIS
  创建完全隔离的 Hyper-V 私有(Private)虚拟交换机。这是整个环境合规的根本。
.DESCRIPTION
  为什么用 Private 而不是 Internal:
    - Private  : 仅 VM <-> VM 互通。宿主机【不会】获得 vEthernet 虚拟网卡,
                 因此宿主在网络栈层面根本不存在通往该网段的接口 —— 最强隔离。
    - Internal : VM <-> VM 且 VM <-> 宿主。宿主会多一块 vEthernet 网卡(能 ping VM)。
    - External : 桥接物理网卡,能上外网。【本实验严禁使用。】
  对应你原计划里的 VirtualBox "Internal Network"(VM-only,不碰宿主),
  Hyper-V 的等价且更严格选项就是 Private。
.NOTES
  需要管理员。脚本幂等:同名交换机已存在则校验其类型而不重建。
#>
[CmdletBinding()]
param()
. "$PSScriptRoot\lib\Common.ps1"
Assert-Admin
$cfg = Get-LabConfig
$name = $cfg.Network.SwitchName

Write-Step "创建隔离私有交换机: $name ($($cfg.Network.Subnet))"

$existing = Get-VMSwitch -Name $name -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.SwitchType -eq 'Private') {
        Write-Ok "交换机 '$name' 已存在且为 Private 类型。"
    } else {
        Write-Fail "交换机 '$name' 已存在但类型为 $($existing.SwitchType)(非 Private)!"
        Write-Fail "这会破坏隔离。请先删除: Remove-VMSwitch -Name '$name' -Force,再重跑本脚本。"
        return
    }
} else {
    New-VMSwitch -Name $name -SwitchType Private | Out-Null
    Write-Ok "已创建 Private 交换机 '$name'。"
}

# --- 立即自检:确认宿主机没有因此获得通往隔离网段的虚拟网卡 ---
Write-Step "自检:确认宿主未暴露在隔离网段"
$hostAdapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$name*" -or $_.InterfaceDescription -like "*$name*" }
if ($hostAdapter) {
    Write-Fail "宿主出现了与该交换机关联的虚拟网卡: $($hostAdapter.Name)"
    Write-Fail "Private 交换机不应产生宿主 vNIC —— 请核查交换机类型!"
} else {
    Write-Ok "宿主机【无】对应该交换机的 vEthernet 网卡 —— 隔离前提成立。"
    Write-Ok "即:宿主在网络层无法 ping 通隔离网内任何 VM。"
}

Write-Host ""
Get-VMSwitch -Name $name | Format-Table Name, SwitchType, AllowManagementOS -AutoSize
Write-Step "下一步: 03-New-LabVMs.ps1  (创建 4 台 VM 并接入此交换机)"
