#requires -Version 5.1
<#
.SYNOPSIS
  在【两阶段搭建】之间安全地切换所有 CSL-* 虚拟机的网卡连接。
.DESCRIPTION
  对应 docs\02-network-isolation.md 的两阶段模型:

    阶段一 Provisioning(临时联网):把每台 CSL VM 的网卡接到一个临时
        交换机(NAT/External,由你预先建好),用于装 OS / 打补丁 / 装防御工具 / 下载规则。
    阶段二 Isolated(完全隔离):把每台 CSL VM 的网卡改接回 CafeSec-Isolated(Private),
        之后才允许进行任何研究活动。

  本脚本只动 config\lab.psd1 里列出的 CSL VM 的网卡的 SwitchName,
  【不】创建、删除或修改任何交换机本身,【不】触碰任何非 CSL 虚拟机。

  -Phase Provisioning:
      把每台 CSL VM 网卡接到 -ProvisioningSwitch 指定的临时交换机。
      该交换机【必须事先存在】。若不存在,脚本只给出创建说明并中止——
      【绝不】静默替你创建 External 交换机(那会桥接物理网卡、打破气隙)。

  -Phase Isolated:
      把每台 CSL VM 网卡改接回 CafeSec-Isolated(读自配置 Network.SwitchName)。
      完成后提醒你运行 04-Verify-Isolation.ps1 做宿主侧验证。

  幂等:已经接在目标交换机上的网卡会被跳过(报告"已就位"),可反复运行。
.PARAMETER Phase
  Provisioning = 临时联网阶段;Isolated = 完全隔离阶段。必填。
.PARAMETER ProvisioningSwitch
  阶段一要接入的临时交换机名(你的 NAT/External 交换机)。
  仅在 -Phase Provisioning 时使用;默认占位名 'CafeSec-Provisioning'。
.PARAMETER WhatIf
  只打印将要执行的网卡切换动作,不实际改动。
.EXAMPLE
  # 阶段一:接到你已建好的 NAT 交换机联网装东西
  .\Switch-LabNetwork.ps1 -Phase Provisioning -ProvisioningSwitch 'CafeSec-NAT'
.EXAMPLE
  # 阶段二:全部切回隔离交换机,然后验证
  .\Switch-LabNetwork.ps1 -Phase Isolated
  .\04-Verify-Isolation.ps1
.NOTES
  需要管理员。只读取 config\lab.psd1,沿用 lib\Common.ps1 的 Get-LabConfig 约定。
  Connect-VMNetworkAdapter -SwitchName 用于把网卡改接到指定交换机(等同 README 阶段 E 的做法)。
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Provisioning', 'Isolated')]
    [string]$Phase,

    # 临时联网交换机名(你的 NAT/External);仅阶段一使用。
    [string]$ProvisioningSwitch = 'CafeSec-Provisioning'
)

. "$PSScriptRoot\lib\Common.ps1"
Assert-Admin
$cfg = Get-LabConfig

$isolatedSwitch = $cfg.Network.SwitchName   # 'CafeSec-Isolated'

# ---- 解析本阶段的目标交换机 ----
if ($Phase -eq 'Isolated') {
    $targetSwitch = $isolatedSwitch
} else {
    $targetSwitch = $ProvisioningSwitch
}

Write-Step "阶段切换: -Phase $Phase  ->  目标交换机 '$targetSwitch'"

# =====================================================================
# 1) 校验目标交换机存在(绝不静默创建 External 交换机)
# =====================================================================
$sw = Get-VMSwitch -Name $targetSwitch -ErrorAction SilentlyContinue
if (-not $sw) {
    if ($Phase -eq 'Isolated') {
        # 隔离交换机不存在 = 还没跑过 02;指向已有脚本即可,不在此处自行创建。
        Write-Fail "隔离交换机 '$targetSwitch' 不存在。请先运行 02-New-IsolatedSwitch.ps1 创建 Private 交换机。"
        return
    }

    # 阶段一:临时交换机缺失 —— 只给说明,坚决不替用户建 External(避免误桥接物理网卡)。
    Write-Fail "临时联网交换机 '$targetSwitch' 不存在。"
    Write-Warn2 "出于隔离安全,本脚本【不会】替你自动创建 External/NAT 交换机(以免误桥接物理网卡、打破气隙)。"
    Write-Host  ""
    Write-Host  "请按需手动创建其中一种,再用 -ProvisioningSwitch 指定它重跑本脚本:" -ForegroundColor Gray
    Write-Host  ""
    Write-Host  "  方案 A —— Internal + NAT(推荐:仅在装东西时临时联网,可控)" -ForegroundColor Gray
    Write-Host  "    New-VMSwitch -Name '$targetSwitch' -SwitchType Internal" -ForegroundColor Gray
    Write-Host  "    # 给宿主上的该 vNIC 配一个网关地址(示例网段 172.31.250.0/24,勿与隔离段 10.10.10.0/24 重叠):" -ForegroundColor Gray
    Write-Host  "    New-NetIPAddress -IPAddress 172.31.250.1 -PrefixLength 24 -InterfaceAlias 'vEthernet ($targetSwitch)'" -ForegroundColor Gray
    Write-Host  "    New-NetNat -Name '${targetSwitch}-NAT' -InternalIPInterfaceAddressPrefix '172.31.250.0/24'" -ForegroundColor Gray
    Write-Host  "    # VM 内手动配:IP 172.31.250.x / 掩码 24 / 网关 172.31.250.1 / DNS 你的上游(如 1.1.1.1)" -ForegroundColor Gray
    Write-Host  ""
    Write-Host  "  方案 B —— External(桥接物理网卡,最省事但暴露面最大;装完务必切回隔离)" -ForegroundColor Gray
    Write-Host  "    Get-NetAdapter | ft Name,InterfaceDescription,Status   # 先确认要桥接的物理网卡名" -ForegroundColor Gray
    Write-Host  "    New-VMSwitch -Name '$targetSwitch' -NetAdapterName '<你的物理网卡名>' -AllowManagementOS `$true" -ForegroundColor Gray
    Write-Host  ""
    Write-Warn2 "提醒:临时交换机网段切勿与隔离网段 $($cfg.Network.Subnet) 重叠。装完所有东西后,务必立即:"
    Write-Warn2 "  .\Switch-LabNetwork.ps1 -Phase Isolated   再   .\04-Verify-Isolation.ps1"
    return
}

# 阶段一接入 External 时给出明确安全提示(已知会打破隔离,仅供临时联网)。
if ($Phase -eq 'Provisioning' -and $sw.SwitchType -eq 'External') {
    Write-Warn2 "目标 '$targetSwitch' 是 External 交换机:此阶段 VM 将【能访问真实网络/外网】,仅用于装系统与工具。"
    Write-Warn2 "完成后请立即切回隔离:  .\Switch-LabNetwork.ps1 -Phase Isolated"
}

# 防呆:阶段一若有人把隔离交换机本身当临时交换机传进来,直接拦下。
if ($Phase -eq 'Provisioning' -and $targetSwitch -eq $isolatedSwitch) {
    Write-Fail "你把隔离交换机 '$isolatedSwitch' 当成临时联网交换机了。隔离交换机无法联网,请指定真正的 NAT/External 交换机。"
    return
}

Write-Ok "目标交换机 '$targetSwitch' 存在,类型 = $($sw.SwitchType)。"

# =====================================================================
# 2) 逐台 CSL VM 切换网卡(只动配置清单里的 VM)
# =====================================================================
$switched = 0    # 实际改接的网卡数
$already  = 0    # 已就位、跳过的网卡数
$missing  = 0    # 配置里有但宿主上没有的 VM 数

foreach ($vmDef in $cfg.VMs) {
    $vmName = $vmDef.Name
    Write-Step "VM: $vmName  [$($vmDef.Role)]"

    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Warn2 "${vmName}: 宿主上尚未创建此 VM,跳过(先跑 03-New-LabVMs.ps1)。"
        $missing++
        continue
    }

    $adapters = @(Get-VMNetworkAdapter -VMName $vmName)
    if ($adapters.Count -eq 0) {
        Write-Warn2 "${vmName}: 没有任何网卡,跳过。"
        continue
    }

    foreach ($a in $adapters) {
        $current = if ([string]::IsNullOrEmpty($a.SwitchName)) { '<未连接>' } else { $a.SwitchName }

        if ($a.SwitchName -eq $targetSwitch) {
            Write-Ok "$vmName / 网卡 '$($a.Name)': 已接在 '$targetSwitch',无需改动。"
            $already++
            continue
        }

        if ($PSCmdlet.ShouldProcess("$vmName / 网卡 '$($a.Name)'", "从 '$current' 改接到 '$targetSwitch'")) {
            # Connect-VMNetworkAdapter 会把网卡(无论原先连着哪个交换机或未连)直接接到目标交换机。
            Connect-VMNetworkAdapter -VMNetworkAdapter $a -SwitchName $targetSwitch
            Write-Ok "$vmName / 网卡 '$($a.Name)': '$current'  ->  '$targetSwitch'"
            $switched++
        }
    }
}

# =====================================================================
# 3) 汇总 + 当前连接状态一览
# =====================================================================
Write-Step "切换汇总"
Write-Host "  改接网卡: $switched   已就位: $already   未创建的 VM: $missing"

Write-Host ""
Get-VM | Where-Object Name -like 'CSL-*' | ForEach-Object {
    $vmName = $_.Name
    Get-VMNetworkAdapter -VMName $vmName | Select-Object `
        @{n = 'VM'; e = { $vmName } }, `
        @{n = 'Adapter'; e = { $_.Name } }, `
        @{n = 'Switch'; e = { if ([string]::IsNullOrEmpty($_.SwitchName)) { '<未连接>' } else { $_.SwitchName } } }, `
        @{n = 'State'; e = { $_.Status } }
} | Format-Table -AutoSize

# =====================================================================
# 4) 下一步提示
# =====================================================================
if ($Phase -eq 'Isolated') {
    Write-Step "已进入【阶段二:完全隔离】"
    Write-Warn2 "请立即运行宿主侧隔离验证:  .\04-Verify-Isolation.ps1"
    Write-Host  "随后在各 Windows 客户机内运行 guest\Test-GuestIsolation.ps1 做客户机侧验证。" -ForegroundColor Gray
    Write-Host  "宿主侧 + 客户机侧两边全 PASS 才算隔离合规,之后方可进行研究。" -ForegroundColor Gray
} else {
    Write-Step "已进入【阶段一:临时联网(Provisioning)】"
    Write-Host  "现在可在各 VM 内装系统/补丁/防御工具、下载规则(见 docs\downloads.md)。" -ForegroundColor Gray
    Write-Warn2 "全部装好后【务必】切回隔离:  .\Switch-LabNetwork.ps1 -Phase Isolated"
}
