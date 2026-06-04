#requires -Version 5.1
<#
.SYNOPSIS
  宿主侧隔离验证。确认隔离交换机配置正确、宿主无法触达隔离网段。
.DESCRIPTION
  这是"隔离是否真的生效"的宿主端证据。客户机内部的验证(ping 外网失败等)
  由 guest\Test-GuestIsolation.ps1 完成 —— 两边都过才算合规。
.NOTES
  只读,不做改动。建议在每次结构性变更后运行。
#>
[CmdletBinding()]
param()
. "$PSScriptRoot\lib\Common.ps1"
$cfg  = Get-LabConfig
$name = $cfg.Network.SwitchName
$fail = 0

Write-Step "宿主侧隔离验证: $name"

# 1) 交换机存在且为 Private
$sw = Get-VMSwitch -Name $name -ErrorAction SilentlyContinue
if (-not $sw) { Write-Fail "交换机 '$name' 不存在。"; return }
if ($sw.SwitchType -eq 'Private') { Write-Ok "交换机类型 = Private(VM-only,不通宿主、不通外网)" }
else { Write-Fail "交换机类型 = $($sw.SwitchType),应为 Private!"; $fail++ }

# 2) 交换机未绑定任何物理网卡(无外部上行链路)
if ([string]::IsNullOrEmpty($sw.NetAdapterInterfaceDescription)) {
    Write-Ok "交换机未绑定物理网卡(无外部上行链路 -> 出不了外网)"
} else {
    Write-Fail "交换机绑定了物理网卡: $($sw.NetAdapterInterfaceDescription) —— 存在外网通路!"; $fail++
}

# 3) 宿主机没有该交换机对应的 vEthernet 网卡
$hostNic = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like "*$name*" -or $_.Name -like "*$name*" }
if ($hostNic) { Write-Fail "宿主存在关联虚拟网卡 '$($hostNic.Name)' —— 宿主可能可达隔离网!"; $fail++ }
else { Write-Ok "宿主无该交换机的 vEthernet 网卡(宿主无法 ping 通隔离网内 VM)" }

# 4) 宿主在三层也到不了隔离网段:用 Find-NetRoute 做最长前缀匹配实测,
#    可捕获汇总/覆盖路由(如 10.0.0.0/8、10.10.0.0/16、/32),弥补精确字符串匹配的盲区。
# NB: $cfg.VMs items are hashtables — member access ($_.IP) reads the key, but
# Select-Object -ExpandProperty IP throws ("找不到属性 IP") because a Hashtable's
# keys are not surfaced as properties. Project the value with ForEach-Object instead.
$probeIp = ($cfg.VMs | Where-Object { $_.IP } | ForEach-Object { $_.IP } | Select-Object -First 1)
if (-not $probeIp) { $probeIp = '10.10.10.10' }
$nr = Find-NetRoute -RemoteIPAddress $probeIp -ErrorAction SilentlyContinue
# Find-NetRoute 同时返回路由对象与源 NetIPAddress 对象;后者无 DestinationPrefix。
# 必须先要求 DestinationPrefix 非空(否则该对象恒通过过滤 -> 永远误报 FAIL),
# 再排除默认路由的所有写法(含 /1 拆分默认路由)与回环。
# 过滤逻辑抽进 LabLogic\Select-IsolationLeakRoute(纯函数,见 tests\LabLogic.Tests.ps1)。
$reach = Select-IsolationLeakRoute -Route $nr
if ($reach) { Write-Fail "宿主存在通往 $probeIp 的具体路由($(($reach.DestinationPrefix) -join ', '))—— 三层可能可达隔离网!"; $fail++ }
else { Write-Ok "宿主无通往隔离网段的具体路由(三层到不了 $probeIp)" }

# 5) 所有 CSL VM 的网卡都接在隔离交换机上(没有"漏接"到别的网络)
Write-Step "VM 网卡连接核查"
foreach ($vm in $cfg.VMs) {
    $g = Get-VM -Name $vm.Name -ErrorAction SilentlyContinue
    if (-not $g) { Write-Warn2 "$($vm.Name): 尚未创建,跳过"; continue }
    $adapters = Get-VMNetworkAdapter -VMName $vm.Name
    foreach ($a in $adapters) {
        if ($a.SwitchName -eq $name) { Write-Ok "$($vm.Name): 网卡接在 '$name' [OK]" }
        elseif ([string]::IsNullOrEmpty($a.SwitchName)) { Write-Warn2 "$($vm.Name): 有未连接的网卡(可接受)" }
        else { Write-Fail "$($vm.Name): 网卡接到了 '$($a.SwitchName)' 而非隔离交换机!"; $fail++ }
    }
}

Write-Step "结论"
if ($fail -eq 0) {
    Write-Ok "宿主侧全部通过 —— 隔离前提成立。"
    Write-Host "请在任一 Windows 客户机内再运行 guest\Test-GuestIsolation.ps1 完成客户机侧验证。" -ForegroundColor Gray
} else {
    Write-Fail "发现 $fail 项问题。修复前【不要】在环境内进行任何研究活动。"
}
exit $fail
