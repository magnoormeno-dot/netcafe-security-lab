#requires -Version 5.1
<#
.SYNOPSIS
  【在每台 Windows 客户机/服务器内部运行】配置隔离网段静态 IP,刻意不设网关/DNS。
.DESCRIPTION
  隔离网内无 DHCP、无网关、无 DNS(这是设计)。不设默认网关本身就是一道隔离保险。
  Ubuntu(Wazuh)用 netplan 配置,见 scripts\wazuh\install-wazuh-manager.sh 顶部注释。
.PARAMETER IPAddress
  本机在 10.10.10.0/24 内的地址,例如 10.10.10.31
.EXAMPLE
  .\Set-StaticIP.ps1 -IPAddress 10.10.10.31
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$IPAddress,
    [int]$Prefix = 24,
    [string]$InterfaceAlias,   # 多网卡时显式指定隔离网卡,避免选错/漏掉正在外联的第二块
    [string]$DnsServer         # 域模式:域成员/域控 DNS 应指向域控(如 10.10.10.20);留空=不设 DNS(隔离默认)
)
$ErrorActionPreference = 'Stop'

# 选定目标网卡:显式指定优先;否则要求恰好只有一块 Up 物理网卡。
# 有歧义就报错(而非 -First 1 盲选)——否则可能配了隔离网卡却漏掉另一块仍在外联的网卡,
# 在那块网卡上保留默认网关与外网,Set-StaticIP 却报告"无网关",反而掩盖泄漏。
if ($InterfaceAlias) {
    $nic = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop
} else {
    $candidates = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
    if ($candidates.Count -eq 0) { throw '未找到 Up 状态的物理网卡。' }
    if ($candidates.Count -gt 1) {
        throw "检测到 $($candidates.Count) 块 Up 网卡:$($candidates.Name -join ', ')。请先移除多余网卡(Remove-VMNetworkAdapter),或用 -InterfaceAlias 指定隔离网卡。"
    }
    $nic = $candidates[0]
}
Write-Host "目标网卡: $($nic.Name) ($($nic.InterfaceDescription))"

# 清掉旧的 IP/网关/DNS,确保干净
Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceIndex $nic.ifIndex -ErrorAction SilentlyContinue |
    Where-Object DestinationPrefix -eq '0.0.0.0/0' |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

# 配静态 IP —— 注意:【不配 -DefaultGateway】,这是隔离的一部分
New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $IPAddress -PrefixLength $Prefix | Out-Null

# DNS:默认不设(隔离网无 DNS;VM 间用主机名请改 hosts 文件)。
# 域模式下传 -DnsServer <域控IP> 让本机指向内部 AD DNS(该 DNS 无转发器/根提示,仍气隙)。
if ($DnsServer) {
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $DnsServer
} else {
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ResetServerAddresses
}

# IPv6 加固:关闭路由器发现/无状态自动配置,避免意外获得 IPv6 默认路由
# (隔离不应仅依赖"恰好没有 IPv6 路由器")。
Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv6 -RouterDiscovery Disabled -ErrorAction SilentlyContinue
Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv6 -ManagedAddressConfiguration Disabled -OtherStatefulConfiguration Disabled -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

# 把"无默认网关"从口头声明变成系统级实测:任一接口若仍有默认路由(IPv4/IPv6),
# 多半是还有第二块网卡未切换/未移除 —— 直接报错,逼操作者先排查。
$stale = Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue
if ($stale) {
    throw "本机仍存在默认网关(可能有第二块网卡未切换/未移除):$(($stale | ForEach-Object { '{0} via {1}' -f $_.DestinationPrefix, $_.NextHop }) -join '; ')。请排查后重试。"
}

$dnsMsg = if ($DnsServer) { "DNS=$DnsServer" } else { "无 DNS" }
Write-Host "[ OK ] 已设置 $IPAddress/$Prefix,无默认网关,$dnsMsg,IPv6 自动配置已关闭。" -ForegroundColor Green
Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 | Format-Table IPAddress, PrefixLength

Write-Host "建议接着运行 Test-GuestIsolation.ps1 验证此机确实出不了网。" -ForegroundColor Gray
