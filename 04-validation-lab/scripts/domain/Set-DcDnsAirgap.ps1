#requires -Version 5.1
<#
.SYNOPSIS
  【在域控 CSL-Server 上,提升并重启后运行】把 AD DNS 锁成"只解析内部域、绝不向外递归",
  以在域环境下保持完全气隙(纵深防御)。
.DESCRIPTION
  域控的 DNS 默认带根提示(root hints),理论上会尝试向公网根服务器递归。本实验网络层本就
  无出口(私有交换机 + 无网关),这些查询只会失败;但为干净起见、且避免任何外联尝试,本脚本:
    * 删除所有 DNS 转发器(确保不会把查询转发到任何上游)。
    * 清空根提示(让 DNS 不再尝试外部递归)。
    * 关闭递归(可选,隔离网内只需解析本域记录)。
    * 校验:解析一个公网域名应当失败,解析本域 FQDN 应当成功。
  纯防御,不改变隔离拓扑,只收紧 DNS 行为。
.NOTES
  需要管理员,且本机已是域控(DNS 角色已就绪)。幂等,可重复运行。
#>
[CmdletBinding()]
param([string]$DomainName = 'cafesec.lab')
. "$PSScriptRoot\..\lib\Common.ps1"
Assert-Admin

Write-Step "锁定 AD DNS 为气隙模式(无转发、无根提示)"

if (-not (Get-Command Get-DnsServerForwarder -ErrorAction SilentlyContinue)) {
    Write-Fail "未找到 DNS Server 模块。请确认本机已是域控并安装了 DNS 角色。"; return
}

# 1) 删除所有转发器
$fwd = (Get-DnsServerForwarder -ErrorAction SilentlyContinue).IPAddress
if ($fwd) {
    foreach ($ip in $fwd) { Remove-DnsServerForwarder -IPAddress $ip -Force -ErrorAction SilentlyContinue }
    Write-Ok "已删除 DNS 转发器: $($fwd -join ', ')"
} else { Write-Ok "无 DNS 转发器(符合预期)。" }

# 2) 清空根提示,避免向公网根服务器递归。
#    注意:Remove-DnsServerRootHint 的两个参数集分别要求 -InputObject(管道)或 -NameServer;
#    裸调用 `-Force` 不绑定任何参数集 -> 静默失败/无操作(再被 SilentlyContinue 吞掉)。
#    必须把 Get 到的对象【管道】传入(文档化的"删全部"写法),并回查断言,避免假报成功。
$hints = Get-DnsServerRootHint -ErrorAction SilentlyContinue
if ($hints) {
    try { $hints | Remove-DnsServerRootHint -Force -ErrorAction Stop }
    catch { Write-Warn2 "清空根提示失败(非致命): $($_.Exception.Message)" }
    $remaining = Get-DnsServerRootHint -ErrorAction SilentlyContinue
    if (-not $remaining) { Write-Ok "已清空 DNS 根提示(root hints)。" }
    else { Write-Fail "根提示仍存在($(@($remaining).Count) 条),清空未生效。" }
} else { Write-Ok "无根提示(已清空)。" }

# 3) 关闭递归(隔离网内只解析本域;关闭可进一步减少外联尝试)
try {
    Set-DnsServerRecursion -Enable $false -ErrorAction Stop
    Write-Ok "已关闭 DNS 递归。"
} catch { Write-Warn2 "关闭递归失败(非致命): $($_.Exception.Message)" }

# 4) 校验
Write-Step "校验"
# 4a 本域应可解析
try {
    Resolve-DnsName -Name $DomainName -Server 127.0.0.1 -ErrorAction Stop | Out-Null
    Write-Ok "本域 $DomainName 可解析(内部 DNS 正常)。"
} catch { Write-Warn2 "本域 $DomainName 解析失败,请检查 AD DNS 区域。" }

# 4b 公网域名应解析失败(气隙)
$ext = $false
try { Resolve-DnsName -Name 'www.microsoft.com' -Server 127.0.0.1 -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; $ext = $true } catch { $ext = $false }
if ($ext) { Write-Fail "公网域名竟然解析成功!请检查是否仍有转发器/根提示。" }
else { Write-Ok "公网域名解析失败(气隙保持)。" }

Write-Step "完成。下一步: ..\guest\Configure-WEC-Collector.ps1(配 WEF 收集器)"
