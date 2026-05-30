#requires -Version 5.1
<#
.SYNOPSIS
  【在 Windows 客户机/服务器内部运行】客户机侧隔离验证。
  证明:能 ping 通同网段 VM,但【绝对】出不了外网、碰不到宿主真实局域网。
.DESCRIPTION
  期望结果:
    - 同隔离网内的其他 VM     -> 可达 (PASS)
    - 公网 IP (1.1.1.1/8.8.8.8) -> 不可达 (PASS = 出不去)
    - 公网域名 DNS 解析        -> 失败  (PASS)
    - 常见家用/企业网段网关    -> 不可达 (PASS)
    - 默认网关                 -> 不存在 (PASS)
  任何一项"本应失败却成功"都说明隔离破裂,立即停用环境排查。
.PARAMETER PeerIP
  同隔离网内另一台 VM 的 IP,用于正向连通性测试。默认 10.10.10.10 (Wazuh)。
.PARAMETER PublicProbeV4
  公网 IPv4 探测目标:刻意固定的公共 IP,用于证明【出口被阻断】(可达即隔离破裂)。默认 1.1.1.1 / 8.8.8.8。
.PARAMETER PublicProbeV6
  公网 IPv6 探测目标,同上。默认 Cloudflare 2606:4700:4700::1111。
#>
[CmdletBinding()]
param(
    [string]$PeerIP = '10.10.10.10',
    [string[]]$PublicProbeV4 = @('1.1.1.1', '8.8.8.8'),
    [string]$PublicProbeV6 = '2606:4700:4700::1111'
)

$pass = 0; $fail = 0
function Check {
    param([string]$Desc,[scriptblock]$Test,[bool]$Expect)
    $got = [bool](& $Test)
    if ($got -eq $Expect) { Write-Host "[PASS] $Desc" -ForegroundColor Green; $script:pass++ }
    else { Write-Host "[FAIL] $Desc  (期望=$Expect 实际=$got)" -ForegroundColor Red; $script:fail++ }
}

Write-Host "`n=== 客户机隔离验证 (本机: $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -like '10.10.10.*'}).IPAddress)) ===`n" -ForegroundColor Cyan

# 1) 正向(信息性):peer 可达性 —— 失败只 WARN,不计入隔离破口判定。
#    peer 可能未开机/未配 IP/丢 ICMP(Linux 防火墙常丢 ping),故 ICMP 失败时回退 TCP 探测。
#    这是全脚本唯一的"正向连通"证据,若误判为 FAIL 会让人误以为隔离坏了,所以与 $fail 解耦。
$peerOk = [bool](Test-Connection -ComputerName $PeerIP -Count 2 -Quiet)
if (-not $peerOk) {
    foreach ($p in 1514,1515,22,443) {
        if ((Test-NetConnection -ComputerName $PeerIP -Port $p -WarningAction SilentlyContinue).TcpTestSucceeded) { $peerOk = $true; break }
    }
}
if ($peerOk) { Write-Host "[PASS] 可达隔离网内 peer ($PeerIP) — VM 间连通已确认" -ForegroundColor Green; $pass++ }
else { Write-Host "[WARN] peer ($PeerIP) 不可达 — 可能未开机/未配 IP/丢 ICMP;VM<->VM 连通未确认,与隔离是否破裂无关" -ForegroundColor Yellow }

# 2) 反向:公网 IP 必须不可达(目标为刻意固定的公共 IP,见 -PublicProbeV4)
foreach ($ip in $PublicProbeV4) {
    Check "公网 $ip 不可达(出不了外网)" { Test-Connection -ComputerName $ip -Count 2 -Quiet } $false
}

# 3) 向公网 DNS 解析器(UDP/53)解析必须失败 —— 真实出口探测,而非"未配 DNS"的同义反复。
#    先清本地缓存并跳过 HOSTS,再强制把查询发往 1.1.1.1;否则缓存/HOSTS 命中会让"已解析"
#    在未发包的情况下假成功,从而把已隔离的机器误报为破裂。隔离网无路由到 1.1.1.1,应超时失败。
Check "向公网 DNS 解析器(1.1.1.1)解析失败(UDP/53 出不去)" {
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    try { Resolve-DnsName 'www.microsoft.com' -Server '1.1.1.1' -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Out-Null; $true }
    catch { $false }
} $false

# 4) 常见真实局域网网关不可达(确认碰不到宿主真实 LAN)
foreach ($gw in '192.168.1.1','192.168.0.1','192.168.31.1','10.0.0.1') {
    Check "真实 LAN 网关 $gw 不可达" { Test-Connection -ComputerName $gw -Count 1 -Quiet } $false
}

# 5) 本机不应存在默认网关(IPv4 0.0.0.0/0 或 IPv6 ::/0 路由)
Check "本机无默认网关(无 0.0.0.0/0 或 ::/0 路由)" {
    [bool](Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue) -or
    [bool](Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue)
} $false

# 5b) IPv6 也必须出不了网:全程只测 IPv4 会让 IPv6 通路被误判为已隔离(false PASS)。
Check "公网 IPv6 $PublicProbeV6 不可达" { Test-Connection -ComputerName $PublicProbeV6 -Count 2 -Quiet } $false
Check "无全局/ULA IPv6 地址(仅 fe80:: 链路本地可接受)" {
    [bool](Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike 'fe80:*' })
} $false

# 6) TCP 443 出站到公网应失败
Check "TCP 443 -> 公网失败" {
    (Test-NetConnection -ComputerName $PublicProbeV4[0] -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded
} $false

Write-Host "`n=== 结果: PASS=$pass  FAIL=$fail ===" -ForegroundColor Cyan
if ($fail -eq 0) {
    Write-Host "隔离已生效:此机连得到同网段 VM,但出不了外网、碰不到真实 LAN。合规。" -ForegroundColor Green
} else {
    Write-Host "隔离存在破口!立即停止任何研究活动并排查网卡/交换机配置。" -ForegroundColor Red
}
exit $fail
