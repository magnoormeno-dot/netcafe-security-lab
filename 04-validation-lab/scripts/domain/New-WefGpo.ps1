#requires -Version 5.1
<#
.SYNOPSIS
  【在域控 CSL-Server 上运行】创建并下发一个 GPO,把客户机配置成 WEF 事件源:
  设置 SubscriptionManager(指向收集器)+ 启用 WinRM 远程管理策略,并链接到域。
.DESCRIPTION
  对应第五步要求的"GPO 配置要点"。本脚本用 GroupPolicy 模块完成【可脚本化】的高置信部分:
    1) 注册表策略:Configure target Subscription Manager
       HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
       值 "1" = Server=http://<收集器FQDN>:5985/wsman/SubscriptionManager/WEC,Refresh=<秒>
       —— 域内走 Kerberos,无需证书/IssuerCA(这正是建域的目的)。
    2) 注册表策略:Allow remote server management through WinRM
       HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service  AllowAutoConfig=1 / IPv4Filter=* / IPv6Filter=*
       —— 配置 WinRM 监听器自动配置(AllowAutoConfig)+ 把服务启动类型设为自动(次次重启生效);
          注意:这不会立刻启动当前会话的 WinRM 服务,需单独保证(见下方"需手工补充")。
    3) 把 GPO 链接到域根(可按需改为链接到某 OU 以缩小范围)。

  【需手工/用 GPP 补充的三项】(无法仅靠 Set-GPRegistryValue 完整表达,见 docs\03-domain-and-wef.md):
    * 确保源端 WinRM 服务【正在运行】:本脚本已把启动类型策略设为自动(次次重启后生效),
      但不会立刻启动当前会话的服务。要立刻生效,在各源机跑 ..\guest\Configure-WEF-Source.ps1
      (含 winrm quickconfig + 重启服务),或用 GPP "服务" 设为 自动 + 启动。
    * 把 NT AUTHORITY\NETWORK SERVICE 加入各源机本地 "Event Log Readers"
      (转发 Security 日志所需)—— 用 GPP "本地用户和组",或在各机跑 ..\guest\Configure-WEF-Source.ps1。
    * 高级审核策略(4688 进程创建含命令行、登录事件等)—— 见文档给出的 GUI 路径。
.PARAMETER CollectorFqdn
  WEF 收集器(= 域控)的 FQDN,必须与其 Kerberos 名称一致。默认 CSL-Server.cafesec.lab。
.PARAMETER RefreshSeconds
  源端拉取订阅配置的间隔秒数。默认 60。
.PARAMETER GpoName
  GPO 名称,默认 'CafeSec-WEF-Source'。
.PARAMETER TargetOU
  GPO 链接目标的可分辨名(DN)。默认域根(由域 FQDN 推导)。
.EXAMPLE
  .\New-WefGpo.ps1
.EXAMPLE
  .\New-WefGpo.ps1 -CollectorFqdn CSL-Server.cafesec.lab -RefreshSeconds 60
.NOTES
  需要管理员且在域控上运行(需 GroupPolicy 模块,随 RSAT/AD DS 安装)。幂等:GPO 已存在则更新其值。
#>
[CmdletBinding()]
param(
    [string]$CollectorFqdn  = 'CSL-Server.cafesec.lab',
    [int]   $RefreshSeconds = 60,
    [string]$GpoName        = 'CafeSec-WEF-Source',
    [string]$TargetOU
)
. "$PSScriptRoot\..\lib\Common.ps1"
Assert-Admin

if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    Write-Fail "未找到 GroupPolicy 模块。请在域控上运行(AD DS/RSAT 会带该模块)。"; return
}
Import-Module GroupPolicy -ErrorAction Stop

# 推导域根 DN(若未显式指定 -TargetOU)
if (-not $TargetOU) {
    try { $TargetOU = (Get-ADDomain -ErrorAction Stop).DistinguishedName }
    catch {
        # 退化:从计算机的 DNS 域名拼 DN
        $dns = (Get-CimInstance Win32_ComputerSystem).Domain
        if (-not $dns) { Write-Fail "无法确定域 DN,请用 -TargetOU 指定。"; return }
        $TargetOU = ($dns.Split('.') | ForEach-Object { "DC=$_" }) -join ','
    }
}

Write-Step "创建/更新 GPO: $GpoName"
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) { $gpo = New-GPO -Name $GpoName -Comment 'CafeSec Lab: 配置 WEF 事件源(SubscriptionManager + WinRM)'; Write-Ok "已创建 GPO '$GpoName'。" }
else { Write-Ok "GPO '$GpoName' 已存在,更新其设置。" }

# 1) SubscriptionManager(源发起型,Kerberos/HTTP/5985)
$subValue = "Server=http://$CollectorFqdn`:5985/wsman/SubscriptionManager/WEC,Refresh=$RefreshSeconds"
$subKey   = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
Set-GPRegistryValue -Name $GpoName -Key $subKey -ValueName '1' -Type String -Value $subValue | Out-Null
Write-Ok "SubscriptionManager = $subValue"

# 2) Allow remote server management through WinRM(允许 WinRM 运行时自动配置监听器)
#    注意:这只是"允许自动配置监听器"的策略,本身【不会启动】WinRM 服务。
$winrmKey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
Set-GPRegistryValue -Name $GpoName -Key $winrmKey -ValueName 'AllowAutoConfig' -Type DWord  -Value 1   | Out-Null
Set-GPRegistryValue -Name $GpoName -Key $winrmKey -ValueName 'IPv4Filter'      -Type String -Value '*' | Out-Null
Set-GPRegistryValue -Name $GpoName -Key $winrmKey -ValueName 'IPv6Filter'      -Type String -Value '*' | Out-Null
Write-Ok "已配置 WinRM 监听器自动配置策略(AllowAutoConfig=1)。"

# 2b) 把 WinRM 服务启动类型设为【自动】。Win11 桌面版默认 WinRM=手动(触发启动),
#     仅靠 AllowAutoConfig 不会让服务运行;源发起型 WEF 需要 WinRM 服务实际在跑。
#     用注册表策略把服务 Start 设为 2(自动)—— 客户机【下次重启后】生效
#     (加域本身会重启一次)。注意:这【不会立刻启动】当前会话的服务,见结尾"仍需补充"。
$winrmSvcKey = 'HKLM\SYSTEM\CurrentControlSet\Services\WinRM'
Set-GPRegistryValue -Name $GpoName -Key $winrmSvcKey -ValueName 'Start' -Type DWord -Value 2 | Out-Null
Write-Ok "已把 WinRM 服务启动类型策略设为 自动(次次重启生效)。"

# 3) 链接到目标(域根或指定 OU)
$linked = (Get-GPInheritance -Target $TargetOU -ErrorAction SilentlyContinue).GpoLinks | Where-Object DisplayName -eq $GpoName
if (-not $linked) {
    New-GPLink -Name $GpoName -Target $TargetOU -LinkEnabled Yes | Out-Null
    Write-Ok "已将 GPO 链接到 $TargetOU"
} else { Write-Ok "GPO 已链接到 $TargetOU(跳过)。" }

Write-Step "GPO 下发完成"
Write-Host "在客户机 'gpupdate /force' 后,【且 WinRM 服务已运行】,源端才会向 $CollectorFqdn 推送事件。" -ForegroundColor Gray
Write-Host "仍需补充(见 docs\03-domain-and-wef.md):" -ForegroundColor Yellow
Write-Host "  * WinRM 服务需正在运行:本 GPO 已设其为自动(次次重启生效);要立刻生效在各源机跑 ..\guest\Configure-WEF-Source.ps1。" -ForegroundColor Yellow
Write-Host "  * 把 NETWORK SERVICE 加入各源机 'Event Log Readers'(转发 Security 日志所需)。" -ForegroundColor Yellow
Write-Host "  * 高级审核策略(4688 含命令行 / 登录事件等)。" -ForegroundColor Yellow
Write-Host "收集器侧请确认已运行 ..\guest\Configure-WEC-Collector.ps1 并导入订阅。" -ForegroundColor Gray
