#requires -Version 5.1
<#
.SYNOPSIS
  【在每台 Windows 客户机 (10.10.10.31/32) 上运行】把本机配置为 WEF 事件源,
  推送关键安全事件到收集器 CSL-Server。
.DESCRIPTION
  源发起型(source-initiated)订阅:客户机定期联系收集器拉取订阅并推送事件。
  需要:WinRM 启用 + 配置 SubscriptionManager 指向收集器 + 网络服务账户有读日志权限。
  纯防御配置,不改变任何业务行为。
  【域模式】本机已加入 cafesec.lab,WEF 走 Kerberos(HTTP/5985),无需证书。
  本脚本是【手动逐机】配置方式;推荐改用域控上的 ..\domain\New-WefGpo.ps1 经 GPO 统一下发。
  关键:Kerberos 必须用收集器的【FQDN】(匹配其 SPN),不能用裸 IP。
.PARAMETER CollectorFqdn
  收集器(= 域控)FQDN,默认 CSL-Server.cafesec.lab。客户机已加域、DNS 指向域控,可解析它。
#>
[CmdletBinding()]
param(
    [string]$CollectorFqdn = 'CSL-Server.cafesec.lab'
)
$ErrorActionPreference = 'Stop'
function Test-Admin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not (Test-Admin)) { throw "需要管理员权限。" }

Write-Host "=== 配置 WEF 事件源 -> 收集器 $CollectorFqdn ===" -ForegroundColor Cyan

# 1) 启用 WinRM(源端也需要 WinRM 服务运行)
winrm quickconfig -quiet

# 2) 配置 SubscriptionManager(源发起型)。5985 = WinRM HTTP;域内走 Kerberos。
#    Refresh=60 秒拉取一次订阅配置。用 FQDN(非 IP)以匹配收集器 Kerberos SPN。
$server = "Server=http://$CollectorFqdn`:5985/wsman/SubscriptionManager/WEC,Refresh=60"
$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name '1' -Value $server
Write-Host "[ OK ] SubscriptionManager = $server" -ForegroundColor Green

# 3) 让 NETWORK SERVICE 账户能读安全日志(转发安全事件所需)
#    把 NETWORK SERVICE 加入 'Event Log Readers' 本地组。
try {
    $grp = [ADSI]"WinNT://./Event Log Readers,group"
    $grp.Add("WinNT://NT AUTHORITY/NETWORK SERVICE")
    Write-Host "[ OK ] 已将 NETWORK SERVICE 加入 'Event Log Readers'。" -ForegroundColor Green
} catch {
    if ($_.Exception.Message -match 'already a member|已经是') { Write-Host "[ OK ] NETWORK SERVICE 已在 Event Log Readers 中。" -ForegroundColor Green }
    else { Write-Host "[WARN] 加入 Event Log Readers 失败: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# 4) 重启 WinRM 让配置生效
Restart-Service WinRM

Write-Host "`n在收集器上用 'wecutil gr CafeSec-Security' 查看本源的运行状态(应出现本机)。" -ForegroundColor Gray
Write-Host "排错: 在源端运行 eventvwr -> 应用程序和服务日志\Microsoft\Windows\Eventlog-ForwardingPlugin\Operational" -ForegroundColor Gray
