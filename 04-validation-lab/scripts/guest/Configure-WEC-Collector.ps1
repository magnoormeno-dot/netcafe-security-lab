#requires -Version 5.1
<#
.SYNOPSIS
  【在 CSL-Server (10.10.10.20) 上运行】把这台服务器配置为 Windows 事件收集器 (WEC)。
.DESCRIPTION
  WEF = Windows Event Forwarding。客户机(WEF source)把关键安全事件
  推送到本收集器,集中存档。这是纯防御的日志汇聚机制,与 Wazuh 互补:
  WEF 走原生 WinRM,无需第三方 agent。
  本脚本:启用 WinRM、初始化收集器服务、导入源发起型(source-initiated)订阅。
  【域模式】本机已是域控 cafesec.lab 的成员/域控,源发起型 WEF 走 Kerberos(HTTP/5985),
  无需证书。源端配置由 ..\domain\New-WefGpo.ps1 经 GPO 下发(或各机手动跑 Configure-WEF-Source.ps1)。
.PARAMETER SubscriptionXml
  订阅定义 XML 路径,默认指向项目内 config\wef\cafesec-subscription.xml。
#>
[CmdletBinding()]
param(
    [string]$SubscriptionXml = "$PSScriptRoot\..\..\config\wef\cafesec-subscription.xml"
)
$ErrorActionPreference = 'Stop'
function Test-Admin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not (Test-Admin)) { throw "需要管理员权限。" }

Write-Host "=== 配置 Windows 事件收集器 (WEC) ===" -ForegroundColor Cyan

# 1) WinRM(收集器需要监听以接收推送)
Write-Host "启用 WinRM..." -ForegroundColor Cyan
winrm quickconfig -quiet

# 2) 初始化 Windows Event Collector 服务(幂等)
Write-Host "初始化 wecutil 收集器服务..." -ForegroundColor Cyan
wecutil qc /q

Set-Service -Name Wecsvc -StartupType Automatic
Start-Service -Name Wecsvc -ErrorAction SilentlyContinue

# 3) 导入订阅
if (Test-Path $SubscriptionXml) {
    $resolved = (Resolve-Path $SubscriptionXml).Path
    Write-Host "导入订阅: $resolved" -ForegroundColor Cyan
    # 已存在则先删后建,保证幂等。
    # 注意:PS 5.1 下对原生命令做 2>$null,会把每行 stderr 包成 NativeCommandError;
    # 在 $ErrorActionPreference='Stop' 下这是【终止性】错误 —— 首次运行(订阅尚不存在)时
    # wecutil gs 会向 stderr 报"不存在",从而抛异常、在导入订阅【之前】中断脚本。
    # 故用局部 Continue 作用域 + $LASTEXITCODE 判定是否已存在,绝不让重定向冒泡成异常。
    $subName = ([xml](Get-Content $resolved)).Subscription.SubscriptionId
    $exists = $false
    if ($subName) {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & wecutil gs $subName 1>$null 2>$null
        $exists = ($LASTEXITCODE -eq 0)
        $ErrorActionPreference = $prevEAP
    }
    if ($exists) { wecutil ds $subName }
    wecutil cs $resolved
    Write-Host "[ OK ] 订阅已导入。" -ForegroundColor Green
    wecutil es
} else {
    Write-Host "[WARN] 找不到订阅 XML: $SubscriptionXml" -ForegroundColor Yellow
}

Write-Host "`n收集器就绪。转发来的事件落在日志: 'Forwarded Events' (ForwardedEvents)。" -ForegroundColor Gray
Write-Host "源端配置(二选一):" -ForegroundColor Gray
Write-Host "  * 推荐:在域控运行 ..\domain\New-WefGpo.ps1 经 GPO 给全体客户机下发 SubscriptionManager。" -ForegroundColor Gray
Write-Host "  * 或:在每台客户机手动运行 Configure-WEF-Source.ps1 -CollectorFqdn CSL-Server.cafesec.lab" -ForegroundColor Gray
Write-Host "用 'wecutil gr CafeSec-Security' 查看各源是否 Active。" -ForegroundColor Gray
