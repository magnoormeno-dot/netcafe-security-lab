#requires -Version 5.1
<#
.SYNOPSIS
  【在每台 Windows 客户机 (CSL-Client01/02) 上运行】把本机加入 cafesec.lab 域。
  会先把 DNS 指向域控,然后加域并重启。
.DESCRIPTION
  加域前提:客户机的 DNS 必须能解析到域控(否则定位不到域)。隔离网无独立 DNS,
  因此本脚本把隔离网卡的 DNS 指向域控 CSL-Server(10.10.10.20,它运行 AD 集成 DNS)。
  这【不破坏气隙】:该 DNS 无转发器、无根提示(见 Set-DcDnsAirgap.ps1),只解析内部域;
  Test-GuestIsolation.ps1 仍强制向 1.1.1.1 探测、判定出口被阻断。
  加域后,WEF/Sysmon/审核策略即可由域 GPO(New-WefGpo.ps1)统一下发。
.PARAMETER DomainName
  目标域 FQDN,默认 cafesec.lab。
.PARAMETER DcIp
  域控 IP(同时是 DNS),默认 10.10.10.20。
.PARAMETER DomainCredential
  有加域权限的域账户(如 CAFESEC\Administrator)。必填,PSCredential。
.PARAMETER InterfaceAlias
  多网卡时显式指定隔离网卡。
.EXAMPLE
  $cred = Get-Credential CAFESEC\Administrator
  .\Join-LabDomain.ps1 -DomainCredential $cred
.NOTES
  需要管理员。加域成功后会【自动重启】。重启后用域账户登录。
#>
[CmdletBinding()]
param(
    [string]$DomainName = 'cafesec.lab',
    [string]$DcIp       = '10.10.10.20',
    [Parameter(Mandatory)][System.Management.Automation.PSCredential]$DomainCredential,
    [string]$InterfaceAlias
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\Common.ps1"
Assert-Admin

Write-Step "加入域: $DomainName(域控/DNS = $DcIp)"

# 选定隔离网卡(显式优先;否则要求恰好一块 Up 网卡)
if ($InterfaceAlias) {
    $nic = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop
} else {
    $candidates = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
    if ($candidates.Count -eq 0) { throw '未找到 Up 状态的物理网卡。' }
    if ($candidates.Count -gt 1) { throw "检测到 $($candidates.Count) 块 Up 网卡:$($candidates.Name -join ', ')。请用 -InterfaceAlias 指定隔离网卡。" }
    $nic = $candidates[0]
}

# 1) DNS 指向域控(否则定位不到域)
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $DcIp
Write-Ok "已将 $($nic.Name) 的 DNS 设为 $DcIp。"

# 2) 预检:能否解析到域
try {
    Resolve-DnsName -Name $DomainName -Server $DcIp -ErrorAction Stop | Out-Null
    Write-Ok "已能解析域 $DomainName。"
} catch {
    Write-Fail "无法通过 $DcIp 解析域 $DomainName。请确认域控已就绪(Install-DomainController.ps1 + Set-DcDnsAirgap.ps1)且网络互通。"
    return
}

# 3) 加域并重启
Write-Step "Add-Computer(将自动重启)"
Add-Computer -DomainName $DomainName -Credential $DomainCredential -Restart -Force
