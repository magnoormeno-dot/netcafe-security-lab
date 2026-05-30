#requires -Version 5.1
<#
.SYNOPSIS
  【在 CSL-Server (10.10.10.20) 上运行】把本机提升为新林 cafesec.lab 的首个域控制器(DC),
  并安装 AD 集成 DNS。完成后自动重启。
.DESCRIPTION
  为什么要域:工作组(非域)机器间的【源发起型 WEF 走 Kerberos 无法工作】。建立域后:
    * WEF 源 -> 收集器走 Kerberos(HTTP/5985)原生生效,无需证书。
    * Sysmon / 审核策略 / WEF 订阅可由 GPO 统一下发(对应第五步的 GPO 要求)。

  气隙保持:DC 会运行 AD 集成 DNS,仅解析内部域 cafesec.lab。
  本脚本【不】配置任何 DNS 转发器;提升并重启后,再运行 Set-DcDnsAirgap.ps1
  清空根提示(root hints),确保 DNS 绝不尝试向外递归 —— 网络层本就无出口,这是纵深防御。

  前置条件(务必先满足):
    * 本机已设静态 IP 10.10.10.20/24、无默认网关(guest\Set-StaticIP.ps1)。
    * 本机【主机名】已改为 CSL-Server 并重启过一次(域控提升前应先定好计算机名)。
    * 本机的首选 DNS 指向自身(脚本会自动设为 127.0.0.1)。
.PARAMETER DomainName
  新林的 FQDN,默认 cafesec.lab(纯内部域,不与任何真实域冲突)。
.PARAMETER NetbiosName
  NetBIOS 域名,默认 CAFESEC。
.PARAMETER SafeModePassword
  DSRM(目录服务还原模式)管理员密码。必填,SecureString。请妥善保存。
.EXAMPLE
  $dsrm = Read-Host -AsSecureString "设置 DSRM 密码"
  .\Install-DomainController.ps1 -SafeModePassword $dsrm
.NOTES
  需要管理员。提升过程会【自动重启】。重启后:
    1) 运行 Set-DcDnsAirgap.ps1(清根提示/确认无转发器)。
    2) 运行 ..\guest\Configure-WEC-Collector.ps1(配置 WEF 收集器)。
    3) 运行 New-WefGpo.ps1(下发 WEF/审核策略 GPO)。
  Windows Server 评估版可正常充当 DC。
#>
[CmdletBinding()]
param(
    [string]$DomainName  = 'cafesec.lab',
    [string]$NetbiosName = 'CAFESEC',
    [Parameter(Mandatory)][System.Security.SecureString]$SafeModePassword,
    [string]$InterfaceAlias    # 多网卡时显式指定隔离网卡
)
. "$PSScriptRoot\..\lib\Common.ps1"
Assert-Admin

Write-Step "提升为域控制器: 新林 $DomainName ($NetbiosName)"

# 0) 校验静态 IP(域控必须固定为 10.10.10.20;其它脚本都硬编码该地址)。不满足直接中止,避免装错地址。
$ipOk = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object IPAddress -eq '10.10.10.20'
if (-not $ipOk) { Write-Fail "未检测到本机 IPv4 = 10.10.10.20。请先运行 guest\Set-StaticIP.ps1 -IPAddress 10.10.10.20 -DnsServer 127.0.0.1 后重试。"; return }

# 1) 首选 DNS 指向自身。多块 Up 网卡可能意味着还挂着外联网卡(气隙隐患):
#    要么用 -InterfaceAlias 指定隔离网卡,要么中止 —— 绝不在不确定的网卡布局下提升域控(不可逆)。
if ($InterfaceAlias) {
    $nic = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop
} else {
    $cands = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
    if ($cands.Count -eq 0) { Write-Fail "未找到 Up 状态的物理网卡。"; return }
    if ($cands.Count -gt 1) { Write-Fail "检测到 $($cands.Count) 块 Up 网卡:$($cands.Name -join ', ')。请先移除多余网卡,或用 -InterfaceAlias 指定隔离网卡。"; return }
    $nic = $cands[0]
}
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses '127.0.0.1'
Write-Ok "已将本机首选 DNS 设为 127.0.0.1(域控自身)。"

# 2) 安装 AD DS + DNS 角色
Write-Step "安装 AD DS / DNS 角色"
$feat = Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools
if (-not $feat.Success) { Write-Fail "角色安装失败,终止。"; return }
Write-Ok "AD-Domain-Services + DNS 角色已安装。"

# 3) 提升为新林首个域控(含 AD 集成 DNS)。完成后自动重启。
Write-Step "Install-ADDSForest(将自动重启)"
Import-Module ADDSDeployment
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetbiosName `
    -SafeModeAdministratorPassword $SafeModePassword `
    -InstallDns:$true `
    -DatabasePath 'C:\Windows\NTDS' `
    -SysvolPath  'C:\Windows\SYSVOL' `
    -LogPath     'C:\Windows\NTDS' `
    -Force `
    -NoRebootOnCompletion:$false

# 注:Install-ADDSForest 成功后会自行重启,以下提示通常不会显示。
Write-Host "若未自动重启,请手动重启。重启后依次运行: Set-DcDnsAirgap.ps1 -> ..\guest\Configure-WEC-Collector.ps1 -> New-WefGpo.ps1" -ForegroundColor Gray
