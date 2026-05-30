#requires -Version 5.1
<#
.SYNOPSIS
  【在 Windows 客户机/服务器内部运行】安装 Sysmon 并应用 SwiftOnSecurity 基线配置。
.DESCRIPTION
  纯防御:Sysmon 是微软 Sysinternals 的端点日志记录器,生成丰富的进程/网络/文件
  /注册表事件到事件日志,供 Sigma 规则与 Wazuh 检测使用。
  隔离网无法联网下载,所以本脚本从【本地路径】取 Sysmon 与配置文件。
  把以下文件先用 Copy-VMFile 注入到 VM(见 docs),或放进挂载的 ISO:
    - Sysmon.zip 解压出的 Sysmon64.exe
    - sysmonconfig-export.xml (SwiftOnSecurity 配置)
.PARAMETER SysmonExe
  Sysmon64.exe 的本地完整路径。
.PARAMETER ConfigXml
  Sysmon 配置 XML 的本地完整路径。
.EXAMPLE
  .\Deploy-Sysmon.ps1 -SysmonExe C:\CafeSec\Sysmon64.exe -ConfigXml C:\CafeSec\sysmonconfig-export.xml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SysmonExe,
    [Parameter(Mandatory)][string]$ConfigXml
)
$ErrorActionPreference = 'Stop'
function Test-Admin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not (Test-Admin)) { throw "需要管理员权限。" }

foreach ($f in @($SysmonExe,$ConfigXml)) { if (-not (Test-Path $f)) { throw "找不到文件: $f" } }

$svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Sysmon 已安装,更新配置..." -ForegroundColor Yellow
    & $SysmonExe -c $ConfigXml
} else {
    Write-Host "安装 Sysmon 并应用配置..." -ForegroundColor Cyan
    & $SysmonExe -accepteula -i $ConfigXml
}

Start-Sleep -Seconds 2
$svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "[ OK ] Sysmon64 服务运行中。" -ForegroundColor Green
} else {
    throw "Sysmon 安装后未运行,请检查。"
}

# 验证事件正在写入
$log = 'Microsoft-Windows-Sysmon/Operational'
$cnt = (Get-WinEvent -LogName $log -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "[ OK ] 事件日志 '$log' 最近事件数(采样): $cnt" -ForegroundColor Green
Write-Host "配置生效版本:" -ForegroundColor Gray
& $SysmonExe -c
