#requires -Version 5.1
<#
  Common.ps1 — 所有 CafeSec 脚本共用的辅助函数与配置加载。
  在脚本顶部用:  . "$PSScriptRoot\lib\Common.ps1"   (或相对路径)载入。
#>

function Get-LabConfig {
    [CmdletBinding()]
    param(
        # 注意:dot-source 时 $PSScriptRoot 绑定的是 Common.ps1 自身所在目录(...\scripts\lib),
        # 而非调用者目录。项目根 = 上两级:<root>\scripts\lib -> <root>;配置在 <root>\config。
        [string]$ConfigPath = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'config\lab.psd1')
    )
    if (-not (Test-Path $ConfigPath)) {
        throw "找不到配置文件 lab.psd1 ($ConfigPath)。请用 -ConfigPath 指定其绝对路径。"
    }
    return Import-PowerShellDataFile -Path $ConfigPath
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    if (-not (Test-IsAdmin)) {
        throw "此脚本需要管理员权限。请右键 PowerShell -> '以管理员身份运行' 后重试。"
    }
}

function Write-Step  { param([string]$m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok    { param([string]$m) Write-Host "[ OK ]  $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Fail  { param([string]$m) Write-Host "[FAIL]  $m" -ForegroundColor Red }
