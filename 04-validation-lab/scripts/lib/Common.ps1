#requires -Version 5.1
<#
  Common.ps1 — 所有 CafeSec 脚本共用的辅助函数与配置加载。
  在脚本顶部用:  . "$PSScriptRoot\lib\Common.ps1"   (或相对路径)载入。
#>

# Pure, unit-testable decision logic lives in LabLogic.psm1; import it here so every
# script that dot-sources Common.ps1 gains it. $PSScriptRoot here = ...\scripts\lib.
Import-Module (Join-Path $PSScriptRoot 'LabLogic.psm1') -Force

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
    $cfg = Import-PowerShellDataFile -Path $ConfigPath
    # Reproducibility/portability: honor env overrides (CAFESEC_VMROOT/CAFESEC_ISOROOT) and
    # auto-relocate the VM/ISO roots when the configured drive is absent (a host with no E:).
    # No-op on the author's host (E: present). Never fatal: on any failure we keep the psd1 values.
    try {
        $vols = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' }
        $cfg.Paths.VmRoot  = Resolve-LabPathRoot -ConfiguredPath $cfg.Paths.VmRoot  -OverridePath $env:CAFESEC_VMROOT  -Volume $vols -LeafName 'CafeSec-Lab\VMs'
        $cfg.Paths.IsoRoot = Resolve-LabPathRoot -ConfiguredPath $cfg.Paths.IsoRoot -OverridePath $env:CAFESEC_ISOROOT -Volume $vols -LeafName 'CafeSec-Lab\ISO'
    } catch {
        Write-Verbose "Lab path resolution skipped: $($_.Exception.Message)"
    }
    return $cfg
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
