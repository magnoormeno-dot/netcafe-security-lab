#requires -Version 5.1
<#
.SYNOPSIS
  启用 Hyper-V 平台与管理工具。需要管理员,完成后通常需要重启。
.NOTES
  本机检测到 HypervisorPresent=True,可能已有 Hyper-V/VBS/WSL2。
  即便如此,显式启用 Microsoft-Hyper-V-All 可确保 PowerShell 模块、
  vmms 服务、虚拟交换机管理齐全。脚本是幂等的——已启用则跳过。
#>
[CmdletBinding()]
param([switch]$NoPrompt)
. "$PSScriptRoot\lib\Common.ps1"
Assert-Admin

Write-Step "启用 Hyper-V"

$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
if ($feature.State -eq 'Enabled') {
    Write-Ok "Hyper-V 已处于启用状态,无需操作。"
} else {
    Write-Host "即将启用功能: Microsoft-Hyper-V-All (含管理工具)"
    if (-not $NoPrompt) {
        $ans = Read-Host "继续吗? 完成后可能要求重启 [y/N]"
        if ($ans -notmatch '^(y|Y)') { Write-Warn2 "已取消。"; return }
    }
    $r = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
    Write-Ok "Hyper-V 功能已启用。"
    if ($r.RestartNeeded) {
        Write-Warn2 "需要重启才能生效。请重启后再运行 02-New-IsolatedSwitch.ps1"
    }
}

# 确认核心服务/模块
$svc = Get-Service vmms -ErrorAction SilentlyContinue
if ($svc) { Write-Ok "Hyper-V 管理服务 vmms 状态: $($svc.Status)" }
if (Get-Command New-VMSwitch -ErrorAction SilentlyContinue) { Write-Ok "Hyper-V PowerShell 模块可用 (New-VMSwitch 已就绪)" }
else { Write-Warn2 "未检测到 Hyper-V PowerShell 模块,可能需重启后再试。" }

Write-Step "完成。重启(如被要求)后运行: 02-New-IsolatedSwitch.ps1"
