#requires -Version 5.1
<#
.SYNOPSIS
  接缝②:把主仓 02-integrity-monitor(CafeSec 完整性监控)部署进靶场 Windows VM,
  建立 billing 路径基线并扫描 —— 用真实 Sysmon/事件日志替代其合成 fixtures。
.DESCRIPTION
  在靶场 Windows 客户机内运行。它创建独立 venv、可编辑安装该工具(含 windows 额外依赖),
  生成 HMAC 签名密钥与基线,然后对一个 billing 风格的路径扫描。
  入口用 `python -m integrity_monitor`(包内置 __main__),不依赖 Scripts 目录是否在 PATH。

  两阶段说明:pip 依赖(blake3/click/psutil/pyyaml/requests/pywin32/python-evtx)需要联网,
  请在【阶段一(临时联网)】部署;或用 -WheelDir 指定离线 wheel 目录做断网安装。
  本工具是保守的防御监控:只读取/哈希/比对,不修改/绕过/篡改任何 billing 软件。

.PARAMETER SourceDir
  02-integrity-monitor 源码目录。默认取 lab.psd1 的 Repo.IntegrityMonitor;
  在 VM 内通常先把该文件夹用 Copy-VMFile/ISO 拷进来,再用 -SourceDir 指向它。
.PARAMETER BillingPath
  要建立基线/扫描的 billing 风格路径,默认 C:\CafeBilling。
.PARAMETER WorkDir
  venv、基线、密钥的工作目录,默认 C:\CafeSec\integrity。
.PARAMETER WheelDir
  (可选)离线 wheel 目录;给了则用 --no-index --find-links 断网安装。
.PARAMETER InstallOnly
  只安装,不建基线/扫描。
.EXAMPLE
  .\Deploy-IntegrityMonitor.ps1 -SourceDir C:\CafeSec\02-integrity-monitor -BillingPath C:\CafeBilling
.NOTES
  建议管理员运行(读取受保护路径/事件日志)。Python 3.10+ 需已安装(见 docs\downloads.md)。
#>
[CmdletBinding()]
param(
    [string]$SourceDir,
    [string]$BillingPath = 'C:\CafeBilling',
    [string]$WorkDir     = 'C:\CafeSec\integrity',
    [string]$WheelDir,
    [switch]$InstallOnly
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\Common.ps1"

$moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $SourceDir) {
    try { $cfg = Get-LabConfig; $rel = $cfg.Repo.IntegrityMonitor } catch { $rel = '..\02-integrity-monitor' }
    $cand = Join-Path $moduleRoot $rel
    $rp = Resolve-Path -LiteralPath $cand -ErrorAction SilentlyContinue
    $SourceDir = if ($rp) { $rp.ProviderPath } else { $cand }
}

Write-Step "部署完整性监控 (02-integrity-monitor)"
if (-not (Test-Path (Join-Path $SourceDir 'pyproject.toml'))) {
    Write-Fail "在 $SourceDir 未找到 pyproject.toml。请把 02-integrity-monitor 文件夹拷进本机并用 -SourceDir 指向它。"
    return
}
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Write-Fail "未找到 python。请先安装 Python 3.10+(见 docs\downloads.md)。"; return }

# 1) venv
if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }
$venv = Join-Path $WorkDir '.venv'
$venvPy = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path $venvPy)) {
    Write-Host "创建 venv: $venv" -ForegroundColor Cyan
    & python -m venv $venv
}
if (-not (Test-Path $venvPy)) { Write-Fail "venv 创建失败。"; return }

# 2) 安装(联网 或 离线 wheelhouse)
Write-Host "安装 cafesec-integrity-monitor(可编辑 + windows 额外依赖)..." -ForegroundColor Cyan
& $venvPy -m pip install --upgrade pip | Out-Null
if ($WheelDir) {
    if (-not (Test-Path $WheelDir)) { Write-Fail "WheelDir 不存在: $WheelDir"; return }
    & $venvPy -m pip install --no-index --find-links $WheelDir -e "$SourceDir[windows]"
} else {
    & $venvPy -m pip install -e "$SourceDir[windows]"
}
if ($LASTEXITCODE -ne 0) {
    Write-Warn2 "带 [windows] 额外依赖安装失败,回退为仅核心依赖(事件日志解析功能可能受限)。"
    & $venvPy -m pip install -e $SourceDir
    if ($LASTEXITCODE -ne 0) { Write-Fail "安装失败。若处于断网阶段,请用 -WheelDir 指定离线 wheel 目录。"; return }
}
# 验证入口可用
& $venvPy -m integrity_monitor --help *> $null
if ($LASTEXITCODE -ne 0) { Write-Warn2 "`python -m integrity_monitor` 自检返回非零,请检查安装。" }
else { Write-Ok "完整性监控已安装,入口可用(python -m integrity_monitor)。" }

if ($InstallOnly) { Write-Step "仅安装完成。"; return }

# 3) 基线 + 扫描
if (-not (Test-Path $BillingPath)) {
    Write-Warn2 "billing 路径不存在: $BillingPath。先创建一个用于演示(放几个示例文件),或用 -BillingPath 指向真实路径。"
    New-Item -ItemType Directory -Path $BillingPath -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $BillingPath 'billing-agent.cfg') -Value 'demo=true' -Encoding ASCII
}
$store = Join-Path $WorkDir 'baseline.json'
$hmac  = Join-Path $WorkDir 'hmac.key'
if (-not (Test-Path $hmac)) {
    # 生成 32 字节随机 HMAC 密钥(密钥与基线不要放同一可写目录 —— 此处演示,生产请分离)
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    [System.IO.File]::WriteAllBytes($hmac, $bytes)
    Write-Ok "已生成 HMAC 密钥: $hmac(生产环境请放到收银用户不可写的位置)。"
}

Write-Step "建立基线: $BillingPath"
& $venvPy -m integrity_monitor baseline create --path $BillingPath --store $store --hmac-key-file $hmac
Write-Step "对照扫描"
& $venvPy -m integrity_monitor scan --path $BillingPath --store $store --hmac-key-file $hmac
Write-Step "校验基线签名"
& $venvPy -m integrity_monitor verify --store $store --hmac-key-file $hmac

Write-Step "完成"
Write-Host "在靶场里改动一个 billing 文件后再 scan,即可看到 drift 检出(完整性监控在真实遥测上的验证)。" -ForegroundColor Gray
Write-Host "进程/事件日志异常检查会消费本机真实 Sysmon/Security 日志(见 02-integrity-monitor\docs)。" -ForegroundColor Gray
