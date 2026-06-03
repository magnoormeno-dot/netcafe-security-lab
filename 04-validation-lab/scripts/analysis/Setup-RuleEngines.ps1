#requires -Version 5.1
<#
.SYNOPSIS
  在分析侧(可在 CSL-Server 或专门的分析 VM 上)准备 Sigma 与 YARA 运行环境与目录结构。
.DESCRIPTION
  纯防御:Sigma = 通用检测规则语言(可转换为 Wazuh/各 SIEM 查询);YARA = 文件/内存特征匹配。
  本脚本只搭【引擎与目录】,不附带任何检测规则 —— 你之后把自己的规则放进 rules\sigma 与 rules\yara。
  隔离网无法 pip/choco 在线安装,故支持两种来源:
    (A) 临时联网阶段在线安装(默认)
    (B) 提供本地离线安装包路径
.PARAMETER YaraZip
  (可选) 本地 YARA 发行版 zip 路径(离线安装)。
#>
[CmdletBinding()]
param([string]$YaraZip)
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\..\lib\Common.ps1"   # for Get-LabArtifactManifest / Test-LabArtifactChecksum (LabLogic)

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # 项目根
$rulesSigma = Join-Path $root 'rules\sigma'
$rulesYara  = Join-Path $root 'rules\yara'
$tools      = Join-Path $root 'downloads\tools'
New-Item -ItemType Directory -Force -Path $rulesSigma,$rulesYara,$tools | Out-Null

Write-Host "=== Sigma 引擎 (sigma-cli) ===" -ForegroundColor Cyan
if (Get-Command python -ErrorAction SilentlyContinue) {
    # 临时联网阶段:安装 sigma-cli + OpenSearch 后端。
    # 重要:不存在官方 'wazuh' sigma 后端;Wazuh 索引器/Dashboard 基于 OpenSearch,
    # 因此用 opensearch 后端生成可直接在 Wazuh Dashboard / OpenSearch 使用的查询。
    python -m pip install --upgrade pip
    python -m pip install sigma-cli
    # sigma 是 pip 安装的控制台脚本;若其 Scripts 目录尚未进 PATH,直接调用会抛 CommandNotFound,
    # 且 $LASTEXITCODE 会保留上一条(pip)的 0 而误判成功。故先解析命令,显式置零再核对 $? 与退出码。
    $sigmaCmd = Get-Command sigma -ErrorAction SilentlyContinue
    if ($sigmaCmd) {
        $global:LASTEXITCODE = 0
        & $sigmaCmd plugin install opensearch
        $ok = ($? -and $LASTEXITCODE -eq 0)
    } else {
        Write-Host "[WARN] 安装后未在 PATH 找到 sigma(可能 Python Scripts 目录未加入 PATH)。请重开 PowerShell 或把该目录加入 PATH 后重试: sigma plugin install opensearch" -ForegroundColor Yellow
        $ok = $false
    }
    if ($ok) {
        Write-Host "[ OK ] sigma-cli + opensearch 后端已安装。示例转换:" -ForegroundColor Green
        Write-Host "  # 生成 Lucene 查询(可在 Wazuh Dashboard / OpenSearch 使用):" -ForegroundColor Gray
        Write-Host "  sigma convert -t opensearch_lucene -p ecs_windows --disable-pipeline-check $rulesSigma\your_rule.yml" -ForegroundColor Gray
        Write-Host "  # 生成 OpenSearch 告警监控规则 JSON:" -ForegroundColor Gray
        Write-Host "  sigma convert -t opensearch_lucene -f monitor_rule -p ecs_windows --disable-pipeline-check $rulesSigma\your_rule.yml" -ForegroundColor Gray
    } else {
        Write-Host "[WARN] sigma opensearch 后端安装未成功(可能正处于断网阶段或 sigma 不在 PATH)。请在临时联网阶段重试: sigma plugin install opensearch" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARN] 未检测到 python。请先安装 Python 3,再重跑;或离线安装 sigma-cli wheel。" -ForegroundColor Yellow
}

Write-Host "`n=== YARA 引擎 ===" -ForegroundColor Cyan
$yaraExe = Join-Path $tools 'yara64.exe'
if ($YaraZip -and (Test-Path $YaraZip)) {
    Expand-Archive -Path $YaraZip -DestinationPath $tools -Force
    Write-Host "[ OK ] 已从 $YaraZip 解压 YARA 到 $tools" -ForegroundColor Green
} elseif (Test-Path $yaraExe) {
    Write-Host "[ OK ] 已存在 $yaraExe" -ForegroundColor Green
} else {
    Write-Host "[WARN] 未提供 YARA。下载 VirusTotal/yara 的 Windows 发行版 zip(地址见 docs\downloads.md)," -ForegroundColor Yellow
    Write-Host "       用 -YaraZip 指定路径重跑,或手动解压 yara64.exe 到 $tools" -ForegroundColor Yellow
}

# 可复现:若 config\versions.psd1 钉了 yara64.exe 的 SHA256,则校验,确保用的是产出证据时的同一构建。
if (Test-Path $yaraExe) {
    try {
        $pin   = (Get-LabArtifactManifest).Yara.ExeSha256
        $match = Test-LabArtifactChecksum -Path $yaraExe -ExpectedSha256 $pin
        if ($match -eq $true)      { Write-Host "[ OK ] yara64.exe 与 versions.psd1 钉定的 SHA256 一致(可复现)。" -ForegroundColor Green }
        elseif ($match -eq $false) { Write-Host "[WARN] yara64.exe 的 SHA256 与 versions.psd1 不一致 —— 与产出证据时的构建不同,结果可能无法复现。" -ForegroundColor Yellow }
        else                       { Write-Host "[INFO] versions.psd1 未钉 yara64.exe 哈希,跳过校验。" -ForegroundColor Gray }
    } catch {
        Write-Host "[INFO] 未能加载 versions.psd1($($_.Exception.Message)),跳过 yara 校验。" -ForegroundColor Gray
    }
}

# 目录占位说明
Set-Content -Path (Join-Path $rulesSigma 'README.txt') -Value "把你的 Sigma 规则(.yml)放在此目录。用 sigma convert -t opensearch_lucene -p ecs_windows --disable-pipeline-check <rule>.yml 转换(详见 Setup-RuleEngines.ps1 输出与 README.md)。" -Encoding UTF8
Set-Content -Path (Join-Path $rulesYara  'README.txt') -Value "把你的 YARA 规则(.yar/.yara)放在此目录。用 scripts\analysis\Invoke-YaraScan.ps1 扫描。" -Encoding UTF8

Write-Host "`n目录就绪:" -ForegroundColor Gray
Write-Host "  Sigma 规则 -> $rulesSigma" -ForegroundColor Gray
Write-Host "  YARA  规则 -> $rulesYara" -ForegroundColor Gray
