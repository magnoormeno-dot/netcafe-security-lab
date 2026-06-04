#requires -Version 5.1
<#
.SYNOPSIS
  接缝①:直接校验主仓 01-hardening-checklist/detection 下的【真实】Sigma / YARA 规则,产出报告。
.DESCRIPTION
  这是验证靶场与检测规则之间的接缝。它不复制规则,而是从仓库的 detection 目录就地读取:
    * Sigma:用 sigma-cli 的 opensearch 后端做 `sigma convert` —— 能转换 = 规则语法/字段可用。
    * YARA :用 yara64.exe 编译每条规则(对空临时文件扫描,退出码 0 = 可编译);可选对 -Target 实扫。
  产出 reports\rule-validation-<时间>.md 与 .jsonl。

  诚实边界:本脚本做的是【离线的规则可转换/可编译校验】(catch 语法/字段错误)。
  "规则在真实遥测上是否命中"需要在【运行中的靶场】里做:部署 Sysmon/WEF/Wazuh 后,
  由你本人在隔离环境内手动触发良性动作(如停一个测试服务),再到 Wazuh/ForwardedEvents 里确认命中。
  本脚本不执行任何攻击/触发动作。

.PARAMETER SigmaDir
  Sigma 规则目录。默认取 lab.psd1 的 Repo.DetectionSigma(相对本模块根解析到 ../01-.../detection/sigma)。
.PARAMETER YaraDir
  YARA 规则目录。默认取 lab.psd1 的 Repo.DetectionYara。
.PARAMETER Target
  (可选)用 YARA 规则实扫的目录/文件;不给则只做编译校验。
.PARAMETER YaraExe
  yara64.exe 路径,默认 downloads\tools\yara64.exe(见 Setup-RuleEngines.ps1)。
.PARAMETER Pipeline
  sigma convert 用的处理管线,默认 ecs_windows(贴合 Sysmon/Windows 字段)。
.EXAMPLE
  .\Invoke-RuleValidation.ps1                       # 校验仓库全部 Sigma/YARA 规则
.EXAMPLE
  .\Invoke-RuleValidation.ps1 -Target C:\Samples    # 额外用 YARA 实扫一个目录
.NOTES
  无需管理员。需 sigma-cli(opensearch 后端)与 yara64.exe —— 由 Setup-RuleEngines.ps1 在临时联网阶段装好。
#>
[CmdletBinding()]
param(
    [string]$SigmaDir,
    [string]$YaraDir,
    [string]$Target,
    [string]$YaraExe,
    [string]$Pipeline = 'ecs_windows',
    # OpenSearch backend target. Current pySigma-backend-opensearch exposes 'opensearch_lucene'
    # (the older 'opensearch' target name was removed). ecs_windows ECS mappings are valid for
    # OpenSearch (an Elasticsearch fork), so we pass --disable-pipeline-check on the convert below.
    [string]$SigmaTarget = 'opensearch_lucene'
)
$ErrorActionPreference = 'Continue'   # 规则转换/编译失败是数据,不应终止脚本
. "$PSScriptRoot\..\lib\Common.ps1"

$moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # 04-validation-lab\
$cfg = Get-LabConfig

function Resolve-RepoPath {
    param([string]$Relative)
    $p = Join-Path $moduleRoot $Relative
    $rp = Resolve-Path -LiteralPath $p -ErrorAction SilentlyContinue
    if ($rp) { return $rp.ProviderPath } else { return $p }
}

if (-not $SigmaDir) { $SigmaDir = Resolve-RepoPath $cfg.Repo.DetectionSigma }
if (-not $YaraDir)  { $YaraDir  = Resolve-RepoPath $cfg.Repo.DetectionYara }
if (-not $YaraExe)  { $YaraExe  = Join-Path $moduleRoot 'downloads\tools\yara64.exe' }

Write-Step "规则校验(消费主仓 01-hardening-checklist/detection)"
Write-Host "  Sigma 目录: $SigmaDir" -ForegroundColor Gray
Write-Host "  YARA  目录: $YaraDir"  -ForegroundColor Gray

$results = @()

# ---------- Sigma ----------
Write-Step "Sigma → opensearch 转换校验"
$sigmaCmd = Get-Command sigma -ErrorAction SilentlyContinue
if (-not $sigmaCmd) {
    Write-Warn2 "未找到 sigma(先在临时联网阶段跑 analysis\Setup-RuleEngines.ps1)。跳过 Sigma 校验。"
} elseif (-not (Test-Path $SigmaDir)) {
    Write-Warn2 "Sigma 目录不存在: $SigmaDir。跳过。"
} else {
    $sigmaFiles = Get-ChildItem -Path $SigmaDir -Recurse -Filter *.yml -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike '*example*' }   # 跳过 *.example.yml 调优样例
    foreach ($f in $sigmaFiles) {
        $global:LASTEXITCODE = 0
        # sigma-cli writes progress ("Parsing Sigma rules") to stderr, so $? is unreliable here
        # (it would flip to $false on any stderr write); judge success by the native exit code only.
        $out = & $sigmaCmd convert -t $SigmaTarget -p $Pipeline --disable-pipeline-check $f.FullName 2>&1
        $ok = ($LASTEXITCODE -eq 0)
        $msg = if ($ok) { 'converted' } else { (($out | Out-String).Trim() -split "`n" | Select-Object -First 2) -join ' ' }
        $results += [pscustomobject]@{ kind='sigma'; rule=$f.Name; ok=$ok; detail=$msg }
        Write-Host ("  {0} {1}" -f $(if($ok){'[ OK ]'}else{'[FAIL]'}), $f.Name) -ForegroundColor $(if($ok){'Green'}else{'Red'})
        if (-not $ok) { Write-Host ("        $msg") -ForegroundColor DarkYellow }
    }
}

# ---------- YARA ----------
$yaraHeader = 'YARA 编译校验'
if ($Target) { $yaraHeader += " + 实扫 $Target" }
Write-Step $yaraHeader
if (-not (Test-Path $YaraExe)) {
    Write-Warn2 "未找到 yara64.exe ($YaraExe)。先跑 analysis\Setup-RuleEngines.ps1。跳过 YARA 校验。"
} elseif (-not (Test-Path $YaraDir)) {
    Write-Warn2 "YARA 目录不存在: $YaraDir。跳过。"
} else {
    # 编译校验用的空临时文件(yara 需要一个扫描目标)
    $tmp = Join-Path $env:TEMP ("cafesec_yara_probe_{0}.bin" -f $PID)
    Set-Content -LiteralPath $tmp -Value 'cafesec-rule-compile-probe' -Encoding ASCII
    try {
        $yaraFiles = Get-ChildItem -Path $YaraDir -Recurse -Include *.yar,*.yara -ErrorAction SilentlyContinue
        foreach ($r in $yaraFiles) {
            $scanPath = if ($Target) { $Target } else { $tmp }
            $global:LASTEXITCODE = 0
            $out = & $YaraExe -w $r.FullName $scanPath 2>&1
            # yara: 0 = 成功(命中或未命中均 0);非 0 = 编译/运行错误
            $ok = ($LASTEXITCODE -eq 0)
            $hits = if ($ok -and $Target) { @($out | Where-Object { $_ -and $_ -notmatch '^yara' }).Count } else { 0 }
            $msg = if ($ok) { if ($Target) { "compiled; matches=$hits" } else { 'compiled' } } else { (($out | Out-String).Trim() -split "`n" | Select-Object -First 2) -join ' ' }
            $results += [pscustomobject]@{ kind='yara'; rule=$r.Name; ok=$ok; detail=$msg }
            Write-Host ("  {0} {1}  {2}" -f $(if($ok){'[ OK ]'}else{'[FAIL]'}), $r.Name, $(if($ok -and $Target){"(matches=$hits)"}else{''})) -ForegroundColor $(if($ok){'Green'}else{'Red'})
            if (-not $ok) { Write-Host ("        $msg") -ForegroundColor DarkYellow }
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

# ---------- 报告 ----------
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$reportDir = Join-Path $moduleRoot 'reports'
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
$mdPath  = Join-Path $reportDir "rule-validation-$stamp.md"
$jsonl   = Join-Path $reportDir "rule-validation-$stamp.jsonl"

$pass = @($results | Where-Object ok).Count
$fail = @($results | Where-Object { -not $_.ok }).Count

$md = @()
$md += "# Rule validation report ($stamp)"
$md += ""
$md += "> 合成实验室证据(规则可转换/可编译校验)。非现场验证;引用前须人工复核。"
$md += ""
$md += "Source rules: ``01-hardening-checklist/detection`` | Pipeline: ``$Pipeline`` | Pass: **$pass** Fail: **$fail**"
$md += ""
$md += "| Kind | Rule | Result | Detail |"
$md += "| --- | --- | --- | --- |"
foreach ($r in $results) {
    $md += ("| {0} | {1} | {2} | {3} |" -f $r.kind, $r.rule, $(if($r.ok){'✅'}else{'❌'}), ($r.detail -replace '\|','\\|'))
}
Set-Content -LiteralPath $mdPath -Value ($md -join "`r`n") -Encoding UTF8
$results | ForEach-Object { $_ | ConvertTo-Json -Compress } | Set-Content -LiteralPath $jsonl -Encoding UTF8

Write-Step "完成: Pass=$pass Fail=$fail"
Write-Host "  报告: $mdPath" -ForegroundColor Gray
Write-Host "  数据: $jsonl"  -ForegroundColor Gray
Write-Host "  下一步:在运行中的靶场里部署 Sysmon/WEF/Wazuh 后,手动触发良性动作以做【实弹】命中验证(见 COVERAGE.md)。" -ForegroundColor Gray
