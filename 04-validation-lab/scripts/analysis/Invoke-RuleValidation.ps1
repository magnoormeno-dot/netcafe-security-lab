#requires -Version 5.1
<#
.SYNOPSIS
  Seam #1: validate the REAL Sigma / YARA rules under 01-hardening-checklist/detection and write a report.
.DESCRIPTION
  This is the seam between the validation lab and the detection rules. It does not copy the rules; it
  reads them in place from the repo's detection directories:
    * Sigma: `sigma convert` with the opensearch backend's `lucene` target (the Wazuh indexer is
      OpenSearch, so Lucene queries are directly usable). A clean convert proves the rule's
      syntax/fields/logsource are valid.
    * YARA : compile each rule with yara64.exe (a no-match scan of an empty temp file exits 0 = compiles);
      with -Target it additionally scans a real path.
  Writes reports\rule-validation-<timestamp>.md and .jsonl.

  Honesty boundary: this performs OFFLINE rule convert/compile validation (it catches field/syntax errors).
  Whether a rule actually FIRES on real telemetry must be validated in a RUNNING lab: deploy Sysmon/WEF/
  Wazuh, then manually trigger a benign action (e.g. stop a test service) and confirm the hit in
  Wazuh/ForwardedEvents. This script performs no attack/trigger action.

  Exit code: 0 only when at least one rule was processed and all processed rules passed; otherwise the
  number of failures (or 1 if no rule engine was available, so an empty run cannot masquerade as clean).
  This makes the offline subset CI-enforceable.

.PARAMETER SigmaDir   Sigma rules directory. Default: lab.psd1 Repo.DetectionSigma (../01-.../detection/sigma).
.PARAMETER YaraDir    YARA rules directory. Default: lab.psd1 Repo.DetectionYara.
.PARAMETER Target     (optional) Path to additionally scan with YARA; omit for compile-only.
.PARAMETER YaraExe    Path to yara64.exe. Default: downloads\tools\yara64.exe (see Setup-RuleEngines.ps1).
.PARAMETER Pipeline   sigma processing pipeline. Default ecs_windows (matches Sysmon/Windows fields).
.PARAMETER SigmaTarget sigma conversion target. Default 'lucene' (opensearch backend; OpenSearch/Wazuh).
.EXAMPLE
  .\Invoke-RuleValidation.ps1                    # validate all repo Sigma/YARA rules
.EXAMPLE
  .\Invoke-RuleValidation.ps1 -Target C:\Samples # also YARA-scan a directory
.NOTES
  No admin required. Needs sigma-cli (opensearch backend + pysigma-pipeline-windows) and yara64.exe,
  installed by Setup-RuleEngines.ps1 during the temporary-connectivity phase.
#>
[CmdletBinding()]
param(
    [string]$SigmaDir,
    [string]$YaraDir,
    [string]$Target,
    [string]$YaraExe,
    [string]$Pipeline = 'ecs_windows',
    [string]$SigmaTarget = 'lucene'
)
$ErrorActionPreference = 'Continue'   # a rule failing convert/compile is data, not a script error
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

Write-Step "Rule validation (consuming 01-hardening-checklist/detection)"
Write-Host "  Sigma dir: $SigmaDir" -ForegroundColor Gray
Write-Host "  YARA  dir: $YaraDir"  -ForegroundColor Gray

$results = @()
$enginesAvailable = $false

# ---------- Sigma ----------
Write-Step "Sigma -> $SigmaTarget convert validation (pipeline: $Pipeline)"
$sigmaCmd = Get-Command sigma -ErrorAction SilentlyContinue
if (-not $sigmaCmd) {
    Write-Warn2 "sigma not found (run analysis\Setup-RuleEngines.ps1 during the connectivity phase). Skipping Sigma."
} elseif (-not (Test-Path $SigmaDir)) {
    Write-Warn2 "Sigma dir not found: $SigmaDir. Skipping."
} else {
    $enginesAvailable = $true
    $sigmaFiles = Get-ChildItem -Path $SigmaDir -Recurse -Filter *.yml -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike '*example*' }   # skip *.example.yml tuning samples
    foreach ($f in $sigmaFiles) {
        $global:LASTEXITCODE = 0
        # sigma writes "Parsing Sigma rules" to stderr; under PS 5.1 that flips $? to $false
        # (NativeCommandError), so gate on the exit code only (command existence is already ensured).
        $out = & $sigmaCmd convert -t $SigmaTarget -p $Pipeline $f.FullName 2>&1
        $ok = ($LASTEXITCODE -eq 0)
        $msg = if ($ok) { 'converted' } else { (($out | Out-String).Trim() -split "`n" | Select-Object -First 2) -join ' ' }
        $results += [pscustomobject]@{ kind = 'sigma'; rule = $f.Name; ok = $ok; detail = $msg }
        Write-Host ("  {0} {1}" -f $(if ($ok) { '[ OK ]' } else { '[FAIL]' }), $f.Name) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
        if (-not $ok) { Write-Host ("        $msg") -ForegroundColor DarkYellow }
    }
}

# ---------- YARA ----------
$yaraHeader = 'YARA compile validation'
if ($Target) { $yaraHeader += " + scan $Target" }
Write-Step $yaraHeader
if (-not (Test-Path $YaraExe)) {
    Write-Warn2 "yara64.exe not found ($YaraExe). Run analysis\Setup-RuleEngines.ps1. Skipping YARA."
} elseif (-not (Test-Path $YaraDir)) {
    Write-Warn2 "YARA dir not found: $YaraDir. Skipping."
} else {
    $enginesAvailable = $true
    # empty temp file as a compile-check target (yara needs a scan target)
    $tmp = Join-Path $env:TEMP ("cafesec_yara_probe_{0}.bin" -f $PID)
    Set-Content -LiteralPath $tmp -Value 'cafesec-rule-compile-probe' -Encoding ASCII
    try {
        $yaraFiles = Get-ChildItem -Path $YaraDir -Recurse -Include *.yar, *.yara -ErrorAction SilentlyContinue
        foreach ($r in $yaraFiles) {
            $scanPath = if ($Target) { $Target } else { $tmp }
            $global:LASTEXITCODE = 0
            $out = & $YaraExe -w $r.FullName $scanPath 2>&1
            # yara: 0 = success (match or no match); non-zero = compile/run error
            $ok = ($LASTEXITCODE -eq 0)
            $hits = if ($ok -and $Target) { @($out | Where-Object { $_ -and $_ -notmatch '^yara' }).Count } else { 0 }
            $msg = if ($ok) { if ($Target) { "compiled; matches=$hits" } else { 'compiled' } } else { (($out | Out-String).Trim() -split "`n" | Select-Object -First 2) -join ' ' }
            $results += [pscustomobject]@{ kind = 'yara'; rule = $r.Name; ok = $ok; detail = $msg }
            Write-Host ("  {0} {1}  {2}" -f $(if ($ok) { '[ OK ]' } else { '[FAIL]' }), $r.Name, $(if ($ok -and $Target) { "(matches=$hits)" } else { '' })) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
            if (-not $ok) { Write-Host ("        $msg") -ForegroundColor DarkYellow }
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

# ---------- report ----------
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$reportDir = Join-Path $moduleRoot 'reports'
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
$mdPath = Join-Path $reportDir "rule-validation-$stamp.md"
$jsonl  = Join-Path $reportDir "rule-validation-$stamp.jsonl"

$pass = @($results | Where-Object ok).Count
$fail = @($results | Where-Object { -not $_.ok }).Count

$md = @()
$md += "# Rule validation report ($stamp)"
$md += ""
$md += "> Reproducible synthetic lab evidence (offline rule convert/compile check). Not field validation; human-review before citing."
$md += ""
$md += "Source rules: ``01-hardening-checklist/detection`` | Sigma target: ``$SigmaTarget`` | Pipeline: ``$Pipeline`` | Pass: **$pass** Fail: **$fail**"
$md += ""
$md += "| Kind | Rule | Result | Detail |"
$md += "| --- | --- | --- | --- |"
foreach ($r in $results) {
    $md += ("| {0} | {1} | {2} | {3} |" -f $r.kind, $r.rule, $(if ($r.ok) { 'PASS' } else { 'FAIL' }), ($r.detail -replace '\|', '\\|'))
}
Set-Content -LiteralPath $mdPath -Value ($md -join "`r`n") -Encoding UTF8
$results | ForEach-Object { $_ | ConvertTo-Json -Compress } | Set-Content -LiteralPath $jsonl -Encoding UTF8

Write-Step "Done: Pass=$pass Fail=$fail"
Write-Host "  report: $mdPath" -ForegroundColor Gray
Write-Host "  data:   $jsonl"  -ForegroundColor Gray

# ---------- honest exit code (CI-enforceable) ----------
if (-not $enginesAvailable -or $results.Count -eq 0) {
    Write-Fail "No rule engine was available, so NOTHING was validated. Install sigma-cli + yara64.exe (Setup-RuleEngines.ps1) and re-run."
    exit 1
}
if ($fail -gt 0) {
    Write-Fail "$fail rule(s) failed to convert/compile. See the report."
} else {
    Write-Ok "All $pass rule(s) converted/compiled cleanly."
    Write-Host "  Next: in a running lab, deploy Sysmon/WEF/Wazuh and manually trigger benign actions for live-fire validation (see COVERAGE.md)." -ForegroundColor Gray
}
exit $fail
