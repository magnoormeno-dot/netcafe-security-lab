#requires -Version 5.1
<#
.SYNOPSIS
  On the analysis side (the CSL-Server or a dedicated analysis VM) prepare the Sigma and YARA runtime
  and directory structure.
.DESCRIPTION
  Purely defensive: Sigma = generic detection-rule language (converts to Wazuh / SIEM queries);
  YARA = file/memory pattern matching. This script only sets up the ENGINES and DIRECTORIES; it ships no
  detection rules of its own -- the source of truth is 01-hardening-checklist/detection (consumed in place
  by Invoke-RuleValidation.ps1). The local rules\sigma and rules\yara dirs are a lab-only overlay.
  The isolated network cannot pip/choco online, so two sources are supported:
    (A) online install during the temporary-connectivity phase (default)
    (B) a local offline package path
.PARAMETER YaraZip
  (optional) path to a local YARA Windows release zip (offline install).
.NOTES
  The offline convert/compile rung is also enforced in CI by .github/workflows/validation-lab-rules.yml.
#>
[CmdletBinding()]
param([string]$YaraZip)
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # module root
$rulesSigma = Join-Path $root 'rules\sigma'
$rulesYara  = Join-Path $root 'rules\yara'
$tools      = Join-Path $root 'downloads\tools'
New-Item -ItemType Directory -Force -Path $rulesSigma, $rulesYara, $tools | Out-Null

Write-Host "=== Sigma engine (sigma-cli) ===" -ForegroundColor Cyan
if (Get-Command python -ErrorAction SilentlyContinue) {
    # Temporary-connectivity phase: install sigma-cli + the OpenSearch backend + the Windows pipeline.
    # Note: there is no official 'wazuh' sigma backend; the Wazuh indexer/Dashboard is OpenSearch, so the
    # opensearch backend's 'lucene' target produces queries usable directly in the Wazuh Dashboard.
    # pysigma-pipeline-windows provides the 'ecs_windows' pipeline used at convert time.
    python -m pip install --upgrade pip
    python -m pip install sigma-cli pysigma-pipeline-windows
    # sigma is a pip-installed console script; if its Scripts dir is not yet on PATH, a bare call throws
    # CommandNotFound and $LASTEXITCODE keeps the previous (pip) 0, misreading success. Resolve first.
    $sigmaCmd = Get-Command sigma -ErrorAction SilentlyContinue
    if ($sigmaCmd) {
        $global:LASTEXITCODE = 0
        & $sigmaCmd plugin install opensearch
        $ok = ($LASTEXITCODE -eq 0)
    } else {
        Write-Host "[WARN] sigma not found on PATH after install (Python Scripts dir may not be on PATH). Reopen PowerShell or add it to PATH and retry: sigma plugin install opensearch" -ForegroundColor Yellow
        $ok = $false
    }
    if ($ok) {
        Write-Host "[ OK ] sigma-cli + opensearch backend installed. Example conversion:" -ForegroundColor Green
        Write-Host "  # produce a Lucene query (usable in Wazuh Dashboard / OpenSearch):" -ForegroundColor Gray
        Write-Host "  sigma convert -t lucene -p ecs_windows $rulesSigma\your_rule.yml" -ForegroundColor Gray
        Write-Host "  # validate the repo's real rules + write a report:" -ForegroundColor Gray
        Write-Host "  .\Invoke-RuleValidation.ps1" -ForegroundColor Gray
    } else {
        Write-Host "[WARN] sigma opensearch backend not installed (offline phase, or sigma not on PATH). Retry during the connectivity phase: sigma plugin install opensearch" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARN] python not found. Install Python 3 and re-run, or install the sigma-cli wheel offline." -ForegroundColor Yellow
}

Write-Host "`n=== YARA engine ===" -ForegroundColor Cyan
$yaraExe = Join-Path $tools 'yara64.exe'
if ($YaraZip -and (Test-Path $YaraZip)) {
    Expand-Archive -Path $YaraZip -DestinationPath $tools -Force
    Write-Host "[ OK ] extracted YARA from $YaraZip to $tools" -ForegroundColor Green
} elseif (Test-Path $yaraExe) {
    Write-Host "[ OK ] $yaraExe already present" -ForegroundColor Green
} else {
    Write-Host "[WARN] YARA not provided. Download the VirusTotal/yara Windows release zip (see docs\downloads.md)," -ForegroundColor Yellow
    Write-Host "       re-run with -YaraZip <path>, or extract yara64.exe to $tools manually." -ForegroundColor Yellow
}

# directory placeholder notes (lab-only overlay; the source of truth is 01-hardening-checklist/detection)
Set-Content -Path (Join-Path $rulesSigma 'README.txt') -Value "Lab-only overlay. The source of truth is 01-hardening-checklist/detection/sigma. Validate with .\Invoke-RuleValidation.ps1, or convert one rule with: sigma convert -t lucene -p ecs_windows <rule>.yml" -Encoding UTF8
Set-Content -Path (Join-Path $rulesYara  'README.txt') -Value "Lab-only overlay. The source of truth is 01-hardening-checklist/detection/yara. Scan with scripts\analysis\Invoke-YaraScan.ps1." -Encoding UTF8

Write-Host "`nDirectories ready:" -ForegroundColor Gray
Write-Host "  Sigma rules -> $rulesSigma" -ForegroundColor Gray
Write-Host "  YARA  rules -> $rulesYara" -ForegroundColor Gray
