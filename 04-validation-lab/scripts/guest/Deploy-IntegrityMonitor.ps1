#requires -Version 5.1
<#
.SYNOPSIS
  Seam (2): Deploy the main repo's 02-integrity-monitor (CafeSec integrity monitoring) into the
  range Windows VM, establish a billing-path baseline, and scan -- replacing its synthetic
  fixtures with real Sysmon/event log data.
.DESCRIPTION
  Runs inside the range Windows guest. It creates an isolated venv, installs the tool in editable
  mode (including the windows extra dependencies), generates an HMAC signing key and a baseline,
  then scans a billing-style path.
  The entry point uses `python -m integrity_monitor` (the package's built-in __main__), so it does
  not depend on whether the Scripts directory is on PATH.

  Two-phase note: the pip dependencies (blake3/click/psutil/pyyaml/requests/pywin32/python-evtx)
  require network access, so deploy during [Phase 1 (temporary connectivity)]; alternatively, use
  -WheelDir to point at an offline wheel directory for an air-gapped install.
  This tool is conservative defensive monitoring: it only reads/hashes/compares, and never
  modifies/bypasses/tampers with any billing software.

.PARAMETER SourceDir
  The 02-integrity-monitor source directory. Defaults to Repo.IntegrityMonitor from lab.psd1;
  inside the VM you typically copy that folder in first via Copy-VMFile/ISO, then point -SourceDir
  at it.
.PARAMETER BillingPath
  The billing-style path to baseline/scan. Defaults to C:\CafeBilling.
.PARAMETER WorkDir
  The working directory for the venv, baseline, and key. Defaults to C:\CafeSec\integrity.
.PARAMETER WheelDir
  (Optional) An offline wheel directory; when provided, installs air-gapped using
  --no-index --find-links.
.PARAMETER InstallOnly
  Install only; do not build a baseline or scan.
.EXAMPLE
  .\Deploy-IntegrityMonitor.ps1 -SourceDir C:\CafeSec\02-integrity-monitor -BillingPath C:\CafeBilling
.NOTES
  Running as administrator is recommended (to read protected paths/event logs). Python 3.10+ must
  already be installed (see docs\downloads.md).
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

Write-Step "Deploying integrity monitor (02-integrity-monitor)"
if (-not (Test-Path (Join-Path $SourceDir 'pyproject.toml'))) {
    Write-Fail "pyproject.toml not found in $SourceDir. Please copy the 02-integrity-monitor folder onto this machine and point -SourceDir at it."
    return
}
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Write-Fail "python not found. Please install Python 3.10+ first (see docs\downloads.md)."; return }

# 1) venv
if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }
$venv = Join-Path $WorkDir '.venv'
$venvPy = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path $venvPy)) {
    Write-Host "Creating venv: $venv" -ForegroundColor Cyan
    & python -m venv $venv
}
if (-not (Test-Path $venvPy)) { Write-Fail "Failed to create venv."; return }

# 2) Install (online or offline wheelhouse)
Write-Host "Installing cafesec-integrity-monitor (editable + windows extras)..." -ForegroundColor Cyan
& $venvPy -m pip install --upgrade pip | Out-Null
if ($WheelDir) {
    if (-not (Test-Path $WheelDir)) { Write-Fail "WheelDir does not exist: $WheelDir"; return }
    & $venvPy -m pip install --no-index --find-links $WheelDir -e "$SourceDir[windows]"
} else {
    & $venvPy -m pip install -e "$SourceDir[windows]"
}
if ($LASTEXITCODE -ne 0) {
    Write-Warn2 "Install with the [windows] extras failed; falling back to core dependencies only (event log parsing may be limited)."
    & $venvPy -m pip install -e $SourceDir
    if ($LASTEXITCODE -ne 0) { Write-Fail "Install failed. If you are in the air-gapped phase, use -WheelDir to specify an offline wheel directory."; return }
}
# Verify the entry point works
& $venvPy -m integrity_monitor --help *> $null
if ($LASTEXITCODE -ne 0) { Write-Warn2 "`python -m integrity_monitor` self-check returned non-zero; please check the installation." }
else { Write-Ok "Integrity monitor installed; entry point available (python -m integrity_monitor)." }

if ($InstallOnly) { Write-Step "Install-only complete."; return }

# 3) Baseline + scan
if (-not (Test-Path $BillingPath)) {
    Write-Warn2 "Billing path does not exist: $BillingPath. Creating one for the demo (with a few sample files), or use -BillingPath to point at a real path."
    New-Item -ItemType Directory -Path $BillingPath -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $BillingPath 'billing-agent.cfg') -Value 'demo=true' -Encoding ASCII
}
$store = Join-Path $WorkDir 'baseline.json'
$hmac  = Join-Path $WorkDir 'hmac.key'
if (-not (Test-Path $hmac)) {
    # Generate a 32-byte random HMAC key (keep the key and baseline out of the same writable directory -- this is for the demo; in production, separate them)
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    [System.IO.File]::WriteAllBytes($hmac, $bytes)
    Write-Ok "HMAC key generated: $hmac (in production, place it where the point-of-sale user cannot write)."
}

Write-Step "Establishing baseline: $BillingPath"
& $venvPy -m integrity_monitor baseline create --path $BillingPath --store $store --hmac-key-file $hmac
Write-Step "Comparison scan"
& $venvPy -m integrity_monitor scan --path $BillingPath --store $store --hmac-key-file $hmac
Write-Step "Verifying baseline signature"
& $venvPy -m integrity_monitor verify --store $store --hmac-key-file $hmac

Write-Step "Done"
Write-Host "Modify a billing file in the range and scan again to see drift detection (validating the integrity monitor against real telemetry)." -ForegroundColor Gray
Write-Host "The process/event-log anomaly checks consume this machine's real Sysmon/Security logs (see 02-integrity-monitor\docs)." -ForegroundColor Gray
