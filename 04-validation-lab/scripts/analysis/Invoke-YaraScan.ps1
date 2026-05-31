#requires -Version 5.1
<#
.SYNOPSIS
  Scan a specified directory with all YARA rules under rules\yara. Purely defensive: file signature matching / forensic triage.
.PARAMETER TargetPath
  The directory or file to scan.
.PARAMETER YaraExe
  Path to yara64.exe, defaults to downloads\tools\yara64.exe.
.PARAMETER RulesDir
  YARA rules directory, defaults to rules\yara.
.EXAMPLE
  .\Invoke-YaraScan.ps1 -TargetPath C:\Samples
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TargetPath,
    [string]$YaraExe,
    [string]$RulesDir
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $YaraExe)  { $YaraExe  = Join-Path $root 'downloads\tools\yara64.exe' }
if (-not $RulesDir) { $RulesDir = Join-Path $root 'rules\yara' }

if (-not (Test-Path $YaraExe)) { throw "yara64.exe not found: $YaraExe (run Setup-RuleEngines.ps1 first)" }
$rules = Get-ChildItem -Path $RulesDir -Recurse -Include *.yar,*.yara -ErrorAction SilentlyContinue
if (-not $rules) { throw "No .yar/.yara rules found under $RulesDir. Please add rules first." }
if (-not (Test-Path $TargetPath)) { throw "Scan target does not exist: $TargetPath" }

Write-Host "Recursively scanning $TargetPath with $($rules.Count) rule files ..." -ForegroundColor Cyan
foreach ($r in $rules) {
    Write-Host "`n--- Rule: $($r.Name) ---" -ForegroundColor Gray
    & $YaraExe -r -w $r.FullName $TargetPath
}
Write-Host "`nScan complete." -ForegroundColor Green
