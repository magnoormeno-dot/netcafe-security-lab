#requires -Version 5.1
<#
.SYNOPSIS
  用 rules\yara 下的所有 YARA 规则扫描指定目录。纯防御:文件特征匹配/取证分诊。
.PARAMETER TargetPath
  要扫描的目录或文件。
.PARAMETER YaraExe
  yara64.exe 路径,默认 downloads\tools\yara64.exe。
.PARAMETER RulesDir
  YARA 规则目录,默认 rules\yara。
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

if (-not (Test-Path $YaraExe)) { throw "找不到 yara64.exe: $YaraExe (先运行 Setup-RuleEngines.ps1)" }
$rules = Get-ChildItem -Path $RulesDir -Recurse -Include *.yar,*.yara -ErrorAction SilentlyContinue
if (-not $rules) { throw "$RulesDir 下没有任何 .yar/.yara 规则。请先放入规则。" }
if (-not (Test-Path $TargetPath)) { throw "扫描目标不存在: $TargetPath" }

Write-Host "用 $($rules.Count) 个规则文件递归扫描 $TargetPath ..." -ForegroundColor Cyan
foreach ($r in $rules) {
    Write-Host "`n--- 规则: $($r.Name) ---" -ForegroundColor Gray
    & $YaraExe -r -w $r.FullName $TargetPath
}
Write-Host "`n扫描完成。" -ForegroundColor Green
