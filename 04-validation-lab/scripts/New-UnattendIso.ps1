#requires -Version 5.1
<#
.SYNOPSIS
  Build a small unattended-install seed ISO (Windows autounattend.xml, or Ubuntu cloud-init
  NoCloud user-data/meta-data) to automate Phase-1 OS provisioning of the lab VMs.

.DESCRIPTION
  Turns the templates in config\unattend into a ready-to-attach ISO by substituting tokens and
  delegating the actual ISO authoring to the proven New-PayloadIso.ps1 (IMAPI2, no ADK/oscdimg,
  no admin). Attach the result as a second DVD so Windows Setup / Ubuntu subiquity auto-detect it:

    Windows : autounattend.xml on a data DVD is auto-detected by Windows Setup.
    Ubuntu  : cloud-init NoCloud requires the seed volume label to be CIDATA (handled here).

  STATUS: provisioning helper for TEMPLATES that must be validated on first real build
  (the Windows {{IMAGE_NAME}} must match an edition in your eval ISO; the Ubuntu password hash
  must be replaced). See docs\05-unattended-provisioning.md.

.PARAMETER Os
  'Windows' or 'Ubuntu'.
.PARAMETER Hostname
  Computer name / hostname to bake in. Defaults: Windows 'CSL-Client01', Ubuntu 'csl-wazuh'.
.PARAMETER ImageName
  (Windows) the /IMAGE/NAME to install from the eval ISO. Default 'Windows 11 Enterprise Evaluation'.
.PARAMETER AdminUser
  (Windows) local administrator account name. Default 'labadmin'.
.PARAMETER AdminPassword
  (Windows) local administrator password as a SecureString. If omitted, a documented throwaway
  lab default is used (CHANGE for anything but a disposable isolated lab).
.PARAMETER TimeZone
  (Windows) time zone id. Default 'UTC'.
.PARAMETER IsoPath
  Output .iso path. Default <IsoRoot>\unattend-<Os>-<Hostname>.iso.
.PARAMETER TemplateDir
  Template root. Default <module>\config\unattend.
.PARAMETER Force
  Overwrite an existing output ISO.
.EXAMPLE
  .\New-UnattendIso.ps1 -Os Ubuntu
.EXAMPLE
  .\New-UnattendIso.ps1 -Os Windows -Hostname CSL-Server -ImageName 'Windows Server 2022 SERVERSTANDARD' -Force
.NOTES
  No admin required. Pure local ISO authoring; does not start any install.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('Windows', 'Ubuntu')][string]$Os,
    [string]$Hostname,
    [string]$ImageName = 'Windows 11 Enterprise Evaluation',
    [string]$AdminUser = 'labadmin',
    [System.Security.SecureString]$AdminPassword,
    [string]$TimeZone = 'UTC',
    [string]$IsoPath,
    [string]$TemplateDir,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib\Common.ps1"

$moduleRoot = Split-Path -Parent $PSScriptRoot
if (-not $TemplateDir) { $TemplateDir = Join-Path $moduleRoot 'config\unattend' }
if (-not $Hostname) { $Hostname = if ($Os -eq 'Windows') { 'CSL-Client01' } else { 'csl-wazuh' } }

Write-Step "Build unattended-install ISO ($Os / $Hostname)"

# Default output path (IsoRoot from config, else module root).
if (-not $IsoPath) {
    try { $isoRoot = (Get-LabConfig).Paths.IsoRoot } catch { $isoRoot = $moduleRoot }
    $IsoPath = Join-Path $isoRoot ("unattend-{0}-{1}.iso" -f $Os.ToLower(), $Hostname)
}

# Stage the rendered answer file(s) in a temp folder, then hand to New-PayloadIso.
$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("cafesec-unattend-{0}" -f ([guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Path $staging -Force | Out-Null
try {
    if ($Os -eq 'Windows') {
        $tpl = Join-Path $TemplateDir 'windows\autounattend-template.xml'
        if (-not (Test-Path -LiteralPath $tpl)) { throw "Missing template: $tpl" }

        if ($AdminPassword) {
            $pwPlain = [System.Net.NetworkCredential]::new('', $AdminPassword).Password
        } else {
            $pwPlain = 'CafeSecLab!2026'
            Write-Warn2 "Using the default lab admin password. Pass -AdminPassword (SecureString) to override."
        }

        $xml = Get-Content -LiteralPath $tpl -Raw
        $xml = $xml -replace '\{\{HOSTNAME\}\}', $Hostname
        $xml = $xml -replace '\{\{IMAGE_NAME\}\}', $ImageName
        $xml = $xml -replace '\{\{ADMIN_USER\}\}', $AdminUser
        $xml = $xml -replace '\{\{ADMIN_PASSWORD\}\}', $pwPlain
        $xml = $xml -replace '\{\{TIMEZONE\}\}', $TimeZone
        if ($xml -match '\{\{[A-Z_]+\}\}') { throw "Unsubstituted token(s) remain in the rendered autounattend.xml." }

        # autounattend.xml must be valid XML before we burn it.
        $null = [xml]$xml
        [System.IO.File]::WriteAllText((Join-Path $staging 'autounattend.xml'), $xml, (New-Object System.Text.UTF8Encoding($false)))
        $volume = 'CAFESEC_UA'
    } else {
        $ud = Join-Path $TemplateDir 'ubuntu\user-data'
        $md = Join-Path $TemplateDir 'ubuntu\meta-data'
        foreach ($p in @($ud, $md)) { if (-not (Test-Path -LiteralPath $p)) { throw "Missing template: $p" } }

        $userData = (Get-Content -LiteralPath $ud -Raw) -replace 'csl-wazuh', $Hostname
        $metaData = (Get-Content -LiteralPath $md -Raw) -replace 'csl-wazuh', $Hostname
        [System.IO.File]::WriteAllText((Join-Path $staging 'user-data'), $userData, (New-Object System.Text.UTF8Encoding($false)))
        [System.IO.File]::WriteAllText((Join-Path $staging 'meta-data'), $metaData, (New-Object System.Text.UTF8Encoding($false)))
        $volume = 'CIDATA'   # required label for cloud-init NoCloud auto-detection
    }

    if ($PSCmdlet.ShouldProcess($IsoPath, "build $Os unattend ISO from $TemplateDir")) {
        $payload = Join-Path $PSScriptRoot 'New-PayloadIso.ps1'
        & $payload -SourceFolder $staging -IsoPath $IsoPath -VolumeName $volume -Force:$Force
    }
} finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Attach during Phase-1 provisioning, e.g.:" -ForegroundColor Cyan
Write-Host ("  Add-VMDvdDrive -VMName $Hostname -Path '$IsoPath'") -ForegroundColor Gray
Write-Host "Then boot the VM from its OS install ISO; the seed ISO is auto-detected." -ForegroundColor Gray
Write-Host "Validate on first build -- see docs\05-unattended-provisioning.md." -ForegroundColor DarkGray
