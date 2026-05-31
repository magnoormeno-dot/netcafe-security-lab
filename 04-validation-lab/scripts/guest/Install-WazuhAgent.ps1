#requires -Version 5.1
<#
.SYNOPSIS
  [Run inside the Windows guest/server] Install the Wazuh agent and connect it to the Wazuh manager on the isolated network.
.DESCRIPTION
  Purely defensive: the Wazuh agent reports endpoint security events (including Sysmon and Windows security logs) to the
  Wazuh manager (10.10.10.10) for centralized detection/alerting (open-source SIEM/XDR).
  The isolated network has no internet access, so the wazuh-agent MSI must first be injected via Copy-VMFile or placed in an ISO.
  See docs\downloads.md for the download URL (download it during the [temporary online phase], then deploy offline).
.PARAMETER MsiPath
  Full local path to wazuh-agent-<ver>.msi.
.PARAMETER ManagerIP
  IP of the Wazuh manager; defaults to 10.10.10.10.
.PARAMETER AgentName
  Registration name for this agent; defaults to the computer name.
.EXAMPLE
  .\Install-WazuhAgent.ps1 -MsiPath C:\CafeSec\wazuh-agent-4.9.2-1.msi
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$MsiPath,
    [string]$ManagerIP = '10.10.10.10',
    [string]$AgentName = $env:COMPUTERNAME,
    [System.Security.SecureString]$RegistrationPassword   # Only needed when the manager's authd has a registration password set (SecureString)
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $MsiPath)) { throw "MSI not found: $MsiPath" }

# Materialize the SecureString into plaintext (kept in memory only, discarded after use): both the MSI properties and agent-auth -P accept plaintext only.
$regPwPlain = $null
if ($RegistrationPassword) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($RegistrationPassword)
    try   { $regPwPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

Write-Host "Installing Wazuh agent -> manager $ManagerIP, name $AgentName ..." -ForegroundColor Cyan
# MSI parameters: write the manager and registration server addresses plus the agent name -- Wazuh 4.x uses these to auto-register on first service start.
# Note: do [NOT] use $args for the variable -- it is a PowerShell automatic variable, and reusing it introduces hidden problems.
$msiArgs = "/i `"$MsiPath`" /q WAZUH_MANAGER=`"$ManagerIP`" WAZUH_REGISTRATION_SERVER=`"$ManagerIP`" WAZUH_AGENT_NAME=`"$AgentName`""
if ($regPwPlain) { $msiArgs += " WAZUH_REGISTRATION_PASSWORD=`"$regPwPlain`"" }
$p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
# 0=success; 3010/1641=success but a reboot is required/has been triggered -- all treated as success, not as failures.
if (@(0,3010,1641) -notcontains $p.ExitCode) { throw "msiexec exit code $($p.ExitCode)" }
if (@(3010,1641) -contains $p.ExitCode) { Write-Host "[WARN] MSI install succeeded, but a reboot (exit code $($p.ExitCode)) is required to complete it." -ForegroundColor Yellow }
Write-Host "[ OK ] MSI installation complete." -ForegroundColor Green

# Registration: preferably handled by the MSI's WAZUH_MANAGER/WAZUH_REGISTRATION_SERVER above, which auto-registers on first service start.
# Only when client.keys was not generated do we fall back to the legacy agent-auth.
# Key point: the Wazuh agent is 32-bit and installs under "Program Files (x86)" -- using $env:ProgramFiles would fail to find it and silently skip registration.
$pf86      = ${env:ProgramFiles(x86)}
$ossecBase = if ($pf86 -and (Test-Path (Join-Path $pf86 'ossec-agent\agent-auth.exe'))) { Join-Path $pf86 'ossec-agent' } else { Join-Path $env:ProgramFiles 'ossec-agent' }
$authd     = Join-Path $ossecBase 'agent-auth.exe'
$keyFile   = Join-Path $ossecBase 'client.keys'
$hasKey    = (Test-Path $keyFile) -and ((Get-Item $keyFile -ErrorAction SilentlyContinue).Length -gt 0)
if (-not $hasKey -and (Test-Path $authd)) {
    Write-Host "Fallback: no client.keys found, registering with the manager via agent-auth instead (requires authd enabled on the manager)..." -ForegroundColor Cyan
    $authArgs = @('-m', $ManagerIP, '-A', $AgentName)
    if ($regPwPlain) { $authArgs += @('-P', $regPwPlain) }
    & $authd @authArgs
} elseif (-not (Test-Path $authd)) {
    Write-Host "[WARN] agent-auth.exe not found ($authd). Will rely on the MSI's auto-registration; if authd is not enabled on the manager, pre-generate a key with manage_agents and register manually." -ForegroundColor Yellow
}

# Start the service
Start-Service -Name WazuhSvc -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') { Write-Host "[ OK ] WazuhSvc is running and reporting to $ManagerIP." -ForegroundColor Green }
else { Write-Host "[WARN] WazuhSvc is not running. Check that <server><address> in ossec.conf is $ManagerIP, and confirm registration succeeded." -ForegroundColor Yellow }

Write-Host "`nOn the manager, run  /var/ossec/bin/agent_control -l  to confirm this agent is connected (Active)." -ForegroundColor Gray
