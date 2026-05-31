#requires -Version 5.1
<#
.SYNOPSIS
  CafeSec Lab host-side one-click orchestration: runs host scripts 00->04 in order (preflight -> enable Hyper-V -> create isolated switch
  -> create VMs -> host-side isolation verification), automatically handles the reboot gate after enabling Hyper-V, and prints follow-up guidance for in-VM / domain steps at the end.

.DESCRIPTION
  This script only orchestrates the [host-side] steps that can be automated. In-VM steps (installing the OS, configuring static IPs, promoting the domain controller / joining the domain,
  deploying Sysmon/Wazuh/WEF, the rule engines) cannot be run from the host on your behalf -- at the end it lists the checklist and documentation pointers.

  Design:
    * Each substep runs in an [isolated powershell.exe child process] -- this isolates `exit` inside substeps (e.g. 04 uses exit $fail),
      preventing them from terminating this orchestration session; success/failure is determined from the child process ExitCode. Substep output is displayed live in this console.
    * Idempotent: all substeps can be run repeatedly; when enabling Hyper-V requires a reboot, this script stops, and running it again after the reboot resumes from where it left off.
    * Safety: -DryRun only prints the plan without executing (and does not require administrator); a failed hard step stops immediately; destructive operations are not part of this script.

.PARAMETER StartAt
  Starting step number (0-4), default 0. After a reboot you can use -StartAt 2 to skip completed steps (re-running directly is also safe, since substeps are idempotent).
.PARAMETER StopAt
  Ending step number (0-4), default 4.
.PARAMETER DryRun
  Only prints the steps and commands that would be executed, without actually running any substep (no administrator required, good for a preview first).
.PARAMETER VmWhatIf
  Passes -WhatIf to step 3 (create VMs), only previewing the VMs that would be created without actually creating them.
.PARAMETER NoPrompt
  Non-interactive: skips the confirmation before starting.
.EXAMPLE
  .\Invoke-LabSetup.ps1 -DryRun          # Review the plan first (no administrator required)
.EXAMPLE
  .\Invoke-LabSetup.ps1                   # Actually orchestrate 00->04 as administrator
.EXAMPLE
  .\Invoke-LabSetup.ps1 -StartAt 2        # After the Hyper-V enable reboot, resume from "create switch"
.NOTES
  Actual execution requires administrator (except -DryRun). This script only covers the host side; for the domain / defense stack see sections D-G of the README and docs\03.
#>
[CmdletBinding()]
param(
    [ValidateRange(0,4)][int]$StartAt = 0,
    [ValidateRange(0,4)][int]$StopAt  = 4,
    [switch]$DryRun,
    [switch]$VmWhatIf,
    [switch]$NoPrompt
)
. "$PSScriptRoot\lib\Common.ps1"

# Run a host script in an isolated child process: isolate its exit, capture the ExitCode, pass output straight through to the console.
function Invoke-HostStep {
    param(
        [int]$Num,
        [string]$Title,
        [string]$ScriptName,
        [string[]]$ScriptArgs = @()
    )
    $path = Join-Path $PSScriptRoot $ScriptName
    Write-Host ""
    Write-Host ("===== Step {0} / {1} =====" -f $Num, $Title) -ForegroundColor Magenta
    Write-Host ("  -> {0} {1}" -f $ScriptName, ($ScriptArgs -join ' ')) -ForegroundColor DarkGray
    if (-not (Test-Path $path)) { Write-Fail "Script not found: $path"; return 1 }
    if ($DryRun) { Write-Warn2 "  [DryRun] Not actually executing."; return 0 }

    $argLine = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $path
    if ($ScriptArgs.Count) { $argLine += ' ' + ($ScriptArgs -join ' ') }
    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argLine -NoNewWindow -Wait -PassThru
    if ($null -ne $p.ExitCode) { return [int]$p.ExitCode } else { return 0 }
}

# DryRun requires no administrator (preview only); only actual execution requires administrator.
if (-not $DryRun) { Assert-Admin }
Get-LabConfig | Out-Null   # Validate up front that lab.psd1 can be loaded (each substep reads it again on its own at runtime)

Write-Step "CafeSec Lab host-side orchestration (Invoke-LabSetup)"
Write-Host ("Range: step {0} -> {1}{2}" -f $StartAt, $StopAt, $(if ($DryRun) { '   [DryRun]' } else { '' })) -ForegroundColor Gray
if ($StartAt -gt $StopAt) { Write-Fail "StartAt($StartAt) is greater than StopAt($StopAt)."; return }

# ---- Mandatory prerequisite checks (locale-safe; stop immediately if unmet) ----
$edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
if ($edition -match '^Core') {
    Write-Fail "This is the Home edition ($edition), which does not include Hyper-V. Pro/Enterprise/Education/Server is required."
    return
}
$hvPresent = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
$vtFw = (Get-CimInstance Win32_Processor | Select-Object -First 1).VirtualizationFirmwareEnabled
if (-not ($hvPresent -or $vtFw)) {
    Write-Fail "Virtualization (VT-x) not detected. Enable Intel VT-x in the BIOS/UEFI and retry."
    return
}
Write-Ok ("Prerequisite checks passed: EditionID={0}, HypervisorPresent={1}" -f $edition, $hvPresent)

# ---- Step plan ----
$vmArgs = if ($VmWhatIf) { @('-WhatIf') } else { @() }
$steps = @(
    @{ Num = 0; Title = 'Preflight (read-only)';        Script = '00-Preflight-Check.ps1';   Args = @();           Advisory = $true;  RebootGate = $false }
    @{ Num = 1; Title = 'Enable Hyper-V';        Script = '01-Enable-HyperV.ps1';     Args = @('-NoPrompt');Advisory = $false; RebootGate = $true  }
    @{ Num = 2; Title = 'Create isolated private switch';     Script = '02-New-IsolatedSwitch.ps1';Args = @();           Advisory = $false; RebootGate = $false }
    @{ Num = 3; Title = 'Create 4 lab VMs';     Script = '03-New-LabVMs.ps1';        Args = $vmArgs;       Advisory = $false; RebootGate = $false }
    @{ Num = 4; Title = 'Host-side isolation verification';       Script = '04-Verify-Isolation.ps1';  Args = @();           Advisory = $true;  RebootGate = $false }
)

# Print the plan
Write-Host "`nWill orchestrate in order (host side only):" -ForegroundColor Cyan
$steps | Where-Object { $_.Num -ge $StartAt -and $_.Num -le $StopAt } |
    ForEach-Object { Write-Host ("  [{0}] {1}  ({2})" -f $_.Num, $_.Title, $_.Script) -ForegroundColor Gray }

if (-not $NoPrompt -and -not $DryRun) {
    $ans = Read-Host "`nStart execution? [y/N]"
    if ($ans -notmatch '^(y|Y)') { Write-Warn2 "Cancelled."; return }
}

# ---- Execution ----
$results = @()
foreach ($s in $steps) {
    if ($s.Num -lt $StartAt -or $s.Num -gt $StopAt) { continue }

    $code = Invoke-HostStep -Num $s.Num -Title $s.Title -ScriptName $s.Script -ScriptArgs $s.Args
    $ok = ($code -eq 0)
    $status = if ($ok) { 'OK' } elseif ($s.Advisory) { 'WARN' } else { 'FAIL' }
    $results += [pscustomobject]@{ Step = $s.Num; Title = $s.Title; ExitCode = $code; Status = $status }

    # Hyper-V reboot gate: after enabling, creating the switch/VMs depends on the vmms service running + the Hyper-V module being ready.
    if ($s.RebootGate -and -not $DryRun) {
        $vmms = Get-Service vmms -ErrorAction SilentlyContinue
        $usable = $vmms -and $vmms.Status -eq 'Running' -and (Get-Command New-VMSwitch -ErrorAction SilentlyContinue)
        $rebootPending = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        if (-not $usable -or $rebootPending) {
            Write-Host ""
            Write-Warn2 "Hyper-V is enabled, but a [reboot] is required before continuing (the vmms service / Hyper-V module is not ready yet)."
            Write-Host  "Reboot this machine, then re-run (substeps are idempotent and will automatically skip completed steps):" -ForegroundColor Yellow
            Write-Host  "    .\Invoke-LabSetup.ps1            # or   .\Invoke-LabSetup.ps1 -StartAt 2" -ForegroundColor Yellow
            Write-Step "Paused at the reboot gate"
            $results | Format-Table Step, Title, ExitCode, Status -AutoSize
            return
        }
        Write-Ok "Hyper-V is ready (vmms running), continuing."
    }

    # Hard step failure -> stop; advisory step failure -> warn only and continue.
    if (-not $ok -and -not $s.Advisory) {
        Write-Host ""
        Write-Fail "Step $($s.Num) ($($s.Title)) failed (ExitCode=$code). Orchestration stopped; investigate and re-run."
        break
    }
    if (-not $ok -and $s.Advisory) {
        Write-Warn2 "Step $($s.Num) ($($s.Title)) returned non-zero (ExitCode=$code); this step is advisory, continuing."
    }
}

# ---- Summary ----
Write-Step "Orchestration summary"
$results | Format-Table Step, Title, ExitCode, Status -AutoSize

if ($DryRun) {
    Write-Warn2 "DryRun complete: the above is the plan, no changes were made. Remove -DryRun and run as administrator to actually orchestrate."
}

# ---- Follow-up steps (in-VM / domain -- cannot be run from the host on your behalf) ----
Write-Step "Follow-up steps (in-VM / domain)"
Write-Host @'
Once the host-side scaffolding is in place (isolated switch + 4 VMs), continue per sections D-G of the README:

  Phase one (temporary network connectivity to install the OS/tools):
    .\Switch-LabNetwork.ps1 -Phase Provisioning -ProvisioningSwitch <your NAT switch>
    - Power on each machine and install the OS; per docs\downloads.md download and install Sysmon / Wazuh agent / tools
    - For offline tool injection you can use .\New-PayloadIso.ps1 to package them into an ISO

  Build the domain (see docs\03-domain-and-wef.md):
    CSL-Server:  .\domain\Install-DomainController.ps1 -SafeModePassword (Read-Host -AsSecureString)
                 After reboot:  .\domain\Set-DcDnsAirgap.ps1
    Clients:      .\domain\Join-LabDomain.ps1 -DomainCredential (Get-Credential CAFESEC\Administrator)

  Defense stack:
    Ubuntu:      bash scripts/wazuh/install-wazuh-manager.sh
    Windows:     guest\Deploy-Sysmon.ps1  /  guest\Install-WazuhAgent.ps1
    Domain controller:        guest\Configure-WEC-Collector.ps1  ->  domain\New-WefGpo.ps1
    Analysis side:      analysis\Setup-RuleEngines.ps1

  Phase two (lock down isolation and verify):
    .\Switch-LabNetwork.ps1 -Phase Isolated
    Configure a static IP on each VM (domain members add -DnsServer 10.10.10.20; the domain controller -DnsServer 127.0.0.1)
    Host side:  .\04-Verify-Isolation.ps1
    Inside each VM: Windows -> guest\Test-GuestIsolation.ps1 ; Ubuntu -> wazuh/test-guest-isolation.sh
    >> Isolation is compliant only when both the host side and the client side fully PASS; only then may research proceed. <<
'@ -ForegroundColor Gray
