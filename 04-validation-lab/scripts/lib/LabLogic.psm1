<#
  LabLogic.psm1 - Pure, side-effect-free decision logic for the CafeSec validation lab.

  Everything here takes its inputs as parameters (no Hyper-V / AD / network / admin
  calls), so the load-bearing safety logic can be unit-tested on any CI agent without
  a Hyper-V host. The thin top-level scripts gather live state (Get-VM, Get-Service,
  Find-NetRoute, registry...) and pass it into these functions. Imported by Common.ps1.

  Comments are intentionally ASCII-only: this module is dot-imported under Windows
  PowerShell 5.1, which misreads BOM-less non-ASCII as ANSI/GBK.
#>

function Select-IsolationLeakRoute {
    <#
    .SYNOPSIS
      From Find-NetRoute output, return only routes that represent a REAL specific
      path to the isolated subnet (an isolation leak). Excludes default routes (incl.
      /1 split-default), loopback, and IPv6 loopback - which are never evidence of a
      leak and would otherwise produce a false FAIL.
    #>
    [CmdletBinding()]
    param([object[]]$Route)
    $excluded = @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1', '::/0', '::/1', '8000::/1')
    @($Route | Where-Object {
            $_.DestinationPrefix -and
            ($_.DestinationPrefix -notin $excluded) -and
            ($_.DestinationPrefix -notlike '127.*') -and
            ($_.DestinationPrefix -ne '::1/128')
        })
}

function Test-HyperVRebootGate {
    <#
    .SYNOPSIS
      Decide whether Hyper-V still needs a reboot before vmms / New-VMSwitch are usable.
      Returns $true when the orchestrator should pause and ask for a restart.
    #>
    [CmdletBinding()]
    param(
        [string]$VmmsStatus,        # Get-Service vmms .Status as string ('Running'/'Stopped'/'' if absent)
        [bool]$HasSwitchCmdlet,     # whether Get-Command New-VMSwitch resolved
        [bool]$RebootPending        # CBS RebootPending registry key present
    )
    $usable = ($VmmsStatus -eq 'Running') -and $HasSwitchCmdlet
    return ((-not $usable) -or $RebootPending)
}

function Resolve-PhaseSwitch {
    <#
    .SYNOPSIS
      Resolve the target switch name + validation flags for Switch-LabNetwork's
      two-phase model, without touching Hyper-V.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Provisioning', 'Isolated')][string]$Phase,
        [Parameter(Mandatory)][string]$IsolatedSwitch,
        [string]$ProvisioningSwitch
    )
    $target = if ($Phase -eq 'Isolated') { $IsolatedSwitch } else { $ProvisioningSwitch }
    [pscustomobject]@{
        Phase                      = $Phase
        TargetSwitch               = $target
        IsIsolated                 = ($Phase -eq 'Isolated')
        # A provisioning switch equal to the isolated switch is a user error (unroutable).
        ProvisioningEqualsIsolated = ($Phase -eq 'Provisioning' -and $target -eq $IsolatedSwitch)
    }
}

function Test-IsHomeEdition {
    <#
    .SYNOPSIS
      Locale-safe Windows Home detection. Home/Core editions (no Hyper-V) have an
      EditionID starting with 'Core'. Uses EditionID, never the localized Caption.
    #>
    [CmdletBinding()]
    param([string]$EditionId)
    return [bool]($EditionId -match '^Core')
}

function Resolve-LabPathRoot {
    <#
    .SYNOPSIS
      Reproducibility/portability: choose the VM or ISO root path.
      Priority: explicit override (env var) -> configured path if its drive exists ->
      auto-pick the largest-free injected volume. Pure: volumes are passed in.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfiguredPath,  # e.g. 'E:\CafeSec-Lab\VMs'
        [string]$OverridePath,                           # e.g. $env:CAFESEC_VMROOT
        [object[]]$Volume,                               # Get-Volume-like: .DriveLetter, .SizeRemaining
        [string]$LeafName                                # appended on auto-pick, e.g. 'CafeSec-Lab\VMs'
    )
    if (-not [string]::IsNullOrWhiteSpace($OverridePath)) { return $OverridePath }

    $letter = (Split-Path -Qualifier $ConfiguredPath).TrimEnd(':')
    if ($Volume | Where-Object { $_.DriveLetter -eq $letter }) { return $ConfiguredPath }

    $best = $Volume | Where-Object { $_.DriveLetter } | Sort-Object SizeRemaining -Descending | Select-Object -First 1
    if (-not $best) { return $ConfiguredPath }   # nothing better; preflight will FAIL clearly
    if ($LeafName) { return ('{0}:\{1}' -f $best.DriveLetter, $LeafName) }
    return ('{0}:\' -f $best.DriveLetter)
}

function Test-LabSwitchRemovable {
    <#
    .SYNOPSIS
      Safety guard for Reset-Lab: ONLY the configured isolated switch may ever be
      removed. Any other name (NAT/External/Default Switch/...) returns $false.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SwitchName,
        [Parameter(Mandatory)][string]$IsolatedSwitchName
    )
    return ($SwitchName -eq $IsolatedSwitchName)
}

function Select-LabResetVmName {
    <#
    .SYNOPSIS
      The Reset-Lab deletion allowlist rule: intersection of candidate VM names with
      the config's CSL names. A name not in the config is NEVER returned.
    #>
    [CmdletBinding()]
    param(
        [string[]]$ConfigName,
        [string[]]$CandidateName
    )
    @($CandidateName | Where-Object { $ConfigName -contains $_ })
}

function Test-LabArtifactChecksum {
    <#
    .SYNOPSIS
      Verify a downloaded artifact against a pinned SHA-256.
      Returns: $true match | $false missing-file-or-mismatch | $null when no hash is
      pinned (unknown - caller decides whether to warn).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ExpectedSha256
    )
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    if ([string]::IsNullOrWhiteSpace($ExpectedSha256)) { return $null }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    return ($actual -eq $ExpectedSha256.Trim())
}

function Get-LabArtifactManifest {
    <#
    .SYNOPSIS
      Load the pinned-version + checksum manifest (config/versions.psd1) so tool/ISO
      versions are reproducible rather than floating ('master', '4.x').
    #>
    [CmdletBinding()]
    param([string]$ManifestPath)
    if (-not $ManifestPath) {
        $ManifestPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'config\versions.psd1'
    }
    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "Version manifest not found: $ManifestPath"
    }
    return Import-PowerShellDataFile -LiteralPath $ManifestPath
}

Export-ModuleMember -Function @(
    'Select-IsolationLeakRoute',
    'Test-HyperVRebootGate',
    'Resolve-PhaseSwitch',
    'Test-IsHomeEdition',
    'Resolve-LabPathRoot',
    'Test-LabSwitchRemovable',
    'Select-LabResetVmName',
    'Test-LabArtifactChecksum',
    'Get-LabArtifactManifest'
)
