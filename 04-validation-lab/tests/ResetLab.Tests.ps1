# Pester v5 structural safety tests for Reset-Lab.ps1 (the most destructive script).
# These lock in the load-bearing safety properties so a future edit cannot silently
# widen the blast radius. The deletion-scoping *logic* itself is unit-tested in
# LabLogic.Tests.ps1 (Select-LabResetVmName / Test-LabSwitchRemovable).
BeforeAll {
    $script:resetPath = (Resolve-Path (Join-Path $PSScriptRoot '..\scripts\Reset-Lab.ps1')).Path
    $script:resetText = Get-Content -LiteralPath $script:resetPath -Raw
}

Describe 'Reset-Lab safety wiring' {
    It 'guards switch removal with the Test-LabSwitchRemovable allowlist' {
        $script:resetText | Should -Match 'Test-LabSwitchRemovable'
    }
    It 'has exactly one Remove-VMSwitch call, bound to the config-derived target' {
        ([regex]::Matches($script:resetText, 'Remove-VMSwitch')).Count | Should -Be 1
        $script:resetText | Should -Match 'Remove-VMSwitch -Name \$targetSwitch\.Name'
    }
    It 'derives deletion targets only from the config CSL VM list' {
        $script:resetText | Should -Match '\$cslNames\s*=\s*@\(\$cfg\.VMs'
    }
    It 'wraps every destructive op (Remove-VM / VHDX / switch) in try/catch for resilient teardown' {
        ([regex]::Matches($script:resetText, 'try \{')).Count | Should -BeGreaterOrEqual 3
    }
    It 'requires explicit confirmation (typed DELETE or -Force) before any deletion' {
        $script:resetText | Should -Match "-cne 'DELETE'"
        $script:resetText | Should -Match '\$Force'
    }
    It 'documents that NAT/External switches are preserved (never deleted)' {
        $script:resetText | Should -Match 'NAT/External'
    }
}
