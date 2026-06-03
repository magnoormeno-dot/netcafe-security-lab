# Pester v5 unit tests for LabLogic.psm1 (pure decision logic, no Hyper-V required).
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\scripts\lib\LabLogic.psm1') -Force
}

Describe 'Select-IsolationLeakRoute' {
    It 'returns a specific /32 route to the isolated subnet as a leak' {
        $routes = @([pscustomobject]@{ DestinationPrefix = '10.10.10.10/32' })
        (Select-IsolationLeakRoute -Route $routes).DestinationPrefix | Should -Be '10.10.10.10/32'
    }
    It 'excludes default, split-default, loopback and IPv6 loopback routes' {
        $routes = @(
            [pscustomobject]@{ DestinationPrefix = '0.0.0.0/0' },
            [pscustomobject]@{ DestinationPrefix = '0.0.0.0/1' },
            [pscustomobject]@{ DestinationPrefix = '128.0.0.0/1' },
            [pscustomobject]@{ DestinationPrefix = '::/0' },
            [pscustomobject]@{ DestinationPrefix = '::/1' },
            [pscustomobject]@{ DestinationPrefix = '8000::/1' },
            [pscustomobject]@{ DestinationPrefix = '127.0.0.1/32' },
            [pscustomobject]@{ DestinationPrefix = '::1/128' }
        )
        Select-IsolationLeakRoute -Route $routes | Should -BeNullOrEmpty
    }
    It 'ignores objects with an empty DestinationPrefix (the Find-NetRoute source NetIPAddress)' {
        $routes = @([pscustomobject]@{ DestinationPrefix = $null }, [pscustomobject]@{ DestinationPrefix = '' })
        Select-IsolationLeakRoute -Route $routes | Should -BeNullOrEmpty
    }
    It 'returns empty for empty input' {
        Select-IsolationLeakRoute -Route @() | Should -BeNullOrEmpty
    }
}

Describe 'Test-HyperVRebootGate' {
    It 'no reboot needed when vmms Running, cmdlet present, nothing pending' {
        Test-HyperVRebootGate -VmmsStatus 'Running' -HasSwitchCmdlet $true -RebootPending $false | Should -BeFalse
    }
    It 'reboot needed when a reboot is pending even if otherwise usable' {
        Test-HyperVRebootGate -VmmsStatus 'Running' -HasSwitchCmdlet $true -RebootPending $true | Should -BeTrue
    }
    It 'reboot needed when vmms is not Running' {
        Test-HyperVRebootGate -VmmsStatus 'Stopped' -HasSwitchCmdlet $true -RebootPending $false | Should -BeTrue
    }
    It 'reboot needed when the New-VMSwitch cmdlet is missing (module not loaded yet)' {
        Test-HyperVRebootGate -VmmsStatus '' -HasSwitchCmdlet $false -RebootPending $false | Should -BeTrue
    }
}

Describe 'Resolve-PhaseSwitch' {
    It 'Isolated phase targets the isolated switch' {
        $r = Resolve-PhaseSwitch -Phase 'Isolated' -IsolatedSwitch 'CafeSec-Isolated' -ProvisioningSwitch 'CafeSec-NAT'
        $r.TargetSwitch | Should -Be 'CafeSec-Isolated'
        $r.IsIsolated | Should -BeTrue
        $r.ProvisioningEqualsIsolated | Should -BeFalse
    }
    It 'Provisioning phase targets the provisioning switch' {
        $r = Resolve-PhaseSwitch -Phase 'Provisioning' -IsolatedSwitch 'CafeSec-Isolated' -ProvisioningSwitch 'CafeSec-NAT'
        $r.TargetSwitch | Should -Be 'CafeSec-NAT'
        $r.IsIsolated | Should -BeFalse
    }
    It 'flags the footgun of using the isolated switch as a provisioning switch' {
        $r = Resolve-PhaseSwitch -Phase 'Provisioning' -IsolatedSwitch 'CafeSec-Isolated' -ProvisioningSwitch 'CafeSec-Isolated'
        $r.ProvisioningEqualsIsolated | Should -BeTrue
    }
}

Describe 'Test-IsHomeEdition' {
    It 'detects Home/Core editions by EditionID' {
        Test-IsHomeEdition -EditionId 'Core' | Should -BeTrue
        Test-IsHomeEdition -EditionId 'CoreSingleLanguage' | Should -BeTrue
    }
    It 'does not flag Hyper-V-capable editions' {
        Test-IsHomeEdition -EditionId 'Professional' | Should -BeFalse
        Test-IsHomeEdition -EditionId 'Enterprise' | Should -BeFalse
        Test-IsHomeEdition -EditionId 'ServerStandard' | Should -BeFalse
        Test-IsHomeEdition -EditionId '' | Should -BeFalse
    }
}

Describe 'Resolve-LabPathRoot' {
    It 'honors an explicit override above everything else' {
        $v = @([pscustomobject]@{ DriveLetter = 'E'; SizeRemaining = 100GB })
        Resolve-LabPathRoot -ConfiguredPath 'E:\CafeSec-Lab\VMs' -OverridePath 'X:\custom' -Volume $v -LeafName 'CafeSec-Lab\VMs' | Should -Be 'X:\custom'
    }
    It 'keeps the configured path when its drive exists' {
        $v = @([pscustomobject]@{ DriveLetter = 'E'; SizeRemaining = 100GB })
        Resolve-LabPathRoot -ConfiguredPath 'E:\CafeSec-Lab\VMs' -Volume $v -LeafName 'CafeSec-Lab\VMs' | Should -Be 'E:\CafeSec-Lab\VMs'
    }
    It 'auto-relocates to the largest free volume when the configured drive is absent' {
        $v = @(
            [pscustomobject]@{ DriveLetter = 'C'; SizeRemaining = 100GB },
            [pscustomobject]@{ DriveLetter = 'D'; SizeRemaining = 500GB }
        )
        Resolve-LabPathRoot -ConfiguredPath 'E:\CafeSec-Lab\VMs' -Volume $v -LeafName 'CafeSec-Lab\VMs' | Should -Be 'D:\CafeSec-Lab\VMs'
    }
    It 'falls back to the configured path when no volumes are available' {
        Resolve-LabPathRoot -ConfiguredPath 'E:\CafeSec-Lab\VMs' -Volume @() -LeafName 'CafeSec-Lab\VMs' | Should -Be 'E:\CafeSec-Lab\VMs'
    }
}

Describe 'Test-LabSwitchRemovable' {
    It 'allows removing only the configured isolated switch' {
        Test-LabSwitchRemovable -SwitchName 'CafeSec-Isolated' -IsolatedSwitchName 'CafeSec-Isolated' | Should -BeTrue
    }
    It 'refuses any other switch (NAT/External/Default)' {
        Test-LabSwitchRemovable -SwitchName 'CafeSec-NAT' -IsolatedSwitchName 'CafeSec-Isolated' | Should -BeFalse
        Test-LabSwitchRemovable -SwitchName 'Default Switch' -IsolatedSwitchName 'CafeSec-Isolated' | Should -BeFalse
    }
}

Describe 'Select-LabResetVmName' {
    It 'returns only candidates that are in the config allowlist' {
        Select-LabResetVmName -ConfigName @('CSL-A', 'CSL-B') -CandidateName @('CSL-A', 'CSL-B', 'CSL-C') |
            Should -Be @('CSL-A', 'CSL-B')
    }
    It 'never returns a non-CSL VM even if present on the host' {
        Select-LabResetVmName -ConfigName @('CSL-A') -CandidateName @('ProdDC01', 'CSL-A', 'MyHomeVM') |
            Should -Be @('CSL-A')
    }
    It 'returns empty when nothing matches' {
        Select-LabResetVmName -ConfigName @('CSL-A') -CandidateName @('Other') | Should -BeNullOrEmpty
    }
}

Describe 'Test-LabArtifactChecksum' {
    BeforeAll {
        $script:tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("cafesec-test-{0}.bin" -f ([guid]::NewGuid().ToString('N')))
        Set-Content -LiteralPath $script:tmp -Value 'cafesec-checksum-fixture' -Encoding Ascii
        $script:realHash = (Get-FileHash -LiteralPath $script:tmp -Algorithm SHA256).Hash
    }
    AfterAll {
        Remove-Item -LiteralPath $script:tmp -Force -ErrorAction SilentlyContinue
    }
    It 'returns true when the hash matches (case-insensitive)' {
        Test-LabArtifactChecksum -Path $script:tmp -ExpectedSha256 $script:realHash.ToLower() | Should -BeTrue
    }
    It 'returns false when the hash does not match' {
        Test-LabArtifactChecksum -Path $script:tmp -ExpectedSha256 ('0' * 64) | Should -BeFalse
    }
    It 'returns false when the file is missing' {
        Test-LabArtifactChecksum -Path 'Z:\does\not\exist.bin' -ExpectedSha256 $script:realHash | Should -BeFalse
    }
    It 'returns null when no hash is pinned (unknown)' {
        Test-LabArtifactChecksum -Path $script:tmp -ExpectedSha256 '' | Should -BeNullOrEmpty
    }
}

Describe 'Get-LabArtifactManifest' {
    It 'throws when the manifest is missing' {
        { Get-LabArtifactManifest -ManifestPath 'Z:\no\versions.psd1' } | Should -Throw
    }
    It 'loads a manifest psd1 when present' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("cafesec-manifest-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
        Set-Content -LiteralPath $tmp -Value "@{ Sysmon = @{ Version = '15.15' } }" -Encoding Ascii
        try {
            (Get-LabArtifactManifest -ManifestPath $tmp).Sysmon.Version | Should -Be '15.15'
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}
