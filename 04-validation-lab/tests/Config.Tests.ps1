# Pester v5 tests for the central config (lab.psd1) loaded via Common.ps1 / Get-LabConfig.
BeforeAll {
    . (Join-Path $PSScriptRoot '..\scripts\lib\Common.ps1')
    $script:cfg = Get-LabConfig
}

Describe 'lab.psd1 via Get-LabConfig' {
    It 'defines exactly the four CSL VMs' {
        $script:cfg.VMs.Count | Should -Be 4
        ($script:cfg.VMs.Name | Sort-Object) | Should -Be @('CSL-Client01', 'CSL-Client02', 'CSL-Server', 'CSL-Wazuh')
    }
    It 'uses a Private isolated switch named CafeSec-Isolated' {
        $script:cfg.Network.SwitchName | Should -Be 'CafeSec-Isolated'
        $script:cfg.Network.SwitchType | Should -Be 'Private'
    }
    It 'keeps every VM IP inside the isolated 10.10.10.0/24 subnet' {
        foreach ($vm in $script:cfg.VMs) { $vm.IP | Should -Match '^10\.10\.10\.\d{1,3}$' }
    }
    It 'has no default gateway (air-gapped by design)' {
        $script:cfg.Network.Gateway | Should -BeNullOrEmpty
    }
    It 'targets the internal cafesec.lab domain' {
        $script:cfg.Domain.Enabled | Should -BeTrue
        $script:cfg.Domain.Fqdn | Should -Be 'cafesec.lab'
    }
    It 'resolves VM/ISO roots to a CafeSec-Lab path on some drive (portable across hosts)' {
        $script:cfg.Paths.VmRoot | Should -Match 'CafeSec-Lab[\\/]VMs$'
        $script:cfg.Paths.IsoRoot | Should -Match 'CafeSec-Lab[\\/]ISO$'
    }
    It 'keeps total static VM memory within a 64GB host budget' {
        ($script:cfg.VMs.MemoryGB | Measure-Object -Sum).Sum | Should -BeLessOrEqual 32
    }
}

Describe 'Get-LabConfig path resolution (wired end-to-end)' {
    It 'honors the CAFESEC_VMROOT / CAFESEC_ISOROOT environment overrides' {
        $env:CAFESEC_VMROOT = 'Q:\custom-vmroot'
        $env:CAFESEC_ISOROOT = 'Q:\custom-isoroot'
        try {
            $c = Get-LabConfig
            $c.Paths.VmRoot | Should -Be 'Q:\custom-vmroot'
            $c.Paths.IsoRoot | Should -Be 'Q:\custom-isoroot'
        } finally {
            Remove-Item Env:\CAFESEC_VMROOT, Env:\CAFESEC_ISOROOT -ErrorAction SilentlyContinue
        }
    }
}
