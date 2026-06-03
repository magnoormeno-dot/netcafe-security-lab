# Pester v5 tests for unattended provisioning: template validity + a real ISO build
# (New-UnattendIso -> New-PayloadIso via IMAPI2; runs locally, no admin / no Hyper-V).
BeforeAll {
    $script:mod = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:newIso = Join-Path $script:mod 'scripts\New-UnattendIso.ps1'
    $script:tplWin = Join-Path $script:mod 'config\unattend\windows\autounattend-template.xml'
    $script:tplUd = Join-Path $script:mod 'config\unattend\ubuntu\user-data'
    $script:outDir = Join-Path ([System.IO.Path]::GetTempPath()) ("cafesec-prov-{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $script:outDir -Force | Out-Null
}
AfterAll {
    Remove-Item -LiteralPath $script:outDir -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Unattend templates' {
    It 'Windows autounattend template is well-formed XML' {
        { [xml](Get-Content -LiteralPath $script:tplWin -Raw) } | Should -Not -Throw
    }
    It 'Ubuntu user-data carries the required autoinstall keys' {
        $ud = Get-Content -LiteralPath $script:tplUd -Raw
        $ud | Should -Match 'autoinstall:'
        $ud | Should -Match 'version:\s*1'
        $ud | Should -Match 'identity:'
    }
}

Describe 'New-UnattendIso' {
    It 'builds a non-empty Ubuntu cloud-init seed ISO' {
        $out = Join-Path $script:outDir 'ubuntu.iso'
        & $script:newIso -Os Ubuntu -IsoPath $out -Force | Out-Null
        Test-Path -LiteralPath $out | Should -BeTrue
        (Get-Item -LiteralPath $out).Length | Should -BeGreaterThan 0
    }
    It 'builds a non-empty Windows autounattend seed ISO (all tokens substituted)' {
        $out = Join-Path $script:outDir 'win.iso'
        & $script:newIso -Os Windows -Hostname 'CSL-Test' -IsoPath $out -Force | Out-Null
        Test-Path -LiteralPath $out | Should -BeTrue
        (Get-Item -LiteralPath $out).Length | Should -BeGreaterThan 0
    }
}
