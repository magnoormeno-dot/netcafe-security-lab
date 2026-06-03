# Pester v5 integration tests for the CVP evidence generator (no admin / no Hyper-V).
BeforeAll {
    $script:gen = (Resolve-Path (Join-Path $PSScriptRoot '..\scripts\analysis\Export-CvpEvidence.ps1')).Path
    $script:outDir = Join-Path ([System.IO.Path]::GetTempPath()) ("cafesec-evid-{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $script:outDir -Force | Out-Null
}
AfterAll {
    Remove-Item -LiteralPath $script:outDir -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Export-CvpEvidence -Stub' {
    BeforeAll {
        $script:stubOut = Join-Path $script:outDir 'stub.md'
        & $script:gen -Stub -OutputPath $script:stubOut | Out-Null
        $script:stub = Get-Content -LiteralPath $script:stubOut -Raw
    }
    It 'writes the evidence file' {
        Test-Path -LiteralPath $script:stubOut | Should -BeTrue
    }
    It 'carries the do-not-cite STUB banner' {
        $script:stub | Should -Match 'STATUS: STUB'
        $script:stub | Should -Match 'DO NOT CITE'
    }
    It 'states the synthetic / not-field-validated safety boundary' {
        $script:stub | Should -Match '## Scope & safety boundary'
        $script:stub | Should -Match 'synthetic and reproducible'
        $script:stub | Should -Match 'Not field-validated'
        $script:stub | Should -Match 'No production, test-net, or third-party probing'
        $script:stub | Should -Match 'defensive workflows only'
    }
    It 'includes the reviewer gate' {
        $script:stub | Should -Match 'Reviewer gate'
    }
    It 'leaves result rows pending (no real data yet)' {
        $script:stub | Should -Match 'pending'
    }
}

Describe 'Export-CvpEvidence from a rule-validation report (.jsonl)' {
    BeforeAll {
        $script:jsonl = Join-Path $script:outDir 'rule-validation-test.jsonl'
        $rows = @(
            '{"kind":"sigma","rule":"billing_process_termination.yml","ok":true,"detail":"converted"}',
            '{"kind":"sigma","rule":"broken_rule.yml","ok":false,"detail":"convert error"}',
            '{"kind":"yara","rule":"generic_memory_scanner.yar","ok":true,"detail":"compiled"}'
        )
        Set-Content -LiteralPath $script:jsonl -Value $rows -Encoding Ascii
        $script:popOut = Join-Path $script:outDir 'populated.md'
        & $script:gen -ReportPath $script:jsonl -OutputPath $script:popOut | Out-Null
        $script:pop = Get-Content -LiteralPath $script:popOut -Raw
    }
    It 'renders the Sigma pass/fail summary from the report (1 pass, 1 fail)' {
        $script:pop | Should -Match '\|\s*Sigma -> opensearch convert\s*\|\s*1\s*\|\s*1\s*\|'
    }
    It 'renders the YARA pass/fail summary from the report (1 pass, 0 fail)' {
        $script:pop | Should -Match '\|\s*YARA compile\s*\|\s*1\s*\|\s*0\s*\|'
    }
    It 'lists each rule with its result' {
        $script:pop | Should -Match 'billing_process_termination\.yml'
        $script:pop | Should -Match 'generic_memory_scanner\.yar'
    }
    It 'does NOT carry the STUB banner once real data is present' {
        $script:pop | Should -Not -Match 'STATUS: STUB'
    }
    It 'still carries the safety boundary and reviewer gate' {
        $script:pop | Should -Match '## Scope & safety boundary'
        $script:pop | Should -Match 'Reviewer gate'
    }
}
