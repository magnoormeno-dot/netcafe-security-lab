#
# PSScriptAnalyzer settings for 04-validation-lab.
# Invoked by .github/workflows/validation-lab-lint.yml.
# (ASCII-only on purpose: this file is parsed by tooling, so it must not depend on BOM/encoding.)
#
@{
    # Gate on Warning as well as Error to keep script quality high.
    Severity = @('Error', 'Warning')

    # Only exclusion: these are interactive operational scripts where colored console
    # progress/result output is intentional, so Write-Host is the correct tool (they are
    # not a function library and do not return objects to the pipeline). Every other rule
    # stays on -- including PSAvoidUsingComputerNameHardcoded (the isolation egress-probe
    # targets are now parameters, not hardcoded literals).
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
    )
}
