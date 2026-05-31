# Local YARA overlay (lab-only)

The **source of truth** for rules is
[`../../../01-hardening-checklist/detection/yara`](../../../01-hardening-checklist/detection/yara).
`scripts\analysis\Invoke-RuleValidation.ps1` (compile check) and `scripts\analysis\Invoke-YaraScan.ps1`
(scan) can both point there; they do **not** copy the rules.

This directory is only for **lab-specific** throwaway/experimental YARA rules. Submit real rules to
`01-hardening-checklist/detection/yara`.
