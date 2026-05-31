# Local Sigma overlay (lab-only)

The **source of truth** for rules is
[`../../../01-hardening-checklist/detection/sigma`](../../../01-hardening-checklist/detection/sigma).
`scripts\analysis\Invoke-RuleValidation.ps1` consumes those rules in place (it does **not** copy them).

This directory is only for **lab-specific** throwaway/experimental Sigma rules (e.g. a draft written to
reproduce a local behavior). Do not copy the repo's rules here; submit real rules to
`01-hardening-checklist/detection/sigma`.
