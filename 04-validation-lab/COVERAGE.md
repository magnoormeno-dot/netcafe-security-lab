# Coverage Matrix — what the validation lab actually validates

This module is the reproducible testbed for the rest of the repository. The tables below map
the project's **detection rules** (`01-hardening-checklist/detection/`) and **hardening checklist
items** (`01-hardening-checklist/checklist/`) to the lab telemetry, scripts, and verification steps
that exercise them.

**Honesty note.** Status labels describe what the lab can *demonstrate / validate in a synthetic,
reproducible environment* — not field-validated production results. Per the repo's
"What This Project Will Not Publish" policy, lab output must be human-reviewed before it is cited as
evidence in `docs/cvp/` or `docs/pilot/`.

Status legend: **✅ validated** (lab generates the telemetry and the rule/monitor can be exercised end-to-end) ·
**◐ partial** (lab demonstrates the principle at single-host scale; full venue scope needs physical VLANs/firewall) ·
**○ out-of-lab** (depends on physical network gear the single-host lab does not model).

---

## A. Detection rules → lab telemetry & validation

The lab enables the exact event sources these rules query: Sysmon (`guest\Deploy-Sysmon.ps1`),
Windows Security auditing incl. **4688 process-creation with command line** (audit-policy GPO,
`docs/03-domain-and-wef.md`), PowerShell 4104, service events 7045/7040, and central collection via
WEF (`ForwardedEvents`) + Wazuh.

| Rule (`01-hardening-checklist/detection/`) | Required telemetry | Lab source | Validate with | Status |
| --- | --- | --- | --- | --- |
| `sigma/billing_process_termination.yml` | `process_creation` (Image, CommandLine, ParentImage) | Sysmon EID 1 + Security 4688 (+cmdline) | `Invoke-RuleValidation.ps1` (convert) → run a benign control-process stop **inside** the lab → confirm hit in Wazuh/ForwardedEvents | ✅ |
| `sigma/critical_service_disabled.yml` | service stop/disable (7036/7040/7045) | System/Security + Sysmon; WEF subscription already selects 7045/7040 | `Invoke-RuleValidation.ps1` → `Stop-Service`/`sc config start=disabled` on a lab test service | ✅ |
| `sigma/anomalous_registry_modification.yml` | registry set/rename (Sysmon EID 12/13/14) | Sysmon (SwiftOnSecurity base covers registry) | `Invoke-RuleValidation.ps1` → controlled registry write to a watched key | ✅ |
| `yara/unsigned_injector_patterns.yar` | file/memory bytes | files on a lab VM | `Invoke-RuleValidation.ps1` (compile) + `Invoke-YaraScan.ps1 -TargetPath …` | ✅ |
| `yara/suspicious_packer_traits.yar` | file bytes | files on a lab VM | same as above | ✅ |
| `yara/generic_memory_scanner.yar` | process memory | lab VM process memory | compile-check now; live memory scan needs YARA on a running VM | ◐ |

> The Sigma rule `billing_process_termination.yml` already lists *"Lab validation of the incident
> response playbook"* as an expected false-positive — this module is that lab.

## B. Integrity monitor (`02-integrity-monitor`) → lab

| Capability | Lab realization | Status |
| --- | --- | --- |
| File baseline + drift (`baseline`/`scan`/`verify`) | `guest\Deploy-IntegrityMonitor.ps1` installs the tool into a lab Windows VM and baselines a billing-like path (`C:\CafeBilling`) | ✅ |
| Process anomaly checks (unsigned/writable-dir/parent-child) | runs against real lab processes instead of `tests/fixtures/sample_events.json` | ✅ |
| Windows event-log analysis (logon/process/service/registry/log-clear) | consumes the lab's real Security/Sysmon logs | ✅ |
| Webhook alerting | point `--webhook` at the lab Wazuh/collector | ◐ |

## C. Hardening checklist → lab

The single-host Hyper-V lab models the **principles and the verification methodology**; full venue
VLAN/firewall items are physical-network scope. The lab's strongest checklist contribution is the
**Log & Monitoring plane** and the **isolation-verification methodology**.

| Checklist item | Lab implementation / validation | Status |
| --- | --- | --- |
| `03-network-isolation` **NI-14** log denied/critical traffic; **Log VLAN** | WEF (`Configure-WEC-Collector` + GPO) + Wazuh = the project's "Log & Monitoring VLAN", realized | ✅ |
| `03-network-isolation` verification methodology (the "Verification:" lines) | `04-Verify-Isolation.ps1` + `guest\Test-GuestIsolation.ps1` + `wazuh\test-guest-isolation.sh` operationalize the checklist's verify steps (IPv4/IPv6 egress, route, DNS) | ✅ |
| `03-network-isolation` **NI-05 / NI-11 / NI-19** client cannot reach server mgmt (SMB/RDP/WinRM/DB) | demonstrated at host scale: Private switch + isolation verifier prove clients reach neither host nor internet; WEF WinRM path is the one *intended* allow | ◐ |
| `03-network-isolation` **NI-02/03/04** VLAN zones, policy-enforcement, deny-by-default | principle demonstrated (isolated segment, no convenience path); real multi-VLAN + firewall = venue gear | ○ |
| `03-network-isolation` **NI-28/31** controlled DNS, no internal-name leak | `domain\Set-DcDnsAirgap.ps1` = internal AD DNS, no forwarders/root hints, no external leak | ✅ |
| `01-windows-host` Sysmon/audit-policy/PowerShell logging | `guest\Deploy-Sysmon.ps1` + audit-policy GPO + WEF subscription (4688+cmdline, 4104) | ✅ |
| `01-windows-host` Secure Boot / TPM baseline | `03-New-LabVMs.ps1` builds Gen2 + Secure Boot + vTPM | ◐ |
| `02-billing-software` "verify billing binaries/services/config unchanged" | `Deploy-IntegrityMonitor.ps1` baselines + scans a billing-like path | ✅ |
| `05-incident-response` playbook validation | run a control-process-stop in the lab → confirm `billing_process_termination.yml` fires → exercise IR steps | ✅ |

## D. Evidence flow back to the project (seam #5)

`Invoke-RuleValidation.ps1` writes a structured report (`reports\rule-validation-<run>.md` + `.jsonl`)
listing which rules converted/compiled cleanly and (optionally) which fired on lab telemetry.
`scripts\analysis\Export-CvpEvidence.ps1` then renders that report into the CVP evidence format at
[`../docs/cvp/lab-validation-evidence.md`](../docs/cvp/lab-validation-evidence.md) — clearly labelled
synthetic/reproducible, with a reviewer gate — so it can feed `../docs/cvp/evidence-pack.md` and
`../docs/pilot/synthetic-shared-pc-venue/` only after human review.
