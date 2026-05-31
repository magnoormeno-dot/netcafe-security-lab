# Coverage Matrix — what the validation lab actually validates

This module is the reproducible testbed for the rest of the repository. The tables below map the
project's **detection rules** (`01-hardening-checklist/detection/`) and **hardening checklist items**
(`01-hardening-checklist/checklist/`) to the lab telemetry, scripts, and verification steps that exercise
them — and, critically, to whether a **committed artifact actually proves it yet**.

**Honesty note.** Status labels distinguish *proven by a committed artifact* from *wired but not yet run*.
Lab output is reproducible synthetic evidence, **not** field validation; per the repo's
"What This Project Will Not Publish" policy, it must be human-reviewed before being cited in `docs/cvp/` or
`docs/pilot/`.

### Status legend

- **✅ proven** — a committed artifact (a CI run or the evidence file) demonstrates this passed.
- **◐ wired-unrun** — the lab implements and wires this, and it is runnable, but **no committed run proves
  it yet** (it requires the running VM lab + a manual benign trigger, which is the operator's step).
- **○ out-of-lab** — depends on physical network gear (VLANs/firewall/switch/AP) the single-host lab cannot model.

> As of this commit, the **only ✅ items are the offline rule convert/compile** (enforced by CI
> [`validation-lab-rules.yml`](.github/workflows/validation-lab-rules.yml) and recorded in
> [`docs/cvp/lab-validation-evidence.md`](docs/cvp/lab-validation-evidence.md): Sigma 3/3, YARA 3/3).
> Everything that needs running VMs is **◐ wired-unrun** until a committed live-lab run replaces it.

---

## A. Detection rules → lab telemetry & validation

The offline rung (rule converts/compiles) is proven and CI-enforced. The live-fire rung (rule fires on
real telemetry) is wired but unrun: it needs Sysmon (`guest\Deploy-Sysmon.ps1`), audit policy + WEF, Wazuh,
and a manual benign trigger.

| Rule (`01-hardening-checklist/detection/`) | Offline (convert/compile) | Live-fire (fires on telemetry) | Live-fire trigger |
| --- | --- | --- | --- |
| `sigma/billing_process_termination.yml` | ✅ converts (lucene) | ◐ wired-unrun | benign control-process stop → confirm hit in Wazuh/ForwardedEvents |
| `sigma/critical_service_disabled.yml` | ✅ converts (lucene) | ◐ wired-unrun | `Stop-Service`/`sc config start=disabled` on a lab test service |
| `sigma/anomalous_registry_modification.yml` | ✅ converts (lucene) | ◐ wired-unrun | controlled registry write to a watched key (Sysmon EID 12/13/14) |
| `yara/unsigned_injector_patterns.yar` | ✅ compiles | ◐ wired-unrun | `Invoke-YaraScan.ps1 -TargetPath …` on a lab VM |
| `yara/suspicious_packer_traits.yar` | ✅ compiles | ◐ wired-unrun | same as above |
| `yara/generic_memory_scanner.yar` | ✅ compiles | ◐ wired-unrun | live memory scan on a running VM |

> Proof of the offline column: CI `validation-lab-rules.yml` runs `sigma convert -t lucene -p ecs_windows`
> + `yara` compile on every change to the rules, and `docs/cvp/lab-validation-evidence.{md,jsonl}` records the
> last result. The Sigma rule `billing_process_termination.yml` even lists *"Lab validation of the incident
> response playbook"* as an expected false-positive — this module is that lab (live-fire pending a run).

## B. Integrity monitor (`02-integrity-monitor`) → lab

| Capability | Lab realization | Status |
| --- | --- | --- |
| File baseline + drift (`baseline`/`scan`/`verify`) | `guest\Deploy-IntegrityMonitor.ps1` installs the tool into a lab Windows VM and baselines a billing-like path | ◐ wired-unrun |
| Process anomaly checks (unsigned/writable-dir/parent-child) | would run against real lab processes instead of `tests/fixtures/sample_events.json` | ◐ wired-unrun |
| Windows event-log analysis (logon/process/service/registry/log-clear) | would consume the lab's real Security/Sysmon logs | ◐ wired-unrun |
| Unit-tested detection logic (mock providers) | proven in the monitor's own CI (`ci.yml`: ruff/mypy/pytest) | ✅ (in 02's CI, against mocks — not live telemetry) |

## C. Hardening checklist → lab

The single-host Hyper-V lab models the **principles and the verification methodology**; full venue
VLAN/firewall items are physical-network scope. None of the VM-dependent rows are proven until a committed
live-lab run exists.

| Checklist item | Lab implementation | Status |
| --- | --- | --- |
| `03-network-isolation` verification methodology (the "Verification:" lines) | `04-Verify-Isolation.ps1` + `guest\Test-GuestIsolation.ps1` + `wazuh\test-guest-isolation.sh` operationalize the checklist's verify steps (IPv4/IPv6 egress, route, DNS) | ◐ wired-unrun |
| `03-network-isolation` **NI-14** log critical traffic; **Log VLAN** | WEF (`Configure-WEC-Collector` + GPO) + Wazuh = the project's "Log & Monitoring VLAN" | ◐ wired-unrun |
| `03-network-isolation` **NI-28/31** controlled DNS, no internal-name leak | `domain\Set-DcDnsAirgap.ps1` = internal AD DNS, no forwarders/root hints | ◐ wired-unrun |
| `03-network-isolation` **NI-05 / NI-11 / NI-19** client cannot reach server mgmt | demonstrated at host scale by the Private switch + isolation verifier | ◐ wired-unrun |
| `03-network-isolation` **NI-02/03/04** VLAN zones, policy-enforcement, deny-by-default | real multi-VLAN + firewall = venue gear | ○ out-of-lab |
| `01-windows-host` Sysmon/audit-policy/PowerShell logging | `guest\Deploy-Sysmon.ps1` + audit-policy GPO + WEF subscription (4688+cmdline, 4104) | ◐ wired-unrun |
| `01-windows-host` Secure Boot / TPM baseline | `03-New-LabVMs.ps1` builds Gen2 + Secure Boot + vTPM | ◐ wired-unrun |
| `02-billing-software` "verify billing binaries/services/config unchanged" | `Deploy-IntegrityMonitor.ps1` baselines + scans a billing-like path | ◐ wired-unrun |
| Detection-rule convert/compile (offline) | CI `validation-lab-rules.yml` + evidence file | ✅ proven |

## D. Evidence flow back to the project (seam #5)

`Invoke-RuleValidation.ps1` validates the offline rung and writes `reports\rule-validation-<run>.{md,jsonl}`
(exit non-zero on any failure or zero rules — so an empty run cannot look clean).
`scripts\analysis\Export-CvpEvidence.ps1` renders the latest report into the CVP evidence format at
[`../docs/cvp/lab-validation-evidence.md`](../docs/cvp/lab-validation-evidence.md) and commits the backing
`.jsonl` next to it (so the reviewer gate references a real artifact). It refuses to emit non-stub evidence
unless a report with >0 rules exists. The same offline rung is enforced on every PR by
[`validation-lab-rules.yml`](.github/workflows/validation-lab-rules.yml). Live-fire results are added only
after a committed run in a running lab, and only after human review.
