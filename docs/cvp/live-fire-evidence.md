# Live-fire Detection Evidence (synthetic, benign, lab-owned)

> **Reproducible synthetic lab evidence — not field validation.** This records that detection rules in
> `01-hardening-checklist/detection/` **fire on controlled benign telemetry** in a running, fully
> network-isolated lab. It complements the offline convert/compile evidence in
> [`lab-validation-evidence.md`](lab-validation-evidence.md) (which only proves the rules parse).
> Per [`evidence-pack.md`](evidence-pack.md), a human must review this before it is cited.

## Scope & safety boundary

- **Benign stimuli only.** Every stimulus targets a **non-existent, lab-owned dummy** (a service that
  was never running, a fictional registry key). No real service/process/data is stopped or altered; no
  exploit, payload, or detection-bypass content is used. Each stimulus is fully reverted (dummy service
  deleted, registry key removed, audit-policy change reverted).
- **Isolated.** Applied inside the air-gapped `cafesec.lab` Hyper-V lab (Private switch `CafeSec-Isolated`,
  10.10.10.0/24, no host vEthernet, no gateway), driven from the host over **PowerShell Direct (VMBus)** —
  no network, so isolation is never broken to run the test.
- **Not field-validated.** No production, test-net, or third-party system was involved.

## Live defense stack at time of test

| Component | State |
| --- | --- |
| Domain `cafesec.lab` | CSL-Server = DC + AD-DNS (air-gapped: no forwarders/root hints, recursion off) |
| Endpoints | CSL-Client01/02 (Win 11 Ent eval) domain-joined; CSL-Server (Win Server 2022 eval) |
| Sysmon + SwiftOnSecurity config | **Running on all 3 Windows VMs** (pinned 15.20) |
| WEF pipeline | WEC collector + `CafeSec-Security` subscription on the DC; `CafeSec-WEF-Source` GPO; sources forwarding to `ForwardedEvents`; 4688 command-line auditing ON |
| Offline rule validation | Sigma 3/3 + YARA 3/3 convert/compile (see companion doc) |

## Run metadata

| Field | Value |
| --- | --- |
| Date (host local) | 2026-06-04 |
| Target endpoint | CSL-Client01 (10.10.10.31) |
| Method | benign stimulus over PS Direct -> capture matching Windows/Sysmon event on the endpoint |
| Capture script | `cafesec-m4-livefire.ps1` (host-side; ASCII-only; adversarially reviewed) |

## Results — detection rules lit by benign stimuli

| # | Rule (`01-hardening-checklist/detection/sigma/`) | Benign stimulus (lab dummy) | Telemetry the rule keys on | Hit | Captured evidence |
| --- | --- | --- | --- | --- | --- |
| TC1 | `billing_process_termination.yml` | `sc.exe stop CafeSecDummyBilling` (service never existed) | Sysmon **EID 1** process_creation (Image+CommandLine) | ✅ **HIT** | `Image: C:\Windows\System32\sc.exe  CommandLine: "...\sc.exe" stop CafeSecDummyBilling` |
| TC2 | `critical_service_disabled.yml` | `sc.exe create CafeSecWatchdogDummy` then delete (do-nothing dummy) | System **7045** service installed | ✅ **HIT** | `A service was installed... Service Name: CafeSecWatchdogDummy  Service Type: user mode service  Start Type: demand start` |
| TC3 | `anomalous_registry_modification.yml` | set `HKLM\SOFTWARE\VenueBilling\UpdateUrl` (fictional key) | Security **4657** registry value modified | ◐ pending | requires the Registry-audit subcategory + a SetValue SACL; the capture script now enables/sets/reverts both (5-arg `RegistryAuditRule`) — re-run to confirm |

> **Interpretation.** TC1 and TC2 are confirmed end-to-end: a benign, reversible stimulus on a real
> domain endpoint produced exactly the telemetry the corresponding Sigma rule selects on, captured live.
> This is the live-fire counterpart to the offline 6/6 convert/compile evidence. TC3 keys on Windows
> Security 4657, which requires registry object-access auditing (a deliberate baseline-hardening item);
> the stimulus is rule-correct and the capture path is in place.

## Map to the runbook

These correspond to the benign test cases in
[`../../04-validation-lab/docs/04-defensive-validation-runbook.md`](../../04-validation-lab/docs/04-defensive-validation-runbook.md)
and the rows in [`../../04-validation-lab/COVERAGE.md`](../../04-validation-lab/COVERAGE.md) §A.

## Reviewer gate (before citing in the CVP evidence pack)

- [ ] Stimuli confirmed benign + reversible (dummy targets only; cleanup verified).
- [ ] "Hit" rows backed by the captured event excerpt above (and, for cross-host proof, the same event
      present in `ForwardedEvents` on CSL-Server).
- [ ] Wording stays "synthetic / benign / lab-owned", never "field-validated".
- [ ] Isolation was in force during the test (host-side `04-Verify-Isolation.ps1` + guest checks PASS).
