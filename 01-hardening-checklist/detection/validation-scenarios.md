# Detection Validation Scenario Cards

Non-operational adversary-emulation scenario cards for validating blue-team
detections in the CafeSec Lab synthetic shared-PC venue lab.

**Scope and safety**

- These cards validate that detections fire and that responders can act. They
  are **not** attack playbooks.
- They contain **no** commands, command lines, payloads, persistence, stealth,
  evasion, credential-access, or monitoring-bypass instructions.
- All actions are performed inside the synthetic lab against lab-owned hosts.
  There is no third-party target. No real vendors or real targets are named.
- Emulation should be driven through approved, ticketed test harnesses or
  documented manual operator actions inside a maintenance window - the goal is
  a known-good stimulus, observed and reverted, not a reusable technique.

Each card maps to one shipped Sigma rule and uses that rule's own field set so
validators can confirm the right telemetry reaches the SIEM.

---

## Card 1 - Billing/Control Process Termination Attempt

**Maps to:** `sigma/billing_process_termination.yml`

**Defensive objective**
Confirm that an attempt to stop a billing, restoration, logging, or protection
process from a customer-facing host produces a high-severity alert with enough
context (acting user, parent process, host) for a responder to triage within the
target time window. Validate that the approved-admin-path filter suppresses
sanctioned maintenance and only that.

**ATT&CK technique family**
- T1562.001 - Impair Defenses: Disable or Modify Tools
- T1059 - Command and Scripting Interpreter

**Synthetic telemetry expected**
- Windows `process_creation` event (Event ID 4688 / Sysmon Event ID 1) for a
  recognized control utility, originating from a non-approved parent path.
- Populated fields the rule selects on: `Image`, `ParentImage`, `CommandLine`,
  `ParentCommandLine`, `User`, `Computer`, `UtcTime`.
- A correlated dip in the targeted agent's health/heartbeat stream (the billing
  or restoration agent reporting it was asked to stop).

**Evidence to collect**
- The raw matching process-creation record and the Sigma alert it generated
  (rule ID `58f9bf1a-1f0d-4d28-a9d8-2ff2e4be74f8`).
- Time delta between event generation and alert surfacing (detection latency).
- Agent health log showing the stop attempt and whether the process actually
  terminated or was protected.
- Operator triage note: who, host role, inside a window or not.

**False-positive risks**
- Approved maintenance scripts during a documented support window.
- A vendor updater stopping and restarting its own service during patching.
- EDR/management tooling performing controlled remediation.
- Lab validation runs themselves - tag and exclude these from FP metrics.

**Operator-safe mitigations (validation level)**
- Keep terminations of control software gated behind approved admin paths and
  ticketed maintenance windows; alert on everything outside that.
- Avoid broad username filters (e.g. "admin", "operator"); prefer exact named
  maintenance accounts with reviewed, time-boxed exceptions, per the rule's own
  tuning warning.
- Ensure protected processes auto-restart and that the restart is itself logged
  so a stop attempt is visible even when it fails.

---

## Card 2 - Critical Venue Service Disabled / Stopped

**Maps to:** `sigma/critical_service_disabled.yml`

**Defensive objective**
Confirm that a service-control event affecting a billing, restoration, logging,
backup, or protection service is detected and correlated with the acting context,
and that planned maintenance is cleanly distinguished from unexpected disruption.

**ATT&CK technique family**
- T1562.001 - Impair Defenses: Disable or Modify Tools
- T1543.003 - Create or Modify System Process: Windows Service

**Synthetic telemetry expected**
- Windows System log Service Control Manager events: 7034 (unexpected
  termination), 7035/7036 (control/state change), 7040 (start-type change),
  7045 (new service install).
- Fields the rule selects on: `Provider_Name`, `EventID`, `Message`,
  `Computer`, `TimeCreated`, including the bad-state wording ("stopped",
  "disabled", "terminated unexpectedly", "start type") for a critical service
  name.

**Evidence to collect**
- The matching System-log record(s) and the resulting alert
  (rule ID `92bd2cf4-c23e-4ee8-a4d6-90f07f755d96`).
- Correlation pivot: nearest process-creation, logon, and billing-audit events
  on the same host/time window.
- Service state before and after, plus whether it self-recovered.
- Confirmation that the maintenance filter (`ApprovedMaintenance`,
  `VendorUpdateWindow`) correctly suppressed a planned-change control run.

**False-positive risks**
- Legitimate vendor updates that stop a service before replacing it.
- Planned patching or scheduled reboot windows.
- Initial software install during an approved deployment.
- Service restarts from resource exhaustion or power events.

**Operator-safe mitigations (validation level)**
- Tune the critical-service name list to the lab's actual billing/restoration/
  logging/backup component names so the rule is neither noisy nor blind.
- Route all planned service changes through the maintenance-tagged path so
  unplanned stops stand out.
- Set critical services to auto-restart and alert on start-type changes, not
  just stops, since a disabled start type is a quieter precursor.

---

## Card 3 - Anomalous Registry Modification

**Maps to:** `sigma/anomalous_registry_modification.yml`

**Defensive objective**
Confirm that registry changes to startup, security-policy, proxy/DNS, logging,
application-control, or billing-configuration keys are detected, attributed to a
user and process, and judged against host role and change windows - and that the
approved-change-account filter works without over-suppressing.

**ATT&CK technique family**
- T1112 - Modify Registry
- T1547 - Boot or Logon Autostart Execution
- T1562.001 - Impair Defenses: Disable or Modify Tools

**Synthetic telemetry expected**
- Windows Security log Event ID 4657 (registry value modified), which requires
  registry object-access auditing to be enabled on the monitored keys.
- Fields the rule selects on: `ObjectName` (a watched key path), `ObjectValueName`
  (a watched value such as a Run entry, service `Start`/`ImagePath`, a logging
  toggle, or a proxy/DNS value), `SubjectUserName`, `ProcessName`, `NewValue`,
  `Computer`, `TimeCreated`.

**Evidence to collect**
- The matching 4657 record(s) and the alert
  (rule ID `e1fc50ea-ae34-4d37-8ae1-854551ddf4ac`, level: medium).
- Before/after value of the modified key and which watched path category it falls
  under (autostart, policy, network, billing config).
- Acting process and user, and whether the change occurred inside an approved
  deployment/support window.
- Verification that auditing is actually enabled on the watched keys - a missing
  4657 stream is itself a finding (detection blind spot, not an all-clear).

**False-positive risks**
- Group Policy refreshes touching policy keys.
- Vendor updates during approved maintenance windows.
- Endpoint-management tools applying baseline configuration.
- Initial deployment or lab testing.

**Operator-safe mitigations (validation level)**
- Maintain the approved-change account filter (`svc_patch`, `svc_config`) as
  exact, reviewed service accounts rather than broad name matches.
- Confirm SACLs/auditing remain enabled on the watched keys as part of routine
  health checks, since registry detection silently degrades if auditing is off.
- Treat changes to logging and application-control toggles as higher priority
  than benign autostart edits when prioritizing the medium-severity queue.

---

## Validation run checklist (all cards)

1. Confirm the relevant log source is enabled and forwarding before stimulus
   (process auditing, System log, registry SACLs).
2. Capture a clean baseline window so the stimulus is attributable.
3. Apply the synthetic stimulus inside a maintenance window on a lab host.
4. Record: did the rule fire, detection latency, completeness of fields,
   correlation pivots available.
5. Revert any lab change and confirm services/keys/processes return to baseline.
6. Tag the run so it is excluded from production false-positive metrics.
7. File results against the validation runbook and update the tuning register if
   a benign source needs a reviewed exception.

**Related references**
- `references/mapping-to-mitre-attack.md` - technique-to-control index.
- `detection/tuning-guide.md` and `detection/tuning-register.example.csv` -
  exception tracking.
- `docs/business/validation-runbook.md` - end-to-end validation process.
