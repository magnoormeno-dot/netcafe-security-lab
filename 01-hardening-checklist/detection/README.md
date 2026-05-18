# Detection Rules

This directory contains defensive detection content for internet cafes, gaming venues, esports hotels, and shared-PC environments.

The rules are intentionally generic. They are designed to identify behavioral patterns that matter to defenders, not to name, clone, or operationalize any specific billing bypass, cheat, or tampering tool.

## Contents

| Path | Purpose |
| --- | --- |
| `yara/` | File and memory-oriented YARA rules for generic suspicious binary traits. |
| `sigma/` | Windows event-log Sigma rules for service tampering, registry changes, and billing process disruption. |
| `tuning-guide.md` | False-positive handling, tuning governance, and review workflow. |
| `tuning-register.example.csv` | Minimum register fields for local tuning decisions. |

## Safety Principles

- Rules must describe detection intent, expected false positives, and validation steps.
- Rules must avoid vendor-specific accusations unless coordinated disclosure has already occurred.
- Rules must not include bypass instructions, exploit chains, credentials, or tool-specific operational details.
- Rules should map to MITRE ATT&CK where appropriate.

## Operational Notes

Run new rules in audit or test mode before production alerting. Gaming venues have noisy endpoints: launchers, anti-cheat components, peripheral drivers, vendor support tools, and legacy billing agents can all create unusual telemetry. Treat a detection as a triage signal, not automatic proof of malicious activity.

Useful first triage questions:

- Which host role generated the event?
- Is the source path writable by customers or staff?
- Is the binary signed by an expected publisher?
- Did a billing, restoration, logging, or endpoint-protection service stop?
- Was the event near a cashier adjustment, customer dispute, vendor support session, or physical anomaly?

Use `tuning-guide.md` before suppressing or lowering severity for a rule. Tuning
must be narrow, evidence-backed, owned by a named operator, and time-limited.

## References

- YARA documentation: https://yara.readthedocs.io/
- Sigma documentation: https://sigmahq.io/docs/
- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
