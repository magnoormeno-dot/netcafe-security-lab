# Sigma Rules

The Sigma rules in this directory provide vendor-neutral Windows event detections for shared-PC venue operations.

## Rules

| Rule | Intent |
| --- | --- |
| `billing_process_termination.yml` | Detects attempts to terminate or manipulate billing, restoration, logging, or endpoint-protection processes. |
| `critical_service_disabled.yml` | Detects critical service stop, disable, crash, or new service installation events. |
| `anomalous_registry_modification.yml` | Detects registry changes affecting startup, policy, proxy, DNS, Defender, and billing-related paths. |

## Deployment Guidance

These rules require tuning. Replace placeholder service names, process names, and registry paths with local billing vendor names after coordinated review. Do not publish vendor-specific detections as accusations without responsible disclosure.

Recommended validation:

1. Validate YAML syntax with `sigma check` or a compatible pySigma workflow.
2. Convert rules to the target SIEM backend.
3. Test against lab-generated Windows events.
4. Run in low-severity or audit mode for at least one business week.
5. Tune false positives by approved admin hosts, vendor support windows, and maintenance scripts.

## Local Tuning

Keep the Sigma source rules generic. Apply venue-specific filters after
conversion to the target SIEM and record decisions in
`../tuning-register.example.csv` or the venue ticketing system.

Use `local-tuning.example.yml` as an operator-readable template for approved
maintenance windows, service accounts, host roles, and expiry dates. It is not a
Sigma rule and should not be loaded directly into a SIEM without conversion.

Do not add broad suppressions for administrator accounts, PowerShell, billing
servers, or vendor names. Those fields are useful pivots for triage, not safe
allowlist boundaries by themselves.

## References

- Sigma documentation: https://sigmahq.io/docs/
- pySigma validation: https://sigmahq-pysigma.readthedocs.io/
- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
