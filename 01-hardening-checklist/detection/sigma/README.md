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

## References

- Sigma documentation: https://sigmahq.io/docs/
- pySigma validation: https://sigmahq-pysigma.readthedocs.io/
- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
