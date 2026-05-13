# Tool Threat Model

## Assets

- Baseline file or database
- HMAC signing key
- Alert output
- Configuration file
- Monitoring account
- Evidence produced during scans

## Threats

| Threat | Impact | Mitigation |
| --- | --- | --- |
| Baseline tampering | Modified files appear trusted | HMAC signatures, restricted ACLs, central backup |
| HMAC key disclosure | Attacker can sign malicious baselines | Store key outside writable paths, restrict admin access |
| Alert deletion | Operators miss tampering | Write alerts to central collector or restricted share |
| Overbroad exclusions | Important files are skipped | Review exclusions after each vendor update |
| Privileged monitor account | Monitor compromise becomes privilege escalation | Run with least privilege and read-only access where possible |
| False positives | Staff disable monitoring | Pilot, tune, document maintenance windows |

## Non-Goals

The tool is not EDR, anti-cheat, exploit prevention, or a billing software patch. It provides integrity evidence and operational signals.
