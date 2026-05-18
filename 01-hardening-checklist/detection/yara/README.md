# YARA Rules

The YARA rules in this directory detect generic suspicious traits relevant to shared-PC venue defense. They are not signatures for specific tools or named vendors.

## Rules

| Rule | Intent |
| --- | --- |
| `generic_memory_scanner.yar` | Detects binaries that combine memory scanning APIs with comparison and scan-loop indicators. |
| `unsigned_injector_patterns.yar` | Detects unsigned PE files with process-opening, remote memory-write, and remote-thread style imports. |
| `suspicious_packer_traits.yar` | Detects high-level packer traits that complicate review and are unusual for venue billing components. |

## Deployment Guidance

Use these rules as triage inputs only. A match should trigger signature verification, path review, process-tree review, and comparison against a known-good software inventory.

Recommended test flow:

1. Compile rules with `yara` or a compatible scanner.
2. Run against a clean software corpus from the venue.
3. Document false positives by publisher, file path, and host role.
4. Run against a controlled malware or tooling corpus only in a lab.
5. Tune alert severity before production deployment.

## False Positive Handling

Use `../tuning-guide.md` before downgrading YARA matches. A match from an
approved signed vendor binary may be documented as expected only when publisher,
hash, version, source, host role, and expiry are recorded.

Do not tune away matches from customer-writable directories, removable media,
temporary folders, game mod folders, or unknown support-tool downloads. In
shared-PC venues, location and write permissions are often more important than a
single static signature.

## References

- YARA writing rules: https://yara.readthedocs.io/en/stable/writingrules.html
- YARA PE module: https://yara.readthedocs.io/en/latest/modules/pe.html
- MITRE ATT&CK T1055 Process Injection: https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1105 Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1027 Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
