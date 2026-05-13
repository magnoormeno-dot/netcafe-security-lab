# Case Study 0001: Client Agent Service Stops During Peak Hours

## Summary

A gaming venue observed repeated billing client agent service stops on a small number of customer-facing PCs during evening peak hours. No vendor or customer is named in this case. The useful lesson is defensive: service health, process creation logs, and camera context together provided a faster answer than any single data source.

## Environment

- Venue type: gaming venue with customer-facing Windows PCs
- Approximate host count: fewer than 100 client PCs
- Billing architecture: local billing server with client agent installed on each PC
- Network segmentation: client VLAN separated from billing server VLAN by firewall rules
- Logging sources: Windows System and Security logs, billing server agent status, firewall logs, limited CCTV
- Restoration model: client PCs restored to a known image after reboot, with selected game cache exceptions

## Initial Signal

The first signal was not a malware alert. Staff noticed that two adjacent client PCs showed inconsistent session state in the cashier console. The billing server logs reported agent check-in gaps. Windows System logs later showed service stop events near the same time window.

## Timeline

| Time | Event | Evidence |
| --- | --- | --- |
| T0 | Cashier noticed inconsistent session state | Cashier console observation |
| T+5m | Client PCs moved to quarantine VLAN | Switch change record |
| T+15m | Windows logs exported before reimage | System and Security `.evtx` files |
| T+25m | Billing server logs exported | Agent health and session logs |
| T+45m | Camera footage reviewed for affected aisle | NVR export record |
| T+2h | Client PCs rebuilt from known-good image | Restore validation checklist |

## Defensive Analysis

The event pattern suggested local tampering or a failed maintenance action rather than a billing server outage. The important evidence was the correlation between service control events, process creation telemetry, and the physical location of affected systems. The venue avoided immediate reimaging until logs were exported, which preserved enough context to decide that only the affected client systems required rebuild.

No bypass method is described here. The defensive takeaway is that billing agent health should be treated as a monitored business signal, not as a normal helpdesk inconvenience.

## ATT&CK Mapping

| Technique | Reason |
| --- | --- |
| T1562.001 Disable or Modify Tools | Service stop affected a business-control and evidence-generating component. |
| T1543.003 Windows Service | Windows service state was central to the incident timeline. |
| T1070.001 Clear Windows Event Logs | No log clearing occurred, but alerting for this would have increased confidence. |
| T1200 Hardware Additions | Physical context was reviewed because affected systems were customer-facing. |

## Controls That Worked

- Network segmentation limited the affected clients to the billing application path.
- Billing server agent health logs identified check-in gaps.
- Windows System logs preserved service stop timing.
- Camera coverage helped staff understand physical context.

## Controls That Failed Or Were Missing

- Process creation command-line logging was not enabled on all client PCs.
- The venue did not yet have a file integrity baseline for billing agent binaries.
- Restoration exception review was informal and not tied to a change record.

## Detection Opportunities

- Alert when a billing, restoration, logging, or endpoint-protection service stops on a client PC.
- Alert when a billing agent misses multiple expected check-ins.
- Correlate service stops with process creation events from shells, taskkill, sc.exe, PowerShell, or vendor updaters.
- Preserve CCTV footage when service tampering aligns with a customer session.

## Remediation

- Enabled process creation logging with command line on pilot client PCs.
- Added service-stop Sigma detection for billing and restoration services.
- Added file hash baselines for billing agent binaries and configuration.
- Created a pre-reimage evidence checklist for suspicious client PCs.
- Reviewed restoration exceptions and removed one unnecessary writable directory.

## References

- CafeSec Lab Windows host hardening checklist: `../checklist/01-windows-host.md`
- CafeSec Lab incident response checklist: `../checklist/05-incident-response.md`
- MITRE ATT&CK T1562.001: https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK T1543.003: https://attack.mitre.org/techniques/T1543/003/
