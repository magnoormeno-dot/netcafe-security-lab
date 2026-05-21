# Synthetic Pilot Executive Summary

## Assessment Metadata

| Field | Value |
| --- | --- |
| Venue reference | `SYNTH-VENUE-001` |
| Date range | `2026-05-18` to `2026-05-24` |
| Assessor | CafeSec Lab Research Team |
| Scope | Client PC, cashier workstation, billing server, integrity monitoring, selected detection tuning |
| Out of scope | Customer records, payment data, CCTV, real vendor systems, live third-party infrastructure |
| Evidence handling | Synthetic package under `docs/pilot/synthetic-shared-pc-venue/` |

## Executive Summary

The synthetic pilot shows that a shared-PC venue can review billing and
restoration drift without collecting customer data or publishing vendor-specific
details. One expected vendor update created service-restart and binary-change
alerts; those alerts were narrowed to a signed updater, approved maintenance
ticket, and short expiry window rather than being permanently suppressed. A
separate failed-login pattern on the synthetic billing server remained open for
operator review because it was not linked to a maintenance task. The next control
to add is a scheduled baseline review process with explicit re-baseline rules.

## Scope Summary

| Area | Included | Notes |
| --- | --- | --- |
| Billing server | Yes | Synthetic failed-logon review and clean integrity scan. |
| Cashier workstation | Yes | Clean integrity scan in sample telemetry. |
| Client PCs | Yes | One synthetic client with service restart and signed binary change. |
| Network segmentation | Partial | Intake records the model; packet-level review is out of scope. |
| Restoration system | Partial | Monitored as a scoped path; restoration behavior is not emulated. |
| Detection rules | Yes | Service-disabled, process-termination, and failed-login pattern review. |
| Incident response process | Partial | Escalation owner recorded; full tabletop exercise is out of scope. |

## Priority Findings

| Priority | Finding | Operational impact | Verification or mitigation |
| --- | --- | --- | --- |
| P1 | Failed network logon pattern was not tied to maintenance. | Billing server access attempts require operator review. | Review Windows logon events, source address, account status, and maintenance records. |
| P2 | Vendor update restarts a billing client service. | Expected updates can resemble tampering if not documented. | Restrict tuning to signed updater path, ticketed window, and expiry date. |
| P3 | Baseline lifecycle depends on operator discipline. | Re-baselining too quickly can hide unauthorized changes. | Require approval, hash review, and preserved old baseline before re-baseline. |

## Tuning Decisions

| Signal | Decision | Reason |
| --- | --- | --- |
| `critical_service_disabled` during `SYN-CHG-0007` | Lower severity temporarily | Stop/start happened inside approved maintenance window and restarted cleanly. |
| `critical_service_disabled` outside maintenance | Keep alerting | Same event can affect billing enforcement when unexplained. |
| `billing_process_termination` by signed updater | Document expected parent | Decision limited to synthetic updater path and expiry window. |
| Failed login pattern on billing server | Escalate for review | No matching maintenance task or approved explanation. |

## Immediate Actions

| Action | Owner | Due date | Verification |
| --- | --- | --- | --- |
| Review failed logon source and account status. | Operations lead | `2026-05-19` | Ticket notes include source, account, and disposition. |
| Confirm signed updater hash after maintenance. | IT contractor | `2026-05-19` | Hash and publisher recorded in change ticket. |
| Review temporary tuning expiry. | Venue owner | `2026-05-25` | Expired tuning is removed or re-approved with evidence. |

## Residual Risk

After the immediate actions, the synthetic venue has a clearer way to separate
approved vendor maintenance from unexplained drift. Residual risk remains around
operator review discipline, restoration-system assumptions, and incomplete
network-level evidence. The next maturity step is to add a scheduled-task
deployment example and a post-pilot review template.

