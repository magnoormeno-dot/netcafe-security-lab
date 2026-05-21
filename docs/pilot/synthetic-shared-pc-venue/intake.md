# Synthetic Pilot Intake

## Review Metadata

| Field | Value |
| --- | --- |
| Venue reference | `SYNTH-VENUE-001` |
| Pilot dates | `2026-05-18` to `2026-05-24` |
| Review type | Synthetic defensive pilot workflow |
| Evidence class | Synthetic, non-sensitive |
| Assessor | CafeSec Lab Research Team |
| Intended audience | Venue operator, IT contractor, blue-team reviewer |

## Environment Summary

| Area | Synthetic value |
| --- | --- |
| Client PCs | 12 Windows shared-PC clients |
| Cashier workstation | 1 Windows workstation |
| Billing server | 1 Windows server |
| Restoration system | Client PCs restored nightly |
| Billing model | Client/server billing application |
| Network model | Client VLAN, management VLAN, cashier VLAN |
| Monitoring scope | Billing agent path, restoration agent path, selected config files |
| Excluded data | Customer profiles, browser history, payment exports, CCTV, identity records |

## Host Roles

| Host role | Synthetic hostname | Monitoring goal |
| --- | --- | --- |
| Client PC | `SYN-CLIENT-03` | Detect billing/restoration agent drift. |
| Cashier workstation | `SYN-CASHIER-01` | Detect cashier application and config drift. |
| Billing server | `SYN-BILLING-01` | Detect billing service, config, and plugin drift. |

## Assumptions

- The pilot is authorized by the venue operator.
- All telemetry is synthetic and suitable for public documentation.
- The baseline is created after a known-good maintenance window.
- Vendor names are replaced with neutral placeholders.
- No live payment, identity, or customer activity records are collected.

## Pilot Objectives

1. Create a signed baseline for the scoped files.
2. Run scheduled integrity scans during one synthetic business day.
3. Review service-restart and binary-change alerts.
4. Record false-positive decisions with expiry and owner fields.
5. Produce an operator-readable summary with residual risk.

## Success Conditions

- The baseline verifies successfully.
- Alerts can be linked to synthetic maintenance records or escalated.
- No tuning decision creates a broad permanent allowlist.
- The executive summary separates observed facts from assumptions.
- The workflow produces a repeatable structure for a future authorized pilot.

