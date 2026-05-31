# CafeSec Defensive Pilot Offer Sheet

This draft describes the first commercial offer to validate. Do not publish
fixed pricing until at least three buyer conversations confirm the scope.

## Offer

**CafeSec Defensive Pilot** is a fixed-scope security review for shared-PC
venues and the IT providers who support them.

It helps answer:

- Which billing, cashier, and client-PC assets should be monitored first?
- Which Windows controls are missing or unverifiable?
- Which file or service changes are expected maintenance, and which need review?
- Which alerts would create unnecessary staff fatigue?
- What should the operator fix in the next 30 days?

## Who It Is For

- Internet cafes and gaming venues.
- Esports hotels.
- Kiosk or managed shared-PC fleets.
- IT contractors supporting these environments.
- Small MSSPs needing a venue-specific defensive workflow.

## What Is Included

| Step | Output |
| --- | --- |
| Intake | Scope, host roles, excluded data classes, authorization notes. |
| Control review | Checklist-based review of Windows, billing, network, and incident-response controls. |
| Integrity pilot design | Baseline plan for one to three host roles. |
| Detection tuning review | False-positive and escalation notes for selected rules. |
| Executive summary | Operator-readable summary with priorities and next actions. |
| 30-day plan | Practical remediation actions with owners and verification steps. |

## What Is Not Included

- Billing bypass testing.
- Exploit development.
- Malware, persistence, stealth, or evasion work.
- Unauthorized testing.
- Credential collection.
- Customer-data review.
- Legal compliance advice.
- Public vendor accusations outside coordinated disclosure.

## Scope Boundary: Billing Integrity, Not Billing Fraud

This pilot covers tampering with **billing infrastructure** — unexpected changes to billing/cashier
binaries, services, and configuration files, plus the Windows telemetry around them. It does **not** detect
**billing fraud** (free time, balance manipulation, refund/free-time abuse at the till). That activity
lives inside the billing application's own database and audit logs, which this pilot does not read.
Operators feeling that pain should pursue the vendor-config controls in the hardening checklist —
server-side pricing, named cashier accounts, and tamper-evident, exportable refund/free-time/adjustment
logs (`01-hardening-checklist/checklist/02-billing-software.md`, BS-05/26/27/36). A future deliverable that
ingests the vendor's own adjustment exports is a candidate, not part of this offer.

## Required From The Buyer

- Written authorization for scoped systems.
- A technical contact who understands the venue environment.
- A business owner or manager who can approve findings.
- A maintenance window for review if production systems are involved.
- Agreement not to send customer data, credentials, or payment records.

## Example Pilot Scope

| Host role | Included examples |
| --- | --- |
| Client PC | Billing client agent, restoration agent, approved configuration files. |
| Cashier workstation | Cashier application path, selected config files, local service state. |
| Billing server | Billing service configuration, plugin directory, relevant Windows events. |

## Buyer-Facing Outcome

At the end of the pilot, the buyer receives:

- what was reviewed;
- what was not reviewed;
- the top three operational risks;
- which alerts were expected maintenance;
- which alerts require follow-up;
- what to fix in the next seven days;
- what to schedule in the next 30 days.

## Expected Operator Effort (a one-time review is not ongoing protection)

This is a **point-in-time** review. The integrity monitor only keeps value if someone runs scans, triages
drift (especially after game/billing-vendor updates), and re-baselines correctly. A venue with no IT staff
should budget for this — either an in-house owner/contractor who can make re-baseline judgment calls, or a
recurring "monthly review" engagement. Estimate the standing triage load explicitly before committing; if
no one can sustain it, point-in-time monitoring will be ignored rather than acted on. Decide up front
whether the deliverable is a one-time assessment or ongoing assurance, and price/staff accordingly.

## Draft Pricing Hypothesis

Pricing should be treated as a test.

- Lite pilot: USD 300-500.
- Standard pilot: USD 900-1500.
- Vendor review: USD 1500-3000.

The first design partner may receive a reduced fixed price in exchange for
permission to publish a fully anonymized lessons-learned note.

## Safe Outreach Message

```text
CafeSec Lab is testing a small defensive pilot for shared-PC venues such as internet cafes, gaming venues, esports hotels, and managed PC fleets.

The pilot does not include bypass testing, exploit development, credential handling, or customer-data review. It focuses on hardening review, integrity baselines, detection tuning, and an operator-readable 30-day action plan.

Project home: https://cafeseclab.com/
Synthetic example: https://github.com/magnoormeno-dot/netcafe-security-lab/tree/main/docs/pilot/synthetic-shared-pc-venue

Would you be willing to review the pilot scope and tell me whether it matches a real operator problem?
```

