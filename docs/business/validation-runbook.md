# Commercial Validation Runbook

This runbook operationalizes issue #4: validate whether the CafeSec Defensive
Pilot offer matches a real buyer problem before building a SaaS product or
managed service.

## Validation Objective

The objective is not to sell aggressively. The objective is to learn whether a
shared-PC venue operator, IT contractor, MSSP, or software vendor recognizes the
problem and would consider paying for a fixed-scope defensive pilot.

## Target Segments

Start with ten prospects across these categories:

| Segment | Why it matters | Qualification signal |
| --- | --- | --- |
| Independent gaming venue | Direct buyer with shared-PC operational risk. | Operates public gaming PCs or event PCs. |
| Esports hotel operator | Direct buyer with guest-facing PCs and room operations. | Uses shared PCs or managed gaming rooms. |
| Internet cafe chain | Direct buyer with repeated host roles. | Multiple venues or standardized client images. |
| Local IT contractor | Channel partner for small venues. | Supports Windows fleets or venue software. |
| Small MSSP | Channel partner with security operations capacity. | Serves SMB, hospitality, or gaming clients. |
| Billing software vendor | Partner or referral source. | Sells venue-management or billing software. |
| Kiosk/fleet operator | Adjacent buyer with managed public endpoints. | Manages public or semi-public Windows hosts. |
| University esports lab | Feedback source, not necessarily buyer. | Operates managed gaming PCs. |
| LAN center consultant | Channel partner with domain knowledge. | Advises or deploys gaming venue infrastructure. |
| Cybersecurity practitioner with venue experience | Feedback source. | Can review workflow realism. |

Do not publish named prospects in the repository. Store prospect notes in a
private tracker because outreach status, objections, and contact details are not
public project artifacts.

## Qualification Questions

Use these questions before pitching a pilot:

1. Do they operate or support shared-PC environments?
2. Do they have billing, cashier, launcher, restoration, or kiosk software?
3. Do they have authority to approve a defensive review or introduce the owner?
4. Can the discussion avoid customer data, credentials, screenshots, and vendor
   secrets?
5. Is their interest operational, not bypass-oriented?

If any answer is unclear, keep the conversation at the workflow-review level.

## Outreach Sequence

### Message 1: Feedback Request

Ask for feedback before asking for a sale.

```text
Hi,

I am validating CafeSec Lab, a defensive security project for shared-PC venues such as internet cafes, gaming venues, esports hotels, kiosks, and managed PC fleets.

I am not asking for sensitive data. I am looking for practical feedback on whether this defensive pilot workflow matches a real operator problem:

https://github.com/magnoormeno-dot/netcafe-security-lab/tree/main/docs/pilot/synthetic-shared-pc-venue

The pilot focuses on hardening review, integrity baselines, detection tuning, and an operator-readable 30-day action plan. It explicitly excludes bypass testing, exploit development, credential handling, customer-data review, and unauthorized testing.

Would you be willing to spend 10 minutes reviewing the scope and telling me what feels useful, unrealistic, or missing?
```

### Message 2: Follow-Up

Send only once, after several days.

```text
Following up once on the CafeSec Lab pilot workflow.

The most useful feedback would be:
- whether the intake fields are realistic;
- whether service/file integrity alerts would be too noisy;
- what a venue owner would need in the executive summary;
- what should stay out of scope for a first pilot.

No production data or sensitive details are needed.
```

### Message 3: Paid Pilot Qualification

Use only after they confirm the problem is real.

```text
Thanks for the feedback. I am testing a small fixed-scope CafeSec Defensive Pilot.

The current hypothesis is:
- Lite pilot: one host role and a short executive summary;
- Standard pilot: up to three host roles, baseline plan, tuning notes, and a 30-day action plan.

Would this be something your organization would consider paying for if the scope, authorization, and data boundaries were clear?
```

## Objection Categories

Record objections using these categories:

| Category | Example |
| --- | --- |
| Price | "This is too expensive for a venue." |
| Urgency | "We have not had incidents, so this is low priority." |
| Trust | "We do not know who you are yet." |
| Privacy | "We cannot share logs or host details." |
| Time | "Staff cannot support a pilot." |
| Technical fit | "We already use an MSP, EDR, or restoration product." |
| Buyer mismatch | "Venue owner cares, but IT contractor controls systems." |
| Scope concern | "This sounds like pentesting or vendor criticism." |

## Private Tracker Fields

Use a private tracker with these fields:

```csv
prospect_id,segment,organization,contact_surface,status,last_contact_utc,next_action,problem_recognized,budget_signal,privacy_concern,trust_concern,price_objection,notes
```

Recommended statuses:

- `identified`
- `contacted`
- `replied`
- `qualified`
- `not_qualified`
- `declined`
- `follow_up`
- `pilot_candidate`

## Success Criteria For Issue #4

Issue #4 should be considered complete only when:

- ten prospects are identified in the private tracker;
- five qualified prospects are contacted;
- at least three real conversations or replies are documented privately;
- at least one public or permissioned feedback item is linked;
- `docs/business/service-offer-sheet.md` is updated based on evidence.

