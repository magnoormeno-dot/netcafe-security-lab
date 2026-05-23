# CafeSec Lab Commercialization Plan

This plan moves CafeSec Lab from a public defensive research project toward a
small, service-led commercial offering. The commercial path should not weaken
the project's safety boundaries, coordinated disclosure posture, or
vendor-neutral research identity.

## Commercial Thesis

Shared-PC venues have a specific operational security problem: billing systems,
cashier hosts, client images, restoration tools, game launchers, and local
networks are business-critical but often managed without enterprise security
staff.

The first commercial product should not be a broad SaaS platform. It should be a
paid defensive pilot that converts the public research workflow into a concrete
operator outcome:

> "In one week, CafeSec Lab helps a venue or service provider understand what
> should be monitored, what changed unexpectedly, which alerts are noise, and
> which controls should be fixed first."

## First Paid Offer

Name: **CafeSec Defensive Pilot**

Format: fixed-scope remote or hybrid assessment.

Target buyer:

- independent internet cafe or gaming venue owner;
- esports hotel operator;
- IT contractor managing shared-PC venues;
- small MSSP serving hospitality or gaming clients;
- billing or venue-management software vendor that wants defensive review
  material.

Primary deliverables:

- intake and asset-scope worksheet;
- Windows host and billing-software control review;
- integrity-monitor baseline plan for one to three host roles;
- detection-rule tuning notes using synthetic or authorized telemetry;
- operator executive summary;
- prioritized 30-day remediation plan.

Out of scope:

- exploit development;
- billing bypass testing;
- unauthorized testing;
- customer-data review;
- live credential handling;
- vendor-specific vulnerability publication outside coordinated disclosure.

## Positioning

CafeSec Lab should position itself as a defensive workflow and evidence partner,
not as a replacement for an EDR, SIEM, MSSP, or legal compliance advisor.

Suggested positioning line:

> Defensive security pilots for shared-PC venues: hardening review, integrity
> baselines, detection tuning, and operator-readable risk summaries.

What makes the offer specific:

- shared-PC venue threat model;
- billing and restoration-system operational context;
- false-positive handling for noisy venue software stacks;
- low-budget deployment assumptions;
- public defensive research artifacts that operators can inspect before buying.

## Pricing Hypotheses

Pricing should be validated with real buyers before public listing.

| Offer | Hypothesis | Notes |
| --- | --- | --- |
| Discovery call | Free | 30 minutes, only to qualify scope and authorization. |
| Lite pilot | USD 300-500 | One host role, one synthetic or authorized log sample, summary only. |
| Standard pilot | USD 900-1500 | Up to three host roles, baseline plan, tuning register, executive summary. |
| Vendor review package | USD 1500-3000 | Architecture review and defensive recommendations for a vendor or integrator. |

Do not discount by promising ongoing monitoring before the pilot workflow is
stable. If recurring revenue is tested later, start with monthly review support,
not a full managed SOC.

## 90-Day Commercial Roadmap

### Days 1-14: Validation Setup

- Create a one-page public offer sheet.
- Open a GitHub discussion or issue for commercial pilot questions.
- Ask three real operators or IT contractors to review the synthetic pilot
  package.
- Record objections: price, privacy concerns, time required, trust, and
  perceived urgency.
- Keep all feedback non-sensitive unless handled privately.

Exit criteria:

- at least three real conversations;
- one public or permissioned quote;
- one revised offer sheet.

### Days 15-45: Design Partner Pilot

- Offer one heavily scoped design-partner pilot.
- Use only written authorization and scoped systems.
- Apply the current intake, executive summary, and tuning-register templates.
- Produce one anonymized public lessons-learned note if the partner permits it.

Exit criteria:

- one completed pilot or documented rejection;
- updated templates based on real friction;
- one private or public testimonial if appropriate.

### Days 46-75: Repeatability

- Convert repeated pilot steps into a checklist-driven delivery process.
- Add a scheduled-task deployment example and baseline rotation guidance.
- Add synthetic Sigma fixtures and one tuning decision per rule family.
- Publish `v0.2.0` only when the workflow is materially more repeatable.

Exit criteria:

- `v0.2.0` release candidate;
- one complete synthetic pilot package;
- green CI;
- clear known limitations.

### Days 76-90: Revenue Test

- Approach five qualified prospects with the standard pilot offer.
- Track conversion, objections, and time spent per opportunity.
- Decide whether to continue service-led pilots, partner with IT contractors, or
  pause commercialization until more evidence exists.

Exit criteria:

- one paid pilot, or a written decision explaining why buyers did not convert;
- revised pricing and scope;
- clear next commercial experiment.

## Sales Qualification Rules

Only accept a pilot when all conditions are true:

- the buyer controls the systems or has written authorization;
- scope excludes customer private data and live credentials;
- the buyer understands this is defensive review, not bypass testing;
- there is an identified operational owner;
- findings can be delivered without naming vendors publicly;
- payment terms and cancellation boundaries are clear.

Reject or defer when:

- the buyer asks for billing bypass, exploit chains, stealth, or credential work;
- authorization is vague;
- the buyer wants public vendor accusations without coordinated disclosure;
- the scope requires legal or privacy advice beyond security-control review;
- expected effort exceeds the fixed-scope pilot.

## Distribution Channels

Start with channels where trust can be built through specificity:

- direct outreach to shared-PC venue operators and local IT contractors;
- LinkedIn posts showing the synthetic pilot workflow;
- GitHub issue #3 for public feedback;
- short research notes explaining practical tuning decisions;
- vendor-neutral outreach to billing or venue-management software providers;
- small MSSP conversations where CafeSec Lab can provide niche domain context.

Do not rely on broad social media launch posts as the main growth path. The
audience is narrow and trust-sensitive.

## Commercial Risks

| Risk | Why it matters | Mitigation |
| --- | --- | --- |
| Buyers do not feel urgency | Security is often invisible until an incident. | Sell a pilot as operational evidence and downtime reduction, not abstract security. |
| Too technical for venue owners | YARA, Sigma, and baselines can overwhelm buyers. | Lead with executive summary and 30-day action plan. |
| Existing tools appear to solve it | Wazuh, Sysmon, Defender, and MSSPs cover parts of the stack. | Differentiate on shared-PC workflow, tuning, and billing/restoration context. |
| Privacy and authorization concerns | Venues may handle customer or identity data. | Exclude sensitive data by default and require written scope. |
| Service delivery does not scale | A solo maintainer can become the bottleneck. | Keep fixed scope, templates, and clear non-goals. |
| CVP optics distort priorities | Commercial work could look like permission-chasing. | Keep buyer value, defensive deliverables, and public safety boundaries primary. |

## Metrics To Track

| Metric | Target for first 90 days |
| --- | --- |
| Qualified conversations | 8-12 |
| Public or permissioned feedback comments | 3 |
| Design-partner pilots | 1 |
| Paid pilots | 1 |
| Average delivery time | Under 10 hours for standard pilot |
| New public defensive artifacts | 3 |
| Rejected unsafe requests | Track all; publish aggregate lessons only if safe |

## Reference Context

- Wazuh documents file integrity monitoring as a core XDR/SIEM capability:
  <https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html>
- Microsoft Sysmon is a common Windows telemetry source for process and system
  activity:
  <https://learn.microsoft.com/windows/security/operating-system-security/sysmon/overview>
- CafeSec Lab project goal:
  <https://github.com/magnoormeno-dot/netcafe-security-lab/blob/main/docs/roadmap/project-goal.md>

