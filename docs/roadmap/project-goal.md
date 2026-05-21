# CafeSec Lab Project Goal

This document defines the current operating goal for CafeSec Lab. It should help
decide what to build, what to defer, and what not to publish.

## North Star Goal

By 2026-08-31, CafeSec Lab should demonstrate a repeatable defensive workflow
for shared-PC venues: intake, threat model, hardening review, integrity-monitor
baseline, detection tuning, and an operator-readable risk summary.

The goal is not to prove that one vendor, region, or venue type is secure or
insecure. The goal is to make practical defensive work easier to verify and
repeat.

## Success Criteria

The goal is met when the project can show all of the following:

- a public operator workflow that starts with a lightweight intake form and ends
  with an executive summary;
- at least one complete synthetic pilot package using anonymized, non-sensitive
  data;
- integrity-monitor deployment guidance that a Windows operator can follow in a
  test environment;
- one documented false-positive tuning path for each Sigma rule family;
- one detection or monitoring deep-dive that explains the reasoning behind a
  rule without publishing bypass instructions;
- a `v0.2.0` release with clear defensive value, known limitations, and
  non-goals;
- green CI and working public links for `cafeseclab.com`,
  `research.cafeseclab.com`, and `security.txt`.

## Near-Term Milestones

| Milestone | Target outcome |
| --- | --- |
| `v0.1.x` maintenance | Keep identity, links, CI, and contact channels clean. |
| Operator workflow draft | Publish intake, executive-summary, and post-pilot templates. |
| Detection tuning evidence | Add synthetic fixtures and tuning decisions for current rules. |
| Integrity monitor deployment | Document scheduled-task deployment and baseline rotation. |
| `v0.2.0` release | Package the first repeatable defensive pilot workflow. |

## Non-Goals

CafeSec Lab will not pursue these as project goals:

- publishing bypass tools, exploit chains, credentials, or weaponized proof of
  concept code;
- making vendor-specific vulnerability claims outside coordinated disclosure;
- presenting synthetic examples as field validation;
- optimizing for certification optics at the expense of technical defensibility;
- expanding into broad security consulting before the shared-PC venue workflow
  is coherent.

## Operating Principle

Every public artifact should answer at least one of these questions:

- Can an operator verify a control state more reliably?
- Can a defender tune a detection with less operational fatigue?
- Can a vendor or venue identify a safer architecture decision?
- Can a future researcher reproduce the reasoning without needing private data?

If an artifact does not answer one of those questions, it should be deferred.

