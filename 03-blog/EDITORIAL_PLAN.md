# CafeSec Lab Editorial Plan

This file tracks future research-note formats for the v0.2 phase. The goal is
to keep the blog recognizably technical while avoiding a single repeated essay
shape.

## v0.2 Format Goals

- Publish at least one operator Q&A article.
- Publish at least one anonymized case-study article.
- Publish at least one detection engineering deep dive tied to a Sigma or YARA
  rule in this repository.
- Keep every article defensive: no bypass tooling, no vendor accusation without
  coordinated disclosure, and no operational detail that helps abuse billing
  systems.

## Planned Articles

| Working title | Format | Status | Why it exists |
| --- | --- | --- | --- |
| Ten Questions Operators Ask Before Hardening a Shared-PC Venue | Q&A | Planned | Uses the language of owners and IT contractors instead of conference-paper structure. |
| A Billing Agent Stopped During Peak Hours: An Anonymized Response Timeline | Case study | Planned | Shows evidence handling, containment, and recovery decisions without naming a venue or vendor. |
| How `billing_process_termination.yml` Became a Sigma Rule | Detection deep dive | Planned | Explains rule intent, log source assumptions, false-positive tuning, and validation workflow. |

## Style Notes

- Use "we" only when it reflects project practice or observed operational
  patterns.
- Prefer concrete venue operations over abstract maturity language.
- Vary article endings: checklist, timeline, decision tree, Q&A recap, or rule
  tuning notes.
- Avoid leaning too often on the pattern "X is not Y; it is Z." Use it only
  when the contrast is doing real analytical work.
