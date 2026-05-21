# Synthetic Shared-PC Venue Pilot Package

This package is a fully synthetic example for reviewers, operators, and
contributors. It shows how CafeSec Lab expects a defensive pilot to be scoped,
logged, tuned, and summarized without exposing customer data, vendor secrets, or
real venue details.

It is not field validation. It is a reproducible example of the workflow the
project is building toward for `v0.2.0`.

## Package Contents

| File | Purpose |
| --- | --- |
| `intake.md` | Synthetic venue profile and review scope. |
| `sample-events.jsonl` | Synthetic monitoring and Windows-style event records. |
| `tuning-register.csv` | Example false-positive and escalation decisions. |
| `executive-summary.md` | Operator-readable pilot summary. |

## Scenario Summary

The synthetic venue has:

- one billing server;
- one cashier workstation;
- twelve shared client PCs;
- restoration software on client PCs;
- a vendor updater that restarts selected services during a maintenance window;
- integrity monitoring configured for billing and restoration paths only.

The pilot intentionally creates one benign false-positive pattern: an approved
vendor updater restarts a billing client service and updates one signed binary.
The package shows how that event should be documented, narrowed, and reviewed
instead of being broadly allowlisted.

## Safety Boundaries

The package does not include:

- real customer names or account data;
- credentials or tokens;
- real vendor names;
- private IP addressing from an actual venue;
- exploit code, bypass steps, or abuse instructions.

## How To Use This Package

1. Read `intake.md` to understand the scoped environment.
2. Review `sample-events.jsonl` as if it were one day of pilot telemetry.
3. Review `tuning-register.csv` to see how decisions are recorded.
4. Read `executive-summary.md` as the operator-facing output.
5. Compare findings with `docs/operators/executive-summary-template.md`.

The goal is repeatability: the same structure should work for a real authorized
pilot after replacing synthetic facts with approved private evidence.

