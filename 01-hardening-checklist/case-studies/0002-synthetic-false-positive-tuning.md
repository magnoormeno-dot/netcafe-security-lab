# Case Study 0002: Synthetic False-Positive Tuning During A Vendor Update

## Status

Synthetic example. No vendor, venue, customer, credential, or real telemetry is
represented here.

## Summary

A shared-PC venue runs a weekly vendor maintenance window. During the window, a
signed updater stops a billing client service, replaces one signed binary, and
starts the service again. The monitoring stack raises a service-disabled alert
and a file-integrity alert.

The important decision is not whether to silence the alert. The important
decision is how narrowly the alert can be explained without weakening future
detection.

## Observed Signals

| Signal | Synthetic evidence |
| --- | --- |
| Service stop | `SyntheticBillingClient` entered stopped state. |
| Service start | Same service restarted within one minute. |
| File change | `billing-agent.exe` hash changed. |
| Publisher | Replacement binary had a valid synthetic vendor signature. |
| Maintenance ticket | `SYN-CHG-0007` covered the update window. |

## Initial Risk

Stopping a billing client service can affect local billing enforcement, session
control, or operator visibility. A file change in the same window can be benign
vendor maintenance, but it can also hide unauthorized modification if the venue
uses broad allowlists or re-baselines immediately.

## Tuning Decision

The alert was not disabled. The decision was:

- lower severity only inside the approved maintenance window;
- limit the match to the signed updater path;
- require a maintenance ticket reference;
- keep the same service stop outside maintenance as high priority;
- set an expiry date for review.

## Why This Matters

False positives are operational work. If staff learn that every service restart
is meaningless, they stop reading alerts. If every vendor update is treated as a
security incident, the monitoring process becomes too expensive to run.

The defensible middle path is evidence-backed tuning: narrow scope, documented
owner, expiry date, and a preserved high-priority path for unexplained events.

## Follow-Up Controls

- Record vendor updater path, publisher, and expected service behavior.
- Preserve old and new hashes before re-baselining.
- Review temporary tuning after the next maintenance cycle.
- Add failed restart or missing restart as a separate escalation condition.
- Keep billing-server logon events in scope during the same maintenance window.

## References

- Synthetic pilot package:
  `docs/pilot/synthetic-shared-pc-venue/`
- Tuning guide:
  `01-hardening-checklist/detection/tuning-guide.md`
- Operator summary template:
  `docs/operators/executive-summary-template.md`

