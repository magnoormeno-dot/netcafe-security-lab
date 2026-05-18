# Detection Tuning And False Positive Handling

This guide defines how CafeSec Lab detection content should be tuned in real
venues. The goal is to reduce alert noise without hiding billing tampering,
service disablement, process manipulation, or evidence destruction.

Detection tuning is a change-control process. It is not a shortcut for deleting
rules after the first noisy day.

## Principles

- Tune by host role, approved maintenance window, signed publisher, service
  account, and change record before tuning by broad keyword.
- Prefer severity reduction or enrichment over full suppression.
- Every tuning decision needs an owner, reason, evidence, start date, expiry
  date, and review outcome.
- Never create permanent exceptions for customer-writable paths such as
  Downloads, Temp, desktop folders, browser cache directories, removable media,
  or game mod folders.
- Do not allowlist unsigned binaries unless the operator has a written vendor
  justification and a compensating control.
- Revisit tuning after vendor updates, billing software upgrades, restoration
  policy changes, and network segmentation changes.

## Standard Triage Workflow

1. Identify the host role: client PC, cashier workstation, billing server,
   image-builder, restoration console, network management host, or lab host.
2. Preserve the original event, matched rule, process tree, file path, user, and
   timestamp before making changes.
3. Check whether the event occurred during an approved maintenance or vendor
   support window.
4. Verify binary publisher and hash with `Get-AuthenticodeSignature` and
   `Get-FileHash`.
5. Check whether the source path is writable by customers, cashier users, or
   generic staff accounts.
6. Correlate with billing software audit logs, restoration logs, Windows service
   events, and central log collector data.
7. Decide one of four outcomes: true positive, benign expected activity, noisy
   but useful signal, or insufficient evidence.
8. Record the decision in the tuning register and set an expiry date.

## Approved Outcomes

| Outcome | Action | Requirements |
| --- | --- | --- |
| True positive | Escalate to incident response. | Preserve evidence, isolate only when necessary, and follow `checklist/05-incident-response.md`. |
| Benign expected activity | Add a narrow tuning entry. | Requires owner, change record, host role, exact path/user/window, and expiry. |
| Noisy but useful signal | Lower severity or add enrichment. | Keep the event visible in weekly review. |
| Insufficient evidence | Keep the rule active. | Collect more context before tuning. |

## Sigma Tuning Guidance

Sigma rules should be tuned after conversion to the target SIEM. Keep the source
rule generic and apply venue-specific filters in local content.

Recommended tuning dimensions:

- `Computer` or normalized host role.
- `User` or service account.
- `ParentImage`, `Image`, and signed publisher.
- `CommandLine` only when the command belongs to an approved script path.
- Maintenance window identifiers from change-control records.
- Vendor support session IDs where available.

Avoid broad filters such as:

- all events from `powershell.exe`;
- all events from an administrator account;
- all service stop events on billing servers;
- all registry writes by endpoint management tools;
- all events containing the vendor name.

## YARA Tuning Guidance

YARA matches in this project are triage signals. They should trigger context
collection, not automatic deletion or public attribution.

Recommended YARA triage steps:

1. Record file path, SHA-256, size, first-seen time, host role, and user context.
2. Check whether the file is signed by an expected publisher.
3. Compare against the approved software inventory and golden-image hash list.
4. Prioritize matches from customer-writable or staff-writable paths.
5. For commercial packers, document publisher, product, version, and source.
6. Re-scan after vendor updates because packer and import patterns can change.

Do not tune away a YARA match only because the file is present on many hosts.
Fleet-wide presence can indicate either legitimate deployment or broad
compromise.

## Tuning Register

Use `tuning-register.example.csv` as the minimum register. Store the real
register in the evidence zone or ticketing system, not in a public repository if
it contains vendor names, internal hostnames, usernames, or case details.

Minimum fields:

- `rule_id`
- `decision`
- `scope`
- `host_role`
- `match_field`
- `match_value`
- `reason`
- `evidence_reference`
- `owner`
- `approved_by`
- `created_utc`
- `expires_utc`
- `review_status`

## Review Cadence

| Cadence | Review |
| --- | --- |
| Daily during pilot | Review all high-severity alerts and new tuning candidates. |
| Weekly in production | Review expired exceptions, noisy rules, and untriaged medium/high alerts. |
| After vendor updates | Revalidate hashes, signatures, service names, and expected process behavior. |
| After incidents | Remove unsafe exceptions and back-test tuned rules against preserved events. |

## Red Flags

Treat the following as escalation triggers, even if an event resembles a known
false positive:

- customer-writable path involved;
- unsigned executable involved;
- service stop followed by billing state inconsistency;
- registry modification followed by logging, Defender, proxy, DNS, or startup
  drift;
- event occurred outside a maintenance window;
- log clearing or central collector outage near the detection;
- same alert appears across many client PCs in a short time window.

