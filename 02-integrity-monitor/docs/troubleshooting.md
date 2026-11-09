# Troubleshooting

## Baseline Verification Fails

- Confirm the same HMAC key is used for creation and verification.
- Confirm the baseline file was not edited manually.
- Restore the last known-good baseline from backup if tampering is suspected.
- `signed but no HMAC key was provided` means the baseline carries a signature and the command ran without `--hmac-key-file`. Pass the key. A signed baseline is never accepted unchecked.

## Scan Reports A Missing Or Unreadable Baseline

`scan` exits non-zero and raises a critical alert (`Baseline missing`, `Baseline failed verification`, or `Baseline HMAC key unavailable`) instead of reporting zero changes.

- On a new host, run `integrity-monitor baseline create` first.
- On a host that already had a baseline, treat the missing or damaged file as possible tampering. Preserve the host state before restoring the baseline from backup.

## Too Many File Changes

- Check whether a vendor update or game cache path was included.
- Add cache directories to `excludes`.
- Re-baseline only after validating the update source and signatures.

## BLAKE3 Is Unavailable

Install dependencies with:

```powershell
python -m pip install -r requirements.txt
```

Or use only `sha256` in configuration.

## Windows Event Logs Are Empty

- On Linux and CI, live Windows event collection returns no events by design.
- On Windows, install the optional `windows` dependencies.
- Confirm the process has permission to read Security and System logs.
- Only classic logs are read. A channel name containing `/`, such as `Microsoft-Windows-PowerShell/Operational`, is skipped with an `event_channel_not_supported` warning.
- After the first read, each poll returns only events newer than the bookmark. An empty result on a quiet host is expected.
- For `monitor --once` on a schedule, set `--event-state-file` or `event_analyzer.state_file`. Without it every run starts again from the most recent events.
- An `event_log_gap` warning means events were lost between polls, either because the log wrapped or because more than the backlog limit arrived. Enlarge the log or poll more often.

## Webhook Alerts Fail

- Confirm the webhook URL and type.
- Test with console or file alerting first.
- Check proxy and outbound firewall policy.
- A failed delivery does not stop the run. The alert is printed to stderr, the remaining alerts are still sent, and `monitor` retries it on the next cycle.
- Configure an alert file alongside the webhook so a local copy exists while the webhook is unreachable.
- The webhook URL is left out of error messages on purpose, because it is a credential.
