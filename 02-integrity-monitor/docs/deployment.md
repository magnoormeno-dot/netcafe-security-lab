# Deployment

## Pilot First

Deploy the monitor to one non-production host or a small pilot group before enabling broad alerting. Gaming venues have noisy software stacks, and every rule needs local context.

For a field-ready one-week procedure, use `pilot-runbook.md` with
`../config/venue-pilot.example.yaml`.

## Recommended Windows Layout

- Install path: `C:\CafeSec\IntegrityMonitor`
- Baseline path: `C:\CafeSec\baseline.json`
- HMAC key path: `C:\CafeSec\baseline.hmac.key`
- Alert path: `C:\CafeSec\alerts.jsonl`
- Central copy: Wazuh, Windows Event Forwarding, SIEM, or restricted share

## Baseline Workflow

1. Build or validate a known-good host.
2. Create a baseline with `integrity-monitor baseline create`.
3. Store the HMAC key in a restricted location.
4. Run `integrity-monitor scan` daily or after updates.
5. Re-baseline only after approved changes.

## Scheduled Task Example

Run as a dedicated low-privilege monitoring account with read access to target paths and write access only to the alert destination.

```powershell
integrity-monitor scan `
  --config "C:\CafeSec\monitor.local.yaml" `
  --store "C:\CafeSec\baseline.json" `
  --hmac-key-file "C:\CafeSec\baseline.hmac.key" `
  --alert-file "C:\CafeSec\alerts.jsonl"
```

## Operations

- Treat deleted or modified billing binaries as high severity.
- Preserve alerts and scan output before reimaging.
- Re-baseline after vendor updates only when signatures, hashes, and service health are validated.
