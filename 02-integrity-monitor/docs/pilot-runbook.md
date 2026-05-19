# Pilot Runbook For Shared-PC Gaming Venues

This runbook describes a conservative first deployment of CafeSec Integrity
Monitor in an internet cafe, gaming venue, esports hotel, or managed shared-PC
site. It is
designed for a one-week pilot before broad rollout.

The monitor is defensive and read-oriented. It should not modify billing
software, restoration software, game launchers, customer data, or payment
records.

## Pilot Scope

Start with three host roles:

| Host role | Purpose | Initial targets |
| --- | --- | --- |
| Client PC | Detect drift in billing agent, restoration agent, and local enforcement files. | Billing client agent, restoration agent, approved local config files. |
| Cashier workstation | Detect drift in cashier application files and local configuration. | Cashier application directory, local config, approved plugin directory. |
| Billing server | Detect drift in server binaries and operational configuration. | Billing server application, service configuration exports, integration plugins. |

Do not monitor customer profile folders, browser histories, chat logs, payment
exports, CCTV exports, or identity-document storage during the pilot. Those data
sets require separate legal, privacy, and retention review.

## Directory Layout

Use a restricted local directory on each host:

```powershell
New-Item -ItemType Directory -Path C:\CafeSec -Force | Out-Null
New-Item -ItemType Directory -Path C:\CafeSec\logs -Force | Out-Null
icacls C:\CafeSec /inheritance:r
icacls C:\CafeSec /grant:r "Administrators:(OI)(CI)(F)" "SYSTEM:(OI)(CI)(F)"
```

If a non-administrator monitoring account is used, grant it read access to the
monitored application paths and append-only write access to the alert location.
Do not grant cashier or customer accounts write access to baselines, HMAC keys,
or alert outputs.

## Install

Use a controlled administrative PowerShell session. During the current pilot,
install from a checked-out repository and keep the virtual environment outside
customer-writable paths:

```powershell
cd C:\CafeSec
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e C:\CafeSec\netcafe-security-lab\02-integrity-monitor
```

After a signed package or internal wheel is available, replace the editable
install with a pinned package artifact from a trusted repository:

```powershell
python -m pip install cafesec-integrity-monitor==0.1.0
```

## Configure

Copy the example configuration and replace vendor-specific paths:

```powershell
Copy-Item .\config\venue-pilot.example.yaml C:\CafeSec\monitor.local.yaml
notepad C:\CafeSec\monitor.local.yaml
```

Generate an HMAC key and restrict it:

```powershell
[byte[]] $Key = 1..32 | ForEach-Object { Get-Random -Maximum 256 }
[IO.File]::WriteAllBytes("C:\CafeSec\baseline.hmac.key", $Key)
icacls C:\CafeSec\baseline.hmac.key /inheritance:r
icacls C:\CafeSec\baseline.hmac.key /grant:r "Administrators:F" "SYSTEM:F"
```

## Create The First Baseline

Create the baseline only after the host is known-good, patched, and approved by
the venue operator or service provider.

```powershell
integrity-monitor baseline create `
  --config C:\CafeSec\monitor.local.yaml `
  --store C:\CafeSec\baseline.json `
  --hmac-key-file C:\CafeSec\baseline.hmac.key `
  --metadata venue=venue-pilot `
  --metadata role=client-pc `
  --metadata approved_by=operator
```

Verify that the baseline signature can be checked:

```powershell
integrity-monitor verify `
  --store C:\CafeSec\baseline.json `
  --hmac-key-file C:\CafeSec\baseline.hmac.key
```

## Run A Manual Scan

Run the first scan interactively and inspect the JSON summary:

```powershell
integrity-monitor scan `
  --config C:\CafeSec\monitor.local.yaml `
  --store C:\CafeSec\baseline.json `
  --hmac-key-file C:\CafeSec\baseline.hmac.key `
  --alert-file C:\CafeSec\alerts.jsonl
```

Expected first result after a clean baseline:

```json
{
  "changes": 0,
  "findings": 0
}
```

Non-zero findings are not automatically malicious. Triage them against vendor
updates, game launcher changes, restoration exceptions, and known maintenance
activity before escalating.

## Scheduled Task Pilot

Run every 30 minutes during business hours and after the nightly restoration
cycle:

```powershell
$Action = New-ScheduledTaskAction `
  -Execute "C:\CafeSec\.venv\Scripts\integrity-monitor.exe" `
  -Argument "scan --config C:\CafeSec\monitor.local.yaml --store C:\CafeSec\baseline.json --hmac-key-file C:\CafeSec\baseline.hmac.key --alert-file C:\CafeSec\alerts.jsonl"
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddHours(8) `
  -RepetitionInterval (New-TimeSpan -Minutes 30) `
  -RepetitionDuration (New-TimeSpan -Hours 16)
Register-ScheduledTask `
  -TaskName "CafeSec Integrity Monitor Scan" `
  -Action $Action `
  -Trigger $Trigger `
  -Description "CafeSec file integrity scan for approved billing and restoration paths" `
  -RunLevel Highest
```

Review task results:

```powershell
Get-ScheduledTaskInfo -TaskName "CafeSec Integrity Monitor Scan"
Get-Content C:\CafeSec\alerts.jsonl -Tail 20
```

## Acceptance Criteria

Treat the pilot as successful only when all conditions are met:

- Seven consecutive days of successful scans on each pilot host role.
- No untriaged high-severity file modifications or removals.
- All expected changes are tied to approved maintenance records.
- Baseline HMAC verification succeeds after each maintenance window.
- Alerts are stored somewhere cashier and customer accounts cannot edit.
- At least one operator can explain when to re-baseline and when not to.

## Re-Baseline Rules

Re-baseline only after:

- the vendor update source is verified;
- file signatures and hashes are reviewed;
- billing, cashier, restoration, and logging services are healthy;
- the change is recorded with date, approver, host role, and reason.

Do not re-baseline to silence unexplained alerts. Preserve `alerts.jsonl`, the
old baseline, the new scan output, and relevant Windows event logs before making
changes.

## Pilot Report Template

```text
Venue:
Host role:
Hostname:
Pilot dates:
Baseline version:
Baseline approver:
Scan interval:
Alert destination:
Total file changes:
Unexplained file changes:
High-severity alerts:
False positives:
Operational issues:
Decision: expand / repeat pilot / stop
```
