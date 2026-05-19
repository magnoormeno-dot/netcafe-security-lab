# Configuration

`monitor.example.yaml` shows a conservative configuration for a Windows venue.
`venue-pilot.example.yaml` adds a more operational pilot template for a
shared-PC gaming venue. The values are examples only. Replace paths, process keywords,
alert destinations, and excluded cache paths with local values.

## HMAC Key

Baseline HMAC keys should be generated and stored outside customer-writable directories.

```powershell
[byte[]] $key = 1..32 | ForEach-Object { Get-Random -Maximum 256 }
[IO.File]::WriteAllBytes("C:\CafeSec\baseline.hmac.key", $key)
```

## Suggested Storage

- Baseline: `C:\CafeSec\baseline.json` or a restricted SQLite file.
- Alerts: `C:\CafeSec\alerts.jsonl` or a central log share.
- HMAC key: password vault, secure admin share, or restricted local path.

Cashier users should not be able to modify baselines, HMAC keys, or alert outputs.
