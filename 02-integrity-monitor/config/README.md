# Configuration

`monitor.example.yaml` shows a conservative configuration for a Windows venue.
`venue-pilot.example.yaml` adds a more operational pilot template for a
shared-PC gaming venue. The values are examples only. Replace paths, process keywords,
alert destinations, and excluded cache paths with local values.

## Configuration Keys

The CLI reads the keys below. Any other key is reported in the log as
`config_key_ignored`, so a typo does not silently disable a setting.

| Key | Used by | Meaning |
| --- | --- | --- |
| `targets` | `baseline create`, `scan`, `monitor` | Files, directories, or globs to hash. |
| `excludes` | `baseline create`, `scan`, `monitor` | Glob patterns to skip. |
| `algorithms` | `baseline create`, `scan`, `monitor` | `sha256`, `blake3`, or both. |
| `alerting.file` | `scan`, `monitor` | JSON Lines alert file. `--alert-file` overrides it. |
| `alerting.dedup_window_seconds` | `scan`, `monitor` | Suppress a repeated alert inside this window. |
| `process_monitor.protected_process_keywords` | `monitor` | Names that mark billing or control processes. |
| `process_monitor.allowed_writable_processes` | `monitor` | Process names allowed to run from writable paths. |
| `process_monitor.suspicious_children` | `monitor` | Child process names that are suspicious under a protected parent. |
| `process_monitor.expected_hashes` | `monitor` | Map of executable path to approved SHA-256. Enables the hash-drift check. |
| `process_monitor.include_unsigned_check` | `monitor` | Set `false` to skip the Authenticode check. |
| `event_analyzer.channels` | `monitor` | Classic Windows logs to read. Names containing `/` are not supported. |
| `event_analyzer.state_file` | `monitor` | Where event-log bookmarks are kept. `--event-state-file` overrides it. |
| `event_analyzer.critical_keywords` | `monitor` | Keywords that mark venue-critical services and processes. |
| `event_analyzer.suspicious_processes` | `monitor` | Tool names that are suspicious near those keywords. |
| `event_analyzer.failed_login_burst_threshold` | `monitor` | Failed logons that make a burst. |
| `event_analyzer.failed_login_burst_window_minutes` | `monitor` | Time window for a burst. |
| `pilot` | none | Free-form pilot notes. Not read by the tool. |

A file and a webhook can be used together: pass `--webhook-url` and every alert
goes to both. The console is used only when neither is configured.

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
- Event-log bookmarks: `C:\CafeSec\event-state.json`.

Cashier users should not be able to modify baselines, HMAC keys, or alert outputs.
