# CafeSec Integrity Monitor

CafeSec Integrity Monitor is a defensive monitoring tool for internet cafes, gaming venues, esports hotels, and shared-PC environments. It creates signed file baselines, scans billing-related paths, monitors process anomalies, analyzes Windows event-log patterns, and sends deduplicated alerts.

The tool is intentionally conservative. It does not bypass, patch, exploit, or tamper with billing software. It gives operators evidence when critical files, services, processes, or logs drift from an expected baseline.

## Features

- JSON or SQLite baseline storage.
- Optional HMAC baseline signatures for tamper evidence.
- SHA-256 and BLAKE3 file hashing.
- File, directory, and glob scanning.
- Incremental file scanning using size and mtime prefilters.
- Process anomaly checks for writable directories, unsigned Windows binaries, unusual parent-child relationships, and known-good baseline drift.
- Windows event-log analysis for logon, process creation, service installation, service state, registry modification, and log-clearing events.
- Console, file, and webhook alerting with time-window deduplication.
- CLI commands for `baseline`, `scan`, `monitor`, and `verify`.

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e .[dev]
```

## Quick Start

```powershell
# Create a baseline.
integrity-monitor baseline create --path "C:\CafeBilling" --store .\baseline.json --hmac-key-file .\hmac.key

# Scan against the latest baseline.
integrity-monitor scan --path "C:\CafeBilling" --store .\baseline.json --hmac-key-file .\hmac.key

# Verify baseline signatures.
integrity-monitor verify --store .\baseline.json --hmac-key-file .\hmac.key
```

## Safety Notes

- Test on a non-production host before broad deployment.
- Do not store HMAC keys in the same writable directory as baselines.
- Send alerts to a location cashier users cannot edit.
- Preserve evidence before reimaging a suspicious host.

## License

MIT.
