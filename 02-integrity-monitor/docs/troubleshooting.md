# Troubleshooting

## Baseline Verification Fails

- Confirm the same HMAC key is used for creation and verification.
- Confirm the baseline file was not edited manually.
- Restore the last known-good baseline from backup if tampering is suspected.

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

## Webhook Alerts Fail

- Confirm the webhook URL and type.
- Test with console or file alerting first.
- Check proxy and outbound firewall policy.
