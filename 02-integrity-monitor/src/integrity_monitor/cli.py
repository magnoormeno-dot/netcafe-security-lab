"""Command-line interface for CafeSec Integrity Monitor."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, cast

import click
import yaml

from integrity_monitor.alerting import (
    Alert,
    AlertDeliveryError,
    Alerter,
    ConsoleAlerter,
    DeduplicationCache,
    FileAlerter,
    WebhookAlerter,
)
from integrity_monitor.core.baseline import (
    BaselineIntegrityError,
    BaselineManager,
    BaselineNotFoundError,
)
from integrity_monitor.core.event_analyzer import (
    EventAnalyzer,
    EventFinding,
    EventProvider,
    JsonEventProvider,
    WindowsEventProvider,
)
from integrity_monitor.core.file_integrity import (
    FileChange,
    FileIntegrityMonitor,
    HashAlgorithm,
    IntegrityScanResult,
    ScanTarget,
)
from integrity_monitor.core.process_monitor import ProcessMonitor
from integrity_monitor.utils.logging import configure_logging

LOGGER = logging.getLogger(__name__)

# Every configuration key the CLI reads. ``None`` marks a key without nested
# options. Anything else in a config file is reported instead of being dropped
# silently.
_CONFIG_KEYS: dict[str, frozenset[str] | None] = {
    "targets": None,
    "excludes": None,
    "algorithms": None,
    "alerting": frozenset({"dedup_window_seconds", "file"}),
    "process_monitor": frozenset(
        {
            "protected_process_keywords",
            "allowed_writable_processes",
            "suspicious_children",
            "expected_hashes",
            "include_unsigned_check",
        }
    ),
    "event_analyzer": frozenset(
        {
            "channels",
            "state_file",
            "critical_keywords",
            "suspicious_processes",
            "failed_login_burst_threshold",
            "failed_login_burst_window_minutes",
        }
    ),
    # Free-form pilot bookkeeping carried in the venue templates.
    "pilot": None,
}


class _HmacKeyError(click.ClickException):
    """Raised when the HMAC key file cannot be used."""


def _read_hmac_key(path: str | None) -> bytes | None:
    if path is None:
        return None
    try:
        key = Path(path).read_bytes().strip()
    except OSError as exc:
        raise _HmacKeyError(f"Cannot read HMAC key file {path}: {exc}") from exc
    if not key:
        raise _HmacKeyError(f"HMAC key file is empty: {path}")
    return key


# Conditions under which files cannot be compared with a trusted baseline.
_BASELINE_FAILURES = (BaselineNotFoundError, BaselineIntegrityError, _HmacKeyError)


def _scan_against_baseline(
    store: str,
    hmac_key_file: str | None,
    *,
    targets: list[ScanTarget],
    algorithms: list[HashAlgorithm],
    excludes: list[str],
) -> IntegrityScanResult:
    """Scan targets against the latest baseline, raising if there is none to trust."""

    manager = BaselineManager(store, hmac_key=_read_hmac_key(hmac_key_file))
    monitor = FileIntegrityMonitor(
        targets,
        algorithms=algorithms,
        excludes=excludes,
        baseline_manager=manager,
    )
    return monitor.scan(require_baseline=True)


def _load_config(path: str | None) -> dict[str, Any]:
    if path is None:
        return {}
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise click.ClickException("Configuration file must contain a mapping")
    config = dict(payload)
    _warn_unknown_config_keys(config)
    return config


def _warn_unknown_config_keys(config: dict[str, Any]) -> None:
    for key, value in config.items():
        if key not in _CONFIG_KEYS:
            LOGGER.warning("config_key_ignored", extra={"key": str(key)})
            continue
        known = _CONFIG_KEYS[key]
        if known is None or not isinstance(value, dict):
            continue
        for nested in value:
            if nested not in known:
                LOGGER.warning("config_key_ignored", extra={"key": f"{key}.{nested}"})


def _section(config: dict[str, Any], name: str) -> dict[str, Any]:
    value = config.get(name)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise click.ClickException(f"{name} must be a mapping")
    return dict(value)


def _str_list(section: dict[str, Any], name: str, key: str) -> list[str] | None:
    value = section.get(key)
    if value is None:
        return None
    if not isinstance(value, list):
        raise click.ClickException(f"{name}.{key} must be a list")
    return [str(item) for item in value]


def _str_set(section: dict[str, Any], name: str, key: str) -> set[str] | None:
    values = _str_list(section, name, key)
    return None if values is None else set(values)


def _int_option(section: dict[str, Any], name: str, key: str, default: int) -> int:
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise click.ClickException(f"{name}.{key} must be a non-negative integer")
    return value


def _targets_from_args(paths: tuple[str, ...], config: dict[str, Any]) -> list[ScanTarget]:
    configured = config.get("targets", [])
    targets: list[str] = list(paths)
    if isinstance(configured, list):
        targets.extend(str(item) for item in configured)
    if not targets:
        raise click.ClickException("At least one --path or configured target is required")
    return [ScanTarget(pattern=target) for target in targets]


def _algorithms(config: dict[str, Any], cli_algorithms: tuple[str, ...]) -> list[HashAlgorithm]:
    if cli_algorithms:
        values = list(cli_algorithms)
    else:
        configured = config.get("algorithms", ["sha256"])
        if not isinstance(configured, list):
            raise click.ClickException("algorithms must be a list")
        values = [str(item) for item in configured]
    invalid = sorted(set(values) - {"sha256", "blake3"})
    if invalid:
        raise click.ClickException(f"Unsupported algorithm(s): {', '.join(invalid)}")
    return [cast(HashAlgorithm, item) for item in values]


def _excludes(config: dict[str, Any]) -> list[str]:
    configured = config.get("excludes", [])
    if not isinstance(configured, list):
        raise click.ClickException("excludes must be a list")
    return [str(item) for item in configured]


def _alerters_from_options(
    config: dict[str, Any],
    *,
    alert_file: str | None,
    webhook_url: str | None,
    webhook_kind: str,
) -> list[Alerter]:
    """Build every alert backend requested on the command line or in config.

    ``--alert-file`` overrides ``alerting.file``. A file and a webhook can be
    used together. The console is used when neither is configured.
    """

    section = _section(config, "alerting")
    window = _int_option(section, "alerting", "dedup_window_seconds", 900)
    configured_file = section.get("file")
    file_path = alert_file or (None if configured_file is None else str(configured_file))

    alerters: list[Alerter] = []
    if file_path:
        alerters.append(FileAlerter(file_path, dedup_cache=DeduplicationCache(window)))
    if webhook_url:
        alerters.append(
            WebhookAlerter(webhook_url, kind=webhook_kind, dedup_cache=DeduplicationCache(window))
        )
    if not alerters:
        alerters.append(ConsoleAlerter(dedup_cache=DeduplicationCache(window)))
    return alerters


class _AlertDispatcher:
    """Send alerts to every backend without letting a failed one stop the run.

    An alert a backend could not deliver is echoed to stderr once, kept in a
    bounded queue, and retried by ``retry_pending``.
    """

    MAX_PENDING = 1000

    def __init__(self, alerters: list[Alerter]) -> None:
        self.alerters = alerters
        self._pending: dict[tuple[int, str], tuple[Alerter, Alert]] = {}

    @property
    def undelivered(self) -> int:
        """Return how many alerts are still waiting for a backend."""

        return len(self._pending)

    def emit(self, alert: Alert) -> None:
        """Send an alert to every backend."""

        for alerter in self.alerters:
            self._deliver(alerter, alert)

    def retry_pending(self) -> None:
        """Try again to deliver alerts that failed earlier."""

        for alerter, alert in list(self._pending.values()):
            self._deliver(alerter, alert)

    def _deliver(self, alerter: Alerter, alert: Alert) -> None:
        key = (id(alerter), alert.stable_key())
        try:
            alerter.emit(alert)
        except AlertDeliveryError as exc:
            if key not in self._pending:
                LOGGER.error(
                    "alert_delivery_failed",
                    extra={
                        "backend": type(alerter).__name__,
                        "error": str(exc),
                        "title": alert.title,
                    },
                )
                # Keep a copy where the operator can still find it.
                click.echo(json.dumps(alert.__dict__, ensure_ascii=True, default=str), err=True)
                if len(self._pending) >= self.MAX_PENDING:
                    dropped = next(iter(self._pending))
                    LOGGER.error(
                        "alert_retry_queue_full", extra={"dropped": self._pending[dropped][1].title}
                    )
                    del self._pending[dropped]
            self._pending[key] = (alerter, alert)
        else:
            self._pending.pop(key, None)


def _file_change_alert(change: FileChange, *, severity: str, dedup_key: str | None) -> Alert:
    return Alert(
        title=f"File {change.change_type}: {Path(change.path).name}",
        severity=severity,
        source="file_integrity",
        description=f"{change.change_type.title()} file detected at {change.path}",
        dedup_key=dedup_key,
        details=change.__dict__,
    )


def _baseline_failure_alert(store: str, error: Exception) -> Alert:
    """Describe a baseline that is missing or cannot be trusted.

    Without a trusted baseline no file comparison can run, so this is reported
    as a critical alert instead of an empty result.
    """

    if isinstance(error, BaselineNotFoundError):
        kind, title = "missing", "Baseline missing"
    elif isinstance(error, _HmacKeyError):
        kind, title = "key", "Baseline HMAC key unavailable"
    else:
        kind, title = "invalid", "Baseline failed verification"
    return Alert(
        title=title,
        severity="critical",
        source="file_integrity",
        description=(
            f"File integrity could not be checked against {store}: {error}. "
            "Treat this as possible tampering until the baseline is restored."
        ),
        dedup_key=f"baseline:{kind}:{store}",
        details={"store": store, "error": str(error)},
    )


def _event_dedup_key(finding: EventFinding) -> str:
    key = f"{finding.rule_id}:{finding.event.computer}:{finding.event.event_id}"
    record_number = finding.event.data.get("record_number")
    # Distinct log records are distinct alerts. Without a record number, fall
    # back to one alert per rule, host, and event ID inside the window.
    return key if record_number is None else f"{key}:{record_number}"


def _process_monitor_from_config(config: dict[str, Any]) -> ProcessMonitor:
    name = "process_monitor"
    section = _section(config, name)
    expected_hashes = section.get("expected_hashes")
    if expected_hashes is not None and not isinstance(expected_hashes, dict):
        raise click.ClickException(f"{name}.expected_hashes must map executable paths to SHA-256")
    include_unsigned_check = section.get("include_unsigned_check", True)
    if not isinstance(include_unsigned_check, bool):
        raise click.ClickException(f"{name}.include_unsigned_check must be true or false")
    return ProcessMonitor(
        expected_hashes=(
            None
            if expected_hashes is None
            else {str(path): str(digest) for path, digest in expected_hashes.items()}
        ),
        allowed_writable_processes=_str_set(section, name, "allowed_writable_processes"),
        protected_process_keywords=_str_set(section, name, "protected_process_keywords"),
        suspicious_children=_str_set(section, name, "suspicious_children"),
        include_unsigned_check=include_unsigned_check,
    )


def _event_analyzer_from_config(
    config: dict[str, Any],
    *,
    event_json: str | None,
    event_state_file: str | None,
) -> EventAnalyzer:
    name = "event_analyzer"
    section = _section(config, name)
    provider: EventProvider
    if event_json:
        provider = JsonEventProvider(event_json)
    else:
        configured_state = section.get("state_file")
        provider = WindowsEventProvider(
            channels=_str_list(section, name, "channels"),
            state_path=event_state_file
            or (None if configured_state is None else str(configured_state)),
        )
    return EventAnalyzer(
        provider=provider,
        critical_keywords=_str_set(section, name, "critical_keywords"),
        suspicious_processes=_str_set(section, name, "suspicious_processes"),
        failed_login_burst_threshold=_int_option(section, name, "failed_login_burst_threshold", 5),
        failed_login_burst_window_minutes=_int_option(
            section, name, "failed_login_burst_window_minutes", 10
        ),
    )


@click.group()
@click.option("--log-level", default="INFO", show_default=True, help="Logging level.")
@click.option("--plain-logs", is_flag=True, help="Emit human-readable logs instead of JSON logs.")
def main(log_level: str, plain_logs: bool) -> None:
    """Defensive integrity monitoring for shared-PC venues."""

    configure_logging(log_level, json_logs=not plain_logs)


@main.group()
def baseline() -> None:
    """Manage file integrity baselines."""


@baseline.command("create")
@click.option("--path", "paths", multiple=True, help="File, directory, or glob to baseline.")
@click.option("--store", required=True, help="Baseline storage path (.json or .sqlite).")
@click.option("--config", "config_path", help="Optional YAML configuration file.")
@click.option("--hmac-key-file", help="File containing HMAC key bytes.")
@click.option("--algorithm", "algorithms", multiple=True, help="Hash algorithm: sha256 or blake3.")
@click.option("--metadata", multiple=True, help="Metadata as key=value.")
def baseline_create(
    paths: tuple[str, ...],
    store: str,
    config_path: str | None,
    hmac_key_file: str | None,
    algorithms: tuple[str, ...],
    metadata: tuple[str, ...],
) -> None:
    """Create and persist a new baseline version."""

    config = _load_config(config_path)
    manager = BaselineManager(store, hmac_key=_read_hmac_key(hmac_key_file))
    monitor = FileIntegrityMonitor(
        _targets_from_args(paths, config),
        algorithms=_algorithms(config, algorithms),
        excludes=_excludes(config),
        baseline_manager=manager,
    )
    metadata_map: dict[str, object] = dict(_metadata_map(metadata))
    version = monitor.create_baseline(metadata=metadata_map)
    click.echo(json.dumps(version.to_dict(), indent=2, sort_keys=True, default=str))


@baseline.command("list")
@click.option("--store", required=True, help="Baseline storage path.")
@click.option("--hmac-key-file", help="File containing HMAC key bytes.")
def baseline_list(store: str, hmac_key_file: str | None) -> None:
    """List baseline versions."""

    manager = BaselineManager(store, hmac_key=_read_hmac_key(hmac_key_file))
    versions = manager.list_versions()
    for version in versions:
        valid = manager.verify_version(version)
        click.echo(
            f"{version.version_id}\t{version.created_at}\tvalid={valid}"
            f"\trecords={len(version.records)}"
            f"\tsignature={manager.signature_status(version)}"
        )


@baseline.command("rollback")
@click.option("--store", required=True, help="Baseline storage path.")
@click.option("--version-id", required=True, help="Version to roll back to.")
@click.option("--hmac-key-file", help="File containing HMAC key bytes.")
def baseline_rollback(store: str, version_id: str, hmac_key_file: str | None) -> None:
    """Create a new latest baseline from a previous version."""

    manager = BaselineManager(store, hmac_key=_read_hmac_key(hmac_key_file))
    version = manager.rollback(version_id)
    click.echo(json.dumps(version.to_dict(), indent=2, sort_keys=True, default=str))


@main.command()
@click.option("--path", "paths", multiple=True, help="File, directory, or glob to scan.")
@click.option("--store", required=True, help="Baseline storage path.")
@click.option("--config", "config_path", help="Optional YAML configuration file.")
@click.option("--hmac-key-file", help="File containing HMAC key bytes.")
@click.option("--algorithm", "algorithms", multiple=True, help="Hash algorithm: sha256 or blake3.")
@click.option("--alert-file", help="Write alerts to JSON Lines file.")
@click.option("--webhook-url", help="Send alerts to webhook URL.")
@click.option(
    "--webhook-kind", default="generic", show_default=True, help="generic, slack, or discord."
)
def scan(
    paths: tuple[str, ...],
    store: str,
    config_path: str | None,
    hmac_key_file: str | None,
    algorithms: tuple[str, ...],
    alert_file: str | None,
    webhook_url: str | None,
    webhook_kind: str,
) -> None:
    """Scan files against the latest baseline.

    Exits non-zero when the baseline is missing or fails verification, or when
    an alert could not be delivered.
    """

    config = _load_config(config_path)
    dispatcher = _AlertDispatcher(
        _alerters_from_options(
            config, alert_file=alert_file, webhook_url=webhook_url, webhook_kind=webhook_kind
        )
    )
    targets = _targets_from_args(paths, config)
    try:
        result = _scan_against_baseline(
            store,
            hmac_key_file,
            targets=targets,
            algorithms=_algorithms(config, algorithms),
            excludes=_excludes(config),
        )
    except _BASELINE_FAILURES as exc:
        dispatcher.emit(_baseline_failure_alert(store, exc))
        raise click.ClickException(str(exc)) from exc

    for change in result.changes:
        dispatcher.emit(
            _file_change_alert(
                change,
                severity="high" if change.change_type in {"removed", "modified"} else "medium",
                dedup_key=f"file:{change.change_type}:{change.path}",
            )
        )
    for finding in result.findings:
        dispatcher.emit(
            Alert(
                title=finding.title,
                severity=finding.severity,
                source="file_heuristic",
                description=finding.description,
                dedup_key=f"{finding.rule_id}:{finding.evidence.get('path', '')}",
                details=finding.evidence,
            )
        )

    summary = {
        "records": len(result.records),
        "changes": len(result.changes),
        "findings": len(result.findings),
        "errors": result.errors,
        "undelivered_alerts": dispatcher.undelivered,
    }
    click.echo(json.dumps(summary, indent=2, sort_keys=True))
    if dispatcher.undelivered:
        raise click.ClickException(f"{dispatcher.undelivered} alert(s) could not be delivered")


@main.command()
@click.option("--store", required=True, help="Baseline storage path.")
@click.option(
    "--hmac-key-file",
    required=True,
    help="File containing HMAC key bytes. Signatures cannot be verified without it.",
)
def verify(store: str, hmac_key_file: str) -> None:
    """Verify all baseline signatures.

    Exits non-zero when the store holds no baseline or any version fails.
    """

    manager = BaselineManager(store, hmac_key=_read_hmac_key(hmac_key_file))
    versions = manager.list_versions()
    if not versions:
        raise click.ClickException(f"No baseline versions found in {store}")
    failures = [version.version_id for version in versions if not manager.verify_version(version)]
    if failures:
        raise click.ClickException(f"Baseline verification failed: {', '.join(failures)}")
    click.echo(f"All {len(versions)} baseline version(s) verified.")


@main.command()
@click.option("--path", "paths", multiple=True, help="File, directory, or glob to scan.")
@click.option("--store", help="Baseline storage path.")
@click.option("--config", "config_path", help="Optional YAML configuration file.")
@click.option("--hmac-key-file", help="File containing HMAC key bytes.")
@click.option("--interval", default=300, show_default=True, help="Seconds between scans.")
@click.option("--once", is_flag=True, help="Run one cycle and exit.")
@click.option("--event-json", help="Analyze events from JSON instead of live Windows logs.")
@click.option(
    "--event-state-file",
    help="Persist Windows event-log bookmarks here so separate runs do not skip or repeat events.",
)
@click.option("--alert-file", help="Write alerts to JSON Lines file.")
@click.option("--webhook-url", help="Send alerts to webhook URL.")
@click.option(
    "--webhook-kind", default="generic", show_default=True, help="generic, slack, or discord."
)
def monitor(
    paths: tuple[str, ...],
    store: str | None,
    config_path: str | None,
    hmac_key_file: str | None,
    interval: int,
    once: bool,
    event_json: str | None,
    event_state_file: str | None,
    alert_file: str | None,
    webhook_url: str | None,
    webhook_kind: str,
) -> None:
    """Run file, process, and event monitoring.

    With ``--once`` the command exits non-zero when the baseline is missing or
    fails verification, or when an alert could not be delivered.
    """

    config = _load_config(config_path)
    dispatcher = _AlertDispatcher(
        _alerters_from_options(
            config, alert_file=alert_file, webhook_url=webhook_url, webhook_kind=webhook_kind
        )
    )
    targets = _targets_from_args(paths, config) if store else []
    file_algorithms = _algorithms(config, ())
    excludes = _excludes(config)
    # Built once: both keep state between cycles (event-log bookmarks and
    # recent failed logons).
    process_monitor = _process_monitor_from_config(config)
    event_analyzer = _event_analyzer_from_config(
        config, event_json=event_json, event_state_file=event_state_file
    )

    while True:
        dispatcher.retry_pending()
        baseline_ok = True
        if store:
            try:
                changes = _scan_against_baseline(
                    store,
                    hmac_key_file,
                    targets=targets,
                    algorithms=file_algorithms,
                    excludes=excludes,
                ).changes
            except _BASELINE_FAILURES as exc:
                # Keep process and event monitoring running, but say loudly
                # that file integrity is not being checked.
                baseline_ok = False
                changes = []
                dispatcher.emit(_baseline_failure_alert(store, exc))
            for change in changes:
                dispatcher.emit(_file_change_alert(change, severity="high", dedup_key=None))

        for process_finding in process_monitor.scan():
            dispatcher.emit(
                Alert(
                    title=process_finding.title,
                    severity=process_finding.severity,
                    source="process_monitor",
                    description=process_finding.description,
                    dedup_key=(
                        f"{process_finding.rule_id}:"
                        f"{process_finding.pid}:"
                        f"{process_finding.process_name}"
                    ),
                    details=process_finding.evidence,
                )
            )

        for event_finding in event_analyzer.analyze():
            dispatcher.emit(
                Alert(
                    title=event_finding.title,
                    severity=event_finding.severity,
                    source="event_analyzer",
                    description=event_finding.description,
                    dedup_key=_event_dedup_key(event_finding),
                    details=event_finding.evidence,
                )
            )

        if once:
            if not baseline_ok:
                raise click.ClickException(f"File integrity was not checked against {store}")
            if dispatcher.undelivered:
                raise click.ClickException(
                    f"{dispatcher.undelivered} alert(s) could not be delivered"
                )
            return
        time.sleep(interval)


def _metadata_map(items: tuple[str, ...]) -> dict[str, str]:
    values: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise click.ClickException(f"Metadata must be key=value: {item}")
        key, value = item.split("=", 1)
        values[key] = value
    return values


if __name__ == "__main__":
    main()
