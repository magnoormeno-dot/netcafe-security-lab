"""Command-line interface for CafeSec Integrity Monitor."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, cast

import click
import yaml

from integrity_monitor.alerting import Alert, ConsoleAlerter, FileAlerter, WebhookAlerter
from integrity_monitor.core.baseline import BaselineManager
from integrity_monitor.core.event_analyzer import EventAnalyzer, JsonEventProvider
from integrity_monitor.core.file_integrity import FileIntegrityMonitor, HashAlgorithm, ScanTarget
from integrity_monitor.core.process_monitor import ProcessMonitor
from integrity_monitor.utils.logging import configure_logging

LOGGER = logging.getLogger(__name__)


def _read_hmac_key(path: str | None) -> bytes | None:
    if path is None:
        return None
    return Path(path).read_bytes().strip()


def _load_config(path: str | None) -> dict[str, Any]:
    if path is None:
        return {}
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise click.ClickException("Configuration file must contain a mapping")
    return dict(payload)


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


def _alerter_from_options(
    *,
    alert_file: str | None,
    webhook_url: str | None,
    webhook_kind: str,
) -> ConsoleAlerter | FileAlerter | WebhookAlerter:
    if webhook_url:
        return WebhookAlerter(webhook_url, kind=webhook_kind)
    if alert_file:
        return FileAlerter(alert_file)
    return ConsoleAlerter()


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
@click.option(
    "--path", "paths", multiple=True, required=True, help="File, directory, or glob to baseline."
)
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
            f"{version.version_id}\t{version.created_at}\tvalid={valid}\trecords={len(version.records)}"
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
@click.option(
    "--path", "paths", multiple=True, required=True, help="File, directory, or glob to scan."
)
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
    """Scan files against the latest baseline."""

    config = _load_config(config_path)
    manager = BaselineManager(store, hmac_key=_read_hmac_key(hmac_key_file))
    monitor = FileIntegrityMonitor(
        _targets_from_args(paths, config),
        algorithms=_algorithms(config, algorithms),
        excludes=_excludes(config),
        baseline_manager=manager,
    )
    result = monitor.scan()
    alerter = _alerter_from_options(
        alert_file=alert_file, webhook_url=webhook_url, webhook_kind=webhook_kind
    )

    for change in result.changes:
        alerter.emit(
            Alert(
                title=f"File {change.change_type}: {Path(change.path).name}",
                severity="high" if change.change_type in {"removed", "modified"} else "medium",
                source="file_integrity",
                description=f"{change.change_type.title()} file detected at {change.path}",
                dedup_key=f"file:{change.change_type}:{change.path}",
                details=change.__dict__,
            )
        )
    for finding in result.findings:
        alerter.emit(
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
    }
    click.echo(json.dumps(summary, indent=2, sort_keys=True))


@main.command()
@click.option("--store", required=True, help="Baseline storage path.")
@click.option("--hmac-key-file", help="File containing HMAC key bytes.")
def verify(store: str, hmac_key_file: str | None) -> None:
    """Verify all baseline signatures."""

    manager = BaselineManager(store, hmac_key=_read_hmac_key(hmac_key_file))
    failures: list[str] = []
    for version in manager.list_versions():
        if not manager.verify_version(version):
            failures.append(version.version_id)
    if failures:
        raise click.ClickException(f"Baseline verification failed: {', '.join(failures)}")
    click.echo("All baseline versions verified.")


@main.command()
@click.option("--path", "paths", multiple=True, help="File, directory, or glob to scan.")
@click.option("--store", help="Baseline storage path.")
@click.option("--config", "config_path", help="Optional YAML configuration file.")
@click.option("--hmac-key-file", help="File containing HMAC key bytes.")
@click.option("--interval", default=300, show_default=True, help="Seconds between scans.")
@click.option("--once", is_flag=True, help="Run one cycle and exit.")
@click.option("--event-json", help="Analyze events from JSON instead of live Windows logs.")
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
    alert_file: str | None,
    webhook_url: str | None,
    webhook_kind: str,
) -> None:
    """Run file, process, and event monitoring."""

    config = _load_config(config_path)
    alerter = _alerter_from_options(
        alert_file=alert_file, webhook_url=webhook_url, webhook_kind=webhook_kind
    )

    while True:
        if store:
            manager = BaselineManager(store, hmac_key=_read_hmac_key(hmac_key_file))
            file_monitor = FileIntegrityMonitor(
                _targets_from_args(paths, config),
                algorithms=_algorithms(config, ()),
                excludes=_excludes(config),
                baseline_manager=manager,
            )
            for change in file_monitor.scan().changes:
                alerter.emit(
                    Alert(
                        title=f"File {change.change_type}: {Path(change.path).name}",
                        severity="high",
                        source="file_integrity",
                        description=f"{change.change_type.title()} file detected at {change.path}",
                        details=change.__dict__,
                    )
                )

        for process_finding in ProcessMonitor().scan():
            alerter.emit(
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

        provider = JsonEventProvider(event_json) if event_json else None
        for event_finding in EventAnalyzer(provider=provider).analyze():
            alerter.emit(
                Alert(
                    title=event_finding.title,
                    severity=event_finding.severity,
                    source="event_analyzer",
                    description=event_finding.description,
                    dedup_key=(
                        f"{event_finding.rule_id}:"
                        f"{event_finding.event.computer}:"
                        f"{event_finding.event.event_id}"
                    ),
                    details=event_finding.evidence,
                )
            )

        if once:
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
