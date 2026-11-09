from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
import requests
from click.testing import CliRunner

from integrity_monitor.alerting import Alert, AlertDeliveryError, Alerter
from integrity_monitor.cli import (
    _AlertDispatcher,
    _event_analyzer_from_config,
    _load_config,
    _process_monitor_from_config,
    main,
)
from integrity_monitor.core.event_analyzer import JsonEventProvider, WindowsEventProvider
from integrity_monitor.core.process_monitor import ProcessFinding


def read_alerts(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def write_key(tmp_path: Path) -> Path:
    key = tmp_path / "baseline.hmac.key"
    key.write_bytes(b"unit-test-hmac-key-32-bytes-long")
    return key


class QuietProcessMonitor:
    """Stand-in that avoids inspecting the processes of the test machine."""

    def __init__(self, **_options: object) -> None:
        pass

    def scan(self) -> list[ProcessFinding]:
        return []


class FlakyAlerter(Alerter):
    """Fail a set number of deliveries, then succeed."""

    def __init__(self, failures: int) -> None:
        super().__init__()
        self.failures = failures
        self.sent: list[str] = []

    def _send(self, alert: Alert) -> None:
        if self.failures > 0:
            self.failures -= 1
            raise AlertDeliveryError("backend unavailable")
        self.sent.append(alert.title)


def test_cli_baseline_create_and_scan(sample_tree: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    store = tmp_path / "baseline.json"

    create = runner.invoke(
        main,
        ["baseline", "create", "--path", str(sample_tree), "--store", str(store)],
    )
    scan = runner.invoke(main, ["scan", "--path", str(sample_tree), "--store", str(store)])

    assert create.exit_code == 0
    assert scan.exit_code == 0
    assert '"changes": 0' in scan.output


def test_cli_uses_configured_targets_without_path(sample_tree: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    store = tmp_path / "baseline.json"
    config = tmp_path / "monitor.yaml"
    config.write_text(
        f'targets:\n  - "{sample_tree.as_posix()}"\nalgorithms:\n  - sha256\n',
        encoding="utf-8",
    )

    create = runner.invoke(
        main,
        ["baseline", "create", "--config", str(config), "--store", str(store)],
    )
    scan = runner.invoke(
        main,
        ["scan", "--config", str(config), "--store", str(store)],
    )

    assert create.exit_code == 0
    assert scan.exit_code == 0
    assert '"changes": 0' in scan.output


def test_cli_verify_fails_on_missing_store(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(
        main,
        [
            "verify",
            "--store",
            str(tmp_path / "missing.json"),
            "--hmac-key-file",
            str(write_key(tmp_path)),
        ],
    )

    assert result.exit_code == 1
    assert "No baseline versions found" in result.output
    assert "verified" not in result.output


def test_cli_verify_requires_hmac_key(sample_tree: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    store = tmp_path / "baseline.json"
    runner.invoke(main, ["baseline", "create", "--path", str(sample_tree), "--store", str(store)])

    result = runner.invoke(main, ["verify", "--store", str(store)])

    assert result.exit_code == 2
    assert "--hmac-key-file" in result.output


def test_cli_verify_passes_for_signed_store_and_fails_for_unsigned(
    sample_tree: Path, tmp_path: Path
) -> None:
    runner = CliRunner()
    key = write_key(tmp_path)
    signed = tmp_path / "signed.json"
    unsigned = tmp_path / "unsigned.json"
    runner.invoke(
        main,
        [
            "baseline",
            "create",
            "--path",
            str(sample_tree),
            "--store",
            str(signed),
            "--hmac-key-file",
            str(key),
        ],
    )
    runner.invoke(
        main, ["baseline", "create", "--path", str(sample_tree), "--store", str(unsigned)]
    )

    ok = runner.invoke(main, ["verify", "--store", str(signed), "--hmac-key-file", str(key)])
    bad = runner.invoke(main, ["verify", "--store", str(unsigned), "--hmac-key-file", str(key)])

    assert ok.exit_code == 0
    assert "All 1 baseline version(s) verified." in ok.output
    assert bad.exit_code == 1
    assert "Baseline verification failed" in bad.output


def test_cli_scan_fails_and_alerts_when_baseline_is_missing(
    sample_tree: Path, tmp_path: Path
) -> None:
    runner = CliRunner()
    store = tmp_path / "baseline.json"
    alerts = tmp_path / "alerts.jsonl"
    runner.invoke(main, ["baseline", "create", "--path", str(sample_tree), "--store", str(store)])
    (sample_tree / "agent.exe").write_bytes(b"tampered")
    store.unlink()

    result = runner.invoke(
        main,
        ["scan", "--path", str(sample_tree), "--store", str(store), "--alert-file", str(alerts)],
    )

    assert result.exit_code == 1
    assert "No baseline versions found" in result.output
    assert '"changes": 0' not in result.output
    [alert] = read_alerts(alerts)
    assert alert["title"] == "Baseline missing"
    assert alert["severity"] == "critical"


def test_cli_scan_refuses_signed_baseline_without_key(sample_tree: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    store = tmp_path / "baseline.json"
    alerts = tmp_path / "alerts.jsonl"
    runner.invoke(
        main,
        [
            "baseline",
            "create",
            "--path",
            str(sample_tree),
            "--store",
            str(store),
            "--hmac-key-file",
            str(write_key(tmp_path)),
        ],
    )

    result = runner.invoke(
        main,
        ["scan", "--path", str(sample_tree), "--store", str(store), "--alert-file", str(alerts)],
    )

    assert result.exit_code == 1
    assert "no HMAC key was provided" in result.output
    assert read_alerts(alerts)[0]["title"] == "Baseline failed verification"


def test_cli_scan_alerts_when_baseline_store_is_corrupted(
    sample_tree: Path, tmp_path: Path
) -> None:
    runner = CliRunner()
    store = tmp_path / "baseline.json"
    alerts = tmp_path / "alerts.jsonl"
    store.write_text("{truncated", encoding="utf-8")

    result = runner.invoke(
        main,
        ["scan", "--path", str(sample_tree), "--store", str(store), "--alert-file", str(alerts)],
    )

    assert result.exit_code == 1
    assert "is unreadable" in result.output
    assert read_alerts(alerts)[0]["title"] == "Baseline failed verification"


@pytest.mark.parametrize("key_state", ["empty", "missing"])
def test_cli_scan_alerts_when_hmac_key_is_unusable(
    sample_tree: Path, tmp_path: Path, key_state: str
) -> None:
    runner = CliRunner()
    store = tmp_path / "baseline.json"
    alerts = tmp_path / "alerts.jsonl"
    key = write_key(tmp_path)
    runner.invoke(
        main,
        [
            "baseline",
            "create",
            "--path",
            str(sample_tree),
            "--store",
            str(store),
            "--hmac-key-file",
            str(key),
        ],
    )
    if key_state == "empty":
        key.write_bytes(b"\n")
    else:
        key.unlink()

    result = runner.invoke(
        main,
        [
            "scan",
            "--path",
            str(sample_tree),
            "--store",
            str(store),
            "--hmac-key-file",
            str(key),
            "--alert-file",
            str(alerts),
        ],
    )

    assert result.exit_code == 1
    assert "HMAC key file" in result.output
    assert read_alerts(alerts)[0]["title"] == "Baseline HMAC key unavailable"


def test_cli_scan_writes_alerts_to_configured_file(sample_tree: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    store = tmp_path / "baseline.json"
    alerts = tmp_path / "configured" / "alerts.jsonl"
    config = tmp_path / "monitor.yaml"
    config.write_text(
        f'targets:\n  - "{sample_tree.as_posix()}"\n'
        f'alerting:\n  dedup_window_seconds: 60\n  file: "{alerts.as_posix()}"\n',
        encoding="utf-8",
    )
    runner.invoke(main, ["baseline", "create", "--config", str(config), "--store", str(store)])
    (sample_tree / "agent.exe").write_bytes(b"agent-v2")

    result = runner.invoke(main, ["scan", "--config", str(config), "--store", str(store)])

    assert result.exit_code == 0
    titles = [alert["title"] for alert in read_alerts(alerts)]
    assert "File modified: agent.exe" in titles


def test_cli_scan_keeps_alerting_when_webhook_is_down(
    sample_tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    store = tmp_path / "baseline.json"
    alerts = tmp_path / "alerts.jsonl"
    runner.invoke(main, ["baseline", "create", "--path", str(sample_tree), "--store", str(store)])
    (sample_tree / "agent.exe").write_bytes(b"agent-v2")
    (sample_tree / "config.json").unlink()
    attempts: list[str] = []

    def failing_post(url: str, *, json: dict[str, Any], timeout: float) -> None:
        attempts.append(str(json["title"]))
        raise requests.ConnectionError(f"cannot reach {url}")

    monkeypatch.setattr("integrity_monitor.alerting.webhook.requests.post", failing_post)

    result = runner.invoke(
        main,
        [
            "scan",
            "--path",
            str(sample_tree),
            "--store",
            str(store),
            "--alert-file",
            str(alerts),
            "--webhook-url",
            "https://hooks.example.test/services/secret-token",
        ],
    )

    titles = {alert["title"] for alert in read_alerts(alerts)}
    # The first webhook failure used to abort the scan. Every alert is still
    # attempted, the file copy is complete, and the run reports the failure.
    assert {"File modified: agent.exe", "File removed: config.json"} <= titles
    assert {"File modified: agent.exe", "File removed: config.json"} <= set(attempts)
    assert result.exit_code == 1
    assert "could not be delivered" in result.output
    assert "secret-token" not in result.output


def test_alert_dispatcher_retries_undelivered_alerts() -> None:
    alerter = FlakyAlerter(failures=2)
    dispatcher = _AlertDispatcher([alerter])
    alert = Alert(title="Log cleared", severity="critical", source="unit", description="1102")

    dispatcher.emit(alert)
    assert dispatcher.undelivered == 1
    # Detecting the same condition again must not queue a second copy.
    dispatcher.emit(alert)
    assert dispatcher.undelivered == 1

    dispatcher.retry_pending()

    assert dispatcher.undelivered == 0
    assert alerter.sent == ["Log cleared"]


def test_load_config_reports_unknown_keys(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    config = tmp_path / "monitor.yaml"
    config.write_text(
        "targets: []\nalerting:\n  file: alerts.jsonl\n  webhook: nope\ntypo_section: {}\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        _load_config(str(config))

    ignored = {
        record.__dict__["key"]
        for record in caplog.records
        if record.getMessage() == "config_key_ignored"
    }
    assert ignored == {"alerting.webhook", "typo_section"}


def test_process_monitor_options_come_from_config() -> None:
    monitor = _process_monitor_from_config(
        {
            "process_monitor": {
                "protected_process_keywords": ["VenuePOS"],
                "allowed_writable_processes": ["Launcher.exe"],
                "expected_hashes": {"/opt/venue/pos": "ABCDEF"},
                "include_unsigned_check": False,
            }
        }
    )

    assert monitor.protected_process_keywords == {"venuepos"}
    assert monitor.allowed_writable_processes == {"launcher.exe"}
    assert list(monitor.expected_hashes.values()) == ["abcdef"]
    assert monitor.include_unsigned_check is False


def test_event_analyzer_options_come_from_config(tmp_path: Path) -> None:
    state = tmp_path / "events.json"
    config = {
        "event_analyzer": {
            "channels": ["Security"],
            "state_file": str(state),
            "critical_keywords": ["VenuePOS"],
            "failed_login_burst_threshold": 3,
        }
    }

    analyzer = _event_analyzer_from_config(config, event_json=None, event_state_file=None)
    from_fixture = _event_analyzer_from_config(config, event_json="e.json", event_state_file=None)

    assert isinstance(analyzer.provider, WindowsEventProvider)
    assert analyzer.provider.channels == ["Security"]
    assert analyzer.provider.state_path == state
    assert analyzer.critical_keywords == {"venuepos"}
    assert analyzer.failed_login_burst_threshold == 3
    assert isinstance(from_fixture.provider, JsonEventProvider)


def test_cli_monitor_once_reports_missing_baseline_and_keeps_monitoring(
    sample_tree: Path, tmp_path: Path, fixture_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("integrity_monitor.cli.ProcessMonitor", QuietProcessMonitor)
    runner = CliRunner()
    alerts = tmp_path / "alerts.jsonl"

    result = runner.invoke(
        main,
        [
            "monitor",
            "--once",
            "--path",
            str(sample_tree),
            "--store",
            str(tmp_path / "missing.json"),
            "--event-json",
            str(fixture_dir / "sample_events.json"),
            "--alert-file",
            str(alerts),
        ],
    )

    titles = [alert["title"] for alert in read_alerts(alerts)]
    assert result.exit_code == 1
    assert "File integrity was not checked" in result.output
    assert "Baseline missing" in titles
    # Event analysis still ran after the baseline failure.
    assert "Windows Security log cleared" in titles
