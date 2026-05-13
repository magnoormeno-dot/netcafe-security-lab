from __future__ import annotations

import json
from pathlib import Path

import pytest

from integrity_monitor.alerting import Alert, ConsoleAlerter, DeduplicationCache, FileAlerter


def test_deduplication_cache_suppresses_repeated_alert() -> None:
    cache = DeduplicationCache(window_seconds=60)
    alert = Alert(title="Test", severity="low", source="unit", description="same")

    assert cache.should_emit(alert, now=100.0)
    assert not cache.should_emit(alert, now=120.0)
    assert cache.should_emit(alert, now=200.0)


def test_file_alerter_writes_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    alerter = FileAlerter(path)

    emitted = alerter.emit(Alert(title="Title", severity="high", source="unit", description="desc"))

    assert emitted
    payload = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert payload["title"] == "Title"


def test_console_alerter_emits(capsys: pytest.CaptureFixture[str]) -> None:
    alerter = ConsoleAlerter()

    alerter.emit(Alert(title="Console", severity="low", source="unit", description="desc"))

    assert "Console" in capsys.readouterr().out
