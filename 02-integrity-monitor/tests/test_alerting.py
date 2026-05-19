from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from integrity_monitor.alerting import (
    Alert,
    ConsoleAlerter,
    DeduplicationCache,
    FileAlerter,
    WebhookAlerter,
)


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


def test_webhook_generic_payload_includes_alert_details() -> None:
    alert = Alert(
        title="Process drift",
        severity="high",
        source="process",
        description="Hash differs from baseline",
        details={"pid": 1234},
    )
    alerter = WebhookAlerter("https://example.test/webhook")

    payload = alerter._payload(alert)

    assert payload["title"] == "Process drift"
    assert payload["severity"] == "high"
    assert payload["source"] == "process"
    assert payload["details"] == {"pid": 1234}


def test_webhook_slack_payload_contains_blocks() -> None:
    alert = Alert(title="Service stopped", severity="medium", source="event", description="7036")
    alerter = WebhookAlerter("https://example.test/slack", kind="slack")

    payload = alerter._payload(alert)

    assert payload["text"] == "[MEDIUM] Service stopped: 7036"
    blocks = cast(list[dict[str, Any]], payload["blocks"])
    assert blocks[0]["type"] == "section"
    assert blocks[1]["type"] == "context"


def test_webhook_discord_payload_contains_embed_fields() -> None:
    alert = Alert(title="Registry change", severity="medium", source="event", description="4657")
    alerter = WebhookAlerter("https://example.test/discord", kind="discord")

    payload = alerter._payload(alert)

    assert payload["content"] == "[MEDIUM] Registry change: 4657"
    embeds = cast(list[dict[str, Any]], payload["embeds"])
    assert embeds[0]["title"] == "Registry change"
    assert embeds[0]["fields"] == [
        {"name": "Severity", "value": "medium", "inline": True},
        {"name": "Source", "value": "event", "inline": True},
    ]


def test_webhook_emit_posts_once_with_deduplication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

    def fake_post(url: str, *, json: dict[str, Any], timeout: float) -> FakeResponse:
        calls.append({"url": url, "json": json, "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr("integrity_monitor.alerting.webhook.requests.post", fake_post)
    alert = Alert(
        title="Writable execution",
        severity="medium",
        source="process",
        description="Tool ran from Downloads",
        dedup_key="same-alert",
    )
    alerter = WebhookAlerter(
        "https://example.test/generic",
        timeout_seconds=2.5,
        dedup_cache=DeduplicationCache(window_seconds=60),
    )

    assert alerter.emit(alert)
    assert not alerter.emit(alert)
    assert len(calls) == 1
    assert calls[0]["url"] == "https://example.test/generic"
    assert calls[0]["timeout"] == 2.5
    assert cast(dict[str, Any], calls[0]["json"])["title"] == "Writable execution"


def test_webhook_emit_propagates_http_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailingResponse:
        def raise_for_status(self) -> None:
            raise RuntimeError("webhook failed")

    def fake_post(_url: str, *, json: dict[str, Any], timeout: float) -> FailingResponse:
        assert json["title"] == "Failure"
        assert timeout == 5.0
        return FailingResponse()

    monkeypatch.setattr("integrity_monitor.alerting.webhook.requests.post", fake_post)
    alerter = WebhookAlerter("https://example.test/fail")

    with pytest.raises(RuntimeError, match="webhook failed"):
        alerter.emit(
            Alert(title="Failure", severity="high", source="unit", description="backend error")
        )
