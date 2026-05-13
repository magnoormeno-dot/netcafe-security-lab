from __future__ import annotations

from pathlib import Path

from integrity_monitor.core.event_analyzer import EventAnalyzer, EventRecord, JsonEventProvider


class FakeEventProvider:
    def __init__(self, events: list[EventRecord]) -> None:
        self._events = events

    def events(self) -> list[EventRecord]:
        return self._events


def test_json_event_provider_loads_fixture(fixture_dir: Path) -> None:
    provider = JsonEventProvider(fixture_dir / "sample_events.json")

    events = provider.events()

    assert len(events) == 3
    assert events[0].event_id == 7036


def test_event_analyzer_detects_log_clear(fixture_dir: Path) -> None:
    analyzer = EventAnalyzer(provider=JsonEventProvider(fixture_dir / "sample_events.json"))

    findings = analyzer.analyze()

    assert any(finding.rule_id == "event.security_log_cleared" for finding in findings)


def test_event_analyzer_detects_service_change() -> None:
    event = EventRecord(
        event_id=7036,
        source="Service Control Manager",
        channel="System",
        computer="CLIENT-01",
        message="The rollback watchdog service entered the stopped state.",
    )
    analyzer = EventAnalyzer(provider=FakeEventProvider([event]))

    findings = analyzer.analyze()

    assert any(finding.rule_id == "event.critical_service_change" for finding in findings)


def test_event_analyzer_detects_registry_change() -> None:
    event = EventRecord(
        event_id=4657,
        source="Security",
        channel="Security",
        computer="CLIENT-01",
        message="Object Name: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    )
    analyzer = EventAnalyzer(provider=FakeEventProvider([event]))

    findings = analyzer.analyze()

    assert any(finding.rule_id == "event.sensitive_registry_modification" for finding in findings)
