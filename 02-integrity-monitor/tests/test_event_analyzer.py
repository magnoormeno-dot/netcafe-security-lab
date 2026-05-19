from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import ClassVar

import pytest

from integrity_monitor.core.event_analyzer import (
    EventAnalyzer,
    EventRecord,
    JsonEventProvider,
    WindowsEventProvider,
)


class FakeEventProvider:
    def __init__(self, events: list[EventRecord]) -> None:
        self._events = events

    def events(self) -> list[EventRecord]:
        return self._events


class FakeWin32Event:
    EventID = 0x10000 + 4688
    StringInserts: ClassVar[tuple[str, ...]] = ("billing-agent.exe", "powershell.exe -NoProfile")
    SourceName = "Microsoft-Windows-Security-Auditing"
    ComputerName = "CLIENT-01"
    TimeGenerated = "2026-05-20 10:00:00"
    RecordNumber = 42


def test_json_event_provider_loads_fixture(fixture_dir: Path) -> None:
    provider = JsonEventProvider(fixture_dir / "sample_events.json")

    events = provider.events()

    assert len(events) == 3
    assert events[0].event_id == 7036


def test_json_event_provider_rejects_non_list_payload(tmp_path: Path) -> None:
    path = tmp_path / "events.json"
    path.write_text('{"event_id": 1102}', encoding="utf-8")
    provider = JsonEventProvider(path)

    with pytest.raises(ValueError, match="must contain a list"):
        provider.events()


def test_json_event_provider_normalizes_optional_fields(tmp_path: Path) -> None:
    path = tmp_path / "events.json"
    path.write_text(
        """
        [
          {
            "event_id": "4625",
            "source": 123,
            "channel": "Security",
            "computer": "CLIENT-02",
            "timestamp": null,
            "user": 456,
            "message": "failed",
            "data": {"LogonType": 10}
          }
        ]
        """,
        encoding="utf-8",
    )
    provider = JsonEventProvider(path)

    events = provider.events()

    assert events == [
        EventRecord(
            event_id=4625,
            source="123",
            channel="Security",
            computer="CLIENT-02",
            timestamp=None,
            user="456",
            message="failed",
            data={"LogonType": 10},
        )
    ]


def test_windows_event_provider_returns_empty_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("integrity_monitor.core.event_analyzer.is_windows", lambda: False)

    assert WindowsEventProvider().events() == []


def test_windows_event_provider_reads_and_closes_fake_win32_log(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("integrity_monitor.core.event_analyzer.is_windows", lambda: True)
    closed_handles: list[str] = []
    read_count = 0

    def open_event_log(_server: object, channel: str) -> str:
        return f"handle:{channel}"

    def read_event_log(_handle: str, _flags: int, _offset: int) -> list[FakeWin32Event]:
        nonlocal read_count
        read_count += 1
        if read_count == 1:
            return [FakeWin32Event()]
        return []

    def close_event_log(handle: str) -> None:
        closed_handles.append(handle)

    fake_win32evtlog = types.ModuleType("win32evtlog")
    fake_win32evtlog.__dict__.update(
        {
            "EVENTLOG_BACKWARDS_READ": 1,
            "EVENTLOG_SEQUENTIAL_READ": 2,
            "OpenEventLog": open_event_log,
            "ReadEventLog": read_event_log,
            "CloseEventLog": close_event_log,
        }
    )
    monkeypatch.setitem(sys.modules, "win32evtlog", fake_win32evtlog)

    provider = WindowsEventProvider(channels=["Security"], limit_per_channel=5)

    events = provider.events()

    assert closed_handles == ["handle:Security"]
    assert events == [
        EventRecord(
            event_id=4688,
            source="Microsoft-Windows-Security-Auditing",
            channel="Security",
            computer="CLIENT-01",
            timestamp="2026-05-20 10:00:00",
            user=None,
            message="billing-agent.exe | powershell.exe -NoProfile",
            data={
                "strings": ["billing-agent.exe", "powershell.exe -NoProfile"],
                "record_number": 42,
            },
        )
    ]


def test_event_analyzer_detects_log_clear(fixture_dir: Path) -> None:
    analyzer = EventAnalyzer(provider=JsonEventProvider(fixture_dir / "sample_events.json"))

    findings = analyzer.analyze()

    assert any(finding.rule_id == "event.security_log_cleared" for finding in findings)


def test_event_analyzer_detects_failed_login() -> None:
    event = EventRecord(
        event_id=4625,
        source="Security",
        channel="Security",
        computer="CLIENT-01",
        user="cashier",
        data={"IpAddress": "10.10.20.55"},
    )
    analyzer = EventAnalyzer(provider=FakeEventProvider([event]))

    findings = analyzer.analyze()

    assert findings[0].rule_id == "event.failed_logon"
    assert findings[0].severity == "low"
    assert findings[0].evidence["user"] == "cashier"


def test_event_analyzer_detects_suspicious_process_creation() -> None:
    event = EventRecord(
        event_id=4688,
        source="Security",
        channel="Security",
        computer="CLIENT-01",
        message="New Process Name: powershell.exe Parent Process Name: billing-agent.exe",
    )
    analyzer = EventAnalyzer(provider=FakeEventProvider([event]))

    findings = analyzer.analyze()

    assert any(finding.rule_id == "event.suspicious_process_creation" for finding in findings)


def test_event_analyzer_ignores_suspicious_process_without_control_context() -> None:
    event = EventRecord(
        event_id=4688,
        source="Security",
        channel="Security",
        computer="CLIENT-01",
        message="New Process Name: powershell.exe Parent Process Name: explorer.exe",
    )
    analyzer = EventAnalyzer(provider=FakeEventProvider([event]))

    findings = analyzer.analyze()

    assert not findings


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


def test_event_analyzer_service_install_is_high_severity() -> None:
    event = EventRecord(
        event_id=4697,
        source="Service Control Manager",
        channel="System",
        computer="CLIENT-01",
        message="A service was installed: billing watchdog updater",
    )
    analyzer = EventAnalyzer(provider=FakeEventProvider([event]))

    findings = analyzer.analyze()

    finding = next(
        finding for finding in findings if finding.rule_id == "event.critical_service_change"
    )
    assert finding.severity == "high"


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


def test_event_analyzer_detects_registry_change_from_data() -> None:
    event = EventRecord(
        event_id=4657,
        source="Security",
        channel="Security",
        computer="CLIENT-01",
        data={"ObjectName": "HKLM\\System\\CurrentControlSet\\Services\\CafeBilling"},
    )
    analyzer = EventAnalyzer(provider=FakeEventProvider([event]))

    findings = analyzer.analyze()

    assert any(finding.rule_id == "event.sensitive_registry_modification" for finding in findings)
