from __future__ import annotations

import json
import logging
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

import pytest

from integrity_monitor.core.event_analyzer import (
    EventAnalyzer,
    EventFinding,
    EventRecord,
    JsonEventProvider,
    WindowsEventProvider,
)


class FakeEventProvider:
    def __init__(self, events: list[EventRecord]) -> None:
        self._events = events

    def events(self) -> list[EventRecord]:
        return self._events


class QueuedEventProvider:
    """Return one prepared batch of events per poll."""

    def __init__(self, batches: list[list[EventRecord]]) -> None:
        self._batches = list(batches)

    def events(self) -> list[EventRecord]:
        return self._batches.pop(0) if self._batches else []


@dataclass
class LoggedEvent:
    """A record in the fake classic event log."""

    RecordNumber: int
    EventID: int = 4625
    StringInserts: tuple[str, ...] = ("cashier",)
    SourceName: str = "Microsoft-Windows-Security-Auditing"
    ComputerName: str = "CLIENT-01"
    TimeGenerated: str = "2026-05-20 10:00:00"


class FakeWin32Log:
    """In-memory stand-in for the pywin32 classic event log API."""

    BATCH_SIZE = 2

    def __init__(self) -> None:
        self.records: dict[str, list[int]] = {}
        self.opened: list[str] = []
        self.closed: list[str] = []
        self._cursors: dict[str, int] = {}

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        module = types.ModuleType("win32evtlog")
        module.__dict__.update(
            {
                "EVENTLOG_BACKWARDS_READ": 1,
                "EVENTLOG_SEQUENTIAL_READ": 2,
                "OpenEventLog": self.open,
                "ReadEventLog": self.read,
                "CloseEventLog": self.close,
            }
        )
        monkeypatch.setattr("integrity_monitor.core.event_analyzer.is_windows", lambda: True)
        monkeypatch.setitem(sys.modules, "win32evtlog", module)

    def open(self, _server: object, channel: str) -> str:
        self.opened.append(channel)
        self._cursors[channel] = len(self.records.get(channel, []))
        return channel

    def read(self, handle: str, _flags: int, _offset: int) -> list[LoggedEvent]:
        cursor = self._cursors[handle]
        start = max(0, cursor - self.BATCH_SIZE)
        self._cursors[handle] = start
        return [LoggedEvent(number) for number in reversed(self.records[handle][start:cursor])]

    def close(self, handle: str) -> None:
        self.closed.append(handle)


def record_numbers(events: list[EventRecord]) -> list[int]:
    return [int(event.data["record_number"]) for event in events]


def failed_logon(record_number: int | None, minute: int) -> EventRecord:
    data: dict[str, object] = {"IpAddress": "10.10.20.55"}
    if record_number is not None:
        data["record_number"] = record_number
    return EventRecord(
        event_id=4625,
        source="Security",
        channel="Security",
        computer="CLIENT-01",
        timestamp=f"2026-05-20T10:{minute:02d}:00Z",
        user="cashier",
        data=data,
    )


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


def test_windows_event_provider_returns_only_new_events_on_later_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log = FakeWin32Log()
    log.records["Security"] = list(range(1, 11))
    log.install(monkeypatch)
    provider = WindowsEventProvider(channels=["Security"], limit_per_channel=3)

    first = provider.events()
    log.records["Security"].extend([11, 12])
    second = provider.events()
    third = provider.events()

    # The first read is the recent window; later reads are oldest-first deltas.
    assert record_numbers(first) == [8, 9, 10]
    assert record_numbers(second) == [11, 12]
    assert third == []
    assert log.closed == ["Security", "Security", "Security"]


def test_windows_event_provider_reads_backlog_beyond_first_read_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log = FakeWin32Log()
    log.records["Security"] = [1, 2, 3]
    log.install(monkeypatch)
    provider = WindowsEventProvider(channels=["Security"], limit_per_channel=2)
    provider.events()

    # More events arrive between polls than the first-read window holds.
    log.records["Security"].extend(range(4, 11))

    assert record_numbers(provider.events()) == [4, 5, 6, 7, 8, 9, 10]


def test_windows_event_provider_rereads_after_log_reset(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    log = FakeWin32Log()
    log.records["Security"] = list(range(90, 101))
    log.install(monkeypatch)
    provider = WindowsEventProvider(channels=["Security"], limit_per_channel=2)
    provider.events()

    # The log was cleared, so numbering starts again below the bookmark.
    log.records["Security"] = [1, 2, 3]
    with caplog.at_level(logging.WARNING):
        events = provider.events()

    assert record_numbers(events) == [1, 2, 3]
    assert "event_log_reset_detected" in caplog.messages
    assert provider.events() == []


def test_windows_event_provider_warns_when_backlog_limit_drops_events(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    log = FakeWin32Log()
    log.records["Security"] = [1, 2]
    log.install(monkeypatch)
    provider = WindowsEventProvider(
        channels=["Security"], limit_per_channel=2, max_backlog_per_channel=3
    )
    provider.events()

    log.records["Security"].extend(range(3, 11))
    with caplog.at_level(logging.WARNING):
        events = provider.events()

    assert record_numbers(events) == [8, 9, 10]
    gap = next(item for item in caplog.records if item.getMessage() == "event_log_gap")
    assert gap.__dict__["missed_events"] == 5
    assert gap.__dict__["reason"] == "backlog_limit"


def test_windows_event_provider_warns_when_log_overwrote_unread_events(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    log = FakeWin32Log()
    log.records["Security"] = [1, 2]
    log.install(monkeypatch)
    provider = WindowsEventProvider(channels=["Security"], limit_per_channel=2)
    provider.events()

    # Records 3-5 were written and then overwritten before the next poll.
    log.records["Security"] = [6, 7]
    with caplog.at_level(logging.WARNING):
        events = provider.events()

    assert record_numbers(events) == [6, 7]
    gap = next(item for item in caplog.records if item.getMessage() == "event_log_gap")
    assert gap.__dict__["missed_events"] == 3
    assert gap.__dict__["reason"] == "log_overwritten"


def test_windows_event_provider_persists_bookmarks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state = tmp_path / "state" / "events.json"
    log = FakeWin32Log()
    log.records["Security"] = [1, 2, 3]
    log.install(monkeypatch)

    WindowsEventProvider(channels=["Security"], state_path=state).events()
    log.records["Security"].append(4)
    # A new process picks up where the previous one stopped.
    resumed = WindowsEventProvider(channels=["Security"], state_path=state).events()

    assert record_numbers(resumed) == [4]
    assert json.loads(state.read_text(encoding="utf-8"))["channels"] == {"Security": 4}


def test_windows_event_provider_ignores_damaged_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state = tmp_path / "events.json"
    state.write_text("{not json", encoding="utf-8")
    log = FakeWin32Log()
    log.records["Security"] = [1, 2, 3]
    log.install(monkeypatch)

    events = WindowsEventProvider(channels=["Security"], state_path=state).events()

    assert record_numbers(events) == [1, 2, 3]


def test_windows_event_provider_skips_channels_the_legacy_api_cannot_read(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    log = FakeWin32Log()
    log.records["Security"] = [1]
    log.install(monkeypatch)
    provider = WindowsEventProvider(
        channels=["Microsoft-Windows-PowerShell/Operational", "Security"]
    )

    with caplog.at_level(logging.WARNING):
        events = provider.events()

    assert log.opened == ["Security"]
    assert record_numbers(events) == [1]
    assert "event_channel_not_supported" in caplog.messages


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


def test_event_analyzer_detects_failed_login_burst() -> None:
    events = [
        EventRecord(
            event_id=4625,
            source="Security",
            channel="Security",
            computer="CLIENT-01",
            timestamp=f"2026-05-20T10:0{index}:00Z",
            user="cashier",
            data={"IpAddress": "10.10.20.55"},
        )
        for index in range(5)
    ]
    analyzer = EventAnalyzer(
        provider=FakeEventProvider(events),
        failed_login_burst_threshold=5,
        failed_login_burst_window_minutes=10,
    )

    findings = analyzer.analyze()

    burst = next(finding for finding in findings if finding.rule_id == "event.failed_logon_burst")
    assert burst.severity == "medium"
    assert burst.evidence["count"] == 5
    assert burst.evidence["user"] == "cashier"
    assert burst.evidence["source_address"] == "10.10.20.55"


def test_event_analyzer_detects_burst_split_across_polls() -> None:
    provider = QueuedEventProvider(
        [
            [failed_logon(1, 0), failed_logon(2, 1), failed_logon(3, 2)],
            [failed_logon(4, 3), failed_logon(5, 4)],
            [],
        ]
    )
    analyzer = EventAnalyzer(provider=provider, failed_login_burst_threshold=5)

    first = analyzer.analyze()
    second = analyzer.analyze()
    third = analyzer.analyze()

    def bursts(findings: list[EventFinding]) -> list[EventFinding]:
        return [item for item in findings if item.rule_id == "event.failed_logon_burst"]

    assert bursts(first) == []
    assert len(bursts(second)) == 1
    assert bursts(second)[0].evidence["count"] == 5
    # No new failed logon arrived, so the remembered burst is not repeated.
    assert bursts(third) == []


def test_event_analyzer_does_not_count_reread_events_twice() -> None:
    same_three = [failed_logon(1, 0), failed_logon(2, 1), failed_logon(3, 2)]
    provider = QueuedEventProvider([list(same_three), list(same_three)])
    analyzer = EventAnalyzer(provider=provider, failed_login_burst_threshold=5)

    findings = analyzer.analyze() + analyzer.analyze()

    assert all(item.rule_id != "event.failed_logon_burst" for item in findings)


def test_event_analyzer_forgets_failed_logons_outside_the_burst_window() -> None:
    provider = QueuedEventProvider(
        [
            [failed_logon(1, 0), failed_logon(2, 1), failed_logon(3, 2), failed_logon(4, 3)],
            [failed_logon(5, 40)],
        ]
    )
    analyzer = EventAnalyzer(
        provider=provider,
        failed_login_burst_threshold=5,
        failed_login_burst_window_minutes=10,
    )

    findings = analyzer.analyze() + analyzer.analyze()

    assert all(item.rule_id != "event.failed_logon_burst" for item in findings)
    assert len(analyzer._recent_failed_logons) == 1


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
