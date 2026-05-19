"""Windows event-log and mock event analysis."""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar, Protocol

from integrity_monitor.utils.platform import is_windows

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class EventRecord:
    """A normalized security-relevant event."""

    event_id: int
    source: str
    channel: str
    computer: str
    timestamp: str | None = None
    user: str | None = None
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EventFinding:
    """A finding produced from event analysis."""

    rule_id: str
    severity: str
    title: str
    description: str
    event: EventRecord
    evidence: dict[str, Any] = field(default_factory=dict)


class EventProvider(Protocol):
    """Protocol for event providers."""

    def events(self) -> list[EventRecord]:
        """Return normalized events."""


class Win32EventLike(Protocol):
    """Subset of pywin32 event attributes used by the provider."""

    EventID: int
    StringInserts: Sequence[object] | None
    SourceName: object
    ComputerName: object
    TimeGenerated: object
    RecordNumber: int


class JsonEventProvider:
    """Load normalized events from a JSON fixture or export."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def events(self) -> list[EventRecord]:
        """Return events from a JSON file."""

        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("Event JSON must contain a list")
        return [self._record_from_dict(dict(item)) for item in payload]

    @staticmethod
    def _record_from_dict(item: dict[str, Any]) -> EventRecord:
        return EventRecord(
            event_id=int(item["event_id"]),
            source=str(item.get("source", "")),
            channel=str(item.get("channel", "")),
            computer=str(item.get("computer", "")),
            timestamp=None if item.get("timestamp") is None else str(item.get("timestamp")),
            user=None if item.get("user") is None else str(item.get("user")),
            message=str(item.get("message", "")),
            data=dict(item.get("data", {})),
        )


class WindowsEventProvider:
    """Read recent Windows events through pywin32 when available."""

    DEFAULT_CHANNELS: ClassVar[tuple[str, ...]] = ("Security", "System")

    def __init__(self, channels: list[str] | None = None, *, limit_per_channel: int = 200) -> None:
        self.channels = channels or list(self.DEFAULT_CHANNELS)
        self.limit_per_channel = limit_per_channel

    def events(self) -> list[EventRecord]:
        """Return recent Windows events.

        On non-Windows platforms the provider returns an empty list so the
        development and CI workflow remains portable.
        """

        if not is_windows():
            return []
        try:
            import win32evtlog
        except ImportError:
            LOGGER.warning("pywin32_not_available_for_event_collection")
            return []

        records: list[EventRecord] = []
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        for channel in self.channels:
            handle = win32evtlog.OpenEventLog(None, channel)
            try:
                count = 0
                while count < self.limit_per_channel:
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not events:
                        break
                    for event in events:
                        if count >= self.limit_per_channel:
                            break
                        records.append(self._from_win32_event(channel, event))
                        count += 1
            finally:
                win32evtlog.CloseEventLog(handle)
        return records

    @staticmethod
    def _from_win32_event(channel: str, event: Win32EventLike) -> EventRecord:
        event_id = int(event.EventID) & 0xFFFF
        strings = [str(item) for item in (event.StringInserts or [])]
        return EventRecord(
            event_id=event_id,
            source=str(event.SourceName),
            channel=channel,
            computer=str(event.ComputerName),
            timestamp=str(event.TimeGenerated),
            user=None,
            message=" | ".join(strings),
            data={"strings": strings, "record_number": int(event.RecordNumber)},
        )


class EventAnalyzer:
    """Analyze Windows events relevant to venue billing security."""

    LOGIN_SUCCESS = 4624
    LOGIN_FAILURE = 4625
    PROCESS_CREATE = 4688
    SERVICE_INSTALL = 4697
    REGISTRY_MODIFY = 4657
    LOG_CLEARED = 1102
    SERVICE_EVENTS: ClassVar[frozenset[int]] = frozenset({7034, 7035, 7036, 7040, 7045})

    def __init__(
        self,
        provider: EventProvider | None = None,
        *,
        critical_keywords: set[str] | None = None,
        suspicious_processes: set[str] | None = None,
        failed_login_burst_threshold: int = 5,
        failed_login_burst_window_minutes: int = 10,
    ) -> None:
        """Initialize the analyzer."""

        self.provider = provider or WindowsEventProvider()
        self.failed_login_burst_threshold = failed_login_burst_threshold
        self.failed_login_burst_window = timedelta(minutes=failed_login_burst_window_minutes)
        self.critical_keywords = {
            item.lower()
            for item in (
                critical_keywords
                or {
                    "billing",
                    "cashier",
                    "client agent",
                    "restore",
                    "rollback",
                    "watchdog",
                    "wazuh",
                    "sysmon",
                }
            )
        }
        self.suspicious_processes = {
            item.lower()
            for item in (
                suspicious_processes
                or {
                    "taskkill.exe",
                    "sc.exe",
                    "reg.exe",
                    "powershell.exe",
                    "pwsh.exe",
                    "wmic.exe",
                }
            )
        }

    def analyze(self) -> list[EventFinding]:
        """Analyze provider events and return findings."""

        events = self.provider.events()
        findings: list[EventFinding] = []
        for event in events:
            findings.extend(self._analyze_event(event))
        findings.extend(self._detect_failed_login_bursts(events))
        return findings

    def _analyze_event(self, event: EventRecord) -> list[EventFinding]:
        checks = [
            self._detect_failed_login_observed,
            self._detect_suspicious_process_creation,
            self._detect_service_install_or_change,
            self._detect_registry_modification,
            self._detect_log_clearing,
        ]
        findings: list[EventFinding] = []
        for check in checks:
            finding = check(event)
            if finding is not None:
                findings.append(finding)
        return findings

    def _detect_failed_login_observed(self, event: EventRecord) -> EventFinding | None:
        if event.event_id != self.LOGIN_FAILURE:
            return None
        return EventFinding(
            rule_id="event.failed_logon",
            severity="low",
            title="Failed logon observed",
            description="A failed logon event was observed and should be correlated for bursts.",
            event=event,
            evidence={"user": event.user, "data": event.data},
        )

    def _detect_failed_login_bursts(self, events: list[EventRecord]) -> list[EventFinding]:
        """Detect repeated failed logons by host, user, and source address."""

        grouped: dict[tuple[str, str, str], list[tuple[datetime | None, int, EventRecord]]] = {}
        for index, event in enumerate(events):
            if event.event_id != self.LOGIN_FAILURE:
                continue
            key = self._failed_login_group_key(event)
            grouped.setdefault(key, []).append(
                (self._parse_timestamp(event.timestamp), index, event)
            )

        findings: list[EventFinding] = []
        for key, group in grouped.items():
            if len(group) < self.failed_login_burst_threshold:
                continue
            ordered = sorted(
                group,
                key=lambda item: (item[0] is None, item[0] or datetime.min, item[1]),
            )
            finding = self._failed_login_burst_for_group(key, ordered)
            if finding is not None:
                findings.append(finding)
        return findings

    def _failed_login_burst_for_group(
        self,
        key: tuple[str, str, str],
        events: list[tuple[datetime | None, int, EventRecord]],
    ) -> EventFinding | None:
        if any(timestamp is None for timestamp, _index, _event in events):
            burst_events = events[: self.failed_login_burst_threshold]
        else:
            burst_events = []
            for start_index, (start_time, _index, _event) in enumerate(events):
                if start_time is None:
                    continue
                window_end = start_time + self.failed_login_burst_window
                candidates = [
                    item
                    for item in events[start_index:]
                    if item[0] is not None and item[0] <= window_end
                ]
                if len(candidates) >= self.failed_login_burst_threshold:
                    burst_events = candidates[: self.failed_login_burst_threshold]
                    break
        if len(burst_events) < self.failed_login_burst_threshold:
            return None

        first_time = burst_events[0][0]
        last_time = burst_events[-1][0]
        event = burst_events[-1][2]
        computer, user, source_address = key
        return EventFinding(
            rule_id="event.failed_logon_burst",
            severity="medium",
            title="Repeated failed logons observed",
            description=(
                "Multiple failed logons for the same host, user, and source address "
                "were observed inside the configured burst window."
            ),
            event=event,
            evidence={
                "computer": computer,
                "user": user,
                "source_address": source_address,
                "count": len(burst_events),
                "threshold": self.failed_login_burst_threshold,
                "window_minutes": int(self.failed_login_burst_window.total_seconds() // 60),
                "first_seen": None if first_time is None else first_time.isoformat(),
                "last_seen": None if last_time is None else last_time.isoformat(),
            },
        )

    def _detect_suspicious_process_creation(self, event: EventRecord) -> EventFinding | None:
        if event.event_id != self.PROCESS_CREATE:
            return None
        message = self._event_text(event)
        if not any(name in message for name in self.suspicious_processes):
            return None
        if not any(keyword in message for keyword in self.critical_keywords):
            return None
        return EventFinding(
            rule_id="event.suspicious_process_creation",
            severity="high",
            title="Suspicious process creation near venue control context",
            description=(
                "A suspicious administrative process appears in a billing or venue-control context."
            ),
            event=event,
            evidence={"message": event.message, "data": event.data},
        )

    def _detect_service_install_or_change(self, event: EventRecord) -> EventFinding | None:
        if event.event_id not in self.SERVICE_EVENTS and event.event_id != self.SERVICE_INSTALL:
            return None
        message = self._event_text(event)
        if not any(keyword in message for keyword in self.critical_keywords):
            return None
        severity = "high" if event.event_id in {4697, 7040, 7045} else "medium"
        return EventFinding(
            rule_id="event.critical_service_change",
            severity=severity,
            title="Critical venue service changed state",
            description="A billing, restoration, logging, or protection service changed state.",
            event=event,
            evidence={"event_id": event.event_id, "message": event.message},
        )

    def _detect_registry_modification(self, event: EventRecord) -> EventFinding | None:
        if event.event_id != self.REGISTRY_MODIFY:
            return None
        message = self._event_text(event)
        watched_markers = [
            "currentversion\\run",
            "currentcontrolset\\services",
            "windows defender",
            "powershell",
            "internet settings",
            "tcpip\\parameters",
            "billing",
        ]
        if not any(marker in message for marker in watched_markers):
            return None
        return EventFinding(
            rule_id="event.sensitive_registry_modification",
            severity="medium",
            title="Sensitive registry modification",
            description=(
                "A registry path affecting startup, services, security, network, "
                "or billing configuration changed."
            ),
            event=event,
            evidence={"message": event.message, "data": event.data},
        )

    def _detect_log_clearing(self, event: EventRecord) -> EventFinding | None:
        if event.event_id != self.LOG_CLEARED:
            return None
        return EventFinding(
            rule_id="event.security_log_cleared",
            severity="critical",
            title="Windows Security log cleared",
            description="The Windows Security event log was cleared.",
            event=event,
            evidence={"user": event.user, "computer": event.computer},
        )

    @staticmethod
    def _event_text(event: EventRecord) -> str:
        values = [event.message, event.source, event.channel, event.user or ""]
        values.extend(str(value) for value in event.data.values())
        return " ".join(values).lower()

    @staticmethod
    def _failed_login_group_key(event: EventRecord) -> tuple[str, str, str]:
        user = event.user or str(
            event.data.get("TargetUserName")
            or event.data.get("SubjectUserName")
            or event.data.get("AccountName")
            or ""
        )
        source_address = str(
            event.data.get("IpAddress")
            or event.data.get("SourceNetworkAddress")
            or event.data.get("WorkstationName")
            or ""
        )
        return (event.computer, user, source_address)

    @staticmethod
    def _parse_timestamp(value: str | None) -> datetime | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        if normalized.endswith("Z"):
            normalized = f"{normalized[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if parsed.tzinfo is not None:
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
