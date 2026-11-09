"""Alerting abstractions and deduplication support."""

from __future__ import annotations

import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Alert:
    """A normalized alert emitted by the monitor."""

    title: str
    severity: str
    source: str
    description: str
    dedup_key: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def stable_key(self) -> str:
        """Return a stable deduplication key for this alert."""

        if self.dedup_key:
            return self.dedup_key
        payload = json.dumps(
            {
                "title": self.title,
                "severity": self.severity,
                "source": self.source,
                "description": self.description,
                "details": self.details,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AlertDeliveryError(RuntimeError):
    """Raised when an alert backend cannot deliver an alert."""


class DeduplicationCache:
    """Time-window alert deduplication cache."""

    def __init__(self, window_seconds: int = 900) -> None:
        """Initialize the cache.

        Args:
            window_seconds: Suppress matching alerts inside this window.
        """

        self.window_seconds = window_seconds
        self._last_seen: dict[str, float] = {}

    def is_duplicate(self, alert: Alert, *, now: float | None = None) -> bool:
        """Return whether a matching alert was recorded inside the window."""

        current = time.time() if now is None else now
        previous = self._last_seen.get(alert.stable_key())
        return previous is not None and current - previous < self.window_seconds

    def record(self, alert: Alert, *, now: float | None = None) -> None:
        """Remember that an alert was delivered."""

        current = time.time() if now is None else now
        self._last_seen[alert.stable_key()] = current
        self._prune(current)

    def should_emit(self, alert: Alert, *, now: float | None = None) -> bool:
        """Check and record an alert in one step.

        Backends that can fail should call ``is_duplicate`` and ``record``
        separately so an alert is only recorded once it has been delivered.
        """

        current = time.time() if now is None else now
        if self.is_duplicate(alert, now=current):
            return False
        self.record(alert, now=current)
        return True

    def _prune(self, now: float) -> None:
        expired = [
            key for key, seen in self._last_seen.items() if now - seen > self.window_seconds * 2
        ]
        for key in expired:
            del self._last_seen[key]


class Alerter(ABC):
    """Abstract base class for alert emitters."""

    def __init__(self, dedup_cache: DeduplicationCache | None = None) -> None:
        """Initialize the alerter."""

        self.dedup_cache = dedup_cache or DeduplicationCache()

    def emit(self, alert: Alert) -> bool:
        """Emit an alert if it is not suppressed by deduplication.

        The alert is recorded for deduplication only after the backend accepts
        it. A failed delivery therefore stays eligible for a retry instead of
        being suppressed for the rest of the window.
        """

        if self.dedup_cache.is_duplicate(alert):
            return False
        self._send(alert)
        self.dedup_cache.record(alert)
        return True

    @abstractmethod
    def _send(self, alert: Alert) -> None:
        """Send an alert to the backend.

        Raise ``AlertDeliveryError`` when the backend is unreachable or rejects
        the alert, so callers can keep running and retry.
        """
