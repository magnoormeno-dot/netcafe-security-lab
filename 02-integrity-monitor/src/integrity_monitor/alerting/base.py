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


class DeduplicationCache:
    """Time-window alert deduplication cache."""

    def __init__(self, window_seconds: int = 900) -> None:
        """Initialize the cache.

        Args:
            window_seconds: Suppress matching alerts inside this window.
        """

        self.window_seconds = window_seconds
        self._last_seen: dict[str, float] = {}

    def should_emit(self, alert: Alert, *, now: float | None = None) -> bool:
        """Return whether an alert should be emitted."""

        current = time.time() if now is None else now
        key = alert.stable_key()
        previous = self._last_seen.get(key)
        if previous is not None and current - previous < self.window_seconds:
            return False
        self._last_seen[key] = current
        self._prune(current)
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
        """Emit an alert if it is not suppressed by deduplication."""

        if not self.dedup_cache.should_emit(alert):
            return False
        self._send(alert)
        return True

    @abstractmethod
    def _send(self, alert: Alert) -> None:
        """Send an alert to the backend."""
