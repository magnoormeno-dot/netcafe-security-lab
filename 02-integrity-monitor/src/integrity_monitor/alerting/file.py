"""File alert backend."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from integrity_monitor.alerting.base import (
    Alert,
    AlertDeliveryError,
    Alerter,
    DeduplicationCache,
)


class FileAlerter(Alerter):
    """Append alerts to a JSON Lines file."""

    def __init__(self, path: str | Path, dedup_cache: DeduplicationCache | None = None) -> None:
        """Initialize the file alerter."""

        super().__init__(dedup_cache=dedup_cache)
        self.path = Path(path)

    def _send(self, alert: Alert) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "title": alert.title,
            "severity": alert.severity,
            "source": alert.source,
            "description": alert.description,
            "dedup_key": alert.dedup_key,
            "details": alert.details,
        }
        line = json.dumps(payload, ensure_ascii=True, default=str) + "\n"
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError as exc:
            raise AlertDeliveryError(f"Alert file write failed: {exc}") from exc
