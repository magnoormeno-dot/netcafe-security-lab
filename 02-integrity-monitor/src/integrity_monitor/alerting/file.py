"""File alert backend."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from integrity_monitor.alerting.base import Alert, Alerter, DeduplicationCache


class FileAlerter(Alerter):
    """Append alerts to a JSON Lines file."""

    def __init__(self, path: str | Path, dedup_cache: DeduplicationCache | None = None) -> None:
        """Initialize the file alerter."""

        super().__init__(dedup_cache=dedup_cache)
        self.path = Path(path)

    def _send(self, alert: Alert) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "title": alert.title,
            "severity": alert.severity,
            "source": alert.source,
            "description": alert.description,
            "dedup_key": alert.dedup_key,
            "details": alert.details,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True, default=str) + "\n")
