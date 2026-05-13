"""Webhook alert backend."""

from __future__ import annotations

from typing import Any

import requests

from integrity_monitor.alerting.base import Alert, Alerter, DeduplicationCache


class WebhookAlerter(Alerter):
    """Send alerts to Slack, Discord, or a generic webhook."""

    def __init__(
        self,
        url: str,
        *,
        kind: str = "generic",
        timeout_seconds: float = 5.0,
        dedup_cache: DeduplicationCache | None = None,
    ) -> None:
        """Initialize the webhook alerter.

        Args:
            url: Webhook URL.
            kind: One of ``generic``, ``slack``, or ``discord``.
            timeout_seconds: HTTP timeout.
        """

        super().__init__(dedup_cache=dedup_cache)
        self.url = url
        self.kind = kind.lower()
        self.timeout_seconds = timeout_seconds

    def _send(self, alert: Alert) -> None:
        payload = self._payload(alert)
        response = requests.post(self.url, json=payload, timeout=self.timeout_seconds)
        response.raise_for_status()

    def _payload(self, alert: Alert) -> dict[str, Any]:
        text = f"[{alert.severity.upper()}] {alert.title}: {alert.description}"
        if self.kind == "slack":
            return {
                "text": text,
                "blocks": [
                    {"type": "section", "text": {"type": "mrkdwn", "text": text}},
                    {
                        "type": "context",
                        "elements": [{"type": "mrkdwn", "text": f"source: {alert.source}"}],
                    },
                ],
            }
        if self.kind == "discord":
            return {
                "content": text,
                "embeds": [
                    {
                        "title": alert.title,
                        "description": alert.description,
                        "fields": [
                            {"name": "Severity", "value": alert.severity, "inline": True},
                            {"name": "Source", "value": alert.source, "inline": True},
                        ],
                    }
                ],
            }
        return {
            "title": alert.title,
            "severity": alert.severity,
            "source": alert.source,
            "description": alert.description,
            "details": alert.details,
        }
