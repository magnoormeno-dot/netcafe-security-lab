"""Console alert backend."""

from __future__ import annotations

import json

import click

from integrity_monitor.alerting.base import Alert, Alerter


class ConsoleAlerter(Alerter):
    """Print alerts to stdout as JSON lines."""

    def _send(self, alert: Alert) -> None:
        click.echo(json.dumps(alert.__dict__, ensure_ascii=True, default=str))
