"""Alerting backends."""

from integrity_monitor.alerting.base import Alert, Alerter, DeduplicationCache
from integrity_monitor.alerting.console import ConsoleAlerter
from integrity_monitor.alerting.file import FileAlerter
from integrity_monitor.alerting.webhook import WebhookAlerter

__all__ = [
    "Alert",
    "Alerter",
    "ConsoleAlerter",
    "DeduplicationCache",
    "FileAlerter",
    "WebhookAlerter",
]
