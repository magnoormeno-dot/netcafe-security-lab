"""Structured logging helpers for the integrity monitor."""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, ClassVar


class JsonFormatter(logging.Formatter):
    """Format log records as compact JSON lines.

    The formatter preserves standard logging fields and includes any structured
    values passed through the ``extra`` dictionary.
    """

    RESERVED: ClassVar[frozenset[str]] = frozenset(
        {
            "args",
            "asctime",
            "created",
            "exc_info",
            "exc_text",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "module",
            "msecs",
            "message",
            "msg",
            "name",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "stack_info",
            "thread",
            "threadName",
        }
    )

    def format(self, record: logging.LogRecord) -> str:
        """Return a JSON representation of a log record."""

        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        for key, value in record.__dict__.items():
            if key not in self.RESERVED and not key.startswith("_"):
                payload[key] = value

        return json.dumps(payload, ensure_ascii=True, default=str)


def configure_logging(level: str = "INFO", *, json_logs: bool = True) -> None:
    """Configure package logging.

    Args:
        level: Logging level name.
        json_logs: Whether to emit JSON lines.
    """

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        JsonFormatter() if json_logs else logging.Formatter("%(levelname)s %(message)s")
    )
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(numeric_level)
    root.addHandler(handler)


def bind_context(
    logger: logging.Logger, **context: object
) -> logging.LoggerAdapter[logging.Logger]:
    """Return a logger adapter with stable structured context."""

    return logging.LoggerAdapter(logger, extra=dict(context))


def event_extra(values: Mapping[str, object]) -> dict[str, object]:
    """Return a plain ``extra`` dictionary for logging calls."""

    return dict(values)
