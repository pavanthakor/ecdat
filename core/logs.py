"""Structured JSON logging.

One line of JSON per event, so a scan's history is greppable and machine
readable without a parser. Every record carries an ``event`` name; anything
else a call site passes through ``extra`` is merged in as a top-level field.

Named ``logs`` rather than ``logging`` so that reading an import inside this
package never leaves any doubt about which module is meant.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

__all__ = ["JsonFormatter", "configure_logging", "get_logger"]

#: Attributes LogRecord always carries; anything else was passed by a call site
#: and is therefore part of the event.
_RESERVED = frozenset(
    set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "asctime"}
)


class JsonFormatter(logging.Formatter):
    """Render a LogRecord as a single JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": getattr(record, "event", record.getMessage()),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key, value in vars(record).items():
            if key not in _RESERVED and key != "event":
                payload[key] = value
        return json.dumps(payload, default=str, sort_keys=True)


def configure_logging(level: int = logging.INFO) -> None:
    """Send ECDAT's logs to stderr as JSON.

    stderr, not stdout: the CLI writes the CBOM to stdout, and mixing log lines
    into it would corrupt the document.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger("ecdat")
    root.handlers = [handler]
    root.setLevel(level)
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"ecdat.{name}")
