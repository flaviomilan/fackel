"""Structured logging configuration.

Supports two output formats controlled via ``FACKEL_LOG_FORMAT``:

- ``text`` *(default)* — human-readable, coloured for terminal use.
- ``json`` — one JSON object per line, suitable for log aggregation
  (ELK, Loki, CloudWatch, etc.).

Usage::

    from fackel.logging_config import configure_logging

    configure_logging(verbose=True)  # reads FACKEL_LOG_FORMAT from env

All existing ``logging.getLogger(__name__)`` calls throughout the
codebase work unchanged — only the root formatter changes.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime


class _JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON line.

    Fields: ``ts``, ``level``, ``logger``, ``message``, plus any
    ``exc_info`` serialised under ``exception``.
    """

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1] is not None:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


_TEXT_FORMAT = "%(asctime)s [%(name)s] %(message)s"
_TEXT_DATEFMT = "%H:%M:%S"


def configure_logging(*, verbose: bool = False) -> None:
    """Set up the root logger with the appropriate formatter.

    Parameters
    ----------
    verbose:
        When ``True``, the ``fackel`` logger hierarchy is set to DEBUG;
        otherwise only WARNING and above are emitted.

    Environment
    -----------
    ``FACKEL_LOG_FORMAT``
        ``"json"`` for structured JSON output; anything else (or unset)
        defaults to human-readable text.
    """
    log_format = os.getenv("FACKEL_LOG_FORMAT", "text").lower()

    root = logging.getLogger()
    root.setLevel(logging.WARNING)

    root.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    if log_format == "json":
        handler.setFormatter(_JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(_TEXT_FORMAT, datefmt=_TEXT_DATEFMT))

    root.addHandler(handler)

    if verbose:
        logging.getLogger("fackel").setLevel(logging.DEBUG)
