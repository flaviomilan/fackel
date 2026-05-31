"""Inject the scan correlation id into log records."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from .events import current_scan_id

logger = logging.getLogger(__name__)


class ScanIdLogFilter(logging.Filter):
    """Inject ``scan_id`` from :data:`current_scan_id` into log records.

    Designed to be attached to a logging *handler* (where filters apply
    to all records, including those propagated up from child loggers)
    rather than to a logger (where filters only apply to records logged
    directly on that logger).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "scan_id"):
            record.scan_id = current_scan_id.get() or "-"
        return True


_scan_id_factory_installed = False
_previous_record_factory: Callable[..., logging.LogRecord] | None = None


def install_scan_id_log_filter() -> None:
    """Globally tag every :class:`logging.LogRecord` with ``scan_id``.

    Uses :func:`logging.setLogRecordFactory` so the attribute is present
    on records from any logger (orchestrator, agents, third-party libs)
    and survives logger-level filter lookups.
    """
    global _scan_id_factory_installed, _previous_record_factory
    if _scan_id_factory_installed:
        return
    _previous_record_factory = logging.getLogRecordFactory()
    prev_factory = _previous_record_factory

    def _factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = prev_factory(*args, **kwargs)
        if not hasattr(record, "scan_id"):
            record.scan_id = current_scan_id.get() or "-"
        return record

    logging.setLogRecordFactory(_factory)
    _scan_id_factory_installed = True
