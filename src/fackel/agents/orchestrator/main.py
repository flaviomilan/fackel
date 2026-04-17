"""Orchestrator entry point.

Provides ``run`` (blocking) as the public interface consumed by the CLI
and tests.

Supports Human-in-the-Loop via ``interrupt()`` — when the graph pauses
at the approval gate, callers must resume with ``Command(resume=value)``.
"""

from __future__ import annotations

import functools
import logging
import signal
import threading
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command

from fackel.persistence import bind_store_for_scan
from fackel.settings import get_settings
from fackel.tooling import sanitize_target

from .graph import _reset_graph, build_graph
from .state import ScanState
from .streaming import current_scan_id, install_scan_id_log_filter

logger = logging.getLogger(__name__)


@functools.lru_cache(maxsize=1)
def _get_graph() -> CompiledStateGraph:  # type: ignore[type-arg]
    """Lazy-build the compiled graph (cached after first call)."""
    return build_graph()


def reset_orchestrator() -> None:
    """Clear the cached graph, checkpointer, and compiled agents — for tests only."""
    from fackel.agents.osint.agent import build as _build_osint
    from fackel.agents.osint.specialists import build_specialist as _build_specialist
    from fackel.agents.vuln_scan.specialists import build_vuln_specialist as _build_vuln_specialist

    _get_graph.cache_clear()
    _build_osint.cache_clear()
    _build_specialist.cache_clear()
    _build_vuln_specialist.cache_clear()
    _reset_graph()


def _initial_state(target: str, active_scan: bool) -> dict[str, Any]:
    clean_target = sanitize_target(target)
    return {
        "target": clean_target,
        "active_scan": active_scan,
        "discovered_ips": [],
        "discovered_subdomains": [],
        "findings": [],
        "unassessed_areas": [],
        "phase_evaluations": [],
        "ip_classifications": [],
        "tech_fingerprints": [],
        "osint_messages": [],
        "vuln_messages": [],
        "vuln_base_prompt": "",
        "risk_score": {},
        "report": "",
        "asset_inventory": "",
    }


def _config(scan_id: str) -> RunnableConfig:
    """Generate a unique thread config with scan-level correlation ID."""
    return cast(
        RunnableConfig,
        {
            "configurable": {"thread_id": str(uuid.uuid4())},
            "metadata": {"scan_id": scan_id},
        },
    )


class ScanTimeoutError(Exception):
    """Raised when the global scan timeout is exceeded."""


class ScanInterruptedError(Exception):
    """Raised when the scan receives SIGINT or SIGTERM."""


def _scan_timeout() -> int:
    """Return the global scan timeout in seconds from settings."""
    return get_settings().scan_timeout


def _timeout_handler(signum: int, frame: Any) -> None:
    raise ScanTimeoutError("Global scan timeout exceeded")


def _interrupt_handler(signum: int, frame: Any) -> None:
    sig_name = signal.Signals(signum).name
    raise ScanInterruptedError(f"Scan interrupted by {sig_name}")


# SIGALRM is only available on POSIX.  On Windows / environments where it
# is missing, we fall back to a threading.Timer that sets an event.
_HAS_SIGALRM = hasattr(signal, "SIGALRM")


class _TimeoutGuard:
    """Context manager that enforces a global scan timeout.

    On POSIX systems, uses ``signal.SIGALRM`` for reliable in-thread
    interruption.  On Windows / other platforms, falls back to a
    ``threading.Timer`` that sets an event polled after ``graph.invoke``.

    Parameters
    ----------
    timeout:
        Timeout in seconds.
    install_signal_handlers:
        When ``True`` (default), overrides ``SIGINT``/``SIGTERM`` for the
        duration of the scan so they raise :class:`ScanInterruptedError`.
        This is appropriate for the CLI but **must** be ``False`` when
        the orchestrator is invoked from an embedded host (web server,
        worker, notebook) that owns its own signal handlers.  The
        ``SIGALRM``-based timeout (POSIX) is independent of this flag and
        is always installed.

    Usage::

        guard = _TimeoutGuard(timeout_seconds)
        with guard:
            result = graph.invoke(...)
            guard.check()               # raises if timer fired (threading path)
    """

    def __init__(
        self,
        timeout: int,
        *,
        install_signal_handlers: bool = True,
        use_signals: bool = True,
    ) -> None:
        self._timeout = timeout
        # A timeout of 0 (or negative) disables the global scan timeout — no
        # alarm/timer is armed.  SIGINT/SIGTERM handling is independent and
        # still installed per ``install_signal_handlers``.
        self._enabled = timeout > 0
        self._install_signal_handlers = install_signal_handlers
        # ``signal.signal`` / ``signal.alarm`` only work on the main thread; when
        # the orchestrator runs in a worker thread (interactive harness), set
        # ``use_signals=False`` to force the ``threading.Timer`` timeout path and
        # skip SIGINT/SIGTERM installation.
        self._use_signals = use_signals and _HAS_SIGALRM
        self._prev_alarm: Any = None
        self._prev_int: Any = None
        self._prev_term: Any = None
        self._timer: threading.Timer | None = None
        self._expired = threading.Event()

    # -- context manager interface -----------------------------------------

    def __enter__(self) -> _TimeoutGuard:
        if self._enabled:
            if self._use_signals:
                self._prev_alarm = signal.signal(signal.SIGALRM, _timeout_handler)
                signal.alarm(self._timeout)
            else:
                self._timer = threading.Timer(self._timeout, self._expired.set)
                self._timer.daemon = True
                self._timer.start()

        if self._install_signal_handlers:
            self._prev_int = signal.signal(signal.SIGINT, _interrupt_handler)
            self._prev_term = signal.signal(signal.SIGTERM, _interrupt_handler)

        if self._enabled:
            logger.info("orchestrator: global timeout set to %d s", self._timeout)
        else:
            logger.info("orchestrator: global scan timeout disabled")
        return self

    def __exit__(self, *exc: object) -> None:
        if self._enabled:
            if self._use_signals:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, self._prev_alarm)
            elif self._timer is not None:
                self._timer.cancel()

        if self._install_signal_handlers:
            signal.signal(signal.SIGINT, self._prev_int)
            signal.signal(signal.SIGTERM, self._prev_term)

    # -- polling interface for the threading fallback ----------------------

    def check(self) -> None:
        """Raise ``ScanTimeoutError`` if the timer has expired (threading path)."""
        if self._enabled and not self._use_signals and self._expired.is_set():
            raise ScanTimeoutError("Global scan timeout exceeded")


def run(
    target: str,
    *,
    active_scan: bool = True,
    approval_callback: Callable[[dict[str, Any]], bool] | None = None,
    timeout: int | None = None,
    install_signal_handlers: bool = True,
) -> ScanState:
    """Execute the full scan workflow and return final state.

    Parameters
    ----------
    target:
        Domain or IP to scan.
    active_scan:
        Whether to enable active scanning phases.
    approval_callback:
        An optional callable ``(interrupt_value: dict) -> bool`` used to
        handle the human-in-the-loop approval gate.  If *None* and an
        interrupt occurs, the scan is automatically approved.
    timeout:
        Global scan timeout in seconds, overriding ``FACKEL_SCAN_TIMEOUT``.
        ``None`` (default) uses the configured setting; ``0`` or negative
        **disables** the timeout entirely (the scan runs until completion,
        interruption, or per-tool/per-LLM timeouts).
    install_signal_handlers:
        When ``True`` (default, suitable for the one-shot CLI), install
        SIGALRM/SIGINT/SIGTERM handlers.  Set ``False`` when calling ``run``
        from a **worker thread** (the interactive harness): signal handlers
        can only be set on the main thread, so the timeout falls back to a
        ``threading.Timer`` and SIGINT/SIGTERM are left to the host.

    Raises
    ------
    ScanTimeoutError
        When the scan exceeds the resolved timeout (default
        ``FACKEL_SCAN_TIMEOUT`` = 3600 s). Not raised when the timeout is
        disabled (``0``).
    ScanInterruptedError
        When the process receives SIGINT or SIGTERM during scanning.
    """
    scan_id = uuid.uuid4().hex[:12]
    install_scan_id_log_filter()
    logger.info("orchestrator: run %s (active_scan=%s, scan_id=%s)", target, active_scan, scan_id)

    graph = _get_graph()
    config = _config(scan_id)

    resolved_timeout = _scan_timeout() if timeout is None else timeout

    token = current_scan_id.set(scan_id)
    data_dir = Path(get_settings().data_dir).expanduser()
    try:
        with (
            bind_store_for_scan(scan_id, data_dir),
            _TimeoutGuard(
                resolved_timeout,
                install_signal_handlers=install_signal_handlers,
                use_signals=install_signal_handlers,
            ) as guard,
        ):
            result = graph.invoke(_initial_state(target, active_scan), config=config)
            guard.check()

            snapshot = graph.get_state(config)
            while snapshot.next:
                interrupt_values = snapshot.tasks[0].interrupts
                if interrupt_values:
                    interrupt_data = interrupt_values[0].value
                    approved = (
                        approval_callback(interrupt_data) if approval_callback is not None else True
                    )
                else:
                    approved = True

                result = graph.invoke(Command(resume=approved), config=config)
                guard.check()
                snapshot = graph.get_state(config)
    except ScanInterruptedError:
        logger.warning("orchestrator: scan %s interrupted — cleaning up", scan_id)
        raise
    finally:
        current_scan_id.reset(token)

    result["scan_id"] = scan_id
    return cast(ScanState, result)
