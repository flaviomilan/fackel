"""Event emission, per-context callbacks, lanes, and cooperative cancel.

LangGraph node functions have a fixed ``(state) -> dict`` signature, so callbacks
are stored in :class:`contextvars.ContextVar` slots; concurrent scans / threads
get isolated wiring rather than racing on module globals.  LangGraph copies the
parent context into worker threads, so ``current_lane`` / ``current_cancel`` set
inside a node propagate to every event it emits.
"""

from __future__ import annotations

import contextlib
import contextvars
import threading
from collections.abc import Callable, Iterator
from typing import Any

EventCallback = Callable[[str, str, dict[str, Any]], None] | None

ToolApprovalCallback = Callable[[dict[str, Any]], str] | None

# Per-context state (asyncio tasks / threads get isolated values).  See
# the module docstring for the rationale.
_event_callback_var: contextvars.ContextVar[EventCallback] = contextvars.ContextVar(
    "fackel_event_callback", default=None
)
_tool_approval_callback_var: contextvars.ContextVar[ToolApprovalCallback] = contextvars.ContextVar(
    "fackel_tool_approval_callback", default=None
)
_tool_approval_enabled_var: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "fackel_tool_approval_enabled", default=False
)

# Scan-level correlation id; used by structured logging and event payloads.
current_scan_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "fackel_current_scan_id", default=None
)


class StreamCancelledError(RuntimeError):
    """Raised inside agent streaming when a cooperative cancel is requested.

    The interactive harness sets :data:`current_cancel`; ``emit`` (called on every
    token/tool event) checks it and raises this to unwind the agent stream and the
    graph from a worker thread (signals only work on the main thread)."""


# Scan cancel flag; when set, the next emitted event raises ``StreamCancelledError``.
# Bound per-run by the harness worker so it propagates into specialist threads.
current_cancel: contextvars.ContextVar[threading.Event | None] = contextvars.ContextVar(
    "fackel_current_cancel", default=None
)


# Per-agent "lane" id; identifies which parallel specialist emitted an event so
# the renderer can show concurrent agents in separate lanes instead of one
# interleaved stream.  ``None`` (the default) means the single sequential "main"
# lane.  LangGraph copies the parent context into worker threads, so setting this
# inside a specialist node propagates to every event that node emits.
current_lane: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "fackel_current_lane", default=None
)


@contextlib.contextmanager
def lane(name: str) -> Iterator[None]:
    """Bind *name* as the current event lane for the duration of the block.

    Events emitted inside the block carry ``data["lane"] = name`` (attached by
    :func:`emit`); the previous lane is restored on exit.
    """
    token = current_lane.set(name)
    try:
        yield
    finally:
        current_lane.reset(token)


def set_event_callback(cb: EventCallback) -> None:
    """Set the callback that receives real-time ReAct events."""
    _event_callback_var.set(cb)


def set_tool_approval(
    enabled: bool,
    callback: ToolApprovalCallback = None,
) -> None:
    """Enable or disable per-tool-call human approval.

    When enabled, active scanning agents (port_scan, vuln_scan) are built
    with ``HumanInTheLoopMiddleware`` and each tool call interrupts for
    human approval before executing.

    Parameters
    ----------
    enabled:
        Whether to enable tool-level approval.
    callback:
        Optional ``(interrupt_data: dict) -> str`` returning ``"approve"``,
        ``"reject"``, or ``"edit"``.  If *None*, tools are auto-approved.
    """
    _tool_approval_enabled_var.set(enabled)
    _tool_approval_callback_var.set(callback)


def is_tool_approval_enabled() -> bool:
    """Whether tool-level approval is active for scanning agents."""
    return _tool_approval_enabled_var.get()


@contextlib.contextmanager
def run_session(
    *,
    event_callback: EventCallback = None,
    tool_approval: ToolApprovalCallback = None,
    approve_tools: bool = False,
    cancel: threading.Event | None = None,
) -> Iterator[None]:
    """Bind a run's streaming wiring atomically, restoring it on exit.

    One cohesive entry point for the per-run context (event callback, tool-approval
    callback/flag, cooperative cancel) instead of scattered ``set_*`` calls plus
    manual teardown.  All bindings are restored via ``ContextVar.reset`` when the
    block exits — so nothing leaks into the next run even on error.

    Note: the underlying state stays in :mod:`contextvars` by necessity —
    LangGraph node functions have a fixed ``(state, config)`` signature, so a run
    object cannot be threaded through them directly; the context is what LangGraph
    copies into the parallel specialist worker threads.
    """
    cb_token = _event_callback_var.set(event_callback)
    enabled_token = _tool_approval_enabled_var.set(approve_tools)
    approval_token = _tool_approval_callback_var.set(tool_approval)
    cancel_token = current_cancel.set(cancel) if cancel is not None else None
    try:
        yield
    finally:
        _event_callback_var.reset(cb_token)
        _tool_approval_enabled_var.reset(enabled_token)
        _tool_approval_callback_var.reset(approval_token)
        if cancel_token is not None:
            current_cancel.reset(cancel_token)


def reset_streaming_context() -> None:
    """Reset all per-context streaming state — for tests only."""
    _event_callback_var.set(None)
    _tool_approval_callback_var.set(None)
    _tool_approval_enabled_var.set(False)
    current_scan_id.set(None)


# Serialises event-callback invocations: parallel specialist nodes run on
# separate threads, and the CLI's Rich renderer is not thread-safe.
_emit_lock = threading.Lock()


def emit(phase: str, event_type: str, data: dict[str, Any]) -> None:
    """Notify the event callback if set, attaching ``scan_id`` when known.

    Thread-safe: callback dispatch is serialised so concurrent OSINT
    specialist threads cannot corrupt the renderer.
    """
    cancel = current_cancel.get()
    if cancel is not None and cancel.is_set():
        raise StreamCancelledError("scan cancelled by user")
    cb = _event_callback_var.get()
    if cb is None:
        return
    scan_id = current_scan_id.get()
    if scan_id is not None and "scan_id" not in data:
        data = {**data, "scan_id": scan_id}
    lane_id = current_lane.get()
    if lane_id is not None and "lane" not in data:
        data = {**data, "lane": lane_id}
    with _emit_lock:
        cb(phase, event_type, data)
