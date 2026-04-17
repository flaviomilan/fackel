"""Agent streaming infrastructure for the orchestrator graph.

Split into focused submodules; this package re-exports the public surface so
existing ``from ..streaming import X`` / ``streaming.X`` call sites keep working:

- :mod:`.tokens`     — token estimation (context meter / trimming)
- :mod:`.events`     — callbacks, lanes, cancel, ``emit``
- :mod:`.logfilter`  — scan-id log tagging
- :mod:`.toolio`     — tool-output validation + result events
- :mod:`.agent`      — ``_AgentStreamer`` / ``run_and_stream_agent``
"""

from __future__ import annotations

from .agent import _AgentStreamer, agent_summary, run_and_stream_agent
from .events import (
    EventCallback,
    StreamCancelledError,
    ToolApprovalCallback,
    current_cancel,
    current_lane,
    current_scan_id,
    emit,
    is_tool_approval_enabled,
    lane,
    reset_streaming_context,
    run_session,
    set_event_callback,
    set_tool_approval,
)
from .logfilter import ScanIdLogFilter, install_scan_id_log_filter
from .tokens import _estimate_tokens, text_tokens
from .toolio import _classify_error, emit_content_blocks, validate_tool_output

__all__ = [
    "EventCallback",
    "ScanIdLogFilter",
    "StreamCancelledError",
    "ToolApprovalCallback",
    "_AgentStreamer",
    "_classify_error",
    "_estimate_tokens",
    "agent_summary",
    "current_cancel",
    "current_lane",
    "current_scan_id",
    "emit",
    "emit_content_blocks",
    "install_scan_id_log_filter",
    "is_tool_approval_enabled",
    "lane",
    "reset_streaming_context",
    "run_and_stream_agent",
    "run_session",
    "set_event_callback",
    "set_tool_approval",
    "text_tokens",
    "validate_tool_output",
]
