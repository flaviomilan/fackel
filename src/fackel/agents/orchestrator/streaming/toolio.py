"""Tool-output validation/sanitisation and tool-result event emission."""

from __future__ import annotations

import json
import logging
import time

from langchain_core.messages import AIMessage, ToolMessage

from fackel.tooling.output_sanitizer import sanitize_tool_output as _sanitize_output

from .events import emit

logger = logging.getLogger(__name__)


def validate_tool_output(msg: ToolMessage) -> ToolMessage:
    """Validate and sanitize tool results before they reach the agent.

    Detects errors from two sources:
    - ``ToolException`` via ``handle_tool_error`` (msg.status == "error")
    - Legacy envelope with ``status: "error"`` in JSON content

    Non-error outputs are run through :func:`sanitize_tool_output` to
    enforce size limits, strip control characters, and redact prompt
    injection patterns.

    Logs warnings for malformed or error outputs without blocking the agent.
    """
    if getattr(msg, "status", None) == "error":
        logger.debug("tool %s raised ToolException: %s", msg.name, msg.content)
        return msg

    # --- sanitize raw content before structural checks ---
    if isinstance(msg.content, str):
        sanitized = _sanitize_output(msg.content, tool_name=msg.name or "")
        if sanitized != msg.content:
            logger.debug(
                "tool %s output sanitized (%d → %d bytes)",
                msg.name,
                len(msg.content),
                len(sanitized),
            )
            msg = msg.model_copy(update={"content": sanitized})

    try:
        payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
        if isinstance(payload, dict):
            status = payload.get("status")
            if status == "error":
                logger.debug(
                    "tool %s returned error: %s",
                    msg.name,
                    payload.get("error", "unknown"),
                )
            elif "tool" not in payload:
                logger.debug(
                    "tool %s returned non-standard output (missing 'tool' key)",
                    msg.name,
                )
    except (json.JSONDecodeError, TypeError, AttributeError):
        logger.debug("tool %s returned non-JSON output", msg.name)
    return msg


def emit_content_blocks(phase: str, msg: AIMessage) -> None:
    """Emit reasoning events from a complete AI message.

    Extended-thinking models (Claude, o-series) produce ``content_blocks``
    with ``type="reasoning"`` entries that are emitted as separate
    ``reasoning_trace`` events.  Regular text was already streamed
    token-by-token via the ``messages`` stream.
    """
    blocks = getattr(msg, "content_blocks", None)
    if not blocks:
        return

    for block in blocks:
        if isinstance(block, dict):
            block_type = block.get("type", "text")
            content = block.get("content", block.get("text", ""))
        elif hasattr(block, "type"):
            block_type = getattr(block, "type", "text")
            content = getattr(block, "content", getattr(block, "text", ""))
        else:
            continue

        if block_type == "reasoning" and content:
            emit(phase, "reasoning_trace", {"content": content})


def _emit_tool_result_event(phase: str, msg: ToolMessage) -> None:
    """Emit a ``tool_result`` or ``tool_error`` event for a validated message.

    Error events include a structured payload with ``tool``, ``error``,
    ``error_class`` (timeout | auth | connection | unknown), and ISO
    ``timestamp`` so consumers can persist or aggregate failure data.
    """
    is_error = False
    error_hint = ""
    error_class = "unknown"

    if getattr(msg, "status", None) == "error":
        is_error = True
        error_hint = str(msg.content)[:200] if msg.content else "unknown"
        error_class = _classify_error(error_hint)
    else:
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            if isinstance(payload, dict) and payload.get("status") == "error":
                is_error = True
                error_hint = str(payload.get("error", "unknown"))
                error_class = _classify_error(error_hint)
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

    if is_error:
        emit(
            phase,
            "tool_error",
            {
                "tool": msg.name,
                "error": error_hint,
                "error_class": error_class,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        )
    else:
        emit(phase, "tool_result", {"tool": msg.name, "content": str(msg.content)})


def _classify_error(error_text: str) -> str:
    """Map an error message to a coarse category for aggregation."""
    lower = error_text.lower()
    if "timeout" in lower or "timed out" in lower:
        return "timeout"
    if "401" in lower or "403" in lower or "auth" in lower or "api key" in lower:
        return "auth"
    if "connection" in lower or "refused" in lower or "unreachable" in lower:
        return "connection"
    if "rate" in lower and "limit" in lower:
        return "rate_limit"
    if "context length" in lower or "maximum context" in lower or "context_length" in lower:
        return "context_length"
    return "unknown"
