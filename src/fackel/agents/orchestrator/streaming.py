"""Agent streaming infrastructure for the orchestrator graph.

Manages real-time event emission and tool-approval callbacks during
ReAct agent execution.  The CLI layer configures callbacks via
``set_event_callback`` and ``set_tool_approval`` before invoking the
graph.

Note on module-level state
~~~~~~~~~~~~~~~~~~~~~~~~~~
LangGraph node functions have a fixed ``(state) -> dict`` signature,
so dependency injection of callbacks is not possible through function
arguments.  Module-level slots are the pragmatic compromise; they are
set once before graph execution and cleared afterwards.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import Callable
from typing import Any

from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage, ToolMessage
from langchain_core.runnables import RunnableConfig
from langgraph.types import Command

logger = logging.getLogger(__name__)

try:
    from openai import APIConnectionError, APITimeoutError, RateLimitError

    _LLM_TRANSIENT_ERRORS: tuple[type[Exception], ...] = (
        RateLimitError,
        APIConnectionError,
        APITimeoutError,
    )
except ImportError:  # pragma: no cover - openai always installed via langchain-openai
    _LLM_TRANSIENT_ERRORS = ()

EventCallback = Callable[[str, str, dict[str, Any]], None] | None

ToolApprovalCallback = Callable[[dict[str, Any]], str] | None


_event_callback: EventCallback = None
_tool_approval_callback: ToolApprovalCallback = None
_tool_approval_enabled: bool = False

MAX_AGENT_ITERATIONS = 40


def set_event_callback(cb: EventCallback) -> None:
    """Set the callback that receives real-time ReAct events."""
    global _event_callback
    _event_callback = cb


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
    global _tool_approval_enabled, _tool_approval_callback
    _tool_approval_enabled = enabled
    _tool_approval_callback = callback


def is_tool_approval_enabled() -> bool:
    """Whether tool-level approval is active for scanning agents."""
    return _tool_approval_enabled


def emit(phase: str, event_type: str, data: dict[str, Any]) -> None:
    """Notify the event callback if set."""
    if _event_callback is not None:
        _event_callback(phase, event_type, data)


def validate_tool_output(msg: ToolMessage) -> ToolMessage:
    """Basic structural validation of tool results.

    Detects errors from two sources:
    - ``ToolException`` via ``handle_tool_error`` (msg.status == "error")
    - Legacy envelope with ``status: "error"`` in JSON content

    Logs warnings for malformed or error outputs without blocking the agent.
    """
    if getattr(msg, "status", None) == "error":
        logger.debug("tool %s raised ToolException: %s", msg.name, msg.content)
        return msg

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


def agent_summary(messages: list[Any]) -> str:
    """Return the last AI message content, or a fallback."""
    for msg in reversed(messages):
        if (
            isinstance(msg, AIMessage)
            and isinstance(msg.content, str)
            and msg.content.strip()
            and not getattr(msg, "tool_calls", None)
        ):
            return msg.content.strip()
    return "No findings."


class _AgentStreamer:
    """Streams a ReAct agent, emitting events and collecting messages.

    Handles dual ``stream_mode=["updates", "messages"]``:

    * **updates** — complete ``AIMessage`` / ``ToolMessage`` objects per
      node execution for reliable tracking and message collection.
    * **messages** — token-level ``AIMessageChunk`` objects for real-time
      streaming display.

    Also enforces ``MAX_AGENT_ITERATIONS`` and handles HITL
    interrupt/resume cycles when the inner agent has a checkpointer.
    """

    def __init__(self, agent: Any, phase: str, config: RunnableConfig | None = None) -> None:
        self._agent = agent
        self._phase = phase
        self._messages: list[Any] = []
        self._tool_call_count = 0
        self._hit_limit = False
        self._has_checkpointer = getattr(agent, "checkpointer", None) is not None

        inner: dict[str, Any] = {}
        if self._has_checkpointer:
            inner.setdefault("configurable", {})["thread_id"] = str(uuid.uuid4())

        if config:
            outer_callbacks = config.get("callbacks")
            if outer_callbacks:
                inner["callbacks"] = outer_callbacks
            if config.get("metadata"):
                inner["metadata"] = config["metadata"]
            if config.get("tags"):
                inner["tags"] = config["tags"]

        self._config: dict[str, Any] | None = inner or None

    def run(self, user_message: str) -> list[Any]:
        """Execute the full streaming cycle and return collected messages."""
        emit(self._phase, "start", {})
        self._stream_once({"messages": [HumanMessage(content=user_message)]})
        self._handle_interrupts()
        return self._messages

    _MAX_LLM_RETRIES = 1
    _LLM_RETRY_DELAY = 5.0

    def _stream_once(self, input_data: Any) -> None:
        """Run one streaming pass using dual updates + messages mode.

        Catches transient OpenAI API errors (rate-limit, timeout,
        connection) and retries once with back-off.  If the retry also
        fails, the error is logged and an event emitted so the scan can
        continue with whatever messages were already collected.
        """
        retries = 0
        while True:
            try:
                for mode, event in self._agent.stream(
                    input_data,
                    config=self._config,
                    stream_mode=["updates", "messages"],
                ):
                    if mode == "messages":
                        self._on_message_chunk(event)
                    elif mode == "updates" and isinstance(event, dict):
                        self._on_node_update(event)
                    if self._hit_limit:
                        break
                return
            except _LLM_TRANSIENT_ERRORS as exc:
                if retries < self._MAX_LLM_RETRIES:
                    retries += 1
                    delay = self._LLM_RETRY_DELAY * retries
                    logger.warning(
                        "%s: transient LLM error (%s), retrying in %.0fs (%d/%d)",
                        self._phase,
                        type(exc).__name__,
                        delay,
                        retries,
                        self._MAX_LLM_RETRIES,
                    )
                    emit(
                        self._phase,
                        "warning",
                        {"content": f"LLM API error ({type(exc).__name__}), retrying…"},
                    )
                    time.sleep(delay)
                    continue
                logger.error(
                    "%s: LLM API error after %d retries — continuing with partial data",
                    self._phase,
                    self._MAX_LLM_RETRIES,
                    exc_info=True,
                )
                emit(
                    self._phase,
                    "error",
                    {
                        "content": f"LLM API error ({type(exc).__name__}), proceeding with partial data."
                    },
                )
                return

    def _on_message_chunk(self, event: tuple[Any, Any]) -> None:
        """Handle token-level streaming for real-time display."""
        chunk, _metadata = event
        if isinstance(chunk, AIMessageChunk) and chunk.content and not chunk.tool_call_chunks:
            emit(self._phase, "token", {"content": chunk.content})

    def _on_node_update(self, event: dict[str, Any]) -> None:
        """Handle node-level updates for reliable message collection."""
        for _node, node_data in event.items():
            if not isinstance(node_data, dict):
                continue
            for msg in node_data.get("messages", []):
                if isinstance(msg, AIMessage) and not isinstance(msg, AIMessageChunk):
                    self._on_ai_message(msg)
                elif isinstance(msg, ToolMessage):
                    self._on_tool_result(msg)
        self._check_iteration_limit()

    def _on_ai_message(self, msg: AIMessage) -> None:
        """Process a complete AI message — track tool calls or emit content."""
        self._messages.append(msg)
        if msg.tool_calls:
            for tc in msg.tool_calls:
                self._tool_call_count += 1
                emit(
                    self._phase,
                    "tool_call",
                    {"tool": tc["name"], "args": tc.get("args", {})},
                )
        elif msg.content:
            emit_content_blocks(self._phase, msg)

    def _on_tool_result(self, msg: ToolMessage) -> None:
        """Validate and record a tool result message."""
        validated = validate_tool_output(msg)
        self._messages.append(validated)
        _emit_tool_result_event(self._phase, validated)

    def _check_iteration_limit(self) -> None:
        """Stop streaming if max tool-call iterations exceeded."""
        if self._tool_call_count < MAX_AGENT_ITERATIONS:
            return
        logger.warning(
            "%s: hit max iterations (%d tool calls) — stopping agent",
            self._phase,
            MAX_AGENT_ITERATIONS,
        )
        emit(
            self._phase,
            "reasoning",
            {"content": f"⚠ Agent stopped: reached {MAX_AGENT_ITERATIONS} tool call limit."},
        )
        self._hit_limit = True

    def _handle_interrupts(self) -> None:
        """Resume interrupted tool approvals (HITL middleware)."""
        if not self._has_checkpointer or self._hit_limit:
            return
        snapshot = self._agent.get_state(self._config)
        while snapshot.next:
            if not (snapshot.tasks and snapshot.tasks[0].interrupts):
                break
            interrupt_data = snapshot.tasks[0].interrupts[0].value
            emit(self._phase, "tool_approval", {"data": interrupt_data})
            decision = (
                _tool_approval_callback(interrupt_data)
                if _tool_approval_callback is not None
                else "approve"
            )
            self._stream_once(Command(resume=decision))
            if self._hit_limit:
                break  # type: ignore[unreachable]
            snapshot = self._agent.get_state(self._config)


def _emit_tool_result_event(phase: str, msg: ToolMessage) -> None:
    """Emit a ``tool_result`` or ``tool_error`` event for a validated message."""
    is_error = False
    error_hint = ""

    if getattr(msg, "status", None) == "error":
        is_error = True
        error_hint = str(msg.content)[:200] if msg.content else "unknown"
    else:
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            if isinstance(payload, dict) and payload.get("status") == "error":
                is_error = True
                error_hint = str(payload.get("error", "unknown"))
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

    if is_error:
        emit(phase, "tool_error", {"tool": msg.name, "error": error_hint})
    else:
        emit(phase, "tool_result", {"tool": msg.name, "content": str(msg.content)[:500]})


def run_and_stream_agent(
    agent: Any,
    phase: str,
    user_message: str,
    *,
    config: RunnableConfig | None = None,
) -> list[Any]:
    """Stream a ReAct agent and return all collected messages.

    Uses dual ``stream_mode=["updates", "messages"]`` for reliable
    message collection and real-time token streaming.  Enforces
    ``MAX_AGENT_ITERATIONS`` and handles HITL interrupt/resume cycles.

    Parameters
    ----------
    config:
        Optional ``RunnableConfig`` from the outer orchestrator graph.
        Callbacks, metadata, and tags are merged into the inner agent
        config so observability traces (LangSmith) nest correctly.
    """
    return _AgentStreamer(agent, phase, config=config).run(user_message)
