"""ReAct agent streaming — dual updates/messages mode, retry, HITL, budget."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    HumanMessage,
    ToolMessage,
    trim_messages,
)
from langchain_core.runnables import RunnableConfig
from langchain_core.runnables.config import merge_configs
from langgraph.types import Command

from fackel.settings import get_settings

from .events import _tool_approval_callback_var, emit
from .tokens import _estimate_tokens
from .toolio import _emit_tool_result_event, emit_content_blocks, validate_tool_output

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

    Also enforces ``max_agent_iterations`` and handles HITL
    interrupt/resume cycles when the inner agent has a checkpointer.
    """

    def __init__(self, agent: Any, phase: str, config: RunnableConfig | None = None) -> None:
        self._agent = agent
        self._phase = phase
        self._messages: list[Any] = []
        self._tool_call_count = 0
        self._hit_limit = False
        self._has_checkpointer = getattr(agent, "checkpointer", None) is not None

        inner: RunnableConfig = {}
        if self._has_checkpointer:
            inner.setdefault("configurable", {})["thread_id"] = str(uuid.uuid4())

        # Align LangGraph's recursion limit with the tool-call budget so the
        # default (25 super-steps) doesn't silently cap the agent below the
        # configured limit. A ReAct round is ~2 super-steps; ``<= 0`` disables
        # the budget entirely, so we lift the recursion limit too.
        max_iter = get_settings().max_agent_iterations
        inner["recursion_limit"] = 10_000 if max_iter <= 0 else max(2 * max_iter + 10, 25)

        # merge_configs preserves callbacks, metadata, tags, run_name,
        # and run_id from the outer orchestrator config so that
        # LangSmith traces nest correctly under the parent run.
        self._config: RunnableConfig | None = (
            merge_configs(config, inner) if config else inner
        ) or None

    def run(self, user_message: str) -> list[Any]:
        """Execute the full streaming cycle and return collected messages."""
        s = get_settings()
        max_iterations = s.max_agent_iterations
        emit(self._phase, "start", {})
        if max_iterations > 0:
            budget_notice = (
                f"\n\n[BUDGET: You have a maximum of {max_iterations} tool calls"
                " for this phase. Use them wisely — prioritise high-value actions"
                " and batch independent calls.]"
            )
        else:
            budget_notice = (
                "\n\n[BUDGET: No fixed tool-call limit for this phase. Still be"
                " economical — stop when the playbook is complete or no new"
                " information is being found.]"
            )
        self._stream_once({"messages": [HumanMessage(content=user_message + budget_notice)]})
        self._handle_interrupts()
        return self._messages

    _MAX_LLM_RETRIES = property(lambda self: get_settings().llm_max_retries)
    _LLM_RETRY_DELAY = property(lambda self: get_settings().llm_retry_delay)

    def _stream_once(self, input_data: Any) -> None:
        """Run one streaming pass using dual updates + messages mode.

        Catches transient OpenAI API errors (rate-limit, timeout,
        connection) and retries once with back-off.  If the retry also
        fails, the error is logged and an event emitted so the scan can
        continue with whatever messages were already collected.

        When input contains messages, applies ``trim_messages`` to keep
        the conversation within the model's context window and avoid
        runaway token usage on long-running agents.
        """
        if isinstance(input_data, dict) and "messages" in input_data:
            input_data = dict(input_data)
            input_data["messages"] = trim_messages(
                input_data["messages"],
                max_tokens=get_settings().agent_context_window,
                token_counter=_estimate_tokens,
                strategy="last",
                allow_partial=False,
                start_on="human",
            )
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

    _BUDGET_WARNING_RATIO = property(lambda self: get_settings().budget_warning_ratio)

    def _check_iteration_limit(self) -> None:
        """Stop streaming if max tool-call iterations exceeded.

        Emits a soft warning when 80 % of the budget is consumed so the
        agent can start wrapping up.
        """
        max_iterations = get_settings().max_agent_iterations
        if max_iterations <= 0:
            return  # disabled — no hard tool-call cap

        if self._tool_call_count >= max_iterations:
            logger.warning(
                "%s: hit max iterations (%d tool calls) — stopping agent",
                self._phase,
                max_iterations,
            )
            emit(
                self._phase,
                "reasoning",
                {"content": f"⚠ Agent stopped: reached {max_iterations} tool call limit."},
            )
            self._hit_limit = True
            return

        warning_threshold = int(max_iterations * self._BUDGET_WARNING_RATIO)
        if self._tool_call_count == warning_threshold:
            remaining = max_iterations - self._tool_call_count
            logger.info(
                "%s: %d/%d tool calls used — %d remaining",
                self._phase,
                self._tool_call_count,
                max_iterations,
                remaining,
            )
            emit(
                self._phase,
                "reasoning",
                {
                    "content": (
                        f"⚠ Budget warning: {remaining} tool calls remaining"
                        f" out of {max_iterations}. Start wrapping up."
                    )
                },
            )

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
            cb = _tool_approval_callback_var.get()
            decision = cb(interrupt_data) if cb is not None else "approve"
            self._stream_once(Command(resume=decision))
            if self._hit_limit:
                break  # type: ignore[unreachable]
            snapshot = self._agent.get_state(self._config)


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
    ``max_agent_iterations`` and handles HITL interrupt/resume cycles.

    Parameters
    ----------
    config:
        Optional ``RunnableConfig`` from the outer orchestrator graph.
        Callbacks, metadata, and tags are merged into the inner agent
        config so observability traces (LangSmith) nest correctly.
    """
    return _AgentStreamer(agent, phase, config=config).run(user_message)
