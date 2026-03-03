"""Centralized model configuration and middleware for all agents.

Each agent reads from ``FACKEL_MODEL_{AGENT}`` env-var, defaulting to
``gpt-5-mini``.  One place to change, one convention to remember.

Middleware stack (applied to every ReAct agent):

- **ParallelToolCalls** — enables ``parallel_tool_calls`` so the LLM can
  batch independent tool calls in a single response.
- **ToolRetryMiddleware** — retries network-level tool failures
  (``ConnectionError``, ``TimeoutError``, ``OSError``) with exponential
  backoff, avoiding premature agent failure from transient errors.
- **HumanInTheLoopMiddleware** *(opt-in)* — interrupts before active
  scanning tools (nmap, nuclei, etc.) for per-tool-call human approval.
  Enabled by passing ``approve_tools=True`` to :func:`default_middleware`.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from langchain.agents.middleware import HumanInTheLoopMiddleware, ToolRetryMiddleware
from langchain.agents.middleware.types import (
    AgentMiddleware,
    ModelRequest,
    ModelResponse,
)
from langchain_openai import ChatOpenAI

from fackel.settings import get_settings

_RETRYABLE_ERRORS: tuple[type[Exception], ...] = (
    ConnectionError,
    TimeoutError,
    OSError,
)

ACTIVE_SCAN_TOOLS: frozenset[str] = frozenset(
    {
        "naabu_scan",
        "nmap_port_scan",
        "nuclei_scan",
        "dalfox_scan",
        "wpscan_scan",
        "corsy_scan",
        "feroxbuster_scan",
        "katana_crawl",
        "testssl_scan",
        "sqlmap_scan",
        "ssrf_detect",
        "open_redirect_scan",
        "ssti_scan",
        "ffuf_scan",
    }
)


def get_model(agent_name: str) -> str:
    """Return the LLM model name for *agent_name*.

    Looks up ``FACKEL_MODEL_{AGENT_NAME}`` (upper-cased) in the
    environment, falling back to :data:`_DEFAULT_MODEL`.
    """
    env_var = f"FACKEL_MODEL_{agent_name.upper()}"
    return os.getenv(env_var, get_settings().default_model)


def build_llm(
    agent_name: str,
    *,
    model_name: str | None = None,
    temperature: float | None = None,
    request_timeout: int | None = None,
) -> ChatOpenAI:
    """Build a ``ChatOpenAI`` with standard configuration.

    Centralises model selection, timeout, and LangSmith tracing in one
    place so agents stay DRY.  When ``LANGCHAIN_TRACING_V2=true`` and
    ``LANGCHAIN_API_KEY`` are set, LangChain automatically traces all
    LLM calls to LangSmith — no explicit callback required.

    Parameters
    ----------
    agent_name:
        Logical name used to resolve ``FACKEL_MODEL_{AGENT}`` env-var.
    model_name:
        Explicit model override; bypasses env-var lookup.
    temperature:
        Sampling temperature.  ``None`` leaves the provider default.
    request_timeout:
        Per-request timeout in seconds (default :data:`LLM_REQUEST_TIMEOUT`).
    """
    kwargs: dict[str, Any] = {
        "model": model_name or get_model(agent_name),
        "request_timeout": request_timeout or get_settings().llm_request_timeout,
    }
    if temperature is not None:
        kwargs["temperature"] = temperature
    return ChatOpenAI(**kwargs)


def default_middleware(
    *,
    approve_tools: bool = False,
) -> list[AgentMiddleware]:
    """Return the standard middleware stack for ReAct agents.

    All ReAct agents share the same middleware to keep behaviour consistent:

    1. ``ParallelToolCalls`` — batches independent tool calls.
    2. ``ToolRetryMiddleware`` — retries transient network errors with
       exponential backoff (max 2 retries, 1 s initial delay, 2x factor).
    3. ``HumanInTheLoopMiddleware`` *(opt-in)* — when *approve_tools* is
       ``True``, interrupts before each active scanning tool call so the
       operator can approve, edit, or reject it.

    Parameters
    ----------
    approve_tools:
        Enable per-tool-call human approval for active scanning tools.
        Requires a checkpointer on the agent graph to support interrupts.
    """
    s = get_settings()
    mw: list[AgentMiddleware] = [
        ParallelToolCalls(),
        ToolRetryMiddleware(
            max_retries=s.tool_retry_max_retries,
            retry_on=_RETRYABLE_ERRORS,
            backoff_factor=s.tool_retry_backoff_factor,
            initial_delay=s.tool_retry_initial_delay,
            on_failure="continue",
        ),
    ]
    if approve_tools:
        mw.append(
            HumanInTheLoopMiddleware(
                interrupt_on=dict.fromkeys(ACTIVE_SCAN_TOOLS, True),
            )
        )
    return mw


class ParallelToolCalls(AgentMiddleware):
    """Middleware that enables ``parallel_tool_calls`` on every LLM request.

    When the OpenAI API receives ``parallel_tool_calls=True`` it may return
    several tool calls in a single response, which LangGraph's ToolNode
    executes concurrently via a thread-pool.  This dramatically reduces
    wall-clock time for agents that have many independent tools to call in
    each batch.
    """

    def wrap_model_call(
        self,
        request: ModelRequest[Any],
        handler: Callable[[ModelRequest[Any]], ModelResponse[Any]],
    ) -> ModelResponse[Any]:
        request.model_settings.setdefault("parallel_tool_calls", True)
        return handler(request)

    async def awrap_model_call(  # type: ignore[override]
        self,
        request: ModelRequest[Any],
        handler: Callable[[ModelRequest[Any]], ModelResponse[Any]],
    ) -> ModelResponse[Any]:
        request.model_settings.setdefault("parallel_tool_calls", True)
        return await handler(request)  # type: ignore[misc,no-any-return]
