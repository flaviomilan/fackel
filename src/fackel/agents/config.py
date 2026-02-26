"""Centralized model configuration and middleware for all agents.

Each agent reads from ``FACKEL_MODEL_{AGENT}`` and ``FACKEL_PROVIDER_{AGENT}``
env-vars.  Provider defaults to ``openai``, model defaults to
``gpt-5-mini`` for OpenAI or ``llama3.2`` for Ollama.

Supported providers (extensible via :data:`_PROVIDER_FACTORIES`):

- **openai** — ``ChatOpenAI`` (default).
- **ollama** — ``ChatOllama`` for locally-hosted models.

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
from langchain_core.language_models.chat_models import BaseChatModel

_DEFAULT_PROVIDER = "openai"

_DEFAULT_MODELS: dict[str, str] = {
    "openai": "gpt-5-mini",
    "ollama": "llama3.2",
}

LLM_REQUEST_TIMEOUT: int = 120

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
    }
)

# ---------------------------------------------------------------------------
# Provider factory registry
# ---------------------------------------------------------------------------


def _build_openai(model: str, temperature: float | None, timeout: int) -> BaseChatModel:
    """Create a ``ChatOpenAI`` instance."""
    from langchain_openai import ChatOpenAI

    kwargs: dict[str, Any] = {"model": model, "request_timeout": timeout}
    if temperature is not None:
        kwargs["temperature"] = temperature
    return ChatOpenAI(**kwargs)


def _build_ollama(model: str, temperature: float | None, timeout: int) -> BaseChatModel:
    """Create a ``ChatOllama`` instance for locally-hosted models."""
    try:
        from langchain_ollama import ChatOllama
    except ImportError as exc:
        raise ImportError(
            "langchain-ollama is required for the Ollama provider. "
            "Install it with: pip install langchain-ollama"
        ) from exc

    base_url = os.getenv("FACKEL_OLLAMA_BASE_URL", "http://localhost:11434")
    kwargs: dict[str, Any] = {
        "model": model,
        "base_url": base_url,
        "timeout": timeout,
    }
    if temperature is not None:
        kwargs["temperature"] = temperature
    return ChatOllama(**kwargs)


_PROVIDER_FACTORIES: dict[str, Callable[[str, float | None, int], BaseChatModel]] = {
    "openai": _build_openai,
    "ollama": _build_ollama,
}


def get_provider(agent_name: str) -> str:
    """Return the LLM provider for *agent_name*.

    Looks up ``FACKEL_PROVIDER_{AGENT_NAME}`` (upper-cased) in the
    environment, falling back to :data:`_DEFAULT_PROVIDER`.
    """
    env_var = f"FACKEL_PROVIDER_{agent_name.upper()}"
    return os.getenv(env_var, _DEFAULT_PROVIDER).lower()


def get_model(agent_name: str) -> str:
    """Return the LLM model name for *agent_name*.

    Looks up ``FACKEL_MODEL_{AGENT_NAME}`` (upper-cased) in the
    environment, falling back to the provider-specific default model.
    """
    env_var = f"FACKEL_MODEL_{agent_name.upper()}"
    explicit = os.getenv(env_var)
    if explicit:
        return explicit
    provider = get_provider(agent_name)
    return _DEFAULT_MODELS.get(provider, _DEFAULT_MODELS["openai"])


def build_llm(
    agent_name: str,
    *,
    model_name: str | None = None,
    temperature: float | None = None,
    request_timeout: int | None = None,
) -> BaseChatModel:
    """Build a chat model for the configured provider.

    Centralises provider selection, model selection, timeout, and
    LangSmith tracing in one place so agents stay DRY.

    Provider resolution: ``FACKEL_PROVIDER_{AGENT}`` env-var, defaulting
    to ``openai``.  Model resolution: ``FACKEL_MODEL_{AGENT}`` env-var,
    defaulting to the provider-specific default (see :data:`_DEFAULT_MODELS`).

    Parameters
    ----------
    agent_name:
        Logical name used to resolve ``FACKEL_PROVIDER_{AGENT}`` and
        ``FACKEL_MODEL_{AGENT}`` env-vars.
    model_name:
        Explicit model override; bypasses env-var lookup.
    temperature:
        Sampling temperature.  ``None`` leaves the provider default.
    request_timeout:
        Per-request timeout in seconds (default :data:`LLM_REQUEST_TIMEOUT`).
    """
    provider = get_provider(agent_name)
    model = model_name or get_model(agent_name)
    timeout = request_timeout or LLM_REQUEST_TIMEOUT

    factory = _PROVIDER_FACTORIES.get(provider)
    if factory is None:
        supported = ", ".join(sorted(_PROVIDER_FACTORIES))
        raise ValueError(
            f"Unknown LLM provider '{provider}' for agent '{agent_name}'. "
            f"Supported providers: {supported}"
        )
    return factory(model, temperature, timeout)


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
    mw: list[AgentMiddleware] = [
        ParallelToolCalls(),
        ToolRetryMiddleware(
            max_retries=2,
            retry_on=_RETRYABLE_ERRORS,
            backoff_factor=2.0,
            initial_delay=1.0,
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
