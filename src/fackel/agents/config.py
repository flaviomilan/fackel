"""Centralized model configuration and middleware for all agents.

Each agent reads from ``FACKEL_MODEL_{AGENT}`` env-var, defaulting to
``gpt-5-mini``.  One place to change, one convention to remember.

Middleware stack (applied to every ReAct agent):

- **ParallelToolCalls** — enables ``parallel_tool_calls`` so the LLM can
  batch independent tool calls in a single response.
- **ToolOutputSanitizer** — strips prompt-injection patterns and enforces
  size limits on tool results before they are persisted to agent state.
- **ToolRetryMiddleware** — retries transient network-level tool failures
  (``ConnectionError``, ``TimeoutError``) with exponential backoff and
  jitter, avoiding premature agent failure from transient errors.
- **HumanInTheLoopMiddleware** *(opt-in)* — interrupts before active
  scanning tools (nmap, nuclei, etc.) for per-tool-call human approval.
  Enabled by passing ``approve_tools=True`` to :func:`default_middleware`.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any, cast

from langchain.agents.middleware import (
    ClearToolUsesEdit,
    ContextEditingMiddleware,
    HumanInTheLoopMiddleware,
    ToolRetryMiddleware,
)
from langchain.agents.middleware.types import (
    AgentMiddleware,
    ModelRequest,
    ModelResponse,
    ToolCallRequest,
)
from langchain.chat_models import init_chat_model
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import ToolMessage

from fackel.settings import get_settings
from fackel.tooling.output_sanitizer import sanitize_tool_output

# Only genuinely transient, network-level failures are retried.  Bare
# ``OSError`` is deliberately excluded: ``ConnectionError`` and ``TimeoutError``
# (its transient subclasses) are listed explicitly, while non-transient
# ``OSError`` variants — ``FileNotFoundError``, ``PermissionError``, disk-full —
# must fail fast rather than waste retries.  ``ToolRetryMiddleware`` already
# applies exponential backoff with jitter.
_RETRYABLE_ERRORS: tuple[type[Exception], ...] = (
    ConnectionError,
    TimeoutError,
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
        # Tools that send traffic to the target — must require approval too.
        "wafw00f_detect",
        "s3scanner_scan",
        "graphql_scan",
        "httpx_scan",
        "extract_webpage_content",
        "security_headers_audit",
    }
)


def _supports_parallel_tool_calls(model: Any) -> bool:
    """Return True when *model* is an OpenAI chat model (incl. Azure).

    Uses class name string check to avoid hard-coupling to imports and to handle
    subclasses (e.g. AzureChatOpenAI) without explicit isinstance checks.
    """
    cls_name = type(model).__name__
    return cls_name in {"ChatOpenAI", "AzureChatOpenAI"}


def get_model(agent_name: str) -> str:
    """Return the LLM model name for *agent_name*.

    Looks up ``FACKEL_MODEL_{AGENT_NAME}`` (upper-cased) in the
    environment, falling back to :data:`_DEFAULT_MODEL`.
    """
    env_var = f"FACKEL_MODEL_{agent_name.upper()}"
    return os.getenv(env_var, get_settings().default_model)


_KNOWN_PROVIDERS: frozenset[str] = frozenset(
    {
        "anthropic",
        "azure_openai",
        "bedrock",
        "cohere",
        "copilot",
        "deepseek",
        "fireworks",
        "google_genai",
        "google_vertexai",
        "groq",
        "huggingface",
        "mistralai",
        "nvidia",
        "ollama",
        "openai",
        "openrouter",
        "together",
        "xai",
    }
)


_COPILOT_SMALL_CONTEXT_MODELS: frozenset[str] = frozenset(
    {
        "openai/gpt-5",
        "openai/o1",
        "openai/o1-mini",
        "openai/o1-preview",
    }
)
"""GitHub Models endpoint variants known to enforce a tight (~4K)
per-request input cap that even Fackel's compact prompts cannot fit into.
Listed here so :func:`build_llm` can fail fast with a clear remediation
message instead of bubbling an opaque HTTP 413."""


_COPILOT_FREE_TIER_REQUEST_BUDGET_TOKENS = 8000
"""GitHub Models free tier caps every model at this many tokens per request.
Fackel's full-profile prompts measure ~13K tokens; the compact profile fits
within this budget."""


def _split_provider_model(model: str, default_provider: str) -> tuple[str, str]:
    """Return ``(provider, model_name)``.

    Accepts ``"openai:gpt-4o-mini"`` or plain ``"gpt-4o-mini"``.
    Ollama tag syntax (``"qwen2.5:7b"``) is **not** treated as a provider
    prefix — the colon is only split when the left side is a known provider.
    """
    if ":" in model:
        candidate, _, rest = model.partition(":")
        if candidate.strip().lower() in _KNOWN_PROVIDERS:
            return candidate.strip().lower(), rest.strip()
    return default_provider, model


def build_llm(
    agent_name: str,
    *,
    model_name: str | None = None,
    temperature: float | None = None,
    request_timeout: int | None = None,
) -> BaseChatModel:
    """Build a chat model with standard configuration.

    Centralises model selection, timeout, and LangSmith tracing in one
    place so agents stay DRY.  When ``LANGCHAIN_TRACING_V2=true`` and
    ``LANGCHAIN_API_KEY`` are set, LangChain automatically traces all
    LLM calls to LangSmith — no explicit callback required.

    Provider selection: the resolved model name may carry a ``provider:model``
    prefix (e.g. ``"ollama:llama3.1"`` or ``"openai:gpt-4o-mini"``).  When no
    prefix is present, :attr:`~fackel.settings.Settings.llm_provider` is used
    as the fallback provider.

    Parameters
    ----------
    agent_name:
        Logical name used to resolve ``FACKEL_MODEL_{AGENT}`` env-var.
    model_name:
        Explicit model override (may include a ``provider:`` prefix); bypasses
        env-var lookup.
    temperature:
        Sampling temperature.  ``None`` leaves the provider default.
    request_timeout:
        Per-request timeout in seconds (default :attr:`~fackel.settings.Settings.llm_request_timeout`).
    """
    s = get_settings()
    raw = model_name or get_model(agent_name)
    provider, name = _split_provider_model(raw, s.llm_provider)
    timeout = request_timeout or s.llm_request_timeout

    kwargs: dict[str, Any] = {}
    if temperature is not None:
        kwargs["temperature"] = temperature
    if provider == "ollama":
        kwargs["base_url"] = s.ollama_base_url
        kwargs["client_kwargs"] = {"timeout": timeout}
    elif provider == "copilot":
        github_token = os.getenv("GITHUB_TOKEN", "").strip()
        if not github_token:
            raise ValueError(
                "GITHUB_TOKEN environment variable is required when using the "
                "'copilot' provider. Set it to a GitHub Personal Access Token."
            )
        if name in _COPILOT_SMALL_CONTEXT_MODELS:
            raise ValueError(
                f"Model '{name}' on the GitHub Models ('copilot') endpoint "
                "enforces a ~4K-token request cap that Fackel's agent prompts "
                "cannot fit into, even on the compact prompt profile. Switch "
                "FACKEL_DEFAULT_MODEL (or the relevant FACKEL_MODEL_<AGENT>) "
                "to a larger model — e.g. 'openai/gpt-4.1' or 'openai/gpt-4o' "
                "— and ensure FACKEL_PROMPT_PROFILE=compact."
            )
        if s.prompt_profile != "compact":
            raise ValueError(
                "The GitHub Models ('copilot') endpoint enforces an "
                f"{_COPILOT_FREE_TIER_REQUEST_BUDGET_TOKENS}-token request cap "
                "on its free tier (every model). Fackel's full-profile prompts "
                "measure ~13K tokens and will return HTTP 413. Set "
                "FACKEL_PROMPT_PROFILE=compact, or switch FACKEL_LLM_PROVIDER "
                "to a provider without that cap (e.g. 'openai' with "
                "OPENAI_API_KEY)."
            )
        kwargs["base_url"] = s.copilot_api_base
        kwargs["api_key"] = github_token
        kwargs["request_timeout"] = timeout
        provider = "openai"
    else:
        kwargs["request_timeout"] = timeout

    return cast(BaseChatModel, init_chat_model(name, model_provider=provider, **kwargs))


def default_middleware(
    *,
    approve_tools: bool = False,
) -> list[AgentMiddleware]:
    """Return the standard middleware stack for ReAct agents.

    All ReAct agents share the same middleware to keep behaviour consistent:

    1. ``ParallelToolCalls`` — batches independent tool calls.
    2. ``ToolOutputSanitizer`` — sanitises each tool result (size limit,
       control-char stripping, prompt-injection redaction) before it is
       persisted to agent state and re-read by the model.
    3. ``ToolRetryMiddleware`` — retries transient network errors with
       exponential backoff (max 2 retries, 1 s initial delay, 2x factor).
    4. ``ContextEditingMiddleware`` *(compact profile only)* — clears
       older tool results when the accumulated context approaches the
       8K-token cap of the GitHub Models free tier.
    4. ``HumanInTheLoopMiddleware`` *(opt-in)* — when *approve_tools* is
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
        # Outermost tool wrapper: sanitises the final (post-retry) tool result
        # before it is checkpointed and re-read by the model.
        ToolOutputSanitizer(),
        ToolRetryMiddleware(
            max_retries=s.tool_retry_max_retries,
            retry_on=_RETRYABLE_ERRORS,
            backoff_factor=s.tool_retry_backoff_factor,
            initial_delay=s.tool_retry_initial_delay,
            on_failure="continue",
        ),
    ]
    # Prune stale tool results before the request exceeds the model's context
    # window.  This is critical on the GitHub Models ('copilot') endpoint
    # whose free tier enforces an 8K-token request cap (every model): a long
    # OSINT scan accumulates ~30 tool results that easily blow past the cap
    # mid-run and surface as HTTP 413 'tokens_limit_reached'.
    if s.prompt_profile == "compact":
        mw.append(
            ContextEditingMiddleware(
                edits=[
                    ClearToolUsesEdit(
                        trigger=5500,
                        clear_at_least=1500,
                        keep=3,
                        clear_tool_inputs=True,
                        placeholder="[older tool result cleared to fit context window]",
                    )
                ],
                token_count_method="approximate",  # noqa: S106 — not a secret
            )
        )
    if approve_tools:
        mw.append(
            HumanInTheLoopMiddleware(
                interrupt_on=dict.fromkeys(ACTIVE_SCAN_TOOLS, True),
            )
        )
    return mw


class ParallelToolCalls(AgentMiddleware):
    """Middleware that enables ``parallel_tool_calls`` on OpenAI LLM requests.

    When the OpenAI API receives ``parallel_tool_calls=True`` it may return
    several tool calls in a single response, which LangGraph's ToolNode
    executes concurrently via a thread-pool.  This dramatically reduces
    wall-clock time for agents that have many independent tools to call in
    each batch.

    No-op for non-OpenAI providers (e.g. Ollama, Anthropic).
    """

    def wrap_model_call(
        self,
        request: ModelRequest[Any],
        handler: Callable[[ModelRequest[Any]], ModelResponse[Any]],
    ) -> ModelResponse[Any]:
        if _supports_parallel_tool_calls(request.model):
            request.model_settings.setdefault("parallel_tool_calls", True)
        return handler(request)

    async def awrap_model_call(  # type: ignore[override]
        self,
        request: ModelRequest[Any],
        handler: Callable[[ModelRequest[Any]], ModelResponse[Any]],
    ) -> ModelResponse[Any]:
        if _supports_parallel_tool_calls(request.model):
            request.model_settings.setdefault("parallel_tool_calls", True)
        return await handler(request)  # type: ignore[misc,no-any-return]


class ToolOutputSanitizer(AgentMiddleware):
    """Sanitise tool outputs before they are persisted to agent state.

    External services and scanned targets can return adversarial content
    designed to manipulate the LLM once it lands in the message history as a
    tool observation.  This middleware wraps every tool call and runs the
    resulting ``ToolMessage`` through :func:`sanitize_tool_output` (size
    limit, control-character stripping, prompt-injection pattern redaction)
    **before** it is checkpointed and re-read by the model on the next turn.

    Unlike the orchestrator's streaming observer — which only sanitises its
    local display copy — this middleware mutates the message that actually
    reaches the LLM.  Error results (``status == "error"``) and non-string
    payloads (e.g. ``Command``) are passed through untouched.
    """

    def _sanitize(self, result: ToolMessage | Any) -> ToolMessage | Any:
        if not isinstance(result, ToolMessage):
            return result
        if getattr(result, "status", None) == "error":
            return result
        if not isinstance(result.content, str):
            return result
        clean = sanitize_tool_output(result.content, tool_name=result.name or "")
        if clean != result.content:
            return result.model_copy(update={"content": clean})
        return result

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Any],
    ) -> ToolMessage | Any:
        return self._sanitize(handler(request))

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Any],
    ) -> ToolMessage | Any:
        return self._sanitize(await handler(request))
