"""Centralized operational settings for the Fackel scanner.

Every tunable parameter — timeout, retry count, backoff factor, size
limit — lives here with a sensible default.  Each setting can be
overridden via an environment variable following the ``FACKEL_`` prefix
convention.

Usage::

    from fackel.settings import get_settings

    s = get_settings()
    timeout = s.scan_timeout
    retries = s.tool_retry_max_retries

The ``Settings`` dataclass is **frozen** (immutable after creation) and
loaded lazily on first call to :func:`get_settings`, which is cached
for the process lifetime.  Tests can call :func:`_reset_settings` to
force a reload.

Environment Variables
---------------------
See :class:`Settings` field docstrings and ``docs/configuration.md``
for the full reference table.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)


def _env_int(key: str, default: int) -> int:
    """Read *key* from the environment as ``int``, falling back to *default*."""
    raw = os.getenv(key, "").strip()
    if raw:
        try:
            return int(raw)
        except ValueError:
            logger.warning(
                "%s=%r is not a valid integer — using default %d",
                key,
                raw,
                default,
            )
    return default


def _env_float(key: str, default: float) -> float:
    """Read *key* from the environment as ``float``, falling back to *default*."""
    raw = os.getenv(key, "").strip()
    if raw:
        try:
            return float(raw)
        except ValueError:
            logger.warning(
                "%s=%r is not a valid float — using default %s",
                key,
                raw,
                default,
            )
    return default


def _env_str(key: str, default: str) -> str:
    """Read *key* from the environment as ``str``, falling back to *default*."""
    return os.getenv(key, default).strip() or default


def _env_bool(key: str, default: bool) -> bool:
    """Read *key* from the environment as a boolean, falling back to *default*."""
    raw = os.getenv(key)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable operational settings loaded once from the environment.

    Grouped by subsystem.  Every field maps 1-to-1 to a ``FACKEL_*``
    environment variable listed in the field comment.
    """

    # --- Scan orchestration ---------------------------------------------------
    scan_timeout: int
    """``FACKEL_SCAN_TIMEOUT`` — global scan timeout in seconds (default 3600).

    Set to ``0`` (or negative) to **disable** the global timeout entirely.
    """

    max_agent_iterations: int
    """``FACKEL_MAX_AGENT_ITERATIONS`` — max tool calls per agent phase (default 50).

    Set to ``0`` (or negative) to **disable** the tool-call limit; the agent then
    runs until its playbook is complete (or the scan timeout). Disabling also
    lifts LangGraph's recursion limit so it does not cap the phase early.
    """

    max_pivots: int
    """``FACKEL_MAX_PIVOTS`` — max entity-driven OSINT pivot passes (default 2).

    Set to ``0`` to disable the agentic pivot loop (one OSINT pass + retry only).
    """

    osint_specialists: bool
    """``FACKEL_OSINT_SPECIALISTS`` — run OSINT as focused specialist sub-agents
    (DNS/infra, subdomains, scan-DBs, web/tech, surface, secrets, people) each with
    a narrow toolset, instead of one monolithic 31-tool agent (default ``True``).
    Set to ``false`` to use the single-agent path."""

    vuln_specialists: bool
    """``FACKEL_VULN_SPECIALISTS`` — run vuln-scan as parallel specialist sub-agents
    (surface/discovery, nuclei, web-injection, app/config, TLS) fanned out via
    LangGraph ``Send``, instead of one monolithic agent (default ``True``).

    Note: vuln scanning is **active** — parallel specialists send concurrent traffic
    to the target, which is faster but more likely to trip WAF/rate-limits. Per-tool
    HITL approval (``FACKEL_APPROVE_TOOLS``) forces the sequential single-agent path
    regardless of this flag. Set to ``false`` to always use the single-agent path."""

    budget_warning_ratio: float
    """``FACKEL_BUDGET_WARNING_RATIO`` — warn agent at this fraction of budget (default 0.8)."""

    # --- LLM provider ---------------------------------------------------------
    default_model: str
    """``FACKEL_DEFAULT_MODEL`` — fallback LLM model name (default ``gpt-5-mini``)."""

    llm_provider: str
    """``FACKEL_LLM_PROVIDER`` — default LLM provider when model name lacks a "provider:model" prefix (default "openai"; supported: "openai", "ollama")."""

    ollama_base_url: str
    """``FACKEL_OLLAMA_BASE_URL`` — base URL of the Ollama server (default "http://localhost:11434"). Only used when provider is "ollama"."""

    copilot_api_base: str
    """``FACKEL_COPILOT_API_BASE`` — base URL of the GitHub Models API (default "https://models.github.ai/inference"). Only used when provider is "copilot"."""

    llm_request_timeout: int
    """``FACKEL_LLM_REQUEST_TIMEOUT`` — per-request LLM timeout in seconds (default 120)."""

    llm_max_retries: int
    """``FACKEL_LLM_MAX_RETRIES`` — transient LLM error retries (default 1)."""

    llm_retry_delay: float
    """``FACKEL_LLM_RETRY_DELAY`` — initial delay between LLM retries in seconds (default 5.0)."""

    # --- Tool retry middleware ------------------------------------------------
    tool_retry_max_retries: int
    """``FACKEL_TOOL_RETRY_MAX_RETRIES`` — ToolRetryMiddleware max retries (default 2)."""

    tool_retry_backoff_factor: float
    """``FACKEL_TOOL_RETRY_BACKOFF_FACTOR`` — backoff multiplier (default 2.0)."""

    tool_retry_initial_delay: float
    """``FACKEL_TOOL_RETRY_INITIAL_DELAY`` — initial delay in seconds (default 1.0)."""

    # --- Subprocess execution -------------------------------------------------
    subprocess_timeout: int
    """``FACKEL_SUBPROCESS_TIMEOUT`` — default subprocess timeout in seconds (default 180)."""

    subprocess_max_output: int
    """``FACKEL_SUBPROCESS_MAX_OUTPUT`` — max bytes per stdout/stderr stream (default 2 MiB)."""

    # --- Output sanitizer -----------------------------------------------------
    sanitizer_max_bytes: int
    """``FACKEL_SANITIZER_MAX_BYTES`` — max tool output before truncation (default 50000)."""

    # --- HTTP client ----------------------------------------------------------
    http_retry_total: int
    """``FACKEL_HTTP_RETRY_TOTAL`` — total retries for shared HTTP session (default 2)."""

    http_backoff_factor: float
    """``FACKEL_HTTP_BACKOFF_FACTOR`` — backoff factor for HTTP retries (default 1.0)."""

    # --- Circuit breaker ------------------------------------------------------
    circuit_breaker_threshold: int
    """``FACKEL_CIRCUIT_BREAKER_THRESHOLD`` — failures before opening circuit (default 3)."""

    circuit_breaker_reset_timeout: float
    """``FACKEL_CIRCUIT_BREAKER_RESET_TIMEOUT`` — seconds before half-open probe (default 60)."""

    # --- Logging --------------------------------------------------------------
    log_format: str
    """``FACKEL_LOG_FORMAT`` — ``"text"`` or ``"json"`` (default ``"text"``)."""

    # --- Checkpoint -----------------------------------------------------------
    checkpoint_db: str
    """``FACKEL_CHECKPOINT_DB`` — SQLite path for graph state (default ``~/.fackel/checkpoints.db``)."""

    # --- Agent context management ---------------------------------------------
    agent_context_window: int
    """``FACKEL_AGENT_CONTEXT_WINDOW`` — max tokens for trim_messages guard (default 120000)."""

    # --- Prompt composition ---------------------------------------------------
    prompt_profile: str
    """``FACKEL_PROMPT_PROFILE`` — ``"full"`` (default) or ``"compact"``.
    ``"compact"`` swaps in slim ``*_compact.md`` skill files and skips
    supplementary sections, fitting prompts within small-context endpoints
    such as the GitHub Models free tier (8K tokens/request)."""

    # --- Domain persistence ---------------------------------------------------
    data_dir: str
    """``FACKEL_DATA_DIR`` — root directory for per-scan domain JSONL stores
    (default ``~/.fackel/data``)."""

    # --- CLI presentation -----------------------------------------------------
    nerd_font: bool
    """``FACKEL_NERD_FONT`` — render the CLI with Nerd Font glyphs (default ``True``).

    Set to ``false`` (or ``0``) when the terminal font lacks Nerd Font patches; the
    harness then falls back to an ASCII glyph set that keeps column alignment intact."""


def _load_settings() -> Settings:
    """Build a ``Settings`` instance from the current environment."""
    return Settings(
        # Scan orchestration
        scan_timeout=_env_int("FACKEL_SCAN_TIMEOUT", 3600),
        max_agent_iterations=_env_int("FACKEL_MAX_AGENT_ITERATIONS", 50),
        max_pivots=_env_int("FACKEL_MAX_PIVOTS", 2),
        osint_specialists=_env_bool("FACKEL_OSINT_SPECIALISTS", True),
        vuln_specialists=_env_bool("FACKEL_VULN_SPECIALISTS", True),
        budget_warning_ratio=_env_float("FACKEL_BUDGET_WARNING_RATIO", 0.8),
        # LLM provider
        default_model=_env_str("FACKEL_DEFAULT_MODEL", "gpt-5-mini"),
        llm_provider=_env_str("FACKEL_LLM_PROVIDER", "openai"),
        ollama_base_url=_env_str("FACKEL_OLLAMA_BASE_URL", "http://localhost:11434"),
        copilot_api_base=_env_str("FACKEL_COPILOT_API_BASE", "https://models.github.ai/inference"),
        llm_request_timeout=_env_int("FACKEL_LLM_REQUEST_TIMEOUT", 120),
        llm_max_retries=_env_int("FACKEL_LLM_MAX_RETRIES", 1),
        llm_retry_delay=_env_float("FACKEL_LLM_RETRY_DELAY", 5.0),
        # Tool retry middleware
        tool_retry_max_retries=_env_int("FACKEL_TOOL_RETRY_MAX_RETRIES", 2),
        tool_retry_backoff_factor=_env_float("FACKEL_TOOL_RETRY_BACKOFF_FACTOR", 2.0),
        tool_retry_initial_delay=_env_float("FACKEL_TOOL_RETRY_INITIAL_DELAY", 1.0),
        # Subprocess execution
        subprocess_timeout=_env_int("FACKEL_SUBPROCESS_TIMEOUT", 180),
        subprocess_max_output=_env_int("FACKEL_SUBPROCESS_MAX_OUTPUT", 2 * 1024 * 1024),
        # Output sanitizer
        sanitizer_max_bytes=_env_int("FACKEL_SANITIZER_MAX_BYTES", 50_000),
        # HTTP client
        http_retry_total=_env_int("FACKEL_HTTP_RETRY_TOTAL", 2),
        http_backoff_factor=_env_float("FACKEL_HTTP_BACKOFF_FACTOR", 1.0),
        # Circuit breaker
        circuit_breaker_threshold=_env_int("FACKEL_CIRCUIT_BREAKER_THRESHOLD", 3),
        circuit_breaker_reset_timeout=_env_float("FACKEL_CIRCUIT_BREAKER_RESET_TIMEOUT", 60.0),
        # Logging
        log_format=_env_str("FACKEL_LOG_FORMAT", "text"),
        # Checkpoint
        checkpoint_db=_env_str(
            "FACKEL_CHECKPOINT_DB",
            str(Path.home() / ".fackel" / "checkpoints.db"),
        ),
        # Agent context management
        agent_context_window=_env_int("FACKEL_AGENT_CONTEXT_WINDOW", 120_000),
        # Prompt composition
        prompt_profile=_env_str("FACKEL_PROMPT_PROFILE", "full"),
        # Domain persistence
        data_dir=_env_str(
            "FACKEL_DATA_DIR",
            str(Path.home() / ".fackel" / "data"),
        ),
        # CLI presentation
        nerd_font=_env_bool("FACKEL_NERD_FONT", True),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton ``Settings`` instance (cached after first call)."""
    return _load_settings()


def _reset_settings() -> None:
    """Clear the settings cache so the next call reloads from env.

    Intended for **tests only** — production code should never call this.
    """
    get_settings.cache_clear()
