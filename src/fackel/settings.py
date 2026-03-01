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


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable operational settings loaded once from the environment.

    Grouped by subsystem.  Every field maps 1-to-1 to a ``FACKEL_*``
    environment variable listed in the field comment.
    """

    # --- Scan orchestration ---------------------------------------------------
    scan_timeout: int
    """``FACKEL_SCAN_TIMEOUT`` — global scan timeout in seconds (default 3600)."""

    max_agent_iterations: int
    """``FACKEL_MAX_AGENT_ITERATIONS`` — max tool calls per agent phase (default 50)."""

    budget_warning_ratio: float
    """``FACKEL_BUDGET_WARNING_RATIO`` — warn agent at this fraction of budget (default 0.8)."""

    # --- LLM provider ---------------------------------------------------------
    default_model: str
    """``FACKEL_DEFAULT_MODEL`` — fallback LLM model name (default ``gpt-5-mini``)."""

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


def _load_settings() -> Settings:
    """Build a ``Settings`` instance from the current environment."""
    return Settings(
        # Scan orchestration
        scan_timeout=_env_int("FACKEL_SCAN_TIMEOUT", 3600),
        max_agent_iterations=_env_int("FACKEL_MAX_AGENT_ITERATIONS", 50),
        budget_warning_ratio=_env_float("FACKEL_BUDGET_WARNING_RATIO", 0.8),
        # LLM provider
        default_model=_env_str("FACKEL_DEFAULT_MODEL", "gpt-5-mini"),
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
