"""Provider API key configuration and validation helpers.

Each ``ProviderKeySpec`` groups all env vars a provider needs together with
the LangChain tool names that depend on it.  When ``hard_fail`` is *True*
(the default), tools are **removed** from the agent if the key is missing.
Providers with ``hard_fail=False`` (e.g. HIBP, EmailRep) degrade gracefully
and are kept available even without a key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProviderKeySpec:
    """Describe one external provider and its required configuration."""

    provider: str
    env_vars: tuple[str, ...]
    tool_names: tuple[str, ...]
    hard_fail: bool = True


PROVIDER_KEYS: tuple[ProviderKeySpec, ...] = (
    ProviderKeySpec("Shodan", ("SHODAN_API_KEY",), ("shodan_lookup",)),
    ProviderKeySpec("VirusTotal", ("VIRUSTOTAL_API_KEY",), ("virustotal_subdomain_enum",)),
    ProviderKeySpec("Censys", ("CENSYS_API_ID", "CENSYS_API_SECRET"), ("censys_lookup",)),
    ProviderKeySpec("HaveIBeenPwned", ("HIBP_API_KEY",), ("analyze_email",), hard_fail=False),
    ProviderKeySpec("EmailRep", ("EMAILREP_API_KEY",), ("analyze_email",), hard_fail=False),
)


def _is_env_set(var: str) -> bool:
    return bool((os.getenv(var) or "").strip())


def get_provider_key_status() -> list[tuple[ProviderKeySpec, bool]]:
    """Return each provider with a boolean indicating if all its keys are configured."""
    return [
        (spec, all(_is_env_set(v) for v in spec.env_vars))
        for spec in PROVIDER_KEYS
    ]


def get_unavailable_tool_names() -> dict[str, tuple[str, tuple[str, ...]]]:
    """Return tool names that should be skipped due to missing API keys.

    Returns ``{tool_name: (provider, missing_env_vars)}`` for tools whose
    provider has ``hard_fail=True`` and at least one key is missing.
    """
    unavailable: dict[str, tuple[str, tuple[str, ...]]] = {}
    for spec in PROVIDER_KEYS:
        if not spec.hard_fail:
            continue
        missing = tuple(v for v in spec.env_vars if not _is_env_set(v))
        if missing:
            for name in spec.tool_names:
                unavailable[name] = (spec.provider, missing)
    return unavailable


def filter_tools(
    tools: list[Any],
) -> tuple[list[Any], list[tuple[str, str, tuple[str, ...]]]]:
    """Partition *tools* into available and skipped based on API key availability.

    Returns ``(available, skipped)`` where *skipped* contains
    ``(tool_name, provider, missing_env_vars)`` tuples.
    """
    unavailable = get_unavailable_tool_names()
    available: list[Any] = []
    skipped: list[tuple[str, str, tuple[str, ...]]] = []
    for tool in tools:
        name = getattr(tool, "name", "")
        if name in unavailable:
            provider, missing = unavailable[name]
            skipped.append((name, provider, missing))
        else:
            available.append(tool)
    return available, skipped


