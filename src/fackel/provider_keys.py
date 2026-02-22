"""Provider API key configuration and validation helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderKeySpec:
    """Describe one provider key expected in the environment."""

    provider: str
    env_var: str
    used_by: tuple[str, ...]


PROVIDER_KEYS: tuple[ProviderKeySpec, ...] = (
    ProviderKeySpec("VirusTotal", "VIRUSTOTAL_API_KEY", ("tools/virustotal_tool.py",)),
    ProviderKeySpec("Shodan", "SHODAN_API_KEY", ("tools/shodan_tool.py",)),
    ProviderKeySpec("SerpAPI", "SERPAPI_API_KEY", ("tools/serpapi_tool.py", "tools/linkedin_employee_search.py")),
    ProviderKeySpec("Censys", "CENSYS_API_ID", ("tools/censys_tool.py",)),
    ProviderKeySpec("Censys", "CENSYS_API_SECRET", ("tools/censys_tool.py",)),
    ProviderKeySpec("HaveIBeenPwned", "HIBP_API_KEY", ("tools/email_analyzer.py",)),
    ProviderKeySpec("EmailRep", "EMAILREP_API_KEY", ("tools/email_analyzer.py",)),
)


def get_provider_key_status() -> list[tuple[ProviderKeySpec, bool]]:
    """Return each provider key with a boolean indicating if it is configured."""
    statuses: list[tuple[ProviderKeySpec, bool]] = []
    for spec in PROVIDER_KEYS:
        configured = bool((os.getenv(spec.env_var) or "").strip())
        statuses.append((spec, configured))
    return statuses


def has_any_provider_key() -> bool:
    """Return True when at least one provider key is configured."""
    return any(configured for _, configured in get_provider_key_status())
