from __future__ import annotations

import os
from dataclasses import dataclass

# Mapping de ferramentas para variáveis de ambiente necessárias
TOOL_REQUIREMENTS: dict[str, list[str]] = {
    "shodan_lookup": ["SHODAN_API_KEY"],
    "virustotal_subdomain_enum": ["VIRUSTOTAL_API_KEY"],
    "censys_lookup": ["CENSYS_API_ID", "CENSYS_API_SECRET"],
    "censys_web_lookup": ["CENSYS_API_ID", "CENSYS_API_SECRET"],
    "serp_search": ["SERPAPI_API_KEY"],
}

# Ferramentas sem dependência de API ficam sempre disponíveis (extensível para pro/plugins)
ALWAYS_ON: set[str] = {
    "whois_lookup",
    "dnsdumpster_lookup",
    "duckduckgo_lookup",
    "extract_webpage_content",
    "job_search",
    "search_linkedin_for_employees",
    "analyze_email",
    "analyze_professional_profile",
    "probe_host",
    "nmap_port_scan",
}


def register_tool_requirements(tool_name: str, required_vars: list[str]) -> None:
    """Expose a hook so pro/plugins can declare env requirements."""
    TOOL_REQUIREMENTS[tool_name] = required_vars


def register_always_on(tool_name: str) -> None:
    """Mark tool as available independent of API keys (used by offline/local tools)."""
    ALWAYS_ON.add(tool_name)


@dataclass
class Capabilities:
    available: set[str]
    missing: dict[str, list[str]]

    def summary_lines(self) -> list[str]:
        lines = []
        if self.available:
            lines.append("Ferramentas habilitadas: " + ", ".join(sorted(self.available)))
        if self.missing:
            details = [f"{tool} (faltam: {', '.join(vars)})" for tool, vars in self.missing.items()]
            lines.append("Ferramentas desabilitadas: " + "; ".join(sorted(details)))
        return lines


def detect_capabilities() -> Capabilities:
    available: set[str] = set()
    missing: dict[str, list[str]] = {}

    for tool_name, required_vars in TOOL_REQUIREMENTS.items():
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            missing[tool_name] = missing_vars
        else:
            available.add(tool_name)

    available.update(ALWAYS_ON)

    return Capabilities(available=available, missing=missing)
