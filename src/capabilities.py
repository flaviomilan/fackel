from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, List, Set


# Mapping de ferramentas para variáveis de ambiente necessárias
TOOL_REQUIREMENTS: Dict[str, List[str]] = {
    "shodan_lookup": ["SHODAN_API_KEY"],
    "virustotal_subdomain_enum": ["VIRUSTOTAL_API_KEY"],
    "censys_lookup": ["CENSYS_API_ID", "CENSYS_API_SECRET"],
    "censys_web_lookup": ["CENSYS_API_ID", "CENSYS_API_SECRET"],
    "serp_search": ["SERPAPI_API_KEY"],
}


@dataclass
class Capabilities:
    available: Set[str]
    missing: Dict[str, List[str]]

    def summary_lines(self) -> List[str]:
        lines = []
        if self.available:
            lines.append("Ferramentas habilitadas: " + ", ".join(sorted(self.available)))
        if self.missing:
            details = [f"{tool} (faltam: {', '.join(vars)})" for tool, vars in self.missing.items()]
            lines.append("Ferramentas desabilitadas: " + "; ".join(sorted(details)))
        return lines


def detect_capabilities() -> Capabilities:
    available: Set[str] = set()
    missing: Dict[str, List[str]] = {}

    for tool_name, required_vars in TOOL_REQUIREMENTS.items():
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            missing[tool_name] = missing_vars
        else:
            available.add(tool_name)

    # Ferramentas sem dependência de API ficam sempre disponíveis
    always_on = {
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
    available.update(always_on)

    return Capabilities(available=available, missing=missing)
