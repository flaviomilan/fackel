from __future__ import annotations

from typing import Any

from fackel.core.registry import ToolRegistry, ToolFn, ToolCategory
from tools.censys_tool import censys_lookup
from tools.censys_web_tool import censys_web_lookup
from tools.feroxbuster_tool import feroxbuster_scan
from tools.dnsdumpster_tool import dnsdumpster_lookup
from tools.duckduckgo_tool import duckduckgo_lookup
from tools.email_analyzer import analyze_email
from tools.httpx_tool import httpx_scan
from tools.host_prober import probe_host
from tools.job_search import job_search
from tools.linkedin_employee_search import search_linkedin_for_employees
from tools.nmap_scanner import nmap_port_scan
from tools.naabu_tool import naabu_scan
from tools.nuclei_tool import nuclei_scan
from tools.profile_analyzer import analyze_professional_profile
from tools.serpapi_tool import serp_search
from tools.shodan_tool import shodan_lookup
from tools.virustotal_tool import virustotal_subdomain_enum
from tools.katana_tool import katana_crawl
from tools.wafw00f_tool import wafw00f_detect
from tools.webpage_extractor import extract_webpage_content
from tools.whois import whois_lookup


def _register_builtin_tools(registry: ToolRegistry) -> None:
    registry.register("whois_lookup", whois_lookup, category="passive")
    registry.register(
        "virustotal_subdomain_enum",
        virustotal_subdomain_enum,
        category="passive",
        required_env=["VIRUSTOTAL_API_KEY"],
    )
    registry.register("dnsdumpster_lookup", dnsdumpster_lookup, category="passive")
    registry.register(
        "shodan_lookup",
        shodan_lookup,
        category="passive",
        required_env=["SHODAN_API_KEY"],
    )
    registry.register("duckduckgo_lookup", duckduckgo_lookup, category="passive")
    registry.register(
        "extract_webpage_content", extract_webpage_content, category="passive"
    )
    registry.register("job_search", job_search, category="passive")
    registry.register(
        "serp_search", serp_search, category="passive", required_env=["SERPAPI_API_KEY"]
    )
    registry.register(
        "search_linkedin_for_employees",
        search_linkedin_for_employees,
        category="passive",
    )
    registry.register("analyze_email", analyze_email, category="passive")
    registry.register(
        "analyze_professional_profile", analyze_professional_profile, category="passive"
    )
    registry.register(
        "censys_lookup",
        censys_lookup,
        category="passive",
        required_env=["CENSYS_API_ID", "CENSYS_API_SECRET"],
    )
    registry.register(
        "censys_web_lookup",
        censys_web_lookup,
        category="passive",
        required_env=["CENSYS_API_ID", "CENSYS_API_SECRET"],
    )
    registry.register("probe_host", probe_host, category="active")
    registry.register("nmap_port_scan", nmap_port_scan, category="active")
    registry.register("httpx_scan", httpx_scan, category="active")
    registry.register("naabu_scan", naabu_scan, category="active")
    registry.register("nuclei_scan", nuclei_scan, category="active")
    registry.register("katana_crawl", katana_crawl, category="active")
    registry.register("feroxbuster_scan", feroxbuster_scan, category="active")
    registry.register("wafw00f_detect", wafw00f_detect, category="active")


_DEFAULT_REGISTRY = ToolRegistry()
_register_builtin_tools(_DEFAULT_REGISTRY)


# Backwards-compat convenience exports (static snapshots)
TOOL_REGISTRY = {name: td.fn for name, td in _DEFAULT_REGISTRY._tools.items()}
PASSIVE_TOOL_NAMES = _DEFAULT_REGISTRY.names("passive")
ACTIVE_TOOL_NAMES = _DEFAULT_REGISTRY.names("active")


def get_tool_registry() -> ToolRegistry:
    return _DEFAULT_REGISTRY


def register_tool(
    name: str,
    fn: ToolFn,
    category: ToolCategory = "passive",
    required_env: list[str] = None,
) -> None:
    """Register extra tools (used by pro/plugins) into the shared registry."""
    _DEFAULT_REGISTRY.register(name, fn, category=category, required_env=required_env)


def get_all_tools(active_scan: bool, available_tool_names: set[str]):
    registry = get_tool_registry()
    plan = registry.plan(available_tool_names, active_scan)
    return [registry.get(name) for name in plan if registry.get(name)]
