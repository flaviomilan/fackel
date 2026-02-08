from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal

from tools.censys_tool import censys_lookup
from tools.censys_web_tool import censys_web_lookup
from tools.dnsdumpster_tool import dnsdumpster_lookup
from tools.duckduckgo_tool import duckduckgo_lookup
from tools.email_analyzer import analyze_email
from tools.host_prober import probe_host
from tools.job_search import job_search
from tools.linkedin_employee_search import search_linkedin_for_employees
from tools.nmap_scanner import nmap_port_scan
from tools.profile_analyzer import analyze_professional_profile
from tools.serpapi_tool import serp_search
from tools.shodan_tool import shodan_lookup
from tools.virustotal_tool import virustotal_subdomain_enum
from tools.webpage_extractor import extract_webpage_content
from tools.whois import whois_lookup


ToolCategory = Literal["passive", "active"]
ToolFn = Callable[[Any], Any]


@dataclass(slots=True)
class ToolDefinition:
    name: str
    fn: ToolFn
    category: ToolCategory = "passive"


class ToolRegistry:
    """Registry that allows extending tools at runtime (free/pro/plugins)."""

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}
        self._by_category: dict[ToolCategory, set[str]] = {"passive": set(), "active": set()}

    def register(self, name: str, fn: ToolFn, category: ToolCategory = "passive") -> None:
        self._tools[name] = ToolDefinition(name=name, fn=fn, category=category)
        self._by_category.setdefault(category, set()).add(name)

    def get(self, name: str) -> ToolFn | None:
        definition = self._tools.get(name)
        return definition.fn if definition else None

    def names(self, category: ToolCategory | None = None) -> list[str]:
        if category is None:
            return list(self._tools.keys())
        return list(self._by_category.get(category, set()))

    def plan(self, available: set[str], active_scan: bool) -> list[str]:
        """Compute the ordered plan given capabilities and mode."""
        plan = [name for name in self.names("passive") if name in available]
        if active_scan:
            plan.extend([name for name in self.names("active") if name in available])
        return plan


def _register_builtin_tools(registry: ToolRegistry) -> None:
    registry.register("whois_lookup", whois_lookup, category="passive")
    registry.register("virustotal_subdomain_enum", virustotal_subdomain_enum, category="passive")
    registry.register("dnsdumpster_lookup", dnsdumpster_lookup, category="passive")
    registry.register("shodan_lookup", shodan_lookup, category="passive")
    registry.register("duckduckgo_lookup", duckduckgo_lookup, category="passive")
    registry.register("extract_webpage_content", extract_webpage_content, category="passive")
    registry.register("job_search", job_search, category="passive")
    registry.register("serp_search", serp_search, category="passive")
    registry.register("search_linkedin_for_employees", search_linkedin_for_employees, category="passive")
    registry.register("analyze_email", analyze_email, category="passive")
    registry.register("analyze_professional_profile", analyze_professional_profile, category="passive")
    registry.register("censys_lookup", censys_lookup, category="passive")
    registry.register("censys_web_lookup", censys_web_lookup, category="passive")
    registry.register("probe_host", probe_host, category="active")
    registry.register("nmap_port_scan", nmap_port_scan, category="active")


_DEFAULT_REGISTRY = ToolRegistry()
_register_builtin_tools(_DEFAULT_REGISTRY)


# Backwards-compat convenience exports (static snapshots)
TOOL_REGISTRY = {name: td.fn for name, td in _DEFAULT_REGISTRY._tools.items()}
PASSIVE_TOOL_NAMES = _DEFAULT_REGISTRY.names("passive")
ACTIVE_TOOL_NAMES = _DEFAULT_REGISTRY.names("active")


def get_tool_registry() -> ToolRegistry:
    return _DEFAULT_REGISTRY


def register_tool(name: str, fn: ToolFn, category: ToolCategory = "passive") -> None:
    """Register extra tools (used by pro/plugins) into the shared registry."""
    _DEFAULT_REGISTRY.register(name, fn, category=category)


def get_all_tools(active_scan: bool, available_tool_names: set[str]):
    registry = get_tool_registry()
    plan = registry.plan(available_tool_names, active_scan)
    return [registry.get(name) for name in plan if registry.get(name)]
