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


TOOL_REGISTRY = {
    "whois_lookup": whois_lookup,
    "virustotal_subdomain_enum": virustotal_subdomain_enum,
    "dnsdumpster_lookup": dnsdumpster_lookup,
    "shodan_lookup": shodan_lookup,
    "duckduckgo_lookup": duckduckgo_lookup,
    "extract_webpage_content": extract_webpage_content,
    "job_search": job_search,
    "serp_search": serp_search,
    "search_linkedin_for_employees": search_linkedin_for_employees,
    "analyze_email": analyze_email,
    "analyze_professional_profile": analyze_professional_profile,
    "censys_lookup": censys_lookup,
    "censys_web_lookup": censys_web_lookup,
    "probe_host": probe_host,
    "nmap_port_scan": nmap_port_scan,
}


PASSIVE_TOOL_NAMES = [
    "whois_lookup",
    "virustotal_subdomain_enum",
    "dnsdumpster_lookup",
    "shodan_lookup",
    "duckduckgo_lookup",
    "extract_webpage_content",
    "job_search",
    "serp_search",
    "search_linkedin_for_employees",
    "analyze_email",
    "analyze_professional_profile",
    "censys_lookup",
    "censys_web_lookup",
]


ACTIVE_TOOL_NAMES = ["probe_host", "nmap_port_scan"]


def _filter_tools(tool_names, allowed_names):
    return [TOOL_REGISTRY[name] for name in tool_names if name in allowed_names]


def get_passive_tools(available_tool_names):
    """Returns passive tools that are available based on capabilities."""
    return _filter_tools(PASSIVE_TOOL_NAMES, available_tool_names)


def get_active_tools(available_tool_names):
    """Returns active tools that are available based on capabilities."""
    return _filter_tools(ACTIVE_TOOL_NAMES, available_tool_names)


def get_all_tools(active_scan: bool, available_tool_names):
    """Returns tools based on scanning mode and capability detection."""
    tools = get_passive_tools(available_tool_names)
    if active_scan:
        print("[Collector] Active scanning enabled. Adding active tools.")
        tools.extend(get_active_tools(available_tool_names))
    return tools
