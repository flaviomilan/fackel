from src.tools.censys_tool import censys_lookup
from src.tools.censys_web_tool import censys_web_lookup
from src.tools.dnsdumpster_tool import dnsdumpster_lookup
from src.tools.duckduckgo_tool import duckduckgo_lookup
from src.tools.email_analyzer import analyze_email
from src.tools.host_prober import probe_host
from src.tools.job_search import job_search
from src.tools.linkedin_employee_search import search_linkedin_for_employees
from src.tools.nmap_scanner import nmap_port_scan
from src.tools.profile_analyzer import analyze_professional_profile
from src.tools.serpapi_tool import serp_search
from src.tools.shodan_tool import shodan_lookup
from src.tools.virustotal_tool import virustotal_subdomain_enum
from src.tools.webpage_extractor import extract_webpage_content
from src.tools.whois import whois_lookup


def get_passive_tools():
    """Returns a list of all available passive OSINT tools."""
    return [
        whois_lookup,
        virustotal_subdomain_enum,
        dnsdumpster_lookup,
        shodan_lookup,
        duckduckgo_lookup,
        extract_webpage_content,
        job_search,
        serp_search,
        search_linkedin_for_employees,
        analyze_email,
        analyze_professional_profile,
        censys_lookup,
        censys_web_lookup,
    ]


def get_active_tools():
    """Returns a list of all available active scanning tools."""
    return [probe_host, nmap_port_scan]


def get_all_tools(active_scan: bool = False):
    """Returns a list of tools based on the scanning mode."""
    tools = get_passive_tools()
    if active_scan:
        print("[Collector] Active scanning enabled. Adding active tools.")
        tools.extend(get_active_tools())
    return tools
