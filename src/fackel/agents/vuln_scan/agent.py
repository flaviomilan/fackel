"""Vulnerability scan specialist — ReAct agent for infrastructure vuln scanning.

The LLM uses Nuclei, httpx, wafw00f, feroxbuster, katana, testssl, dalfox,
sqlmap, ffuf, and specialised detectors (SSRF, SSTI, open redirect, security
headers, JWT analysis) to detect vulnerabilities, map web surfaces, analyse
TLS configurations, and identify WAF protections.
"""

from __future__ import annotations

from langchain.agents import create_agent
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph.state import CompiledStateGraph

from fackel.agents.config import build_llm, default_middleware
from fackel.prompts import compose_prompt
from tools.scanning.feroxbuster_tool import feroxbuster_scan
from tools.scanning.ffuf_tool import ffuf_scan
from tools.scanning.graphql_scanner import graphql_scan
from tools.scanning.httpx_tool import httpx_scan
from tools.scanning.katana_tool import katana_crawl
from tools.scanning.s3scanner_tool import s3scanner_scan
from tools.scanning.wafw00f_tool import wafw00f_detect
from tools.vuln.corsy_tool import corsy_scan
from tools.vuln.dalfox_tool import dalfox_scan
from tools.vuln.jwt_analyzer import jwt_analyzer
from tools.vuln.nuclei_tool import nuclei_scan
from tools.vuln.open_redirect_tool import open_redirect_scan
from tools.vuln.security_headers import security_headers_audit
from tools.vuln.sqlmap_tool import sqlmap_scan
from tools.vuln.ssrf_tool import ssrf_detect
from tools.vuln.ssti_tool import ssti_scan
from tools.vuln.testssl_tool import testssl_scan
from tools.vuln.webpage_extractor import extract_webpage_content
from tools.vuln.wpscan_tool import wpscan_scan

TOOLS = [
    nuclei_scan,
    dalfox_scan,
    wpscan_scan,
    corsy_scan,
    httpx_scan,
    wafw00f_detect,
    graphql_scan,
    feroxbuster_scan,
    katana_crawl,
    s3scanner_scan,
    testssl_scan,
    extract_webpage_content,
    security_headers_audit,
    jwt_analyzer,
    sqlmap_scan,
    ssrf_detect,
    open_redirect_scan,
    ssti_scan,
    ffuf_scan,
]


def build(
    model_name: str | None = None,
    *,
    approve_tools: bool = False,
) -> CompiledStateGraph:  # type: ignore[type-arg]
    """Return a compiled ReAct vulnerability scan agent.

    Parameters
    ----------
    approve_tools:
        When ``True``, wraps active scanning tools with
        ``HumanInTheLoopMiddleware`` so each tool call requires explicit
        human approval before execution.
    """
    llm = build_llm("vuln_scan", model_name=model_name)
    return create_agent(
        llm,
        TOOLS,
        system_prompt=compose_prompt(
            "vuln_scan",
            "tools/vuln_scanning",
            "tools/security_headers",
            "tools/sqli_scanning",
            "tools/jwt_analysis",
            "tools/ssrf_scanning",
            "tools/api_fuzzing",
            "tools/xss_scanning",
            "tools/wordpress_scanning",
            "tools/graphql_scanning",
            "tools/web_crawling",
            "contracts/nuclei",
            "contracts/httpx",
            "strategy/error_resilience",
        ),
        middleware=default_middleware(approve_tools=approve_tools),
        checkpointer=MemorySaver() if approve_tools else None,
        name="vuln_scan",
    )
