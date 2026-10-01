"""Vulnerability scan specialist — ReAct agent for infrastructure vuln scanning.

The LLM uses Nuclei, httpx, wafw00f, feroxbuster, katana, testssl, dalfox,
sqlmap, ffuf, and specialised detectors (SSRF, SSTI, open redirect, security
headers, JWT analysis) to detect vulnerabilities, map web surfaces, analyse
TLS configurations, and identify WAF protections.
"""

from __future__ import annotations

from fackel.tools.scanning.feroxbuster_tool import feroxbuster_scan
from fackel.tools.scanning.ffuf_tool import ffuf_scan
from fackel.tools.scanning.graphql_scanner import graphql_scan
from fackel.tools.scanning.httpx_tool import httpx_scan
from fackel.tools.scanning.katana_tool import katana_crawl
from fackel.tools.scanning.s3scanner_tool import s3scanner_scan
from fackel.tools.scanning.wafw00f_tool import wafw00f_detect
from fackel.tools.vuln.corsy_tool import corsy_scan
from fackel.tools.vuln.dalfox_tool import dalfox_scan
from fackel.tools.vuln.jwt_analyzer import jwt_analyzer
from fackel.tools.vuln.nuclei_tool import nuclei_scan
from fackel.tools.vuln.open_redirect_tool import open_redirect_scan
from fackel.tools.vuln.security_headers import security_headers_audit
from fackel.tools.vuln.sqlmap_tool import sqlmap_scan
from fackel.tools.vuln.ssrf_tool import ssrf_detect
from fackel.tools.vuln.ssti_tool import ssti_scan
from fackel.tools.vuln.testssl_tool import testssl_scan
from fackel.tools.vuln.webpage_extractor import extract_webpage_content
from fackel.tools.vuln.wpscan_tool import wpscan_scan

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


_VULN_PROMPT_SECTIONS: tuple[str, ...] = (
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
    "tools/http_probing",
    "contracts/nuclei",
    "contracts/httpx",
    "strategy/error_resilience",
)
