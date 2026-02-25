"""Vulnerability scan specialist — ReAct agent for infrastructure vuln scanning.

The LLM uses Nuclei, httpx, wafw00f, feroxbuster, katana, testssl, and
webpage extraction to detect vulnerabilities, map web surfaces, analyse TLS
configurations, and identify WAF protections.
"""

from __future__ import annotations

from langchain_openai import ChatOpenAI
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import create_react_agent

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt
from tools.scanning.feroxbuster_tool import feroxbuster_scan
from tools.scanning.graphql_scanner import graphql_scan
from tools.scanning.httpx_tool import httpx_scan
from tools.scanning.katana_tool import katana_crawl
from tools.scanning.wafw00f_tool import wafw00f_detect
from tools.vuln.nuclei_tool import nuclei_scan
from tools.vuln.testssl_tool import testssl_scan
from tools.vuln.webpage_extractor import extract_webpage_content

TOOLS = [
    nuclei_scan,
    httpx_scan,
    wafw00f_detect,
    graphql_scan,
    feroxbuster_scan,
    katana_crawl,
    testssl_scan,
    extract_webpage_content,
]


def build(model_name: str | None = None) -> CompiledStateGraph:
    """Return a compiled ReAct vulnerability scan agent."""
    llm = ChatOpenAI(model=model_name or get_model("vuln_scan"))
    return create_react_agent(llm, TOOLS, prompt=load_prompt("vuln_scan"))
