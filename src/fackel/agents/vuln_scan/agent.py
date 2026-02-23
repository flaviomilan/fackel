"""Vulnerability scan specialist — ReAct agent for infrastructure vuln scanning.

The LLM uses Nuclei, httpx, wafw00f, feroxbuster, and katana to detect
vulnerabilities, map web surfaces, and identify WAF protections.
"""

from __future__ import annotations

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt
from tools.feroxbuster_tool import feroxbuster_scan
from tools.graphql_scanner import graphql_scan
from tools.httpx_tool import httpx_scan
from tools.katana_tool import katana_crawl
from tools.nuclei_tool import nuclei_scan
from tools.wafw00f_tool import wafw00f_detect

TOOLS = [nuclei_scan, httpx_scan, wafw00f_detect, graphql_scan, feroxbuster_scan, katana_crawl]


def build(model_name: str | None = None):
    """Return a compiled ReAct vulnerability scan agent."""
    llm = ChatOpenAI(model=model_name or get_model("vuln_scan"))
    return create_react_agent(llm, TOOLS, prompt=load_prompt("vuln_scan"))
