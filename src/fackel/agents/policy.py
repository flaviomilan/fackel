from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

from fackel.schemas.state import AgentState
from fackel.agents.playbooks import extract_signals
from fackel.agents.vector_store import VectorPlaybookStore


@dataclass
class ToolProposal:
    tool: str
    rule: str
    reason: str


@dataclass
class Rule:
    name: str
    tool: str
    matcher: Callable[[AgentState], Optional[str]]
    reason: str | None = None


class ToolPolicyEngine:
    """Adaptive policy to enqueue tools based on detected technologies.

    Rules return a text reason when matched. Only known tools should be enqueued
    (filtered by caller against registry). This class is intentionally lightweight
    but ready for extension with external playbooks/RAG.
    """

    def __init__(self) -> None:
        self.playbooks = VectorPlaybookStore()
        # Heuristic fallbacks (kept for safety even with playbooks)
        self.rules: List[Rule] = [
            Rule(
                name="graphql",
                tool="nuclei_scan",
                matcher=self._match_graphql,
                reason="GraphQL indicators detected; run nuclei with GraphQL templates",
            ),
            Rule(
                name="wordpress",
                tool="nuclei_scan",
                matcher=self._match_wordpress,
                reason="WordPress indicators detected; run nuclei CMS templates",
            ),
            Rule(
                name="waf_detection",
                tool="wafw00f_detect",
                matcher=self._match_waf_needed,
                reason="Web surface detected; confirm WAF presence",
            ),
            Rule(
                name="web_httpx",
                tool="httpx_scan",
                matcher=self._match_web_surface,
                reason="HTTP service detected; enrich with httpx",
            ),
            Rule(
                name="web_crawl",
                tool="katana_crawl",
                matcher=self._match_web_surface,
                reason="HTTP service detected; crawl paths with katana",
            ),
            Rule(
                name="web_dirb",
                tool="feroxbuster_scan",
                matcher=self._match_web_surface,
                reason="HTTP service detected; brute-force dirs with feroxbuster",
            ),
        ]

    def apply(self, state: AgentState) -> list[ToolProposal]:
        proposals: list[ToolProposal] = []
        already = set(state.completed + state.plan)

        # 1) Data-driven playbooks (RAG-lite)
        signals = extract_signals(state)
        for tool in self.playbooks.match(signals):
            if tool.name not in already:
                proposals.append(
                    ToolProposal(tool=tool.name, rule="playbook", reason=tool.reason)
                )

        # 2) Built-in rules (heuristics)
        for rule in self.rules:
            reason = rule.matcher(state)
            if reason and rule.tool not in already:
                proposals.append(ToolProposal(tool=rule.tool, rule=rule.name, reason=reason))

        return proposals

    # --------- Matchers ---------
    def _match_graphql(self, state: AgentState) -> str | None:
        signals: list[str] = []

        # Evidence content
        for ev in state.store.report.evidence:
            if self._text_mentions_graphql(ev.content):
                signals.append(f"evidence:{ev.source_tool}")

        # Services metadata
        for host in state.store.report.hosts.values():
            for svc in host.services:
                blob = " ".join(filter(None, [svc.name, svc.product, svc.version, svc.extra]))
                if self._text_mentions_graphql(blob):
                    signals.append(f"service:{host.hostname}:{svc.port}")

        # Findings evidence
        for finding in state.store.report.findings:
            for text in (finding.title, finding.description, finding.evidence):
                if self._text_mentions_graphql(text):
                    signals.append("finding")

        # Analysis logs
        for log in state.analysis_log:
            if self._text_mentions_graphql(log.get("analysis", "")):
                signals.append(f"analysis:{log.get('tool')}")

        if signals:
            return f"GraphQL indicators: {', '.join(sorted(set(signals)))}"
        return None

    def _match_wordpress(self, state: AgentState) -> str | None:
        signals: list[str] = []
        patterns = [r"wordpress", r"wp-content", r"wp-json", r"wp-admin", r"woocommerce"]

        for ev in state.store.report.evidence:
            if self._text_mentions(ev.content, patterns):
                signals.append(f"evidence:{ev.source_tool}")

        for host in state.store.report.hosts.values():
            for svc in host.services:
                blob = " ".join(filter(None, [svc.name, svc.product, svc.version, svc.extra]))
                if self._text_mentions(blob, patterns):
                    signals.append(f"service:{host.hostname}:{svc.port}")

        for finding in state.store.report.findings:
            for text in (finding.title, finding.description, finding.evidence):
                if self._text_mentions(text, patterns):
                    signals.append("finding")

        for log in state.analysis_log:
            if self._text_mentions(log.get("analysis", ""), patterns):
                signals.append(f"analysis:{log.get('tool')}")

        if signals:
            return f"WordPress indicators: {', '.join(sorted(set(signals)))}"
        return None

    def _match_web_surface(self, state: AgentState) -> str | None:
        """Detects exposed HTTP services to trigger httpx/katana/feroxbuster."""
        signals: list[str] = []
        web_ports = {80, 443, 8080, 8443, 8000, 3000, 5000, 4200}

        for host in state.store.report.hosts.values():
            for svc in host.services:
                if svc.port in web_ports or self._text_mentions(svc.name, [r"http", r"https", r"proxy", r"web"]):
                    signals.append(f"service:{host.hostname}:{svc.port}")

        for ev in state.store.report.evidence:
            if self._text_mentions(ev.content, [r"http://", r"https://", r"server:", r"content-type"]):
                signals.append(f"evidence:{ev.source_tool}")

        for log in state.analysis_log:
            if self._text_mentions(log.get("analysis", ""), [r"http", r"web server", r"ssl", r"tls"]):
                signals.append(f"analysis:{log.get('tool')}")

        if signals:
            return f"Web surface indicators: {', '.join(sorted(set(signals)))}"
        return None

    def _match_waf_needed(self, state: AgentState) -> str | None:
        """Trigger wafw00f when HTTP surface exists and wafw00f not already run."""
        web_reason = self._match_web_surface(state)
        if web_reason:
            return f"{web_reason} -> assess WAF"
        return None

    # --------- Helpers ---------
    @staticmethod
    def _text_mentions_graphql(text: str | None) -> bool:
        return ToolPolicyEngine._text_mentions(text, [r"graphql", r"graphiql", r"apollo", r"hasura"])

    @staticmethod
    def _text_mentions(text: str | None, patterns: Iterable[str]) -> bool:
        if not text:
            return False
        text_low = text.lower()
        return any(re.search(p, text_low) for p in patterns)
