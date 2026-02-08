"""Signal extraction utilities for policy engine."""

from __future__ import annotations

from fackel.schemas.state import AgentState


def extract_signals(state: AgentState) -> list[str]:
    """Extract textual signals from evidence, services, findings, and analysis logs."""
    signals: list[str] = []

    for ev in state.store.report.evidence:
        signals.append(ev.content or "")
        signals.append(ev.source_tool or "")

    for host in state.store.report.hosts.values():
        for svc in host.services:
            for part in (svc.name, svc.product, svc.version, svc.extra):
                if part:
                    signals.append(part)
            signals.append(f"{svc.protocol}/{svc.port}")

    for finding in state.store.report.findings:
        for part in (finding.title, finding.description, finding.evidence):
            if part:
                signals.append(part)

    for log in state.analysis_log:
        if log.get("analysis"):
            signals.append(log["analysis"])
        if log.get("tool"):
            signals.append(log["tool"])

    # Normalize trivial empties
    return [s for s in signals if s]
