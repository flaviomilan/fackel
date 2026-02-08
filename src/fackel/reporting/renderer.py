from __future__ import annotations

from fackel.core.models import DomainReport
from fackel.core.scoring import compute_domain_score, risk_label
from fackel.core.store import StructuredStore


def render_structured_summary(store: StructuredStore) -> str:
    report: DomainReport = store.report
    scores = compute_domain_score(store)
    lines: list[str] = []

    lines.append("### Score Geral")
    lines.append(
        f"- Domínio `{report.domain}`: score {scores['domain_score']:.1f} ({risk_label(scores['domain_score'])})"
    )
    lines.append("")

    if report.hosts:
        lines.append("### Hosts e Serviços")
        for name, host in report.hosts.items():
            host_score = scores["host_scores"].get(name, 0.0)
            lines.append(
                f"- **{name}** (IP: {host.ip or 'n/d'}) — score {host_score:.1f} ({risk_label(host_score)})"
            )
            if host.services:
                for svc in host.services:
                    cves = ", ".join([c.cve_id for c in svc.cves]) if svc.cves else "-"
                    lines.append(
                        f"  - {svc.protocol}/{svc.port} {svc.name or ''} {svc.product or ''} {svc.version or ''} (estado: {svc.state}) CVEs: {cves}"
                    )
        lines.append("")

    if report.findings:
        lines.append("### Achados")
        for f in report.findings:
            lines.append(f"- [{f.severity or 'info'}] {f.title}")
        lines.append("")

    all_cves = set()
    for host in report.hosts.values():
        for svc in host.services:
            for c in svc.cves:
                all_cves.add(c.cve_id)
    if all_cves:
        lines.append("### CVEs Encontradas")
        for cve in sorted(all_cves):
            lines.append(f"- {cve}")
        lines.append("")

    if report.evidence:
        lines.append("### Evidências")
        for ev in report.evidence:
            content = ev.content.strip()
            lines.append(f"- {ev.source_tool}: {content}")

    return "\n".join(lines)
