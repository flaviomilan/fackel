from __future__ import annotations

from fackel.core.models import DomainReport, Service
from fackel.core.store import StructuredStore


def _cvss_from_service(service: Service) -> float:
    scores = [c.cvss for c in service.cves if c.cvss is not None]
    return max(scores) if scores else 0.0


def _risk_label(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def score_store(store: StructuredStore) -> dict:
    host_scores: dict[str, float] = {}
    for name, host in store.report.hosts.items():
        service_scores = [_cvss_from_service(svc) for svc in host.services]
        host_scores[name] = max(service_scores) if service_scores else 0.0

    domain_score = max(host_scores.values()) if host_scores else 0.0
    return {
        "domain_score": domain_score,
        "host_scores": host_scores,
    }


def render_structured_summary(store: StructuredStore) -> str:
    report: DomainReport = store.report
    scores = score_store(store)
    lines: list[str] = []

    lines.append("### Score Geral")
    lines.append(f"- Domínio `{report.domain}`: score {scores['domain_score']:.1f} ({_risk_label(scores['domain_score'])})")
    lines.append("")

    if report.hosts:
        lines.append("### Hosts e Serviços")
        for name, host in report.hosts.items():
            host_score = scores["host_scores"].get(name, 0.0)
            lines.append(f"- **{name}** (IP: {host.ip or 'n/d'}) — score {host_score:.1f} ({_risk_label(host_score)})")
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
        lines.append("### Evidências (resumo)")
        for ev in report.evidence[:10]:
            preview = ev.content.strip().splitlines()[0][:160]
            lines.append(f"- {ev.source_tool}: {preview}...")
        if len(report.evidence) > 10:
            lines.append(f"- (+{len(report.evidence) - 10} evidências ocultas)")

    return "\n".join(lines)
