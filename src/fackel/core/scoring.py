from __future__ import annotations

from fackel.core.models import Service
from fackel.core.store import StructuredStore

# Risk Scsre Thresholds
SCORE_CRITICAL = 9.0
SCORE_HIGH = 7.0
SCORE_MEDIUM = 4.0


def cvss_from_service(service: Service) -> float:
    """Calculate max CVSS score for a service based on its CVEs."""
    scores = [c.cvss for c in service.cves if c.cvss is not None]
    return max(scores) if scores else 0.0


def risk_label(score: float) -> str:
    """Classify risk score into readable label."""
    if score >= SCORE_CRITICAL:
        return "critical"
    if score >= SCORE_HIGH:
        return "high"
    if score >= SCORE_MEDIUM:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def compute_domain_score(store: StructuredStore) -> dict:
    """Compute aggregate risk scores for the domain and its hosts."""
    host_scores: dict[str, float] = {}

    for name, host in store.report.hosts.items():
        service_scores = [cvss_from_service(svc) for svc in host.services]
        host_scores[name] = max(service_scores) if service_scores else 0.0

    domain_score = max(host_scores.values()) if host_scores else 0.0

    return {
        "domain_score": domain_score,
        "host_scores": host_scores,
    }
