"""Confidence / provenance scoring for information records.

Codifies the ``validation/source_reliability`` guidance into a numeric score so
findings carry an explicit trust level instead of being treated as equally
certain.  Confidence is a function of:

- **Source trust** — how authoritative the producing tool is (direct
  observation > scan database/aggregator > scraping/inference).
- **Corroboration** — how many *independent* sources reported the same fact;
  each extra source narrows the remaining gap to full confidence.

Used by the persistence layer (per-record ``confidence``), the judge
(record summaries), and pivot prioritisation.
"""

from __future__ import annotations

SOURCE_TRUST: dict[str, float] = {
    "dns_resolve": 0.95,
    "dnsx_resolve": 0.95,
    "tlscert_lookup": 0.95,
    "nmap_port_scan": 0.95,
    "naabu_scan": 0.9,
    "whois_lookup": 0.9,
    "crtsh_subdomain_enum": 0.9,
    "httpx_scan": 0.9,
    "bgp_lookup": 0.9,
    "reverse_dns_lookup": 0.85,
    "ipinfo_lookup": 0.85,
    "whatweb_scan": 0.8,
    "shodan_lookup": 0.8,
    "censys_lookup": 0.8,
    "subfinder_enum": 0.8,
    "amass_enum": 0.8,
    "github_repo_discovery": 0.8,
    "internetdb_lookup": 0.75,
    "securitytrails_history": 0.75,
    "virustotal_subdomain_enum": 0.75,
    "linkfinder_extract": 0.7,
    "fofa_search": 0.7,
    "otx_passive_dns": 0.7,
    "urlscan_search": 0.7,
    "hunter_email_search": 0.7,
    "analyze_email": 0.7,
    "dnsdumpster_lookup": 0.65,
    "gau_urls": 0.6,
    "paramspider_crawl": 0.6,
    "cloudbrute_enum": 0.6,
    "trufflehog_scan": 0.85,
    "js_secret_scan": 0.75,
    "job_search": 0.4,
}

DEFAULT_TRUST = 0.6


def score_confidence(source_tools: list[str]) -> float:
    """Return a 0-1 confidence score for a fact reported by *source_tools*.

    The score starts at the most-trusted contributing source, then each
    additional *distinct* source halves the remaining gap to 1.0 (diminishing
    corroboration). An empty source list falls back to :data:`DEFAULT_TRUST`.
    """
    if not source_tools:
        return DEFAULT_TRUST
    distinct = set(source_tools)
    best = max(SOURCE_TRUST.get(tool, DEFAULT_TRUST) for tool in distinct)
    extra = len(distinct) - 1
    confidence = best + (1.0 - best) * (1.0 - 0.5**extra)
    return round(min(confidence, 1.0), 3)
