# Tool — SSRF Scanning

## Purpose

Detect Server-Side Request Forgery (SSRF) vulnerabilities that
allow an attacker to make the target server send requests to
internal or arbitrary resources.

## Tools

| Tool                | Purpose                                         |
|---------------------|---------------------------------------------------|
| `ssrf_detect`       | Detection via nuclei templates (ssrf, oast tags)   |
| `nuclei_scan`       | With `-tags ssrf` for additional coverage         |
| `open_redirect_scan` | Open redirect → can escalate to SSRF       |
| `ssti_scan`         | SSTI → frequently chained with SSRF            |

## Usage Rules

1. **ssrf_detect on endpoints accepting URLs as parameters** —
   parameters like url=, redirect=, callback=, next=, file=, path=.
2. **Blind SSRF via OOB** — nuclei uses OAST callbacks to detect
   blind SSRF (server makes request to controlled domain).
3. **Correlate with open redirect** — open redirect can be
   chained to bypass SSRF whitelists.
4. **Check cloud metadata** — SSRF to 169.254.169.254 in
   cloud environments (AWS, GCP, Azure) is critical.

## Scope Boundaries

- Do not attempt manual access to internal resources.
- Detection only — do not exfiltrate data via SSRF.
- Respect target rate limiting.

## Fallback Strategy

| Scenario                   | Action                                     |
|----------------------------|--------------------------------------------|
| WAF blocking callbacks     | Document WAF, try alternative encoding    |
| No URL parameters          | Use crawling to discover endpoints         |
| nuclei no findings         | Document as "not detectable by auto scan"  |

## Normalization

- Type: blind_ssrf, full_read_ssrf, partial_ssrf.
- Severity: critical (full read/cloud metadata), high (blind SSRF), medium (partial).
- Template ID preserved for reference.
