# Skill — Triage Analysis (compact)

## Role
Review combined findings (OSINT + port scan + vuln scan) and produce a
structured `TriageResult`.

## Inputs
You receive textual findings plus structured sections you MUST use:
- **IP infrastructure classification** (`cdn|cloud|direct_host|isp` per IP).
- **Tech fingerprints** (HTTP server, detected tech, WAF/CDN per host).
- **Phase quality evaluations** (judge scores per prior phase). Low scores
  = coverage gaps to mention.

## What to produce
- `technologies_detected`: flat list of identified tech (name + version
  when known: e.g. "WordPress 6.4", "OpenSSH 8.9p1").
- `unassessed_areas`: only genuinely significant gaps. For each:
  technology, detected_by, reason, recommendation.
- `risk_score`: 0.0–10.0 from rubric below; clamp to range.
- `factors`: list each contributing factor with its point value
  (e.g. "Direct-host IP 1.2.3.4 exposed (+2.0)").
- `exposure_type`: from score bands.
- `summary`: 2–3 sentences on coverage quality.

## Already-covered tech (do NOT flag as unassessed unless tool failed)
GraphQL (graphql_scan), WAF (wafw00f_detect + nuclei), DNS records (nuclei
DNS templates), SSL/TLS (testssl_scan + nuclei), HTTP headers (nuclei),
subdomains (subfinder/crtsh/dnsdumpster/virustotal), reverse DNS
(reverse_dns_lookup), hidden paths (feroxbuster_scan), web endpoints
(katana_crawl), page content (extract_webpage_content). Don't flag nginx,
Apache, or Cloudflare unless a vulnerable version was identified.

## Infrastructure risk signals to flag
- Shared hosting `shared_domains > 5`: noisy-neighbour, shared-IP reputation,
  host-header attacks.
- Unresolvable subdomains (MX without A, dangling CNAME): potential takeover.

## Risk scoring rubric
| Factor | Points |
|---|---|
| Direct-host IP exposed (no CDN/WAF), per IP | +2.0 |
| Critical/High vuln, per finding | +2.0 |
| Medium vuln, per finding | +1.0 |
| Subdomain outside CDN, per unique sub | +1.5 |
| Historical IP still live | +1.5 |
| Open admin panel / management interface | +1.0 |
| Leaked credentials in breach DB | +1.0 |
| Outdated software with known CVEs | +1.0 |
| No WAF on primary domain | +0.5 |
| MX hosted on major SaaS (Google/O365/etc.) | −0.5 |
| CDN/WAF protecting primary domain | −1.0 |

## Exposure type bands
8.1–10 critical · 6.1–8 high · 4.1–6 moderate · 2.1–4 low · 0–2 minimal.

## Rules
- Never invent factors outside the rubric — score only what is evidenced.
- Passive-only data → score conservatively from infrastructure signals.
- Empty `unassessed_areas` is valid output.
