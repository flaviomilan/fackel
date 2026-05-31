# Tool — Vulnerability Scanning

## Purpose

Identify known vulnerabilities in target services, web applications, and
configurations using automated scanners.

## Tools

| Tool                      | Purpose                                                 |
|---------------------------|-----------------------------------------------------------|
| `nuclei_scan`             | Vulnerability templates (CVEs, misconfigs)          |
| `testssl_scan`            | TLS/SSL configuration analysis                           |
| `security_headers_audit`  | HTTP security headers audit (CSP, HSTS, etc.) |
| `sqlmap_scan`             | Automated SQL Injection detection                    |
| `ssrf_detect`             | Server-Side Request Forgery detection via nuclei        |
| `open_redirect_scan`      | Open Redirect detection via nuclei                      |
| `ssti_scan`               | Server-Side Template Injection detection via nuclei     |
| `jwt_analyzer`            | JWT token security analysis                        |

## Usage Rules

1. **nuclei is primary scanner** — run with templates relevant
   to detected technologies.
2. **Selective templates** — use tags based on fingerprinting:
   - WordPress detected → `-tags wordpress`
   - Apache → `-tags apache`
   - GraphQL detected → `-tags graphql`
   - Generic → `-tags cve,misconfig,exposure`
3. **Specialized scans via nuclei** — for specific coverage:
   - SQLi suspect → `ssrf_detect` or `nuclei_scan -tags sqli`
   - Redirect params detected → `open_redirect_scan`
   - Template engine detected → `ssti_scan -tags ssti`
   - SSRF suspect → `ssrf_detect -tags ssrf`
4. **testssl on HTTPS hosts** — verify cipher suites, protocols,
   certificates, TLS vulnerabilities.
5. **security_headers_audit on all web hosts** — pure HTTP analysis
   without external binary dependency.
6. **sqlmap on endpoints with parameters** — use `--batch --level=1
   --risk=1` for safe automation. Active tool: requires approval.
7. **jwt_analyzer when JWT detected** — decode, check alg:none,
   expired claims, weak secrets. Passive tool without binaries.
8. **Categorize severity** — critical, high, medium, low, info.
9. **Mandatory evidence** — each finding must have proof (request/response).

## Scope Boundaries

- Only authorized hosts.
- Do not use exploit/RCE templates without explicit authorization.
- Rate limit: maximum 10 requests/second per host.
- Do not run extensive fuzzing without justification.
- sqlmap **only** with `--batch` and `--level ≤ 2` in automated mode.

## Fallback Strategy

| Scenario                   | Action                                     |
|----------------------------|--------------------------------------------|
| WAF blocking nuclei        | Reduce rate, document WAF                 |
| Templates timeout          | Retry with larger timeout or specific tags |
| Many findings (>100)       | Filter by severity >= medium              |
| testssl timeout            | Try with checks='protocols,vulnerabilities' |
| testssl no result          | Retry with fast=False and openssl_timeout=20  |
| nuclei empty               | Retry with tags of detected technology    |
| Likely false positive      | Mark as "needs verification"              |

## Output Structure

```json
{
  "tool": "nuclei_scan",
  "target": "https://example.com",
  "status": "ok|error",
  "data": {
    "total": 12,
    "findings": [
      {
        "template_id": "CVE-2024-1234",
        "matcher_name": "cloudflare",
        "name": "WordPress Plugin RCE",
        "severity": "critical",
        "matched_at": "https://example.com/wp-content/plugins/vuln/readme.txt",
        "type": "http",
        "host": "example.com",
        "ip": "203.0.113.10",
        "tags": ["cve", "wordpress", "rce"],
        "description": "...",
        "extracted_results": ["v2.3.1"],
        "curl_command": "curl -X GET https://..."
      }
    ]
  }
}
```

- No findings: `data: {"findings": [], "message": "no vulnerabilities found"}`.
- `extracted_results` and `curl_command` only appear when template produces them —
  do not assume presence before reading.
- No fields `url`, `evidence`, or `by_severity` in envelope —
  derive severity count from `findings` in agent.

## Normalization

- CVE IDs in CVE-YYYY-NNNNN format.
- Severity standardized: critical, high, medium, low, info.
- Full URLs (not relative).
- Tags preserved for cross-reference.

## Anomalies

- **Confirmed critical CVE** → maximum priority in report.
- **TLS 1.0/1.1 enabled** → compliance issue (PCI DSS).
- **Self-signed cert in production** → trust issue, potential MitM.
- **Weak cipher suites** (RC4, DES, NULL) → interception risk.
- **Multiple vulns in same component** → system not patched.
- **Info disclosure** (stack traces, version headers) → facilitates exploitation.
