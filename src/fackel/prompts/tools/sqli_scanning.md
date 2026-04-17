# Tool — SQL Injection Scanning

## Purpose

Detect SQL Injection vulnerabilities in URL parameters,
POST forms, cookies, and HTTP headers.

## Tools

| Tool          | Purpose                                              |
|---------------|--------------------------------------------------------|
| `sqlmap_scan` | Automated SQLi detection (boolean, time, error, UNION) |
| `nuclei_scan` | Specific SQLi templates with `-tags sqli`         |

## Usage Rules

1. **sqlmap only on endpoints with parameters** — URLs without parameters
   do not produce useful results.
2. **Batch mode mandatory** — `--batch` is always-on for automation.
3. **Conservative level and risk**:
   - Level 1 (default): GET/POST params
   - Level 2: includes Cookie header
   - Never use level > 3 or risk > 2 without explicit authorization.
4. **Restrict `technique`** — default `BEUSTQ` covers everything. To
   reduce noise or time, restrict to a subset, e.g.
   `technique="BEU"` (boolean + error + UNION) on slow targets.
5. **`random_agent: true`** — rotate User-Agent on each request,
   useful for WAFs that whitelist sqlmap's default agent.
6. **nuclei as complement** — use `-tags sqli` for coverage of
   known SQLi CVEs in CMSs and frameworks.
7. **Confirm findings** — SQLi requires evidence (payload + response).
8. **Do not extract data** — only detect, do not use `--dump`.

## Scope Boundaries

- Only authorized endpoints.
- NEVER use `--os-shell`, `--os-cmd`, `--dump` or `--dump-all`.
- Rate limit: respect target WAF/rate limiting.
- `--flush-session` to avoid cache from previous sessions.

## Fallback Strategy

| Scenario                   | Action                                     |
|----------------------------|--------------------------------------------|
| WAF blocking payloads      | Document WAF, try `--tamper=space2comment` |
| sqlmap timeout             | Reduce level, retry with larger timeout    |
| No parameters found        | Use crawling + paramspider first           |
| False positive             | Mark as "needs manual verification"        |

## Normalization

- Technique standardized: boolean-based blind, time-based blind,
  error-based, UNION query, stacked queries.
- Severity: critical (UNION/stacked), high (error-based/boolean), medium (time-based).
- Parameter name preserved.
  error-based, UNION query, stacked queries.
- Severity: critical (UNION/stacked), high (error-based/boolean), medium (time-based).
- Parameter name preservado.
