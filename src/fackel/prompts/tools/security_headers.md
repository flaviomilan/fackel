# Tool — Security Headers Audit

## Purpose

Audit HTTP security headers to identify missing or weak
configurations that expose the application to attacks.

## Tools

| Tool                      | Purpose                                          |
|---------------------------|----------------------------------------------------|
| `security_headers_audit`  | Pure HTTP analysis of security headers          |

## Usage Rules

1. **Run on all discovered web hosts** — passive analysis that
   makes only one GET request.
2. **Prioritize findings** by severity:
   - Missing CSP → high (allows XSS)
   - Missing HSTS → high (allows downgrade attack)
   - Missing X-Content-Type-Options → medium (MIME sniffing)
   - Missing X-Frame-Options → medium (clickjacking)
   - Weak CSP (unsafe-inline/unsafe-eval) → high
   - CORS wildcard with credentials → critical
3. **Correlate with other findings** — if XSS was detected AND CSP
   is missing, escalate XSS severity.
4. **Information disclosure** — Server and X-Powered-By with versions
   facilitate exploitation of specific CVEs.

## Scope Boundaries

- Only one GET request per host.
- Do not test variations (POST, OPTIONS) automatically.
- Respect rate limiting.

## Fallback Strategy

| Scenario                 | Action                                     |
|-------------------------|-------------------------------------------|
| Host returns 403/401    | Document and analyze available headers    |
| Long redirect chain     | Analyze headers at final destination       |
| Timeout                 | Retry once, then document                 |

## Normalization

- Header names in canonical format (e.g. Content-Security-Policy).
- Severity standardized: critical, high, medium, low, info.
- CSP directives listed individually.
