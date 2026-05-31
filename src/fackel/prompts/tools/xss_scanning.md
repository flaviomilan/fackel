# Tool — XSS & CORS Scanning

## Purpose

Detect Cross-Site Scripting (XSS) and CORS
misconfiguration vulnerabilities in target web applications.

## Tools

| Tool           | Purpose                                          |
|----------------|------------------------------------------------------|
| `dalfox_scan`  | Advanced XSS scanner — reflected, stored, DOM-based|
| `corsy_scan`   | CORS misconfiguration detection                  |

## Usage Rules

1. **dalfox on endpoints with parameters** — extract URLs from GAU/katana
   and feed to dalfox.
2. **corsy on all web hosts** — CORS misconfiguration is common and
   impactful.
3. **paramspider + dalfox** — use paramspider to discover parameters,
   then dalfox to test.
4. **Confirm findings** — XSS requires evidence (payload + response).
5. **DOM XSS** — dalfox tests automatically, but verify sources/sinks.

## Scope Boundaries

- Only authorized endpoints.
- Do not persist payloads in stored XSS (only confirm reflected).
- Rate limit: respect target WAF/rate limiting.
- Do not test on payment forms or sensitive areas without
  explicit authorization.

## Fallback Strategy

| Scenario                 | Action                                     |
|-------------------------|-------------------------------------------|
| WAF blocking payloads   | Try alternative encoding, document WAF    |
| No parameters found     | Use deeper crawling                       |
| dalfox timeout          | Reduce scope to top endpoints              |
| corsy no findings       | Document CORS as properly configured       |

## Output Structure

```json
{
  "tool": "dalfox_scan",
  "target": "https://example.com/search?q=test",
  "data": {
    "findings": [
      {
        "type": "reflected_xss",
        "url": "https://example.com/search?q=<script>alert(1)</script>",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "evidence": "Payload reflected in response body without encoding",
        "severity": "high",
        "waf_bypassed": false
      }
    ],
    "total_findings": 2,
    "endpoints_tested": 45
  }
}
```

## Normalization

- Type standardized: reflected_xss, stored_xss, dom_xss, cors_misconfiguration.
- Payload preserved verbatim.
- Severity: critical (stored XSS w/ auth bypass), high (reflected XSS),
  medium (DOM XSS), low (CORS informational).

## Anomalies

- **Reflected XSS without WAF** → easy to exploit, high priority.
- **CORS with origin: * + credentials** → maximum risk, sensitive data
  accessible cross-origin.
- **Multiple vulnerable parameters** → systemic lack of sanitization.
- **DOM XSS in third-party JS** → supply chain risk.
- **WAF bypass found** → WAF misconfigured, false sense of security.
