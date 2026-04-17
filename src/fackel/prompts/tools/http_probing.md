# Tool — HTTP Probing

## Purpose

Identify web technologies, server headers, WAF/CDN, redirects,
and status codes for each host on the attack surface.

## Tools

| Tool            | Purpose                                          |
|-----------------|------------------------------------------------------|
| `httpx_scan`    | Fast HTTP probing — tech, titles, redirects     |
| `whatweb_scan`  | Deep fingerprint — CMS, frameworks, libs, versions |
| `wafw00f_detect`| WAF/IPS identification                           |

## Usage Rules

1. **httpx is mandatory** — run on every domain/IP with web port.
2. **whatweb complements httpx** — detects CMS versions, jQuery, analytics
   that httpx does not capture. Run on main hosts.
3. **wafw00f** — run on main domain to identify WAF.
   Use `check_all: true` when you need to enumerate ALL WAFs in
   stack (CDN + WAF + bot manager); default is stop at first
   match for speed.
4. **Parallelism** — httpx, whatweb, and wafw00f are independent, execute
   in batch.

## Scope Boundaries

- Only authorized hosts and known ports (80, 443, 8080, 8443).
- Do not follow redirects to out-of-scope domains.
- Respect robots.txt as indicator (document, do not block).

## Fallback Strategy

| Scenario             | Action                                            |
|----------------------|-------------------------------------------------|
| Connection refused   | Host does not serve HTTP — document                |
| TLS error            | Try HTTP-only, document TLS error           |
| WAF blocking         | Document WAF, note impact on results    |
| Timeout              | Try with larger timeout, document if persists|

## Output Structure

```json
{
  "tool": "httpx_scan",
  "target": "<host>",
  "data": {
    "url": "https://example.com",
    "status_code": 200,
    "title": "Site Title",
    "server": "nginx/1.24",
    "technologies": ["WordPress 6.4", "PHP 8.2"],
    "cdn": "cloudflare",
    "waf": "cloudflare",
    "redirect_chain": ["http://example.com → https://example.com"]
  }
}
```

## Normalization

- URLs normalized (trailing slash consistent).
- Server headers preserved verbatim (case-sensitive).
- Technologies with version when available.

## Anomalies

- **Redirect to external domain** → possible phishing or migration.
- **Server header missing** → hardening or reverse proxy.
- **Multiple WAFs** → complex configuration, potential bypasses.
- **HTTP 403 on everything** → aggressive WAF or IP blocked.
- **Unexpected title** (e.g. "Parking page") → domain may have expired.
