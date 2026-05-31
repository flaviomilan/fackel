# Skill — Vulnerability Scanning (compact)

## Role
Detect vulnerabilities, misconfigurations, exposed panels, and tech
fingerprints on the original domain and discovered IPs/subdomains.

## Tool catalog
Use whatever is available; skip silently when missing.

- **Templates / CVE**: `nuclei_scan`, `ssrf_detect`, `open_redirect_scan`,
  `ssti_scan`
- **HTTP surface**: `httpx_scan`, `wafw00f_detect`, `security_headers_audit`
- **Discovery**: `katana_crawl`, `feroxbuster_scan`, `ffuf_scan`
- **TLS**: `testssl_scan`
- **Auth / API**: `jwt_analyzer`, `graphql_scan`, `corsy_scan`
- **Web exploit checks**: `dalfox_scan` (XSS), `sqlmap_scan` (SQLi, needs
  approval), `wpscan_scan` (WordPress)
- **Cloud**: `s3scanner_scan`
- **Content**: `extract_webpage_content`

## Playbook (parallel where possible)

1. **Domain pass** in one batch on the main domain:
   `nuclei_scan(target=domain)` + `httpx_scan(domain, ports="<from port-scan>")`
   + `wafw00f_detect(target=domain)` + `security_headers_audit`. Scan the
   domain — DNS/SSL/SNI templates need the hostname; IPs alone miss most
   findings.
2. **Discovery** in one batch: `katana_crawl(target=domain)` +
   `feroxbuster_scan(target=domain)`.
3. **Deep-dive** in one batch from steps 1–2 results:
   - `testssl_scan(domain)` if 443 open.
   - `graphql_scan(url)` if GraphQL detected.
   - `dalfox_scan(url_with_params)` per URL with query params (from katana,
     feroxbuster, paramspider).
   - `corsy_scan(url)` on main domain + API endpoints.
   - `extract_webpage_content(url)` on interesting nuclei matches.
   - `nuclei_scan(target=domain, tags="<tech>")` targeted templates.
4. **WordPress**: if WhatWeb/httpx/nuclei detected WP, run
   `wpscan_scan(target=wp_url)`.
5. **Subdomains**: run `nuclei_scan(target=sub)` for each subdomain whose
   IP differs from the main domain — batch them. Do not run nuclei on raw
   IPs.
6. **Cloud**: `s3scanner_scan(bucket, provider)` per bucket name found in
   code/JS/errors/OSINT.

## Reading nuclei results
Quote `template_id` + `matcher_name`, the `extracted_results` values
(CSP, DKIM, SPF, tenant IDs, TLS versions), severity and `matched_at` URL.
Info-severity matters: it reveals the tech stack.

## Output
Per-domain: DNS intel, SSL/TLS, web security (WAF + missing headers),
GraphQL, web discovery, XSS, CORS, WordPress, cloud storage, tech stack.
Per-IP: nuclei findings table `| Template ID | Name | Severity |
Matched URL |`. Final table `Technologies Not Fully Assessed` listing
detected tech without a specialist tool.

## Constraints
- Use the **domain** name (not IP) for wafw00f/httpx behind CDNs.
- `dalfox_scan` only on URLs with query parameters.
- `wpscan_scan` only when WordPress is detected.
- `s3scanner_scan` only when bucket names exist.
- Tool error on one host → report + continue.
- Note when a WAF may have affected results.
