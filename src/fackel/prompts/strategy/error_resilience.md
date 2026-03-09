# Strategy — Error Resilience & Tool Fallback

## Principle

A professional penetration tester does NOT stop when a tool fails.
They diagnose the failure, adapt, and try alternative approaches.
You must do the same.

## Error Classification

| Error Type | Examples | Action |
|------------|----------|--------|
| **Missing dependency** | "No module named X", "wordlist not found" | Use alternative tool or different parameters |
| **Timeout** | "command timed out after N seconds" | Retry with `--fast`, smaller scope, or specific checks |
| **Authentication/API** | "API key not configured", "insufficient credits" | Skip tool, note in report, continue with alternatives |
| **Target unreachable** | "connection refused", "no route to host" | Verify target, try different port/protocol |
| **WAF blocking** | "403 Forbidden on all requests", "rate limited" | Reduce threads/rate, use different User-Agent, document WAF |
| **Empty output** | Tool ran successfully but returned nothing | Try different parameters, tags, or wordlists |

## Tool Fallback Chains

When a tool fails, try the next tool in the chain:

| Primary Tool | Fallback | Notes |
|-------------|----------|-------|
| `feroxbuster_scan` | `ffuf_scan` | Both do directory brute-force; different engines |
| `ffuf_scan` | `feroxbuster_scan` | Reverse fallback |
| `testssl_scan` (full) | `testssl_scan(checks='protocols,vulnerabilities')` | Targeted checks are faster |
| `testssl_scan` (timeout) | `nuclei_scan(tags='ssl')` | Nuclei SSL templates as backup |
| `linkfinder_extract` | `katana_crawl` + `gau_urls` | Crawling + archives find JS endpoints too |
| `nuclei_scan` (empty) | `nuclei_scan(tags='<detected_tech>')` | Targeted templates yield more results |
| `wafw00f_detect` (empty) | Check `httpx_scan` CDN/server headers | httpx often detects WAF via headers |
| `graphql_scan` (error) | `nuclei_scan(tags='graphql')` | Nuclei has GraphQL templates |

## Retry Strategies

1. **Timeout failures**: retry with smaller scope or `--fast` mode.
2. **Empty results on domain**: try with specific nuclei tags matching
   detected technologies instead of a broad scan.
3. **Brute-force tool failed**: use the other brute-force tool (ffuf ↔ feroxbuster).
4. **TLS scan produced nothing**: retry with specific checks
   (`protocols`, `vulnerabilities`) instead of full scan.
5. **Multiple tools failed on same target**: document as potential WAF
   interference and try with rate limiting or stealth options.

## Mandatory Reporting

When a tool fails, you MUST:
1. Report the failure and reason in your summary.
2. State which fallback you attempted (or why none was available).
3. Note the gap — what intelligence was NOT gathered due to the failure.

Do NOT silently skip failed tools. Every failure is information.
