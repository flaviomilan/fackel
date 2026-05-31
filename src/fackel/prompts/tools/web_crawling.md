# Tool — Web Crawling & URL Discovery

## Purpose

Discover URLs, endpoints, parameters, and hidden paths in target
web applications to maximize attack surface coverage.

## Tools

| Tool                | Purpose                                        |
|---------------------|--------------------------------------------------|
| `katana_crawl`      | Headless crawler — SPA support, JS rendering    |
| `feroxbuster_scan`  | Directory/file brute-force                      |
| `gau_urls`          | Historical URLs (Wayback Machine, CT, Common Crawl)|
| `paramspider_crawl` | Parameter discovery in URLs                     |

## Usage Rules

1. **GAU first** — collect historical URLs (fast, passive).
2. **katana in parallel with GAU** — active crawling with JS rendering.
3. **feroxbuster selective** — brute-force on main hosts with
   targeted wordlist (detected technology).
4. **paramspider on collected URLs** — extract parameters for XSS/SQLi.
   Use `exclude` to filter redundant static extensions
   (e.g. `exclude="png,jpg,css,woff"`) and cut heavy noise.
5. **Deduplicate** — URLs from multiple sources will have significant overlap.

## Scope Boundaries

- Only hosts within authorized scope.
- Maximum crawling depth: 5 levels.
- Do not follow links to third parties (ads, analytics, CDNs).
- feroxbuster: 5k max wordlist per host (not full dirbuster).
- Exclude static extensions: .css, .png, .jpg, .gif, .svg, .woff.

## Fallback Strategy

| Scenario                    | Action                                     |
|-----------------------------|------------------------------------------|
| WAF blocking crawler        | Reduce rate, generic User-Agent            |
| katana timeout on SPA       | Increase JS timeout, reduce depth          |
| feroxbuster many 403s       | Stop, WAF active — document                |
| GAU no results              | New domain — focus on active crawling       |
| Many URLs (>5000)           | Filter by unique paths, remove params      |

## Output Structure

```json
{
  "tool": "katana_crawl",
  "target": "https://example.com",
  "data": {
    "urls": [
      "https://example.com/api/v1/users",
      "https://example.com/admin/login",
      "https://example.com/graphql"
    ],
    "total_urls": 342,
    "unique_paths": 89,
    "forms_found": 5,
    "js_files": 23,
    "api_endpoints": 15
  }
}
```

## Normalization

- URLs normalized (consistent encoding).
- Remove fragments (#).
- Deduplicate by path (ignore query params for path count).
- Classify: page, api, form, asset, admin, auth.

## Anomalies

- **Accessible /admin endpoint** → verify authentication.
- **GraphQL endpoint** → test introspection query.
- **Unauthenticated APIs** → test direct access.
- **URLs in Wayback but 404 now** → possible content removal
  (historical info leak).
- **Backup directories** (.bak, .old, .tar.gz) → data exposure.
- **Parameters with sequential ID pattern** → IDOR potential.
