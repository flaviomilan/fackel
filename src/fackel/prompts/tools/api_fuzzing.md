# Tool — API Fuzzing & Directory Discovery

## Purpose

Discover hidden directories, sensitive files, API endpoints,
and virtual hosts via brute-force with wordlists.

## Tools

| Tool              | Purpose                                            |
|-------------------|----------------------------------------------------|
| `ffuf_scan`       | Fast fuzzing of directories/files/APIs             |
| `feroxbuster_scan`| Recursive directory brute-force                    |

## When to Use Each Tool

- **`ffuf_scan` first** when the goal is:
  - API endpoint discovery (supports positional FUZZ keyword)
  - Test multiple HTTP methods (GET, POST, PUT, DELETE, OPTIONS)
  - Authenticated endpoints (supports custom headers)
  - Virtual host discovery (header `Host: FUZZ.example.com`)
- **`feroxbuster_scan` first** when the goal is:
  - Recursive directory tree with depth (depth 1-4)
  - General content discovery (backup files, admin panels, configs)
  - Extensive brute-force with automatic extensions
- **Mutual fallback** — if one fails (dependency, timeout, WAF), use
  the other immediately. They are interchangeable for basic discovery.

## Usage Rules

1. **ffuf for API endpoint discovery** — use with API wordlists:
   - `https://api.example.com/v1/FUZZ` for REST endpoints
   - `https://example.com/FUZZ` for directories
2. **Test multiple HTTP methods on APIs** — GET for reading,
   POST/PUT for writing, DELETE for removal, OPTIONS for CORS.
   Status 405 (Method Not Allowed) confirms valid endpoint.
3. **Headers for authenticated endpoints** (only `ffuf_scan`):
   - `Authorization: Bearer <token>` for REST APIs
   - `Cookie: session=<value>` for web applications
   - Test authenticated endpoints when tokens are available.
4. **Virtual host discovery** with ffuf:
   - URL: `https://<IP>/` with header `Host: FUZZ.example.com`
   - Subdomain wordlist (not directory wordlist)
   - Filter by `filter_size` — nonexistent vhosts return same size.
5. **Relevant extensions** — `.php,.html,.js,.json,.xml,.txt,.bak,.conf`
   based on detected technology.
6. **Selective match codes** — default: 200,204,301,302,307,401,403,405.
   - 401/403 indicate protected but existing resources.
   - 405 indicates valid endpoint but wrong method.
7. **False positive filtering** — iterative workflow:
   - Initial scan without size filters.
   - If many results with same size/words → custom 404 page.
   - Re-scan with `filter_size` or `filter_words` to exclude pattern.
   - Example: 200 results all with length 1234 → `filter_size: "1234"`.
8. **Adaptive threads** — default 20 for normal targets.
   - Reduce to 5-10 under WAF or rate limiting.
   - Increase up to 50 only on robust targets without protection.
9. **Correlate with detected technology** — WordPress → wp-admin,
   wp-content; Laravel → .env, artisan; etc.
10. **Status-code allowlist/denylist** — `match_codes` keeps only the
    codes you list (e.g. `"200,301"`); `filter_codes` discards them
    (e.g. `"404"`). Combine to suppress noisy 404 walls quickly.
11. **Recursion (ffuf)** — set `recursion: true` with
    `recursion_depth` (1-3) when you need to walk discovered
    directories without launching feroxbuster. Higher depths cost
    quadratic requests; never exceed 3 without justification.
12. **feroxbuster status filter** — pass `filter_status="404,403"`
    to drop boring responses when the target floods them.

## Scope Boundaries

- Only authorized hosts.
- Threads: default 20, maximum 50. Reduce under WAF.
- Standard wordlists (SecLists common.txt or dirb/common.txt).
- Do not run recursive fuzzing without justification.
- Respect rate limiting and WAF.

## Fallback Strategy

| Scenario                   | Action                                     |
|----------------------------|--------------------------------------------|
| WAF blocking requests      | Reduce threads to 5-10, document WAF       |
| Wordlist not found         | Both use bundled wordlist automatically    |
| feroxbuster failed         | Use ffuf_scan as alternative               |
| ffuf failed                | Use feroxbuster_scan as alternative        |
| Many results (>500)        | Filter by status 200 or filter_size        |
| Custom 404 detected        | Re-scan with filter_size of standard size  |
| ffuf/feroxbuster timeout   | Reduce wordlist or extensions              |

> **IMPORTANT**: ffuf and feroxbuster are complementary and interchangeable.
> If one fails (dependency, timeout, error), use the other immediately.
> Both now include automatic wordlist — should not fail due to wordlist.

## Output Structure

### ffuf_scan

```json
{
  "tool": "ffuf_scan",
  "target": "https://example.com/FUZZ",
  "status": "ok",
  "data": {
    "total": 2,
    "findings": [
      {
        "url": "https://example.com/admin",
        "input": "admin",
        "status": 200,
        "length": 1234,
        "words": 100,
        "lines": 50,
        "content_type": "text/html",
        "redirect_location": ""
      },
      {
        "url": "https://example.com/api",
        "input": "api",
        "status": 301,
        "length": 0,
        "words": 0,
        "lines": 0,
        "content_type": "",
        "redirect_location": "https://example.com/api/"
      }
    ]
  }
}
```

### feroxbuster_scan

```json
{
  "tool": "feroxbuster_scan",
  "target": "https://example.com",
  "status": "ok",
  "data": {
    "total": 2,
    "results": [
      {
        "url": "https://example.com/admin",
        "status": 200,
        "length": 1234,
        "mime": "text/html",
        "words": 100,
        "lines": 50
      },
      {
        "url": "https://example.com/.env",
        "status": 200,
        "length": 56,
        "mime": "text/plain",
        "words": 10,
        "lines": 5
      }
    ]
  }
}
```

### Severity Classification

- **high**: admin panels, config files (.env, .htaccess), backup files (.sql, .bak)
- **medium**: hidden directories, protected endpoints (401/403)
- **info**: common resources, redirects
