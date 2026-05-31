# httpx Tool Contract

## Identity

- **Tool name**: `httpx_scan`
- **Category**: Reconnaissance / Passive-Active Boundary
- **Requires approval**: No (HTTP probing only)

## Purpose

HTTP probing for technology fingerprinting, server headers, WAF detection,
redirect analysis, and status code enumeration.

## Input Contract

| Parameter        | Type | Required | Description                                                  |
|------------------|------|----------|--------------------------------------------------------------|
| domain           | str  | yes      | IP, domain, or full URL to probe                             |
| ports            | str  | no       | Comma-separated ports (e.g. `80,443,8080`); empty = defaults |
| tech_detect      | bool | no       | Technology fingerprinting (default `true`)                   |
| follow_redirects | bool | no       | Follow HTTP redirects (default `true`)                       |
| status_code      | bool | no       | Include status codes in output (default `true`)              |
| title            | bool | no       | Include HTML titles (default `true`)                         |

## Output Contract

```json
{
  "tool": "httpx_scan",
  "target": "<domain>",
  "status": "ok|error",
  "data": {
    "results": [
      {
        "url": "https://example.com",
        "status_code": 200,
        "title": "Example Site",
        "webserver": "nginx/1.24",
        "tech": ["WordPress", "PHP"],
        "cdn": "cloudflare"
      }
    ]
  }
}
```

> Field set inside each result depends on httpx version and the
> flags passed; the LLM should treat unknown keys as informational
> and never assume a field exists before reading it.

## Expected Discoveries

- TECHNOLOGY for each detected software component
- DNS_RECORD for redirect chains

## Failure Modes

- Connection refused → target not serving HTTP
- Timeout → slow response, retry with longer timeout
- TLS errors → note and continue with HTTP-only
