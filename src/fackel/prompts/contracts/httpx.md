# httpx Tool Contract

## Identity

- **Tool name**: `httpx_scan`
- **Category**: Reconnaissance / Passive-Active Boundary
- **Requires approval**: No (HTTP probing only)

## Purpose

HTTP probing for technology fingerprinting, server headers, WAF detection,
redirect analysis, and status code enumeration.

## Input Contract

| Parameter | Type   | Required | Description                        |
|-----------|--------|----------|------------------------------------|
| domain    | string | yes      | Domain or IP to probe              |
| ports     | string | no       | Ports to check (default: 80,443)   |

## Output Contract

```json
{
  "tool": "httpx_scan",
  "target": "<domain>",
  "status": "success|error",
  "data": {
    "results": [
      {
        "url": "https://example.com",
        "status_code": 200,
        "title": "Example Site",
        "server": "nginx/1.24",
        "technologies": ["WordPress", "PHP"],
        "cdn": "cloudflare",
        "waf": "cloudflare"
      }
    ]
  }
}
```

## Expected Discoveries

- TECHNOLOGY for each detected software component
- DNS_RECORD for redirect chains

## Failure Modes

- Connection refused → target not serving HTTP
- Timeout → slow response, retry with longer timeout
- TLS errors → note and continue with HTTP-only
