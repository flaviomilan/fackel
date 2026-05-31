# Nuclei Tool Contract

## Identity

- **Tool name**: `nuclei_scan`
- **Category**: Vulnerability Scanning / Active
- **Requires approval**: Yes (active scanning tool)

## Purpose

Template-based vulnerability scanner that checks for CVEs,
misconfigurations, exposures, and technology fingerprints.

## Input Contract

| Parameter | Type   | Required | Description                                        |
|-----------|--------|----------|----------------------------------------------------|
| target    | string | yes      | Domain, subdomain, or full URL. **Never a raw IP** |
| severity  | string | no       | Comma-separated: `critical,high,medium,low,info`   |
| tags      | string | no       | Comma-separated template tags (see examples below) |

> **Important**: the parameter is `tags`, not `templates`. Common
> tag values: `cve`, `wordpress`, `joomla`, `drupal`, `graphql`,
> `api`, `misconfig`, `exposure`, `tech`, `default-login`,
> `takeover`, `rce`, `xss`, `sqli`, `lfi`, `ssrf`, `redirect`,
> `nginx`, `apache`, `iis`. Leave empty to use all templates.

## Output Contract

```json
{
  "tool": "nuclei_scan",
  "target": "<target>",
  "status": "ok|error",
  "data": {
    "total": 12,
    "findings": [
      {
        "template_id": "CVE-2024-1234",
        "matcher_name": "cloudflare",
        "name": "WordPress Plugin RCE",
        "severity": "critical",
        "matched_at": "https://example.com/wp-content/plugins/vuln/",
        "type": "http",
        "host": "example.com",
        "ip": "203.0.113.10",
        "tags": ["cve", "wordpress", "rce"],
        "description": "...",
        "extracted_results": ["..."],
        "curl_command": "curl ..."
      }
    ]
  }
}
```

When no findings: `data: {"findings": [], "message": "..."}`.

## Expected Discoveries

- VULNERABILITY for each CVE or misconfiguration
- TECHNOLOGY for detected software

## Failure Modes

- WAF blocking → results may be incomplete, note in findings
- Rate limiting → lower request rate template option
- Timeout → large template sets may timeout on slow targets
