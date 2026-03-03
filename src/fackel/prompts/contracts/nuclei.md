# Nuclei Tool Contract

## Identity

- **Tool name**: `nuclei_scan`
- **Category**: Vulnerability Scanning / Active
- **Requires approval**: Yes (active scanning tool)

## Purpose

Template-based vulnerability scanner that checks for CVEs,
misconfigurations, exposures, and technology fingerprints.

## Input Contract

| Parameter | Type   | Required | Description                          |
|-----------|--------|----------|--------------------------------------|
| target    | string | yes      | URL or host to scan                  |
| templates | string | no       | Specific template category/ID        |
| severity  | string | no       | Filter by severity (critical,high)   |

## Output Contract

```json
{
  "tool": "nuclei_scan",
  "target": "<target>",
  "status": "success|error",
  "data": {
    "findings": [
      {
        "template_id": "cve-2024-xxxx",
        "severity": "high",
        "matched_url": "https://example.com/path",
        "extracted_results": []
      }
    ]
  }
}
```

## Expected Discoveries

- VULNERABILITY for each CVE or misconfiguration
- TECHNOLOGY for detected software

## Failure Modes

- WAF blocking → results may be incomplete, note in findings
- Rate limiting → lower request rate template option
- Timeout → large template sets may timeout on slow targets
