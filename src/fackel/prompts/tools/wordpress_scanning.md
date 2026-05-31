# Tool — WordPress Scanning

## Purpose

Identify WordPress-specific vulnerabilities: outdated plugins,
vulnerable themes, user enumeration, insecure configurations.

## Tools

| Tool             | Purpose                                        |
|------------------|--------------------------------------------------|
| `wpscan_scan`    | Specialized WordPress scanner — plugins, themes, users |

## Usage Rules

1. **Run only when WordPress detected** — confirm via
   fingerprinting (whatweb/httpx) before running.
2. **Complete enumeration**: plugins (-e ap), themes (-e at), users (-e u).
3. **Plugin versions are critical** — direct match with CVE databases.
4. **WPScan API token** — if available, use for updated vulnerability
   data from WPVulnDB.
5. **Document EVERYTHING** — even plugins without known CVE are surface.

## Scope Boundaries

- Only WordPress sites in scope.
- Do not attempt password brute-force.
- Do not exploit found vulnerabilities.
- Appropriate rate limiting to not take down site.

## Fallback Strategy

| Scenario                   | Action                                     |
|----------------------------|--------------------------------------------|
| WAF blocking WPScan        | Stealth mode (--random-user-agent)        |
| No API token               | Run without — less CVE data               |
| Very customized WordPress  | Enumerate manually via /wp-content/       |
| Timeout                    | Reduce scope to plugins + version only    |

## Output Structure

```json
{
  "tool": "wpscan_scan",
  "target": "https://example.com",
  "data": {
    "wordpress_version": "6.4.2",
    "plugins": [
      {
        "name": "contact-form-7",
        "version": "5.8",
        "vulnerabilities": [],
        "outdated": false
      },
      {
        "name": "elementor",
        "version": "3.18",
        "vulnerabilities": ["CVE-2024-XXXX"],
        "outdated": true
      }
    ],
    "themes": [{"name": "twentytwentyfour", "version": "1.0"}],
    "users": ["admin", "editor1"],
    "total_plugins": 12,
    "vulnerable_plugins": 2
  }
}
```

## Normalization

- Plugin/theme names in slug format (lowercase, hyphens).
- CVEs in standard format.
- Versions in semver.

## Anomalies

- **Plugin with known CVE** → high priority, especially RCE/SQLi.
- **Outdated WordPress version** → multiple potential CVEs.
- **User "admin" exists** → common brute-force target.
- **XML-RPC enabled** → brute-force amplification.
- **Debug mode active** → information disclosure (wp-config.php).
