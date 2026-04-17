# Orchestrator — Surface Exhaustion

## Objective

Assess whether the target's attack surface has been sufficiently explored,
identifying areas with inadequate coverage that need further investigation.

## Inputs

| Field                | Type         | Description                               |
|----------------------|--------------|-------------------------------------------|
| `scope`              | `dict`       | Total scope (hosts, domains, IPs)         |
| `tools_executed`     | `dict`       | Tools executed per target                 |
| `findings_coverage`  | `dict`       | Findings coverage per category            |
| `expected_coverage`  | `dict`       | Minimum expected coverage                 |
| `${user_context}`    | `string`     | Operational context (optional)            |

## Outputs

| Field                | Type         | Description                               |
|----------------------|--------------|-------------------------------------------|
| `exhaustion_score`   | `float`      | Exhaustion score (0-100%)                 |
| `uncovered_areas`    | `list[dict]` | Areas with insufficient coverage          |
| `recommended_tools`  | `list[dict]` | Tools recommended to close the gaps       |
| `sufficient`         | `bool`       | Whether coverage is sufficient to report  |

## Rules

1. **Coverage categories**:
   - Subdomains: covered when 3+ sources consulted
   - Ports: covered when naabu + nmap executed
   - Vulns: covered when nuclei + tech-specific scanner executed
   - OSINT: covered when APIs + breach + WHOIS executed
   - Web: covered when crawling + fingerprinting + XSS executed
2. **Minimum score to report: 70%** — below that, continue investigating.
3. **Critical categories** (subdomains, ports, vulns) need coverage >= 80%.
4. **Informational categories** (OSINT, breach) accept 50% coverage.
5. **Do not mark as covered** if every tool in the category failed.

## Quality Criteria

- Score reflects real coverage, not the number of tools executed.
- Uncovered areas come with a specific recommendation.
- Distinguish "not covered" from "covered with no findings" (a valid result).

## Template

```
SURFACE EXHAUSTION
==================

Coverage per category:
| Category      | Score | Status    | Gap                  |
|---------------|-------|-----------|----------------------|
| Subdomains    | 90%   | OK        | —                    |
| Ports         | 85%   | OK        | —                    |
| Vulns         | 60%   | GAP       | Missing testssl      |
| OSINT         | 70%   | OK        | —                    |
| Web           | 45%   | GAP       | Missing XSS scan     |

Overall score: [weighted average]%
Sufficient to report: [yes/no]

Recommended actions for gaps:
1. [category] → run [tool] (estimate: +[x]% coverage)
```
