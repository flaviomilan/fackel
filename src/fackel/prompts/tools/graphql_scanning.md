# Tool — GraphQL Scanning

## Purpose

Identify GraphQL endpoints and test for common vulnerabilities:
enabled introspection, query complexity attacks, information disclosure.

## Tools

| Tool                 | Purpose                                       |
|----------------------|-------------------------------------------------|
| `graphql_scan`       | Endpoint detection + introspection + vulns    |

## Usage Rules

1. **Detect endpoint first** — test common paths (/graphql,
   /api/graphql, /v1/graphql, /query).
2. **Introspection query** — if enabled, extract full schema.
3. **Test vulnerabilities**:
   - Query complexity/depth limit
   - Batching attacks
   - Field suggestion (information disclosure)
   - Authorization bypass (access mutations without auth)
4. **Preserve schema** — schema introspection is valuable evidence.

## Scope Boundaries

- Only authorized GraphQL endpoints.
- Do not run destructive mutations.
- Introspection queries are passive (safe to run).

## Fallback Strategy

| Scenario                     | Action                                    |
|------------------------------|--------------------------------------------|
| Introspection disabled       | Try field suggestion, document             |
| Endpoint not found           | Test alternative paths                     |
| Auth required                | Document, test with/without auth           |
| Rate limited                 | Reduce query frequency                     |

## Output Structure

```json
{
  "tool": "graphql_scan",
  "target": "https://example.com/graphql",
  "data": {
    "endpoint": "/graphql",
    "introspection_enabled": true,
    "types_count": 45,
    "queries_count": 12,
    "mutations_count": 8,
    "vulnerabilities": [
      {
        "type": "introspection_enabled",
        "severity": "medium",
        "evidence": "Full schema exposed"
      }
    ]
  }
}
```

## Normalization

- Endpoint as relative path.
- Vulnerability types standardized.
- Severity: critical, high, medium, low, info.

## Anomalies

- **Introspection in production** → information disclosure (medium+).
- **Mutations without auth** → potential data manipulation (critical).
- **No depth limit** → DoS via nested queries (high).
- **Field suggestions reveal schema** → info disclosure even without introspection.
