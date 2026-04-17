# Strategy — Approach Change

## Objective

Adapt the technical approach when the current strategy is not producing
results — including changing tools, techniques, or angle of attack.

## Inputs

| Field                    | Type         | Description                             |
|--------------------------|--------------|-----------------------------------------|
| `current_approach`       | `dict`       | Current approach (tools, techniques)    |
| `success_rate`           | `float`      | Success rate of the current approach    |
| `blocking_factors`       | `list[dict]` | Factors blocking progress               |
| `available_alternatives` | `list[dict]` | Alternative tools/techniques            |
| `${user_context}`        | `string`     | Operational context (optional)          |

## Outputs

| Field                  | Type         | Description                               |
|------------------------|--------------|-------------------------------------------|
| `new_approach`         | `dict`       | New approach                              |
| `changes`              | `list[dict]` | Changes applied                           |
| `expected_improvement` | `string`     | Expected improvement                      |
| `rollback_plan`        | `string`     | Plan if the new approach also fails       |

## Rules

1. **Triggers for an approach change**:
   - WAF blocking all active tools → switch to passive techniques.
   - Systematic timeouts → switch to lighter/faster tools.
   - False-positive rate > 50% → switch to more precise tools.
   - Target not responding to scanning → pivot to OSINT/API.
2. **Possible changes**:
   - Tool substitution (nuclei → nikto, feroxbuster → dirsearch).
   - Technique change (brute-force → crawling, active → passive).
   - Angle change (web → network, external → OSINT-only).
   - Parameter tuning (rate, timeout, wordlist).
3. **Try the smaller change first** — params before tool, tool before
   technique.
4. **Rollback plan is mandatory** — if the new approach fails, what next?
5. **At most 2 approach changes** per assessment — instability lowers
   quality.

## Quality Criteria

- Change driven by data, not frustration.
- Smaller change attempted before a larger one.
- Rollback plan documented.
- Expected improvement well-founded.

## Template

```
APPROACH CHANGE
===============

Current approach: ${current_approach}
Success rate: ${success_rate}%
Blocking factor: ${blocking_factor}

Proposed change:
| Aspect     | Before          | After             | Reason         |
|------------|-----------------|-------------------|----------------|
| Tool       | nuclei          | nikto             | WAF blocking   |
| Rate       | 10/s            | 2/s               | Rate limit     |
| Technique  | brute-force     | crawling          | 403 on all     |

Expected improvement: [description with rationale]
Rollback: if it fails, [alternative plan]
```
