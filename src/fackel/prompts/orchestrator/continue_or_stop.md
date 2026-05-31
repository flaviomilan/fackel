# Orchestrator — Continue or Stop

## Objective

Decide whether the pipeline should keep running tools or stop because
sufficient coverage has been reached, the budget is exhausted, or returns
are diminishing.

## Inputs

| Field                | Type         | Description                               |
|----------------------|--------------|-------------------------------------------|
| `iteration`          | `int`        | Current iteration number                  |
| `findings_count`     | `int`        | Total findings collected                  |
| `new_findings_delta` | `int`        | New findings in the last iteration        |
| `coverage`           | `dict`       | Coverage per category                     |
| `budget_remaining`   | `dict`       | Remaining budget                          |
| `unresolved_gaps`    | `list[dict]` | Gaps still open                           |
| `${user_context}`    | `string`     | Operational context (optional)            |

## Outputs

| Field                | Type         | Description                               |
|----------------------|--------------|-------------------------------------------|
| `decision`           | `string`     | "continue" or "stop"                      |
| `reason`             | `string`     | Justification for the decision            |
| `remaining_value`    | `float`      | Estimated value of continuing (0-1)       |

## Rules

1. **Stop when**:
   - 3 iterations with no significant new findings (diminishing returns).
   - Budget exhausted (0 calls remaining).
   - Coverage >= 90% across all categories.
   - All hypotheses tested.
2. **Continue when**:
   - Critical vulns found that require investigation.
   - Significant gaps in important categories.
   - New targets discovered but not yet investigated.
   - Budget available and ROI positive.
3. **Never stop if**:
   - A critical vuln is confirmed without complete evidence.
   - The primary scope has not been minimally covered.
4. **Never continue if**:
   - Budget is zero.
   - The last 3 iterations had delta = 0.
   - The target is unresponsive / unavailable.

## Quality Criteria

- Clear binary decision (continue/stop).
- Concrete reason, not vague.
- `remaining_value` reflects an honest analysis.

## Template

```
DECISION: CONTINUE OR STOP
==========================

Metrics:
- Iteration: ${iteration}
- Total findings: ${findings_count}
- Last-iteration delta: ${new_findings_delta}
- Coverage: ${coverage}
- Budget remaining: ${budget_remaining}

Analysis:
- Diminishing returns? [yes/no — last 3 deltas]
- Critical gaps open? [list]
- Does the budget allow one more iteration? [yes/no]

Decision: [CONTINUE | STOP]
Reason: [concrete justification]
Value of continuing: [0.0 - 1.0]
```
