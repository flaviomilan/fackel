# Orchestrator — Loop Detection

## Objective

Identify and break loops in the pipeline where the same tools are called
repeatedly without producing new results.

## Inputs

| Field                | Type         | Description                                     |
|----------------------|--------------|-------------------------------------------------|
| `tool_history`       | `list[dict]` | Call history (tool, target, timestamp)          |
| `findings_per_call`  | `dict`       | New findings per call                           |
| `current_iteration`  | `int`        | Current iteration                               |
| `${user_context}`    | `string`     | Operational context (optional)                  |

## Outputs

| Field                | Type         | Description                                     |
|----------------------|--------------|-------------------------------------------------|
| `loop_detected`      | `bool`       | Whether a loop was detected                     |
| `loop_type`          | `string`     | Type: exact_repeat, oscillation, drift          |
| `offending_tools`    | `list[str]`  | Tools involved in the loop                      |
| `recommended_action` | `string`     | Corrective action                               |

## Rules

1. **Exact repeat** — same tool, same target, same params called 2+ times
   → clear loop.
2. **Oscillation** — tool A → tool B → tool A → tool B with no new findings
   → unproductive oscillation.
3. **Drift** — target changes slightly each iteration but results do not
   change → expansion without value.
4. **Tolerance**: 1 repeat is acceptable (legitimate retry); 2+ is a loop.
5. **Default action**: stop the looping tools, advance to the next phase.
6. **Do not count as a loop**: same tool on different targets (legitimate).

## Quality Criteria

- Precise detection (no false positives on legitimate retries).
- Loop type identified correctly.
- Corrective action specific and actionable.

## Template

```
LOOP DETECTION
==============

Analyse the call history:

1. Group by (tool, target):
   - If count > 2 with the same findings → exact_repeat
   - If alternating A→B→A→B with delta=0 → oscillation
   - If target drift with no new findings → drift

2. If a loop is detected:
   - Identify the offending tools
   - Recommend: skip the looping tools, advance the phase
   - Or: change strategy (different params/targets)

3. If not detected:
   - Confirm progress is being made
   - Report efficiency metrics
```
