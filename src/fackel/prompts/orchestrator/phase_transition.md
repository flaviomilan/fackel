# Orchestrator — Phase Transition

## Objective

Decide when the pipeline should transition between phases (recon →
enumeration → scanning → validation → reporting), ensuring the current
phase's exit criteria are satisfied.

## Inputs

| Field                | Type         | Description                               |
|----------------------|--------------|-------------------------------------------|
| `current_phase`      | `string`     | Current pipeline phase                    |
| `phase_objectives`   | `list[str]`  | Objectives of the current phase           |
| `objectives_met`     | `dict`       | Status of each objective (bool + evidence)|
| `phase_duration`     | `int`        | Time in the current phase (iterations)    |
| `${user_context}`    | `string`     | Operational context (optional)            |

## Outputs

| Field                | Type         | Description                               |
|----------------------|--------------|-------------------------------------------|
| `transition`         | `bool`       | Whether to transition                     |
| `next_phase`         | `string`     | Next phase                                |
| `unmet_objectives`   | `list[str]`  | Objectives not achieved                   |
| `carry_forward`      | `list[dict]` | Items to resolve in the next phase        |
| `phase_summary`      | `string`     | Summary of the phase that is ending       |

## Rules

1. **Exit criteria per phase**:
   - **Recon**: domains mapped, IPs identified, WHOIS collected
   - **Enumeration**: subdomains enumerated, ports scanned, services
     detected
   - **Scanning**: vulns verified, technologies fingerprinted, web crawled
   - **Validation**: findings cross-referenced, false positives filtered,
     severity assigned
   - **Reporting**: report compiled, recommendations generated
2. **80% criterion** — transition when 80% of the phase's objectives are
   satisfied.
3. **Do not transition if**:
   - Fewer than 50% of objectives achieved.
   - A critical vuln was found that requires investigation in the current
     phase.
4. **Phase timeout** — if >5 iterations in the same phase without progress,
   transition with carry_forward.
5. **Carry forward** — unmet objectives are documented and forwarded as
   open items.

## Quality Criteria

- Decision based on measurable objectives.
- Carry forward documented explicitly.
- Phase summary precise and concise.
- Transitions do not skip phases (recon → scanning is forbidden).

## Template

```
PHASE TRANSITION
================

Current phase: ${current_phase}
Iterations: ${phase_duration}

Phase objectives:
| Objective               | Status | Evidence           |
|-------------------------|--------|--------------------|
| [objective 1]           | ✅/❌  | [reference]        |
| [objective 2]           | ✅/❌  | [reference]        |

Progress: [X/Y objectives] = [Z%]

Decision: [TRANSITION | CONTINUE]
Next phase: [phase] (if transitioning)
Carry forward: [unmet objectives]
Summary: [what was achieved in this phase]
```
