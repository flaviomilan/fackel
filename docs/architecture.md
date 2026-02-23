# Architecture

This document describes the internal architecture of Fackel — how the LangGraph
orchestrator coordinates specialist agents, manages shared state, routes between
phases, and streams events to the CLI.

---

## Table of contents

- [System diagram](#system-diagram)
- [Packages](#packages)
- [Orchestrator graph](#orchestrator-graph)
  - [Graph definition](#graph-definition)
  - [Routing logic](#routing-logic)
  - [Checkpointing](#checkpointing)
- [Shared state — ScanState](#shared-state--scanstate)
- [Prompt system](#prompt-system)
  - [Soul prompt](#soul-prompt)
  - [Skill prompts](#skill-prompts)
- [Event streaming](#event-streaming)
- [Report generation](#report-generation)
- [Safety guards](#safety-guards)

---

## System diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                         CLI (typer + Rich)                        │
│  fackel <target> [--active-scan] [-v] [-o file]                  │
│  Registers event callback → Rich console rendering               │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                    orchestrator.run() / run_stream()              │
│  Creates ScanState, builds LangGraph, manages interrupt/resume   │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                LangGraph StateGraph(ScanState)                    │
│                                                                  │
│  ┌──────────┐     ┌──────────────┐     ┌────────────┐           │
│  │  osint   │────▶│approval_gate │────▶│ port_scan  │           │
│  │(11 tools)│     │  (HitL)      │     │ (2 tools)  │           │
│  └──────────┘     └──────────────┘     └─────┬──────┘           │
│       │                                      │                   │
│       │ (no active scan)         ┌───────────▼────────────┐      │
│       │                          │ evaluate_phase (judge)  │      │
│       │                          └──┬──────────────────┬──┘      │
│       │                             │                  │          │
│       │                    ┌────────▼───┐    ┌────────▼────┐     │
│       │                    │ vuln_scan  │    │   triage    │     │
│       │                    │ (8 tools)  │    │ (structured)│     │
│       │                    └────────┬───┘    └──────┬──────┘     │
│       │                             │               │            │
│       │                    ┌────────▼───┐           │            │
│       │                    │   triage   │           │            │
│       └────────────┐       └────────┬───┘           │            │
│                    │                │               │            │
│                    ▼                ▼               ▼            │
│              ┌──────────────────────────────────────────┐        │
│              │             report_node                   │        │
│              │           (LLM synthesis)                 │        │
│              └──────────────────┬───────────────────────┘        │
│                                 │                                │
│                                END                               │
└──────────────────────────────────────────────────────────────────┘
```

---

## Packages

| Package | Responsibility |
|---------|---------------|
| `src/cli/` | Typer CLI entry point, event rendering with Rich |
| `src/fackel/agents/orchestrator/` | LangGraph state machine, nodes, routing, evaluator |
| `src/fackel/agents/osint/` | OSINT ReAct agent construction |
| `src/fackel/agents/port_scan/` | Port scan ReAct agent construction |
| `src/fackel/agents/vuln_scan/` | Vulnerability scan ReAct agent construction |
| `src/fackel/agents/triage/` | Triage structured output (no tools) |
| `src/fackel/agents/report/` | Report synthesis (no tools) |
| `src/fackel/agents/prompts/` | Two-tier prompt loading and caching |
| `src/fackel/domain/` | Domain models, enumerations (infrastructure-agnostic) |
| `src/fackel/utils/` | Pure validation utilities (network, target) |
| `src/fackel/` | Provider key management, report writer |
| `src/tools/` | 25 LangChain `@tool`-decorated functions + validators + utilities |

---

## Orchestrator graph

### Graph definition

Defined in `src/fackel/agents/orchestrator/graph.py`.

The orchestrator is a **LangGraph `StateGraph`** with `ScanState` as its state
schema. Each node is a Python function that receives the current state and
returns a partial update.

**Nodes:**

| Node | Function | Type |
|------|----------|------|
| `osint` | `osint_node` | ReAct agent (streaming) |
| `approval_gate` | `approval_gate` | HitL interrupt |
| `port_scan` | `port_scan_node` | ReAct agent (streaming) + judge |
| `vuln_scan` | `vuln_scan_node` | ReAct agent (streaming) + judge |
| `triage` | `triage_node` | Structured LLM output |
| `report` | `report_node` | Single LLM call |

**Edges:**

```
__start__  → osint
osint      → route_after_osint (conditional)
               ├─ "approval_gate"  (active_scan=True AND targets found)
               └─ "report"         (passive or no targets)
approval_gate → Command(goto="port_scan") or Command(goto="report")
port_scan  → route_after_port_scan (conditional)
               ├─ "vuln_scan"      (default: proceed or adapt)
               └─ "triage"         (judge says skip_downstream)
vuln_scan  → triage
triage     → report
report     → __end__
```

### Routing logic

**`route_after_osint(state)`:**

Returns `"approval_gate"` when **all** of:
1. `state["active_scan"]` is `True`
2. At least one IPv4 address OR at least one subdomain was discovered

Otherwise returns `"report"` — skipping port scan, vuln scan, and triage
entirely (common for passive-only scans or when OSINT discovers no
infrastructure).

**`route_after_port_scan(state)`:**

Reads the latest `PhaseEvaluation` from `state["phase_evaluations"]`. If the
judge's `recommendation` is `"skip_downstream"`, routes to `"triage"`, skipping
vulnerability scanning. Otherwise routes to `"vuln_scan"`.

This enables **adaptive pipeline routing** — if port scanning found nothing
meaningful, the expensive vuln scan phase is skipped.

### Checkpointing

The graph uses LangGraph's `MemorySaver` for in-memory checkpointing. Each
invocation gets a unique `thread_id` (UUID). This enables:

- **State persistence** across graph nodes
- **Interrupt/resume** for the approval gate (Human-in-the-Loop)
- **Failure recovery** (replay from last checkpoint)

---

## Shared state — ScanState

Defined in `src/fackel/agents/orchestrator/state.py`.

```python
class ScanState(TypedDict):
    target: str                                        # Domain or IP (user input)
    active_scan: bool                                  # Whether active phases run
    discovered_ips: list[str]                          # IPs found during OSINT
    discovered_subdomains: list[str]                   # Subdomains from OSINT
    findings: Annotated[list[Finding], add]            # Append-only findings
    unassessed_areas: Annotated[list[dict], add]       # Triage gaps
    phase_evaluations: Annotated[list[dict], add]      # Judge assessments
    report: str                                        # Final Markdown report
```

### Finding structure

```python
class Finding(TypedDict):
    phase: str           # "osint" | "port_scan" | "vuln_scan" | "triage"
    title: str           # Human-readable label
    detail: str          # Full Markdown content
    severity: str        # "critical" | "high" | "medium" | "low" | "info"
    source_tool: str     # Primary tool name
    confidence: float    # 0.0–1.0
```

### Append-only semantics

The `findings`, `unassessed_areas`, and `phase_evaluations` fields use
LangGraph's `Annotated[list, add]` reducer. When a node returns
`{"findings": [new_finding]}`, LangGraph **appends** it to the existing list
rather than overwriting. This ensures no phase can destroy another phase's data.

---

## Prompt system

Defined in `src/fackel/agents/prompts/__init__.py`.

### Architecture

Two-tier composition — a shared **soul** prompt (agent identity and rules)
combined with a task-specific **skill** prompt.

```python
load_prompt("osint")     # → soul.md + "\n\n---\n\n" + skills/osint.md
load_prompt("port_scan") # → soul.md + "\n\n---\n\n" + skills/port_scan.md
```

Prompts are loaded from disk and cached via `@lru_cache(maxsize=16)`.

### Soul prompt

`src/fackel/agents/prompts/soul.md` — shared by all agents.

Defines:

| Section | Content |
|---------|---------|
| **Identity** | Security professional in a multi-agent workflow. Focus exclusively on assigned role. Only scan targets explicitly provided. |
| **Reasoning** | Think → Act → Observe. Broad first for coverage, then deeper on high-severity. Failure resilience — one tool failure must never block the phase. Economy — no duplicate calls. |
| **Stop criteria** | Playbook complete, no new information (last 2+ calls), all targets covered, or 15+ tool calls. |
| **Anti-hallucination** | 5 mandatory rules: never fabricate, only use tool outputs, report failures, no speculation, distinguish info from risk. |

### Skill prompts

Located in `src/fackel/agents/prompts/skills/`.

| File | Agent | Content |
|------|-------|---------|
| `osint.md` | OSINT | 8-step playbook (DNS → WHOIS → subdomain enum → reverse DNS → Shodan/Censys → job search → email analysis). Tool table. Structured output format. |
| `port_scan.md` | Port Scan | Strategy: naabu (top 1000) per IP first, then nmap for service fingerprinting. Skip duplicate subdomain IPs. Per-IP table output. |
| `vuln_scan.md` | Vuln Scan | 8-section playbook: domain nuclei first → HTTP surface + WAF → deep-dive on findings → web discovery (katana + feroxbuster) → TLS analysis → page content → subdomain scans. |
| `triage.md` | Triage | Technology identification, coverage gap analysis. Technology coverage table. Infrastructure risk signals. Gap severity classification. |
| `report.md` | Report | 8-section report structure. Phase quality assessment integration. Writing rules (factual, tables over prose, quantify). |
| `judge.md` | Judge | Scoring guide (0.0–1.0), recommendation guide (proceed/adapt/skip_downstream). Phase-specific expectations. |

---

## Event streaming

### Event flow

```
Graph node → _emit(phase, event_type, data) → _event_callback → CLI renderer
```

Nodes emit events via the `_emit()` function in `nodes.py`, which delegates to a
module-level `_event_callback`. The CLI sets this callback via
`set_event_callback()` before invoking the graph.

### Event types

| Event Type | Data | Rendered As |
|------------|------|-------------|
| `start` | `{phase}` | Section header: `▶ Phase Name` |
| `tool_call` | `{name, args}` | `🔧 tool_name(arg=val, ...)` |
| `tool_result` | `{name, preview}` | `← tool_name: preview...` (verbose only) |
| `tool_error` | `{name, error}` | `✗ tool_name: error` (red) |
| `reasoning` | `{text}` | `💭 line` (verbose only, italic) |
| `summary` | `{content}` | Rich panel with Markdown |
| `evaluation` | `{completeness, score, recommendation}` | `📊 Quality: completeness (score: X.X) → recommendation` |
| `done` | `{phase}` | `✓ Phase complete` (green) |

### Agent streaming

Each ReAct agent is streamed via LangGraph's `agent.stream()` with
`stream_mode="updates"`. The `_run_and_stream_agent()` helper in `nodes.py`:

1. Iterates over stream events
2. Validates tool outputs against the standard envelope format
3. Emits appropriate events for each message (AI reasoning, tool calls, results, errors)
4. Enforces the max iteration guard (40 tool calls)
5. Returns collected messages for post-processing (IP/subdomain extraction)

---

## Report generation

### Dual reports

Fackel generates two reports per scan:

| Report | Destination | Content |
|--------|-------------|---------|
| **LLM report** | Terminal (Rich Markdown) | Concise narrative synthesized by the report agent |
| **Archival report** | Disk (`reports/<target>_<timestamp>.md`) | Comprehensive document with all raw phase details |

### Archival report structure

Generated by `build_full_report(state)` in `src/fackel/report_writer.py`:

1. **Header** — metadata table (target, date, active scan, counts)
2. **Table of Contents** — auto-generated
3. **Executive Summary** — extracted from LLM report
4. **Discovered Assets** — IP table + subdomain list
5. **Phase Findings** — verbatim findings with inline quality assessments
6. **Phase Quality Assessments** — summary table + per-phase details
7. **Unassessed Areas** — coverage gaps from triage
8. **Full LLM Report** — complete report agent output
9. **Footer** — generation timestamp

---

## Safety guards

| Guard | Location | Behaviour |
|-------|----------|-----------|
| **MAX_AGENT_ITERATIONS = 40** | `nodes.py` | Stops ReAct loop after 40 tool calls per phase |
| **_SUBDOMAIN_CAP = 30** | `nodes.py` | Limits subdomains passed to downstream agents |
| **Tool output validation** | `nodes.py` | Checks for standard envelope (`tool`, `status`), logs warnings for malformed outputs |
| **Reverse-PTR filtering** | `nodes.py` | Removes auto-generated PTR hostnames (e.g. `200-210-75-128.example.com`) from subdomain lists |
| **Input validation rails** | `tools/validators.py` | `guard_target()` validates target type and blocks shell metacharacters |
| **Provider key gating** | `provider_keys.py` | Removes tools with missing API keys from agents |
| **LLM-as-a-judge** | `evaluator.py` | Never raises — returns safe fallback on failure (score=0.5, completeness=partial) |
| **Approval gate** | `graph.py` | HitL interrupt before active scanning |
| **IPv6 filtering** | `nodes.py` | Port scan receives only IPv4 addresses (most active tools don't support IPv6) |
