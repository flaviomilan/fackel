# Prompt System

Complete reference for Fackel's prompt architecture — how agent system prompts
are composed, how dynamic templates inject runtime context, and where each
prompt file is consumed in the pipeline.

---

## Table of contents

- [Overview](#overview)
- [Three-tier architecture](#three-tier-architecture)
- [Loader API](#loader-api)
  - [load_prompt()](#load_prompt)
  - [load_template()](#load_template)
  - [load_section_map()](#load_section_map)
- [Soul prompt](#soul-prompt)
- [Skill prompts](#skill-prompts)
  - [osint.md](#osintmd)
  - [port_scan.md](#port_scanmd)
  - [vuln_scan.md](#vuln_scanmd)
  - [triage.md](#triagemd)
  - [report.md](#reportmd)
  - [judge.md](#judgemd)
- [Templates](#templates)
  - [Task templates](#task-templates)
  - [Strategy templates](#strategy-templates)
  - [Conditional context templates](#conditional-context-templates)
  - [Guidance template](#guidance-template)
  - [Section maps](#section-maps)
  - [Utility templates](#utility-templates)
- [Pipeline prompt flow](#pipeline-prompt-flow)
- [Usage map](#usage-map)
  - [Skill prompt consumers](#skill-prompt-consumers)
  - [Template consumers](#template-consumers)
  - [Section map consumers](#section-map-consumers)
- [File tree](#file-tree)
- [Adding a new prompt](#adding-a-new-prompt)

---

## Overview

Fackel keeps **all prompt text in Markdown files** — no hardcoded strings in
Python. This makes prompts reviewable, diffable, and editable without touching
code.

The system has three layers:

1. **Soul** — shared identity and rules (anti-hallucination, reasoning style)
2. **Skills** — per-agent playbooks and output format specifications
3. **Templates** — dynamic context fragments injected at runtime by graph nodes

All files live under `src/fackel/agents/prompts/` and are loaded via three
cached functions in `src/fackel/agents/prompts/__init__.py`.

---

## Three-tier architecture

```
┌───────────────────────────────────────────────────────────────┐
│                      Agent System Prompt                      │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────┐                              │
│  │         soul.md             │  ← Identity, reasoning,      │
│  │  (shared by ALL agents)     │    stop criteria, anti-       │
│  └──────────────┬──────────────┘    hallucination rules        │
│                 │                                              │
│            ── ─── ──  (separator)                              │
│                 │                                              │
│  ┌──────────────▼──────────────┐                              │
│  │    skills/<agent>.md        │  ← Playbook, tool table,     │
│  │  (one per agent role)       │    output format, strategy    │
│  └─────────────────────────────┘                              │
│                                                               │
│  Composed by: load_prompt("agent")                            │
├───────────────────────────────────────────────────────────────┤
│                     HumanMessage (task)                        │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────┐  ┌─────────────────────┐    │
│  │  templates/<task>.md        │  │ templates/<ctx>.md   │    │
│  │  "Scan {target} for …"     │  │ CDN warnings,        │    │
│  └─────────────────────────────┘  │ tech hints,          │    │
│                                   │ port scan strategy   │    │
│  ┌─────────────────────────────┐  └─────────────────────┘    │
│  │  templates/guidance_suffix  │                              │
│  │  "--- Operator Guidance ---"│                              │
│  └─────────────────────────────┘                              │
│                                                               │
│  Loaded by: load_template("name") / load_section_map("name") │
└───────────────────────────────────────────────────────────────┘
```

**Soul + Skill** form the LLM's system prompt (via `load_prompt()`).

**Templates** are formatted at runtime and injected into the `HumanMessage`
that each graph node sends to the agent. They carry dynamic context — the
target, discovered IPs, operator guidance, strategy hints.

---

## Loader API

Defined in `src/fackel/agents/prompts/__init__.py`.

### load_prompt()

```python
def load_prompt(skill: str) -> str
```

Loads `soul.md` + `skills/<skill>.md`, joined by `\n\n---\n\n`.
Cached via `@lru_cache(maxsize=32)`.

```python
from fackel.agents.prompts import load_prompt

prompt = load_prompt("osint")      # → soul.md + skills/osint.md
prompt = load_prompt("port_scan")  # → soul.md + skills/port_scan.md
```

Used by agent builders (`osint/agent.py`, `port_scan/agent.py`, etc.) to
set the agent's `system_prompt`.

### load_template()

```python
def load_template(name: str) -> str
```

Loads `templates/<name>.md` as raw text. Cached via `@lru_cache(maxsize=32)`.
Templates may contain `{placeholder}` markers — the caller formats them
with `.format(**kwargs)`.

```python
from fackel.agents.prompts import load_template

task = load_template("osint_task").format(target="example.com")
# → "Perform passive OSINT reconnaissance on: example.com"
```

### load_section_map()

```python
def load_section_map(name: str) -> dict[str, str]
```

Loads a template with `## key` headings and returns a dict mapping each
heading to its body text. Cached via `@lru_cache(maxsize=8)`.

```python
from fackel.agents.prompts import load_section_map

hints = load_section_map("ip_class_hints")
# → {"cdn": "⚠ CDN IPs ...", "cloud": "Cloud provider ...", "direct_host": "..."}

descs = load_section_map("phase_descriptions")
# → {"osint": "Passive recon ...", "port_scan": "...", "vuln_scan": "..."}
```

Used when different sections of a template are needed conditionally
(e.g. selecting an IP classification hint based on the detected infra type).

---

## Soul prompt

**File:** `src/fackel/agents/prompts/soul.md` (~70 lines)

Shared by **all six agents**. Prepended to every system prompt via
`load_prompt()`.

| Section | Content |
|---------|---------|
| **Identity** | Security professional in a multi-agent workflow. Focus exclusively on assigned role. Only scan targets explicitly provided. |
| **Reasoning** | Think → Act → Observe. Broad first for coverage, then deeper on high-severity. Failure resilience — one tool failure must never block the phase. Economy — no duplicate calls. |
| **Parallel tool calls** | Encouraged when independent. Never call the same tool twice with identical args. |
| **Stop criteria** | Playbook complete, no new information (last 2+ calls), all targets covered, or 15+ tool calls. |
| **Anti-hallucination** | 5 mandatory rules: never fabricate, only use tool outputs, report failures honestly, no speculation, distinguish informational findings from actual risk. |

---

## Skill prompts

Located in `src/fackel/agents/prompts/skills/`. One file per agent role.

### osint.md

**Agent:** OSINT | **Lines:** ~244

The most detailed playbook. Defines a 22-step passive reconnaissance procedure
covering DNS resolution, WHOIS, subdomain enumeration (subfinder, crt.sh,
VirusTotal, Amass), reverse DNS, IP enrichment (ipinfo, BGP), TLS certificate
inspection, Shodan/Censys/FOFA, historical DNS, URL discovery (gau), cloud
resource enumeration, web tech fingerprinting, parameter discovery, JS endpoint
extraction, secret scanning, and subdomain takeover checks.

Includes a **tool table** (27 tools with accepted target types) and a
**structured summary** output format specification.

### port_scan.md

**Agent:** Port Scan | **Lines:** ~90

Strategy: naabu first (top 1000 ports per IP), then nmap for detailed service
fingerprinting on discovered ports. Skip subdomains that resolve to
already-scanned IPs. Handle nmap failures by retrying with
`skip_host_discovery=True`. Per-IP structured table output.

### vuln_scan.md

**Agent:** Vuln Scan | **Lines:** ~170

8-section playbook: domain nuclei first → HTTP surface + WAF detection →
deep-dive on findings (e.g. GraphQL if discovered) → web discovery (katana +
feroxbuster) → XSS testing → TLS analysis → cloud storage audit → page content
extraction → CORS testing → WordPress scanning (conditional) → subdomain scans.

Includes adaptive strategy notes based on port scan completeness.

### triage.md

**Agent:** Triage | **Lines:** ~150

Technology identification from all accumulated findings. Coverage gap analysis —
what was detected but not adequately tested. Technology coverage table format.
Infrastructure risk signals (open databases, VoIP, etc.). Gap severity
classification (high / medium / low). Risk scoring model (0–10).

### report.md

**Agent:** Report | **Lines:** ~60

8-section report structure: Executive Summary, Scope, Methodology, Discovered
Assets, Findings (per-phase with severity), Phase Quality Assessments,
Unassessed Areas, Recommendations. Writing rules: factual, tables over prose,
evidence citations, severity classification.

### judge.md

**Agent:** Judge | **Lines:** ~72

Scoring guide (0.0–1.0 scale mapping to complete/partial/empty). Recommendation
guide (proceed / adapt / skip_downstream). Phase-specific scoring expectations —
what constitutes "complete" for OSINT vs port scan vs vuln scan. Output model
specification (`PhaseEvaluation`).

---

## Templates

Located in `src/fackel/agents/prompts/templates/`. 16 files organised by
purpose.

### Task templates

Injected as the primary task instruction in the `HumanMessage`.

| Template | Placeholders | Used by | Purpose |
|----------|-------------|---------|---------|
| `osint_task.md` | `{target}` | `nodes/osint.py` | Primary OSINT task: "Perform passive OSINT reconnaissance on: {target}" |
| `osint_retry.md` | `{target}`, `{completeness}`, `{score}`, `{gaps_text}`, `{reasoning}` | `nodes/osint.py` | Retry task when judge scores low — includes quality feedback and specific gaps to address |
| `port_scan_task.md` | *(none)* | `nodes/port_scan.py` | Port scan task header: "Scan the following targets for open ports and services" |
| `vuln_scan_task.md` | *(none)* | `nodes/vuln_scan.py` | Vuln scan task header: "Run vulnerability scans on the target" |
| `triage_task.md` | `{context}` | `triage/agent.py` | Triage task: "Analyse these scan findings: {context}" |
| `intake_system.md` | *(none)* | `cli/intake.py` | System prompt for interactive intake — LLM extracts scan intent from natural language |

### Strategy templates

Appended to task messages to guide agent strategy.

| Template | Placeholders | Used by | Purpose |
|----------|-------------|---------|---------|
| `port_scan_strategy.md` | *(none)* | `nodes/port_scan.py` | Naabu-first strategy, skip duplicate subdomain IPs |
| `vuln_scan_strategy.md` | *(none)* | `nodes/vuln_scan.py` | Domain nuclei first, then subdomains, structured breadth-first approach |

### Conditional context templates

Injected only when specific conditions are met at runtime.

| Template | Placeholders | Condition | Used by | Purpose |
|----------|-------------|-----------|---------|---------|
| `cdn_warning.md` | *(none)* | CDN IPs detected among targets | `nodes/port_scan.py` | Warns agent that CDN proxy IPs won't reveal origin server ports |
| `vuln_scan_empty_ports.md` | *(none)* | Port scan completeness = `empty` | `nodes/vuln_scan.py` | Instructs agent to focus on domain-level checks only |
| `vuln_scan_partial_ports.md` | *(none)* | Port scan completeness = `partial` | `nodes/vuln_scan.py` | Prioritise domain-level scans, skip IP-specific if no ports |
| `vuln_scan_tech_hint.md` | `{technologies}` | Technologies detected in findings | `nodes/vuln_scan.py` | Directs agent to use nuclei templates targeting specific technologies |
| `report_fallback.md` | `{target}` | Report LLM call fails | `report/agent.py` | Fallback report header when the report agent errors |

### Guidance template

| Template | Placeholders | Used by | Purpose |
|----------|-------------|---------|---------|
| `guidance_suffix.md` | `{guidance}` | `nodes/osint.py`, `nodes/port_scan.py`, `nodes/vuln_scan.py`, `nodes/_helpers.py` | Wraps operator guidance text under `--- Operator Guidance ---` heading. Appended to task message when `--guided` is active. |

### Section maps

Parsed by `load_section_map()` into `dict[str, str]`. The `## heading` becomes
the dict key; the body text becomes the value.

| Template | Sections | Used by | Purpose |
|----------|----------|---------|---------|
| `ip_class_hints.md` | `cdn`, `cloud`, `direct_host` | `nodes/port_scan.py` | Per-IP-classification hints (e.g. "CDN IPs yield proxy ports, not origin") selected based on `ip_classifier` output |
| `phase_descriptions.md` | `osint`, `port_scan`, `vuln_scan` | `nodes/_guidance.py` | Human-readable phase descriptions shown in the guidance prompt panel |

---

## Pipeline prompt flow

How prompts flow through a full active scan:

```
┌─────────────────────── Interactive Intake (optional) ───────────┐
│ System: templates/intake_system.md                              │
│ User: free-text conversation                                    │
│ Output: ScanIntent (target, active_scan, focus_areas)           │
└────────────────────────────┬────────────────────────────────────┘
                             │
        ╔════════════════════▼═══════════════════╗
        ║            OSINT Agent                 ║
        ║  System: soul.md + skills/osint.md     ║
        ║  Task:   templates/osint_task.md       ║
        ║          + guidance_suffix (if guided) ║
        ╚════════════════════╤═══════════════════╝
                             │
                    (if score < 0.8)
                             │
        ┌────────────────────▼───────────────────┐
        │         OSINT Retry                     │
        │  Task: templates/osint_retry.md         │
        │        (includes gaps + score feedback) │
        └────────────────────┬───────────────────┘
                             │
        ╔════════════════════▼═══════════════════╗
        ║          Port Scan Agent               ║
        ║  System: soul.md + skills/port_scan.md ║
        ║  Task:   templates/port_scan_task.md   ║
        ║          + port_scan_strategy.md       ║
        ║          + cdn_warning.md (if CDN IPs) ║
        ║          + ip_class_hints (per-IP)     ║
        ║          + guidance_suffix (if guided) ║
        ╚════════════════════╤═══════════════════╝
                             │
        ╔════════════════════▼═══════════════════╗
        ║         Vuln Scan Agent                ║
        ║  System: soul.md + skills/vuln_scan.md ║
        ║  Task:   templates/vuln_scan_task.md   ║
        ║          + vuln_scan_strategy.md       ║
        ║          + vuln_scan_empty_ports.md    ║
        ║            OR vuln_scan_partial_ports  ║
        ║          + vuln_scan_tech_hint.md      ║
        ║          + guidance_suffix (if guided) ║
        ╚════════════════════╤═══════════════════╝
                             │
        ╔════════════════════▼═══════════════════╗
        ║           Triage Agent                 ║
        ║  System: soul.md + skills/triage.md    ║
        ║  Task:   templates/triage_task.md      ║
        ╚════════════════════╤═══════════════════╝
                             │
        ╔════════════════════▼═══════════════════╗
        ║           Report Agent                 ║
        ║  System: soul.md + skills/report.md    ║
        ║  (fallback: templates/report_fallback) ║
        ╚════════════════════╤═══════════════════╝
                             │
                            END
```

The **Judge** agent (`soul.md + skills/judge.md`) runs after each ReAct phase
(OSINT, port scan, vuln scan) to score quality and drive routing decisions.

---

## Usage map

### Skill prompt consumers

Each agent builder calls `load_prompt(skill)` to compose the system prompt.

| Skill | Consumer file | Agent |
|-------|---------------|-------|
| `osint` | `src/fackel/agents/osint/agent.py` | OSINT ReAct (27 tools) |
| `port_scan` | `src/fackel/agents/port_scan/agent.py` | Port Scan ReAct (2 tools) |
| `vuln_scan` | `src/fackel/agents/vuln_scan/agent.py` | Vuln Scan ReAct (12 tools) |
| `triage` | `src/fackel/agents/triage/agent.py` | Triage structured output |
| `report` | `src/fackel/agents/report/agent.py` | Report synthesis |
| `judge` | `src/fackel/agents/orchestrator/evaluator.py` | Phase quality evaluator |

### Template consumers

Graph nodes call `load_template(name)` to build task messages.

| Template | Consumer file |
|----------|---------------|
| `osint_task` | `src/fackel/agents/orchestrator/nodes/osint.py` |
| `osint_retry` | `src/fackel/agents/orchestrator/nodes/osint.py` |
| `port_scan_task` | `src/fackel/agents/orchestrator/nodes/port_scan.py` |
| `port_scan_strategy` | `src/fackel/agents/orchestrator/nodes/port_scan.py` |
| `cdn_warning` | `src/fackel/agents/orchestrator/nodes/port_scan.py` |
| `vuln_scan_task` | `src/fackel/agents/orchestrator/nodes/vuln_scan.py` |
| `vuln_scan_strategy` | `src/fackel/agents/orchestrator/nodes/vuln_scan.py` |
| `vuln_scan_empty_ports` | `src/fackel/agents/orchestrator/nodes/vuln_scan.py` |
| `vuln_scan_partial_ports` | `src/fackel/agents/orchestrator/nodes/vuln_scan.py` |
| `vuln_scan_tech_hint` | `src/fackel/agents/orchestrator/nodes/vuln_scan.py` |
| `triage_task` | `src/fackel/agents/triage/agent.py` |
| `intake_system` | `src/cli/intake.py` |
| `report_fallback` | `src/fackel/agents/report/agent.py` |
| `guidance_suffix` | `nodes/osint.py`, `nodes/port_scan.py`, `nodes/vuln_scan.py`, `nodes/_helpers.py` |

### Section map consumers

| Template | Consumer file | Keys |
|----------|---------------|------|
| `ip_class_hints` | `src/fackel/agents/orchestrator/nodes/port_scan.py` | `cdn`, `cloud`, `direct_host` |
| `phase_descriptions` | `src/fackel/agents/orchestrator/nodes/_guidance.py` | `osint`, `port_scan`, `vuln_scan` |

---

## File tree

```
src/fackel/agents/prompts/
├── __init__.py              # Loader API: load_prompt, load_template, load_section_map
├── soul.md                  # Shared agent identity + rules (~70 lines)
├── skills/
│   ├── osint.md             # OSINT playbook (244 lines)
│   ├── port_scan.md         # Port scan strategy (90 lines)
│   ├── vuln_scan.md         # Vuln scan playbook (170 lines)
│   ├── triage.md            # Coverage gap analysis (150 lines)
│   ├── report.md            # Report writing rules (60 lines)
│   └── judge.md             # Quality scoring guide (72 lines)
└── templates/
    ├── intake_system.md     # Interactive intake system prompt
    ├── osint_task.md         # OSINT task: {target}
    ├── osint_retry.md        # OSINT retry with feedback: {target}, {completeness}, {score}, {gaps_text}, {reasoning}
    ├── port_scan_task.md     # Port scan task header
    ├── port_scan_strategy.md # Naabu→nmap strategy
    ├── cdn_warning.md        # CDN IP warning (conditional)
    ├── ip_class_hints.md     # Section map: cdn / cloud / direct_host
    ├── vuln_scan_task.md     # Vuln scan task header
    ├── vuln_scan_strategy.md # Domain-first vuln strategy
    ├── vuln_scan_empty_ports.md   # Fallback for empty port scan
    ├── vuln_scan_partial_ports.md # Fallback for partial port scan
    ├── vuln_scan_tech_hint.md     # Technology-specific hints: {technologies}
    ├── triage_task.md        # Triage task: {context}
    ├── report_fallback.md    # Report error fallback: {target}
    ├── guidance_suffix.md    # Operator guidance wrapper: {guidance}
    └── phase_descriptions.md # Section map: osint / port_scan / vuln_scan
```

---

## Adding a new prompt

### New skill prompt

1. Create `src/fackel/agents/prompts/skills/<agent>.md`
2. Follow the pattern: `# Skill — <Title>` heading, role description,
   playbook steps, tool table, output format
3. Call `load_prompt("<agent>")` in your agent builder

### New template

1. Create `src/fackel/agents/prompts/templates/<name>.md`
2. Use `{placeholder}` syntax for dynamic values
3. Call `load_template("<name>").format(**kwargs)` in your graph node

### New section map

1. Create `src/fackel/agents/prompts/templates/<name>.md`
2. Use `## key` headings to define sections
3. Call `load_section_map("<name>")["key"]` in your graph node

### Caching

All three loaders use `@lru_cache`. Changes to `.md` files on disk are
**not** picked up without process restart. This is by design — prompts
are treated as deployment-time configuration, not runtime-mutable state.
