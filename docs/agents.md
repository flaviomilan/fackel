# Agents

This document describes each specialist agent in Fackel — how it is constructed,
what tools it has, what prompt drives it, and how it fits into the pipeline.

---

## Table of contents

- [Agent construction pattern](#agent-construction-pattern)
- [OSINT agent](#osint-agent)
- [Port scan agent](#port-scan-agent)
- [Vulnerability scan agent](#vulnerability-scan-agent)
- [Triage agent](#triage-agent)
- [Report agent](#report-agent)
- [Judge (LLM-as-a-judge evaluator)](#judge-llm-as-a-judge-evaluator)
- [Prompt system](#prompt-system)
- [Provider key gating](#provider-key-gating)

---

## Agent construction pattern

All ReAct agents follow the same construction pattern:

```python
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt

def build(model_name: str | None = None) -> CompiledStateGraph:
    llm = ChatOpenAI(model=model_name or get_model("agent_name"))
    prompt = load_prompt("skill_name")
    tools = [tool_a, tool_b, ...]
    available, skipped = filter_tools(tools)
    return create_react_agent(llm, available, prompt=prompt)
```

Key points:
- **Model selection** — `get_model("agent_name")` reads `FACKEL_MODEL_{AGENT_NAME}` env var, falls back to `gpt-5-mini`.
- **Prompt composition** — `load_prompt()` combines `soul.md` (shared identity) with `skills/<name>.md` (task-specific).
- **Tool filtering** — `filter_tools()` removes tools whose API keys are missing.
- **ReAct loop** — LangGraph's `create_react_agent` implements the full Think → Act → Observe cycle.

---

## OSINT agent

**Purpose:** Passive reconnaissance — map the target's external footprint
without sending any probe packets.

**File:** `src/fackel/agents/osint/agent.py`

**Model env var:** `FACKEL_MODEL_OSINT`

### Tools (18)

| Tool | Purpose |
|------|---------||
| `dns_resolve` | Resolve domain to IPs (A + AAAA records) |
| `whois_lookup` | Registration data — registrar, dates, nameservers |
| `shodan_lookup` | Passive service/banner data from Shodan |
| `censys_lookup` | Host/service search via Censys |
| `dnsdumpster_lookup` | Subdomain enum + DNS/MX/NS/TXT records |
| `virustotal_subdomain_enum` | Passive subdomain discovery |
| `crtsh_subdomain_enum` | Subdomain enum via Certificate Transparency |
| `subfinder_enum` | Aggregate 40+ passive sources for subdomains |
| `reverse_dns_lookup` | PTR records + reverse IP for shared hosting |
| `ipinfo_lookup` | IP geolocation, ASN, organisation via ipinfo.io |
| `bgp_lookup` | ASN/prefix lookup via RIPEstat for BGP context |
| `httpx_scan` | HTTP probing + technology fingerprinting |
| `tlscert_lookup` | TLS certificate inspection + SAN subdomain discovery |
| `securitytrails_history` | Historical DNS records — reveals old IPs and hosting changes |
| `urlscan_search` | Cached scan results from Urlscan.io community scans |
| `otx_passive_dns` | Passive DNS records via AlienVault OTX |
| `job_search` | Job posting search for tech stack discovery |
| `analyze_email` | Email breach exposure and reputation scoring |

### Playbook (from `skills/osint.md`)

1. **DNS** — `dns_resolve` to discover IPv4 + IPv6 addresses
2. **WHOIS** — `whois_lookup` for registrar, creation/expiration dates, nameservers
3. **Subdomain enumeration** — run all available tools for maximum coverage:
   - `subfinder_enum` — aggregates 40+ passive sources
   - `crtsh_subdomain_enum` — Certificate Transparency logs
   - `dnsdumpster_lookup` — free, also returns DNS/MX/NS/TXT records
   - `virustotal_subdomain_enum` — if API key available
4. **Reverse DNS** — `reverse_dns_lookup` per discovered IP for shared hosting detection
5. **IP enrichment** — `ipinfo_lookup` per IP for geolocation, ASN, and anycast detection
6. **BGP context** — `bgp_lookup` per IP for ASN holder, prefix, and RIR allocation
7. **TLS certificates** — `tlscert_lookup` for certificate metadata and SAN-based subdomain discovery
8. **Shodan / Censys** — passive service data for each IP (if API keys available)
9. **Historical DNS** — `securitytrails_history` for old IPs that may bypass CDN (if API key available)
10. **URLScan** — `urlscan_search` for cached scan results and technology fingerprints
11. **Passive DNS** — `otx_passive_dns` for AlienVault OTX passive DNS records (if API key available)
12. **HTTP probing** — `httpx_scan` for technology detection and HTTP surface mapping
13. **Job search** — `job_search` with company name for tech stack intelligence
14. **Email analysis** — `analyze_email` if email addresses discovered
15. **Structured summary** — emit findings with evidence citations

### Node post-processing

After the agent completes, `osint_node` in `nodes.py`:

- **Extracts IPs** from `dns_resolve`, `dnsdumpster_lookup`, and `shodan_lookup` tool results
- **Extracts subdomains** from `crtsh_subdomain_enum`, `virustotal_subdomain_enum`, `subfinder_enum`, and `dnsdumpster_lookup`
- **Filters** reverse-PTR-style subdomains (e.g. `200-210-75-128.example.com`)
- Writes `discovered_ips` and `discovered_subdomains` to state

---

## Port scan agent

**Purpose:** Active scanning — discover open TCP ports and fingerprint services.

**File:** `src/fackel/agents/port_scan/agent.py`

**Model env var:** `FACKEL_MODEL_PORT_SCAN`

### Tools (2)

| Tool | Purpose |
|------|---------|
| `naabu_scan` | Fast SYN-based TCP port discovery |
| `nmap_port_scan` | Detailed service version detection + NSE vuln scripts |

### Strategy (from `skills/port_scan.md`)

1. **Naabu first** — run `naabu_scan` (top 1000) against each provided IPv4
2. **Nmap second** — run `nmap_port_scan` per IP with the ports discovered by naabu
3. **Skip duplicate subdomain IPs** — if a subdomain resolves to an already-scanned IP, don't rescan
4. **Handle failures** — re-run nmap with `skip_host_discovery=True` when hosts drop ICMP

### Context injection

The node injects contextual information into the agent's prompt:
- List of discovered IPs (IPv4 only — IPv6 filtered out)
- List of subdomains (capped at 30)
- Scan strategy instructions

### Quality evaluation

After completion, the node runs `evaluate_phase()` (LLM-as-a-judge) to score
the port scan results. The evaluation drives routing — if the judge says
`skip_downstream`, vuln scanning is skipped.

---

## Vulnerability scan agent

**Purpose:** Test discovered attack surface for vulnerabilities, misconfigurations,
and technology fingerprints.

**File:** `src/fackel/agents/vuln_scan/agent.py`

**Model env var:** `FACKEL_MODEL_VULN_SCAN`

### Tools (8)

| Tool | Purpose |
|------|---------|
| `nuclei_scan` | Vulnerability/misconfiguration templates (community-maintained) |
| `httpx_scan` | HTTP probing and technology fingerprinting |
| `wafw00f_detect` | Web Application Firewall detection |
| `graphql_scan` | GraphQL endpoint security testing |
| `feroxbuster_scan` | Recursive directory/content discovery |
| `katana_crawl` | Web crawling for URL/endpoint discovery |
| `testssl_scan` | TLS/SSL protocol, cipher, and vulnerability analysis |
| `extract_webpage_content` | Web page content extraction |

### Playbook (from `skills/vuln_scan.md`)

1. **Domain nuclei** — run `nuclei_scan` on main domain first (broadest coverage)
2. **HTTP surface + WAF** — `httpx_scan` for tech detection, `wafw00f_detect` for WAF
3. **Deep-dive on findings** — if nuclei finds GraphQL, run `graphql_scan`
4. **Web discovery** — `katana_crawl` + `feroxbuster_scan` for hidden endpoints
5. **TLS analysis** — `testssl_scan` for protocol/cipher vulnerabilities
6. **Page content** — `extract_webpage_content` for interesting pages
7. **Subdomain scans** — run `nuclei_scan` per subdomain
8. **Structured summary** — emit findings with evidence

### Adaptive strategy

The vuln scan node adapts based on the port scan evaluation:

| Port scan completeness | Strategy |
|------------------------|----------|
| `empty` | Focus on domain-level checks only |
| `partial` | Prioritise domain-level, skip IP-specific if no ports |
| `complete` | Full breadth scan across all discovered surface |

---

## Triage agent

**Purpose:** Gap analysis — identify technologies that were found but not
adequately assessed, and flag coverage gaps.

**File:** `src/fackel/agents/triage/agent.py`

**Model env var:** `FACKEL_MODEL_TRIAGE`

### Type: structured LLM output (no tools)

Uses `ChatOpenAI.with_structured_output(TriageResult)` for deterministic schema.

### Output model

```python
class UnassessedArea(BaseModel):
    technology: str      # What was found
    detected_by: str     # Which tool detected it
    reason: str          # Why it wasn't assessed
    recommendation: str  # What should be done

class TriageResult(BaseModel):
    technologies_detected: list[str]
    unassessed_areas: list[UnassessedArea]
    summary: str
```

### Behaviour

The triage agent receives all accumulated findings from previous phases and
analyses them for:

- Technologies detected but not specifically tested
- Coverage gaps (e.g. Nuclei found WordPress but no WordPress-specific deep scan was done)
- Infrastructure risk signals (open databases, VoIP services, etc.)
- Gap severity classification (high / medium / low)

---

## Report agent

**Purpose:** Synthesize all findings, evaluations, and coverage gaps into a
professional Markdown penetration test report.

**File:** `src/fackel/agents/report/agent.py`

**Model env var:** `FACKEL_MODEL_REPORT`

### Type: single LLM call (no tools)

Uses a single `ChatOpenAI` invocation with all accumulated context serialised as
input.

### Input context

The report agent receives:
- All `findings` from all phases
- All `unassessed_areas` from triage
- All `phase_evaluations` from the judge
- Target metadata

### Output structure (from `skills/report.md`)

1. Executive Summary
2. Scope
3. Methodology
4. Discovered Assets
5. Findings (per-phase, with severity, evidence, recommendations)
6. Phase Quality Assessments
7. Unassessed Areas / Coverage Gaps
8. Recommendations

### Writing rules

- Factual — only report what tools found
- Tables over prose — quantify where possible
- Evidence citations — link findings to specific tool outputs
- Severity classification — critical > high > medium > low > info

---

## Judge (LLM-as-a-judge evaluator)

**Purpose:** Score each agent phase on quality and completeness, driving adaptive
pipeline routing.

**File:** `src/fackel/agents/orchestrator/evaluator.py`

**Model env var:** `FACKEL_MODEL_JUDGE`

### Type: structured LLM output

Uses `ChatOpenAI.with_structured_output(PhaseEvaluation)`.

### Output model

```python
class PhaseEvaluation(BaseModel):
    phase: str                # Phase name
    completeness: str         # "complete" | "partial" | "empty"
    score: float              # 0.0–1.0
    key_findings: list[str]   # Factual bullets
    gaps: list[str]           # Actionable missing items
    recommendation: str       # "proceed" | "adapt" | "skip_downstream"
    reasoning: str            # One-paragraph explanation
```

### Scoring guide

| Score range | Completeness | Meaning |
|-------------|-------------|---------|
| 0.8–1.0 | `complete` | Rich actionable data, all targets covered |
| 0.4–0.7 | `partial` | Some findings but gaps remain |
| 0.0–0.3 | `empty` | No meaningful data |

### Routing impact

| Recommendation | Effect |
|----------------|--------|
| `proceed` | Continue to next phase normally |
| `adapt` | Continue but adjust strategy (lower scope) |
| `skip_downstream` | Skip the next phase entirely |

### Fault tolerance

`evaluate_phase()` never raises. On any failure (API error, parsing error), it
returns a safe fallback:

```python
PhaseEvaluation(
    phase=phase,
    completeness="partial",
    score=0.5,
    key_findings=[],
    gaps=["Evaluation failed — proceeding with default"],
    recommendation="proceed",
    reasoning="Evaluation encountered an error; defaulting to proceed.",
)
```

---

## Prompt system

### Architecture

Two-tier composition:

```
soul.md  +  skills/<phase>.md  →  final system prompt
─────────   ─────────────────     ────────────────────
Shared       Task-specific         Concatenated with
identity     instructions          "---" separator
```

### Soul prompt (`soul.md`)

Shared by all agents. Defines:

| Section | Content |
|---------|---------|
| **Identity** | Security professional in a multi-agent workflow. Focus exclusively on assigned role. Only scan targets explicitly provided. |
| **Reasoning** | Think → Act → Observe. Broad first then deep. Failure resilience. Economy — no duplicate calls. |
| **Stop criteria** | Playbook complete, no new info (2+ calls), all targets covered, or 15+ tool calls. |
| **Anti-hallucination** | 5 mandatory rules: never fabricate, only use tool outputs, report failures, no speculation, info ≠ vulnerability. |

### Skill prompts

| File | Agent | Key content |
|------|-------|-------------|
| `skills/osint.md` | OSINT | 8-step playbook, tool table, structured output format |
| `skills/port_scan.md` | Port Scan | Strategy: naabu first, nmap for details, skip duplicates |
| `skills/vuln_scan.md` | Vuln Scan | 8-section playbook, adaptive strategy notes |
| `skills/triage.md` | Triage | Technology identification, gap severity, coverage table |
| `skills/report.md` | Report | 8-section structure, writing rules, evidence requirements |
| `skills/judge.md` | Judge | Scoring guide, recommendation guide, phase-specific expectations |

### Caching

Prompts are loaded from disk and cached via `@lru_cache(maxsize=16)`.

---

## Provider key gating

Defined in `src/fackel/provider_keys.py`.

When an agent is built, `filter_tools()` checks which API keys are configured.
Tools with missing keys (and `hard_fail=True`) are **removed** from the agent's
toolkit before it starts. This prevents the LLM from wasting iterations on tools
that can only return errors.

| Provider | Env Vars | Tools | Hard Fail |
|----------|----------|-------|-----------|
| Shodan | `SHODAN_API_KEY` | `shodan_lookup` | Yes |
| VirusTotal | `VIRUSTOTAL_API_KEY` | `virustotal_subdomain_enum` | Yes |
| Censys | `CENSYS_API_ID`, `CENSYS_API_SECRET` | `censys_lookup` | Yes |
| HaveIBeenPwned | `HIBP_API_KEY` | `analyze_email` | No (graceful) |
| EmailRep | `EMAILREP_API_KEY` | `analyze_email` | No (graceful) |

**Hard fail = Yes:** Tool is removed entirely from the agent if key is missing.

**Hard fail = No:** Tool remains available. It degrades gracefully — some data
sources may be unavailable but others still work.
