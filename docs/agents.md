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
from langchain.agents import create_agent

from fackel.agents.config import build_llm, default_middleware
from fackel.agents.prompts import load_prompt
from fackel.provider_keys import filter_tools

def build(model_name: str | None = None, *, approve_tools: bool = False) -> CompiledStateGraph:
    llm = build_llm("agent_name", model_name=model_name)
    tools = [tool_a, tool_b, ...]
    available, skipped = filter_tools(tools)
    return create_agent(
        llm,
        available,
        system_prompt=load_prompt("skill_name"),
        middleware=default_middleware(approve_tools=approve_tools),
        checkpointer=MemorySaver() if approve_tools else None,
        name="agent_name",
    )
```

Key points:
- **Model factory** — `build_llm("agent_name")` centralises model creation, resolves `FACKEL_PROVIDER_{AGENT_NAME}` and `FACKEL_MODEL_{AGENT_NAME}` env vars, dispatches to the appropriate provider (OpenAI, Ollama, etc.), and applies a standard timeout.
- **Prompt composition** — `load_prompt()` combines `soul.md` (shared identity) with `skills/<name>.md` (task-specific).
- **Tool filtering** — `filter_tools()` removes tools whose API keys are missing.
- **Agent naming** — `name="agent_name"` gives each agent an identifiable name in LangSmith traces.
- **ReAct loop** — `create_agent` implements the full Think → Act → Observe cycle.
- **Error handling** — all tools raise `ToolException` on errors with `handle_tool_error = True`, so the LLM sees clean error messages as tool results.
- **Circuit breaker** — HTTP-based tools are wrapped in per-service circuit breakers that disable flaky APIs after 3 consecutive failures.
- **Middleware stack** — `default_middleware()` applies:
  - **ParallelToolCalls** — injects `parallel_tool_calls=True` so independent tools execute concurrently.
  - **ToolRetryMiddleware** — retries transient network errors (ConnectionError, TimeoutError, OSError) with exponential backoff.
  - **HumanInTheLoopMiddleware** *(opt-in)* — when `approve_tools=True`, interrupts before active scanning tools for per-call human approval.
- **Streaming** — agents use dual `stream_mode=["updates", "messages"]` for reliable message collection and real-time token streaming via `_AgentStreamer` in `streaming.py`.
- **RunnableConfig propagation** — orchestrator config (callbacks, metadata, tags) is forwarded to inner agents for nested LangSmith traces.
- **Structured output** — the triage agent uses `response_format=TriageResult` for typed responses.

---

## OSINT agent

**Purpose:** Passive reconnaissance — map the target's external footprint
without sending any probe packets.

**File:** `src/fackel/agents/osint/agent.py`

**Model env var:** `FACKEL_MODEL_OSINT`

### Tools (27)

| Tool | Purpose |
|------|---------||
| `dns_resolve` | Resolve domain to IPs (A + AAAA records) |
| `whois_lookup` | Registration data — registrar, dates, nameservers |
| `shodan_lookup` | Passive service/banner data from Shodan |
| `censys_lookup` | Host/service search via Censys |
| `fofa_search` | Passive asset search engine — hosts, ports, services, tech |
| `dnsdumpster_lookup` | Subdomain enum + DNS/MX/NS/TXT records |
| `virustotal_subdomain_enum` | Passive subdomain discovery |
| `crtsh_subdomain_enum` | Subdomain enum via Certificate Transparency |
| `subfinder_enum` | Aggregate 40+ passive sources for subdomains |
| `gau_urls` | Passive URL discovery — Wayback Machine, Common Crawl, OTX |
| `reverse_dns_lookup` | PTR records + reverse IP for shared hosting |
| `ipinfo_lookup` | IP geolocation, ASN, organisation via ipinfo.io |
| `bgp_lookup` | ASN/prefix lookup via RIPEstat for BGP context |
| `cloudbrute_enum` | Cloud resource discovery — S3, Azure, GCP, DO buckets/apps |
| `httpx_scan` | HTTP probing + technology fingerprinting |
| `tlscert_lookup` | TLS certificate inspection + SAN subdomain discovery |
| `securitytrails_history` | Historical DNS records — reveals old IPs and hosting changes |
| `urlscan_search` | Cached scan results from Urlscan.io community scans |
| `otx_passive_dns` | Passive DNS records via AlienVault OTX |
| `job_search` | Job posting search for tech stack discovery |
| `analyze_email` | Email breach exposure and reputation scoring |
| `amass_enum` | Deep subdomain enumeration via OWASP Amass (40+ sources) |
| `subzy_check` | Subdomain takeover detection (dangling CNAMEs) |
| `paramspider_crawl` | URL parameter discovery from web archives |
| `whatweb_scan` | Web technology fingerprinting (CMS, frameworks, JS libs) |
| `linkfinder_extract` | JavaScript endpoint and API route extraction |
| `trufflehog_scan` | Git repository secret/credential leak scanning |

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
8. **Shodan / Censys / FOFA** — passive service data for each IP (if API keys available)
9. **Historical DNS** — `securitytrails_history` for old IPs that may bypass CDN (if API key available)
10. **URLScan** — `urlscan_search` for cached scan results and technology fingerprints
11. **Passive DNS** — `otx_passive_dns` for AlienVault OTX passive DNS records (if API key available)
12. **HTTP probing** — `httpx_scan` for technology detection and HTTP surface mapping
13. **URL discovery** — `gau_urls` for passive URL discovery from Wayback Machine, Common Crawl, OTX
14. **Job search** — `job_search` with company name for tech stack intelligence
15. **Email analysis** — `analyze_email` if email addresses discovered
16. **Cloud enumeration** — `cloudbrute_enum` with company/brand keyword for S3/Azure/GCP/DO resources
17. **Web tech fingerprinting** — `whatweb_scan` for CMS, frameworks, server software
18. **Parameter discovery** — `paramspider_crawl` for hidden URL parameters from web archives
19. **JS endpoint extraction** — `linkfinder_extract` for API routes in JavaScript files
20. **Secret scanning** — `trufflehog_scan` on GitHub repos/orgs for leaked credentials
21. **Subdomain takeover** — `subzy_check` for dangling CNAME records on discovered subdomains
22. **Structured summary** — emit findings with evidence citations

### Node post-processing

After the agent completes, `osint_node` in `nodes/osint.py`:

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

### Tools (12)

| Tool | Purpose |
|------|---------||
| `nuclei_scan` | Vulnerability/misconfiguration templates (community-maintained) |
| `dalfox_scan` | XSS vulnerability scanner — reflected, stored, DOM-based |
| `httpx_scan` | HTTP probing and technology fingerprinting |
| `wafw00f_detect` | Web Application Firewall detection |
| `graphql_scan` | GraphQL endpoint security testing |
| `feroxbuster_scan` | Recursive directory/content discovery |
| `katana_crawl` | Web crawling for URL/endpoint discovery |
| `s3scanner_scan` | S3 bucket permission audit — public read/write/list |
| `testssl_scan` | TLS/SSL protocol, cipher, and vulnerability analysis |
| `extract_webpage_content` | Web page content extraction |
| `wpscan_scan` | WordPress vulnerability scanner (plugins, themes, users, core) |
| `corsy_scan` | CORS misconfiguration detection |

### Playbook (from `skills/vuln_scan.md`)

1. **Domain nuclei** — run `nuclei_scan` on main domain first (broadest coverage)
2. **HTTP surface + WAF** — `httpx_scan` for tech detection, `wafw00f_detect` for WAF
3. **Deep-dive on findings** — if nuclei finds GraphQL, run `graphql_scan`
4. **Web discovery** — `katana_crawl` + `feroxbuster_scan` for hidden endpoints
5. **XSS testing** — `dalfox_scan` on URLs with query parameters from crawling/discovery
6. **TLS analysis** — `testssl_scan` for protocol/cipher vulnerabilities
7. **Cloud storage** — `s3scanner_scan` if bucket names found in code, JS, or findings
8. **Page content** — `extract_webpage_content` for interesting pages
9. **CORS testing** — `corsy_scan` on API endpoints for CORS misconfigurations
10. **WordPress** — `wpscan_scan` if WordPress is detected (conditional)
11. **Subdomain scans** — run `nuclei_scan` per subdomain
12. **Structured summary** — emit findings with evidence

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

### Type: `create_agent` with `response_format` (no tools)

Uses `create_agent(llm, [], response_format=TriageResult, name="triage")` for
structured output. The typed result is accessed via `result["structured_response"]`.

### Output model

```python
class UnassessedArea(BaseModel):
    technology: str      # What was found
    detected_by: str     # Which tool detected it
    reason: str          # Why it wasn't assessed
    recommendation: str  # What should be done

class RiskScore(BaseModel):
    score: float         # 0-10 exposure risk score
    exposure_type: str   # critical / high / moderate / low / minimal
    factors: list[str]   # Evidence-backed risk factors

class TriageResult(BaseModel):
    technologies_detected: list[str]
    unassessed_areas: list[UnassessedArea]
    risk_score: RiskScore
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

Uses a single LLM invocation (via `build_llm`) with all accumulated context serialised as
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

Uses `build_llm("judge").with_structured_output(PhaseEvaluation)`.

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

## Operator guidance (`--guided`)

When running with `--guided`, the pipeline pauses before each major agent
phase and offers the operator a free-text prompt. The guidance is injected
into the agent's prompt as a priority directive under the heading
`--- Operator Guidance ---`.

### Guidance gates

| Gate | Fires before | Description shown to operator |
|------|-------------|-------------------------------|
| `osint_guidance` | OSINT | Passive recon scope — what to focus on, tools to skip |
| `port_scan_guidance` | Port Scan | Host priority, scan depth, ports of interest |
| `vuln_scan_guidance` | Vuln Scan | Vulnerability types, technologies, tools to prefer/skip |

### Implementation

Guidance gates are lightweight graph nodes in
`src/fackel/agents/orchestrator/nodes/_guidance.py`. Each gate:

1. Checks `is_guidance_enabled()` — if disabled, returns `{}` immediately
   (no interrupt, no UX disruption).
2. If enabled, calls `interrupt()` with phase context.
3. The CLI shows a Rich Panel and collects free-text input.
4. The text is stored in `phase_guidance[phase]` in the graph state.
5. The downstream node reads it via `get_phase_guidance(state, phase)` and
   appends it to the agent prompt.

### State field

```python
phase_guidance: dict[str, str]
# e.g. {"osint": "focus on subdomains", "vuln_scan": "skip wpscan"}
```

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
| Censys | `CENSYS_API_ID`, `CENSYS_API_SECRET` | `censys_lookup` | Yes |\n| WPScan | `WPSCAN_API_TOKEN` | `wpscan_scan` | Yes |
| HaveIBeenPwned | `HIBP_API_KEY` | `analyze_email` | No (graceful) |
| EmailRep | `EMAILREP_API_KEY` | `analyze_email` | No (graceful) |

**Hard fail = Yes:** Tool is removed entirely from the agent if key is missing.

**Hard fail = No:** Tool remains available. It degrades gracefully — some data
sources may be unavailable but others still work.
