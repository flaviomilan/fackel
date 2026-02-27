# Fackel

<p align="center">
  <img width="256" height="256" alt="Fackel logo" src="https://github.com/user-attachments/assets/28ce2f9c-e7d0-41da-83c7-b8bdb3fe542d" />
</p>

<p align="center">
  <strong>Autonomous pentest framework powered by ReAct agents.</strong><br>
  LLM-driven reconnaissance, scanning, triage, and report generation.
</p>

<p align="center">
  <img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12+-blue.svg" />
  <img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-green.svg" />
  <img alt="LangGraph" src="https://img.shields.io/badge/LangGraph-1.x-purple.svg" />
</p>

---

## What is Fackel?

Fackel is a multi-agent pentest framework where **LLMs decide what to do, not
hardcoded pipelines**. Each specialist agent uses the
[ReAct](https://arxiv.org/abs/2210.03629) pattern (Reason + Act) to autonomously
choose which tools to call, interpret results, and decide next steps.

```
Target → OSINT → Approval Gate → Port Scan → Vuln Scan → Triage → Report
           ↕          ↕              ↕            ↕          ↕        ↕
       27 tools  Human-in-     2 tools      12 tools   LLM-as-   LLM
       (passive)  the-Loop      (active)     (active)   a-judge  synthesis
```

### Key features

| Feature | Description |
|---------|-------------|
| **Real ReAct agents** | Each specialist is a `create_agent` with its own system prompt, tools, and LLM. The model decides strategy, not code. |
| **5-phase pipeline** | OSINT → Port Scan → Vulnerability Scan → Triage → Report. Each phase builds on the previous. |
| **Human-in-the-loop** | An approval gate pauses before active scanning, showing discovered targets for operator review. |
| **LLM-as-a-judge** | A quality evaluator scores each phase and drives adaptive routing — skip empty phases, adjust strategy for partial results. |
| **Real-time observability** | Watch tool calls, results, errors, and LLM reasoning stream to the terminal as they happen. |
| **Input validation rails** | Every tool validates its inputs (target type, shell metacharacters) via `guard_target()` — raises `ToolException` for code-level enforcement, not just prompt instructions. |
| **Resilient tool execution** | `ToolException` + `handle_tool_error` propagate clean errors to the LLM. Circuit breakers disable flaky HTTP services after repeated failures. Configurable per-tool timeouts via environment variables. |
| **Per-agent model config** | Assign different models to different agents via environment variables. |
| **Automatic provider gating** | Tools requiring API keys are auto-removed when keys are missing, preventing wasted LLM calls. |
| **Two-tier prompting** | Shared soul prompt (identity + anti-hallucination rules) + task-specific skill prompts per phase. |
| **Dual reports** | Concise LLM report on console + comprehensive archival report saved to disk. |
| **LangSmith tracing** | Set two env vars and all agent phases appear as hierarchical traces — token usage, tool I/O, latency, middleware activity. |

---

## Quick start

### Requirements

| Requirement | Notes |
|-------------|-------|
| Python 3.12+ | Required |
| [`uv`](https://docs.astral.sh/uv/) or `pip` | Package manager |
| OpenAI API key | Or any compatible provider (Azure, Anthropic via LangChain) |
| Go ≥ 1.21 | For most scanning binaries (optional — only needed for active scanning) |
| Ruby (gem) | For `wpscan`, `whatweb` (optional) |
| `naabu`, `nmap` | For port scanning (active scan) |
| `nuclei`, `httpx`, `katana`, `subfinder` | For vulnerability scanning (optional) |

See [docs/tools.md](docs/tools.md) for the full list of required binaries per tool.

#### Automated tool install

```bash
# Install all external binaries automatically
./scripts/install-tools.sh

# Core tools only (nmap, naabu, nuclei, httpx, subfinder)
./scripts/install-tools.sh --minimal

# Audit — check which tools are installed/missing
./scripts/install-tools.sh --check
```

### Install

```bash
# Clone and install
git clone https://github.com/your-org/fackel.git
cd fackel
uv sync --python 3.12
```

Or with pip:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

### Configure

```bash
cp .env.example .env
# Edit .env — OPENAI_API_KEY is the only required key
```

### Run

```bash
# Passive scan (OSINT only → report)
fackel example.com --no-active-scan

# Full scan (OSINT → port scan → vuln scan → triage → report)
fackel example.com

# Verbose mode — see LLM reasoning in real time
fackel example.com -v

# Save report to a specific file
fackel example.com -o report.md

# Check which provider API keys are configured
fackel example.com --check-providers --no-active-scan
```

---

## Pipeline overview

```
                     ┌─────────────────┐
                     │   osint_node    │ ← 27 passive tools
                     │  (ReAct agent)  │   dns, whois, subdomains, etc.
                     └────────┬────────┘
                              │
                    ┌─────────▼──────────┐
                    │  route_after_osint │
                    │  (conditional)     │
                    └──┬─────────────┬───┘
                       │             │
          active_scan  │             │  no active scan
          + IPs found  │             │  or no IPs
                       ▼             │
              ┌─────────────────┐    │
              │ approval_gate   │    │
              │ (HitL interrupt)│    │
              └───┬────────┬────┘    │
          approve │        │ reject  │
                  ▼        └────┐    │
           ┌────────────┐       │    │
           │ port_scan   │      │    │
           │ (ReAct)     │      │    │
           └─────┬───────┘      │    │
                 │              │    │
       ┌─────────▼───────────┐  │    │
       │route_after_port_scan│  │    │
       │(LLM-as-a-judge)     │  │    │
       └──┬──────────────┬───┘  │    │
          │              │      │    │
          ▼              ▼      │    │
   ┌────────────┐  ┌─────────┐  │    │
   │ vuln_scan  │  │ triage  │  │    │
   │ (ReAct)    │  │(struct) │◄      │
   └─────┬──────┘  └────┬────┘       │
         │              │            │
         ▼              │            │
   ┌──────────┐         │            │
   │  triage  │         │            │
   │ (struct) │         │            │
   └─────┬────┘         │            │
         │              │            │
         ▼              ▼            ▼
   ┌──────────────────────────────────┐
   │           report_node            │
   │         (LLM synthesis)          │
   └──────────────┬───────────────────┘
                  │
                 END
```

Each phase is a LangGraph node. The orchestrator manages state flow, conditional
routing, and accumulates findings across phases.

See [docs/architecture.md](docs/architecture.md) for full architectural details.

---

## CLI output

Standard mode shows tool calls and results:

```
Target: eversafe.info
Active scan: yes

────────────────────────────────────────────────────────────
▶ OSINT
────────────────────────────────────────────────────────────
  🔧 dns_resolve(target=eversafe.info)
  🔧 whois_lookup(domain=eversafe.info)
  🔧 subfinder_enum(domain=eversafe.info, all_sources=True)
  🔧 crtsh_subdomain_enum(domain=eversafe.info)
  ✓ OSINT complete

──────────────────────────── ▶ Approval ────────────────────
╭──────────────── ⚠ Approval Required ─────────────────────╮
│ OSINT found 4 IP(s) and 5 subdomain(s).                  │
│ Proceed with active scanning?                            │
╰──────────────────────────────────────────────────────────╯
Approve? [Y/n]: y

────────────────────────────────────────────────────────────
▶ Port Scan
────────────────────────────────────────────────────────────
  🔧 naabu_scan(host=104.21.36.250, top_ports=1000)
  🔧 nmap_port_scan(host=104.21.36.250, ports=80,443)
  📊 Quality: complete (score: 0.9) → proceed
  ✓ Port Scan complete

────────────────────────────────────────────────────────────
▶ Vuln Scan
────────────────────────────────────────────────────────────
  🔧 nuclei_scan(target=eversafe.info)
  🔧 httpx_scan(domain=eversafe.info, tech_detect=True)
  🔧 wafw00f_detect(target=eversafe.info)
  📊 Quality: complete (score: 0.85) → proceed
  ✓ Vuln Scan complete

════════════════════════════════════════════════════════════
# Penetration Test Report for eversafe.info
...
Completed in 220.9s
```

With `-v` (verbose), LLM reasoning is also shown:

```
  💭 ### Structured Summary
  💭 **Domain:** eversafe.info
  💭 **Discovered IP Addresses:**
  💭 - 104.21.36.250
  💭 - 172.67.201.157
```

---

## Specialist agents

| Agent | Type | Tools | Purpose |
|-------|------|-------|---------|
| **OSINT** | ReAct | 27 tools | Passive reconnaissance — DNS, WHOIS, subdomains (subfinder, crt.sh, VirusTotal, Amass), reverse DNS, Shodan/Censys/FOFA, IP enrichment, TLS certs, historical DNS, passive URL discovery (gau), cloud resource enumeration (CloudBrute), web tech fingerprinting (WhatWeb), parameter discovery (ParamSpider), JS endpoint extraction (LinkFinder), subdomain takeover (Subzy), secret scanning (TruffleHog), job search, email analysis |
| **Port Scan** | ReAct | 2 tools | Active scanning — discover open ports (`naabu`) and fingerprint services (`nmap`) |
| **Vuln Scan** | ReAct | 12 tools | Vulnerability scanning — Nuclei templates, XSS detection (DalFox), HTTP tech detection, WAF detection, web crawling, S3 bucket audit, TLS analysis, WordPress scanning (WPScan), CORS misconfiguration (Corsy) |
| **Triage** | Structured LLM | *(none)* | Gap analysis — identify technologies found but not assessed, flag coverage gaps |
| **Report** | LLM chain | *(none)* | Synthesize all findings, evaluations, and gaps into a Markdown pentest report |
| **Judge** | Structured LLM | *(none)* | Quality evaluator — scores each phase (0.0–1.0) and recommends routing |

See [docs/agents.md](docs/agents.md) for detailed agent documentation.

---

## Tool inventory

| Tool | Target Type | Requires | Agent |
|------|------------|----------|-------|
| `dns_resolve` | HOST | — | OSINT |
| `whois_lookup` | DOMAIN | `whois` binary | OSINT |
| `shodan_lookup` | *(custom)* | `SHODAN_API_KEY` | OSINT |
| `censys_lookup` | HOST | `CENSYS_API_ID` + `CENSYS_API_SECRET` | OSINT |
| `dnsdumpster_lookup` | DOMAIN | — | OSINT |
| `virustotal_subdomain_enum` | DOMAIN | `VIRUSTOTAL_API_KEY` | OSINT |
| `crtsh_subdomain_enum` | DOMAIN | — | OSINT |
| `subfinder_enum` | DOMAIN | `subfinder` binary | OSINT |
| `reverse_dns_lookup` | IP | — | OSINT |
| `ipinfo_lookup` | IP | — | OSINT |
| `bgp_lookup` | IP | — | OSINT |
| `httpx_scan` | HOST_OR_URL | `httpx` binary | OSINT, Vuln Scan |
| `tlscert_lookup` | DOMAIN | — | OSINT |
| `securitytrails_history` | DOMAIN | `SECURITYTRAILS_API_KEY` | OSINT |
| `urlscan_search` | DOMAIN | — | OSINT |
| `otx_passive_dns` | DOMAIN | `OTX_API_KEY` | OSINT |
| `fofa_search` | *(custom)* | `FOFA_EMAIL` + `FOFA_KEY` | OSINT |
| `gau_urls` | DOMAIN | `gau` binary | OSINT |
| `cloudbrute_enum` | *(keyword)* | `cloudbrute` binary | OSINT |
| `job_search` | *(free text)* | — | OSINT |
| `analyze_email` | *(email)* | `HIBP_API_KEY` / `EMAILREP_API_KEY` | OSINT |
| `naabu_scan` | HOST | `naabu` binary | Port Scan |
| `nmap_port_scan` | HOST | `nmap` binary | Port Scan |
| `nuclei_scan` | DOMAIN | `nuclei` binary | Vuln Scan |
| `wafw00f_detect` | HOST_OR_URL | `wafw00f` binary | Vuln Scan |
| `graphql_scan` | URL | — | Vuln Scan |
| `feroxbuster_scan` | HOST_OR_URL | `feroxbuster` binary | Vuln Scan |
| `katana_crawl` | HOST_OR_URL | `katana` binary | Vuln Scan |
| `testssl_scan` | HOST | `testssl.sh` binary | Vuln Scan |
| `dalfox_scan` | HOST_OR_URL | `dalfox` binary | Vuln Scan |
| `s3scanner_scan` | *(bucket name)* | `s3scanner` binary | Vuln Scan |
| `extract_webpage_content` | URL | — | Vuln Scan |
| `amass_enum` | DOMAIN | `amass` binary | OSINT |
| `subzy_check` | DOMAIN | `subzy` binary | OSINT |
| `paramspider_crawl` | DOMAIN | `paramspider` binary | OSINT |
| `whatweb_scan` | HOST_OR_URL | `whatweb` binary | OSINT |
| `linkfinder_extract` | HOST_OR_URL | `linkfinder` binary | OSINT |
| `trufflehog_scan` | *(repo URL)* | `trufflehog` binary | OSINT |
| `wpscan_scan` | HOST_OR_URL | `wpscan` binary + `WPSCAN_API_TOKEN` | Vuln Scan |
| `corsy_scan` | HOST_OR_URL | `corsy` binary | Vuln Scan |

See [docs/tools.md](docs/tools.md) for complete tool reference with input schemas and validation rules.

---

## Configuration

### Model per agent

Each agent reads its model from an environment variable, falling back to
`gpt-5-mini`:

| Variable | Agent | Default |
|----------|-------|---------|
| `FACKEL_MODEL_OSINT` | OSINT agent | `gpt-5-mini` |
| `FACKEL_MODEL_PORT_SCAN` | Port scan agent | `gpt-5-mini` |
| `FACKEL_MODEL_VULN_SCAN` | Vuln scan agent | `gpt-5-mini` |
| `FACKEL_MODEL_TRIAGE` | Triage agent | `gpt-5-mini` |
| `FACKEL_MODEL_REPORT` | Report generator | `gpt-5-mini` |
| `FACKEL_MODEL_JUDGE` | Phase quality evaluator | `gpt-5-mini` |

```bash
# Use a more capable model for report generation
export FACKEL_MODEL_REPORT=gpt-4o
```

### API keys

| Variable | Required | Used by |
|----------|----------|---------|
| `OPENAI_API_KEY` | **Yes** | All agents (LLM) |
| `SHODAN_API_KEY` | No | `shodan_lookup` |
| `VIRUSTOTAL_API_KEY` | No | `virustotal_subdomain_enum` |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | No | `censys_lookup` |
| `FOFA_EMAIL` / `FOFA_KEY` | No | `fofa_search` |
| `SECURITYTRAILS_API_KEY` | No | `securitytrails_history` |
| `OTX_API_KEY` | No | `otx_passive_dns` |
| `HIBP_API_KEY` | No | `analyze_email` (graceful degradation) |
| `EMAILREP_API_KEY` | No | `analyze_email` (graceful degradation) |
| `WPSCAN_API_TOKEN` | No | `wpscan_scan` |

Tools with missing API keys (and `hard_fail=True`) are **automatically removed**
from agents, preventing the LLM from attempting calls that would fail.

### Infrastructure (optional)

```bash
# Start MongoDB persistence stack
docker compose up -d
```

The `docker-compose.yml` provides:
- **MongoDB 7** — scan persistence and query system

### Observability (optional)

Fackel uses **LangSmith** for LLM observability.  Set the env vars and all
agent traces appear automatically:

```bash
export LANGSMITH_TRACING=true
export LANGSMITH_API_KEY=lsv2_pt_...
export LANGSMITH_PROJECT=fackel
```

See [docs/configuration.md](docs/configuration.md) for full configuration reference.

---

## Python API

```python
from fackel.agents.orchestrator import run

# Blocking — returns final state
result = run("example.com", active_scan=True)
print(result["report"])
```

---

## Adding new tools

1. Create a new file in `src/tools/` with a `@tool`-decorated function and
   Pydantic input schema:

```python
# src/tools/recon/my_tool.py
from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target


class MyToolInput(BaseModel):
    target: str = Field(description="Domain or IP to scan.")

@tool(args_schema=MyToolInput)
def my_recon_tool(target: str) -> dict:
    """Describe what this tool does — the LLM reads this docstring."""
    target = guard_target(target, "my_recon_tool", TargetType.HOST)
    #  guard_target raises ToolException on invalid input

    # ... implementation ...
    return format_tool_output("my_recon_tool", target, "success", data=result)

# Enable LangChain error propagation — the LLM sees errors as tool results.
my_recon_tool.handle_tool_error = True  # type: ignore[attr-defined]
```

2. Import and add it to the relevant agent's tools list.

3. The LLM will autonomously decide when and how to use it based on
   its docstring and the agent's system prompt.

See [docs/development.md](docs/development.md) for the full development guide.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/architecture.md](docs/architecture.md) | System architecture, graph flow, state management, prompt system |
| [docs/prompts.md](docs/prompts.md) | Prompt system — soul, skills, templates, loader API, pipeline flow |
| [docs/agents.md](docs/agents.md) | Agent specifications, prompts, LLM-as-a-judge evaluator |
| [docs/tools.md](docs/tools.md) | Complete tool reference — schemas, validation, binaries |
| [docs/input-validation.md](docs/input-validation.md) | Input validation system — TargetType, guard_target, security |
| [docs/configuration.md](docs/configuration.md) | Environment variables, API keys, model selection, infrastructure |
| [docs/development.md](docs/development.md) | Contributing guide, adding tools, coding standards, testing |

---

## Development

```bash
# Install dev dependencies
uv sync --python 3.12 --extra dev

# Lint
uv run ruff check src/

# Type check
uv run mypy src/

# Tests
uv run pytest tests/

# Format
uv run ruff format src/
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
