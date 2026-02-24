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
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green.svg" />
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
       11 tools   Human-in-     2 tools      8 tools    LLM-as-   LLM
       (passive)  the-Loop      (active)     (active)   a-judge  synthesis
```

### Key features

| Feature | Description |
|---------|-------------|
| **Real ReAct agents** | Each specialist is a `create_react_agent` with its own system prompt, tools, and LLM. The model decides strategy, not code. |
| **5-phase pipeline** | OSINT → Port Scan → Vulnerability Scan → Triage → Report. Each phase builds on the previous. |
| **Human-in-the-loop** | An approval gate pauses before active scanning, showing discovered targets for operator review. |
| **LLM-as-a-judge** | A quality evaluator scores each phase and drives adaptive routing — skip empty phases, adjust strategy for partial results. |
| **Real-time observability** | Watch tool calls, results, errors, and LLM reasoning stream to the terminal as they happen. |
| **Input validation rails** | Every tool validates its inputs (target type, shell metacharacters) before executing — code-level enforcement, not just prompt instructions. |
| **Per-agent model config** | Assign different models to different agents via environment variables. |
| **Automatic provider gating** | Tools requiring API keys are auto-removed when keys are missing, preventing wasted LLM calls. |
| **Two-tier prompting** | Shared soul prompt (identity + anti-hallucination rules) + task-specific skill prompts per phase. |
| **Dual reports** | Concise LLM report on console + comprehensive archival report saved to disk. |

---

## Quick start

### Requirements

| Requirement | Notes |
|-------------|-------|
| Python 3.12+ | Required |
| [`uv`](https://docs.astral.sh/uv/) or `pip` | Package manager |
| OpenAI API key | Or any compatible provider (Azure, Anthropic via LangChain) |
| `naabu`, `nmap` | For port scanning (active scan) |
| `nuclei`, `httpx`, `katana`, `subfinder` | For vulnerability scanning (optional) |

See [docs/tools.md](docs/tools.md) for the full list of required binaries per tool.

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
                     │   osint_node    │ ← 11 passive tools
                     │  (ReAct agent)  │   dns, whois, subdomains, etc.
                     └────────┬────────┘
                              │
                    ┌─────────▼─────────┐
                    │  route_after_osint │
                    │  (conditional)     │
                    └──┬─────────────┬──┘
                       │             │
          active_scan  │             │  no active scan
          + IPs found  │             │  or no IPs
                       ▼             │
              ┌────────────────┐     │
              │ approval_gate  │     │
              │ (HitL interrupt)│    │
              └───┬────────┬───┘     │
          approve │        │ reject  │
                  ▼        └────┐    │
           ┌────────────┐      │    │
           │ port_scan   │      │    │
           │ (ReAct)     │      │    │
           └─────┬───────┘      │    │
                 │              │    │
       ┌─────────▼──────────┐   │    │
       │route_after_port_scan│  │    │
       │(LLM-as-a-judge)    │  │    │
       └──┬──────────────┬──┘  │    │
          │              │     │    │
          ▼              ▼     │    │
   ┌────────────┐  ┌─────────┐│    │
   │ vuln_scan  │  │ triage  ││    │
   │ (ReAct)    │  │(struct) │◄    │
   └─────┬──────┘  └────┬────┘     │
         │              │          │
         ▼              │          │
   ┌──────────┐         │          │
   │  triage  │         │          │
   │ (struct) │         │          │
   └─────┬────┘         │          │
         │              │          │
         ▼              ▼          ▼
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
│ Proceed with active scanning?                             │
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
| **OSINT** | ReAct | 11 tools | Passive reconnaissance — DNS, WHOIS, subdomains, reverse DNS, Shodan/Censys, job search, email analysis |
| **Port Scan** | ReAct | 2 tools | Active scanning — discover open ports (`naabu`) and fingerprint services (`nmap`) |
| **Vuln Scan** | ReAct | 8 tools | Vulnerability scanning — Nuclei templates, HTTP tech detection, WAF detection, web crawling, TLS analysis |
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
| `job_search` | *(free text)* | — | OSINT |
| `analyze_email` | *(email)* | `HIBP_API_KEY` / `EMAILREP_API_KEY` | OSINT |
| `naabu_scan` | HOST | `naabu` binary | Port Scan |
| `nmap_port_scan` | HOST | `nmap` binary | Port Scan |
| `nuclei_scan` | DOMAIN | `nuclei` binary | Vuln Scan |
| `httpx_scan` | HOST_OR_URL | `httpx` binary | Vuln Scan |
| `wafw00f_detect` | HOST_OR_URL | `wafw00f` binary | Vuln Scan |
| `graphql_scan` | URL | — | Vuln Scan |
| `feroxbuster_scan` | HOST_OR_URL | `feroxbuster` binary | Vuln Scan |
| `katana_crawl` | HOST_OR_URL | `katana` binary | Vuln Scan |
| `testssl_scan` | HOST | `testssl.sh` binary | Vuln Scan |
| `extract_webpage_content` | URL | — | Vuln Scan |

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
| `HIBP_API_KEY` | No | `analyze_email` (graceful degradation) |
| `EMAILREP_API_KEY` | No | `analyze_email` (graceful degradation) |

Tools with missing API keys (and `hard_fail=True`) are **automatically removed**
from agents, preventing the LLM from attempting calls that would fail.

### Infrastructure (optional)

```bash
# Start MongoDB + Langfuse observability stack
docker compose up -d
```

The `docker-compose.yml` provides:
- **MongoDB 7** — scan persistence and query system
- **Langfuse 3** — LLM observability, cost tracking, prompt management
- **ClickHouse** — Langfuse analytics backend
- **PostgreSQL 17** — Langfuse metadata
- **Redis 7** — Langfuse queue
- **MinIO** — Langfuse blob storage

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
# src/tools/my_tool.py
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .utils import format_tool_output
from .validators import TargetType, guard_target


class MyToolInput(BaseModel):
    target: str = Field(description="Domain or IP to scan.")

@tool(args_schema=MyToolInput)
def my_recon_tool(target: str) -> dict:
    """Describe what this tool does — the LLM reads this docstring."""
    target, err = guard_target(target, "my_recon_tool", TargetType.HOST)
    if err:
        return err

    # ... implementation ...
    return format_tool_output("my_recon_tool", target, "success", data=result)
```

2. Import and add it to the relevant agent's tools list.

3. The LLM will autonomously decide when and how to use it based on
   its docstring and the agent's system prompt.

See [docs/development.md](docs/development.md) for the full development guide.

---

## Project structure

```
src/
├── cli/
│   └── main.py                      # Typer CLI with real-time Rich rendering
├── fackel/
│   ├── agents/
│   │   ├── config.py                # Per-agent model selection (env vars)
│   │   ├── prompts/
│   │   │   ├── __init__.py          # Prompt loader with caching
│   │   │   ├── soul.md              # Shared agent identity + rules
│   │   │   └── skills/
│   │   │       ├── osint.md         # OSINT playbook
│   │   │       ├── port_scan.md     # Port scan strategy
│   │   │       ├── vuln_scan.md     # Vuln scan playbook
│   │   │       ├── triage.md        # Coverage gap analysis
│   │   │       ├── report.md        # Report writing rules
│   │   │       └── judge.md         # Quality scoring guide
│   │   ├── orchestrator/
│   │   │   ├── state.py             # ScanState (TypedDict + reducers)
│   │   │   ├── nodes.py             # Graph nodes + event streaming
│   │   │   ├── graph.py             # StateGraph definition + routing
│   │   │   ├── main.py              # Public API: run()
│   │   │   └── evaluator.py         # LLM-as-a-judge quality scoring
│   │   ├── osint/agent.py           # OSINT ReAct agent (11 tools)
│   │   ├── port_scan/agent.py       # Port scan ReAct agent (2 tools)
│   │   ├── vuln_scan/agent.py       # Vuln scan ReAct agent (8 tools)
│   │   ├── triage/agent.py          # Triage structured output
│   │   └── report/agent.py          # Report synthesis
│   ├── provider_keys.py             # API key gating + tool filtering
│   ├── report_writer.py             # Full archival report builder
│   └── utils/
│       ├── network.py               # is_valid_ip, is_valid_domain
│       └── target.py                # extract_host, sanitize_target
└── tools/
    ├── validators.py                # TargetType enum + guard_target()
    ├── utils.py                     # run_command, format_tool_output, etc.
    └── *.py                         # 25 tool wrappers
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/architecture.md](docs/architecture.md) | System architecture, graph flow, state management, prompt system |
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

MIT — see [LICENSE](LICENSE).
