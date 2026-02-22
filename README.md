# Fackel

<p align="center">
  <img width="256" height="256" alt="Fackel logo" src="https://github.com/user-attachments/assets/28ce2f9c-e7d0-41da-83c7-b8bdb3fe542d" />
</p>

<p align="center">
  <strong>Autonomous pentest framework powered by ReAct agents.</strong><br>
  LLM-driven reconnaissance, port scanning, and report generation.
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
Target → OSINT Agent → [Port Scan Agent] → Report Agent → Markdown Report
              ↕                 ↕                ↕
          dns_resolve      naabu_scan         LLM synthesis
                           nmap_port_scan
```

### Key features

- **Real ReAct agents** — each specialist is a `create_react_agent` with its own
  system prompt, tools, and LLM. The model decides strategy, not code.
- **Real-time observability** — watch tool calls, results, and LLM reasoning
  stream to the terminal as they happen.
- **Conditional routing** — the orchestrator graph skips port scanning when
  `--no-active-scan` or no IPs are discovered.
- **Per-agent model config** — assign different models to different agents via
  environment variables.
- **Checkpointed state** — LangGraph `MemorySaver` tracks state across nodes.

---

## Quick start

### Requirements

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) (recommended) or `pip`
- An OpenAI API key (or compatible provider)
- For active scanning: `naabu` and `nmap` binaries

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
# Edit .env and set OPENAI_API_KEY at minimum
```

### Run

```bash
# Passive scan (OSINT only → report)
fackel example.com --no-active-scan

# Full scan (OSINT → port scan → report)
fackel example.com

# Verbose mode — see LLM reasoning in real time
fackel example.com -v

# Save report to file
fackel example.com -o report.md
```

---

## CLI output

Standard mode shows tool calls and results:

```
Target: eversafe.info
Active scan: yes

────────────────────────────────────────────────────────────
▶ OSINT
────────────────────────────────────────────────────────────
  🔧 Calling: dns_resolve(target=eversafe.info)
  ← dns_resolve: {"ips": ["104.21.36.250", "172.67.201.157", ...]}
  ✓ OSINT complete

────────────────────────────────────────────────────────────
▶ Port Scan
────────────────────────────────────────────────────────────
  🔧 Calling: naabu_scan(host=104.21.36.250)
  🔧 Calling: naabu_scan(host=172.67.201.157)
  ← naabu_scan: {"port": 8080, "protocol": "tcp", ...}
  ← naabu_scan: {"port": 8443, "protocol": "tcp", ...}
  🔧 Calling: nmap_port_scan(host=104.21.36.250)
  🔧 Calling: nmap_port_scan(host=172.67.201.157)
  ← nmap_port_scan: {"port": 80, "service": "http", "product": "Cloudflare", ...}
  ← nmap_port_scan: {"port": 443, "service": "https", ...}
  ✓ Port Scan complete

────────────────────────────────────────────────────────────
▶ Report
────────────────────────────────────────────────────────────
  ✓ Report complete
════════════════════════════════════════════════════════════
# Pentest Report for eversafe.info
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

## Architecture

### Orchestrator graph (LangGraph)

```
                     ┌─────────────────┐
                     │   osint_node    │
                     │  (ReAct agent)  │
                     └────────┬────────┘
                              │
                    ┌─────────▼─────────┐
                    │  route_after_osint │
                    │  (conditional)     │
                    └──┬─────────────┬──┘
                       │             │
          active_scan  │             │  no active scan
          + IPs found  │             │  or no IPs
                       ▼             ▼
              ┌────────────┐  ┌────────────┐
              │ port_scan  │  │   report   │
              │ (ReAct)    │  │   (LLM)    │
              └─────┬──────┘  └─────┬──────┘
                    │               │
                    ▼               │
              ┌────────────┐       │
              │   report   │       │
              │   (LLM)    │       │
              └─────┬──────┘       │
                    │               │
                    ▼               ▼
                   END             END
```

### Specialist agents

| Agent | Type | Tools | Purpose |
|-------|------|-------|---------|
| **OSINT** | ReAct | `dns_resolve` | Passive reconnaissance — resolve domains, discover IPs |
| **Port Scan** | ReAct | `naabu_scan`, `nmap_port_scan` | Active scanning — discover open ports and services |
| **Report** | LLM chain | *(none)* | Synthesize findings into a Markdown pentest report |

Each ReAct agent uses `create_react_agent(llm, tools, prompt=SYSTEM_PROMPT)` from
LangGraph. The LLM autonomously decides which tools to invoke, in what order, and
when to stop.

### Project structure

```
src/
├── cli/
│   └── main.py                  # Typer CLI with real-time event rendering
├── fackel/
│   ├── agents/
│   │   ├── config.py            # Centralized model configuration
│   │   ├── orchestrator/
│   │   │   ├── state.py         # ScanState (5 fields)
│   │   │   ├── nodes.py         # Graph nodes + event streaming
│   │   │   ├── graph.py         # StateGraph definition + checkpointer
│   │   │   └── main.py          # Public API: run(), run_stream()
│   │   ├── osint/
│   │   │   └── agent.py         # OSINT ReAct agent
│   │   ├── port_scan/
│   │   │   └── agent.py         # Port scan ReAct agent
│   │   └── report/
│   │       └── agent.py         # Report generation (LLM chain)
│   └── domain/
│       ├── enums.py
│       └── models.py
└── tools/
    ├── dns_resolver.py          # DNS lookup tool
    ├── naabu_tool.py            # Fast TCP port scanner
    ├── nmap_scanner.py          # Detailed port/service scanner
    ├── shodan_tool.py           # Shodan passive lookup
    ├── virustotal_tool.py       # VirusTotal API
    └── ...                      # 20+ additional tools
```

### ScanState

Minimal shared state passed through the graph:

```python
class ScanState(TypedDict):
    target: str               # Domain or IP provided by the user
    active_scan: bool         # Whether active scanning is permitted
    discovered_ips: list[str] # IPs found during OSINT
    findings: list[str]       # Agent summaries (append-only reducer)
    report: str               # Final Markdown report
```

---

## Configuration

### Model per agent

Each agent reads its model from an environment variable, falling back to
`gpt-4o-mini`:

| Variable | Agent | Default |
|----------|-------|---------|
| `FACKEL_MODEL_OSINT` | OSINT agent | `gpt-4o-mini` |
| `FACKEL_MODEL_PORT_SCAN` | Port scan agent | `gpt-4o-mini` |
| `FACKEL_MODEL_REPORT` | Report generator | `gpt-4o-mini` |

```bash
# Use a more capable model for report generation
export FACKEL_MODEL_REPORT=gpt-4o
```

### API keys

| Variable | Required | Used by |
|----------|----------|---------|
| `OPENAI_API_KEY` | **Yes** | All agents (LLM) |
| `SHODAN_API_KEY` | No | Shodan tool |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal tool |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | No | Censys tool |
| `SERPAPI_API_KEY` | No | SerpAPI / LinkedIn tool |

Verify key status:

```bash
fackel --check-providers example.com --no-active-scan
```

### Infrastructure (optional)

```bash
# Start MongoDB + Langfuse observability stack
docker compose up -d
```

---

## Python API

```python
from fackel.agents.orchestrator import run, run_stream

# Blocking — returns final state
result = run("example.com", active_scan=True)
print(result["report"])

# Streaming — yields (node_name, partial_update) per step
for node, update in run_stream("example.com", active_scan=False):
    print(f"[{node}] {list(update.keys())}")
```

---

## Adding new tools

1. Create a new file in `src/tools/` with a `@tool`-decorated function:

```python
# src/tools/my_tool.py
from langchain_core.tools import tool

@tool
def my_recon_tool(target: str) -> dict:
    """Describe what this tool does — the LLM reads this docstring."""
    # ... implementation ...
    return {"target": target, "data": result}
```

2. Import and add it to the relevant agent's `TOOLS` list:

```python
# src/fackel/agents/osint/agent.py
from tools.my_tool import my_recon_tool

TOOLS = [dns_resolve, my_recon_tool]  # Agent now has access to it
```

The LLM will autonomously decide when and how to use the new tool based on its
docstring and the agent's system prompt.

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
```

---

## Roadmap

- [ ] Additional OSINT tools (whois, subdomain enumeration, certificate transparency)
- [ ] Web vulnerability scanning agent (nuclei, httpx, katana)
- [ ] Persistent checkpointer (SQLite/PostgreSQL) for scan resume
- [ ] REST API for programmatic access
- [ ] Langfuse integration for LLM observability and cost tracking
- [ ] Human-in-the-loop approval before active scanning

---

## License

MIT.
