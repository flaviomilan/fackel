# Development Guide

Everything you need to start contributing to Fackel: environment setup, coding
standards, adding tools and agents, testing, linting, and project conventions.

---

## Table of contents

- [Prerequisites](#prerequisites)
- [Environment setup](#environment-setup)
- [Project structure](#project-structure)
- [Project rules](#project-rules)
- [Adding a new tool](#adding-a-new-tool)
- [Adding a new agent](#adding-a-new-agent)
- [Linting](#linting)
- [Type checking](#type-checking)
- [Testing](#testing)

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | ≥ 3.12 |
| [uv](https://github.com/astral-sh/uv) | Latest |
| Docker & Compose | For infrastructure stack |
| Go | For `httpx`, `katana`, `nuclei`, `naabu`, `amass`, `subzy` binaries |
| Ruby (gem) | For `wpscan`, `whatweb` binaries |
| Nmap | For `nmap_scan` tool |

## Environment setup

```bash
# Clone the repository
git clone <repo-url> && cd fackel

# Install all dependencies (including dev extras)
uv sync --extra dev

# Verify installation
uv run fackel --help

# Copy .env template and fill in your API keys
cp .env.example .env
# Edit .env with your OPENAI_API_KEY at minimum

# (Optional) Start infrastructure stack
docker compose up -d
```

### External binaries

Several tools shell out to Go-based or native binaries. Use the automated
installer to set everything up:

```bash
# Install all external binaries
./scripts/install-tools.sh

# Core tools only (nmap, naabu, nuclei, httpx, subfinder)
./scripts/install-tools.sh --minimal

# Audit — check what's installed/missing
./scripts/install-tools.sh --check
```

Or install manually:

```bash
# Go-based tools (require 'go' in PATH)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/0xsha/CloudBrute@latest   # symlink CloudBrute → cloudbrute
go install github.com/sa7mon/S3Scanner@latest    # symlink S3Scanner → s3scanner
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/PentestPad/subzy@latest

# Rust-based tools
cargo install feroxbuster

# Python-based tools
pipx install wafw00f   # or: pip install wafw00f
pipx install paramspider
pipx install trufflehog
pipx install corsy
pipx install linkfinder

# Ruby-based tools (require gem)
gem install wpscan
gem install whatweb     # or: apt install whatweb

# System packages
sudo apt install nmap whois     # Debian/Ubuntu
brew install nmap whois         # macOS

# testssl.sh (git clone + symlink)
git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/.local/share/testssl
ln -sf ~/.local/share/testssl/testssl.sh ~/.local/bin/testssl.sh
```

---

## Project structure

```
src/
├── fackel/
│   ├── agents/
│   │   ├── config.py           # build_llm(), get_model(), default_middleware()
│   │   ├── prompts/
│   │   │   ├── __init__.py      # Prompt loader with caching
│   │   │   ├── soul.md          # Shared agent identity + rules
│   │   │   └── skills/          # Per-agent skill prompts
│   │   ├── orchestrator/       # LangGraph graph
│   │   │   ├── graph.py        # build_graph() — node + edge wiring
│   │   │   ├── nodes/           # Node functions (one file per phase)
│   │   │   │   ├── osint.py     # osint_node(state, config)
│   │   │   │   ├── port_scan.py # port_scan_node(state, config)
│   │   │   │   ├── vuln_scan.py # vuln_scan_node(state, config)
│   │   │   │   ├── triage.py    # triage_node(state, config)
│   │   │   │   └── report_and_gates.py  # report + gate nodes
│   │   │   ├── streaming.py    # _AgentStreamer, run_and_stream_agent()
│   │   │   ├── extractors.py   # Post-processing helpers (IPs, subdomains)
│   │   │   ├── state.py        # ScanState TypedDict + reducers
│   │   │   ├── main.py         # run() entry point
│   │   │   └── evaluator.py    # LLM-as-a-judge (PhaseEvaluation)
│   │   ├── osint/agent.py      # OSINT ReAct agent (27 tools)
│   │   ├── port_scan/agent.py  # Port scan ReAct agent (2 tools)
│   │   ├── vuln_scan/agent.py  # Vuln scan ReAct agent (12 tools)
│   │   ├── triage/agent.py     # Triage structured output
│   │   └── report/agent.py     # Report synthesis
│   ├── tooling/
│   │   ├── validators.py       # guard_target(), TargetType (raises ToolException)
│   │   ├── execution.py        # run_command(), require_binary(), get_tool_timeout()
│   │   ├── sanitizers.py       # Input sanitisation helpers
│   │   ├── ip_classifier.py    # IP classification (CDN, cloud, hosting)
│   │   └── ddgs.py             # DuckDuckGo search wrapper
│   ├── provider_keys.py        # API key gating + tool filtering
│   └── report_writer.py        # Full archival report builder
├── tools/
│   ├── circuit_breaker.py      # Per-service circuit breaker for HTTP tools
│   ├── recon/                  # 22 passive reconnaissance tools
│   ├── osint/                  # 3 open-source intelligence tools
│   ├── scanning/               # 7 active scanning tools
│   └── vuln/                   # 5 vulnerability assessment tools
├── cli/                        # Terminal UI (Typer + Rich)
│   ├── main.py                 # Typer commands (scan, repl, scans, diff, graph, ask)
│   ├── harness.py              # Interactive REPL around the agent pipeline
│   ├── renderer.py             # Real-time event renderer (phases, lanes, tools)
│   ├── presenter.py            # Shared banner / scan header / report / approvals
│   ├── theme.py                # Glyphs (Nerd Font + ASCII) and colour tokens
│   ├── context_tracker.py      # Live token/context meter
│   └── session.py              # Cross-scan session memory
└── tests/
    └── *.py                    # pytest test files
```

**Key conventions:**

- One tool per file in `src/fackel/tools/{recon,osint,scanning,vuln}/`
- One agent builder per file in `src/fackel/agents/{osint,port_scan,vuln_scan,triage,report}/`
- Orchestrator graph logic isolated in `src/fackel/agents/orchestrator/`
- Tool infrastructure (validators, execution, sanitizers) in `src/fackel/tooling/`
- Prompts in Markdown — `soul.md` (shared) + `skills/*.md` (per-agent)

---

## Project rules

Coding standards, code style, anti-patterns, the domain glossary, persistence
rules and the AI review checklist live in a single place:
[`.github/instructions/`](../.github/instructions/). Read them before changing
domain, persistence or tool code; they are not repeated here.

| Topic | File |
|-------|------|
| Architecture and domain model | `project-architecture.instructions.md` |
| Standards and style | `coding-standards.instructions.md` |
| Anti-patterns | `anti-patterns.instructions.md` |
| Ubiquitous language | `domain-glossary.instructions.md` |
| Persistence | `persistence-rules.instructions.md` |
| Review checklist | `ai-review-checklist.instructions.md` |

---

## Adding a new tool

Follow the wiring checklist in
[`.claude/skills/adding-a-tool/SKILL.md`](../.claude/skills/adding-a-tool/SKILL.md)
(tool file, agent list, specialist, binary/API-key gating, prompts, docs, tests).
Copy the shape of an existing tool rather than a prose template:
`src/fackel/tools/recon/subzy_tool.py` (binary wrapper) or
`src/fackel/tools/recon/crtsh_tool.py` (HTTP API with circuit breaker).
Input rules: [input-validation.md](input-validation.md).

---

## Adding a new agent

### 1. Create the agent builder

```python
# src/fackel/agents/my_agent/agent.py
from langchain.agents import create_agent

from fackel.agents.config import build_llm, default_middleware
from fackel.provider_keys import filter_tools
from fackel.tools.recon.tool_a import tool_a
from fackel.tools.recon.tool_b import tool_b

TOOLS = [tool_a, tool_b]

def build(model_name: str | None = None, *, approve_tools: bool = False):
    llm = build_llm("my_agent", model_name=model_name)
    available, skipped = filter_tools(TOOLS)
    return create_agent(
        llm,
        available,
        system_prompt="...",  # Or load_prompt("my_agent")
        middleware=default_middleware(approve_tools=approve_tools),
        name="my_agent",
    )
```

### 2. Add a graph node

Create a file in `src/fackel/agents/orchestrator/nodes/`, e.g. `my_agent.py`:

```python
from langchain_core.runnables import RunnableConfig

from fackel.agents.my_agent.agent import build
from fackel.agents.orchestrator.state import ScanState
from fackel.agents.orchestrator.streaming import run_and_stream_agent

async def my_agent_node(state: ScanState, config: RunnableConfig) -> dict:
    agent = build()
    result = await run_and_stream_agent(
        agent, state, config, agent_label="My Agent"
    )
    return {"my_agent_output": result}
```

Key points:
- Node functions accept `(state, config: RunnableConfig)` — config carries LangSmith callbacks and metadata.
- Use `run_and_stream_agent()` from `fackel.agents.orchestrator.streaming` for consistent streaming and error handling.

### 3. Wire into the graph

In `src/fackel/agents/orchestrator/graph.py`, add the node and edges:

```python
graph.add_node("my_agent", run_my_agent)
graph.add_edge("previous_node", "my_agent")
graph.add_conditional_edges("my_agent", route_after_my_agent)
```

### 4. Update state

Add the new field to `ScanState` in `state.py`:

```python
class ScanState(TypedDict):
    # ... existing fields ...
    my_agent_output: Annotated[str, operator.add]
```

---

## Linting

Fackel uses **ruff** for linting and import sorting:

```bash
# Check for issues
uv run ruff check src/ tests/

# Auto-fix fixable issues
uv run ruff check --fix src/ tests/

# Format code
uv run ruff format src/ tests/
```

### Ruff configuration

From `pyproject.toml`:

```toml
[tool.ruff]
target-version = "py312"
line-length = 100
select = ["E", "F", "I", "B", "UP", "N", "S", "C4", "SIM", "RUF"]
ignore = ["E501"]

[tool.ruff.per-file-ignores]
"__init__.py" = ["F401"]
```

| Rule set | Coverage |
|----------|----------|
| `E` | pycodestyle errors |
| `F` | pyflakes |
| `I` | isort (import ordering) |
| `B` | flake8-bugbear |
| `UP` | pyupgrade (use modern Python) |
| `N` | pep8-naming |
| `S` | flake8-bandit (security) |
| `C4` | flake8-comprehensions |
| `SIM` | flake8-simplify |
| `RUF` | ruff-specific rules |

---

## Type checking

Fackel uses **mypy** in strict mode:

```bash
uv run mypy src/
```

### Mypy configuration

```toml
[tool.mypy]
python_version = "3.12"
strict = true
warn_unused_ignores = true
warn_return_any = true
warn_unreachable = true
disallow_untyped_defs = true
disallow_any_unimported = true
mypy_path = ["src"]
plugins = ["pydantic.mypy"]
exclude = ["tests/fixtures"]
```

All functions **must** have type annotations. The `pydantic.mypy` plugin
provides proper type checking for Pydantic models.

---

## Testing

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src --cov-report=term-missing

# Run specific test file
uv run pytest tests/test_vector_store.py

# Run with verbose output
uv run pytest -v
```

### Test configuration

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q"

[tool.coverage.run]
source = ["src"]
branch = true
```

### Writing tests

- Place tests in the `tests/` directory
- File naming: `test_<module>.py`
- Use `pytest` fixtures for setup/teardown
- Follow the same coding standards as production code
