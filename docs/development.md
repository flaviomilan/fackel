# Development Guide

Everything you need to start contributing to Fackel: environment setup, coding
standards, adding tools and agents, testing, linting, and project conventions.

---

## Table of contents

- [Prerequisites](#prerequisites)
- [Environment setup](#environment-setup)
- [Project structure](#project-structure)
- [Coding standards](#coding-standards)
  - [SOLID](#solid)
  - [YAGNI](#yagni)
  - [DRY](#dry)
  - [KISS](#kiss)
- [Code style](#code-style)
- [Domain glossary](#domain-glossary)
- [Anti-patterns](#anti-patterns)
- [Adding a new tool](#adding-a-new-tool)
- [Adding a new agent](#adding-a-new-agent)
- [Linting](#linting)
- [Type checking](#type-checking)
- [Testing](#testing)
- [Persistence rules](#persistence-rules)
- [AI review checklist](#ai-review-checklist)

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | ≥ 3.12 |
| [uv](https://github.com/astral-sh/uv) | Latest |
| Docker & Compose | For infrastructure stack |
| Go | For `httpx`, `katana`, `nuclei`, `naabu` binaries |
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

Several tools shell out to Go-based or native binaries. Install the ones you
need:

```bash
# Go-based tools (require 'go' in PATH)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/epi052/feroxbuster@latest

# System packages
sudo apt install nmap wafw00f whois     # Debian/Ubuntu
brew install nmap wafw00f whois         # macOS
```

---

## Project structure

```
src/
├── fackel/
│   ├── agents/
│   │   ├── config.py           # get_model(), create_agent()
│   │   ├── provider_keys.py    # API key gating, filter_tools()
│   │   ├── evaluator.py        # LLM-as-a-judge (PhaseEvaluation)
│   │   ├── report_writer.py    # Dual report generation
│   │   └── orchestrator/       # LangGraph graph
│   │       ├── graph.py        # build_graph() — node + edge wiring
│   │       ├── nodes.py        # Node functions (run_osint, run_port_scan, ...)
│   │       ├── state.py        # ScanState TypedDict + reducers
│   │       ├── main.py         # run(), run_stream() entry points
│   │       ├── config.py       # Orchestrator-level settings
│   │       └── workspace/
│   │           └── prompt.md   # Soul prompt (shared identity)
│   └── domain/
│       ├── models.py           # Pydantic domain models (Finding, TriageResult, etc.)
│       └── enums.py            # Domain enumerations
├── tools/
│   ├── validators.py           # guard_target(), TargetType enum
│   ├── utils.py                # run_command(), format_tool_output(), etc.
│   └── *.py                    # One file per tool
├── cli/
│   └── main.py                 # Typer CLI entrypoint
└── tests/
    └── *.py                    # pytest test files
```

**Key conventions:**

- One tool per file in `src/tools/`
- One agent builder per file in `src/fackel/agents/`
- Orchestrator graph logic isolated in `src/fackel/agents/orchestrator/`
- Domain models in `src/fackel/domain/` — no infrastructure dependencies
- Prompts in Markdown — `workspace/prompt.md` (soul) + `workspace/skills/*.md`

---

## Coding standards

### SOLID

- **Single Responsibility** is mandatory. One reason to change per module.
- Dependencies point inward: `domain → application → infrastructure`.
- Prefer **composition** over inheritance.

### YAGNI

- Do **not** introduce abstractions for hypothetical future use.
- No feature flags or configs without a concrete use case.
- Remove unused code immediately.

### DRY

- Extract shared logic only when duplication is **real and meaningful**.
- Avoid "generic helpers" with unclear responsibility.

### KISS

- Prefer explicit and readable code.
- Avoid clever or overly compact implementations.
- Optimise for understanding, not brevity.

---

## Code style

| Rule | Detail |
|------|--------|
| Type hints | Required everywhere — strict mypy enforced |
| Models | Use `dataclasses` or `Pydantic` for structured data |
| Functions | Small, focused, single purpose |
| Side effects | Forbidden in domain logic |
| Timestamps | UTC everywhere |
| Global state | Forbidden |
| Naming | Intention-revealing; matches domain glossary |
| Comments | Comment **WHY**, not **WHAT** — don't state the obvious |
| Line length | 100 characters (ruff enforced) |
| Python target | 3.12 |

---

## Domain glossary

The project uses a strict ubiquitous language. Always use these terms; **never**
use the forbidden alternatives.

| Canonical Term | Definition |
|----------------|------------|
| `ToolExecution` | A single, immutable execution of a tool. Contains raw output and metadata only. |
| `ToolOutputTranslator` | Translates raw tool output into normalized `InformationCandidate`s. |
| `InformationCandidate` | Temporary, non-persisted representation of extracted information. |
| `InformationType` | Semantic category of information (e.g. `EMAIL`, `IP`, `VULNERABILITY`). |
| `InformationRecord` | Persisted, deduplicated, normalised fact. |
| `InformationTimeline` | Append-only history of state changes for an `InformationRecord`. |
| `Fingerprint` | Stable hash derived from `(InformationType + normalized_value)`. |

### Forbidden terms

Do **not** use these words in code, comments, or documentation:

- ~~Finding~~ → use `InformationRecord`
- ~~Artifact~~ → use `InformationRecord`
- ~~Insight~~ → use `InformationRecord`
- ~~Signal~~ → use `InformationRecord`

> **Note:** The `Finding` Pydantic model in `domain/models.py` predates this
> glossary and is used in the scan pipeline output. It should be treated as a
> pipeline concept distinct from the persistence domain glossary.

---

## Anti-patterns

### Forbidden

| Pattern | Why |
|---------|-----|
| God classes | Violates SRP — split into focused modules |
| Generic "utils" modules | Unclear responsibility — give helpers a clear owner |
| Repositories doing business logic | Mix of concerns — keep persistence pure |
| Tool-specific logic in domain layer | Domain must be infrastructure-agnostic |
| Flags for hypothetical future use | YAGNI — add when needed |
| Overuse of inheritance | Prefer composition |

### Red flags

- Classes with more than one reason to change
- Methods longer than ~30 lines
- Helper functions without a clear owner

---

## Adding a new tool

### 1. Create the tool file

```python
# src/tools/my_new_tool.py
from langchain_core.tools import tool
from pydantic import BaseModel, Field
from tools.validators import TargetType, guard_target
from tools.utils import format_tool_output, run_command

class MyNewToolInput(BaseModel):
    """Input schema — Pydantic model with Field descriptions."""
    target: str = Field(description="Target domain or IP")
    timeout: int = Field(default=30, description="Timeout in seconds")

@tool(args_schema=MyNewToolInput)
def my_new_tool(target: str, timeout: int = 30) -> str:
    """One-line description shown to the LLM."""
    # 1. Validate input
    error = guard_target(target, TargetType.DOMAIN)
    if error:
        return format_tool_output("my_new_tool", error)

    # 2. Execute tool logic
    result = run_command(["my-binary", target, "--timeout", str(timeout)])

    # 3. Return standardised envelope
    return format_tool_output("my_new_tool", result)
```

### 2. Wire it into an agent

Add the tool to the agent's tool list in the respective agent builder
(e.g. `src/fackel/agents/osint_agent.py`):

```python
from tools.my_new_tool import my_new_tool

tools = [
    # ... existing tools ...
    my_new_tool,
]
```

### 3. Add provider key gating (if needed)

If the tool requires an API key, add a `ProviderKeySpec` in
`src/fackel/provider_keys.py`:

```python
ProviderKeySpec(
    env_var="MY_API_KEY",
    tool_names=["my_new_tool"],
    hard_fail=True,  # True = remove tool when key missing
)
```

### Checklist

- [ ] Pydantic `BaseModel` input schema with `Field(description=...)`
- [ ] `guard_target()` as first line in function body
- [ ] `format_tool_output()` for return value (standardised envelope)
- [ ] Provider key gating if API key needed
- [ ] Tool added to agent tool list
- [ ] Tested manually: `uv run python -c "from tools.my_new_tool import my_new_tool"`

---

## Adding a new agent

### 1. Create the agent builder

```python
# src/fackel/agents/my_agent.py
from fackel.agents.config import create_agent, get_model
from fackel.agents.provider_keys import filter_tools
from tools.tool_a import tool_a
from tools.tool_b import tool_b

TOOLS = [tool_a, tool_b]

def build_my_agent():
    available_tools = filter_tools(TOOLS)
    return create_agent(
        model_name=get_model("MY_AGENT"),
        tools=available_tools,
        system_prompt="...",  # Or loaded from workspace/skills/my_agent.md
    )
```

### 2. Add a graph node

In `src/fackel/agents/orchestrator/nodes.py`, add a node function:

```python
async def run_my_agent(state: ScanState) -> dict:
    agent = build_my_agent()
    result = await agent.ainvoke({"messages": [...]})
    return {"my_agent_output": result}
```

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

---

## Persistence rules

When working with MongoDB or any persistence layer:

| Rule | Detail |
|------|--------|
| One collection per concept | `ToolExecution`, `InformationRecord`, `InformationTimeline` each get their own collection |
| No polymorphic documents | Don't store mixed types in one collection |
| No deep nesting | Prefer references over embedded documents |
| Append-only history | **Never** update or delete historical records |
| Status changes → timeline | Changes create events, not overwrites |
| Fingerprint deduplication | Always use `Fingerprint`, never tool name or execution ID |
| Idempotent operations | Safe for concurrent writes |

---

## AI review checklist

Before submitting or approving code changes, verify:

- [ ] Single Responsibility is respected
- [ ] No speculative abstractions (YAGNI)
- [ ] No duplicated logic (DRY)
- [ ] Code is simple and readable (KISS)
- [ ] Domain logic is infrastructure-agnostic
- [ ] No historical data mutation
- [ ] Naming matches domain glossary
- [ ] Type hints on all functions
- [ ] `guard_target()` on all tool functions that accept targets
- [ ] `format_tool_output()` for all tool return values

> **If a change does not clearly improve quality, do not make it.**
