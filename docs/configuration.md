# Configuration

Complete reference for all Fackel configuration options: environment variables,
model selection, API keys, CLI options, and infrastructure setup.

---

## Table of contents

- [Environment variables](#environment-variables)
  - [Required](#required)
  - [Model selection](#model-selection)
  - [Provider API keys](#provider-api-keys)
  - [Tool timeouts](#tool-timeouts)
  - [Checkpointer](#checkpointer)
  - [Infrastructure (MongoDB)](#infrastructure-mongodb)
  - [Observability — LangSmith tracing](#observability--langsmith-tracing)
- [CLI options](#cli-options)
- [Provider key gating](#provider-key-gating)
- [Infrastructure — Docker Compose (optional)](#infrastructure--docker-compose-optional)
- [.env file](#env-file)
- [Python API configuration](#python-api-configuration)

---

## Environment variables

### Required

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key (or compatible provider). Used by all agents. |

This is the **only** required variable. Everything else has sensible defaults or
degrades gracefully.

### Model selection

Each agent reads its model from a dedicated environment variable, falling back to
`gpt-5-mini` (defined in `src/fackel/agents/config.py`).

| Variable | Agent | Default |
|----------|-------|---------|
| `FACKEL_MODEL_OSINT` | OSINT ReAct agent | `gpt-5-mini` |
| `FACKEL_MODEL_PORT_SCAN` | Port scan ReAct agent | `gpt-5-mini` |
| `FACKEL_MODEL_VULN_SCAN` | Vulnerability scan ReAct agent | `gpt-5-mini` |
| `FACKEL_MODEL_TRIAGE` | Triage structured output | `gpt-5-mini` |
| `FACKEL_MODEL_REPORT` | Report synthesis | `gpt-5-mini` |
| `FACKEL_MODEL_JUDGE` | Phase quality evaluator | `gpt-5-mini` |

The naming convention is `FACKEL_MODEL_{AGENT_NAME}` where `AGENT_NAME` is
uppercase. The lookup function:

```python
def get_model(agent_name: str) -> str:
    env_var = f"FACKEL_MODEL_{agent_name.upper()}"
    return os.getenv(env_var, "gpt-5-mini")
```

#### Examples

```bash
# Use GPT-4o for report generation (higher quality prose)
export FACKEL_MODEL_REPORT=gpt-4o

# Use a cheaper model for OSINT (mostly tool orchestration)
export FACKEL_MODEL_OSINT=gpt-4o-mini

# Use Claude for all agents
export FACKEL_MODEL_OSINT=claude-sonnet-4-20250514
export FACKEL_MODEL_PORT_SCAN=claude-sonnet-4-20250514
export FACKEL_MODEL_VULN_SCAN=claude-sonnet-4-20250514
export FACKEL_MODEL_TRIAGE=claude-sonnet-4-20250514
export FACKEL_MODEL_REPORT=claude-sonnet-4-20250514
export FACKEL_MODEL_JUDGE=claude-sonnet-4-20250514
```

#### Using non-OpenAI providers

Fackel uses LangChain's `ChatOpenAI`, which supports any OpenAI-compatible API.
Set `OPENAI_API_BASE` (or `OPENAI_BASE_URL`) alongside the model name to use
alternative providers.

### Provider API keys

These enable specific tools. Tools with missing keys are automatically removed
from agents (see [Provider key gating](#provider-key-gating)).

| Variable | Provider | Tools Enabled | Required |
|----------|----------|---------------|----------|
| `SHODAN_API_KEY` | Shodan | `shodan_lookup` | No |
| `VIRUSTOTAL_API_KEY` | VirusTotal | `virustotal_subdomain_enum` | No |
| `CENSYS_API_ID` | Censys | `censys_lookup` | No |
| `CENSYS_API_SECRET` | Censys | `censys_lookup` | No |
| `SECURITYTRAILS_API_KEY` | SecurityTrails | `securitytrails_history` | No |
| `OTX_API_KEY` | AlienVault OTX | `otx_passive_dns` | No |
| `HIBP_API_KEY` | HaveIBeenPwned | `analyze_email` (breach data) | No |
| `EMAILREP_API_KEY` | EmailRep | `analyze_email` (reputation) | No |

**Censys** requires both `CENSYS_API_ID` and `CENSYS_API_SECRET` — if either is
missing, the tool is removed.

**HIBP and EmailRep** use graceful degradation — the `analyze_email` tool stays
available even without keys, but some data sources are skipped.

### Tool timeouts

Subprocess tools (nmap, nuclei, subfinder, etc.) honour per-tool timeout
overrides via `FACKEL_TIMEOUT_{TOOL_NAME}` (value in seconds). If no override
is set, the default from `get_tool_timeout()` (typically 180 s) is used.

| Variable | Tool | Default |
|----------|------|---------|
| `FACKEL_TIMEOUT_NMAP_PORT_SCAN` | nmap | 180 s |
| `FACKEL_TIMEOUT_NUCLEI_SCAN` | nuclei | 180 s |
| `FACKEL_TIMEOUT_SUBFINDER_ENUM` | subfinder | 180 s |
| `FACKEL_TIMEOUT_FEROXBUSTER_SCAN` | feroxbuster | 180 s |
| `FACKEL_TIMEOUT_KATANA_CRAWL` | katana | 180 s |
| `FACKEL_TIMEOUT_HTTPX_PROBE` | httpx | 180 s |
| `FACKEL_TIMEOUT_NAABU_SCAN` | naabu | 180 s |
| `FACKEL_TIMEOUT_WAFW00F` | wafw00f | 180 s |

### Checkpointer

| Variable | Default | Description |
|----------|---------|-------------|
| `FACKEL_CHECKPOINT_DB` | `~/.fackel/checkpoints.db` | SQLite path for graph state persistence. Used by `SqliteSaver` to enable interrupt/resume. |

### Infrastructure (MongoDB)

Optional — for scan persistence when MongoDB is available:

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGO_URI` | `mongodb://fackel:fackelpass@localhost:27017/fackel?authSource=admin` | MongoDB connection URI |
| `MONGO_DB_NAME` | `fackel` | Database name |
| `MONGO_USERNAME` | `fackel` | MongoDB user |
| `MONGO_PASSWORD` | `fackelpass` | MongoDB password |

> **Security note:** Replace default credentials with strong secrets in
> production.

### Observability — LangSmith tracing

LangChain auto-instruments all LLM calls, tool invocations, and agent steps when
these environment variables are set. No code changes required.

| Variable | Description | Required |
|----------|-------------|----------|
| `LANGSMITH_TRACING` | Set to `true` to enable tracing | Yes |
| `LANGSMITH_API_KEY` | LangSmith API key from [smith.langchain.com](https://smith.langchain.com) | Yes |
| `LANGSMITH_PROJECT` | Project name for trace grouping | No (defaults to `default`) |
| `LANGSMITH_ENDPOINT` | Custom LangSmith endpoint URL | No |

#### Quick start

```bash
export LANGSMITH_TRACING=true
export LANGSMITH_API_KEY=lsv2_pt_...
export LANGSMITH_PROJECT=fackel-prod

fackel example.com
```

All agent phases (OSINT, Port Scan, Vuln Scan, Triage, Report) appear as
hierarchical traces in the LangSmith dashboard, including:

- Token usage and latency per LLM call
- Tool inputs/outputs and execution time
- Middleware activity (retries, approval interrupts)
- Full message history per agent session

#### Self-hosted alternative

For self-hosted observability, LangSmith can be deployed on-premise via
the [LangSmith Self-Hosted](https://docs.smith.langchain.com/self_hosting)
guide.  Point ``LANGSMITH_ENDPOINT`` at your instance.

---

## CLI options

```
fackel <target> [OPTIONS]
```

| Argument / Option | Type | Default | Description |
|-------------------|------|---------|-------------|
| `target` | `str` (positional) | *(required)* | Domain or IP to scan |
| `--active-scan / --no-active-scan` | `bool` | `True` | Enable/disable active scanning phases (port scan, vuln scan) |
| `--output / -o` | `Path` | `reports/<target>_<timestamp>.md` | Report output file path |
| `--verbose / -v` | `bool` | `False` | Show LLM reasoning and detailed tool results |
| `--check-providers` | `bool` | `False` | Print provider API key status table before starting the scan |
| `--approve-tools` | `bool` | `False` | Require per-tool-call approval for active scanning tools (nmap, nuclei, etc.) |

### Active scan vs passive

| Mode | Phases | Description |
|------|--------|-------------|
| `--active-scan` *(default)* | OSINT → Approval → Port Scan → Vuln Scan → Triage → Report | Full pipeline. Requires operator approval before active scanning. |
| `--no-active-scan` | OSINT → Report | Passive only. No probe packets sent. No approval required. |

### Verbose mode

Standard mode shows tool calls and completion status. Verbose (`-v`) adds:

- **LLM reasoning** — the model's chain-of-thought before each tool call (`💭`)
- **Tool result previews** — truncated tool output (`← tool_name: ...`)
- **Agent summaries** — full structured summaries from each phase

### Check providers

```bash
fackel example.com --check-providers --no-active-scan
```

Prints a table showing which provider API keys are configured and which tools
are disabled:

```
Provider           Status    Tools
───────────────────────────────────────
Shodan             ✓         shodan_lookup
VirusTotal         ✗         virustotal_subdomain_enum
Censys             ✗         censys_lookup
SecurityTrails     ✗         securitytrails_history
AlienVault OTX     ✗         otx_passive_dns
HaveIBeenPwned     ✗         analyze_email (graceful)
EmailRep           ✗         analyze_email (graceful)
```

---

## Provider key gating

Defined in `src/fackel/provider_keys.py`.

When an agent is built, `filter_tools()` partitions its toolkit:

1. **Available tools** — API key present (or not required)
2. **Skipped tools** — API key missing and `hard_fail=True`

Skipped tools are completely removed from the agent — the LLM never sees them
and cannot attempt to call them.

| Provider | Hard Fail | Behaviour When Missing |
|----------|-----------|----------------------|
| Shodan | Yes | `shodan_lookup` removed entirely |
| VirusTotal | Yes | `virustotal_subdomain_enum` removed |
| Censys | Yes | `censys_lookup` removed |
| SecurityTrails | Yes | `securitytrails_history` removed |
| AlienVault OTX | Yes | `otx_passive_dns` removed |
| HaveIBeenPwned | **No** | `analyze_email` stays; HIBP source silently skipped |
| EmailRep | **No** | `analyze_email` stays; EmailRep source silently skipped |

This prevents the LLM from wasting tool call iterations on tools that can only
return "API key not configured" errors.

---

## Infrastructure — Docker Compose (optional)

A `docker-compose.yml` can be added to provide MongoDB for scan persistence.

```bash
# Start MongoDB
docker compose up -d mongodb

# Override credentials
MONGO_PASSWORD=secure_password docker compose up -d
```

All containers should bind to `127.0.0.1` to prevent external access.

> **Observability** is handled by LangSmith (SaaS or self-hosted) — see
> [Observability — LangSmith tracing](#observability--langsmith-tracing) above.

---

## .env file

Fackel loads `.env` from the project root via `python-dotenv`. Example:

```bash
# Required
OPENAI_API_KEY=sk-...

# Model selection (optional)
FACKEL_MODEL_REPORT=gpt-4o
FACKEL_MODEL_JUDGE=gpt-4o

# LangSmith tracing (optional)
# LANGSMITH_TRACING=true
# LANGSMITH_API_KEY=lsv2_pt_...
# LANGSMITH_PROJECT=fackel

# Per-tool timeout overrides (optional, seconds)
# FACKEL_TIMEOUT_NMAP_PORT_SCAN=300
# FACKEL_TIMEOUT_NUCLEI_SCAN=600

# Provider API keys (optional)
SHODAN_API_KEY=...
VIRUSTOTAL_API_KEY=...
CENSYS_API_ID=...
CENSYS_API_SECRET=...
SECURITYTRAILS_API_KEY=...
OTX_API_KEY=...
HIBP_API_KEY=...
EMAILREP_API_KEY=...

# Checkpointer (optional)
# FACKEL_CHECKPOINT_DB=~/.fackel/checkpoints.db

# Infrastructure (optional)
# MONGO_URI=mongodb://fackel:fackelpass@localhost:27017/fackel?authSource=admin
```

---

## Python API configuration

When using Fackel programmatically, configuration is passed directly:

```python
from fackel.agents.orchestrator import run

# Active scan with custom approval callback
result = run("example.com", active_scan=True, approval_callback=my_callback)

# Passive scan (no approval needed)
result = run("example.com", active_scan=False)
```

Model and API key configuration still uses environment variables — set them
before calling `run()`.

```python
import os
os.environ["FACKEL_MODEL_REPORT"] = "gpt-4o"
os.environ["OPENAI_API_KEY"] = "sk-..."

from fackel.agents.orchestrator import run
result = run("example.com")
```
