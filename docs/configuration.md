# Configuration

Complete reference for all Fackel configuration options: environment variables,
model selection, API keys, CLI options, and infrastructure setup.

---

## Table of contents

- [Environment variables](#environment-variables)
  - [Required](#required)
  - [Model selection](#model-selection)
  - [Provider API keys](#provider-api-keys)
  - [Infrastructure](#infrastructure)
- [CLI options](#cli-options)
- [Provider key gating](#provider-key-gating)
- [Infrastructure — Docker Compose](#infrastructure--docker-compose)
  - [Services](#services)
  - [Volumes](#volumes)
  - [Customisation](#customisation)
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

### Infrastructure

These are used by `docker-compose.yml` for the optional infrastructure stack:

| Variable | Default | Service |
|----------|---------|---------|
| `MONGO_USERNAME` | `fackel` | MongoDB |
| `MONGO_PASSWORD` | `fackelpass` | MongoDB |
| `MONGO_DB_NAME` | `fackel` | MongoDB |
| `DATABASE_URL` | `postgresql://...` | Langfuse (PostgreSQL) |
| `SALT` | `mysalt` | Langfuse |
| `ENCRYPTION_KEY` | *(zero-filled)* | Langfuse |
| `NEXTAUTH_SECRET` | `mysecret` | Langfuse |
| `REDIS_AUTH` | `myredissecret` | Redis |
| `CLICKHOUSE_USER` | `clickhouse` | ClickHouse |
| `CLICKHOUSE_PASSWORD` | `clickhouse` | ClickHouse |
| `MINIO_ROOT_USER` | `minio` | MinIO |
| `MINIO_ROOT_PASSWORD` | `miniosecret` | MinIO |

> **Security note:** All defaults above are marked `# CHANGEME` in the compose
> file. Replace them with strong secrets in production.

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

## Infrastructure — Docker Compose

The `docker-compose.yml` provides an optional infrastructure stack for
observability and persistence.

### Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `mongodb` | `mongo:7` | `127.0.0.1:27017` | Scan persistence, query system |
| `langfuse-web` | `langfuse/langfuse:3` | `3000` | LLM observability UI |
| `langfuse-worker` | `langfuse/langfuse-worker:3` | `127.0.0.1:3030` | Langfuse background processing |
| `clickhouse` | `clickhouse-server` | `127.0.0.1:8123`, `127.0.0.1:9000` | Langfuse analytics backend |
| `postgres` | `postgres:17` | `127.0.0.1:5432` | Langfuse metadata storage |
| `redis` | `redis:7` | `127.0.0.1:6379` | Langfuse queue |
| `minio` | `minio` | `9090` (S3), `127.0.0.1:9091` (console) | Langfuse blob storage |

> **Network security:** All internal services bind to `127.0.0.1` except
> Langfuse web (port 3000) and MinIO S3 (port 9090). External machines cannot
> reach internal services directly.

### Volumes

| Volume | Service | Data |
|--------|---------|------|
| `fackel_mongo_data` | MongoDB | Scan data |
| `langfuse_postgres_data` | PostgreSQL | Langfuse metadata |
| `langfuse_clickhouse_data` | ClickHouse | Langfuse analytics |
| `langfuse_clickhouse_logs` | ClickHouse | Logs |
| `langfuse_minio_data` | MinIO | Blobs |

### Customisation

```bash
# Start only MongoDB (no Langfuse)
docker compose up -d mongodb

# Start full stack
docker compose up -d

# Override credentials
MONGO_PASSWORD=secure_password docker compose up -d

# View Langfuse UI
open http://localhost:3000
```

---

## .env file

Fackel loads `.env` from the project root via `python-dotenv`. Example:

```bash
# Required
OPENAI_API_KEY=sk-...

# Model selection (optional)
FACKEL_MODEL_REPORT=gpt-4o
FACKEL_MODEL_JUDGE=gpt-4o

# Provider API keys (optional)
SHODAN_API_KEY=...
VIRUSTOTAL_API_KEY=...
CENSYS_API_ID=...
CENSYS_API_SECRET=...
SECURITYTRAILS_API_KEY=...
OTX_API_KEY=...
SERPAPI_API_KEY=...
HIBP_API_KEY=...
EMAILREP_API_KEY=...

# Infrastructure (optional, for docker-compose)
MONGO_PASSWORD=your_secure_password
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
