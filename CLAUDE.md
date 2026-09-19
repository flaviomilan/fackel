# fackel

Autonomous pentest framework (LangGraph). Python 3.12, managed with `uv`.

## Commands
- `make lint typecheck test` — the gate before any commit (`make format` to auto-format)
- `make eval` — offline scan-quality regression
- `uv run pytest tests/<path> -q` — a single test file

Commits follow conventional commits (semantic-release).

## Where things are
- Rules for code, domain and persistence: `.github/instructions/`
- Architecture and runtime agents: `docs/architecture.md`, `docs/agents.md`
- Claude Code agents and skills for working on this repo: `.claude/README.md`
  (use `adding-a-tool` for new tools, `editing-prompts` for `src/fackel/prompts/`)

## Boundaries
- `.env` holds real API keys: read `.env.example` instead.
- Real scan data (`FACKEL_DATA_DIR`, `reports/`) stays out of the session.
- Use reserved targets in code, tests and docs: `example.com`, `*.test`, RFC 5737 IPs.
