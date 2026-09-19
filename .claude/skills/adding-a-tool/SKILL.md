---
name: adding-a-tool
description: Wire a new OSINT, recon, scanning or vuln tool into fackel end-to-end (tool file, agent list, specialist, binary/API-key gating, prompts, docs, tests). Use when adding a tool under src/fackel/tools/.
---

# Adding a tool

## Purpose
A tool is only useful once every wiring point knows it. This skill is the single checklist of those points; the code template is a real exemplar, not prose: `src/fackel/tools/recon/subzy_tool.py` (binary wrapper) or `src/fackel/tools/recon/crtsh_tool.py` (HTTP API + `circuit_breaker`).

## Not for
- Changing the internals of an existing tool (just edit it and its test).
- Adding a runtime agent (`docs/development.md`, "Adding a new agent").

## Preconditions
The tool's target type and whether it needs a binary, an API key, or neither are known. The tool sends traffic to the target only if it belongs to an active phase (`scanning/`, `vuln/`); passive lookups go in `recon/` or `osint/`.

## Procedure
Walk every step; end each as **done** or **N/A + reason**.
1. **Tool file** in `src/fackel/tools/{recon,osint,scanning,vuln}/<name>_tool.py`, copying the exemplar's shape: Pydantic input with `Field(description=…)`, `@fackel_tool(args_schema=…)`, `require_binary`/`require_env`, `guard_target(value, tool_name, TargetType.X)` (rules: `docs/input-validation.md`), `run_command` with an argument list, `get_tool_timeout(name, default)`, `format_tool_output(...)`.
2. **Owning agent list:** add to `TOOLS` in `agents/osint/agent.py`, `agents/vuln_scan/agent.py` or `agents/port_scan/agent.py`.
3. **Specialist assignment** (OSINT and vuln only): add the tool name to one specialist in `agents/{osint,vuln_scan}/specialists.py`; `tests/agents/test_specialists.py` fails on unassigned tools.
4. **Gating:**
   - binary → `TOOL_BINARIES` in `tooling/binaries.py`, plus `scripts/install-tools.sh` and `Dockerfile`;
   - API key → `ProviderKeySpec` in `provider_keys.py`, plus `.env.example` and `docs/configuration.md`.
5. **Prompts:** follow `editing-prompts` (tool table in `skills/osint.md`, group line in `osint_compact.md`, or the vuln/port-scan section that covers it).
6. **Records (only if the output should enter the knowledge graph):** extraction in `agents/orchestrator/extractors.py` and `agents/orchestrator/translators/`.
7. **Docs:** entry in `docs/tools.md`.
8. **Test:** `tests/tools/test_<name>_tool.py`, offline (mock binary/HTTP, no network); use reserved targets only (`example.com`, `*.test`).
9. **Gate:** `make lint typecheck test` green.
10. **Review:** launch the `tool-safety-reviewer` agent on the new tool file.

## Output
A tool reachable by its agent, gated correctly, documented, tested, and reviewed; a per-step done/N/A list in the final message.

## Limitations
The list mirrors the code as of writing; if a step points at a missing symbol, `grep -rl <existing similar tool>` across `src/ tests/ docs/ scripts/` finds the real wiring points, then update this file.
