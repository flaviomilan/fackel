---
name: editing-prompts
description: Change runtime agent prompts in src/fackel/prompts/ — soul, per-agent role prompts, shared sections (tools/, contracts/, validation/, …), full and compact variants. Use before touching any prompts/**/*.md or the section lists that compose them.
---

# Editing runtime prompts

## Purpose
Change `src/fackel/prompts/**` without breaking the full/compact pair, the schema↔prompt drift guard, or the shared `soul`.

## Not for
- Dev-time instructions (`CLAUDE.md`, `.claude/**`) — those follow `writing-for-agents`.
- Adding a whole runtime agent — see "Adding a new agent" in `docs/development.md`.

## Layout (how a prompt is composed)
`load_prompt(name)` = `soul.md` + `skills/<name>.md`; `compose_prompt(name, *extras)` appends shared sections. Loader and the compact rule: `src/fackel/prompts/__init__.py`. The `skills/` folder holds per-agent role prompts (naming is historical); the sibling folders are the shared, reusable sections.

## Procedure
1. **Locate the source.** A rule shared by several agents belongs in `soul.md` (+ `soul_compact.md`) or a shared section; a rule for one agent belongs in `skills/<agent>.md`. Search the prompts for the rule first (`grep -rn`) and edit the existing home; keep one home per rule.
2. **Edit the full file, then its `_compact` twin** when one exists (`skills/<name>_compact.md`, `soul_compact.md`). Compact skips `extras`, so anything an agent needs under the compact profile must be inlined in the compact file. Keep compact lean (its budget is ~1.5K tokens for OSINT).
3. **New shared section:** create `prompts/<category>/<name>.md`, then add it to the `extras` of the owning builder (`agents/vuln_scan/agent.py:_VULN_PROMPT_SECTIONS`, `agents/triage/agent.py`, `agents/report/agent.py`, `agents/orchestrator/evaluator.py`) and to the matching list in `tests/test_prompt_consistency.py` and `tests/core/test_prompts.py`. A section referenced nowhere is an orphan — delete it instead.
4. **Tool names and fields:** every tool name must appear in its agent's composed prompt; for `port_scan` and `vuln_scan` every `args_schema` field must too (`tests/test_prompt_consistency.py`). Renaming a tool or field means editing the prompt in the same change.
5. **Gate.** Done when both pass: `uv run pytest tests/core/test_prompts.py tests/test_prompt_consistency.py tests/agents -q` and `make lint`.

## Inputs / output
Input: the behaviour to change and the agent(s) it affects. Output: edited prompt files (full and compact), updated section lists/tests, green gate.

## Limitations
The drift guard checks only the full profile; compact consistency is manual (step 2). Prompts contain example targets: use reserved names only (`example.com`, `*.test`).
