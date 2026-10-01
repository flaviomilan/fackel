# Claude Code tooling for this repo (dev-time)

Agents and skills that help **work on** fackel. They are unrelated to the product's **runtime** agents (OSINT, port scan, vuln scan, triage, report, judge — see `docs/agents.md`). Runtime code and prompts live in `src/fackel/`; nothing here is imported by it.

## Index

```text
Agents
└── tool-safety-reviewer — read-only review of safety rails in tools/tooling/scope

Skills
├── adding-a-tool   — wire a new tool end-to-end (checklist)
└── editing-prompts — change runtime prompts without breaking full/compact or the drift guard

Relations
tool-safety-reviewer ── reads ──> docs/input-validation.md
adding-a-tool ──> editing-prompts
adding-a-tool ──(last step)──> tool-safety-reviewer
```

## Which one for which task

| Task | Use |
|------|-----|
| Add a tool | `adding-a-tool` |
| Change a prompt, prompt section or the tool tables in prompts | `editing-prompts` |
| Check a tool/validator/scope change for safety | `tool-safety-reviewer` |
| General review, TDD, debugging, security review | user-level skills (`code-review`, `tdd`, `diagnosing-bugs`, `security-review`) |
| Add a runtime agent | `docs/development.md`, "Adding a new agent" (no skill: rare) |

## Where each rule lives

| Rule | Single source |
|------|---------------|
| Coding standards, anti-patterns, glossary, persistence, review checklist | `.github/instructions/` |
| Comment / docstring style (docstrings only, no prose `#` comments) | `.github/instructions/comment-style.instructions.md` |
| Target validation, SSRF, secrets | `docs/input-validation.md` and docstrings in `src/fackel/tooling/` |
| Tool wiring checklist | `adding-a-tool` |
| Prompt composition rules | `editing-prompts` |
| Commands and environment limits | `CLAUDE.md` |

## Adding a new agent or skill here

Add one only for a responsibility that recurs, is bounded, and is not already covered by an entry above or a user-level skill. A skill is a procedure any session can follow; an agent is a role that needs its own isolated context and restricted tools. Point to the source of truth instead of copying rules; put the new entry in the Index above.

## Keeping contexts apart

- Dev-time names (`.claude/`) and runtime names (`src/fackel/agents`, `prompts/skills/`) stay separate; the word "skill" under `prompts/` is historical and means a per-agent role prompt.
- The credentials, scan-data and reserved-target rules live in `CLAUDE.md` → Boundaries (always loaded, enforced every session); `tests/fixtures/eval/README.md` shows the reserved targets in use.
