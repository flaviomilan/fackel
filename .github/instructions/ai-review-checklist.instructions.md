---
description: Code review checklist for AI
applyTo: "**/*.py"
---

# AI Review Checklist

Before suggesting changes, verify:

- [ ] Single Responsibility is respected
- [ ] No speculative abstractions (YAGNI)
- [ ] No duplicated logic (DRY)
- [ ] Code is simple and readable (KISS)
- [ ] Domain logic is infrastructure-agnostic
- [ ] No historical data mutation
- [ ] Naming matches domain glossary
- [ ] Type hints on all functions
- [ ] Tools use `@fackel_tool`, call `guard_target()` on every target input, and return via `format_tool_output()`
- [ ] `build_llm()` for agent model construction (never direct `ChatOpenAI`)
- [ ] `name` parameter on all `create_agent()` calls

If a change does not clearly improve quality,
do not suggest it.
