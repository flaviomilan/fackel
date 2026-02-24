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

If a change does not clearly improve quality,
do not suggest it.
