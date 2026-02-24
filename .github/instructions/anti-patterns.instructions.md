---
description: Known anti-patterns to avoid
applyTo: "**/*.py"
---

# Anti-Patterns

## Forbidden
- God classes
- Generic “utils” modules
- Repositories doing business logic
- Tool-specific logic in domain layer
- Flags for hypothetical future use
- Overuse of inheritance

## Red Flags
- Classes with more than one reason to change
- Methods longer than ~30 lines
- Helper functions without a clear owner
