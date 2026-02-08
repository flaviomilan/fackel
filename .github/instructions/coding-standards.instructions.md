---
description: Coding standards and style guidelines
applyTo: "**/*.py"
---

# Coding Standards

## General
- Prefer explicit over implicit
- Functions should do one thing
- Avoid deep nesting
- Raise explicit domain errors

## Python
- Use type hints everywhere
- Prefer dataclasses or Pydantic
- Avoid magic methods unless necessary
- No global mutable state

## Async
- Explicit async boundaries
- Do not mix sync and async in domain logic

## Errors
- Domain errors ≠ infrastructure errors
- Never swallow exceptions silently
