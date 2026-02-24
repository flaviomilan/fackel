---
description: Persistence and data integrity rules
applyTo: "**/*.py"
---

# Persistence Rules

## MongoDB
- One collection per core concept
- No polymorphic documents
- Avoid deep nesting

## Historical Data
- Append-only
- Never update or delete historical records
- Status changes generate timeline events

## Deduplication
- Always use fingerprint
- Never deduplicate by tool or execution

## Transactions
- Prefer idempotent operations
- Be safe for concurrent writes
