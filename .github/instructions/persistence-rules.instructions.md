---
description: Persistence and data integrity rules
applyTo: "**/*.py"
---

# Persistence Rules

Persistence is a **file-based JSONL store** (`src/fackel/persistence/store.py`,
`InformationStore`). Each scan owns a directory under `FACKEL_DATA_DIR` and writes
one append-only JSONL file per core concept: `executions.jsonl`, `records.jsonl`,
`timeline.jsonl`, `edges.jsonl`. Single writer per scan (one scan per process); no
external database.

## Store layout
- One JSONL file per core concept — never mix concepts in one file
- No polymorphic records; avoid deep nesting in a record's `attributes`
- Records are keyed by `fingerprint`

## Historical Data
- Append-only
- Never update or delete historical records
- Status changes generate timeline events (`TimelineEvent`), not in-place edits

## Deduplication
- Always deduplicate by `fingerprint`
- Never deduplicate by tool or execution

## Writes
- Prefer idempotent operations
- Single-writer-per-scan; no cross-process concurrent writes are performed
