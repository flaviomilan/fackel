---
description: Ubiquitous language and domain glossary
applyTo: "**/*.py"
---

# Domain Glossary

This document defines the canonical terminology used in the project.
AI must use these terms consistently.

## Core Terms

### ToolExecution
A single execution of a tool.
Immutable.
Contains raw output and execution metadata only.

### ToolOutputTranslator
Component responsible for translating raw tool output
into normalized InformationCandidates.

### InformationCandidate
A temporary, non-persisted representation of extracted information.

### InformationType
A semantic category of information (e.g. EMAIL, IP, VULNERABILITY).

### InformationRecord
A persisted, deduplicated, normalized fact.

### InformationTimeline
Append-only history of state changes for an InformationRecord.

### Fingerprint
A stable hash derived from (InformationType + normalized_value).

## Forbidden Terms

- Finding
- Artifact
- Insight
- Signal

Use the defined terms instead.
