---
description: Project architecture, domain concepts, and coding guidelines for AI-assisted development
applyTo: "**/*.py"
---

# Project Architecture & AI Coding Guidelines

This document defines the architectural principles, domain model, and coding standards
that must be followed when generating, modifying, or reviewing code in this project.

The goal is long-term maintainability, traceability of information over time, and
high-quality, production-ready code.

---

## 1. Architectural Overview

This project processes outputs from multiple tools (e.g. OSINT, scanners, analyzers),
normalizes the extracted information, and tracks it over time.

Core architectural principles:
- Clear separation between raw tool execution and normalized information
- Append-only historical tracking
- Explicit domain modeling
- Extensibility without schema rewrites
- Strong observability and auditability

The system is designed to answer questions like:
- What information was discovered?
- When was it first and last seen?
- Did it change, get resolved, or get masked?
- Which tools detected it?
- Did an issue reappear after being fixed?

---

## 2. Core Domain Concepts

### 2.1 ToolExecution

Represents a single execution of a tool.

Responsibilities:
- Store raw output
- Store execution metadata (tool name, version, params, runtime)
- Enable debugging, replay, and observability

Important rules:
- ToolExecution is immutable once persisted
- ToolExecution does NOT contain normalized information

---

### 2.2 InformationType

A semantic catalog of information types.

Examples:
- EMAIL_ADDRESS
- IP_ADDRESS
- DOMAIN
- SECURITY_VULNERABILITY
- SERVICE_VERSION
- PERSONAL_IDENTIFIER

Rules:
- InformationTypes are stable and reused across tools
- Different tools can generate the same InformationType
- Types may be grouped by category (PII, Security, Infrastructure, etc.)

---

### 2.3 InformationRecord

Represents a normalized, deduplicated fact extracted from tool outputs.

Key properties:
- Normalized value (used for comparison and deduplication)
- Original value (as reported by the tool)
- Fingerprint-based identity
- Temporal metadata (first_seen_at, last_seen_at)
- Current status (active, resolved, masked, outdated)

Rules:
- InformationRecords represent the *current known state*
- Deduplication is based on fingerprint, not tool or execution
- Multiple ToolExecutions may reference the same InformationRecord

---

### 2.4 InformationTimeline

Tracks the historical evolution of an InformationRecord.

Examples of events:
- created
- updated
- resolved
- masked
- reintroduced

Rules:
- Timeline is append-only
- Historical data is never mutated
- State changes must always generate a timeline event

---

## 3. Data Flow

High-level flow:

Tool Execution
→ Raw Output
→ Tool Output Translator
→ Normalized Information Candidates
→ Deduplication (fingerprint)
→ Persistence
→ Timeline Update

Rules:
- Translation logic is tool-specific
- Persistence logic is tool-agnostic
- Domain logic must not depend on infrastructure details

---

## 4. Persistence Guidelines (MongoDB)

- Each core concept has its own collection
- Avoid deeply nested documents
- Prefer references over embedding for evolving data
- Use indexes for:
  - fingerprint (unique)
  - type_id
  - current_status
  - temporal fields (first_seen_at, last_seen_at)

Important:
- Historical collections must be append-only
- Never delete or overwrite historical records
- Masking or resolution changes status, not history

---

## 5. Coding Principles

All generated or modified code MUST follow:

### SOLID
- Single Responsibility is mandatory
- Dependencies point inward (domain → application → infrastructure)
- Prefer composition over inheritance

### YAGNI
- Do not introduce abstractions for hypothetical future use
- No feature flags or configs without a concrete use case
- Remove unused code immediately

### DRY
- Extract shared logic only when duplication is real and meaningful
- Avoid “generic helpers” with unclear responsibility

### KISS
- Prefer explicit and readable code
- Avoid clever or overly compact implementations
- Optimize for understanding, not brevity

---

## 6. Code Style & Structure

- Use clear, intention-revealing names
- Functions should be small and focused
- Avoid side effects in domain logic
- Use UTC timestamps everywhere
- Prefer dataclasses or Pydantic models for domain objects
- Avoid global state

Comments:
- Do not comment obvious code
- Comment WHY, not WHAT, when intent is non-obvious

---

## 7. What AI Should NOT Do

- Do NOT redesign the architecture
- Do NOT introduce new patterns without a clear violation
- Do NOT optimize prematurely
- Do NOT mix tool-specific logic into core domain or persistence layers
- Do NOT mutate historical data

---

## 8. Quality Bar

Any generated or modified code should:
- Be simpler than the previous version
- Be understandable by a new engineer in minutes
- Preserve existing behavior unless a bug is explicitly fixed
- Be safe for concurrent execution

If a change does not clearly improve clarity, safety, or maintainability,
it should not be made.
