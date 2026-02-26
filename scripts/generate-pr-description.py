#!/usr/bin/env python3
"""Generate a PR description from commit messages and diff context.

Used by:
  - .github/workflows/pr-description.yml  (CI — reads env vars)
  - scripts/pr-describe.sh                (local — pipes from `gh`/`git`)

Requires:
  OPENAI_API_KEY  — API key (OpenAI or compatible endpoint)
  PR_TITLE        — Pull request title
  PR_COMMITS      — One-line commit log
  PR_DIFFSTAT     — `git diff --stat` output
  PR_DIFF         — Truncated unified diff (optional, improves quality)

Optional:
  OPENAI_BASE_URL — Override for GitHub Models, Azure, or local LLMs
  OPENAI_MODEL    — Model name (default: gpt-4o-mini)
"""

from __future__ import annotations

import os
import sys

SYSTEM_PROMPT = """\
You are a senior software engineer writing a pull request description.

The project ("Fackel") is an autonomous OSINT and security intelligence agent
written in Python.  It uses LangGraph, conventional commits (commitizen), and
follows strict domain-driven design.

Given the PR title, commit messages, and diff context, produce a description
that follows this EXACT template — in English, concise, technical:

## What

<1-3 sentences summarising the change.  Link related issues with "Closes #N" if
detectable from commit messages.>

## Why

<1-2 sentences explaining the motivation.>

## How

<Bullet list of implementation highlights — only non-obvious decisions.>

## Checklist

- [ ] Self-reviewed the diff
- [ ] Added/updated tests for changed behavior
- [ ] `uv run ruff check src/ tests/` passes
- [ ] `uv run ruff format --check src/ tests/` passes
- [ ] `uv run pytest tests/` passes
- [ ] Updated docs if applicable
- [ ] No secrets, credentials, or internal URLs in the diff

Rules:
- Do NOT invent information.  If something is unclear, say so briefly.
- Do NOT repeat the full diff in the description.
- Keep it under 300 words (excluding the checklist).
- Output raw Markdown only — no wrapping fences.
"""


def build_user_prompt() -> str:
    title = os.environ.get("PR_TITLE", "(no title)")
    commits = os.environ.get("PR_COMMITS", "(no commits)")
    diffstat = os.environ.get("PR_DIFFSTAT", "")
    diff = os.environ.get("PR_DIFF", "")

    parts = [
        f"### PR title\n{title}",
        f"### Commits\n```\n{commits}\n```",
    ]
    if diffstat:
        parts.append(f"### Diff stat\n```\n{diffstat}\n```")
    if diff:
        parts.append(f"### Diff (truncated)\n```diff\n{diff}\n```")

    return "\n\n".join(parts)


def generate() -> str:
    try:
        from openai import OpenAI
    except ImportError:
        print(
            "ERROR: openai package not installed.  Run: uv pip install openai",
            file=sys.stderr,
        )
        sys.exit(1)

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY not set.", file=sys.stderr)
        sys.exit(1)

    base_url = os.environ.get("OPENAI_BASE_URL")  # None → default OpenAI
    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    client = OpenAI(api_key=api_key, base_url=base_url)

    response = client.chat.completions.create(
        model=model,
        temperature=0.2,
        max_tokens=1024,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt()},
        ],
    )

    return response.choices[0].message.content or ""


if __name__ == "__main__":
    print(generate())
