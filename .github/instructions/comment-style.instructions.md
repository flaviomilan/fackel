---
description: Comment and docstring style — docstrings carry knowledge, not # comments
applyTo: "**/*.py"
---

# Comment Style

Knowledge lives in **docstrings**, not in `#` comments. When you create or edit a
Python file, do not reintroduce the prose-comment patterns that were removed from
this codebase.

## Rules
- Every module, public class and public function has a docstring. Put the *why*,
  the rationale, the gotchas and the invariants there.
- Do **not** add prose `#` comments:
  - no section banners (`# -- glyphs --`, `# === LLM provider ===`);
  - no comments that restate what the next line already says;
  - no inline trailing asides (`x = 1  # set x to one`).
  If a reason is worth writing, write it in the nearest docstring, not beside the code.
- The **only** `#` lines allowed are functional directives the tooling needs:
  `# type: ignore[...]`, `# noqa: ...`, `# pragma: no cover`.
- A new file starts with a module docstring, never with a comment.
- When you must record non-obvious rationale next to a constant or a config value
  that cannot hold a docstring, fold it into the docstring of the function, class or
  module that owns it.

## See also
- `coding-standards.instructions.md` — general style (this file supersedes its
  "comment why, not what" guidance with "put the why in the docstring").
- `anti-patterns.instructions.md`
- `ai-review-checklist.instructions.md`
