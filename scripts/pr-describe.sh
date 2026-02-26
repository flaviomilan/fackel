#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────────────
# scripts/pr-describe.sh — Generate & apply a PR description locally
#
# Usage:
#   ./scripts/pr-describe.sh            # for current branch
#   ./scripts/pr-describe.sh --dry-run  # preview without updating the PR
#
# Prerequisites:
#   - gh CLI authenticated (`gh auth login`)
#   - OPENAI_API_KEY env var (or .env file in project root)
#   - Python openai package: uv pip install openai
# ────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Load .env if available
if [[ -f "$PROJECT_ROOT/.env" ]]; then
  # shellcheck disable=SC1091
  set -a && source "$PROJECT_ROOT/.env" && set +a
fi

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

# ── Resolve base branch ────────────────────────────────────────────────────
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
BASE_BRANCH=$(gh pr view "$CURRENT_BRANCH" --json baseRefName -q .baseRefName 2>/dev/null || echo "main")

echo "▸ Branch: $CURRENT_BRANCH → $BASE_BRANCH"

# ── Collect context ────────────────────────────────────────────────────────
export PR_TITLE
PR_TITLE=$(gh pr view "$CURRENT_BRANCH" --json title -q .title 2>/dev/null || echo "$CURRENT_BRANCH")

export PR_COMMITS
PR_COMMITS=$(git log --oneline --no-merges "origin/${BASE_BRANCH}..HEAD")

export PR_DIFFSTAT
PR_DIFFSTAT=$(git diff --stat "origin/${BASE_BRANCH}..HEAD")

export PR_DIFF
PR_DIFF=$(git diff "origin/${BASE_BRANCH}..HEAD" -- '*.py' '*.yml' '*.toml' '*.md' | head -c 12000)

echo "▸ Commits: $(echo "$PR_COMMITS" | wc -l)"
echo "▸ Generating description…"

# ── Generate ───────────────────────────────────────────────────────────────
BODY=$(python "$SCRIPT_DIR/generate-pr-description.py")

if $DRY_RUN; then
  echo ""
  echo "═══════════════════════════════════════════════════════════"
  echo "$BODY"
  echo "═══════════════════════════════════════════════════════════"
  echo ""
  echo "▸ Dry run — PR not updated."
else
  PR_NUMBER=$(gh pr view "$CURRENT_BRANCH" --json number -q .number)
  echo "$BODY" | gh pr edit "$PR_NUMBER" --body-file -
  echo "▸ PR #${PR_NUMBER} description updated."
fi
