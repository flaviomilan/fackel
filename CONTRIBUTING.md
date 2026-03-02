# Contributing to Fackel

Thank you for considering a contribution to Fackel! This guide covers
everything you need to get started.

For detailed development workflows, see [docs/development.md](docs/development.md).

---

## Table of contents

- [Code of conduct](#code-of-conduct)
- [Quick start](#quick-start)
- [Development workflow](#development-workflow)
- [Commit conventions](#commit-conventions)
- [Code style](#code-style)
- [Testing](#testing)
- [Pull requests](#pull-requests)
- [Architecture overview](#architecture-overview)

---

## Code of conduct

Be respectful, constructive, and inclusive. We follow the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

---

## Quick start

```bash
# 1. Fork and clone
git clone https://github.com/<your-user>/fackel.git && cd fackel

# 2. Install Python dependencies (requires uv)
uv sync --extra dev

# 3. Install pre-commit hooks
uv run pre-commit install --install-hooks

# 4. Install external tool binaries
./scripts/install-tools.sh          # full install
./scripts/install-tools.sh --minimal  # core tools only

# 5. Copy env template
cp .env.example .env
# Edit .env — at minimum set OPENAI_API_KEY

# 6. Run tests
uv run pytest
```

---

## Development workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Make your changes in small, focused commits.
3. Run the full check suite before pushing:
   ```bash
   uv run ruff check src/ tests/     # lint
   uv run ruff format --check src/ tests/  # format check
   uv run mypy src/                   # type check
   uv run pytest                      # tests
   ```
4. Push and open a pull request against `main`.

---

## Commit conventions

We use [Conventional Commits](https://www.conventionalcommits.org/) enforced
by [Commitizen](https://commitizen-tools.github.io/commitizen/). The
pre-commit hook validates your commit messages automatically.

### Format

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Allowed types

| Type | Meaning |
|------|---------|
| `feat` | New feature |
| `fix` | Bug fix |
| `perf` | Performance improvement |
| `refactor` | Code change that neither fixes nor adds |
| `revert` | Reverts a previous commit |
| `docs` | Documentation only |
| `style` | Formatting, whitespace (no logic change) |
| `test` | Adding or updating tests |
| `chore` | Maintenance (deps, CI, tooling) |
| `ci` | CI/CD pipeline changes |
| `build` | Build system or dependency changes |

### Examples

```bash
git commit -m "feat(tools): add gospider web crawler"
git commit -m "fix(ssrf): reject IPv6 mapped addresses"
git commit -m "docs: update configuration reference"
```

---

## Code style

- **Python ≥ 3.12** — use modern syntax (`type` unions, `match`, etc.)
- **Ruff** for linting and formatting (config in `pyproject.toml`)
- **mypy** in strict mode — type hints on all public functions
- **Pydantic v2** for data models, **dataclasses** for lightweight value objects
- Prefer explicit over implicit; prefer composition over inheritance
- Functions should do one thing and be ≤ 30 lines
- No global mutable state

The full coding standards are in
[.github/instructions/coding-standards.instructions.md](.github/instructions/coding-standards.instructions.md).

---

## Testing

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run coverage run -m pytest && uv run coverage report

# Run a specific test file
uv run pytest tests/test_settings.py -v

# Run only fast tests (skip slow / integration)
uv run pytest -m "not slow and not integration"
```

### Writing tests

- Place tests in `tests/` mirroring the source structure.
- Use `pytest` fixtures (see `tests/conftest.py`).
- Mock external binaries and API calls — tests must run offline.
- For settings-dependent tests, call `_reset_settings()` in setup/teardown.
- Target ≥ 50% coverage (CI enforced).

---

## Pull requests

### Before opening

- [ ] All lint/format/type checks pass locally
- [ ] Tests pass (`uv run pytest`)
- [ ] Commit messages follow conventional commits
- [ ] New features include tests
- [ ] Documentation updated if applicable

### PR description

Describe **what** changed and **why**. Reference related issues with
`Closes #123` or `Fixes #123`.

### Review process

- At least one maintainer approval is required.
- CI must pass (lint, typecheck, tests, security audit).
- PRs are squash-merged into `main`.

---

## Architecture overview

Fackel is a LangGraph-based autonomous scanning pipeline:

```
OSINT → Approval Gate → Port Scan → Vuln Scan → Triage → Report
```

Key directories:

| Path | Purpose |
|------|---------|
| `src/fackel/agents/` | Agent definitions and orchestrator graph |
| `src/fackel/tooling/` | Tool wrappers, validators, execution helpers |
| `src/tools/` | LangChain `@tool` implementations |
| `src/cli/` | Typer CLI interface |
| `docs/` | Architecture, configuration, development guides |
| `scripts/` | Installer scripts for external binaries |
| `tests/` | Pytest test suite |

For the full architecture, see [docs/architecture.md](docs/architecture.md).

---

## Reporting issues

- Use GitHub Issues for bugs, feature requests, and questions.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

---

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE).
