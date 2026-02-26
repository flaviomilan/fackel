.PHONY: install dev lint format test coverage audit hooks clean

## Install production dependencies
install:
	uv sync

## Install all dev dependencies + git hooks
dev: install
	uv sync --extra dev
	uv run pre-commit install

## Run ruff lint
lint:
	uv run ruff check src/ tests/

## Auto-format with ruff
format:
	uv run ruff format src/ tests/

## Type check
typecheck:
	uv run mypy src/fackel/

## Run tests (excluding integration)
test:
	uv run pytest tests/ -m "not integration" --tb=short

## Run tests with coverage report
coverage:
	uv run coverage run -m pytest tests/ -m "not integration" -q
	uv run coverage report --fail-under=50

## Dependency vulnerability audit
audit:
	uv run pip-audit

## Install / update git hooks
hooks:
	uv run pre-commit install
	uv run pre-commit install --hook-type commit-msg

## Run all pre-commit hooks against staged files
pre-commit:
	uv run pre-commit run

## Run all pre-commit hooks against all files
pre-commit-all:
	uv run pre-commit run --all-files

## Remove build artefacts
clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info .mypy_cache .ruff_cache .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +

## Install all external tool binaries (Go, system, Python, Rust, git)
setup-tools:
	./scripts/install-tools.sh

## Install core external binaries only (nmap, naabu, nuclei, httpx, subfinder)
setup-tools-minimal:
	./scripts/install-tools.sh --minimal

## Audit which external tool binaries are installed/missing
check-tools:
	./scripts/install-tools.sh --check

## Generate PR description for current branch (dry-run)
pr-describe:
	./scripts/pr-describe.sh --dry-run

## Generate and apply PR description for current branch
pr-describe-apply:
	./scripts/pr-describe.sh
