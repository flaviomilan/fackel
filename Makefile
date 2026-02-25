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
