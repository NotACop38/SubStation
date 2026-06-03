# Substation — pipeline single source of truth.
#
# CI/CD for this project is LOCAL and Claude-driven. There is NO cloud CI and
# NO GitHub Actions. `make ci` is the gate; the git pre-push hook (see `make
# hooks`) runs it before every push. Keep it that way.

PY ?= python3
PKG := substation
SRC := substation tests

.DEFAULT_GOAL := help

.PHONY: help dev ci format format-check lint type test security \
        demo verify release hooks clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

dev: ## Install the package with dev tooling (pinned)
	$(PY) -m pip install -e ".[dev]"

## ---------------------------------------------------------------------------
## CI — the local gate. Run this after any change; it must pass before "done".
## ---------------------------------------------------------------------------
ci: format-check lint type test ## Run the full local CI gate
	@echo "--- [placeholder] detection harness (Tier 1 generate->detect->report) — Phase 1"
	@echo "--- [placeholder] security (bandit + pip-audit) — wire via 'make security' in Phase 2"
	@echo "--- [placeholder] coverage-build (ATT&CK-for-ICS coverage map) — Phase 1/2"
	@echo "ci: OK"

format: ## Auto-format the codebase (ruff)
	ruff format $(SRC)

format-check: ## Verify formatting without writing (ruff)
	ruff format --check $(SRC)

lint: ## Lint (ruff)
	ruff check $(SRC)

type: ## Type-check in strict mode (mypy)
	mypy

test: ## Run unit tests (pytest)
	pytest

security: ## Security audit: bandit (code) + pip-audit (deps)
	bandit -q -r $(PKG)
	pip-audit

## ---------------------------------------------------------------------------
## Product targets (stubs until later phases)
## ---------------------------------------------------------------------------
demo: ## Tier-1 one-command demo: generate -> detect -> report (stub)
	@echo "make demo: Tier-1 demo not yet implemented (Phase 0 stub)."
	$(PY) -m substation.cli demo

verify: ## Tier-2 fidelity validation: Zeek/ICSNPP + Suricata (stub)
	@echo "make verify: Tier-2 validation not yet implemented (Phase 0 stub)."
	$(PY) -m substation.cli verify

release: ## Cut a release (stub)
	@echo "make release: not yet implemented (Phase 0 stub)."

## ---------------------------------------------------------------------------
## Local "continuous" gate
## ---------------------------------------------------------------------------
hooks: ## Install the git pre-push hook that runs `make ci`
	$(PY) scripts/install_hooks.py

clean: ## Remove caches and build artifacts
	rm -rf .mypy_cache .ruff_cache .pytest_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
