# AEGIS development task runner.
#
# Run `make` or `make help` to see the available targets.
#
# Override the install extras on the command line:
#     make install EXTRAS=dev,e2e
#     make install EXTRAS=broker,identity,e2e

EXTRAS ?= all,dev,e2e

COMPOSE_FILE := tests/e2e/docker-compose.e2e.yaml

.PHONY: help install monitor test test-e2e test-e2e-down test-all lint format clean

.DEFAULT_GOAL := help

help:  ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	    awk 'BEGIN{FS=":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install aegis-shield (override extras with EXTRAS=...) and aegis-monitor
	pip install -e ".[$(EXTRAS)]"
	pip install -e "./aegis-monitor[dev]"

monitor:  ## Start the aegis-monitor service locally on :8080
	cd aegis-monitor && uvicorn monitor.app:app --host 0.0.0.0 --port 8080 --reload

test:  ## Run unit/integration tests (excludes e2e)
	pytest tests/ --ignore=tests/e2e -v

test-e2e:  ## Run e2e tests in docker-compose
	docker compose -f $(COMPOSE_FILE) up --build \
	    --abort-on-container-exit --exit-code-from test-runner

test-e2e-down:  ## Tear down e2e docker-compose stack
	docker compose -f $(COMPOSE_FILE) down -v

test-all: test test-e2e  ## Run all tests (unit + e2e)

lint:  ## Run ruff linter
	ruff check .

format:  ## Auto-format with ruff
	ruff format .

clean:  ## Remove caches and build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache build dist
