.DEFAULT_GOAL := help
API := apps/api
GATEWAY := apps/gateway
WORKER := apps/worker
PY := $(API)/.venv/Scripts/python.exe

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## Create one virtualenv for the API, gateway and findings worker
	python -m venv $(API)/.venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e "$(API)[dev]" -e "$(GATEWAY)[dev]" -e "$(WORKER)[dev]"

.PHONY: up
up: ## Start the local backing services
	docker compose -f docker/docker-compose.yml up -d

.PHONY: down
down: ## Stop the local backing services
	docker compose -f docker/docker-compose.yml down

.PHONY: migrate
migrate: ## Apply database migrations
	cd $(API) && .venv/Scripts/python.exe -m alembic upgrade head

.PHONY: seed
seed: ## Create the first organization and Owner
	cd $(API) && .venv/Scripts/python.exe -m aegis_api.cli seed

.PHONY: run
run: ## Run the API with reload
	cd $(API) && .venv/Scripts/python.exe -m uvicorn aegis_api.main:app --reload --port 8080

.PHONY: run-gateway
run-gateway: ## Run agent ingest on port 8081 (shares AEGIS_JWT_SECRET with the API)
	$(PY) -m uvicorn aegis_gateway.main:app --reload --port 8081

.PHONY: run-worker
run-worker: ## Fold gateway events into durable control-plane findings
	$(PY) -m aegis_worker.main

.PHONY: demo-vulnerable
demo-vulnerable: ## Run the vulnerable Java app and require a dashboard finding
	$(PY) scripts/run_vulnerable_demo.py

.PHONY: fmt
fmt: ## Format Python sources
	$(PY) -m black $(API)
	$(PY) -m ruff format $(API)

.PHONY: lint
lint: ## Lint Python sources
	$(PY) -m ruff check $(API)
	$(PY) -m black --check $(API)

.PHONY: types
types: ## Type-check the API
	cd $(API) && .venv/Scripts/python.exe -m mypy src

.PHONY: layering
layering: ## Enforce the hexagonal layer boundaries (ADR-0002)
	$(PY) scripts/check_layering.py

.PHONY: test
test: ## Run the full test suite with coverage
	cd $(API) && .venv/Scripts/python.exe -m pytest

.PHONY: test-fast
test-fast: ## Run only the unit suite (no database required)
	cd $(API) && .venv/Scripts/python.exe -m pytest tests/unit --no-cov -q

.PHONY: smoke
smoke: ## Exercise the API end to end against the dev database
	cd $(API) && .venv/Scripts/python.exe ../../scripts/smoke.py

.PHONY: check
check: lint types layering test ## Run every quality gate
