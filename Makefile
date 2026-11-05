# DevSecShield — one-line commands.  `make help` lists them.
#
# Every target wraps a script that already lives in the repo, so the Makefile adds no logic of its own:
#   scripts/deploy/build_images.sh, scripts/deploy/staging.sh, scripts/release/scan_node_image.sh,
#   scripts/crypto_kb/build_kb.py, e2e/scripts/all.sh.
# Python suites use each project's own virtualenv (uv layout: <project>/.venv); override with BACKEND_PY=..., etc.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

# ---- settings (override on the command line: make deploy-staging HOST=deploy@staging.example.com) -------------
HOST        ?=
DIR         ?= /opt/devsecshield-staging
PROD_DIR    ?= /opt/devsecshield
DSS_TAG     ?=
API_URL     ?=
VERSION     ?=
# A rollback across a release that added migrations downgrades the database first (it drops what they added): the
# remote staging.sh asks on the terminal, or ALLOW_DOWNGRADE=1 consents up front.
ALLOW_DOWNGRADE ?=
ROLLBACK_ARGS := $(if $(filter 1,$(ALLOW_DOWNGRADE)),--allow-downgrade)
COMPOSE     := docker compose -f deploy/staging/docker-compose.yml --env-file deploy/staging/.env
BACKEND_PY  ?= backend/.venv/bin/python
ENGINE_PY   ?= aibom/.venv/bin/python
NODE_PY     ?= scan_node/.venv/bin/python
WORKER_PY   ?= RabbitMQ/worker/.venv/bin/python

# Exported only when given: an empty DSS_TAG in the environment would override deploy/staging/.env for Compose.
ifneq ($(strip $(DSS_TAG)),)
export DSS_TAG
endif

##@ Local stack (the production images, run from deploy/staging on this machine)

.PHONY: init-env
init-env: ## Create deploy/staging/.env and backend.env from the examples (mode 600) if they do not exist
	@cd deploy/staging && for f in .env backend.env; do \
	  if [ -e "$$f" ]; then echo "keep   deploy/staging/$$f"; \
	  else cp "$$f.example" "$$f" 2>/dev/null || cp "$${f#.}.example" "$$f"; chmod 600 "$$f"; echo "create deploy/staging/$$f (edit it)"; fi; done

.PHONY: up
up: ## Start the whole stack locally (needs `make build` first and deploy/staging/.env)
	@test -f deploy/staging/.env || { echo "run: make init-env (then edit deploy/staging/.env)"; exit 1; }
	$(COMPOSE) up -d --wait

.PHONY: down
down: ## Stop the local stack (data volumes are kept)
	$(COMPOSE) down

.PHONY: logs
logs: ## Follow the local stack's logs (SERVICE=backend to pick one)
	$(COMPOSE) logs -f --tail=200 $(SERVICE)

.PHONY: ps
ps: ## Show the local stack's containers and health
	$(COMPOSE) ps

##@ Build

.PHONY: build
build: ## Build all production images (API_URL=https://api.example.com is baked into the frontend)
	@test -n "$(API_URL)" || { echo "set API_URL, e.g. make build API_URL=https://devsec-staging-api.zeroshield.ai"; exit 1; }
	NEXT_PUBLIC_BACKEND_URL="$(API_URL)" scripts/deploy/build_images.sh

.PHONY: node-image
node-image: ## Build the scan-node image and save it as dist/scan-node/scan-node-<VERSION>.tar.gz (+ .sha256)
	@test -n "$(VERSION)" || { echo "set VERSION, e.g. make node-image VERSION=1.1.0"; exit 1; }
	scripts/release/scan_node_image.sh build "$(VERSION)"

.PHONY: node-lock
node-lock: ## Regenerate scan_node/requirements.lock (hashed) after changing scan_node/requirements.txt
	scripts/release/scan_node_image.sh lock

.PHONY: airgap-bundle
airgap-bundle: ## Save every image, infrastructure included, into one archive for an air-gapped site (deploy/staging/images/)
	STAGING_INCLUDE_INFRA=1 scripts/deploy/staging.sh save

.PHONY: kb
kb: ## Rebuild the offline crypto knowledge base into both copies (VERSION=2026.11.05.1, must sort after the current one)
	@test -n "$(VERSION)" || { echo "set VERSION, e.g. make kb VERSION=2026.11.05.1"; exit 1; }
	cd scripts/crypto_kb && python3 build_kb.py "$(VERSION)" ../../backend/utilities/cbom_sources/data/crypto_kb.json
	cp backend/utilities/cbom_sources/data/crypto_kb.json aibom/src/aibom/cbom/data/crypto_kb.json
	cmp backend/utilities/cbom_sources/data/crypto_kb.json aibom/src/aibom/cbom/data/crypto_kb.json
	@echo "knowledge base $(VERSION) written to both copies"

##@ Test

.PHONY: test
test: test-backend test-engine test-node test-worker test-frontend ## Run every suite (backend, engine, scan node, worker, frontend types)

.PHONY: test-backend
test-backend: ## Backend tests
	cd backend && ../$(BACKEND_PY) -m pytest -q -p no:cacheprovider tests

.PHONY: test-engine
test-engine: ## Code-scan engine (aibom) tests
	cd aibom && ../$(ENGINE_PY) -m pytest -q -p no:cacheprovider tests

.PHONY: test-node
test-node: ## Scan-node tests
	cd scan_node && ../$(NODE_PY) -m pytest -q -p no:cacheprovider tests

.PHONY: test-worker
test-worker: ## Scan-worker tests (the live-LLM checks skip unless RUN_LIVE_LLM_TESTS=1)
	cd RabbitMQ/worker && $(abspath $(WORKER_PY)) -m pytest -q -p no:cacheprovider tests \
	  helpers/tests/test_git_allowed_hosts.py helpers/tests/test_safe_zip_extract.py helpers/tests/test_scan_input_links.py

.PHONY: test-frontend
test-frontend: ## Frontend type check
	cd frontend && npx tsc --noEmit

.PHONY: lint
lint: ## Syntax errors and undefined names in Python (ruff E9,F63,F7,F82,F823) plus the frontend type check
	@# archived.py is a dead module (nothing imports it); the images run Python 3.12
	ruff check --target-version py312 --select E9,F63,F7,F82,F823 \
	  --extend-exclude RabbitMQ/worker/helpers/context/archived.py backend aibom/src scan_node RabbitMQ/worker
	cd frontend && npx tsc --noEmit

.PHONY: e2e
e2e: ## Browser end-to-end suite in Docker (e2e/scripts/all.sh; add ARGS=--teardown to remove the stack after)
	bash e2e/scripts/all.sh $(ARGS)

##@ Deploy

.PHONY: deploy-staging
deploy-staging: ## Build, save, copy and start on staging: make deploy-staging HOST=user@host API_URL=https://devsec-staging-api.zeroshield.ai
	@test -n "$(HOST)" || { echo "set HOST=user@staging-host"; exit 1; }
	@test -n "$(API_URL)" || { echo "set API_URL (the staging API URL baked into the frontend)"; exit 1; }
	NEXT_PUBLIC_BACKEND_URL="$(API_URL)" scripts/deploy/staging.sh release "$(HOST)" "$(DIR)"

.PHONY: check-staging
check-staging: ## Health and hydration checks on the staging host: make check-staging HOST=user@host
	@test -n "$(HOST)" || { echo "set HOST=user@staging-host"; exit 1; }
	ssh $(SSH_OPTS) "$(HOST)" "cd '$(DIR)' && scripts/deploy/staging.sh check"

.PHONY: rollback-staging
rollback-staging: ## Roll staging back to the previous release (asks before a database downgrade; ALLOW_DOWNGRADE=1): make rollback-staging HOST=user@host
	@test -n "$(HOST)" || { echo "set HOST=user@staging-host"; exit 1; }
	ssh -t $(SSH_OPTS) "$(HOST)" "cd '$(DIR)' && scripts/deploy/staging.sh rollback $(ROLLBACK_ARGS)"

.PHONY: deploy-prod
deploy-prod: ## PRODUCTION deploy (asks you to type the host): make deploy-prod HOST=user@prod-host API_URL=https://devsecshieldapi.zeroshield.ai
	@test -n "$(HOST)" || { echo "set HOST=user@prod-host"; exit 1; }
	@test -n "$(API_URL)" || { echo "set API_URL (the production API URL baked into the frontend)"; exit 1; }
	@echo "PRODUCTION deploy of $$(git rev-parse --short HEAD) to $(HOST):$(PROD_DIR) with API $(API_URL)."
	@echo "Rollback past the Argon2 release locks out users whose password hash was upgraded (deploy/staging/README.md)."
	@read -r -p "Type the host ($(HOST)) to continue: " answer; [ "$$answer" = "$(HOST)" ] || { echo "aborted"; exit 1; }
	DSS_IMAGE_PREFIX=dss-prod NEXT_PUBLIC_BACKEND_URL="$(API_URL)" scripts/deploy/staging.sh release "$(HOST)" "$(PROD_DIR)"

.PHONY: rollback-prod
rollback-prod: ## Roll PRODUCTION back to the previous release (asks you to type the host, and before a database downgrade)
	@test -n "$(HOST)" || { echo "set HOST=user@prod-host"; exit 1; }
	@read -r -p "Type the host ($(HOST)) to roll PRODUCTION back: " answer; [ "$$answer" = "$(HOST)" ] || { echo "aborted"; exit 1; }
	ssh -t $(SSH_OPTS) "$(HOST)" "cd '$(PROD_DIR)' && DSS_IMAGE_PREFIX=dss-prod scripts/deploy/staging.sh rollback $(ROLLBACK_ARGS)"

##@ Help

.PHONY: help
help: ## List the commands
	@awk 'BEGIN {FS = ":.*## "} /^##@/ {printf "\n%s\n", substr($$0, 5)} /^[a-zA-Z0-9_-]+:.*## / {printf "  make %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo
