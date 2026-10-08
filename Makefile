# Developer shortcuts for the Docker Compose stack. `make` lists targets.
.DEFAULT_GOAL := help
COMPOSE := docker compose

.PHONY: help up down logs ps build shell test check migrate

help: ## Show available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

up: ## Start the stack and wait until healthy (http://127.0.0.1:5000)
	$(COMPOSE) up -d --build --wait

down: ## Stop the stack (keeps the database volume)
	$(COMPOSE) down

logs: ## Follow logs of all services
	$(COMPOSE) logs -f

ps: ## Show service status
	$(COMPOSE) ps

build: ## Rebuild images
	$(COMPOSE) build

shell: ## Open a shell in the web container
	$(COMPOSE) exec web bash

test: ## Run the test suite inside the web container
	$(COMPOSE) run --rm --no-deps -v ./tests:/app/tests web pytest

check: ## Run all git hooks (lint, format, layer rules, secrets) locally
	uv run pre-commit run --all-files

migrate: ## Apply database migrations (available from #4)
	@echo "No migrations yet: Alembic arrives with #4."
