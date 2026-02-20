ENV_FILE = infra/.env
ENV_EXAMPLE = infra/.env.example
COMPOSE = docker compose -f infra/docker-compose.yml --env-file $(ENV_FILE)

.PHONY: dev migrate seed down ensure-env build-backend audit-verify audit-export audit-prune

ensure-env:
	@if [ ! -f $(ENV_FILE) ]; then cp $(ENV_EXAMPLE) $(ENV_FILE); echo "Created $(ENV_FILE) from $(ENV_EXAMPLE)"; fi

dev: ensure-env
	$(COMPOSE) up --build

build-backend: ensure-env
	$(COMPOSE) build backend

migrate: ensure-env
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend alembic upgrade head

seed: ensure-env
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend python -m scripts.seed

down:
	$(COMPOSE) down

audit-verify: ensure-env
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend python -m scripts.audit_maintenance verify

audit-export: ensure-env
	@if [ -z "$(START)" ] || [ -z "$(END)" ]; then echo "Usage: make audit-export START=2026-01-01T00:00:00Z END=2026-02-01T00:00:00Z"; exit 1; fi
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend python -m scripts.audit_maintenance export --start "$(START)" --end "$(END)"

audit-prune: ensure-env
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend python -m scripts.audit_maintenance prune
