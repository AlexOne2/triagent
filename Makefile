ENV_FILE = infra/.env
ENV_EXAMPLE = infra/.env.example
COMPOSE = docker compose -f infra/docker-compose.yml --env-file $(ENV_FILE)

.PHONY: dev migrate seed down ensure-env build-backend

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
