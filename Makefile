COMPOSE = docker compose -f infra/docker-compose.yml --env-file infra/.env

.PHONY: dev migrate seed down

dev:
	$(COMPOSE) up --build

migrate:
	$(COMPOSE) run --rm backend alembic upgrade head

seed:
	$(COMPOSE) run --rm backend python -m scripts.seed

down:
	$(COMPOSE) down
