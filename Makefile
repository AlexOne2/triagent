ENV_FILE = infra/.env
ENV_EXAMPLE = infra/.env.example
COMPOSE = docker compose -f infra/docker-compose.yml --env-file $(ENV_FILE)

.PHONY: dev migrate seed import-synthetic remove-synthetic down ensure-env build-backend wait-db audit-verify audit-export audit-prune campaign-backfill campaign-recluster campaign-metrics campaign-eval triage-backfill reset-data demo-reset

ensure-env:
	@if [ ! -f $(ENV_FILE) ]; then cp $(ENV_EXAMPLE) $(ENV_FILE); echo "Created $(ENV_FILE) from $(ENV_EXAMPLE)"; fi

dev: ensure-env
	$(COMPOSE) up --build

build-backend: ensure-env
	$(COMPOSE) build backend

wait-db: ensure-env
	$(COMPOSE) up -d postgres minio
	@echo "Waiting for postgres..."
	@until $(COMPOSE) exec -T postgres sh -lc 'pg_isready -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"' >/dev/null 2>&1; do sleep 1; done

migrate: wait-db
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend alembic upgrade head

seed: wait-db
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend python -m scripts.seed

import-synthetic: wait-db
	$(COMPOSE) build backend
	$(COMPOSE) run --rm -v "$(CURDIR):/workspace" backend python -m scripts.import_synthetic_corpus --corpus-root "/workspace/$(or $(CORPUS_ROOT),test_data/synthetic-corpus)" --split "$(or $(SPLIT),gold)" $(if $(LIMIT),--limit "$(LIMIT)",) $(if $(OPEN_ONLY),--open-only,) $(if $(REFRESH_EXISTING),--refresh-existing,)

remove-synthetic: wait-db
	$(COMPOSE) build backend
	$(COMPOSE) run --rm -v "$(CURDIR):/workspace" backend python -m scripts.remove_synthetic_corpus --corpus-root "/workspace/$(or $(CORPUS_ROOT),test_data/synthetic-corpus)" --split "$(or $(SPLIT),gold)" $(if $(LIMIT),--limit "$(LIMIT)",) $(if $(DRY_RUN),--dry-run,)

down:
	$(COMPOSE) down

audit-verify: wait-db
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend python -m scripts.audit_maintenance verify

audit-export: wait-db
	@if [ -z "$(START)" ] || [ -z "$(END)" ]; then echo "Usage: make audit-export START=2026-01-01T00:00:00Z END=2026-02-01T00:00:00Z"; exit 1; fi
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend python -m scripts.audit_maintenance export --start "$(START)" --end "$(END)"

audit-prune: wait-db
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend python -m scripts.audit_maintenance prune

campaign-backfill: wait-db
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend python -m scripts.campaign_maintenance backfill

campaign-recluster: wait-db
	@if [ -z "$(START)" ] && [ -z "$(END)" ]; then \
		$(COMPOSE) build backend; \
		$(COMPOSE) run --rm backend python -m scripts.campaign_maintenance recluster; \
	else \
		$(COMPOSE) build backend; \
		$(COMPOSE) run --rm backend python -m scripts.campaign_maintenance recluster --start "$(START)" --end "$(END)"; \
	fi

campaign-metrics: wait-db
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend python -m scripts.campaign_maintenance metrics

campaign-eval: wait-db
	$(COMPOSE) build backend
	$(COMPOSE) run --rm -v "$(CURDIR):/workspace" backend python -m scripts.campaign_maintenance evaluate --manifest "/workspace/$(or $(MANIFEST),test_data/demo-dataset-50/manifest.json)"

triage-backfill: wait-db
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend python -m scripts.backfill_triage_assessments $(if $(LIMIT),--limit "$(LIMIT)",) $(if $(REFRESH_EXISTING),--refresh-existing,)

reset-data: wait-db
	$(COMPOSE) build backend
	$(COMPOSE) run --rm backend python -m scripts.reset_ingested_data

demo-reset: migrate
	$(COMPOSE) build backend
	$(COMPOSE) run --rm -v "$(CURDIR):/workspace" backend python -m scripts.demo_reset --corpus-root "/workspace/$(or $(CORPUS_ROOT),test_data/synthetic-corpus)" --split "$(or $(SPLIT),gold)" $(if $(LIMIT),--limit "$(LIMIT)",) $(if $(INCLUDE_SEED),--include-seed,) $(if $(KEEP_AUDIT),--keep-audit,) $(if $(RESOLVED),--apply-expected-resolution,)
