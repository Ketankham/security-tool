.PHONY: sync lint fmt typecheck test test-unit test-integration up down logs migrate revision \
        licence-check api worker clean

sync:            ## Install/sync all workspace packages
	uv sync --all-packages

lint:            ## Ruff lint
	uv run ruff check apps packages

fmt:             ## Ruff format + fix
	uv run ruff format apps packages
	uv run ruff check --fix apps packages

typecheck:       ## mypy across the workspace
	uv run mypy apps packages

test:            ## Full test suite
	uv run pytest

test-unit:       ## Unit tests only (fast, no docker)
	uv run pytest tests/unit packages/*/tests -m "not integration"

test-integration: ## Requires: make up
	uv run pytest tests/integration -m integration

licence-check:   ## Fail on GPL/AGPL/unknown-licence deps (see ADR-0002)
	uv run python infra/scripts/licence_check.py

up:              ## Start local dev stack (postgres, redis, api, worker)
	docker compose up -d --build

down:
	docker compose down -v

logs:
	docker compose logs -f

migrate:         ## Apply DB migrations
	uv run --package sentinel-db alembic -c packages/db/alembic.ini upgrade head

revision:        ## Autogenerate a new migration: make revision m="add foo"
	uv run --package sentinel-db alembic -c packages/db/alembic.ini revision --autogenerate -m "$(m)"

api:             ## Run the API locally (outside docker) with reload
	uv run --package sentinel-api uvicorn sentinel_api_app.main:app --app-dir apps/api --reload --port 8000

worker:          ## Run a Celery worker locally (outside docker)
	uv run --package sentinel-worker celery -A sentinel_worker_app.celery_app worker --workdir apps/worker --loglevel INFO

clean:
	find . -type d -name '__pycache__' -not -path './.git/*' -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache
