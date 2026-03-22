# ============================================================
# IoT Backend Security Suite — Developer Commands
# ============================================================
# All targets have a plain docker compose equivalent listed
# in case make is not available on your system.

.PHONY: help up down db migrate test test-unit test-isvs test-all logs clean

help:
	@echo ""
	@echo "IoT Backend Security Suite"
	@echo "=========================="
	@echo "  make up          Start full stack (app + db + mailhog)"
	@echo "  make down        Stop all containers"
	@echo "  make db          Start database only"
	@echo "  make migrate     Run Alembic migrations"
	@echo "  make test        Run all tests"
	@echo "  make test-unit   Run unit tests only (no server needed)"
	@echo "  make test-isvs   Run ISVS integration tests"
	@echo "  make logs        Tail app container logs"
	@echo "  make clean       Remove containers and volumes"
	@echo ""

up:
	docker compose up --build -d
	@echo "App running at http://localhost:8000"
	@echo "API docs at  http://localhost:8000/docs"
	@echo "Mailhog at   http://localhost:8025"

down:
	docker compose down

db:
	docker compose up db -d

migrate:
	alembic upgrade head

test-unit:
	pytest tests/unit/ -v --tb=short

test-isvs:
	pytest tests/isvs/ -v --tb=short

test-all:
	pytest tests/ -v --tb=short --ignore=tests/e2e

test: test-all

logs:
	docker compose logs -f app

clean:
	docker compose down -v --remove-orphans