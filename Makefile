.DEFAULT_GOAL := help
SHELL := /bin/bash
UV := uv

.PHONY: help
help: ## Diese Übersicht
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --------------------------------------------------------------------------
# Einrichtung
# --------------------------------------------------------------------------
.PHONY: setup
setup: ## Abhängigkeiten installieren und .env anlegen
	$(UV) sync --python 3.12
	@test -f .env || (cp .env.example .env && echo "→ .env aus Vorlage erstellt, bitte ausfüllen")

.PHONY: up
up: ## Postgres und Redis starten
	docker compose up -d
	@echo "→ warte auf Datenbank…"
	@until docker compose exec -T postgres pg_isready -U jarvis -d jarvis >/dev/null 2>&1; \
		do sleep 1; done
	@echo "→ bereit"

.PHONY: down
down: ## Dienste stoppen
	docker compose down

.PHONY: reset-db
reset-db: ## ⚠ Datenbank komplett neu aufsetzen (Datenverlust)
	docker compose down -v
	$(MAKE) up
	$(MAKE) migrate

# --------------------------------------------------------------------------
# Datenbank
# --------------------------------------------------------------------------
.PHONY: migrate
migrate: ## Migrationen anwenden
	cd apps/api && $(UV) run alembic upgrade head

.PHONY: migration
migration: ## Neue Migration erzeugen: make migration m="beschreibung"
	cd apps/api && $(UV) run alembic revision --autogenerate -m "$(m)"

.PHONY: seed
seed: ## Scope-Katalog und Standardberechtigungen einspielen
	$(UV) run python scripts/seed.py

# --------------------------------------------------------------------------
# Qualität
# --------------------------------------------------------------------------
.PHONY: lint
lint: ## Ruff und Formatprüfung
	$(UV) run ruff check .
	$(UV) run ruff format --check .

.PHONY: fmt
fmt: ## Automatisch formatieren
	$(UV) run ruff check --fix .
	$(UV) run ruff format .

.PHONY: types
types: ## mypy strict
	$(UV) run mypy packages apps/api

.PHONY: test
test: ## Unit-Tests
	$(UV) run pytest -m "not integration and not eval"

.PHONY: test-all
test-all: ## Alle Tests inkl. Integration (benötigt make up)
	$(UV) run pytest

.PHONY: test-security
test-security: ## Injection- und Policy-Suite (blockierend in CI)
	$(UV) run pytest -m security

.PHONY: cov
cov: ## Testabdeckung
	$(UV) run pytest --cov --cov-report=term-missing --cov-report=html

.PHONY: proof
proof: ## Beweislauf: Integrationstests MÜSSEN laufen, Überspringen ist ein Fehler
	@echo "→ Dienste prüfen"
	@docker compose ps --status running --format '{{.Service}}' | sort | tr '\n' ' '; echo
	JARVIS_REQUIRE_SERVICES=1 $(UV) run pytest -m integration -q -rs

.PHONY: gate
gate: lint types gen-check ## Vollständiges Gate inkl. erzwungener Integrationstests
	$(UV) run pytest -q
	JARVIS_REQUIRE_SERVICES=1 $(UV) run pytest -m integration -q
	$(UV) run pytest -m security -q
	$(UV) run pytest tests/unit/test_invariant_coverage.py -q -s

.PHONY: check
check: lint types test ## Vollständige lokale Prüfung

# --------------------------------------------------------------------------
# Codegenerierung (ADR-006)
# --------------------------------------------------------------------------
.PHONY: gen
gen: ## OpenAPI, TypeScript-Typen und Werkzeugkatalog erzeugen
	$(UV) run python scripts/gen_contracts.py

.PHONY: gen-check
gen-check: gen ## CI: bricht ab, wenn generierte Artefakte veraltet sind
	@git diff --exit-code -- apps/web/lib docs/generated \
		|| (echo "✗ Generierte Artefakte sind veraltet. 'make gen' ausführen und committen."; exit 1)

# --------------------------------------------------------------------------
# Notfall
# --------------------------------------------------------------------------
.PHONY: panic
panic: ## ⛔ Alle Läufe stoppen, schreibende Rechte entziehen, Geräte freigeben
	$(UV) run python scripts/panic.py
