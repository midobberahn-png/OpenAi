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

.PHONY: gate-secrets
gate-secrets: ## Secret-Scan über den gesamten Verlauf (dieselbe Prüfung wie in CI)
	@# Diese Prüfung fehlte hier, und das hat gekostet: Ein Block ging mit
	@# grünem Gate raus und blieb im PR an einem roten Secret-Scan haengen —
	@# an zwei Fehlalarmen, die lokal in Sekunden zu klaeren gewesen waeren.
	@# Das ist die Kehrseite des bekannten Falls „CI prueft die
	@# Browserdurchstiche nicht": Wo Gate und CI verschieden viel pruefen,
	@# faellt der Unterschied dem auf die Fuesse, der zuerst darauf trifft.
	@command -v gitleaks >/dev/null 2>&1 || { \
		echo "✗ gitleaks fehlt — 'brew install gitleaks'."; \
		echo "  Wird bewusst nicht uebersprungen: CI fuehrt diese Pruefung."; \
		echo "  Ein Gate, das sie still auslaesst, meldet Gruen fuer etwas,"; \
		echo "  das es nicht geprueft hat."; \
		exit 1; }
	@# Der gesamte Verlauf, nicht nur die neuen Commits: Ein Geheimnis wirkt
	@# ab dem Moment, in dem es gepusht wurde, und nicht erst, wenn jemand die
	@# Zeile wieder anfasst. CI sieht im PR nur dessen Commits — hier ist die
	@# Zusage also die staerkere, und das ist die richtige Richtung.
	gitleaks git --no-banner

.PHONY: gate
gate: lint types gen-check gate-secrets ## Vollständiges Gate inkl. erzwungener Integrationstests
	$(UV) run pytest -q
	JARVIS_REQUIRE_SERVICES=1 $(UV) run pytest -m integration -q
	$(UV) run pytest -m security -q
	$(UV) run pytest tests/unit/test_invariant_coverage.py -q -s
	$(MAKE) gate-web

.PHONY: gate-web
gate-web: ## Die Oberfläche im Gate: bauen, dann im Browser durchspielen
	@# Getrennt und nicht in einer Zeile, weil hier zwei verschiedene Dinge
	@# schiefgehen können: ein Bau, der nicht typprüft, und ein Durchstich, der
	@# nicht durchläuft. Eine gemeinsame Zeile verstecke das eine hinter dem
	@# anderen.
	@if [ ! -d apps/web/node_modules ]; then \
		echo "✗ apps/web/node_modules fehlt — 'make web' ausführen."; exit 1; \
	fi
	cd apps/web && npm run build
	@# Die API wird für den Durchstich selbst gestartet: Ein Gate, das eine
	@# laufende Instanz voraussetzt, prüft je nach Umgebung etwas anderes.
	@# ``WEBAUTHN_ORIGINS`` muss zu der Adresse passen, unter der der Browser
	@# die Seite öffnet — daran hängt die Passkey-Bindung, und ein Test, der
	@# das ignoriert, prüfte eine Anmeldung ohne Herkunftsprüfung.
	@JARVIS_WEB_URL=http://localhost:8000 \
	 WEBAUTHN_ORIGINS=http://localhost:8000 \
	 $(UV) run uvicorn jarvis_api.main:app --host 127.0.0.1 --port 8000 --log-level warning & \
	 API=$$!; \
	 for i in $$(seq 1 40); do curl -sf localhost:8000/health >/dev/null && break || sleep 0.25; done; \
	 (cd apps/web && JARVIS_WEB_URL=http://localhost:8000 npx playwright test); \
	 ERGEBNIS=$$?; kill $$API 2>/dev/null; exit $$ERGEBNIS

.PHONY: web
web: ## Oberfläche bauen (nach apps/web/dist, wird von der API ausgeliefert)
	cd apps/web && npm ci --silent && npm run build

.PHONY: e2e
e2e: ## Durchstiche im Browser gegen eine laufende API
	@echo "→ erwartet eine API auf $${JARVIS_WEB_URL:-http://localhost:8000}"
	cd apps/web && npx playwright test

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
