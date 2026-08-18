# JARVIS — Übergabe an eine neue Sitzung

> Stand: 18.08.2026, Commit `7920dc0`. Dieses Dokument ist der Einstieg für
> eine frische Claude-Code-Sitzung. Es ersetzt kein Architekturdokument,
> sondern sagt, wo das Projekt steht und was als Nächstes zu tun ist.

---

## 1. Was das Projekt ist

Ein selbst gehostetes, provider-unabhängiges persönliches KI-Assistenzsystem
(„JARVIS"). Sprache, Text, Bild, Gesten; dauerhaftes Gedächtnis; Werkzeuge und
Sub-Agenten. **Der prägende Gedanke ist nicht „welches LLM?", sondern „was darf
ein LLM in diesem System bewirken?"** — deshalb wurde der Sicherheitssockel vor
jeder Modellanbindung gebaut.

Kommunikationssprache mit dem Nutzer: **Deutsch**. Auch Code-Kommentare,
Docstrings, Commit-Nachrichten und Testnamen sind deutsch.

---

## 2. Aktueller Stand

| | |
|---|---|
| Commits | 7 (`9875468` … `7920dc0`), lokaler Branch `master`, kein Remote |
| Tests | **319** gesamt — 90 mit `-m security`, 37 mit `-m integration` |
| **Security Invariant Coverage** | **26/29** |
| mypy | `strict`, sauber über 38 Dateien |
| Ruff | sauber (check + format) |
| Datenbank | 30 Tabellen, 4 Migrationen, bi-direktional geprüft |
| Verträge | 95 exportierte Typen in `jarvis_contracts` |

### Commit-Historie

```
7920dc0  chore(core): Orchestrator-Invarianten als PLANNED aufgenommen
e0c5c05  feat(core): Approval Gateway, Ausführungs-Gate, Angriffe B/C/G geschlossen
8baa5c0  feat(core): Security Invariant Coverage als Leitkennzahl
831b50a  feat(core): Policy Engine, Tool Registry, Taint-Gate scharfgestellt
b466450  feat(core): typisierter Run-State/FSM und hash-verkettetes Audit-Log
c7971b4  feat: Architektur V1.1 — Taint-Gate, Identity, Ziele, Entitäten
9875468  feat: Fundament — Verträge, Datenmodell, Migrationen, CI
```

---

## 3. Umgebung aufsetzen

```bash
export PATH="$HOME/.local/bin:/opt/homebrew/bin:$PATH"
cd ~/jarvis

colima start                      # Container-Runtime (Docker Desktop ist NICHT installiert)
docker compose up -d              # Postgres 16 + pgvector, Redis 7
uv sync --all-packages --python 3.12

export DATABASE_URL="postgresql+asyncpg://jarvis:jarvis_dev@localhost:5432/jarvis"
(cd apps/api && uv run alembic upgrade head)
uv run python scripts/seed.py     # 34 Scopes
```

**Wichtig:**

- `docker compose` ist als CLI-Plugin verlinkt (`~/.docker/cli-plugins/docker-compose` → Homebrew).
- **Python 3.12 ist gepinnt.** Das System-Python ist 3.14.6; für MediaPipe,
  CTranslate2 und openWakeWord gibt es dort keine Wheels (ADR-001).
- `timeout` existiert auf diesem macOS nicht — nicht in Skripten verwenden.

### Vollständiges Gate

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy packages apps/api
uv run python scripts/gen_contracts.py     # muss idempotent sein
uv run pytest -q
uv run pytest -m security -q               # blockierend
uv run pytest tests/unit/test_invariant_coverage.py -q -s   # zeigt die Kennzahl
```

---

## 4. Architektur — die fünf nicht verhandelbaren Entscheidungen

Vollständig in `docs/` (18 Dokumente). Einstieg: `docs/00-uebersicht.md`.
Die Bewertung zweier externer Reviews steht in `docs/16-v1.1-review.md`,
einschließlich der **abgelehnten** Vorschläge mit Begründung — damit spätere
Diskussionen dieselben Wege nicht erneut gehen.

1. **Taint-Tracking statt Injection-Erkennung.** Ein Lauf, der Fremdinhalt
   gelesen hat, verliert seine sendenden Werkzeuge. Nicht versuchen, Angriffe
   zu *erkennen* — sie folgenlos machen.
2. **Datenklassifikation P0–P3 ist ein hartes Filter** auf die Modellwahl, keine
   Präferenz. P3 verlässt das Gerät nie.
3. **Berechtigungen sind Daten, kein Code.** Die Policy Engine ist der einzige
   Weg zur Werkzeugausführung.
4. **Rohdaten bleiben an der Kante.** Das WebSocket-Protokoll kennt keinen
   Nachrichtentyp für Audio oder Videoframes.
5. **Kein Agenten-Framework im Kern** (kein LangChain/LangGraph). Begründung in
   ADR-002.

### Taint-Sanitization-Gate (der wichtigste Mechanismus)

V1.0 hatte einen Widerspruch: Das Ablaufdiagramm zeigte „Mails lesen → Termin
anlegen" als erfolgreich, die Policy sperrte es. Ein Sicherheitsmechanismus,
der den Normalfall blockiert, wird abgeschaltet.

Auflösung: Kontamination lässt sich aufheben, **aber nur wo die Bestätigung
eine echte Prüfung ist**:

| Payload | Sanierbar |
|---|---|
| `structured` — kurze typisierte Felder (`calendar.create` ohne Teilnehmer) | ✅ nach Bestätigung |
| `freeform` — Freitext mit Außenwirkung (`mail.send`) | ❌ nie |
| `opaque` (`shell.exec`) | ❌ nie |
| alles `CRITICAL` | ❌ nie |

**`ToolSpec.outbound_fields`** macht die Einstufung *pro Aufruf*: Ein
Kalendereintrag mit Teilnehmern verschickt Einladungen und gilt damit als
`freeform`, unabhängig von der statischen Einstufung.

---

## 5. Was funktioniert

| Komponente | Datei | Zustand |
|---|---|---|
| Verträge | `packages/contracts/jarvis_contracts/` | 12 Module, 95 Typen |
| Zustandsautomat | `packages/core/jarvis_core/runs/fsm.py` | Übergangstabelle, 10 Zustände |
| Audit-Kette | `packages/core/jarvis_core/audit/chain.py` | Kanonisierung, Hash, Verifikation |
| Tool Registry | `packages/core/jarvis_core/tools/registry.py` | **gibt keinen Handler heraus** |
| Policy Engine | `packages/core/jarvis_core/policy/engine.py` | 7 Prüfstufen, Taint zuerst |
| Approval Gateway | `packages/core/jarvis_core/policy/approval.py` | request → respond → authorize |
| Invarianten-Register | `packages/core/jarvis_core/policy/invariants.py` | 29 Invarianten |
| Postgres-Store | `apps/api/jarvis_api/db/approval_store.py` | atomares Compare-and-Set |
| Datenmodell | `apps/api/jarvis_api/db/models.py` | 30 Tabellen |

### Bewiesene Sicherheitseigenschaften

- **Payload-Mutation** nach Bestätigung → `payload-mismatch` (auch bei einer
  einzelnen geänderten Ziffer in der Uhrzeit)
- **TOCTOU**: zwischenzeitlich entzogenes Recht → `policy-changed`
- **Replay**: 10 parallele Einlösungen in getrennten DB-Verbindungen → genau
  eine gewinnt, neun `ALREADY_USED`
- **Kanalbindung**: Geste kann UI-Dialog nicht bestätigen; fremde Sitzung ebenso
  wenig. Ausnahme mit Begründung: UI-Vorschau darf per Sprache bestätigt werden
  (der Nutzer sieht sie dabei), umgekehrt nicht.
- **Audit-Log** append-only per Trigger; Pseudonymisierung (`user_id → NULL`)
  bricht die Hash-Kette nicht, weil `user_id` nicht gehasht wird
- **Gedächtnis-Quarantäne**: `Provenance.from_tainted_run` verhindert
  automatische Übernahme, unabhängig von der Konfidenz

---

## 6. Was **nicht** existiert

Ehrliche Liste. Nichts davon ist „fast fertig".

| Fehlt | Auswirkung |
|---|---|
| **Authentifizierung** | Es gibt keinen Login. `session_id` wird durchgereicht, aber von niemandem verifiziert. Die Sitzungsbindung ist erst dann eine Sicherheitsmaßnahme, wenn Sessions echt sind. |
| **FastAPI-App** | `apps/api/jarvis_api/main.py` existiert nicht. `gen_contracts.py` überspringt die OpenAPI-Erzeugung. Keine HTTP- oder WebSocket-Endpunkte. |
| **LLM-Provider** | Kein `LLMProvider`-Adapter. Nichts ruft ein Modell auf. |
| **Orchestrator** | Punkt 9, der nächste Schritt. |
| **Audit-Sink** | Das `AuditSink`-Protokoll ist definiert, die Postgres-Implementierung fehlt. Der beschriebene `pg_advisory_xact_lock` ist **noch nirgends implementiert** — ohne ihn kann die Kette bei nebenläufigen Schreibern gabeln. |
| **Rate Limiter** | Port definiert, keine Implementierung. |
| **Agent Runtime** | Nur Verträge (`AgentSpec`), keine Laufzeit. |
| **Memory Service** | Nur Verträge und Schema, kein Retrieval-Code. |
| **Alles ab Phase 2** | Voice, Vision, UI, Integrationen. |

### Bekannte kleinere Mängel

- `PostgresApprovalStore.open_for_user()` hat ein N+1 (ruft `get()` je Zeile).
  Unkritisch bei erwarteten Mengen, aber vor der UI zu beheben.
- `ExecutionGrant` ist gegen Fremderzeugung nur per Sentinel gesichert. Python
  kann das nicht vollständig verhindern; die eigentliche Absicherung ist der
  AST-Test. Das steht so im Docstring — **nicht** als „unumgehbar" darstellen.
- Der Testhelfer `_seed()` in `tests/integration/test_approval_gateway.py`
  setzt `invocation_id = run_id`. Nur eine Testabkürzung.
- `tests/unit/test_invariant_coverage.py` sammelt Marker per AST-Scan über
  `tests/`. Wer Tests in ein anderes Verzeichnis legt, muss den Pfad anpassen.

---

## 7. Security Invariant Coverage — die Leitkennzahl

**Testabdeckung ist für diesen Kern die falsche Kennzahl.** 96 % sagen nichts
darüber, ob `kontaminiert → Bestätigung → veränderter Payload → Ausführung`
abgewehrt wird.

Stattdessen: 29 benannte Invarianten in
`packages/core/jarvis_core/policy/invariants.py`. Tests binden sich per
`@pytest.mark.invariant("<id>")`. Ein Meta-Test schlägt fehl, wenn

- eine als `ENFORCED` geführte Invariante keinen Test hat, **oder**
- ein Test sich auf eine unbekannte Kennung beruft.

Generierte Tabelle: `docs/generated/security-invariants.md`.

**Stand 26/29. Offen sind genau die drei, die Punkt 9 schließen muss:**

| Kennung | Was zu belegen ist |
|---|---|
| `orchestrator-consumes-decisions` | Der Orchestrator bildet keine eigene Meinung über Erlaubnis |
| `agent-chain-preserves-capability-binding` | Über A → B → C bleibt die Rechtemenge die Schnittmenge |
| `agent-chain-propagates-taint` | Eine Zwischenstufe darf nicht als Waschmaschine dienen |

---

## 8. Nächster Schritt: Punkt 9 — Orchestrator-Skelett

### Harte Vorgabe

Der Orchestrator ist **Konsument** von Sicherheitsentscheidungen, nicht ihr
Urheber. Erlaubter Ablauf:

```
Eingabe → klassifizieren → planen → Agent/Werkzeug wählen
        → Policy fragen → ALLOW / CONFIRM / DENY
        → Approval Gateway → Ausführungs-Gate → Werkzeug
```

Verboten:

```
Orchestrator
 ├── "das ist wahrscheinlich sicher"
 ├── "der Nutzer hat das bestimmt gemeint"
 ├── "das wurde gerade bestätigt"
 └── direkte Ausführung
```

### Umfang

1. **`packages/core/jarvis_core/orchestrator/`**
   - `classifier.py` — `TurnClassification` (zunächst regelbasiert; das lokale
     Modell kommt mit dem LLM-Provider)
   - `router.py` — deterministisch, **kein LLM**; Datenklasse als hartes Filter
   - `planner.py` — `Plan` mit `PlanStep`/`depends_on`
   - `executor.py` — Zustandsautomat über `Run`; ruft Policy und Gateway
   - `budget.py` — `Usage` gegen `RunBudget`
2. **`packages/core/jarvis_core/agents/`** — Supervisor + `effective_tools`
   über Ketten
3. **Tests für die drei offenen Invarianten**, insbesondere
   - Kette A → B → C: C erbt nicht die Fähigkeiten von B
   - Zwischenstufe liest Fremdinhalt → gesamter Lauf kontaminiert
   - AST-Test: `orchestrator/` konstruiert kein `PolicyDecision.allow()`,
     ruft `registry.execute()` nicht ohne Grant
4. **End-to-End-Test** der gesamten Kette (die Berater erwarten genau diesen):

```
Eingabe „Prüfe meine Mails und blockiere mir eine Stunde für das Wichtigste"
  → Mail-Agent → mail.read → TAINTED
  → Calendar-Agent → calendar.read
  → strukturierter Termin-Payload
  → Policy → CONFIRM → Payload-Hash
  → Re-Authorisierung → Ausführung
  → Audit + Memory-Provenance
```

Werkzeuge dafür als Attrappen registrieren — es geht um die Kette, nicht um
echte Mails.

### Danach (Reihenfolge bewusst geändert)

Ursprünglich war Auth + LLM-Provider vor dem Orchestrator geplant. Die
Reihenfolge wurde umgedreht, damit das Gate existiert, bevor ein Modell zum
ersten Mal ein Werkzeug aufrufen könnte. Nach Punkt 9 folgen daher:

1. Auth (Passkey/Session) — macht `session_id` erst echt
2. `LLMProvider` + Adapter (OpenAI, Anthropic, Ollama)
3. FastAPI-App + WebSocket
4. Web-UI

---

## 9. Arbeitsweise

Vom Nutzer vorgegeben, gilt unverändert:

- Inkrementell arbeiten. Nach jedem sinnvollen Teilabschnitt: implementieren →
  testen → Gate ausführen → Fehler beheben → committen → **kurzen Status melden**.
- Keine neuen Frameworks oder Abstraktionen ohne zwingenden Grund.
- Keine Scope-Erweiterung ohne konkreten technischen Grund.
- Der Nutzer hat pauschale Freigabe erteilt und will nicht wegen Einzelfragen
  unterbrochen werden.
- Ziel ist **kein** beeindruckendes Demo, sondern ein belastbares Fundament.

Der Nutzer lässt den Stand von zwei externen Beratern prüfen. Deren Anmerkungen
kritisch bewerten — mehrere Vorschläge wurden begründet abgelehnt (siehe
`docs/16-v1.1-review.md`). Nicht alles übernehmen, was gut klingt.

---

## 10. Fallstricke, die schon Zeit gekostet haben

| Problem | Lehre |
|---|---|
| **Deutsche Anführungszeichen** `„…"` in einzeiligen Python-Strings | Das gerade `"` beendet den String. Immer `„…“` schreiben oder einfache Anführungszeichen für den Python-String verwenden. Mehrfach passiert. |
| **`RiskLevel` erbte String-Ordnung** | `StrEnum` fällt bei Vergleich mit Fremdtypen auf lexikografisch zurück — `"critical" < "high"` ist wahr, semantisch falsch. Deshalb wird jetzt `TypeError` geworfen. |
| **Ruff `banned-api` wirkt global** | Die Schichtgrenze galt versehentlich überall. Jetzt nur in `packages/contracts` aktiv, per `per-file-ignores`. |
| **Meta-Test startete pytest als Subprozess** | Endlosrekursion, weil der Subprozess dasselbe Modul importiert. Jetzt AST-Analyse. |
| **Session-weite async-Fixture** | asyncpg: „another operation is in progress". Engine-Fixture ist funktionsweit. |
| **Audit-Trigger blockierte DSGVO-Löschung** | Der Trigger verhinderte auch das `ON DELETE SET NULL`. Genau eine Ausnahme ist zugelassen: `user_id → NULL` bei sonst identischer Zeile. |
| **`pending_actions.tool_name` fehlte** | Der Vertrag führte das Feld, die Tabelle nicht — nur der Integrationstest gegen die echte Datenbank fand es. |
| **Alembic + pgvector** | Autogenerate rendert `pgvector.sqlalchemy.VECTOR` ohne Import. `_render_item` in `migrations/env.py` behebt das. |

---

## 11. Dokumentenübersicht

| Datei | Inhalt |
|---|---|
| `docs/00-uebersicht.md` | Zielbild, Risiken, Systemdiagramm, Datenklassifikation |
| `docs/01-tech-stack.md` | 13 ADRs mit Alternativen |
| `docs/02-repo-struktur.md` | Paketgrenzen, Codegenerierung |
| `docs/03-datenmodell.md` | Schema, pgvector, Aufbewahrung |
| `docs/04-orchestrator.md` | **Für Punkt 9 die wichtigste Vorlage** |
| `docs/05-memory-context.md` | Gedächtnisebenen, Retrieval, Referenzauflösung |
| `docs/06-agenten-tools.md` | Supervisor-Muster, Tool-Vertrag |
| `docs/07-security-permissions.md` | Policy, **§4a Taint-Gate**, Secrets, Audit |
| `docs/08`–`13` | Voice, Vision, UI, API, Plugins, Deployment |
| `docs/14-roadmap.md` | Phasen 1–8 |
| `docs/15-testing.md` | Test- und Evalstrategie |
| `docs/16-v1.1-review.md` | Bewertung externer Reviews, **auch die Ablehnungen** |
| `docs/17-identity-goals.md` | Identity, Ziele, Entitäten |
| `docs/generated/` | Scope-Katalog und Invariantentabelle — **generiert, nicht bearbeiten** |

Artifact mit der Architekturübersicht:
https://claude.ai/code/artifact/10372b84-e5da-4b9e-8262-46ec9ae5e37b
