# JARVIS — Übergabe an eine neue Sitzung

> Stand: 19.08.2026, Commit `476461d`. Dieses Dokument ist der Einstieg für
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

Das Repository liegt auf GitHub: `git@github.com:midobberahn-png/OpenAi.git`
(Branch `main`). Der Name des Repositories passt nicht zum Projekt — eine
Umbenennung steht aus.

---

## 2. Aktueller Stand

| | |
|---|---|
| Commits | 34 (`9875468` … `476461d`), Branch `main`, Remote auf GitHub |
| Tests | **766** gesamt — 458 mit `-m security`, 117 mit `-m integration` |
| **Security Invariant Coverage** | **42/43** |
| mypy | `strict`, sauber über 85 Dateien |
| Ruff | sauber (check + format) |
| Datenbank | 32 Tabellen, 8 Migrationen, bi-direktional geprüft |
| CI | GitHub Actions mit Postgres und Redis als Dienste |

### Was seit dem letzten Dossier geschah

Punkt 9 (Orchestrator) war der letzte dokumentierte Stand. Seitdem:
Authentifizierung mit Passkeys und Sitzungen, die HTTP-Schicht, zweistufige
Zugriffsgrenzen, der LLM-Provider-Block mit Ollama-Adapter und Modellschleife —
und **zwei gefundene Sicherheitslücken**, die den Umgang mit dem Projekt
prägen sollten (Abschnitt 7).

### Der Prüfprozess, der sich bewährt hat

Externe Berater bewerteten anfangs nur Statusberichte. Das fand nichts. Seit
`scripts/pruefpaket.py` bekommen sie den sicherheitskritischen Quelltext in
sieben Portionen samt Prüfaufträgen und einer Liste falsifizierbarer
Behauptungen:

```bash
uv run python scripts/pruefpaket.py     # -> pruefpaket/ (nicht versioniert)
git bundle create /tmp/jarvis.bundle --all
```

**Beide gefundenen Bypässe stammen aus dieser Prüfung.** Keiner davon wäre
durch mehr Tests derselben Art gefunden worden.

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
make gate      # Lint, Typen, Vertragsdrift, alle Tests, Kennzahl
make proof     # nur die Integrationstests — Überspringen ist dabei ein Fehler
```

**`JARVIS_REQUIRE_SERVICES=1` ist der wichtigste Schalter dieser Suite.** Ohne
Postgres und Redis überspringt `pytest` die Integrationstests und meldet ein
sattes Grün — inklusive der Tests, die Nebenläufigkeit belegen sollen. Ein
externer Prüfer hat genau das erlebt: 702 Tests, 0 Fehler, 110 übersprungen.
Mit dem Schalter schlagen sie stattdessen fehl. In CI ist er gesetzt.

Einzeln, wenn nötig:

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy packages apps/api
uv run python scripts/gen_contracts.py     # muss idempotent sein
uv run pytest -q
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

### Sicherheitssockel

| Komponente | Datei | Zustand |
|---|---|---|
| Verträge | `packages/contracts/jarvis_contracts/` | 14 Module |
| Zustandsautomat | `core/runs/fsm.py` | Übergangstabelle, 10 Zustände |
| Audit-Kette | `core/audit/chain.py` | Kanonisierung, Hash, Verifikation |
| Tool Registry | `core/tools/registry.py` | prüft die **Herkunft** des Grants nominal |
| Policy Engine | `core/policy/engine.py` | 7 Prüfstufen, Taint zuerst |
| Approval Gateway | `core/policy/approval.py` | request → respond → **claim** → authorize |
| Grant-Verbrauch | `core/tools/grants.py`, `api/db/grant_store.py` | an der `invocation_id`, zuletzt vor dem Handler |
| Invarianten-Register | `core/policy/invariants.py` | 43 Invarianten |

### Orchestrator und Agenten

| Komponente | Datei | Zustand |
|---|---|---|
| Klassifikation | `core/orchestrator/classifier.py` | regelbasiert, stuft nur hoch |
| Router | `core/orchestrator/router.py` | deterministisch, P3 strukturell lokal |
| Planer | `core/orchestrator/planner.py` | drei Modi, lesend vor schreibend |
| Executor | `core/orchestrator/executor.py` | FSM, Policy → Gate → Registry |
| Agentenkette | `core/agents/chain.py` | Schnittmenge über alle Stufen |
| Agent Runtime | `core/agents/runtime.py` | Werkzeugmenge wird **bei jedem Zugriff** neu berechnet |
| Modellschleife | `core/agents/model_loop.py` | führt nichts aus, schlägt nur weiter |

### Anmeldung und HTTP

| Komponente | Datei | Zustand |
|---|---|---|
| Sitzungen | `core/auth/sessions.py` | Doppelfrist, Widerruf, nur Hash gespeichert |
| Passkeys | `core/auth/passkeys.py` | Ablauf im Kern, Krypto im Adapter |
| Zugriffsgrenzen | `core/limits/` | zweistufig: je Client **und** global |
| WebAuthn-Adapter | `apps/api/jarvis_api/auth/` | `py_webauthn`, Origin- und RP-ID-Bindung |
| HTTP-Grenze | `apps/api/jarvis_api/deps.py` | einzige Quelle für Identität |
| Auth-Routen | `apps/api/jarvis_api/routes/auth.py` | Bootstrap, Registrierung, Anmeldung, Sitzungen |

### Sprachmodelle

| Komponente | Datei | Zustand |
|---|---|---|
| Model Gateway | `core/providers/gateway.py` | Zulassung vor jedem Aufruf, fail closed |
| Ollama-Adapter | `packages/providers/jarvis_providers/ollama.py` | HTTP-API, Contract-Tests |

### Bewiesene Sicherheitseigenschaften

Alle mit adversarialen Tests, die meisten gegen Postgres oder Redis:

- **Payload-Mutation** nach Bestätigung → `payload-mismatch`
- **TOCTOU**: entzogenes Recht zwischen Prüfung und Ausführung → `policy-changed`
- **Replay der Nonce**: 10 parallele Einlösungen → genau eine gewinnt
- **Replay der Ausführung**: 10 parallele Autorisierungen in getrennten
  Verbindungen → genau eine gewinnt
- **Grant Confusion**: Grant aus Lauf A in Lauf B → abgewiesen
- **Gefälschter Grant**: `SimpleNamespace` mit korrektem Hash → abgewiesen
- **Kettenrechte**: A → B → C erweitert nichts, Kontamination steigt auf
- **WebAuthn**: falscher Origin, falsche RP-ID, gefälschte Signatur, Replay,
  Zählerregression — gegen die **echte** Bibliothek, mit einem
  Software-Authenticator (`tests/authenticator.py`)
- **Rate-Limit**: 100 gleichzeitige Redis-Treffer ergeben die Stände 1–100
- **Exfiltration über ein Modell**: Das Modell liest die präparierte Mail,
  schlägt `mail.send` an die fremde Adresse vor — und bekommt es nicht
- **Replay des Grants**: derselbe echte Grant zweimal, zehnmal nebenläufig,
  als vier Kopien (`model_copy`/`copy`/`deepcopy`) und über getrennte
  Datenbankverbindungen → der Handler läuft genau einmal

## 6. Was **nicht** existiert

Ehrliche Liste. Nichts davon ist „fast fertig".

| Fehlt | Auswirkung |
|---|---|
| **HTTP-Endpunkte für Läufe** | Es gibt `/auth/*` und `/health`, sonst nichts. Die Kette Identity → Run → Policy → Approval → Execution ist nur im Kern geprüft, nicht über HTTP (`docs/18-angriffskette.md`). |
| **Bestätigungs-Endpunkt** | `POST /actions/{id}/respond` fehlt. Der Mensch hat derzeit keinen Weg, auf „Ja" zu klicken. |
| **Web-UI** | Nichts. Punkt 5 der Roadmap-Phase 1. |
| **Weitere Provider** | Nur Ollama. Anthropic und OpenAI sind mechanisch — dieselbe Form. |
| **Audit-Sink** | Die Hash-Kette ist implementiert und geprüft, die Postgres-Implementierung fehlt. Der `pg_advisory_xact_lock` gegen gabelnde Ketten ebenfalls. |
| **Memory Service** | Nur Verträge und Schema, kein Retrieval. |
| **Context Engine** | Verträge da, Provider fehlen. |
| **Alles ab Phase 2** | Voice, Vision, Integrationen. |

### Bekannte kleinere Mängel

- `PostgresApprovalStore.open_for_user()` hat ein N+1. Vor der UI zu beheben.
- Der Ollama-Adapter ist **nie gegen ein laufendes Ollama** geprüft worden —
  nur gegen aufgezeichnete Antworten. Der erste echte Lauf wird vermutlich
  Kleinigkeiten zutage fördern.
- `test_invariant_coverage.py` sammelt Marker per AST-Scan über `tests/`.

## 7. Security Invariant Coverage — und ihre Grenze

**Testabdeckung ist für diesen Kern die falsche Kennzahl.** Stattdessen: 42
benannte Invarianten in `core/policy/invariants.py`. Tests binden sich per
`@pytest.mark.invariant("<id>")`; ein Meta-Test schlägt fehl, wenn eine
`ENFORCED`-Invariante ohne Test dasteht oder ein Test sich auf eine unbekannte
Kennung beruft.

**Stand 42/43.** Offen: `session-token-rotation` (bewusst, siehe Abschnitt 8).

### Die wichtigste Lektion dieses Projekts

**Zweimal stand eine Invariante auf ENFORCED, die Tests waren grün — und die
Eigenschaft galt nicht.** Beide Male fand es ein externer Prüfer mit dem
Quelltext in der Hand, der etwas ausprobierte.

**Bypass 1 — Herkunft statt Aussehen** (`04d983a`). `ExecutionAuthorization`
war ein `Protocol`. Die Registry prüfte Hash, Lauf und Nutzer — aber nicht,
woher das Objekt stammt. Ein `SimpleNamespace` mit passenden Attributen führte
`mail.send` aus, ohne Policy, ohne Approval, ohne Grant.

> Ein Protocol beantwortet „sieht es so aus?". Wo es um Erlaubnis geht, lautet
> die Frage „kommt es von dort?".

**Bypass 2 — die Einmaligkeit hing am falschen Schritt** (`fc5b94f`). Die
Nonce sicherte die *Bestätigung*, nicht die *Ausführung*. Drei Aufrufe von
`authorize_execution()` ergaben drei Grants und drei versendete Mails — bei
erteilter Zustimmung für genau eine.

**Bypass 3 — die Erlaubnis war nicht knapp** (`476461d`). Der Anspruch aus
Bypass 2 sicherte die *Ausstellung* des Grants. Danach war der Grant ein Wert
wie jeder andere: Die Registry prüfte Herkunft, Hash, Lauf und Nutzer — vier
Aussagen, die bei der zweiten Vorlage unverändert gelten — und rief den
Handler. Ein echter Grant, zweimal vorgelegt, ergab zwei Ausführungen; zehn
nebenläufige ergaben zehn.

Der Prüfer hatte über `authorize_allowed()` reproduziert, also den Pfad ohne
Bestätigung, wo ein Grant ohnehin beliebig oft neu zu bekommen ist. Die
Nachmessung ergab, dass es auch den bestätigten Pfad trifft — der Befund war
**schwerer als sein Nachweis**. Behoben durch einen Verbrauch an der
`invocation_id`, als letzter Schritt vor dem Handler.

**Was alle drei gemeinsam haben:** Es wurde nicht zu wenig geprüft, sondern die
falsche Frage gestellt. Drei grüne Tests deckten Bypass 1 ab; sie prüften, ob
ein Grant mit falschem Hash abgewiesen wird — nur nicht, ob überhaupt einer
vorliegt.

**Und das Muster hat eine Richtung:** Die Einmaligkeit hing dreimal einen
Schritt zu früh — an der Nonce statt an der Ausführung, an der Autorisierung
statt am Aufruf, an der Ausstellung statt an der Verwendung. Die brauchbare
Frage bei jeder Einmaligkeitszusage lautet deshalb nicht „wird geprüft?",
sondern **„wo entsteht die Wirkung, und wie weit ist der Anspruch davon
entfernt?"**

**Für die neue Sitzung heißt das:** Eine grüne Suite und eine hohe Kennzahl
sind kein Beweis. Vor jeder Zusicherung lohnt die Frage, ob der Test die
Eigenschaft prüft oder nur ihre Umgebung. Und: **Der Metatest prüft, ob eine
Invariante einen Test hat — nicht, ob der Test das Richtige prüft.**

Zwei weitere Fehler fielen beim Weiterbauen auf, beide in eigenem Code
(`007a2fd`): „jede Modellantwort ist Fremdinhalt" hätte nach dem ersten
Modellaufruf jeden Lauf kontaminiert; und `AgentSession.tools` war ein
eingefrorenes Set, wodurch die Zusicherung „das Angebot verengt sich mit der
Kontamination" nicht hielt.

## 8. Nächster Schritt

Die Reihenfolge ist begründet, nicht beliebig.

### 1. HTTP-Endpunkte für Läufe und Bestätigungen

`POST /runs`, `POST /actions/{id}/respond`, dazu die Sitzungs- und
Laufübersicht. Zwei Gründe:

* Es gibt **keinen Weg, eine Bestätigung zu erteilen**. Jede Aktion mit
  Außenwirkung hängt daran.
* `docs/18-angriffskette.md` führt die Glieder ④ bis ⑦ als „nur im Kern
  geprüft". Erst diese Endpunkte schließen den Durchstich über HTTP.

Beim Bauen gilt, was bei den Auth-Routen galt: **Strukturtest zuerst**, sonst
schreibt man ihn passend zum Code.

**Nicht vergessen:** Die Registry braucht seit `476461d` einen
`GrantConsumer`, sonst führt sie nichts aus (`UnguardedExecution`). Beim
Verdrahten der Endpunkte gehört dort `PostgresGrantConsumer` hin — nicht
`InProcessGrants`, das ist der Testdoppelgänger und hält nur innerhalb eines
Prozesses. Der Executor muss die Invokation vorher protokollieren, sonst
findet der Verbrauch keine Zeile und lehnt ab.

### 2. Web-UI, Grundfassung

Chat, Statusleiste, Bestätigungsdialog, Permission Center. Ohne sie ist das
System nicht bedienbar.

### 3. Weitere Provider

Anthropic und OpenAI, dieselbe Form wie Ollama. Dabei mitzunehmen, was aus dem
Review offen ist: **Idempotency-Keys pro Invocation.** Der Ausführungsanspruch
verhindert einen zweiten Versuch — er kann nicht verhindern, dass ein
Provider-Timeout eine Aktion ausgeführt hat, die wir als unklar verbuchen.

### Bewusst aufgeschoben: Token-Rotation

`session-token-rotation` bleibt `PLANNED`. Ein gestohlener Token ist bis zum
Ablauf gültig, auch wenn der rechtmäßige Nutzer weiterarbeitet — das ist eine
reale Lücke. Sie wird trotzdem nicht schnell implementiert: Zwei gleichzeitige
Anfragen mit demselben Token dürfen nicht dazu führen, dass eine davon
abgemeldet wird. **Erst die Race-Semantik spezifizieren (ADR), dann bauen.**

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

**Aber:** Die beiden schwersten Fehler des Projekts kamen aus genau diesen
Reviews, und zwar erst, nachdem die Berater den Quelltext bekamen statt
Statusberichte. Vermutungen der Prüfer sind **nachzumessen, nicht zu
bewerten** — mehrere haben sich als unbegründet erwiesen (etwa „500 statt 401
bei kaputten Signaturbytes"), zwei als gravierend. Beides ließ sich in Minuten
klären, indem der Fall ausgeführt wurde.

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
| **Modulzustand am Event-Loop** | Datenbank-Engine und Redis-Client sind Modulvariablen und hängen am Loop, der sie erzeugt hat. Ohne `dispose()` bzw. `dispose_redis()` in der Test-Fixture erbt der nächste Test Verbindungen aus einem geschlossenen Loop. |
| **Rate-Limit sperrt die eigene Testsuite** | Alle HTTP-Tests kommen aus derselben Gegenstelle. Ohne die Fixture `frische_grenzen` scheitert die Suite ab dem elften Aufruf. |
| **`gen-check` schlägt bei uncommitteten Artefakten fehl** | Das ist korrekt: Es prüft gegen den Commit-Stand. `make gen` und mitcommitten. |
| **Naive Ersetzungsskripte auf Testdateien** | Ein Regex über verschachtelte Klammern hat eine 900-Zeilen-Datei zerlegt. Zeilenweise arbeiten oder `git checkout` und neu ansetzen. |

---

## 11. Dokumentenübersicht

| Datei | Inhalt |
|---|---|
| `docs/00-uebersicht.md` | Zielbild, Risiken, Systemdiagramm, Datenklassifikation |
| `docs/01-tech-stack.md` | 13 ADRs mit Alternativen |
| `docs/02-repo-struktur.md` | Paketgrenzen, Codegenerierung |
| `docs/03-datenmodell.md` | Schema, pgvector, Aufbewahrung |
| `docs/04-orchestrator.md` | Klassifikation, Routing, Planung, Ausführung, Budgets |
| `docs/05-memory-context.md` | Gedächtnisebenen, Retrieval, Referenzauflösung |
| `docs/06-agenten-tools.md` | Supervisor-Muster, Tool-Vertrag |
| `docs/07-security-permissions.md` | Policy, **§4a Taint-Gate**, Secrets, Audit |
| `docs/08`–`13` | Voice, Vision, UI, API, Plugins, Deployment |
| `docs/14-roadmap.md` | Phasen 1–8 |
| `docs/15-testing.md` | Test- und Evalstrategie |
| `docs/16-v1.1-review.md` | Bewertung externer Reviews, **auch die Ablehnungen** |
| `docs/17-identity-goals.md` | Identity, Ziele, Entitäten |
| `docs/18-angriffskette.md` | **Jeder Übergang von HTTP bis zur Ausführung — und welcher noch nicht über HTTP geprüft ist** |
| `docs/generated/` | Scope-Katalog und Invariantentabelle — **generiert, nicht bearbeiten** |

Artifact mit der Architekturübersicht:
https://claude.ai/code/artifact/10372b84-e5da-4b9e-8262-46ec9ae5e37b
