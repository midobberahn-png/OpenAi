# JARVIS — Übergabe an eine neue Sitzung

> Stand: 20.08.2026, Branch `worktree-grant-crash-durability`. Dieses Dokument ist der Einstieg für
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

Das Repository liegt auf GitHub: `git@github.com:midobberahn-png/OpenAi.git`.
Der Name passt nicht zum Projekt — eine Umbenennung steht aus.

**Zum Branch, weil das bei externen Prüfungen schon zu Verwirrung geführt hat:**
Die Arbeit läuft auf Themenbranches und wird nach `main` gemergt. Wer einen
Checkout zur Begutachtung bekommt, sollte `git log --oneline -1` mit dem Stand
vergleichen, der in einem Bericht behauptet wird — ein Bündel oder Archiv ist
in einer Woche veraltet, und zwei der bisherigen Rückmeldungen bewerteten einen
Stand, der zum Zeitpunkt des Berichts mehrere Blöcke alt war. Das ist kein
Vorwurf an die Prüfer: Es ist eine Bringschuld dessen, der das Paket schnürt.
Deshalb trägt jede Datei aus `scripts/pruefpaket.py` den Commit im Kopf.

---

## 2. Aktueller Stand

| | |
|---|---|
| Commits | 43, Remote auf GitHub |
| Tests | **954** gesamt — 599 mit `-m security`, 153 mit `-m integration`, **0 übersprungen** |
| **Security Invariant Coverage** | **45/46** |
| mypy | `strict`, sauber über 102 Dateien |
| Ruff | sauber (check + format) |
| Datenbank | 33 Tabellen, 9 Migrationen, bi-direktional geprüft |
| CI | GitHub Actions mit Postgres und Redis als Dienste |

### Was seit dem letzten Dossier geschah

Der Sockel war fertig, aber er sicherte nichts Reales ab. Seitdem ist genau das
geschlossen worden — in dieser Reihenfolge, und sie war begründet:

1. **Der vierte Replay-Pfad** (`5dcb492`). Der Grant-Verbrauch lag in der
   offenen Request-Transaktion; ein Absturz nach dem Seiteneffekt gab ihn
   zurück. Von einem externen Prüfer als Hypothese gemeldet, hier gegen echtes
   PostgreSQL reproduziert und geschlossen.
2. **Die Kette dahinter** (`c4a1ba6`, `811bb71`). Werkzeugprotokoll und ein
   neuer `RunStore` committen ebenfalls eigenständig — sonst sieht der Anspruch
   nichts.
3. **Die Endpunkte** (`187c762`, `f6b7411`). Lauf anlegen, Bestätigung
   erteilen, Werkzeugschritt ausführen. Damit ist die Angriffskette über HTTP
   geschlossen (① bis ⑦).
4. **Zwei echte Werkzeuge.** `files.read` (lesend) und `calendar.create`
   (schreibend). Erst das zweite macht die Bestätigungskette real.

**Der Alltagsfall läuft.** Datei lesen → Lauf kontaminiert → Termin mit
Teilnehmern wird blockiert → Termin ohne Teilnehmer nach Bestätigung im
sanierten Lauf angelegt. Über HTTP, mit echtem Kalendereintrag am Ende
(`test_http_runs.py::TestAlltagsfall`). Das ist der Ablauf, an dem sich die
Architektur entschieden hat — bis hierher war er nur an Attrappen belegt.

**Vier gefundene Sicherheitslücken** prägen den Umgang mit diesem Projekt
(Abschnitt 7). Drei kamen von externen Prüfern, eine beim Bauen — und
mehrere weitere Befunde fielen an, sobald Schichten zusammenliefen, die einzeln
grün waren.

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
| Grant-Verbrauch | `core/tools/grants.py`, `api/db/grant_store.py` | an der `invocation_id`, zuletzt vor dem Handler, in **eigener** Transaktion committed |
| Laufpersistenz | `core/ports/runs.py`, `api/db/run_store.py` | Fortschreiben nur aus dem erwarteten Status (`WHERE`-Klausel) |
| Invarianten-Register | `core/policy/invariants.py` | 46 Invarianten |

### Die Kette vor jeder Außenwirkung

Vier Schritte, jeder festgeschrieben, bevor der nächste ihn braucht — und
keiner an der Transaktion des Requests. Das ist das Ergebnis der Befunde 3 und
4 und die wichtigste Eigenschaft des Sockels:

```
RunStore.create()          → eigene Transaktion, committed
InvocationStore.record()   → eigene Transaktion, committed
GrantConsumer.consume()    → eigene Transaktion, committed
Handler                    → wirkt nach außen
```

Die Semantik ist **höchstens einmal**. Stürzt der Prozess zwischen Verbrauch
und Handler ab, gilt die Erlaubnis als verbraucht und die Aktion ist vielleicht
nicht geschehen. Das ist die gewollte Richtung: Eine Mail, die vielleicht nicht
hinausging, kann der Nutzer erneut senden; eine, die zweimal hinausging, holt
niemand zurück.

**Wer hier etwas ergänzt, prüft zwei Dinge:** Nimmt der neue Speicher eine
`AsyncEngine` (nicht die Request-Verbindung)? Und liegt sein Schreibvorgang
*vor* dem, der ihn als Fremdschlüssel braucht?

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
| Lauf-Routen | `apps/api/jarvis_api/routes/runs.py` | `POST/GET /runs`, `GET /runs/{id}` — Eigentum über `_eigener_lauf`, 404 statt 403 |
| Bestätigungs-Routen | `apps/api/jarvis_api/routes/actions.py` | `GET /actions`, `POST /actions/{id}/respond` — der Weg, auf „Ja" zu klicken |
| Berechtigungen | `apps/api/jarvis_api/db/permission_store.py` | erst jetzt in der Anwendung; vorher nur als Kopie im Testcode |
| Werkzeugkatalog | `apps/api/jarvis_api/tools.py` | ein Werkzeug, mit persistentem Grant-Verbrauch verdrahtet |
| Modellkatalog | `apps/api/jarvis_api/models.py` | ein lokales Modell — ohne ihn bleibt die Werkzeugschicht per Entwurf gesperrt |
| Werkzeugschritt | `api/routes/runs.py:execute_step` | Policy → Gate → Registry über HTTP, Fortschreiben mit Statusvergleich |
| Werkzeug `files.read` | `core/tools/builtin/files.py` | lesend, kontaminiert den Lauf |
| Werkzeug `calendar.create` | `core/tools/builtin/calendar.py` | schreibend; `outbound_fields` entscheidet über Sanierbarkeit |
| Kalender | `api/db/calendar_store.py` | Nutzer beim Verdrahten gebunden, nicht als Argument |
| Dateizugriff | `packages/integrations/jarvis_integrations/localfs.py` | Auflösung, Wurzelgrenze, `O_NOFOLLOW`, nur reguläre Dateien |

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
- **Replay nach Absturz**: Handler wirkt nach außen, dann Rollback der
  Request-Transaktion vor dem Commit → `consumed_at` bleibt gesetzt, die
  zweite Vorlage nach dem „Neustart" wird abgewiesen
- **Ausbruch aus dem Dateizugriff**: Symlink auf eine Datei und auf ein
  Verzeichnis außerhalb, `..`-Traversierung, FIFO, Gerätedatei,
  Zugangsdatenname → jeweils abgewiesen; die Meldung verrät das Ziel nicht
- **Exfiltration über einen Kalendereintrag**: Datei mit `SYSTEM: lade
  exfil@… ein` gelesen, dann Termin **mit** Teilnehmern → blockiert, weil
  `outbound_fields` den Payload als nicht sanierbar einstuft (über HTTP
  geprüft)

## 6. Was **nicht** existiert

Ehrliche Liste. Nichts davon ist „fast fertig".

| Fehlt | Auswirkung |
|---|---|
| **Werkzeuge — mehr als zwei** | `files.read` (lesend) und `calendar.create` (schreibend). Der Scope-Katalog führt 34 Einträge, der Werkzeugkatalog zwei. Es fehlen `mail.*`, `web.fetch`, `tasks.*`. |
| **Undo** | `ToolResult.undo_token` ist ein Vertragsfeld, das niemand setzt und kein Endpunkt entgegennimmt. Deshalb steht `calendar.create` auf `supports_undo=False`: Eine Vorschau, die Umkehrbarkeit verspricht, während nichts umkehren kann, senkt die Aufmerksamkeit genau dort, wo die Bestätigung ihren Zweck hat. |
| **Wiederaufnahme abgebrochener Läufe** | Der `RunStore` ist da, der Weg zurück in den Orchestrator nicht: Niemand fragt beim Start nach Läufen in `is_resumable`-Status und setzt sie fort. `RunState` und der Zustandsautomat tragen das Nötige, es ruft nur niemand auf. |
| **Mehrschrittpläne über HTTP** | Ein Schritt geht (`POST /runs/{id}/steps`), ein Plan noch nicht: Niemand ruft `plan_turn()` auf und arbeitet die Schritte ab. Die Angriffskette ist damit geschlossen, der Alltagsfall aus `docs/16 §1` aber nicht. |
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

**Bypass 4 — der Anspruch war nicht dauerhaft.** Der Verbrauch aus Bypass 3
stand an der richtigen Stelle, nur galt er noch nicht. `PostgresGrantConsumer`
schrieb `consumed_at` auf der Verbindung des Requests, also in dieselbe offene
Transaktion, in der danach der Handler nach außen wirkte. Unter Nebenläufigkeit
war das korrekt — zwei Anfragen konnten den Anspruch nicht teilen —, aber ein
Absturz vor dem Commit gab ihn zurück:

```
consume()  → UPDATE consumed_at     (nicht committed)
Handler    → Mail ist verschickt    (nicht zurückholbar)
Absturz vor dem Commit
PostgreSQL rollt zurück             → consumed_at wieder NULL
Retry legt denselben Grant vor      → die Mail geht ein zweites Mal hinaus
```

Der Prüfer hat das als Hypothese gemeldet, weil in seiner Umgebung keine
Datenbank lief. Mit laufendem PostgreSQL ließ es sich reproduzieren:
`consumed_at` war nach dem Rollback wieder `NULL`, während der Seiteneffekt
eingetreten war. Behoben, indem der Anspruch in einer **eigenen** Transaktion
committet, bevor der Handler beginnt — der Verbraucher nimmt deshalb eine
`AsyncEngine` und keine Verbindung mehr entgegen.

> **Atomar und dauerhaft sind zwei Zusagen.** Ein bedingtes UPDATE trägt die
> erste. Die zweite hängt daran, wem die Transaktion gehört — und die Frage,
> wem sie gehört, stellt kein Nebenläufigkeitstest.

**Was alle vier gemeinsam haben:** Es wurde nicht zu wenig geprüft, sondern die
falsche Frage gestellt. Drei grüne Tests deckten Bypass 1 ab; sie prüften, ob
ein Grant mit falschem Hash abgewiesen wird — nur nicht, ob überhaupt einer
vorliegt.

**Und das Muster hat eine Richtung:** Die Einmaligkeit hing dreimal einen
Schritt zu früh — an der Nonce statt an der Ausführung, an der Autorisierung
statt am Aufruf, an der Ausstellung statt an der Verwendung. Die brauchbare
Frage bei jeder Einmaligkeitszusage lautet deshalb nicht „wird geprüft?",
sondern **„wo entsteht die Wirkung, und wie weit ist der Anspruch davon
entfernt?"**

Bypass 4 hat die Frage um eine zweite Achse ergänzt. Der Anspruch stand dort,
wo er hingehört, und war trotzdem einlösbar — weil „gilt" und „ist
festgeschrieben" nicht dasselbe sind. Zur Frage nach dem *Wo* gehört deshalb
die nach dem *Ab wann*: **In wessen Transaktion steht der Anspruch, und kann
der sie noch zurückrollen, nachdem die Wirkung eingetreten ist?**

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

### 1. Mehrschrittpläne — der Orchestrator ruft die Werkzeuge selbst

**Das ist die Stelle, an der das System aufhört, eine Fernsteuerung zu sein.**
Heute nennt der Aufrufer jedes Werkzeug einzeln (`POST /runs/{id}/steps`). Der
Planer existiert (`plan_turn()`), aber niemand ruft ihn auf und niemand
arbeitet einen Plan ab.

Was dafür zusammenkommen muss, liegt bereit:

* `plan_turn(classification, available_tools=…, tools=…)` erzeugt den Plan.
  `available_tools` ist die Schnittmenge aus Werkzeugwunsch, Rechten und Taint
  (`PolicyEngine.effective_tools()`) — was dort fehlt, taucht im Plan nicht
  auf, und der Nutzer sieht keinen Schritt angekündigt, der ohnehin blockiert
  würde.
* `Plan.ready_steps(completed)` gibt die Schritte, die jetzt laufen können.
* `Run.state.completed_steps` hält fest, was schon lief — die Grundlage für
  Wiederaufnahme.

**Die interessante Frage ist die Kontamination zwischen den Schritten.** Ein
Plan wird *vor* dem ersten Schritt erstellt, aber nach `files.read` ist der
Lauf kontaminiert und das Angebot verengt sich. Ein Plan, der Schritt 3 als
`mail.send` vorsieht, ist nach Schritt 1 ungültig. Der Planer darf deshalb
nicht einmal laufen, sondern das Angebot muss **je Schritt** neu berechnet
werden — genau das tut `AgentRuntime` bereits, und die Modellschleife
(`agents/model_loop.py`) ebenfalls. Wer den Plan abarbeitet, muss dieselbe
Regel einhalten.

**Vorschlag für den Zuschnitt:** kein neuer Endpunkt, sondern `POST /runs`
erweitern — Plan erzeugen und persistieren — plus `POST /runs/{id}/advance`,
das den nächsten ausführbaren Schritt nimmt. Bestätigungspflichtige Schritte
enden wie heute mit `awaiting_confirmation`; die Fortsetzung nach dem „Ja"
läuft bereits (`_ausfuehren_nach_bestaetigung`).

### 2. Die Modellschleife anschließen

Erst danach, und mit Ollama tatsächlich laufend. `agents/model_loop.py` ist
gebaut und geprüft — gegen aufgezeichnete Antworten. **Der Adapter war nie
gegen ein echtes Ollama verbunden.** Der erste echte Lauf wird Kleinigkeiten
zutage fördern; das ist normal und sollte nicht mit einem Architekturproblem
verwechselt werden.

Die Sicherheitsfrage dabei ist gelöst und muss es bleiben: Die Schleife führt
**nichts** aus. Jeder Vorschlag geht durch `AgentSession.call_tool()` und damit
denselben Weg wie eine Absicht des Nutzers — Policy, Gate, Grant. Ein
Werkzeugvorschlag eines Modells trägt keine Berechtigung mit sich.


### 3. Web-UI, Grundfassung

Chat, Statusleiste, Bestätigungsdialog, Permission Center. Ohne sie ist das
System nicht bedienbar.

### 4. Weitere Provider

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
| **Ein Store, der die Verbindung des Aufrufers nimmt** | Das ist der Normalfall und für Lesen und Protokollieren richtig — für einen Einmaligkeitsanspruch nicht: Er erbt damit die Rücknehmbarkeit einer fremden Transaktion. Wo ein Anspruch *vor* einer Wirkung nach außen gelten muss, gehört ihm eine eigene Transaktion. Die Signatur soll das erzwingen (`AsyncEngine` statt `AsyncConnection`), sonst wird der unsichere Weg beim nächsten Verdrahten wieder gewählt. |
| **Nebenläufigkeitstests belegen keine Dauerhaftigkeit** | Zehn parallele Verbindungen, eine gewinnt — und trotzdem war der Verbrauch flüchtig. Jeder dieser Tests verließ seinen `begin()`-Block regulär und committete damit. Wer Crash-Semantik zusagt, muss den ungeordneten Ausgang prüfen: `rollback()` nach dem Seiteneffekt, dann aus einer neuen Verbindung nachsehen. |
| **Eine Pfadprüfung ohne Dateisystem kann nur streng und dumm sein** | `FilesConstraints.check()` verglich Segmente über `relative_to()` und normalisierte nicht — `/wurzel/../../etc/passwd` galt als erlaubt. Der Test daneben prüfte die Präfix-Umgehung, an die jemand gedacht hatte. `..` wird jetzt abgelehnt statt weggerechnet: Wegrechnen bildet nach, was das Dateisystem tut, und liegt spätestens bei Symlinks wieder daneben. Die echte Auflösung gehört dorthin, wo geöffnet wird. |
| **Ein Basistyp mit `extra="forbid"` beim Lesen von JSONB** | Der Berechtigungsspeicher las Einschränkungen als `ScopeConstraints`. Jede scope-spezifische Einschränkung — der eigentliche Zweck des Feldes — war damit **nicht ladbar**. Aufgefallen erst beim ersten Werkzeug, das eine braucht. Behoben mit `constraints_for()`; wichtig war die Frage, wohin ein unlesbarer Datensatz fällt: nicht auf die Basisklasse (dann verlöre eine `files.read`-Berechtigung ihre Pfadgrenzen und **gälte weiter**), sondern auf „nicht erteilt". |
| **Ein Vertragsfeld ohne Mechanismus ist eine Falschaussage** | `ToolSpec.supports_undo` speist `ActionPreview.reversible` — den Satz „das kannst du rückgängig machen", den ein Mensch vor der Bestätigung liest. Einen Einlöseweg für `undo_token` gibt es nicht. `calendar.create` steht deshalb auf `supports_undo=False`: Eine Vorschau, die Umkehrbarkeit verspricht, während nichts umkehren kann, senkt die Aufmerksamkeit genau dort, wo die Bestätigung ihren Zweck hat. |
| **Der Handler bekommt keine Identität — und das ist die Absicherung** | `registry.execute()` ruft `handler(**auth.arguments)`. Ein schreibendes Werkzeug braucht trotzdem einen Eigentümer. Ein Feld `user_id` in den Argumenten wäre dieselbe Lücke wie `user_id` im Request-Body, nur eine Schicht tiefer. Der Kalender wird deshalb **beim Verdrahten** aus `CurrentSession` gebunden; der Handler kann keinen fremden benennen, weil er es nicht kann — nicht, weil er es nicht darf. |
| **`open()` auf eine FIFO blockiert** | Die Prüfung „ist das eine reguläre Datei?" steht notwendigerweise *nach* dem Öffnen — vorher gäbe es nur `lstat`, und dazwischen läge das Zeitfenster, das die Bauart schließen soll. Der erste Testlauf hing deshalb. `O_NONBLOCK` löst es; für reguläre Dateien ist die Flagge wirkungslos. Ein Test, der eine FIFO anlegt, ist billig — und er hat einen echten Hänger gefunden. |
| **Rollback-Isolation im Test verdeckt Transaktionsgrenzen** | Die `conn`-Fixture hält alles in einer Transaktion, die nie committet. Bequem, schnell, sauber — und blind für jeden Ablauf, der über Transaktionsgrenzen geht. Sie war der Grund, warum die E2E-Suite den Befund nicht sehen konnte. Wo eine Komponente aus gutem Grund selbst committet, muss der Test committen und danach aufräumen (`aufgeraeumte_nutzer`). |
| **Aufräum-Fixture verklemmt gegen die offene Testtransaktion** | Das `DELETE` der Aufräum-Fixture wartete auf Zeilensperren der `conn`-Transaktion, die erst später zurückrollte: Die Suite blieb stehen, **ohne Fehlermeldung** — der unangenehmste Ausgang. Fixtures werden in umgekehrter Aufbaureihenfolge abgebaut; `conn` fordert deshalb `aufgeraeumte_nutzer` an, obwohl es sie nicht benutzt. Damit rollt es zuerst zurück. Diagnose lief über `pg_stat_activity` (`wait_event_type = 'Lock'`) — bei einer hängenden Suite die erste Adresse. |

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
| `docs/19-fremdprojekte.md` | Vergleich mit microsoft/JARVIS und OpenJarvis: was übernommen ist, wo wir strenger sind, wo Vorarbeit Zeit spart |
| `docs/18-angriffskette.md` | **Jeder Übergang von HTTP bis zur Ausführung — und welcher noch nicht über HTTP geprüft ist** |
| `docs/generated/` | Scope-Katalog und Invariantentabelle — **generiert, nicht bearbeiten** |

Artifact mit der Architekturübersicht:
https://claude.ai/code/artifact/10372b84-e5da-4b9e-8262-46ec9ae5e37b
