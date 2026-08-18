# Repository- und Projektstruktur

## 1. Grundsatz: Monorepo mit erzwungenen Paketgrenzen

Ein Repository, mehrere unabhängig baubare Pakete. Die Grenzen sind nicht nur Ordner, sondern durch Importregeln (Ruff `flake8-tidy-imports` / ESLint `no-restricted-imports`) erzwungen — sonst erodiert die Schichtung innerhalb weniger Wochen.

**Erlaubte Abhängigkeitsrichtung (nur nach unten):**

```
apps/           →  services/  →  core/  →  contracts/
integrations/   →  core/      →  contracts/
providers/      →  core/      →  contracts/
```

`contracts/` importiert **nichts** aus dem Projekt. `core/` kennt keine konkreten Provider oder Integrationen — nur Protokolle.

---

## 2. Struktur

```
jarvis/
├── README.md
├── docs/                              # diese Architekturdokumente
├── adr/                               # spätere Einzelentscheidungen
├── compose.yaml
├── compose.prod.yaml
├── Makefile                           # make dev | test | gen | migrate | lint
│
├── packages/
│   ├── contracts/                     # ⬅ Quelle der Wahrheit für alle Typen
│   │   ├── pyproject.toml
│   │   └── jarvis_contracts/
│   │       ├── events.py              # WebSocket-Ereignisse (Zod-generiert)
│   │       ├── tools.py               # ToolSpec, ToolResult, RiskLevel
│   │       ├── memory.py              # MemoryRecord, MemoryQuery, Provenance
│   │       ├── agents.py              # AgentRequest, AgentResult, Handoff
│   │       ├── permissions.py         # Scope, PolicyDecision, PendingAction
│   │       ├── context.py             # ContextBundle, ContextFragment
│   │       └── classification.py      # DataClass P0..P3
│   │
│   ├── core/                          # Domänenlogik, keine I/O-Details
│   │   └── jarvis_core/
│   │       ├── orchestrator/
│   │       │   ├── classifier.py      # Intent + Datenklassifikation
│   │       │   ├── router.py          # Modellwahl
│   │       │   ├── planner.py         # Plan-Erzeugung
│   │       │   ├── executor.py        # Zustandsmaschine über Run
│   │       │   ├── verifier.py        # Ergebnisprüfung
│   │       │   └── budget.py          # Token/Zeit/Kosten-Limits
│   │       ├── memory/
│   │       │   ├── working.py
│   │       │   ├── longterm.py
│   │       │   ├── episodic.py
│   │       │   ├── semantic.py
│   │       │   ├── extraction.py      # Kandidaten statt Direktschreiben
│   │       │   └── retrieval.py       # Hybrid-Scoring
│   │       ├── context/
│   │       │   ├── engine.py
│   │       │   ├── providers/         # zeit, kalender, ort, projekte …
│   │       │   └── resolution.py      # "ihm", "das", "morgen"
│   │       ├── agents/
│   │       │   ├── supervisor.py
│   │       │   ├── registry.py
│   │       │   └── specialists/       # research, mail, calendar, coding …
│   │       ├── tools/
│   │       │   ├── registry.py
│   │       │   ├── decorator.py       # @tool(...) → ToolSpec
│   │       │   └── builtin/
│   │       ├── policy/
│   │       │   ├── engine.py
│   │       │   ├── taint.py           # ⬅ Prompt-Injection-Schutz
│   │       │   ├── confirmations.py
│   │       │   └── audit.py           # hash-verkettetes Protokoll
│   │       └── ports/                 # Protokolle (ABCs), keine Impls
│   │           ├── llm.py
│   │           ├── stt.py  tts.py  embeddings.py
│   │           ├── vector_store.py
│   │           ├── mail.py  calendar.py  search.py  files.py
│   │           └── key_provider.py
│   │
│   ├── providers/                     # Implementierungen der KI-Ports
│   │   └── jarvis_providers/
│   │       ├── llm/{openai,anthropic,google,ollama}.py
│   │       ├── stt/{faster_whisper,openai,deepgram}.py
│   │       ├── tts/{elevenlabs,openai,piper}.py
│   │       └── embeddings/{openai,local_bge}.py
│   │
│   ├── integrations/                  # Implementierungen der Fremdsystem-Ports
│   │   └── jarvis_integrations/
│   │       ├── google/{gmail,calendar,oauth}.py
│   │       ├── microsoft/{graph_mail,graph_calendar,oauth}.py
│   │       ├── search/{brave,tavily,fetcher}.py
│   │       ├── files/local_fs.py
│   │       └── smarthome/home_assistant.py       # Phase 8
│   │
│   └── plugins_sdk/                   # öffentliches Plugin-Interface
│       └── jarvis_plugin_sdk/
│
├── apps/
│   ├── api/                           # FastAPI: Router, WS, Auth, DI
│   │   └── jarvis_api/
│   │       ├── main.py
│   │       ├── routers/v1/
│   │       ├── ws/
│   │       ├── auth/
│   │       ├── db/{models.py,session.py}
│   │       └── migrations/            # Alembic
│   ├── worker/                        # arq-Jobs
│   ├── scheduler/                     # Cron, Erinnerungen, Trigger
│   ├── edge/                          # nativ, nicht containerisiert
│   │   └── jarvis_edge/
│   │       ├── audio/{wakeword,vad,stt_stream,tts_playback,aec}.py
│   │       ├── vision/{capture,hands,gestures,privacy_gate}.py
│   │       └── transport/ws_client.py
│   └── web/                           # Next.js
│       ├── app/
│       ├── components/
│       │   ├── core/                  # AI Core (r3f + GLSL)
│       │   ├── panels/                # Kalender, Mail, Tasks, Status
│       │   ├── chat/
│       │   └── permissions/
│       ├── lib/
│       │   ├── api/generated/         # ⬅ generiert, nicht editieren
│       │   ├── ws/
│       │   └── state/
│       └── styles/tokens.css
│
├── plugins/                           # installierte Plugins zur Laufzeit
├── tests/{unit,integration,e2e,evals}/
└── scripts/{gen_contracts.sh,seed.py,rotate_keys.py}
```

---

## 3. Codegenerierung

`make gen` führt aus:

1. FastAPI-App laden → `openapi.json` exportieren
2. `openapi-typescript` → `apps/web/lib/api/generated/schema.d.ts`
3. Pydantic-Event-Modelle → JSON Schema → Zod (`json-schema-to-zod`) → `apps/web/lib/ws/events.ts`
4. Tool-Registry → `docs/generated/tools.md` (lebende Werkzeugdokumentation inkl. Scopes und Risiko)

CI führt `make gen` aus und bricht bei `git diff --exit-code` ab. Damit kann ein Vertrag nicht unbemerkt driften.

---

## 4. Warum diese Aufteilung — und nicht Feature-Ordner

Eine feature-orientierte Struktur (`features/mail/`, `features/calendar/` mit jeweils UI + API + Logik) wäre für ein klassisches CRUD-Produkt besser. Hier ist sie falsch, weil die wichtigste Eigenschaft des Systems **nicht** feature-lokal ist: Berechtigungen, Taint-Tracking, Modellrouting und Gedächtnis schneiden quer durch alle Features. Läge die Policy-Logik in `features/mail/`, gäbe es sie bald in fünf leicht abweichenden Varianten.

Der Preis: Beim Hinzufügen einer Integration berührt man mehrere Ordner (`ports/`, `integrations/`, `tools/builtin/`). Das ist gewollt — jeder dieser Schritte ist eine bewusste Entscheidung, insbesondere die Vergabe von Scope und Risikoklasse.

---

## 5. Werkzeuge und Konventionen

| Zweck | Werkzeug |
|---|---|
| Python-Pakete | `uv` (Workspaces), gepinnt via `uv.lock` |
| Linting/Format | Ruff (inkl. Importgrenzen), Black-kompatibel |
| Typen | mypy `strict` für `contracts/`, `core/`, `providers/` |
| JS-Pakete | pnpm Workspaces |
| Migrationen | Alembic, ausschließlich generiert + manuell geprüft |
| Commits | Conventional Commits; ADR-Pflicht bei Änderungen an `core/ports/` |
| Pre-commit | Ruff, mypy, `make gen`-Prüfung, Secret-Scan (gitleaks) |
