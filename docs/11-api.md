# API-Struktur

API-first (Entwicklungsregel 12): Alle Clients — Web, Edge, Mobile, künftige Integrationen — sprechen dieselbe versionierte Schnittstelle. Es gibt keinen privilegierten Client.

---

## 1. Aufteilung

| Transport | Wofür |
|---|---|
| **REST** `/v1/...` | CRUD, Konfiguration, Verwaltung, alles Idempotente |
| **WebSocket** `/v1/stream` | Laufender Dialog, Streaming, Zustand, Bestätigungen, Edge-Ereignisse |
| **SSE** `/v1/runs/{id}/events` | Fallback, wenn WebSocket blockiert ist |
| **Webhooks** `/v1/hooks/{token}` | Eingehende Trigger für Automationen |

Warum WebSocket und nicht nur SSE: Der Edge Daemon sendet aktiv (Wake, Transkript, Gesten) und empfängt Audio — das ist bidirektional. Ein zweiter Aufwärtskanal per POST würde die Latenz erhöhen und die Zustandsführung verkomplizieren.

---

## 2. REST-Ressourcen

### Dialog

```
POST   /v1/conversations                    neue Konversation
GET    /v1/conversations?limit&cursor       Liste (Cursor-Pagination)
GET    /v1/conversations/{id}
PATCH  /v1/conversations/{id}               Titel, Archivierung
DELETE /v1/conversations/{id}
GET    /v1/conversations/{id}/messages
POST   /v1/conversations/{id}/messages      Nachricht senden → startet Run
```

### Läufe und Aktionen

```
GET    /v1/runs?status&since                Läufe filtern
GET    /v1/runs/{id}
GET    /v1/runs/{id}/steps                  Aktivitätsprotokoll
POST   /v1/runs/{id}/cancel
GET    /v1/actions/pending                  offene Bestätigungen
POST   /v1/actions/{id}/approve             { nonce }
POST   /v1/actions/{id}/reject              { nonce, reason? }
POST   /v1/actions/{id}/undo                { undo_token }
```

### Gedächtnis

```
GET    /v1/memories?kind&q&status&cursor
POST   /v1/memories                         manuell anlegen
PATCH  /v1/memories/{id}
DELETE /v1/memories/{id}
POST   /v1/memories/search                  { query, k, kinds[] } → semantisch
GET    /v1/memories/candidates              Kuratierungs-Queue
POST   /v1/memories/candidates/{id}/accept
POST   /v1/memories/candidates/{id}/reject
```

### Berechtigungen

```
GET    /v1/permissions                      alle Scopes + aktueller Modus
PUT    /v1/permissions/{scope}              { mode, constraints, expires_at }
GET    /v1/permissions/audit?since&action   Audit-Log
GET    /v1/scopes                           Katalog mit Beschreibung + Risiko
```

### Verbundene Konten

```
GET    /v1/accounts
POST   /v1/accounts/{provider}/authorize    → OAuth-Redirect-URL (PKCE)
GET    /v1/accounts/{provider}/callback     OAuth-Callback
DELETE /v1/accounts/{id}                    trennen + Token vernichten
POST   /v1/accounts/{id}/sync
```

### Produktivität

```
GET    /v1/calendar/events?from&to&calendars
POST   /v1/calendar/events                  → ggf. pending_action
PATCH  /v1/calendar/events/{id}
DELETE /v1/calendar/events/{id}
POST   /v1/calendar/freebusy                { duration_min, window, constraints }

GET    /v1/mail/threads?folder&unread&q
GET    /v1/mail/threads/{id}
POST   /v1/mail/drafts
POST   /v1/mail/drafts/{id}/send            → immer pending_action

GET    /v1/tasks    POST /v1/tasks    PATCH /v1/tasks/{id}    DELETE /v1/tasks/{id}
GET    /v1/automations   POST /v1/automations   PATCH /v1/automations/{id}
POST   /v1/automations/{id}/test            Trockenlauf ohne Ausführung
```

**Was davon existiert:** `GET /calendar?from&to&limit` — eigene Termine,
aufsteigend, ohne `from` ab jetzt. Ohne `/v1`, wie der Rest der heutigen API.
Ein Termin zählt zum Fenster, wenn er darin **liegt**, nicht wenn er darin
beginnt; eine Zeitangabe ohne Zone wird abgelehnt statt geraten.

Der Endpunkt ist **kein Werkzeug**, und der Unterschied trägt: Ein
`calendar.read` wäre eine Fähigkeit — etwas, das ein Nutzer erteilen müsste,
das ein Modell vorschlagen könnte und dessen Ergebnis als Fremdinhalt in einen
Lauf liefe. Hier gibt ein bereits angemeldeter Mensch Auskunft über seine
eigenen Termine. Dieselbe Unterscheidung wie zwischen der Rücknahme und einem
`calendar.delete`. Gelesen wird deshalb über einen eigenen Adapter; der
Speicher, den die Werkzeugregistry hält, kann nicht lesen.

Geschrieben wird weiterhin ausschließlich über `calendar.create` samt Vorschau,
Bestätigung und Grant — einen schreibenden HTTP-Weg an dieser Kette vorbei gibt
es nicht und soll es nicht geben.

**Was davon existiert:** `GET /budget` — Tagesstand des angemeldeten Nutzers: `spent_eur` (verbucht), `committed_eur` (verbucht plus zugesagt — daran hängt die Grenze), `limit_eur`, `since` (Tagesbeginn, weil „heute" ohne Zeitzone eine Vermutung ist), `share`, `warning` (ab 80 %), `exhausted` und `by_model` — die Aufschlüsselung je Modell, Anbieter und Zweck. Kein Schreibweg, und das ist die Aussage: Ein Endpunkt, über den sich das eigene Kostenlimit anheben ließe, wäre kein Limit.

### Dokumente

```
POST   /v1/documents                        Upload (multipart) → Ingestion-Job
GET    /v1/documents?q&source
GET    /v1/documents/{id}
DELETE /v1/documents/{id}                   inkl. Chunks + Embeddings
POST   /v1/documents/search                 { query, k } → Chunks mit Belegstelle
```

### System

```
GET    /v1/health                           öffentlich, minimal
GET    /v1/system/status                    Komponenten, Latenzen, Fehler
GET    /v1/system/models                    verfügbare Modelle + Fähigkeiten
GET    /v1/system/tools                     Werkzeugkatalog + Scopes + Risiko
GET    /v1/system/usage?period              Token, Kosten, Aufrufe
GET    /v1/plugins   POST /v1/plugins/{name}/enable|disable
```

### Persönliche Daten

```
GET    /v1/me                               Profil + Präferenzen
PATCH  /v1/me
GET    /v1/me/export                        vollständiger Datenexport
DELETE /v1/me/data                          vollständige Löschung (2-Schritt-Bestätigung)
```

---

## 3. WebSocket-Protokoll

Ein Kanal, typisierte Nachrichten. Alle Ereignisse sind Pydantic-Modelle und werden nach Zod generiert (ADR-006).

```typescript
type ClientMessage =
  | { t: "user.message";     conversation_id: string; text: string; attachments?: Ref[] }
  | { t: "user.interrupt";   run_id: string }
  | { t: "action.respond";   action_id: string; approve: boolean; nonce: string }
  | { t: "edge.hello";       device_id: string; capabilities: string[] }
  | { t: "edge.wake";        confidence: number }
  | { t: "edge.transcript";  text: string; is_final: boolean }
  | { t: "edge.gesture";     gesture: string; confidence: number }
  | { t: "edge.state";       mic: MicState; camera: CamState }
  | { t: "ping" };

type ServerMessage =
  | { t: "run.started";      run_id: string; trace_id: string; seq: number }
  | { t: "run.classified";   intent: Intent; data_class: DataClass }
  | { t: "run.routed";       model: string; provider: string; reason: string }
  | { t: "run.plan";         steps: PlanStep[] }
  | { t: "step.started";     seq: number; description: string }
  | { t: "step.finished";    seq: number; status: string; latency_ms: number }
  | { t: "token.delta";      text: string }
  | { t: "action.pending";   action: PendingAction }
  | { t: "action.resolved";  action_id: string; result: "approved"|"rejected"|"expired" }
  | { t: "run.finished";     status: RunStatus; usage: Usage; cost_eur: string }
  | { t: "run.error";        code: string; message: string; recoverable: boolean }
  | { t: "core.state";       state: CoreState }
  | { t: "system.health";    components: HealthEntry[] }
  | { t: "proactive";        kind: string; title: string; body: string; actions?: Action[] }
  | { t: "tts.chunk";        /* binär, separater Frame */ }
  | { t: "pong" };
```

**Sequenznummern** auf allen Server-Nachrichten. Der Client erkennt Lücken nach Reconnect und lädt fehlende Schritte über `GET /v1/runs/{id}/steps` nach. Ohne das driftet die Anzeige nach jedem Netzwerkwackler.

**Authentifizierung:** Kein Token in der URL (landet in Logs). Stattdessen: `POST /v1/stream/ticket` liefert ein 30 s gültiges Einmal-Ticket, das als erste Nachricht nach dem Handshake gesendet wird.

---

## 4. Fehlerformat

Einheitlich, RFC-9457-nah:

```json
{
  "type": "https://jarvis.local/errors/permission-denied",
  "title": "Berechtigung fehlt",
  "status": 403,
  "detail": "Für das Senden von E-Mails ist die Berechtigung 'mail.send' erforderlich.",
  "instance": "/v1/mail/drafts/9f3a.../send",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "scope": "mail.send",
  "remediation": {
    "action": "grant_permission",
    "url": "/permissions?scope=mail.send"
  }
}
```

Das Feld `remediation` ist bewusst Teil des Vertrags: Ein Fehler, der dem Nutzer nicht sagt, wie er ihn behebt, erzeugt Supportaufwand — auch bei einem persönlichen System, dann eben bei dir selbst.

**Statuscodes:** 400 Validierung · 401 nicht angemeldet · 403 Berechtigung/Policy · 404 · 409 Konflikt (z. B. Terminkollision) · 422 Semantik · 423 Locked (Taint-Sperre) · 429 Rate Limit · 502 Provider-Fehler · 503 degradiert.

**423 Locked** ist eigens vergeben, damit die UI die Taint-Sperre (`07-security §4`) von einer gewöhnlichen fehlenden Berechtigung unterscheiden und passend erklären kann.

---

## 5. Querschnittsregeln

| Regel | Umsetzung |
|---|---|
| Versionierung | Pfad-Präfix `/v1`. Breaking Changes → `/v2`, alte Version 6 Monate parallel |
| Pagination | Cursor-basiert (`?cursor=&limit=`), nie Offset |
| Idempotenz | `Idempotency-Key`-Header bei allen mutierenden Endpunkten mit Außenwirkung |
| Rate Limiting | Header `X-RateLimit-Limit/Remaining/Reset` |
| Tracing | `traceparent` (W3C) eingehend und ausgehend; `trace_id` in jeder Antwort |
| Zeit | Ausschließlich ISO-8601 mit Zeitzone. Keine nackten lokalen Zeiten |
| Geld | Dezimalstring, nie Float (`"0.42"`) |
| Aufzählungen | Als String, nie als Ganzzahl (erweiterbar ohne Bruch) |
| Teilaktualisierung | `PATCH` mit expliziten Feldern; `null` löscht, fehlend lässt unverändert |

---

## 6. OpenAPI und Generierung

FastAPI erzeugt OpenAPI 3.1 vollständig aus den Pydantic-Modellen. `make gen` (siehe `02-repo-struktur.md §3`) leitet daraus TypeScript-Typen und den Client ab. Der CI-Schritt prüft auf Drift.

Zusätzlich generiert: `docs/generated/tools.md` — der vollständige Werkzeugkatalog mit Parametern, Scopes und Risikoklassen. Dieses Dokument ist die Grundlage jedes Sicherheitsreviews und muss deshalb generiert sein, nicht gepflegt.
