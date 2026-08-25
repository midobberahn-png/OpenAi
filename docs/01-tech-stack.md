# Technologieentscheidungen (ADRs)

Format je Entscheidung: **Entscheidung → Warum → Alternativen → Nachteile, die ich in Kauf nehme → Skalierungspfad.**

---

## ADR-001 — Backend: Python 3.12 + FastAPI

**Entscheidung:** Python **3.12** (nicht 3.13/3.14), FastAPI, Pydantic v2, uvicorn, `uv` als Paketmanager.

**Warum:** Das gesamte lokale KI-Ökosystem — `faster-whisper` (CTranslate2), `mediapipe`, `silero-vad`, `openwakeword`, `sentence-transformers` — liefert Wheels konservativ. Auf deinem System liegt Python 3.14.6; dafür existieren für mehrere dieser Pakete noch keine Binärräder, was Kompilierung aus Quellen erzwingt. **3.12 ist der Versionsstand, für den alle genannten Pakete stabile Wheels haben.** FastAPI + Pydantic v2 geben zusätzlich Laufzeitvalidierung *und* automatisches JSON-Schema — beides brauchen wir ohnehin für Tool-Definitionen und Frontend-Typen.

**Alternativen:**

| Option | Pro | Contra |
|---|---|---|
| Node/TypeScript (NestJS) | Eine Sprache für Front und Back, exzellentes Streaming | Lokale ML-Modelle: entweder Python-Sidecar oder deutlich schlechtere Bindings. Der Sidecar käme sowieso — dann lieber gleich Python im Kern. |
| Go | Beste Nebenläufigkeit, ein Binary | ML-Ökosystem praktisch nicht vorhanden; Tool-Schemata müssten von Hand gepflegt werden |
| Rust (Axum) | Performance, Sicherheit | Entwicklungsgeschwindigkeit für ein Projekt dieser Breite zu niedrig |

**Nachteile, die ich in Kauf nehme:** GIL-bedingt schlechte CPU-Parallelität. Abgefedert dadurch, dass fast alles I/O-gebunden ist (LLM-Aufrufe), rechenintensive Teile (Whisper, MediaPipe) im Edge-Prozess laufen und Worker separate Prozesse sind.

**Skalierung:** uvicorn-Worker hinter Reverse Proxy; einzelne heiße Pfade später als eigener Dienst ausgliederbar, da alle Modulgrenzen bereits Schemata sind.

---

## ADR-002 — Kein Agenten-Framework im Kern

**Entscheidung:** Der Orchestrator wird **selbst gebaut**. Kein LangChain, kein LangGraph, kein CrewAI im Kernpfad.

**Warum:** Entwicklungsregel 1 („keine unnötigen Abhängigkeiten") und Regel 7 („keine Abhängigkeit von einem einzigen Anbieter") stehen in direktem Konflikt mit diesen Frameworks. Sie bringen eigene Abstraktionen mit hoher Änderungsrate mit, verstecken Prompt-Konstruktion, erschweren exaktes Token- und Kostentracking und machen genau die Stelle undurchsichtig, an der bei uns die Sicherheitsentscheidungen sitzen (Taint-Tracking, Policy-Gates). Der eigentliche Kern — „Nachricht rein, Tool-Call raus, ausführen, wiederholen" — sind etwa 400–600 Zeilen typisierter Code.

**Alternativen:**

| Option | Pro | Contra |
|---|---|---|
| **LangGraph** | Ausgereifte Zustandsmaschine, Checkpointing, Human-in-the-Loop eingebaut | Hohe API-Volatilität; Checkpointing-Modell passt nicht sauber auf unser Bestätigungsobjekt; zieht LangChain-Abhängigkeitsbaum nach |
| **pydantic-ai** | Sehr nah an unserem Stil, typisiert, schlank | Jung; Tool-Berechtigungen und Taint müssten trotzdem außen herum gebaut werden |
| **Temporal** | Echte Durabilität, Retries, Signals passen exzellent auf Bestätigungen | Eigener Cluster, erheblicher Betriebsaufwand für ein persönliches System |

**Nachteile:** Wir schreiben Retry-, Streaming- und Parallelisierungslogik selbst. Rund 2–3 Wochen Mehraufwand in Phase 1.

**Skalierungspfad:** Der Orchestrator wird als Zustandsmaschine über einem persistierten `Run`-Objekt implementiert (siehe `04-orchestrator.md §6`). Genau diese Form lässt sich später auf Temporal heben, ohne die Agenten- oder Tool-Verträge anzufassen — die Migration beträfe nur den Executor.

---

## ADR-003 — Datenbank: PostgreSQL 16 + pgvector

**Entscheidung:** Eine PostgreSQL-Instanz mit `pgvector` für alles: relationale Daten, Volltext (`tsvector`), Vektoren, Job-Metadaten.

**Warum:** Für ein persönliches System liegt die Vektormenge realistisch bei 10⁵–10⁶ Embeddings (Mails, Dokumente, Episoden mehrerer Jahre). In dieser Größenordnung ist eine dedizierte Vektordatenbank reiner Betriebsaufwand ohne Gegenwert. Der entscheidende Vorteil: **ein Backup, eine Transaktion.** Ein Memory-Eintrag und sein Embedding entstehen atomar; ein Löschauftrag („vergiss alles über Projekt X") ist ein `DELETE ... CASCADE` statt eines verteilten Zweiphasenproblems. Für DSGVO-Löschpflichten ist das nicht nebensächlich, sondern zentral.

Hybrid-Retrieval (BM25 + Vektor) funktioniert in einer Query, weil beide Indizes in derselben Tabelle liegen.

**Alternativen:**

| Option | Pro | Contra |
|---|---|---|
| Qdrant | Beste Filter-Performance, saubere API, HNSW ausgereift | Zweites System: eigenes Backup, eigene Konsistenz, verteilte Löschung |
| Weaviate | Hybridsuche eingebaut | Deutlich schwergewichtiger |
| SQLite + sqlite-vec | Null Betrieb, ideal für Single-User | Kein echter Nebenläufigkeitspfad für Worker + API + Scheduler; Volltext schwächer |
| Chroma | Schnellster Einstieg | Für Produktivbetrieb zu unreif |

**Nachteile:** Ab ca. 5 Mio. Vektoren wird HNSW-Indexpflege in Postgres spürbar; Filter-plus-Vektor-Queries brauchen sorgfältiges Indexdesign.

**Skalierungspfad:** Zugriff ausschließlich über ein `VectorStore`-Protokoll (`search`, `upsert`, `delete`). Ein Qdrant-Adapter ist dann ein Nachmittag Arbeit, nicht eine Migration.

---

## ADR-004 — Ereignisse & Jobs: Redis Streams + arq

**Entscheidung:** Redis 7 für Cache, verteilte Locks, Rate Limiting, Pub/Sub-Fanout an WebSockets sowie **arq** als asyncio-nativer Task-Worker mit Cron-Unterstützung.

**Warum:** arq ist bewusst klein (~2k Zeilen), asyncio-nativ und passt zum FastAPI-Modell ohne den Prozessmodell-Bruch, den Celery mit sich bringt. Redis Streams geben uns Consumer-Gruppen mit Wiederzustellung — ausreichend für Erinnerungen, Ingestion und proaktive Prüfungen.

**Alternativen:** Celery (mächtiger, aber Prozess-/Konfigurationsschwergewicht und schlechte async-Ergonomie); Postgres `LISTEN/NOTIFY` + `SKIP LOCKED` (spart Redis komplett — attraktiv, aber wir brauchen Redis ohnehin für Rate Limiting und Fanout); Temporal (siehe ADR-002); RabbitMQ (überdimensioniert).

**Nachteile:** Redis ist ein weiterer Dienst im Compose-Stack. arq hat eine kleinere Community als Celery.

**Skalierungspfad:** Mehrere Worker-Prozesse; bei echten Durabilitätsanforderungen Wechsel auf Temporal — die Job-Definitionen sind reine Funktionen mit Pydantic-Argumenten und damit portabel.

---

## ADR-005 — Frontend: Next.js 15 + React 19 + TypeScript

**Entscheidung:** Next.js (App Router) im **statischen Export/SPA-Modus**, React 19, TypeScript strict, Tailwind CSS v4, Zustand für Client-State, TanStack Query für Serverdaten, react-three-fiber für den AI Core.

**Warum:** Die Oberfläche ist eine hochdynamische Echtzeit-Anwendung — Server-Rendering bringt hier nahezu keinen Nutzen, weil praktisch jeder Inhalt authentifiziert und live ist. Next.js liefert trotzdem Routing, Bundling und DX; wir nutzen es ohne SSR-Rendering-Pfad. Das hält die Deployment-Topologie einfach: statische Assets + FastAPI, kein Node-Server in Produktion.

**Alternativen:** Vite + React Router (leichter, aber wir bauen Routing/Layouts selbst); SvelteKit (bessere Animationsperformance, kleineres Ökosystem für unsere Bibliotheken); Tauri-Desktop-App (später als Hülle möglich, siehe ADR-011).

**Nachteile:** Next.js ohne SSR nutzt einen Teil seines Werts nicht aus.

---

## ADR-006 — Typsicherheit über die Sprachgrenze: generierte Contracts

**Entscheidung:** Pydantic-Modelle sind die **einzige** Quelle der Wahrheit. Daraus wird generiert:
`Pydantic → OpenAPI 3.1 → TypeScript-Typen + Client` (via `openapi-typescript`), und für WebSocket-Ereignisse `Pydantic → JSON Schema → Zod-Schemata`.

**Warum:** Entwicklungsregel 11 und 12 (Typsicherheit, API-first) sind ohne Generierung nicht durchhaltbar. Handgepflegte TS-Interfaces driften garantiert ab — und bei einem System, in dem ein falsch getyptes Tool-Argument eine Mail an die falsche Person schickt, ist Drift ein Sicherheitsproblem, kein Komfortproblem.

**Umsetzung:** CI-Schritt prüft, ob die generierten Artefakte aktuell sind (`git diff --exit-code`). Abweichung = fehlgeschlagener Build.

**Alternativen:** tRPC (nur bei TS-Backend), Protobuf/gRPC (strengster Vertrag, aber schlechte Browser-Ergonomie und viel Zeremonie), manuelle Pflege (abgelehnt).

---

## ADR-007 — Authentifizierung: Passkeys, nicht OAuth-Login

**Entscheidung:** Klare Trennung zweier Dinge, die im Briefing zusammenfallen:

- **Anmeldung an JARVIS:** WebAuthn/Passkey als primärer Faktor, Argon2id-Passwort als Fallback, serverseitige Sessions in Redis mit rotierenden Cookies.
- **Verbindung zu Fremdsystemen:** OAuth 2.0 + PKCE als *Client* gegenüber Google und Microsoft.

**Warum:** JARVIS ist ein Ein-Personen- bis Familiensystem. Ein OIDC-Provider (Keycloak/Authentik) für ein bis fünf Nutzer ist reiner Betriebsaufwand. Passkeys sind zugleich phishing-resistent — relevant, weil dieses System Zugriff auf Mail und Kalender hat und damit ein hochwertiges Angriffsziel ist.

**Wichtig:** „Login mit Google" wäre hier eine schlechte Idee — es würde bedeuten, dass die Kompromittierung des Google-Kontos gleichzeitig JARVIS *und* alle darin gespeicherten Tokens öffnet.

**Alternativen:** Keycloak/Authentik (Standard, aber schwer); Auth0/Clerk (externer Anbieter im kritischen Pfad, widerspricht dem Selbsthosting-Ansatz).

**Skalierungspfad:** Das Auth-Modul spricht intern bereits in OIDC-Begriffen (`sub`, `scopes`, `session`), ein späterer Wechsel auf einen echten IdP ist ein Adaptertausch.

### Nachtrag (Umsetzung): Sessions liegen in PostgreSQL, nicht in Redis

Die ursprüngliche Fassung dieses ADR sah „serverseitige Sessions in Redis mit rotierenden Cookies" vor. Umgesetzt wurde eine Tabelle `sessions` in PostgreSQL. Drei Gründe, und der erste ist ein Produktmerkmal, kein technischer:

1. **Die Sitzungsübersicht ist Teil des Permission Centers** (`10-ui.md`): „Welche Geräte sind angemeldet, seit wann, welches zuletzt gesehen." In Redis wäre das ein Scan über Schlüssel; in Postgres ist es eine Abfrage mit Index.
2. **Der Widerruf beim Geräteverlust muss vollständig sein.** `UPDATE ... WHERE user_id` erfasst atomar alle Sitzungen eines Nutzers. Über verteilte Schlüssel ist dieselbe Zusicherung aufwendiger — und sie ist genau die, auf die es im Ernstfall ankommt.
3. **Der Latenzvorteil trägt hier nicht.** Sessions sind langlebig (14 Tage), und die Prüfung fällt in denselben Anfragepfad, der ohnehin Berechtigungen aus Postgres liest. Ein zweiter Datenspeicher spart keine Abfrage, sondern fügt eine Ausfallquelle hinzu.

Redis bleibt für das, wofür es gedacht war: flüchtige Zustände wie Rate-Limits und Streaming-Puffer.

**Offen:** Token-Rotation bei jeder Nutzung („rotierende Cookies") ist **nicht** umgesetzt. Sie ist ein echter Schutz — ein gestohlener Token wird entwertet, sobald der rechtmäßige Nutzer sich meldet —, hat aber bei parallelen Anfragen ein Wettlaufproblem, das ohne Sorgfalt zu zufälligen Abmeldungen führt. Bis dahin tragen die Doppelfrist (absolut plus Leerlauf) und der sofort wirksame Widerruf.

---

## ADR-008 — Secrets: Envelope Encryption mit austauschbarem KEK-Provider

**Entscheidung:** OAuth-Tokens und API-Schlüssel liegen **verschlüsselt** in Postgres. Pro Datensatz ein DEK (AES-256-GCM); der DEK ist mit einem KEK verschlüsselt, der aus einem austauschbaren `KeyProvider` kommt:

| Umgebung | KEK-Quelle |
|---|---|
| Entwicklung | Datei-basiert, Pfad via ENV, nicht im Repo |
| macOS-Desktop | macOS Keychain |
| Server-Produktion | HashiCorp Vault Transit oder Cloud-KMS |

**Warum:** Entwicklungsregel 2 und 3. Tokens einfach in eine DB-Spalte zu schreiben, ist der häufigste Fehler in genau dieser Art Projekt — ein Datenbank-Dump ist dann ein Vollzugriff auf dein Postfach. Envelope Encryption erlaubt zudem KEK-Rotation ohne Neuverschlüsselung aller Datensätze.

**Alternativen:** Alles in ENV-Variablen (funktioniert nicht für Nutzer-Tokens, die zur Laufzeit entstehen); Vault von Anfang an (zu schwer für Phase 1); SOPS-verschlüsselte Dateien (gut für Konfiguration, ungeeignet für Laufzeit-Tokens).

**Verschärfung V1.1 — der KEK verlässt seine Instanz nie.** Die ursprüngliche Fassung ließ offen, *wo* entpackt wird. Bei `KEY_PROVIDER=file` läge der KEK im Speicher desselben Prozesses, der HTTP annimmt — eine Schwachstelle im Web-Layer gäbe damit alle Postfach-Tokens preis.

In Produktion entpackt der API-Prozess deshalb **nicht selbst**: Er sendet den `wrapped_dek` an eine Entpack-Instanz (Vault Transit oder ein lokaler Unix-Socket-Dienst unter eigener Benutzerkennung) und erhält nur den DEK zurück. `KEY_PROVIDER=file` bleibt ausschließlich für die Entwicklung zulässig und wird beim Start in Produktion abgelehnt.

---

## ADR-009 — LLM-Provider: eigenes Protokoll über nativen SDKs

**Entscheidung:** Ein schmales `LLMProvider`-Protokoll (`complete`, `stream`, `count_tokens`, `capabilities`) mit Adaptern für die nativen SDKs von OpenAI, Anthropic und Google sowie einen OpenAI-kompatiblen Adapter für Ollama/vLLM.

**Warum die nativen SDKs statt einer OpenAI-kompatiblen Fassade für alles?** Weil die interessanten Fähigkeiten genau dort liegen, wo die Kompatibilitätsschicht sie abschneidet: Prompt-Caching (Anthropic), erweitertes Reasoning, strukturierte Ausgaben, feingranulare Streaming-Ereignisse für Tool-Calls. Diese Unterschiede werden im Protokoll durch ein `capabilities`-Objekt sichtbar gemacht, statt sie zu verstecken.

**Alternativen:** LiteLLM (spart Adapterarbeit, verdeckt aber Provider-Spezifika und wird zur zusätzlichen Fehlerquelle im heißesten Pfad); OpenRouter (ein weiterer Vermittler zwischen dir und deinen Daten — bei P2/P3-Daten inakzeptabel).

**Nachteile:** Drei SDKs zu pflegen, jeweils mit eigenem Änderungsrhythmus. Abgefedert durch Contract-Tests gegen aufgezeichnete Antworten.

**Stand 25.08.2026 — was gebaut ist und was sich beim Bauen gezeigt hat.** Ollama (direkt über HTTP, siehe ADR-010), Anthropic und OpenAI (native SDKs, `httpx`-Client mit `MockTransport` in den Tests, sodass das echte SDK läuft und nur das Netz ersetzt ist). Google fehlt.

Zwei Beobachtungen, die den Kern der Entscheidung bestätigen — die Unterschiede sichtbar zu machen statt sie zu verstecken:

- **`messages.create` kennt bei Anthropic keinen Temperaturparameter mehr**; an seiner Stelle steht `output_config.effort`. Das ist keine andere Schreibweise derselben Sache, und eine erfundene Zuordnung sähe aus, als sei der Wunsch erfüllt worden. `ProviderCapabilities` trägt deshalb ein neues Feld `temperature_control`. Folge: Mit einem Anthropic-Modell sind Werkzeugargumente nicht bestimmt (`plan_arguments.py` verlangt `temperature=0.0`) — eine Frage der Güte, nicht der Sicherheit.
- **`response_format="json"` lässt sich dort nicht zusagen**, weil die API ein Schema verlangt und der Vertrag keines liefert. Der Adapter sagt ab, statt das Feld fallen zu lassen: Fließtext an einen Aufrufer, der ihn parst, ließe den Fehler weit weg von seiner Ursache entstehen.

**Kein Wiederholen in den SDKs** (`max_retries=0`). Die Vorgabe der Bibliotheken ist größer als eins, und das wäre eine stille Abweichung von dem, was das System über sich sagt: Der Modellmodus von `advance` macht einen Versuch, und `timeout_s` gilt je Versuch.

---

## ADR-010 — Lokale Modelle: Ollama als Laufzeit

**Entscheidung:** Ollama als lokale Inferenz-Laufzeit; Modellwahl bewusst offen gehalten (Empfehlung zum Start: ein 8–14B-Instruct-Modell für Klassifikation/Routing, ein größeres Modell nur bei Bedarf).

**Warum:** Ollama bietet Modellverwaltung, automatisches Laden/Entladen, Metal-Beschleunigung auf Apple Silicon und eine OpenAI-kompatible API — damit passt es ohne Sonderweg in ADR-009. Für P3-Daten ist ein lokaler Pfad nicht optional, sondern die Voraussetzung dafür, dass die Klassifikation aus `00-uebersicht.md §8` überhaupt einlösbar ist.

**Alternativen:** llama.cpp direkt (mehr Kontrolle, mehr Handarbeit); LM Studio (GUI-zentriert, schlechter automatisierbar); MLX (auf Apple Silicon schnellste Option — sinnvoll als späterer zweiter Adapter).

---

## ADR-011 — Edge Daemon als eigener Prozess

**Entscheidung:** Audio und Video laufen in einem separaten lokalen Python-Prozess (`jarvis-edge`), der über WebSocket mit dem Kern spricht — **nicht** im Browser und **nicht** im API-Container.

**Warum drei Gründe zusammen:**
1. **Physik:** Container erreichen Mikrofon und Kamera auf macOS nicht sinnvoll.
2. **Datenschutz:** Nur so lässt sich garantieren, dass Roh-Audio und Frames das Gerät nie verlassen — die Behauptung wird zur überprüfbaren Prozessgrenze.
3. **Ausfallsicherheit:** Wake Word und lokale Kommandos funktionieren weiter, wenn der Kern gerade neu startet.

**Alternativen:** Browser (Web Audio + MediaPipe WASM) — kein Wake Word bei geschlossenem Tab, kein Zugriff bei gesperrtem Bildschirm, schlechtere Modellqualität. Bleibt als *zusätzlicher* Client für Gelegenheitsnutzung, nicht als Primärpfad.

**Skalierungspfad:** Der Edge Daemon ist später in eine Tauri- oder Swift-Hülle einbettbar (Menüleisten-App, Global Hotkey, Autostart), ohne Protokolländerung.

---

## ADR-012 — Containerisierung mit bewusster Ausnahme

**Entscheidung:** Docker Compose für API, Worker, Scheduler, Postgres, Redis, Ollama. **Der Edge Daemon läuft nativ**, nicht im Container.

**Warum:** Siehe ADR-011. Ein „alles im Container"-Dogma würde hier zu Bastellösungen mit Geräte-Passthrough führen, die auf macOS ohnehin nicht tragen.

---

## ADR-013 — Netzwerkzugriff über WireGuard/Tailscale statt öffentlicher Exposition

**Entscheidung:** JARVIS wird **nicht** ins offene Internet gestellt. Zugriff von Telefon und anderen Geräten über ein privates Overlay-Netz (Tailscale oder eigenes WireGuard).

**Warum:** Dieses System hält gültige OAuth-Tokens für dein Postfach und deinen Kalender. Die Angriffsfläche eines öffentlich erreichbaren Endpunkts steht in keinem Verhältnis zum Komfortgewinn — zumal ein Overlay-Netz denselben Komfort liefert.

**Alternativen:** Cloudflare Tunnel + Zero Trust (gut, aber Fremdanbieter im Pfad); Reverse Proxy mit mTLS (funktioniert, umständlicher auf Mobilgeräten).

## ADR-014 — Werkzeugdaten im Modellkontext: deklariert, gekappt, ausgezeichnet

**Stand:** entschieden am 21.08.2026.

### Lage

Der abschließende `llm`-Schritt sah nur Schritt*zusammenfassungen* — für
`files.read` Pfad und Bytezahl. Gemessen über HTTP mit laufendem Ollama:

> „Die Datei hatte eine Größe von 69 Byte. **Leider kann ich die Inhalte der
> Datei nicht kennen**, da mir keine Werkzeuge zur Verfügung stehen."

Damit war „lies X und fasse es zusammen" — der Alltagsfall, an dem sich diese
Architektur entschieden hat — ausführbar und wertlos.

Werkzeugdaten in den Prompt zu lassen heißt, Fremdinhalt in den Prompt zu
lassen. Die Frage ist nicht ob, sondern **wie viel, welcher Teil, und wie
gekennzeichnet**.

### Was schon trug und deshalb nicht gebaut wurde

* **Der Taint-Pfad.** Werkzeugabgeleiteter Text floss bereits (`StepOutcome.summary`);
  `Message.is_untrusted` und `ModelGateway._kontaminiert` waren gebaut.
  Der Unterschied ist ein Grad, kein Dammbruch.
* **Die Datenklasse.** `files.read` klassifiziert seinen Inhalt
  (`data_class_for_content`); der Lauf erbt über `escalate()`, und beide
  Modellquellen reichen `run.data_class` ans Gateway. Ein Inhalt, der nach
  Zugangsdaten aussieht, macht den Lauf P3 — und P3 erreicht nur ein lokales
  Modell.

### Entscheidung

**A — Deklarierte Projektion.** `ToolSpec.model_visible_fields`, Vorgabe leer.
Ein Werkzeug erklärt, welche Ergebnisfelder ein Modell sehen darf.

*Verworfen:* `ToolResult.data` vollständig durchreichen. `data` ist
`dict[str, Any]` ohne Grenze; jedes künftige Werkzeug entschiede
stillschweigend mit, was in Prompts landet, und in keinem Diff wäre es zu
sehen. Das ist die Bauart, aus der die bisherigen Befunde stammen.

*Verworfen:* `ToolSpec.returns` umwidmen. Es beschreibt, was ein Werkzeug
zurückgibt; „was darf ein Modell sehen" ist eine andere Frage. Zwei
Bedeutungen in einem Feld sind das, was bei `current_step`/`claim_id` gerade
auseinandergezogen wurde. (Dass `returns` deklariert ist und **nirgends**
gelesen wird, bleibt ein offener Punkt — dritter Fall nach `parameters` und
`supports_undo`.)

**B — Kappung auf dem modellzugewandten Weg**, nicht im Werkzeug.
`MAX_MODELLSICHT = 8.000` Zeichen je Schritt, Kürzung wird benannt.

*Verworfen:* `MAX_BYTES` von `files.read` senken. Die 256 KB gehen an den
**Eigentümer** über HTTP; ihn zu beschneiden, weil ein Modell mitliest,
verschlechtert das Werkzeug für seinen eigentlichen Zweck. Zwei Verbraucher,
zwei Grenzen.

Die Größenordnung folgt aus dem Fenster: 128.000 Token ≈ 512.000 Zeichen. Eine
einzige gelesene Datei könnte die Hälfte belegen — bei jedem Folgeschritt
erneut, weil der Verlauf mitwächst.

Gekappt wird beim **Persistieren** (`StepOutcome.model_view`) und nicht beim
Rendern: Sonst müsste das rohe Ergebnis im Laufzustand liegen — unbegrenzte,
untypisierte Fremddaten in der Persistenz, mit allem, was daran hängt
(Sicherungen, Löschfristen, Größe).

**C — Auszeichnung als Fremdinhalt, ausdrücklich als Komfort.** Ein eigener,
markierter Block je Ergebnis, eigene Nachricht mit `is_untrusted=True`.

> **Die Marke sichert nichts ab.** Ein Modell lässt sich aus einer Trennmarke
> herausreden. Sie verbessert das Verhalten und ist kein Kontrollmechanismus.
> Wer sie als Injection-Schutz führt, wiederholt den Fehler, der dieses Projekt
> bei `supports_undo`, `parameters` und `returns` schon dreimal getroffen hat:
> eine Zusage ohne Mechanismus.

Folgenlos macht Fremdinhalt weiterhin, was es kann: Das Taint-Gate sperrt die
sendenden Werkzeuge, die Datenklassifikation sperrt die Modelle.

### Ausdrücklich nicht entschieden

**Geheimnisse aus dem Prompt filtern.** Ein Filter macht aus „das Modell sieht
es nicht" ein Versprechen, das an einer Regex hängt und beim ersten unbekannten
Format still bricht. Die vorhandene Antwort ist besser: Der Inhalt wird P3, und
P3 verlässt das Gerät strukturell nicht. **Confinement statt Filterung.**

### Abnahme — gemessen, nicht behauptet

| Kriterium | Ergebnis |
|---|---|
| „Lies X und fasse zusammen" liefert Inhalt | Antwort enthält Kickoff, Mittwoch, Nordlicht, September |
| Untergeschobene Anweisung steht **wörtlich** im Prompt, Modell folgt ihr | Taint-Gate blockiert, **0 Kalendereinträge** |
| Nicht deklarierte Felder erreichen den Prompt nicht | `bytes_read`, `truncated` fehlen |
| Gegenprobe ohne Deklaration | Modellsicht ist leer |

### Was die Abnahme nebenbei aufdeckte

Der Test zur Datenklassen-Hochstufung war **grün aus dem falschen Grund**:
pytest leitet `tmp_path` vom Testnamen ab, der Name enthielt „zugangsdaten",
der Pfad stand im Lauf-Input — und der *Klassifikator* setzte P3. Der
Dateiinhalt war unbeteiligt.

Beim Nachmessen zeigte sich die eigentliche Lücke: `looks_like_secret` verlangte
das Schlüsselwort **unmittelbar** vor `=` oder `:`. Bei
`AWS_SECRET_ACCESS_KEY="…"` steht dazwischen noch `_ACCESS_KEY` — ein echter
AWS-Schlüssel fiel durch. Das Muster erlaubt jetzt Bezeichnerzeichen um das
Schlüsselwort herum, mit Gegenproben gegen Prosa.

Diese Heuristik wiegt seit ADR-014 mehr als vorher: Sie entscheidet mit, ob ein
gelesener Dateiinhalt ein Cloud-Modell erreichen darf. Solange nur Ollama
existiert, ist der Unterschied folgenlos — mit dem ersten Cloud-Anbieter ist er
es nicht mehr.

---

## Stack-Zusammenfassung

| Schicht | Wahl |
|---|---|
| Sprache Backend | Python 3.12 (`uv`, Ruff, mypy strict) |
| Web-Framework | FastAPI + Pydantic v2 + uvicorn |
| Datenbank | PostgreSQL 16 + pgvector + Alembic |
| Cache / Bus / Jobs | Redis 7 + arq |
| LLM | OpenAI · Anthropic · Google · Ollama hinter `LLMProvider` |
| Embeddings | Cloud-Modell für P0/P1, lokales Modell (bge-m3 o. ä.) für P2/P3 |
| STT | faster-whisper lokal, Cloud-STT als Option je Klassifikation |
| TTS | `TTSProvider`: ElevenLabs / OpenAI / Piper lokal |
| Wake Word | openWakeWord (Apache-2.0, lokal trainierbar) |
| Vision | MediaPipe Tasks (Hand, Face, Object) |
| Frontend | Next.js 15 · React 19 · TS strict · Tailwind v4 · Zustand · TanStack Query · react-three-fiber |
| Contracts | OpenAPI 3.1 → `openapi-typescript`; Events → Zod |
| Observability | OpenTelemetry → Traces/Metriken; strukturierte Logs (structlog) |
| Deployment | Docker Compose; Edge nativ; Zugriff via WireGuard/Tailscale |
