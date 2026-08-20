# JARVIS

Persönliches, selbst gehostetes KI-Assistenzsystem: Sprache, Text, Vision, Gedächtnis, Werkzeuge und Agenten — mit einem Berechtigungssystem, das jede Aktion mit Außenwirkung kontrolliert.

> **Status: Phase 1 in Arbeit.** Sicherheitssockel, Orchestrator, Agentenketten,
> Anmeldung mit Passkeys, HTTP-Grenze, Sprachmodell-Anbindung (Ollama) und das
> erste echte Werkzeug (`files.read`) stehen. Ein Lauf lässt sich über HTTP
> anlegen und eine Bestätigung erteilen; **ausgeführt** wird über HTTP noch
> nicht.
>
> Diese Zeile ist schon einmal ein Jahr zu alt gewesen — ein externer Prüfer
> hat das README zu Recht als Statusquelle verworfen. Der belastbare Stand
> steht deshalb an genau einer Stelle:
>
> **Neue Sitzung startet hier: [HANDOFF.md](HANDOFF.md)**

---

## Dokumentation

Einstieg: **[docs/00-uebersicht.md](docs/00-uebersicht.md)** — Zielbild, Risiken, Gesamtarchitektur, Diagramme.

| Dokument | Inhalt |
|---|---|
| [00 Übersicht](docs/00-uebersicht.md) | Architekturdiagramm, Komponenten, Risiken, Datenklassifikation |
| [01 Tech-Stack](docs/01-tech-stack.md) | 13 ADRs mit Alternativen und Trade-offs |
| [02 Repo-Struktur](docs/02-repo-struktur.md) | Monorepo, Paketgrenzen, Codegenerierung |
| [03 Datenmodell](docs/03-datenmodell.md) | PostgreSQL-Schema, pgvector, Aufbewahrung |
| [04 Orchestrator](docs/04-orchestrator.md) | Klassifikation, Routing, Planung, Budgets, Failover |
| [05 Memory & Context](docs/05-memory-context.md) | Vier Gedächtnisebenen, Retrieval, Referenzauflösung |
| [06 Agenten & Tools](docs/06-agenten-tools.md) | Supervisor-Muster, Tool-Vertrag, Risikoklassen |
| [07 Security](docs/07-security-permissions.md) | **Policy Engine, Taint-Tracking, Secrets, Audit** |
| [08 Voice](docs/08-voice.md) | Wake Word, STT, TTS, Barge-in, Latenzbudget |
| [09 Vision & Gesten](docs/09-vision-gesture.md) | Kamera-Pipeline, Gesten-Registry, Privacy Gate |
| [10 UI](docs/10-ui.md) | AI Core, Dashboard, Permission Center, Design-Tokens |
| [11 API](docs/11-api.md) | REST-Ressourcen, WebSocket-Protokoll, Fehlerformat |
| [12 Plugins](docs/12-plugins.md) | MCP-Plugins, Manifest, Isolation, Smart Home |
| [13 Deployment](docs/13-deployment.md) | Topologie, Observability, Backup, Kosten |
| [14 Roadmap](docs/14-roadmap.md) | Phasen 1–8 mit Abnahmekriterien und Aufwand |
| [15 Testing](docs/15-testing.md) | Tests, Contract-Tests, Evals, CI |
| [16 V1.1-Review](docs/16-v1.1-review.md) | Bewertung externer Reviews — **einschließlich der abgelehnten Vorschläge mit Begründung** |
| [17 Identity & Ziele](docs/17-identity-goals.md) | Identity, Ziele, Entitäten |
| [19 Fremdprojekte](docs/19-fremdprojekte.md) | Vergleich mit zwei öffentlichen JARVIS-Projekten: was übernommen ist, wo wir strenger sind |
| [18 Angriffskette](docs/18-angriffskette.md) | Jeder Übergang von HTTP bis zur Ausführung: wodurch gesichert, wo noch ungeprüft |
| [generiert](docs/generated/) | Scope-Katalog und Invariantentabelle — **erzeugt, nicht bearbeiten** |

---

## Die fünf Entscheidungen, die alles andere prägen

1. **Datenklassifikation P0–P3 steuert die Modellwahl** — härter als jede Qualitätsheuristik. P3 (Gesundheit, Finanzen, Zugangsdaten) verlässt das Gerät nie.
2. **Taint-Tracking gegen Prompt Injection** — ein Kontext, der Fremdinhalt gelesen hat, verliert alle sendenden Werkzeuge. Die wichtigste Einzelentscheidung des Systems.
3. **Berechtigungen sind Daten, kein Code** — die Policy Engine ist der einzige Weg zur Tool-Ausführung, ihre Entscheidungen sind zur Laufzeit inspizierbar.
4. **Rohdaten bleiben an der Kante** — Audio und Video werden lokal verarbeitet; das Protokoll kennt keinen Nachrichtentyp für Frames.
5. **Kein Agenten-Framework im Kern** — Provider-Unabhängigkeit und exakte Kosten-/Sicherheitskontrolle sind wichtiger als gesparte Wochen.

---

## Zeitrahmen

Nach **Phase 1–4 (≈19 Wochen)** ist das System täglich nutzbar: Chat, Sprache, Mail, Kalender, Gedächtnis.
Phasen 5–8 (≈17 Wochen) sind additiv — UI-Ausbau, Vision, Agenten, Plugins.

---

## Nächster Schritt

**Der Werkzeugschritt über HTTP.** Ein Lauf entsteht über `POST /runs`, eine
Bestätigung wird über `POST /actions/{id}/respond` erteilt — aber ausgeführt
wird noch nicht über die HTTP-Grenze. Damit sind die Glieder ⑤ und ⑦ der
Angriffskette weiterhin nur im Kern geprüft
(**[docs/18-angriffskette.md](docs/18-angriffskette.md)**).

Seit `files.read` ist das nicht mehr durch fehlende Werkzeuge blockiert.

Vollständiger Stand, Umgebung und Fallstricke: **[HANDOFF.md](HANDOFF.md)**

---

## Prüfen

```bash
make up                      # Postgres und Redis
make migrate
make gate                    # Lint, Typen, Vertragsdrift, alle Tests, Kennzahl
```

`make gate` erzwingt die Integrationstests (`JARVIS_REQUIRE_SERVICES=1`).
**Ein übersprungener Integrationstest ist kein bestandener** — ohne diesen
Schalter meldet die Suite ein sattes Grün, auch wenn kein einziger Test gegen
die Datenbank gelaufen ist. Genau das ist externen Prüfern mehrfach passiert.
Fehlen die Dienste, bricht der Lauf mit **einer** Meldung ab statt mit einer
pro Fixture.

Für externe Begutachtung erzeugt `uv run python scripts/pruefpaket.py` den
sicherheitskritischen Quelltext in Portionen samt Prüfaufträgen und einer Liste
falsifizierbarer Behauptungen.
