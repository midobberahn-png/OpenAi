# JARVIS

Persönliches, selbst gehostetes KI-Assistenzsystem: Sprache, Text, Vision, Gedächtnis, Werkzeuge und Agenten — mit einem Berechtigungssystem, das jede Aktion mit Außenwirkung kontrolliert.

> **Status: Phase 1 in Arbeit.** Sicherheitssockel steht (Policy Engine, Taint-Gate,
> Approval Gateway, Audit-Kette). Als Nächstes: Orchestrator-Skelett.
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

**Punkt 9 — Orchestrator-Skelett.** Der Sicherheitssockel steht; der Orchestrator
führt ihn zusammen und muss dabei drei noch offene Invarianten belegen
(`orchestrator-consumes-decisions`, `agent-chain-preserves-capability-binding`,
`agent-chain-propagates-taint`).

Vollständiger Stand, Umgebung und Fallstricke: **[HANDOFF.md](HANDOFF.md)**
