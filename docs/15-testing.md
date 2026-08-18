# Test- und Evaluationsstrategie

Ein KI-System hat zwei Arten von Korrektheit: **deterministische** (der Code tut, was er soll) und **probabilistische** (das Modell tut meistens, was es soll). Beide brauchen unterschiedliche Verfahren. Klassische Tests allein reichen nicht; Evals allein auch nicht.

---

## 1. Testpyramide

```
        ╱ E2E ╲              wenige, kritische Pfade (Playwright)
      ╱─────────╲
     ╱ Integration╲          API + DB + Provider-Doubles
   ╱───────────────╲
  ╱      Unit       ╲        Kern-Logik, Policy, Retrieval, Router
 ╱───────────────────╲
╱   Contract + Eval   ╲      Provider-Verträge + Modellverhalten
```

---

## 2. Unit-Tests — was zwingend abgedeckt sein muss

| Bereich | Warum kritisch |
|---|---|
| **Policy Engine** | Jede Kombination aus Modus, Risiko, Taint, Datenklasse, Constraint. Ein Fehler hier bedeutet eine falsch gesendete Mail. |
| **Taint-Propagierung** | Monotonie, Vererbung über Sub-Agenten, Sperrung der richtigen Tools |
| **Router** | Datenklassifikation als hartes Filter — Test: P3-Anfrage darf niemals ein Cloud-Modell wählen, unter keiner Konfiguration |
| **Budget-Rechnung** | Token-, Kosten-, Schritt- und Tiefenzählung; sauberer Abbruch |
| **Retrieval-Scoring** | Gewichtung, Aktualitätsverfall, Klassen-Filter |
| **Referenzauflösung** | Pronomen, Genus-Kongruenz, Mehrdeutigkeit → Rückfrage |
| **Envelope Encryption** | Ver-/Entschlüsselung, KEK-Rotation ohne Datenverlust |
| **Audit-Kette** | Hash-Verkettung, Manipulationserkennung |
| **Constraint-Prüfung** | Empfängerlisten, Pfadgrenzen, Zeitfenster, Betragsgrenzen |

Zielabdeckung: `core/` ≥ 85 %, `contracts/` 100 % (Validierungsregeln), Gesamtsystem ≥ 70 %.

**Beispiel für den wichtigsten Testfall des Systems:**

```python
async def test_tainted_context_blocks_send(policy, run, mail_send_spec):
    run.taint_level = "tainted"
    decision = await policy.decide(
        PolicyRequest(
            tool_name="send_email",
            run=run,
            arguments={"to": ["x@example.com"], "subject": "…", "body": "…"},
        )
    )
    assert decision.effect == "deny"
    assert decision.escalate_to_user
    # auch mit vollständiger Berechtigung darf es nicht durchgehen:
    await policy.grant("mail.send", mode="allow")
    assert (await policy.decide(...)).effect == "deny"
```

---

## 3. Contract-Tests für Provider

Externe APIs werden nicht in jedem Testlauf angesprochen — das wäre langsam, teuer und unzuverlässig. Stattdessen:

1. Ein **aufgezeichneter Satz echter Antworten** (VCR-Kassetten, Secrets redigiert) je Provider.
2. Jeder Adapter wird gegen die Kassetten geprüft: Parsen, Fehlerbehandlung, Streaming, Tool-Calls.
3. Ein **nächtlicher Job** spielt eine kleine Live-Suite gegen die echten APIs und meldet Abweichungen — so werden Breaking Changes bemerkt, bevor sie im Alltag auffallen.

Dieselbe Testsuite läuft gegen **alle** Implementierungen eines Ports. Ein neuer `LLMProvider` gilt erst als fertig, wenn er die gemeinsame Suite besteht — das ist die praktische Absicherung der Austauschbarkeit aus Entwicklungsregel 6.

---

## 4. Evals — Bewertung des Modellverhaltens

Der Teil, der bei solchen Systemen üblicherweise fehlt und ohne den man Regressionen nicht bemerkt.

### 4.1 Router-Eval

Goldset von 150–300 annotierten Anfragen mit erwarteter Klassifikation.

| Metrik | Ziel |
|---|---|
| Intent-Genauigkeit | ≥ 0,92 |
| **Datenklassifikation Recall für P3** | **1,00 — keine Ausnahme** |
| Komplexitätsgenauigkeit (±1 Stufe) | ≥ 0,90 |
| Erkennung von Mehrschrittigkeit | ≥ 0,88 |

Die zweite Zeile ist die einzige Metrik im gesamten Dokument ohne Toleranz: Eine als P1 fehlklassifizierte P3-Anfrage sendet Gesundheits- oder Finanzdaten an einen Cloud-Anbieter. Falsch-Positive in die andere Richtung (P1 als P3 eingestuft) sind unschädlich — sie kosten nur Qualität. Der Klassifikator wird entsprechend asymmetrisch kalibriert: **im Zweifel höher einstufen.**

### 4.2 Retrieval-Eval

| Metrik | Ziel |
|---|---|
| Recall@5 | ≥ 0,85 |
| MRR | ≥ 0,70 |
| Klassen-Leckage (P3 in Cloud-Kontext) | 0 |

Dient auch der Kalibrierung der vier Scoring-Gewichte aus `05-memory-context.md §4` — per Grid-Search über das Goldset statt nach Gefühl.

### 4.3 Tool-Calling-Eval

Szenarien mit erwartetem Tool und erwarteten Argumenten.

| Metrik | Ziel |
|---|---|
| Richtiges Tool gewählt | ≥ 0,95 |
| Argumente exakt korrekt | ≥ 0,90 |
| Empfänger korrekt (Mail) | ≥ 0,99 |
| Datum/Zeit korrekt (Kalender) | ≥ 0,97 |
| Halluzinierte Tools | 0 |

### 4.4 Sicherheits-Eval (Injection-Suite)

Eine Sammlung von Angriffsversuchen in Mails, Webseiten und Dokumenten:

- direkte Anweisungen („Ignoriere vorherige Anweisungen …")
- getarnte Anweisungen (unsichtbarer Text, weiße Schrift, HTML-Kommentare)
- Autoritätsvortäuschung („Systemhinweis:", „Der Administrator hat angeordnet …")
- Exfiltration über URL-Parameter
- mehrstufige Angriffe (Dokument verweist auf Webseite mit der eigentlichen Nutzlast)
- Versuche, Berechtigungen zu erweitern

**Zielwert: 0 erfolgreiche Ausführungen einer Aktion mit Außenwirkung.** Diese Suite läuft in CI bei jeder Änderung an Policy Engine, Taint-Logik oder Prompt-Konstruktion.

### 4.5 Regressionsschutz beim Modellwechsel

Bei jedem Wechsel eines Modells oder einer Modellversion laufen alle Eval-Suiten gegen alt und neu. Verschlechterung um mehr als 3 Prozentpunkte in einer Kernmetrik blockiert den Wechsel. Ohne dieses Gate ist ein Modellupdate ein Blindflug — die Qualität ändert sich, ohne dass jemand es merkt, bis im Alltag etwas schiefgeht.

---

## 5. Integrationstests

- Echte PostgreSQL- und Redis-Instanz (Testcontainers), keine Mocks für die Datenbank.
- Provider durch Doubles ersetzt, die den aufgezeichneten Antworten entsprechen.
- Vollständige Läufe: Nachricht → Klassifikation → Plan → Tools → Bestätigung → Ergebnis.
- **Wiederaufnahme:** Lauf mitten in `awaiting_confirmation` beenden, Prozess neu starten, bestätigen — der Lauf muss korrekt fortsetzen.
- **Löschung:** `DELETE /v1/me/data` — anschließend Prüfung, dass keine Zeile in keiner Tabelle verbleibt (außer pseudonymisiertem Audit-Log).

---

## 6. E2E-Tests (Playwright)

Wenige, dafür die kritischen Pfade:

1. Anmeldung mit Passkey → Chat → Antwort mit Streaming
2. HIGH-Risk-Aktion → Bestätigungsdialog → Ablehnung → **keine Ausführung**
3. HIGH-Risk-Aktion → Bestätigung → Ausführung → Audit-Eintrag vorhanden
4. Berechtigung entziehen → dieselbe Aktion wird abgelehnt, mit korrekter Begründung
5. Gedächtniseintrag löschen → wird nicht mehr abgerufen
6. Verbindungsabbruch während eines Laufs → Reconnect → Zustand korrekt wiederhergestellt
7. Taint-Sperre → korrekte Meldung (HTTP 423), Aktion nicht ausführbar

---

## 7. Sprach- und Vision-Tests

| Bereich | Verfahren |
|---|---|
| Wake Word | Aufgezeichnete Positiv- und Negativbeispiele; Fehlauslösungen pro Stunde messen; Negativset enthält Fernsehton und Gespräche |
| STT | Eigene Aufnahmen mit Referenztranskript; WER; besonderes Augenmerk auf Eigennamen und Anglizismen |
| Latenz | Automatisierte Messung der Stufen aus `08-voice.md §6`; Regression bei > 15 % Verschlechterung |
| Barge-in | Skriptierte Unterbrechung während der Ausgabe; keine Selbstauslösung durch Echo |
| Gesten | Aufgezeichnete Videosequenzen; Trefferquote und Fehlauslösungsrate; Test bei wechselnden Lichtverhältnissen |

---

## 8. CI-Pipeline

```
1. Lint (Ruff, ESLint) + Format
2. Typen (mypy strict, tsc)
3. Contracts-Drift-Prüfung  (make gen && git diff --exit-code)
4. Unit-Tests + Abdeckungsgrenze
5. Contract-Tests gegen Kassetten
6. Integrationstests (Testcontainers)
7. Sicherheits-Eval (Injection-Suite)        ⬅ blockierend
8. Secret-Scan (gitleaks)
9. Abhängigkeits-Audit (pip-audit, pnpm audit)
10. E2E (nur auf main und Release-Branches)

Nächtlich:  Live-Contract-Tests · vollständige Eval-Suiten · Backup-Restore-Test
```

Schritt 7 ist blockierend und wird nicht übersprungen. Er ist der Test, der verhindert, dass die wichtigste Sicherheitseigenschaft des Systems unbemerkt kaputtgeht.
