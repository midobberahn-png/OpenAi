# Sicherheits-Invarianten

> GENERIERT aus `packages/core/jarvis_core/policy/invariants.py`.

Leitkennzahl des Sicherheitskerns. Testabdeckung sagt nicht, ob der Ablauf
*kontaminiert → Bestätigung → veränderter Payload → Ausführung* abgewehrt wird;
diese Tabelle sagt es.

**Security Invariant Coverage: 26/29**

Ein Meta-Test (`tests/unit/test_invariant_coverage.py`) schlägt fehl, sobald eine
als durchgesetzt geführte Invariante keinen Test hat — die Kennzahl lässt sich
nicht nachträglich passend machen.

## Durchgesetzt

| Kennung | Invariante | Gilt | Komponente |
|---|---|---|---|
| `taint-monotonic` | Kontamination ist monoton | Ein Lauf, der einmal TAINTED ist, wird durch keinen Vorgang wieder CLEAN. | `contracts.classification` |
| `taint-no-implicit-clearing` | Keine stillschweigende Sanierung | Kontamination wird ausschließlich über das Sanitization-Gate aufgehoben — und dort nur durch eine Nutzerbestätigung, nie durch Programmfluss. | `core.policy.engine` |
| `taint-precedes-permission` | Taint wird vor der Berechtigung geprüft | Eine erteilte Berechtigung schaltet in einem kontaminierten Lauf nichts frei. | `core.policy.engine` |
| `taint-cross-run-isolation` | Kontamination überschreitet keine Laufgrenze | Ein sanierter Lauf startet sauber und ohne Kontext des Herkunftslaufs. | `contracts.runs` |
| `taint-memory-quarantine` | Gedächtnis ist kein zeitversetzter Kanal | Gedächtniskandidaten aus kontaminierten Läufen werden nie automatisch übernommen — unabhängig von der Konfidenz. | `contracts.memory` |
| `payload-outbound-classification` | Außenwirkung schlägt Struktur | Ein Aufruf mit belegtem Empfänger- oder Teilnehmerfeld gilt als nicht prüfbar, auch wenn das Werkzeug statisch als strukturiert eingestuft ist. | `contracts.tools` |
| `payload-freeform-never-sanitizable` | Freitext mit Außenwirkung wird nie saniert | Payloads mit Freitext-Außenwirkung sind in kontaminierten Läufen gesperrt. | `contracts.tools` |
| `payload-immutable-after-approval` | Bestätigter Payload ist unveränderlich | Was ausgeführt wird, ist byte-identisch mit dem, was in der Vorschau stand. | `core.policy.approval` |
| `approval-bound-to-payload-hash` | Bestätigung ist an den Payload gebunden | Eine Bestätigung gilt nur für den Payload, dessen Hash bei der Anfrage festgehalten wurde. | `core.policy.approval` |
| `approval-toctou-protected` | Kein Zeitfenster zwischen Prüfung und Ausführung | Unmittelbar vor der Ausführung werden Payload-Hash und Policy erneut geprüft; zwischenzeitlich entzogene Rechte greifen sofort. | `core.policy.approval` |
| `approval-nonce-single-use` | Bestätigungen sind einmalig | Eine Nonce lässt sich genau einmal einlösen, auch unter Nebenläufigkeit. | `core.policy.approval` |
| `approval-not-forgeable-by-model` | Ein Modell kann keine Bestätigung erzeugen | Bestätigungen entstehen ausschließlich aus einer Nutzerinteraktion; Modellausgaben und Werkzeugargumente haben keinen Einfluss darauf. | `core.policy.engine` |
| `approval-channel-bound` | Bestätigt wird dort, wo angezeigt wurde | Eine Bestätigung ist an Nutzer, Sitzung und Anzeigekanal gebunden und lässt sich nicht über einen anderen Kanal oder eine andere Sitzung einlösen. | `core.policy.approval` |
| `approval-critical-ui-only` | Irreversibles wird nur in der Oberfläche bestätigt | CRITICAL-Aktionen akzeptieren keine Sprach- oder Gestenbestätigung. | `contracts.permissions` |
| `policy-single-entry-point` | Die Policy Engine ist der einzige Weg | Kein Werkzeug wird ohne Policy-Entscheidung ausgeführt: Die Registry gibt keinen Handler heraus und verlangt eine ExecutionAuthorization. | `core.policy.engine` |
| `policy-not-overridable-by-content` | Inhalte ändern keine Policy | Werkzeugargumente und Fremdinhalte beeinflussen die Entscheidung nicht — auch nicht bei Feldern wie „user_confirmed“. | `core.policy.engine` |
| `agent-no-capability-escalation` | Delegation erzeugt keine Rechte | Ein Sub-Agent erhält höchstens die Schnittmenge aus eigener Whitelist und Nutzerrechten; ein anderer Agent als Anfragender ändert daran nichts. | `core.policy.engine` |
| `tool-risk-not-self-declared` | Werkzeuge stufen sich nicht selbst herab | Ein Plugin kann seine Risikoklasse nicht senken; der Kern nimmt das Maximum. | `contracts.tools` |
| `tool-no-silent-override` | Kein stiller Namenstausch | Ein bereits registriertes Werkzeug lässt sich nicht überschreiben. | `core.tools.registry` |
| `data-class-hard-filter` | Datenklassifikation ist ein hartes Filter | Ein Kontext, der eine Klasse nicht zulässt, führt kein Werkzeug dieser Klasse aus. | `core.policy.engine` |
| `unattended-runs-are-stricter` | Unbeaufsichtigte Läufe sind strenger | Automationen bestätigen schreibende Aktionen, auch wenn das Recht erteilt ist. | `core.policy.engine` |
| `audit-append-only` | Das Audit-Log ist unveränderlich | UPDATE und DELETE werden auf Datenbankebene abgelehnt. | `db.audit_log` |
| `audit-tamper-evident` | Manipulation ist erkennbar | Änderung, Löschung oder Umsortierung von Einträgen bricht die Hash-Kette. | `core.audit.chain` |
| `audit-survives-erasure` | Löschpflicht und Kette schließen sich nicht aus | Die Pseudonymisierung eines Nutzers lässt die Hash-Kette unversehrt, weil user_id nicht gehasht wird. | `core.audit.chain` |
| `layering-contracts-independent` | Verträge hängen von nichts ab | packages/contracts importiert nichts aus dem Projekt. | `repo` |
| `layering-no-provider-sdk-in-core` | Kein Provider-SDK im Kern | Weder core noch contracts importieren Anbieter-SDKs oder Agenten-Frameworks. | `repo` |

## Noch offen

Ausdrücklich ausgewiesen, damit nicht der Eindruck entsteht, etwas sei
abgesichert, bevor der Kontrollpunkt existiert.

| Kennung | Invariante | Wird gebraucht, weil | Komponente |
|---|---|---|---|
| `orchestrator-consumes-decisions` | Der Orchestrator entscheidet nichts über Sicherheit | Sobald der Orchestrator „das ist wahrscheinlich sicher“ oder „das wurde gerade bestätigt“ selbst beurteilt, gibt es zwei Wahrheiten über Berechtigungen — und die zweite prüft niemand. Er muss Konsument von Sicherheitsentscheidungen sein, nicht ihr Urheber. | `core.orchestrator` |
| `agent-chain-preserves-capability-binding` | Delegationsketten erweitern keine Rechte | Die bisherige Prüfung deckt eine Stufe ab. Bei A → B → C darf C nicht die Fähigkeiten von B erben, nur weil B ihn aufgerufen hat — sonst ist die Kette der Umweg um jede Beschränkung. | `core.agents` |
| `agent-chain-propagates-taint` | Kontamination wandert durch die ganze Kette | Andernfalls genügte eine Zwischenstufe als Waschmaschine: Agent B liest die Mail, meldet ein „sauberes“ Ergebnis nach oben, und A sendet. | `core.agents` |
