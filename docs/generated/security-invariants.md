# Sicherheits-Invarianten

> GENERIERT aus `packages/core/jarvis_core/policy/invariants.py`.

Leitkennzahl des Sicherheitskerns. Testabdeckung sagt nicht, ob der Ablauf
*kontaminiert → Bestätigung → veränderter Payload → Ausführung* abgewehrt wird;
diese Tabelle sagt es.

**Security Invariant Coverage: 61/62**

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
| `execution-claim-single-use` | Eine Bestätigung erwirkt höchstens einen Ausführungsanspruch | Eine bestätigte Aktion erwirkt genau einen Ausführungsanspruch; jede weitere Autorisierung derselben Bestätigung wird abgewiesen, auch unter Nebenläufigkeit. | `core.policy.approval` |
| `grant-single-use` | Ein ausgestellter Grant führt höchstens einmal aus | Ein ExecutionGrant erlaubt genau einen Werkzeugaufruf; jede weitere Vorlage desselben Grants — auch als Kopie, aus einem anderen Prozess, nebenläufig oder nach einem Absturz vor dem Commit — erreicht den Handler nicht. | `core.tools.registry` |
| `approval-not-forgeable-by-model` | Ein Modell kann keine Bestätigung erzeugen | Bestätigungen entstehen ausschließlich aus einer Nutzerinteraktion; Modellausgaben und Werkzeugargumente haben keinen Einfluss darauf. | `core.policy.engine` |
| `approval-channel-bound` | Bestätigt wird dort, wo angezeigt wurde | Eine Bestätigung ist an Nutzer, Sitzung und Anzeigekanal gebunden und lässt sich nicht über einen anderen Kanal oder eine andere Sitzung einlösen. | `core.policy.approval` |
| `identity-derives-from-session` | Identität entsteht an genau einer Stelle | Kein HTTP-Endpunkt übernimmt user_id, session_id oder eine andere Identitätsangabe aus Body, Query, Header oder Pfad; sie stammt ausschließlich aus der verifizierten Sitzung. | `api.http` |
| `bootstrap-only-once` | Die Erstinbetriebnahme gelingt genau einmal | Der Bootstrap-Endpunkt legt einen Nutzer nur an, solange die Nutzertabelle leer ist; die Bedingung liegt im INSERT, nicht in einer Prüfung davor. | `api.http` |
| `auth-endpoints-rate-limited` | Der Anmeldeweg ist begrenzt — auch über viele Adressen | Jeder ohne Anmeldung erreichbare Endpunkt zählt gegen zwei Grenzen: eine je Client und eine globale je Route. Registrierung, Anmeldung und Erstinbetriebnahme haben getrennte Zähler. | `api.http` |
| `rate-limit-counting-is-atomic` | Zählen und Fristsetzen sind unteilbar | Der Zähler wird erhöht und seine Frist gesetzt in einem einzigen, atomaren Schritt; gleichzeitige Anfragen zählen vollständig. | `api.rate_limit` |
| `session-verified-before-approval` | Eine Bestätigung verlangt eine echte Sitzung | Eine Bestätigung wird nur eingelöst, wenn der vorgelegte Sitzungstoken zu genau dieser Sitzung dieses Nutzers gehört und die Sitzung weder abgelaufen noch widerrufen ist. | `core.auth` |
| `passkey-challenge-single-use` | Eine Challenge gilt einmal und für einen Zweck | Eine WebAuthn-Challenge wird genau einmal eingelöst, verfällt nach kurzer Frist und schließt nur die Zeremonie ab, für die sie ausgestellt wurde. | `core.auth` |
| `passkey-clone-detection` | Ein Signaturzähler, der nicht steigt, ist ein Klon | Eine Anmeldung wird abgelehnt, wenn der vorgelegte Signaturzähler nicht über dem gespeicherten liegt — außer beide sind null. | `core.auth` |
| `approval-critical-ui-only` | Irreversibles wird nur in der Oberfläche bestätigt | CRITICAL-Aktionen akzeptieren keine Sprach- oder Gestenbestätigung. | `contracts.permissions` |
| `policy-single-entry-point` | Die Policy Engine ist der einzige Weg | Kein Werkzeug wird ohne Policy-Entscheidung ausgeführt: Die Registry gibt keinen Handler heraus und verlangt einen ExecutionGrant — nominal geprüft (type(auth) is ExecutionGrant), nicht strukturell. | `core.policy.engine` |
| `grant-bound-to-run` | Eine Erlaubnis gilt für einen Aufruf in einem Lauf | Die Registry führt einen Grant nur aus, wenn Lauf und Nutzer des Grants dem Kontext entsprechen, in dem tatsächlich ausgeführt wird. | `core.tools.registry` |
| `data-class-monotonic-within-run` | Die Datenklasse eines Laufs steigt nur | Innerhalb eines Laufs wird die Datenklasse nie gesenkt, und die Obergrenze eines Aufrufs stammt aus der Routing-Entscheidung, nicht vom Aufrufer. | `core.orchestrator` |
| `policy-not-overridable-by-content` | Inhalte ändern keine Policy | Werkzeugargumente und Fremdinhalte beeinflussen die Entscheidung nicht — auch nicht bei Feldern wie „user_confirmed“. | `core.policy.engine` |
| `agent-no-capability-escalation` | Delegation erzeugt keine Rechte | Ein Sub-Agent erhält höchstens die Schnittmenge aus eigener Whitelist und Nutzerrechten; ein anderer Agent als Anfragender ändert daran nichts. | `core.policy.engine` |
| `tool-risk-not-self-declared` | Werkzeuge stufen sich nicht selbst herab | Ein Plugin kann seine Risikoklasse nicht senken; der Kern nimmt das Maximum. | `contracts.tools` |
| `tool-no-silent-override` | Kein stiller Namenstausch | Ein bereits registriertes Werkzeug lässt sich nicht überschreiben. | `core.tools.registry` |
| `plan-step-claimed-before-effect` | Ein Planschritt wird beansprucht, bevor er wirkt | Ein fälliger Planschritt wird atomar und festgeschrieben beansprucht, bevor Modell oder Werkzeug laufen; ein zweiter Anspruch auf denselben Schritt scheitert vor jeder Wirkung. | `api.db.run_store` |
| `plan-step-claim-is-fenced` | Nur der Inhaber gibt seinen Anspruch frei und schreibt sein Ergebnis | Freigabe und Fortschreiben eines beanspruchten Planschrittes gelten nur mit der Kennung, unter der er beansprucht wurde. | `api.db.run_store` |
| `invocation-is-recovery-anchor` | Das Werkzeugprotokoll beantwortet, was aus einem Schritt wurde | Jeder Aufruf eines geplanten Schrittes ist über Lauf und Schrittnummer auffindbar und lesbar, und sein Zustand unterscheidet „ohne Wirkung gescheitert“ von „Wirkung unklar“. | `api.db.invocation_store` |
| `hung-step-is-reassigned-only-when-provably-idle` | Ein hängender Schritt wird nur neu vergeben, wenn er nachweislich nicht wirkte | Ein beanspruchter Planschritt wird erst nach Ablauf einer Frist übernommen — gemessen an der Uhr der Datenbank — und nur, wenn das Werkzeugprotokoll eine Wirkung ausschließt oder das Werkzeug idempotent ist. Die Übernahme vergibt ein neues Fencing-Token und sperrt den Vorgänger vom Schreiben aus. | `core.orchestrator.recovery` |
| `unattended-step-has-no-approval-channel` | Ein Schritt ohne Sitzung erzeugt keine Bestätigung | Ein Werkzeugschritt, der ohne Sitzung ausgeführt wird, legt bei einer CONFIRM-Entscheidung **keine** Bestätigungsanfrage an. Er wird abgewiesen, der Lauf bleibt stehen, und der Protokolleintrag führt ihn als wiederholbar. | `core.orchestrator.executor` |
| `undo-is-bound-to-its-invocation` | Eine Rücknahme trifft genau den Aufruf, zu dem sie gehört | Zurückgenommen wird ausschließlich ein protokollierter, ausgeführter, eigener Aufruf innerhalb von ``UNDO_TTL`` — höchstens einmal, und an dem Rücknahmepunkt, den das Werkzeug selbst hinterlassen hat. Weder Token noch Zielobjekt kommen aus dem Request. | `core.policy.undo` |
| `undo-grant-single-use` | Eine ausgestellte Rücknahme-Erlaubnis nimmt höchstens einmal zurück | Ein ``UndoGrant`` erreicht den Undo-Handler genau einmal. Der Verbrauch liegt an der ``invocation_id``, ist atomar und committet, bevor der Handler läuft — unabhängig davon, wie oft dasselbe Objekt oder eine Kopie davon vorgelegt wird. | `core.tools.registry` |
| `permissions-change-only-at-the-edge` | Rechte erteilt ein Mensch, kein Werkzeug | Berechtigungen werden ausschließlich an der HTTP-Kante geschrieben — aus einer geprüften Sitzung, gegen den Scope-Katalog, mit scope-eigenen Einschränkungen. Kein Werkzeug trägt einen Berechtigungs-Scope, und kein Kernmodul ruft die schreibenden Methoden. | `api.routes.permissions` |
| `audit-chain-records-what-happened` | Was geschieht, steht in der verketteten Spur | Jede Werkzeugausführung, jede Bestätigung und jede Rechteänderung schreibt einen Eintrag in das hash-verkettete Audit-Log — serialisiert, append-only und mit einem Weg, die Kette nachzurechnen. | `api.db.audit_store` |
| `event-stream-is-scoped-and-contentless` | Der Ereignisstrom trägt Hinweise, und zwar nur die eigenen | Ein Ereignisstrom liefert ausschließlich Ereignisse des angemeldeten Nutzers, und er trägt keine Geheimnisse und keinen Fremdinhalt — weder Nonce noch Argumente noch Werkzeugergebnisse. Was gilt, holt die Oberfläche über die API. | `api.events` |
| `tool-result-model-view-is-declared` | Ein Modell sieht von einem Ergebnis nur, was das Werkzeug erklärt hat | Aus einem ``ToolResult`` erreicht ausschließlich das den Prompt, was ``ToolSpec.model_visible_fields`` benennt — gekappt auf eine feste Grenze. Die Vorgabe ist leer. | `contracts.tools` |
| `tool-arguments-match-schema` | Argumente werden gegen das Werkzeugschema geprüft | Kein Argumentobjekt erreicht Policy-Entscheidung, Vorschau, Payload-Hash oder Handler, ohne gegen ``ToolSpec.parameters`` geprüft worden zu sein. | `core.orchestrator.executor` |
| `data-class-hard-filter` | Datenklassifikation ist ein hartes Filter | Ein Kontext, der eine Klasse nicht zulässt, führt kein Werkzeug dieser Klasse aus. | `core.policy.engine` |
| `unattended-runs-are-stricter` | Unbeaufsichtigte Läufe sind strenger | Automationen bestätigen schreibende Aktionen, auch wenn das Recht erteilt ist. | `core.policy.engine` |
| `model-never-sees-excess-data-class` | Ein Anbieter sieht nie Daten oberhalb seiner Zulassung | Eine Anfrage erreicht einen Anbieteradapter nur, wenn dessen Modell für die Datenklasse zugelassen ist; P3 erreicht ausschließlich lokale Modelle. | `core.providers.gateway` |
| `cloud-limited-to-p1-with-zero-retention` | Ein fremder Anbieter sieht höchstens P1 — und P1 nur ohne Vorhaltung | Ein Modell, das nicht auf diesem Gerät läuft, erreicht P0 immer, P1 nur mit hinterlegter Zero-Retention-Zusage, P2 nur nach ausdrücklicher Freigabe und P3 nie. Geprüft wird beim Aufruf, nicht nur im Katalog. | `core.providers.gateway` |
| `model-tool-calls-are-proposals` | Ein Modell schlägt vor, es ordnet nicht an | Werkzeugaufrufe aus einer Modellantwort tragen keine Erlaubnis: Der Vertragstyp führt weder Risiko noch Scope noch Bestätigung, und jeder Vorschlag durchläuft Policy Engine und Ausführungs-Gate wie jede andere Absicht. | `contracts.llm` |
| `orchestrator-consumes-decisions` | Der Orchestrator entscheidet nichts über Sicherheit | Der Orchestrator fragt die Policy Engine und das Ausführungs-Gate; er bildet keine eigene Meinung darüber, ob etwas erlaubt ist. | `core.orchestrator` |
| `agent-chain-preserves-capability-binding` | Delegationsketten erweitern keine Rechte | Über beliebig viele Agentenstufen hinweg bleibt die Rechtemenge die Schnittmenge aller beteiligten Whitelists mit den Nutzerrechten. | `core.agents` |
| `agent-chain-propagates-taint` | Kontamination wandert durch die ganze Kette | Liest ein Agent auf beliebiger Stufe Fremdinhalt, gilt der gesamte übergeordnete Lauf als kontaminiert. | `core.agents` |
| `audit-append-only` | Das Audit-Log ist unveränderlich | UPDATE und DELETE werden auf Datenbankebene abgelehnt. | `db.audit_log` |
| `audit-tamper-evident` | Manipulation ist erkennbar | Änderung, Löschung oder Umsortierung von Einträgen bricht die Hash-Kette. | `core.audit.chain` |
| `audit-chain-break-is-detected` | Ein Bruch wird gefunden, ohne dass jemand nachsieht | Der Arbeiter rechnet die ganze Kette in eigenem Takt nach. Ein Bruch hält ihn an und steht danach als Eintrag in der Kette, die er betrifft. | `core.audit.watch` |
| `audit-survives-erasure` | Löschpflicht und Kette schließen sich nicht aus | Die Pseudonymisierung eines Nutzers lässt die Hash-Kette unversehrt, weil user_id nicht gehasht wird. | `core.audit.chain` |
| `file-access-confined-to-roots` | Ein Dateizugriff verlässt die freigegebenen Wurzeln nicht | files.read gibt nur Inhalte heraus und files.list nur Namen, deren Pfad **nach Auflösung** unterhalb einer konfigurierten Wurzel liegt; eine Abweisung verrät nicht, wohin der Pfad zeigte, und eine Aufzählung löst die Verweise darin nicht auf. | `integrations.localfs` |
| `web-fetch-reaches-only-public-addresses` | Ein Abruf erreicht nur, was aus dem Internet erreichbar ist | web.fetch baut eine Verbindung ausschließlich zu öffentlich routbaren Adressen auf; geprüft wird die aufgelöste Adresse vor dem Verbindungsaufbau und nach jeder Weiterleitung erneut. | `integrations.web` |
| `resource-ownership-checked-once` | Eine Sitzung berechtigt an eigenen Objekten, nicht an beliebigen | Jeder Endpunkt, der eine Ressourcenkennung entgegennimmt, prüft die Zugehörigkeit zum angemeldeten Nutzer über genau eine Funktion; ein fremdes Objekt ist von einem nicht existierenden nicht unterscheidbar. | `api.routes` |
| `run-state-compare-and-set` | Ein Lauf wird nur aus dem erwarteten Status fortgeschrieben | save() schreibt nur, wenn der Lauf noch in dem Status steht, den der Schreiber vorzufinden erwartet; sonst wird abgewiesen und nichts geändert. | `api.db.run_store` |
| `uncertain-effect-resolved-only-by-owner` | Einen unklaren Schritt löst nur sein Eigentümer auf — gegen den aktuellen Anspruch | Ein Schritt mit möglicher, aber unbestätigter Wirkung bleibt gesperrt, bis der Eigentümer des Laufs eine von genau drei benannten Entscheidungen trifft; sie gilt nur gegen das Fencing-Token des gehaltenen Anspruchs und wird in derselben Anweisung geprüft, die schreibt. | `core.orchestrator.resolution` |
| `layering-contracts-independent` | Verträge hängen von nichts ab | packages/contracts importiert nichts aus dem Projekt. | `repo` |
| `layering-no-provider-sdk-in-core` | Kein Provider-SDK im Kern | Weder core noch contracts importieren Anbieter-SDKs oder Agenten-Frameworks. | `repo` |

## Noch offen

Ausdrücklich ausgewiesen, damit nicht der Eindruck entsteht, etwas sei
abgesichert, bevor der Kontrollpunkt existiert.

| Kennung | Invariante | Wird gebraucht, weil | Komponente |
|---|---|---|---|
| `session-token-rotation` | Ein benutzter Sitzungstoken wird ersetzt | Ohne Rotation bleibt ein entwendeter Token bis zum Ablauf gültig, auch wenn der rechtmäßige Nutzer weiterarbeitet — das Zeitfenster für einen Replay ist die volle Sitzungsdauer. Der Grund für den Aufschub ist ein Wettlauf: Zwei gleichzeitige Anfragen mit demselben Token dürfen nicht dazu führen, dass eine davon abgemeldet wird. Die Semantik des Überlappungsfensters ist zu spezifizieren, bevor sie implementiert wird (ADR-007, Nachtrag). | `core.auth` |
