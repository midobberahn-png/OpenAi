#!/usr/bin/env python
"""Erzeugt ein Prüfpaket für externe Begutachtung.

Hintergrund: Die Berater haben bisher Statusberichte bewertet, also
Selbstauskunft. Das ist die schwächste Form der Prüfung — sie kann Fehler in
der Beschreibung nicht von Fehlern im Code unterscheiden, und tatsächlich
enthielten mehrere Rückmeldungen Aussagen über Code, der so nicht existiert.

Dieses Skript legt den sicherheitskritischen Quelltext in Portionen ab, die
sich einzeln in ein Gesprächsfenster kopieren lassen, zusammen mit einer
Prüfliste: jede Behauptung aus den Statusberichten als falsifizierbarer Satz
mit Fundstelle.

    uv run python scripts/pruefpaket.py

Die Ausgabe landet in ``pruefpaket/`` (nicht versioniert) und trägt den
Commit-Stand im Kopf jeder Datei — ein Paket ohne Stand ist in einer Woche
wertlos.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "pruefpaket"


@dataclass(frozen=True)
class Portion:
    nummer: str
    titel: str
    auftrag: str
    dateien: tuple[str, ...]


PORTIONEN: tuple[Portion, ...] = (
    Portion(
        nummer="01",
        titel="Sicherheitskern — Policy, Approval, Ausführungs-Gate",
        auftrag=(
            "Der Kern der Behauptung „kein Werkzeug läuft ohne Gate“. Zu prüfen: "
            "Gibt es einen Pfad zu einem ExecutionGrant, der nicht durch "
            "PolicyEngine.decide() führt? Kann ein Aufrufer die Entscheidung "
            "beeinflussen, statt sie einzuholen? Ist die Reihenfolge der Prüfungen in "
            "decide() an einer Stelle vertauschbar, ohne dass ein Test bricht? "
            "Neu und deshalb besonders zu prüfen: der Grant-Verbrauch in "
            "ToolRegistry.execute() als fünfte Prüfung. Gibt es einen Weg zum Handler, "
            "der an ihm vorbeiführt? Ist seine Stellung am Ende richtig — verbrennt "
            "eine abgelehnte Prüfung wirklich keinen Anspruch? Und hält die Bindung an "
            "die invocation_id, oder gibt es einen Grant, dessen invocation_id sich "
            "beeinflussen lässt?"
        ),
        dateien=(
            "packages/core/jarvis_core/policy/engine.py",
            "packages/core/jarvis_core/policy/approval.py",
            "packages/core/jarvis_core/tools/registry.py",
            "packages/core/jarvis_core/tools/grants.py",
            "packages/core/jarvis_core/ports/grants.py",
            "packages/core/jarvis_core/ports/permissions.py",
            "packages/core/jarvis_core/policy/invariants.py",
        ),
    ),
    Portion(
        nummer="02",
        titel="Orchestrator und Agentenketten",
        auftrag=(
            "Zu prüfen: Leitet der Executor trigger und allowed_data_class wirklich "
            "ausschließlich aus dem Run ab? Gibt es in der Agentenkette einen Weg, die "
            "Schnittmenge zu erweitern statt zu verengen? Kann die Selbstauskunft eines "
            "Sub-Agenten (taint_acquired) Kontamination aufheben?"
        ),
        dateien=(
            "packages/core/jarvis_core/orchestrator/executor.py",
            "packages/core/jarvis_core/agents/chain.py",
            "packages/core/jarvis_core/agents/runtime.py",
            "packages/core/jarvis_core/orchestrator/router.py",
        ),
    ),
    Portion(
        nummer="03",
        titel="Anmeldung — Sitzungen, Passkeys, Zugriffsgrenzen",
        auftrag=(
            "Zu prüfen: Existiert der Sitzungstoken irgendwo außer bei der Ausgabe? "
            "Kann eine Identität aus einem Request stammen? Ist die Klon-Erkennung "
            "umgehbar? Hält das zweistufige Rate-Limit, wenn ein Angreifer für jede "
            "Anfrage eine neue Kennung erfindet?"
        ),
        dateien=(
            "packages/core/jarvis_core/auth/sessions.py",
            "packages/core/jarvis_core/auth/passkeys.py",
            "packages/core/jarvis_core/limits/policy.py",
            "packages/core/jarvis_core/limits/guard.py",
            "packages/contracts/jarvis_contracts/auth.py",
        ),
    ),
    Portion(
        nummer="04",
        titel="HTTP-Grenze — die einzige Stelle, an der Identität entsteht",
        auftrag=(
            "Die dünnste und jüngste Schicht, deshalb die interessanteste. Zu prüfen: "
            "Liest ein Endpunkt Request-Daten als Identität? Gibt es einen Weg an "
            "current_session vorbei? Ist ein Endpunkt ohne Sitzungspflicht dabei, der "
            "nicht in der begründeten Ausnahmeliste steht? Ist X-Forwarded-For "
            "irgendwo ungeprüft verwendet? "
            "Neu in dieser Runde die Lauf- und Bestätigungsrouten und damit die zweite "
            "Frage der Schicht: Die Sitzung sagt, WER fragt — prüft jeder Endpunkt mit "
            "fremder Kennung auch, ob ihm das Objekt GEHOERT? Gibt es einen Ladeweg an "
            "_eigener_lauf/_eigene_aktion vorbei? Unterscheiden sich die Antworten auf "
            "ein fremdes und ein nicht existierendes Objekt irgendwo — im Status, im "
            "Text, in der Laufzeit? Und: Kann der Aufrufer den Bestätigungskanal "
            "beeinflussen?"
        ),
        dateien=(
            "apps/api/jarvis_api/deps.py",
            "apps/api/jarvis_api/routes/auth.py",
            "apps/api/jarvis_api/routes/runs.py",
            "apps/api/jarvis_api/routes/actions.py",
            "apps/api/jarvis_api/tools.py",
            "apps/api/jarvis_api/models.py",
            "apps/api/jarvis_api/main.py",
            "apps/api/jarvis_api/settings.py",
            "apps/api/jarvis_api/auth/webauthn_verifier.py",
        ),
    ),
    Portion(
        nummer="05",
        titel="Persistenz — Atomarität dort, wo sie behauptet wird",
        auftrag=(
            "Alle Einmaligkeitszusagen des Systems hängen an diesen Abfragen. Zu "
            "prüfen: Ist jede Bedingung wirklich in der WHERE-Klausel, oder steht "
            "irgendwo ein lesendes SELECT vor einem schreibenden UPDATE? Kann ein "
            "Zähler ohne Frist entstehen? Und die Frage dieser Runde: Wem gehört "
            "die Transaktion, in der die Zusage steht — dem Aufrufer, der sie "
            "zurückrollen kann, oder dem Store selbst?"
        ),
        dateien=(
            "apps/api/jarvis_api/db/approval_store.py",
            "apps/api/jarvis_api/db/session_store.py",
            "apps/api/jarvis_api/db/webauthn_store.py",
            "apps/api/jarvis_api/db/invocation_store.py",
            "apps/api/jarvis_api/db/grant_store.py",
            "apps/api/jarvis_api/db/run_store.py",
            "apps/api/jarvis_api/db/permission_store.py",
            "apps/api/jarvis_api/rate_limit_store.py",
        ),
    ),
    Portion(
        nummer="09",
        titel="Das erste echte Werkzeug — Dateizugriff",
        auftrag=(
            "Der gesamte Sicherheitssockel sicherte bis zu diesem Block nichts Reales "
            "ab; es gab nur Attrappen. files.read ist das erste Werkzeug mit echter "
            "Außenanbindung und deshalb der interessanteste Prüfgegenstand des Pakets. "
            "Zu prüfen ist vor allem die Pfadgrenze, und zwar auf beiden Ebenen: Die "
            "Berechtigung prüft eine Zeichenkette, der Adapter löst auf. Gibt es einen "
            "Pfad, der beide besteht und trotzdem hinausführt? Hardlink? Ein Symlink, "
            "der erst zwischen resolve() und open() entsteht? Ein Mount innerhalb der "
            "Wurzel? Was passiert bei einer Wurzel, die selbst ein Symlink ist? "
            "Verrät eine Fehlermeldung, ob eine Datei existiert oder wohin ein Verweis "
            "zeigt — auch über die Laufzeit? Und: Ist die Kontamination "
            "(reads_untrusted_content) wirklich gesetzt, oder ließe sich Dateiinhalt in "
            "einen sauberen Lauf bringen?"
        ),
        dateien=(
            "packages/core/jarvis_core/ports/files.py",
            "packages/core/jarvis_core/tools/builtin/files.py",
            "packages/integrations/jarvis_integrations/localfs.py",
            "apps/api/jarvis_api/tools.py",
            "apps/api/jarvis_api/db/permission_store.py",
            "tests/unit/test_localfs.py",
        ),
    ),
    Portion(
        nummer="06",
        titel="Strukturtests — die Absicherung gegen künftige Fehler",
        auftrag=(
            "Diese Tests sollen Fehler finden, die noch niemand gemacht hat — und "
            "zwei von ihnen haben beim letzten Review versagt (siehe „Was seit dem "
            "letzten Paket geschah“). Beide sind gehärtet. Zu prüfen: Lässt sich die "
            "Härtung erneut umgehen? Der Grant-Test folgt jetzt dem aufgerufenen Namen "
            "samt Aliasen, der HTTP-Test der Methode statt des Objektnamens. Wo ist "
            "die nächste Lücke — Dekoratoren über eine Hilfsfunktion, dynamisch "
            "registrierte Routen, `add_api_route()`? Und: Genügt die nominale Prüfung "
            "in test_tool_registry.py, oder gibt es einen Weg an `type(auth) is "
            "ExecutionGrant` vorbei?"
        ),
        dateien=(
            "tests/unit/test_http_boundary.py",
            "tests/unit/test_layering.py",
            "tests/unit/test_tool_registry.py",
            "tests/unit/test_invariant_coverage.py",
        ),
    ),
    Portion(
        nummer="07",
        titel="Adversariale Suiten — was tatsächlich angegriffen wird",
        auftrag=(
            "Zu prüfen: Prüfen diese Tests wirklich das, was ihr Name sagt? Gibt es "
            "Tests, die grün sind, weil sie am eigentlichen Fall vorbeigehen? Der "
            "Software-Authenticator ist dabei das interessanteste Stück — er erzeugt "
            "echte Signaturen und entscheidet damit, ob die WebAuthn-Angriffe geprüft "
            "oder nur behauptet sind."
        ),
        dateien=(
            "tests/authenticator.py",
            "tests/integration/test_http_auth.py",
            "tests/integration/test_e2e_identity_to_execution.py",
            "tests/integration/test_rate_limit.py",
            "tests/unit/test_grant_replay.py",
            "tests/integration/test_grant_consumption.py",
        ),
    ),
    Portion(
        nummer="08",
        titel="Sprachmodelle — Gateway, Adapter, Modellschleife",
        auftrag=(
            "Die jüngste Schicht und die einzige, die noch keine Prüfung gesehen hat. "
            "Hier bekommt ein Sprachmodell zum ersten Mal die Möglichkeit, etwas zu "
            "bewirken. Zu prüfen: Gibt es einen Weg zu einem Modellaufruf, der nicht "
            "durch ModelGateway.complete() führt? Führt die Schleife irgendwo selbst "
            "aus, statt über AgentSession.call_tool() zu gehen? Ist "
            "ModelGateway._kontaminiert() richtig — die Antwort erbt den Taint ihres "
            "Kontexts, statt pauschal als Fremdinhalt zu gelten; wo bricht diese Regel? "
            "Und der wunde Punkt, den ich selbst sehe: data_class ist ein Parameter "
            "von complete(). Das Gateway kann nicht erzwingen, dass er aus dem "
            "persistierten Lauf stammt — es vertraut dem Aufrufer. Gibt es einen "
            "Aufrufer, bei dem dieses Vertrauen nicht gerechtfertigt ist? "
            "Hinweis: Der Ollama-Adapter ist nie gegen ein laufendes Ollama gelaufen, "
            "nur gegen aufgezeichnete Antworten."
        ),
        dateien=(
            "packages/contracts/jarvis_contracts/llm.py",
            "packages/core/jarvis_core/ports/llm.py",
            "packages/core/jarvis_core/providers/gateway.py",
            "packages/core/jarvis_core/agents/model_loop.py",
            "packages/providers/jarvis_providers/ollama.py",
            "tests/unit/test_model_loop.py",
        ),
    ),
)


BEHAUPTUNGEN = """\
## Prüfliste — meine Behauptungen als falsifizierbare Sätze

Jede Zeile ist eine Aussage aus den Statusberichten, so formuliert, dass sie
sich am Code widerlegen lässt. Wo ich selbst Zweifel habe, steht es dabei.

| # | Behauptung | Fundstelle | Portion |
|---|---|---|---|
| B1 | Ein Werkzeug wird nie ohne `ExecutionGrant` ausgeführt. Die Registry prüft die Herkunft **nominal** (`type(auth) is ExecutionGrant`), nicht strukturell. | `tools/registry.py:execute` | 01, 06 |
| B2 | Der Grant ist an Lauf **und** Nutzer gebunden; die Registry vergleicht beide gegen den Ausführungskontext. | `tools/registry.py:execute` | 01 |
| B3 | Die Taint-Prüfung steht vor der Berechtigungsprüfung, und die Reihenfolge ist bedeutungstragend. | `policy/engine.py:decide` | 01 |
| B4 | `authorize_allowed()` nimmt keine mitgebrachte Entscheidung entgegen, sondern fragt selbst. | `policy/approval.py` | 01 |
| B5 | `trigger` und `allowed_data_class` stammen ausschließlich aus dem persistierten `Run`. | `orchestrator/executor.py:_policy_request` | 02 |
| B6 | Über A→B→C ist die Rechtemenge die Schnittmenge aller Stufen; eine Stufe kann nur verengen. | `agents/chain.py:capability_ceiling` | 02 |
| B7 | Die Selbstauskunft eines Sub-Agenten kann Kontamination nur erhöhen, nie aufheben. | `agents/runtime.py:delegate` | 02 |
| B8 | Der Sitzungstoken existiert nur bei der Ausgabe; gespeichert wird ausschließlich sein Hash. | `auth/sessions.py`, `db/session_store.py` | 03, 05 |
| B9 | Eine Bestätigung ist nur mit verifizierter, nicht abgelaufener Sitzung einlösbar. | `policy/approval.py:respond` | 01, 03 |
| B16 | Eine Bestätigung erwirkt **genau einen** Ausführungsanspruch — auch unter Nebenläufigkeit. | `policy/approval.py:authorize_execution`, `db/approval_store.py:_CLAIM` | 01, 05 |
| B17 | Der Anspruch wird zuletzt erhoben; eine abgelehnte Prüfung verbrennt die Bestätigung nicht. | `policy/approval.py:authorize_execution` | 01 |
| B18 | `allowed_data_class` ist Pflicht; es gibt keinen Rückfall auf die Werkzeugklasse. | `policy/approval.py` | 01 |
| B19 | Die Proxy-Kette wird von rechts ausgewertet. | `deps.py:client_identifier` | 04 |
| B10 | Der Nutzer folgt aus dem Passkey; es gibt keinen Parameter, ihn zu benennen. | `auth/passkeys.py` | 03 |
| B11 | Das Rate-Limit ist nicht durch wechselnde Kennungen umgehbar (globale Stufe). | `limits/guard.py`, `limits/policy.py` | 03 |
| B12 | Kein Endpunkt übernimmt eine Identität aus Body, Query, Header oder Pfad. | `routes/auth.py`, `deps.py` | 04 |
| B13 | `X-Forwarded-For` wird nur bei konfiguriertem Proxy geglaubt. | `deps.py:client_identifier` | 04 |
| B14 | Jede Einmaligkeitszusage liegt in der `WHERE`-Klausel, nicht in einer Prüfung davor. | `db/*_store.py`, `rate_limit_store.py` | 05 |
| B15 | Zählen und Fristsetzen sind unteilbar (Lua). | `rate_limit_store.py` | 05 |
| B20 | Es gibt keinen Modellaufruf am Gateway vorbei; der Port kennt weder Datenklasse noch Taint und kann deshalb nichts über die eigene Zulassung entscheiden. | `providers/gateway.py`, `ports/llm.py` | 08 |
| B21 | P3 bleibt lokal, und zwar über **zwei** unabhängige Prüfungen — `accepts()` ist Konfiguration, `is_local` eine Eigenschaft des Deployments. | `providers/gateway.py:_zugelassen` | 08 |
| B22 | Unbekanntes Modell, fehlender Anbieter, überschrittene Datenklasse: jeder Fall endet in einer Ausnahme, nirgends in einem Rückfall auf ein verfügbares Modell. | `providers/gateway.py` | 08 |
| B23 | Eine Antwort erbt die Kontamination ihres Kontexts — nicht mehr (sonst wäre nach dem ersten Aufruf jeder Lauf kontaminiert) und nicht weniger. Der Adapter kann daran nichts ändern; das Gateway überschreibt in beide Richtungen. | `providers/gateway.py:_kontaminiert` | 08 |
| B24 | Die Modellschleife führt **nichts** aus. Jeder Vorschlag geht durch `AgentSession.call_tool()` und damit denselben Weg wie eine Absicht des Nutzers. | `agents/model_loop.py:act` | 08, 02 |
| B25 | Das Werkzeugangebot wird in **jeder** Runde neu berechnet; nach einem Werkzeug, das Fremdinhalt gelesen hat, fehlen die sendenden Werkzeuge im Schema. | `agents/model_loop.py:_angebot` | 08, 02 |
| B26 | Die Schleife bestätigt nicht selbst: Verlangt die Policy eine Bestätigung, endet die Runde mit `NEEDS_CONFIRMATION`. Und sie ist endlich (`max_iterations` plus Laufbudget). | `agents/model_loop.py:act` | 08 |
| B27 | Ein ausgestellter Grant erreicht den Handler höchstens einmal — auch als Kopie, aus einem anderen Prozess und nebenläufig. Der Verbrauch hängt an der `invocation_id`, nicht am Objekt, und steht als letzter Schritt vor dem Handler. | `tools/registry.py:execute`, `db/grant_store.py` | 01, 05 |
| B28 | Eine Registry ohne eingerichteten Grant-Verbrauch führt gar nichts aus. Es gibt keinen Vorgabewert, der ungesichert durchliefe. | `tools/registry.py:execute` | 01 |
| B29 | Der persistente Verbrauch ist **committed, bevor der Handler beginnt** — er liegt in einer eigenen Transaktion und nicht in der des Aufrufers. Ein Absturz nach dem Seiteneffekt und vor dem Commit des Requests gibt den Grant nicht frei. | `db/grant_store.py:consume` | 05 |
| B30 | Die Signatur erzwingt das: `PostgresGrantConsumer` nimmt eine `AsyncEngine`. Eine Request-`AsyncConnection` lässt sich nicht mehr übergeben — der Weg, der in den vierten Replay-Pfad führte, ist keine Frage der Sorgfalt mehr. | `db/grant_store.py:__init__` | 05 |
| B31 | Sieht der Verbrauch die Invokationszeile nicht — weil sie noch in einer offenen fremden Transaktion steht —, wird abgewiesen und nicht durchgewunken. | `db/grant_store.py`, `tests/integration/test_grant_consumption.py` | 05 |
| B32 | Das Werkzeugprotokoll committet jeden Eintrag für sich und übersteht damit den Rollback des Aufrufers. Es liegt nicht in der Transaktion dessen, worüber es Auskunft gibt. | `db/invocation_store.py` | 05 |
| B33 | Protokoll und Anspruch passen ohne Zutun des Tests zusammen: `record()` schreibt die Zeile, `consume()` löst den Anspruch daran ein, beide in eigenen Transaktionen. | `tests/integration/test_grant_consumption.py` | 05 |
| B34 | Ein Lauf wird nur fortgeschrieben, wenn er noch im erwarteten Status steht. Zehn nebenläufige Übergänge ergeben genau einen. | `db/run_store.py:save` | 05 |
| B35 | Der Rundlauf durch JSONB verliert nichts: `Decimal` kommt als `Decimal` zurück, nicht als Zeichenkette, und Zeitpunkte behalten ihre Zone. | `db/run_store.py` | 05 |
| B36 | Die Kette vor jeder Außenwirkung ist lückenlos festgeschrieben: Lauf, dann Protokoll, dann Anspruch — jedes Glied committed, bevor das nächste es braucht, keines an der Transaktion des Requests. | `db/run_store.py`, `db/invocation_store.py`, `db/grant_store.py` | 05 |
| B37 | `POST /runs` legt den Lauf für den angemeldeten Nutzer an. Eine `user_id` im Body wird nicht übernommen — geprüft wird die Zeile in der Datenbank, nicht die Antwort. | `routes/runs.py`, `tests/integration/test_http_runs.py` | 04 |
| B38 | Ein fremder Lauf und ein nicht existierender sind über HTTP nicht unterscheidbar: gleicher Status, gleicher Text. | `routes/runs.py:_eigener_lauf` | 04 |
| B39 | Jeder Endpunkt mit fremder Kennung ruft den Zugehörigkeitsprüfer auf, und keiner lädt daran vorbei. Beides am Quelltext erzwungen. | `tests/unit/test_http_boundary.py` | 04, 06 |
| B40 | Der Bestätigungskanal ist kein Feld des Requests, sondern eine Eigenschaft der Route. Ein Aufrufer kann `allows_channel()` nicht durch eine Behauptung umgehen. | `routes/actions.py` | 04 |
| B41 | Die Liste offener Bestätigungen gibt die Nonce nur für Bestätigungen der eigenen Sitzung heraus. | `routes/actions.py:list_actions` | 04 |
| B42 | Der Werkzeugkatalog der Anwendung steht im Anwendungscode statt nur im Testcode und ist mit `PostgresGrantConsumer` verdrahtet, nicht mit dem Testdoppelgänger. | `tools.py` | 04, 09 |
| B43 | `files.read` gibt nur Inhalte heraus, deren Pfad **nach Auflösung** unterhalb einer konfigurierten Wurzel liegt. Ein Symlink aus dem freigegebenen Ordner heraus besteht die Berechtigungsprüfung und scheitert am Adapter. | `integrations/localfs.py` | 09 |
| B44 | Nur reguläre Dateien werden gelesen. Verzeichnisse, FIFOs und Gerätedateien werden abgewiesen — auch innerhalb der Wurzeln. | `integrations/localfs.py` | 09 |
| B45 | Eine abgewiesene Anfrage verrät nicht, wohin der Pfad zeigte: Symlink-Ausbruch und Pfad-von-außerhalb ergeben dieselbe Meldung. | `integrations/localfs.py` | 09 |
| B46 | Der Lauf ist nach `files.read` kontaminiert. Eine Datei ist Fremdinhalt wie eine Mail; die sendenden Werkzeuge fallen danach aus dem Angebot. | `tools/builtin/files.py` | 09, 02 |
| B47 | Eine Berechtigung, deren gespeicherte Einschränkungen sich nicht zum Scope auslegen lassen, gilt als **nicht erteilt** — kein Rückfall auf die Basisklasse, der die Pfadgrenzen verlöre. | `db/permission_store.py`, `contracts:constraints_for` | 09, 05 |
| B48 | Die Pfadprüfung der Berechtigung lehnt `..` ab, statt es wegzurechnen, und akzeptiert nur absolute Pfade. | `contracts/permissions.py:FilesConstraints` | 09, 01 |
| B49 | Der Werkzeugschritt über HTTP entscheidet nichts selbst: Er löst den Lauf auf, prüft die Zugehörigkeit und übergibt an den Executor. Policy, Gate, Grant und Verbrauch liegen unverändert im Kern. | `routes/runs.py:execute_step` | 04 |
| B50 | Zwei parallele Schritte am selben Lauf ergeben einen Erfolg und einen Konflikt — das Fortschreiben läuft über den Statusvergleich. | `routes/runs.py:execute_step`, `db/run_store.py:save` | 04, 05 |
| B51 | Zugangsdaten sind auch innerhalb freigegebener Ordner gesperrt, geprüft auf dem genannten **und** dem aufgelösten Pfad. Ein Symlink mit harmlosem Namen wird erkannt. | `contracts:is_sensitive_filename`, `integrations/localfs.py` | 09 |
| B52 | Die Erkennung von Zugangsdaten im Inhalt **hebt** die Datenklasse und senkt sie nie. Ein Treffer bedeutet P3 und damit ausschließlich lokale Verarbeitung. | `core/policy/secrets.py` | 09, 01 |

### Was seit dem letzten Paket geschah

Das vorige Paket führte zu einem Befund, der die wichtigste Zusicherung des
Systems widerlegt hat. Er ist hier vollständig aufgeführt, weil die
Gegenprüfung der Reparatur jetzt der dringendste Prüfauftrag ist.

**Der Bypass.** `ExecutionAuthorization` war ein `Protocol`. Die Registry
prüfte Hash, Lauf und Nutzer — aber nicht die Herkunft des Objekts. Ein
`SimpleNamespace` mit passenden Attributen und korrekt berechnetem Hash führte
`mail.send` aus, ohne Policy Engine, ohne Approval Gateway, ohne Grant. Die
Invariante `policy-single-entry-point` stand dabei auf ENFORCED, und drei
grüne Tests deckten die Stelle ab: Sie prüften, dass ein Grant mit falschem
Hash, falschem Lauf oder falschem Nutzer abgewiesen wird — nur nicht, ob
überhaupt einer vorliegt.

**Zwei Strukturtests waren umgehbar.** Der Grant-Test suchte nur
`ExecutionGrant(...)` als `ast.Name`; `approval.ExecutionGrant(...)` kam
durch. Der HTTP-Test erkannte Endpunkte am wörtlichen Namen `router`; mit
`_alias = router` ließ sich ein ungeschützter Endpunkt einschmuggeln, der
`user_id` aus dem Body las.

**Was daraufhin geändert wurde** (Commit `04d983a`):

* `ToolRegistry.execute()` prüft `type(auth) is ExecutionGrant` — nominal und
  ausdrücklich nicht `isinstance`, weil eine Unterklasse `__init__`
  überschreiben könnte. Die Prüfung steht vor allen anderen.
* `ExecutionAuthorization` ist entfernt; an seiner Stelle steht der Grund.
* Beide Strukturtests sind gehärtet, beide Umgehungen nachgestellt und als
  abgewehrt belegt.
* Die Registry-Tests bauten Auth-Objekte nach und bestätigten damit den
  Bypass. Sie gehen jetzt durch `echter_grant()` — also durch Policy Engine
  und Approval Gateway.

**Die unangenehme Erkenntnis steht in `docs/18` §5:** Die Kennzahl blieb
während des gesamten Vorfalls bei 38/39. Der Metatest prüft, ob eine
Invariante einen Test hat — nicht, ob der Test das Richtige prüft.

### Und dann noch einmal, schwerer

Die zweite Prüfrunde fand einen weiteren Bypass, und er wog mehr. Nachgestellt
vor der Reparatur:

    Autorisierung 1: Grant erhalten, ausgeführt
    Autorisierung 2: Grant erhalten, ausgeführt
    Autorisierung 3: Grant erhalten, ausgeführt

    Eine Bestätigung -> 3 Mails versendet

Die Nonce sichert den **Bestätigungsschritt**. Sie ist atomar, gegen
Nebenläufigkeit geprüft und war nie das Problem. Was fehlte, war ein Anspruch
auf die **Ausführung**: `authorize_execution()` prüfte nur, *dass* bestätigt
wurde. `approval-nonce-single-use` stand auf ENFORCED — mit der Begründung,
sonst ließe sich eine bestätigte Aktion beliebig oft ausführen.

Ein zweiter Weg lief über den Orchestrator: `resume_after_approval()` prüft
`state.awaiting_action_id` und löscht sie erst im *neuen* Run-Objekt; zwei
parallele Aufrufe mit demselben Run bestehen beide die Vorprüfung.

Behoben (Commit `fc5b94f`) durch `pending_actions.executed_at` und
`claim_execution()` als bedingtes UPDATE — dieselbe Bauart wie der
Nonce-Verbrauch. Der Anspruch wird als **letzter** Schritt erhoben, nach Hash
und Policy-Recheck: Stünde er davor, könnte ein Angreifer fremde
Bestätigungen entwerten, ohne sie einlösen zu können.

Die Semantik ist ausdrücklich **höchstens einmal**. Stürzt der Prozess
zwischen Anspruch und Werkzeugaufruf ab, gilt die Bestätigung als verbraucht.
Für Aktionen mit Außenwirkung ist das die richtige Richtung — eine Mail, die
vielleicht nicht hinausging, kann der Nutzer erneut senden; eine, die zweimal
hinausging, holt niemand zurück. **Das ist eine Entscheidung, keine
Selbstverständlichkeit, und sie gehört geprüft.**

Drei weitere Befunde derselben Runde, alle behoben (`dfecbb9`):

* `allowed_data_class` war optional und fiel auf `spec.data_class` zurück —
  auf die Klasse des Werkzeugs, das geprüft werden soll. Jetzt Pflichtparameter.
* `X-Forwarded-For` wurde von links gelesen. Jetzt von rechts, mit
  Überspringen bekannter Proxies.
* Der HTTP-Strukturtest scannte nur `routes/`; `/health` in `main.py` war von
  keinem Test erfasst. Jetzt die ganze API-Schicht, plus Fehlschlag bei
  `add_api_route()`.

**Zweimal dasselbe Muster:** Invariante auf ENFORCED, Tests grün, falsche
Frage geprüft. Beide Male gefunden von jemandem mit dem Quelltext in der Hand,
der etwas ausprobiert hat.

### Und ein drittes Mal, an derselben Stelle eine Etage tiefer

Die dritte Prüfrunde fand den nächsten Replay-Pfad, und das Muster ist
inzwischen unverkennbar. Gemeldet wurde: Ein echter `ExecutionGrant` lässt
sich mehrfach an `ToolRegistry.execute()` übergeben. Nachgemessen, auf beiden
Wegen — der Prüfer hatte über `authorize_allowed()` reproduziert, also den
Pfad ohne Bestätigung:

    Pfad A (ohne Bestätigung): 2 seriell, 10 parallel
      — dort ist ein Grant allerdings ohnehin beliebig oft neu zu bekommen.
    Pfad B (nach echter Bestätigung): 2 seriell, 12 nach zehn parallelen.
      — der zweite authorize_execution() wurde korrekt abgewiesen. Der Claim
        wirkt; er sichert nur die Ausstellung, nicht die Verwendung.

Der Prüfer hatte recht, und der Befund reichte weiter als sein Nachweis:
Betroffen war auch der bestätigte Pfad, den er nicht getestet hatte.

**Dreimal dasselbe Muster.** Erst hing die Einmaligkeit an der Nonce statt an
der Ausführung. Dann an der Autorisierung statt am Aufruf. Jetzt an der
Ausstellung statt an der Verwendung. Jedes Mal einen Schritt zu früh, jedes
Mal mit grüner Suite, jedes Mal von außen gefunden.

Behoben durch einen Verbrauch an der `invocation_id`, als letzter Schritt vor
dem Handler (`GrantConsumer`, `InProcessGrants`, `PostgresGrantConsumer`). Die
vier Regressionstests entstanden **vor** der Reparatur und schlugen alle fehl;
dazu drei Integrationstests über getrennte Datenbankverbindungen.

Der dringendste Prüfauftrag dieser Runde ist damit: **Ist es diesmal der
richtige Schritt?** Die Frage, die dreimal falsch beantwortet wurde, lautet
nicht „wird geprüft?", sondern „wo entsteht die Wirkung?".

### Und die vierte Runde hat genau dort noch etwas gefunden

Die Antwort auf den Prüfauftrag oben lautet: der Schritt stimmte, der
Zeitpunkt nicht. `PostgresGrantConsumer` schrieb `consumed_at` auf der
Verbindung des Aufrufers — also in dieselbe offene Transaktion, in der danach
der Handler nach außen wirkte:

    consume()  → UPDATE consumed_at     (nicht committed)
    Handler    → Mail ist verschickt    (nicht zurückholbar)
    Absturz vor dem Commit
    PostgreSQL rollt zurück             → consumed_at wieder NULL
    Retry legt denselben Grant vor      → die Mail geht ein zweites Mal hinaus

Der Prüfer konnte das nicht ausführen — in seiner Umgebung lief keine
Datenbank, alle Integrationstests wurden übersprungen. Er hat es deshalb als
begründete Hypothese gemeldet und ausdrücklich nicht als Befund. Mit
laufendem PostgreSQL war es in einem Testlauf reproduziert: `consumed_at` nach
dem Rollback wieder `NULL`, der Seiteneffekt eingetreten.

**Warum die drei Integrationstests das nicht sahen:** Jeder verließ seinen
`begin()`-Block regulär und committete damit. Sie belegten den geordneten
Ausgang — Nebenläufigkeit, Verbindungsgrenzen — und keiner den ungeordneten.

Behoben, indem der Anspruch in einer eigenen Transaktion committet, bevor der
Handler beginnt. Der Verbraucher nimmt dafür eine `AsyncEngine` statt einer
Verbindung; der unsichere Weg ist damit nicht mehr wählbar.

**Die Lehre, und sie ist neu:** Atomar und dauerhaft sind zwei Zusagen. Die
erste trägt das bedingte UPDATE. Die zweite hängt daran, wem die Transaktion
gehört — und das prüft kein Nebenläufigkeitstest. Zur Frage „wo entsteht die
Wirkung?" gehört deshalb: **„und wem gehört die Transaktion, in der der
Anspruch steht?"**

**Die Kehrseite ist inzwischen mitbehoben.** Ein Anspruch in eigener
Transaktion sieht nichts, was der Aufrufer noch nicht committed hat — und das
Werkzeugprotokoll lag genau dort. Es committet jetzt ebenfalls für sich
(B32), was die Zusage seines eigenen Modulkopfs erst einlöst: Ein
Protokolleintrag, der mit der Transaktion des Aufrufers zurückrollt, fehlt
genau dann, wenn man ihn liest. `test_das_protokoll_traegt_den_anspruch_ohne_zutun_des_tests`
prüft beide Teile zusammen (B33).

Zwei Nebenwirkungen, beide erwünscht: Die Request-Transaktion fasst
`tool_invocations` nicht mehr an, womit die Verklemmungsgefahr zwischen
Anspruch und Request entfällt. Und `ON CONFLICT DO NOTHING` beim Insert greift
erstmals wirklich — vorher verschwand die Zeile mit der abgebrochenen
Transaktion, sodass eine Wiederaufnahme sie nie antraf.

Der Prüfauftrag dieser Runde: **Die Reihenfolge, die daraus folgt.** Der Lauf
muss committed sein, bevor protokolliert wird (Fremdschlüssel auf `runs`), und
protokolliert, bevor der Anspruch greift. Die ersten beiden Glieder scheitern
laut statt still. Zu prüfen ist, ob diese Kette irgendwo anders herum
gedreht werden kann — und ob ein Pfad existiert, auf dem sie statt der
Ausführung die Zusicherung kostet.

### Neu seit der zweiten Runde: der Sprachmodell-Block (Portion 08)

Seit dem letzten Paket ist die Schicht dazugekommen, auf die alles andere
hinauslief: Model Gateway, LLM-Port, Ollama-Adapter und die Modellschleife.
**Sie hat noch keine externe Prüfung gesehen.** Wer nur eine Portion lesen
kann, sollte diese nehmen.

Beim Bauen sind mir zwei eigene Fehler aufgefallen, beide vor dem Commit
behoben — sie stehen hier, weil sie zeigen, wo die Stolperstellen dieser
Schicht liegen:

* **„Jede Modellantwort ist Fremdinhalt"** war die erste Regel. Sie ist
  bequem, streng und falsch: Nach dem ersten Modellaufruf wäre *jeder* Lauf
  kontaminiert und `mail.send` nie wieder möglich — genau der Widerspruch aus
  V1.0, den das Sanitization-Gate aufgelöst hat. Jetzt erbt die Antwort, was
  im Kontext stand.
* **`AgentSession.tools` war ein eingefrorenes Set.** Damit galt die Zusage
  „das Angebot verengt sich mit der Kontamination" nicht — die Schleife hätte
  in Runde 3 mit dem Angebot aus Runde 1 gearbeitet. Die Werkzeugmenge wird
  jetzt bei jedem Zugriff neu berechnet.

Beide Male war die Beschreibung richtig und der Code nicht. Das ist dasselbe
Muster wie bei den beiden Bypässen, nur diesmal früher bemerkt.

### Wo ich die Prüfung am dringendsten für nötig halte

0. **Den Modellblock überhaupt erst einmal ansehen** (Portion 08). Er ist
   ungeprüft, und er ist die Stelle, an der ein Modell erstmals etwas
   auslösen kann. Die konkrete Frage, bei der ich selbst unsicher bin: Das
   Gateway nimmt `data_class` als Parameter entgegen und kann nicht erzwingen,
   dass er aus dem persistierten Lauf stammt. Bei den Werkzeugen war genau
   diese Konstruktion — der Aufrufer bringt seine eigene Obergrenze mit — der
   Befund `allowed_data_class`. Ist sie hier aus einem guten Grund vertretbar
   oder aus Gewohnheit stehengeblieben?

1. **Den Ausführungsanspruch gegenprüfen** (Portion 01 und 05). Der Anspruch
   ist ein bedingtes UPDATE auf `pending_actions.executed_at`. Gibt es einen
   Weg daran vorbei? Ein zweiter Pfad zu einem Grant, der `claim_execution()`
   nicht durchläuft; ein Lauf, der die Bestätigung erneut anlegt statt sie
   einzulösen; eine Wiederaufnahme nach Neustart, die den Anspruch nicht
   sieht. Und die offene Entwurfsfrage: Ist **höchstens einmal** hier richtig,
   oder braucht es einen Weg, einen Anspruch nach einem Absturz vor dem
   Werkzeugaufruf freizugeben?

2. **Die Reparatur des ersten Bypasses gegenprüfen** (Portion 01 und 06). Die
   nominale Prüfung schließt den bekannten Weg. Gibt es einen anderen? Ein
   Grant über `copy`/`pickle`/`__reduce__`; ein echter, für einen anderen
   Zweck erzeugter Grant; ein Weg, `ExecutionGrant` neu zu binden, bevor die
   Registry ihn lokal importiert.

3. **Die gehärteten Strukturtests erneut angreifen** (Portion 06). Sie waren
   schon zweimal umgehbar, und die Härtung folgt wieder Mustern. `add_api_route`
   und Routen außerhalb von `routes/` sind inzwischen abgedeckt — was bleibt?
   Ein Dekorator aus einer Hilfsfunktion, eine per `exec` erzeugte Route, ein
   Router aus einem Paket außerhalb von `jarvis_api`.

4. **`client_identifier()` hinter einem Reverse Proxy.** Ohne gesetztes
   `TRUSTED_PROXIES` ist `request.client.host` die Adresse des Proxys — für
   *alle* Nutzer dieselbe. Die Installation teilt sich dann einen Zähler und
   sperrt sich nach zehn Anmeldeversuchen pro Minute selbst aus. Die sichere
   Voreinstellung hat also einen Betriebspreis, und der ist bislang nur in
   `.env.example` erwähnt, nicht im Deployment-Dokument. Zu prüfen: Sollte die
   Anwendung diesen Zustand beim Start erkennen und melden, statt ihn
   auszusitzen?

   *(Ein zuvor hier vermuteter Mangel hat sich nicht bestätigt: Die
   Fehlerbilder der Anmeldung unterscheiden sich nur zwischen Formfehlern
   (422/400) und inhaltlichen Fehlschlägen (einheitlich 401). Das ist kein
   Orakel über Kontoexistenz — nachgemessen, nicht angenommen.)*

5. **Die Ausnahmeliste `OEFFENTLICH`** in `test_http_boundary.py`. Sie ist die
   Stelle, an der sich eine fehlende Sitzungsprüfung legalisieren lässt, indem
   man einen Namen einträgt. Der Test zwingt zur sichtbaren Änderung, aber
   nicht zur Begründung.
"""


def _commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=REPO, text=True
        ).strip()
    except Exception:  # pragma: no cover - kein Git
        return "unbekannt"


def _sprache(pfad: str) -> str:
    return "python" if pfad.endswith(".py") else "text"


def schreibe_portion(portion: Portion, commit: str) -> tuple[Path, int]:
    zeilen = [
        f"# Prüfpaket {portion.nummer} — {portion.titel}",
        "",
        f"> JARVIS, Commit `{commit}`. Erzeugt mit `scripts/pruefpaket.py`.",
        "",
        "**Prüfauftrag:** " + portion.auftrag,
        "",
        "---",
        "",
    ]
    gesamt = 0
    for pfad in portion.dateien:
        datei = REPO / pfad
        if not datei.exists():
            zeilen += [f"## `{pfad}`", "", "*(fehlt)*", ""]
            continue
        inhalt = datei.read_text(encoding="utf-8")
        gesamt += inhalt.count("\n")
        zeilen += [
            f"## `{pfad}`",
            "",
            f"```{_sprache(pfad)}",
            inhalt.rstrip(),
            "```",
            "",
        ]
    ziel = (
        OUT / f"{portion.nummer}-{portion.titel.split('—')[0].strip().lower().replace(' ', '-')}.md"
    )
    ziel.write_text("\n".join(zeilen), encoding="utf-8")
    return ziel, gesamt


def schreibe_anleitung(commit: str, uebersicht: list[tuple[str, str, int]]) -> Path:
    zeilen = [
        "# JARVIS — Prüfpaket",
        "",
        f"> Commit `{commit}`. Erzeugt mit `scripts/pruefpaket.py`.",
        "",
        "Dieses Paket enthält den sicherheitskritischen Quelltext im Volltext.",
        "Es ersetzt die bisherige Bewertung von Statusberichten: Wer nur die",
        "Beschreibung liest, kann einen Fehler in der Beschreibung nicht von einem",
        "Fehler im Code unterscheiden.",
        "",
        "## Portionen",
        "",
        "| Datei | Inhalt | Zeilen |",
        "|---|---|---|",
    ]
    for name, titel, zahl in uebersicht:
        zeilen.append(f"| `{name}` | {titel} | {zahl} |")
    zeilen += [
        "",
        "Die Portionen sind unabhängig lesbar. Wer nur eine prüfen kann, sollte",
        "**08 (Sprachmodelle)** oder **06 (Strukturtests)** nehmen — die jüngste,",
        "noch ungeprüfte Schicht und die tragendste.",
        "",
        "---",
        "",
        BEHAUPTUNGEN,
        "",
        "---",
        "",
        "## Was im Paket fehlt",
        "",
        "* **Verträge** (`packages/contracts/`) außer `auth.py` und `llm.py` — 12 Module,",
        "  überwiegend Datenstrukturen. Bei Bedarf einzeln nachreichbar.",
        "* **Migrationen** und das Datenmodell (`db/models.py`, ~950 Zeilen).",
        "* **Die übrigen Testsuiten** — Policy, Taint, Approval-Primitive, Klassifikation,",
        "  Planer. Zusammen etwa 2.500 Zeilen.",
        "",
        "Das vollständige Repository ist die bessere Grundlage, wo sie möglich ist:",
        "",
        "```bash",
        "git -C ~/jarvis bundle create /tmp/jarvis.bundle --all   # ein Datei-Abzug",
        "git clone /tmp/jarvis.bundle jarvis                      # beim Prüfer",
        "```",
        "",
        "## Wie der Stand selbst nachprüfbar ist",
        "",
        "```bash",
        "cd ~/jarvis",
        "docker compose up -d                                # Postgres und Redis",
        "make gate                                           # alles unten in einem Lauf",
        "```",
        "",
        "Einzeln, wenn die Zahlen interessieren:",
        "",
        "```bash",
        "uv run pytest -q                                    # 766 Tests",
        "uv run pytest -m security -q                        # 458 blockierende",
        "uv run pytest tests/unit/test_invariant_coverage.py -q -s   # 42/43",
        "uv run mypy packages apps/api                       # strict, 85 Dateien",
        "uv run ruff check . && uv run ruff format --check .",
        "```",
        "",
        "**Ein Hinweis, der beim letzten Mal Zeit gekostet hat:** Ohne laufende",
        "Dienste überspringt `pytest` die Integrationstests und meldet ein sattes",
        "Grün — einschließlich der Tests, die Nebenläufigkeit belegen sollen. Ein",
        "Prüfer hat genau das erlebt: 702 Tests, 0 Fehler, 110 übersprungen. Der",
        "Schalter `JARVIS_REQUIRE_SERVICES=1` macht das Überspringen zum Fehler;",
        "`make gate` und `make proof` setzen ihn, in CI ist er gesetzt. Eine grüne",
        "Ausgabe ohne ihn sagt weniger, als sie aussieht.",
    ]
    ziel = OUT / "00-anleitung.md"
    ziel.write_text("\n".join(zeilen), encoding="utf-8")
    return ziel


def main() -> int:
    OUT.mkdir(exist_ok=True)
    commit = _commit()
    uebersicht: list[tuple[str, str, int]] = []

    print(f"Erzeuge Prüfpaket für Commit {commit} …")
    for portion in PORTIONEN:
        ziel, zeilen = schreibe_portion(portion, commit)
        uebersicht.append((ziel.name, portion.titel, zeilen))
        print(f"  · {ziel.name}  ({zeilen} Zeilen Quelltext)")

    anleitung = schreibe_anleitung(commit, uebersicht)
    print(f"  · {anleitung.name}")
    print(f"\n✓ {len(PORTIONEN) + 1} Dateien in {OUT.relative_to(REPO)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
