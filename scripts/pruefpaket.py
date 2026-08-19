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
            "decide() an einer Stelle vertauschbar, ohne dass ein Test bricht?"
        ),
        dateien=(
            "packages/core/jarvis_core/policy/engine.py",
            "packages/core/jarvis_core/policy/approval.py",
            "packages/core/jarvis_core/tools/registry.py",
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
            "irgendwo ungeprüft verwendet?"
        ),
        dateien=(
            "apps/api/jarvis_api/deps.py",
            "apps/api/jarvis_api/routes/auth.py",
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
            "Zähler ohne Frist entstehen?"
        ),
        dateien=(
            "apps/api/jarvis_api/db/approval_store.py",
            "apps/api/jarvis_api/db/session_store.py",
            "apps/api/jarvis_api/db/webauthn_store.py",
            "apps/api/jarvis_api/db/invocation_store.py",
            "apps/api/jarvis_api/rate_limit_store.py",
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

### Wo ich die Prüfung am dringendsten für nötig halte

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
        "**04 (HTTP-Grenze)** oder **06 (Strukturtests)** nehmen — die jüngste und",
        "die tragendste Schicht.",
        "",
        "---",
        "",
        BEHAUPTUNGEN,
        "",
        "---",
        "",
        "## Was im Paket fehlt",
        "",
        "* **Verträge** (`packages/contracts/`) außer `auth.py` — 12 Module, überwiegend",
        "  Datenstrukturen. Bei Bedarf einzeln nachreichbar.",
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
        "uv run pytest -q                                    # 702 Tests",
        "uv run pytest -m security -q                        # 405 blockierende",
        "uv run pytest tests/unit/test_invariant_coverage.py -q -s   # 39/40",
        "uv run mypy packages apps/api                       # strict, 73 Dateien",
        "uv run ruff check . && uv run ruff format --check .",
        "```",
        "",
        "Die Integrationstests brauchen Postgres und Redis (`docker compose up -d`).",
        "Ohne sie überspringt die Suite still — das ist beim Nachprüfen zu beachten:",
        "Eine grüne Ausgabe ohne laufende Dienste sagt weniger, als sie aussieht.",
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
