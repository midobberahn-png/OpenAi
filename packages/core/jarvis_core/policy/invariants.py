"""Sicherheits-Invarianten als Code.

Testabdeckung ist ab hier die falsche Leitkennzahl. 96 % sagen nichts darüber,
ob der Ablauf ``tainted → Bestätigung → veränderter Payload → Ausführung``
abgewehrt wird — fünfzig zusätzliche Tests für Getter heben die Zahl, nicht
die Sicherheit.

Stattdessen: **Security Invariant Coverage**. Jede Invariante ist hier
benannt; Tests binden sich per ``@pytest.mark.invariant("<id>")`` daran. Ein
Meta-Test schlägt fehl, sobald eine Invariante ohne Test dasteht oder ein
Test sich auf eine unbekannte Invariante beruft.

Damit lässt sich die Kennzahl nicht nachträglich passend machen: Eine
Invariante zu streichen ist eine sichtbare Änderung an dieser Datei.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

__all__ = ["INVARIANTS", "Invariant", "InvariantStatus", "invariant_ids"]


class InvariantStatus(StrEnum):
    ENFORCED = "enforced"
    """Durchgesetzt und durch mindestens einen Test belegt."""

    PLANNED = "planned"
    """Beschlossen, aber der Kontrollpunkt existiert noch nicht.

    Ausdrücklich geführt, damit nicht der Eindruck entsteht, etwas sei
    abgesichert, bevor es das ist.
    """


class Invariant(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    statement: str
    """Was gilt — als prüfbare Aussage, nicht als Absichtserklärung."""

    why: str
    """Was passiert, wenn die Invariante fällt."""

    status: InvariantStatus
    component: str


INVARIANTS: tuple[Invariant, ...] = (
    # -- Taint ----------------------------------------------------------
    Invariant(
        id="taint-monotonic",
        title="Kontamination ist monoton",
        statement="Ein Lauf, der einmal TAINTED ist, wird durch keinen Vorgang wieder CLEAN.",
        why="Andernfalls genügte ein beliebiges Werkzeug als Waschmaschine für den Zustand.",
        status=InvariantStatus.ENFORCED,
        component="contracts.classification",
    ),
    Invariant(
        id="taint-no-implicit-clearing",
        title="Keine stillschweigende Sanierung",
        statement=(
            "Kontamination wird ausschließlich über das Sanitization-Gate aufgehoben — "
            "und dort nur durch eine Nutzerbestätigung, nie durch Programmfluss."
        ),
        why="Ein impliziter Pfad zurück nach CLEAN wäre die Umgehung des gesamten Schutzes.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="taint-precedes-permission",
        title="Taint wird vor der Berechtigung geprüft",
        statement=("Eine erteilte Berechtigung schaltet in einem kontaminierten Lauf nichts frei."),
        why=(
            "Bei umgekehrter Reihenfolge wäre genau der Fall offen, auf den es ankommt: "
            "Vollberechtigung für mail.send nach dem Lesen einer präparierten Mail."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="taint-cross-run-isolation",
        title="Kontamination überschreitet keine Laufgrenze",
        statement="Ein sanierter Lauf startet sauber und ohne Kontext des Herkunftslaufs.",
        why="Sonst wäre der saubere Lauf nur eine Umbenennung des kontaminierten.",
        status=InvariantStatus.ENFORCED,
        component="contracts.runs",
    ),
    Invariant(
        id="taint-memory-quarantine",
        title="Gedächtnis ist kein zeitversetzter Kanal",
        statement=(
            "Gedächtniskandidaten aus kontaminierten Läufen werden nie automatisch "
            "übernommen — unabhängig von der Konfidenz."
        ),
        why=(
            "Die Taint-Sperre gilt nur für die Dauer eines Laufs. Ein geschriebener "
            "„Fakt“ wirkt Wochen später in einem sauberen Lauf, vorbei an jeder Sperre."
        ),
        status=InvariantStatus.ENFORCED,
        component="contracts.memory",
    ),
    # -- Payload und Außenwirkung ---------------------------------------
    Invariant(
        id="payload-outbound-classification",
        title="Außenwirkung schlägt Struktur",
        statement=(
            "Ein Aufruf mit belegtem Empfänger- oder Teilnehmerfeld gilt als nicht "
            "prüfbar, auch wenn das Werkzeug statisch als strukturiert eingestuft ist."
        ),
        why=(
            "Ein Kalendereintrag mit eingeschmuggeltem Teilnehmer verschickt eine "
            "Einladung — das ist Versand, nicht Notiz."
        ),
        status=InvariantStatus.ENFORCED,
        component="contracts.tools",
    ),
    Invariant(
        id="payload-freeform-never-sanitizable",
        title="Freitext mit Außenwirkung wird nie saniert",
        statement="Payloads mit Freitext-Außenwirkung sind in kontaminierten Läufen gesperrt.",
        why=(
            "Eine um eine Ziffer veränderte IBAN im Fließtext übersieht auch ein "
            "aufmerksamer Leser; die Bestätigung wäre dort keine echte Prüfung."
        ),
        status=InvariantStatus.ENFORCED,
        component="contracts.tools",
    ),
    Invariant(
        id="payload-immutable-after-approval",
        title="Bestätigter Payload ist unveränderlich",
        statement=("Was ausgeführt wird, ist byte-identisch mit dem, was in der Vorschau stand."),
        why="Sonst bestätigt der Nutzer A und das System führt B aus.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.approval",
    ),
    Invariant(
        id="approval-bound-to-payload-hash",
        title="Bestätigung ist an den Payload gebunden",
        statement=(
            "Eine Bestätigung gilt nur für den Payload, dessen Hash bei der Anfrage "
            "festgehalten wurde."
        ),
        why="Andernfalls ließe sich eine Bestätigung auf einen anderen Aufruf übertragen.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.approval",
    ),
    Invariant(
        id="approval-toctou-protected",
        title="Kein Zeitfenster zwischen Prüfung und Ausführung",
        statement=(
            "Unmittelbar vor der Ausführung werden Payload-Hash und Policy erneut "
            "geprüft; zwischenzeitlich entzogene Rechte greifen sofort."
        ),
        why=(
            "Eine Bestätigung von 14:00 darf nicht um 04:00 ausgeführt werden, und ein "
            "entzogenes Recht muss ausstehende Bestätigungen entwerten."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.policy.approval",
    ),
    Invariant(
        id="approval-nonce-single-use",
        title="Bestätigungen sind einmalig",
        statement="Eine Nonce lässt sich genau einmal einlösen, auch unter Nebenläufigkeit.",
        why="Sonst ließe sich eine einmal bestätigte Aktion beliebig oft ausführen.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.approval",
    ),
    Invariant(
        id="approval-not-forgeable-by-model",
        title="Ein Modell kann keine Bestätigung erzeugen",
        statement=(
            "Bestätigungen entstehen ausschließlich aus einer Nutzerinteraktion; "
            "Modellausgaben und Werkzeugargumente haben keinen Einfluss darauf."
        ),
        why="Andernfalls schriebe das Modell sich seine Freigaben selbst.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="approval-channel-bound",
        title="Bestätigt wird dort, wo angezeigt wurde",
        statement=(
            "Eine Bestätigung ist an Nutzer, Sitzung und Anzeigekanal gebunden und "
            "lässt sich nicht über einen anderen Kanal oder eine andere Sitzung einlösen."
        ),
        why=(
            "Kein kryptografischer Schutz — den trägt die Nonce —, sondern die "
            "Absicherung informierter Zustimmung: Eine Geste aus vier Metern Entfernung, "
            "die einen ungelesenen Dialog freigibt, ist genau die Bestätigungsmüdigkeit "
            "aus Risiko R5. Die Sitzungsbindung begrenzt zusätzlich den Schaden eines "
            "gestohlenen Sitzungstokens."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.policy.approval",
    ),
    Invariant(
        id="approval-critical-ui-only",
        title="Irreversibles wird nur in der Oberfläche bestätigt",
        statement="CRITICAL-Aktionen akzeptieren keine Sprach- oder Gestenbestätigung.",
        why="Spracherkennung ist zu fehleranfällig — und aus einem anderen Raum auslösbar.",
        status=InvariantStatus.ENFORCED,
        component="contracts.permissions",
    ),
    # -- Berechtigungen und Agenten -------------------------------------
    Invariant(
        id="policy-single-entry-point",
        title="Die Policy Engine ist der einzige Weg",
        statement=(
            "Kein Werkzeug wird ohne Policy-Entscheidung ausgeführt: Die Registry "
            "gibt keinen Handler heraus und verlangt eine ExecutionAuthorization."
        ),
        why="Ein zweiter Pfad wäre der Pfad, den niemand prüft.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="grant-bound-to-run",
        title="Eine Erlaubnis gilt für einen Aufruf in einem Lauf",
        statement=(
            "Die Registry führt einen Grant nur aus, wenn Lauf und Nutzer des Grants dem "
            "Kontext entsprechen, in dem tatsächlich ausgeführt wird."
        ),
        why=(
            "Ohne diese Bindung wäre ein gültiger Grant aus Lauf A in Lauf B verwendbar — "
            "Werkzeugname und Argumente passen dort weiterhin, und der Hash stimmt. Die "
            "Bindung hinge dann allein daran, dass niemand einen Grant über eine "
            "Laufgrenze trägt; das ist eine Hoffnung, keine Zusicherung."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.tools.registry",
    ),
    Invariant(
        id="data-class-monotonic-within-run",
        title="Die Datenklasse eines Laufs steigt nur",
        statement=(
            "Innerhalb eines Laufs wird die Datenklasse nie gesenkt, und die Obergrenze "
            "eines Aufrufs stammt aus der Routing-Entscheidung, nicht vom Aufrufer."
        ),
        why=(
            "Ein Lauf, der P2-Daten gesehen hat, hält sie im Kontext — eine harmlose "
            "Folgeaktion macht ihn nicht wieder öffentlich. Und ein Aufrufer, der seine "
            "eigene Obergrenze bestimmt, hat keine: Ein frei übergebenes "
            "allowed_data_class ließe P3-Werkzeuge in einem Lauf zu, der dafür nie "
            "geroutet wurde."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.orchestrator",
    ),
    Invariant(
        id="policy-not-overridable-by-content",
        title="Inhalte ändern keine Policy",
        statement=(
            "Werkzeugargumente und Fremdinhalte beeinflussen die Entscheidung nicht — "
            "auch nicht bei Feldern wie „user_confirmed“."
        ),
        why="Sonst wäre jede eingehende Mail ein Berechtigungsantrag.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="agent-no-capability-escalation",
        title="Delegation erzeugt keine Rechte",
        statement=(
            "Ein Sub-Agent erhält höchstens die Schnittmenge aus eigener Whitelist und "
            "Nutzerrechten; ein anderer Agent als Anfragender ändert daran nichts."
        ),
        why="Andernfalls wäre die Agentenkette der Umweg um jede Beschränkung.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="tool-risk-not-self-declared",
        title="Werkzeuge stufen sich nicht selbst herab",
        statement="Ein Plugin kann seine Risikoklasse nicht senken; der Kern nimmt das Maximum.",
        why="Sonst hebelte ein einziges bösartiges Manifest die Klassifikation aus.",
        status=InvariantStatus.ENFORCED,
        component="contracts.tools",
    ),
    Invariant(
        id="tool-no-silent-override",
        title="Kein stiller Namenstausch",
        statement="Ein bereits registriertes Werkzeug lässt sich nicht überschreiben.",
        why="Ein Überschreiben tauschte die Berechtigungen hinter demselben Namen aus.",
        status=InvariantStatus.ENFORCED,
        component="core.tools.registry",
    ),
    Invariant(
        id="data-class-hard-filter",
        title="Datenklassifikation ist ein hartes Filter",
        statement="Ein Kontext, der eine Klasse nicht zulässt, führt kein Werkzeug dieser Klasse aus.",
        why="P3-Daten dürfen unter keinen Umständen an einen Cloud-Anbieter gelangen.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="unattended-runs-are-stricter",
        title="Unbeaufsichtigte Läufe sind strenger",
        statement="Automationen bestätigen schreibende Aktionen, auch wenn das Recht erteilt ist.",
        why="Nachts ist keine Instanz anwesend, die eine Fehlentscheidung bemerkt.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    # -- Orchestrierung (noch offen, Punkt 9) ---------------------------
    Invariant(
        id="orchestrator-consumes-decisions",
        title="Der Orchestrator entscheidet nichts über Sicherheit",
        statement=(
            "Der Orchestrator fragt die Policy Engine und das Ausführungs-Gate; er "
            "bildet keine eigene Meinung darüber, ob etwas erlaubt ist."
        ),
        why=(
            "Sobald der Orchestrator „das ist wahrscheinlich sicher“ oder „das wurde "
            "gerade bestätigt“ selbst beurteilt, gibt es zwei Wahrheiten über "
            "Berechtigungen — und die zweite prüft niemand. Er muss Konsument von "
            "Sicherheitsentscheidungen sein, nicht ihr Urheber."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.orchestrator",
    ),
    Invariant(
        id="agent-chain-preserves-capability-binding",
        title="Delegationsketten erweitern keine Rechte",
        statement=(
            "Über beliebig viele Agentenstufen hinweg bleibt die Rechtemenge die "
            "Schnittmenge aller beteiligten Whitelists mit den Nutzerrechten."
        ),
        why=(
            "Die bisherige Prüfung deckt eine Stufe ab. Bei A → B → C darf C nicht "
            "die Fähigkeiten von B erben, nur weil B ihn aufgerufen hat — sonst ist "
            "die Kette der Umweg um jede Beschränkung."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.agents",
    ),
    Invariant(
        id="agent-chain-propagates-taint",
        title="Kontamination wandert durch die ganze Kette",
        statement=(
            "Liest ein Agent auf beliebiger Stufe Fremdinhalt, gilt der gesamte "
            "übergeordnete Lauf als kontaminiert."
        ),
        why=(
            "Andernfalls genügte eine Zwischenstufe als Waschmaschine: Agent B liest "
            "die Mail, meldet ein „sauberes“ Ergebnis nach oben, und A sendet."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.agents",
    ),
    # -- Audit ----------------------------------------------------------
    Invariant(
        id="audit-append-only",
        title="Das Audit-Log ist unveränderlich",
        statement="UPDATE und DELETE werden auf Datenbankebene abgelehnt.",
        why="Wer die Anwendung kompromittiert, soll seine Spuren nicht beseitigen können.",
        status=InvariantStatus.ENFORCED,
        component="db.audit_log",
    ),
    Invariant(
        id="audit-tamper-evident",
        title="Manipulation ist erkennbar",
        statement="Änderung, Löschung oder Umsortierung von Einträgen bricht die Hash-Kette.",
        why="Unveränderlichkeit ohne Nachweis wäre nur eine Behauptung.",
        status=InvariantStatus.ENFORCED,
        component="core.audit.chain",
    ),
    Invariant(
        id="audit-survives-erasure",
        title="Löschpflicht und Kette schließen sich nicht aus",
        statement=(
            "Die Pseudonymisierung eines Nutzers lässt die Hash-Kette unversehrt, weil "
            "user_id nicht gehasht wird."
        ),
        why=(
            "Wären beide Anforderungen unvereinbar, müsste eine von ihnen aufgegeben "
            "werden — die Löschpflicht oder die Unveränderlichkeit."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.audit.chain",
    ),
    # -- Schichtung -----------------------------------------------------
    Invariant(
        id="layering-contracts-independent",
        title="Verträge hängen von nichts ab",
        statement="packages/contracts importiert nichts aus dem Projekt.",
        why="Ein Zyklus koppelte die Typgenerierung an Anwendungscode.",
        status=InvariantStatus.ENFORCED,
        component="repo",
    ),
    Invariant(
        id="layering-no-provider-sdk-in-core",
        title="Kein Provider-SDK im Kern",
        statement="Weder core noch contracts importieren Anbieter-SDKs oder Agenten-Frameworks.",
        why="Sonst wäre die Austauschbarkeit der Provider eine Absichtserklärung.",
        status=InvariantStatus.ENFORCED,
        component="repo",
    ),
)


def invariant_ids() -> frozenset[str]:
    return frozenset(i.id for i in INVARIANTS)


def _no_duplicates() -> None:
    ids = [i.id for i in INVARIANTS]
    if len(ids) != len(set(ids)):
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        raise RuntimeError(f"Doppelte Invarianten-Kennung: {duplicates}")


_no_duplicates()
