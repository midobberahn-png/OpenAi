"""Lauf-Endpunkte.

Glied ④ der Angriffskette — Identität → Lauf — und bis hierher das einzige,
das nur im Kern geprüft war. ``Run.user_id`` stammt aus ``CurrentSession``;
es gibt keinen Parameter, mit dem ein Lauf einem anderen Nutzer zugeordnet
werden könnte.

**Zugehörigkeit ist die zweite Frage.** Die Sitzungsprüfung sagt, *wer* fragt.
Sie sagt nichts darüber, ob der angefragte Lauf dem Fragenden gehört — und das
ist nach ``user_id`` im Body der nächste kurze Angriff: eine gültige eigene
Sitzung und eine fremde ``run_id``. Deshalb geht jeder Zugriff auf einen
benannten Lauf durch ``_eigener_lauf()``, und ein Strukturtest hält fest, dass
daneben kein zweiter Ladeweg entsteht (Invariante
``resource-ownership-checked-once``).

Die Antwort auf einen fremden Lauf ist **404 und nicht 403**: 403 bestätigt,
dass es ihn gibt. Wer Kennungen durchprobiert, soll aus der Antwort nichts
lernen können.

**Was dieser Endpunkt noch nicht tut: ausführen.** Ein Lauf entsteht hier,
wird eingestuft und bleibt in ``queued``. Der Grund ist kein Versäumnis dieser
Datei, sondern eine Abwesenheit dahinter: Es gibt **keine einzige
Werkzeug-Implementierung** (siehe ``jarvis_api.tools``). Ein Ausführungsschritt
über HTTP hätte nichts auszuführen. Die Einstufung läuft trotzdem schon —
``classify()`` ist deterministisch und braucht kein Modell —, damit die
Datenklasse eines Laufs von Anfang an feststeht und nicht nachträglich
behauptet wird.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from jarvis_api.db.run_store import PostgresRunStore
from jarvis_api.deps import (
    Agents,
    Approvals,
    Audit,
    CurrentSession,
    Events,
    Invocations,
    ModelArguments,
    ModelResponse,
    Policy,
    Runs,
    Tools,
)
from jarvis_api.events import als_nachricht
from jarvis_api.models import model_catalog
from jarvis_api.settings import Settings, get_settings
from jarvis_contracts import (
    BUDGET_PRESETS,
    UNDO_TTL,
    ActionWaiting,
    ApprovalChannel,
    InvocationStatus,
    PendingAction,
    Run,
    RunStarted,
    RunStatus,
    RunTrigger,
    Session,
    StepFinished,
    TokenDelta,
    ToolInvocation,
)
from jarvis_core.audit.chain import AuditEntry
from jarvis_core.orchestrator import (
    AdvanceRejected,
    BudgetTracker,
    NoEligibleModel,
    Recovery,
    RunAdvancer,
    ToolExecutor,
    classify,
    plan_turn,
    route,
    utc_now,
)
from jarvis_core.orchestrator.resolution import (
    Resolution,
    ResolutionDenied,
    StepResolver,
)
from jarvis_core.ports.invocations import InvocationStore
from jarvis_core.ports.runs import RunStateConflict
from jarvis_core.tools import ToolRegistry

__all__ = ["router"]

router = APIRouter(prefix="/runs", tags=["runs"])

KANAL: ApprovalChannel = "ui"
"""Der Kanal dieses Transportwegs — kein Feld des Requests.

Dieselbe Überlegung wie bei den Bestätigungen: Der Kanal entscheidet mit, ob
eine Aktion überhaupt bestätigt werden darf. Als Angabe des Aufrufers wäre er
eine Behauptung."""


# --------------------------------------------------------------------------
# Ein- und Ausgaben
# --------------------------------------------------------------------------


class RunRequest(BaseModel):
    """Ein neuer Lauf. Führt bewusst keine ``user_id``."""

    input: str = Field(min_length=1, max_length=8_000)
    channel: Literal["text", "voice"] = "text"
    """Geht in die Einstufung ein — Sprache hat ein anderes Budget und eine
    andere Bestätigungslage als Text. Es ist keine Identitätsangabe: Der
    Kanal beschreibt, *wie* gefragt wurde, nicht *wer* fragt."""


class RunView(BaseModel):
    """Sicht auf einen Lauf.

    Bewusst nicht das Vertragsmodell selbst: ``Run`` führt ``user_id``, und ein
    Antwortmodell, das eine Identität trägt, ist ein Antwortmodell, das morgen
    jemand als Request-Modell wiederverwendet. Der Nutzer steht ohnehin fest —
    er hat gefragt.
    """

    id: str
    status: str
    trigger: str
    taint_level: str
    data_class: str
    intent: str | None
    is_multi_step: bool
    trace_id: str
    started_at: datetime
    finished_at: datetime | None

    goal: str | None = None
    output: str = ""
    """Die formulierte Antwort — der Text, den ein Mensch liest.

    Kommt aus ``RunState.partial_output`` und heißt dort so, weil er auch bei
    einer Budgetüberschreitung ausgeliefert wird statt verworfen zu werden.

    **Er stammt aus einem Modell und kann Fremdinhalt wiedergeben.** Was ihn
    folgenlos macht, ist nicht diese Zeile, sondern die Darstellung: Die
    Oberfläche rendert Text und kein HTML (docs/10-ui.md §5). Ein
    ``dangerouslySetInnerHTML`` an dieser Stelle wäre der direkte Weg von einer
    präparierten Datei in eine Anwendung mit Postfachzugriff.

    Bei ``GET /runs`` bewusst leer, wie der Plan: Eine Übersicht über zwanzig
    Läufe soll nicht zwanzig Antworttexte übertragen."""

    needs_decision: bool = False
    """Wartet dieser Lauf auf einen Menschen?

    **Auch in der Übersicht**, anders als ``unresolved`` — und der Grund ist,
    dass es nichts kostet: Der Vermerk steht im Zustand, der ohnehin geladen
    ist. Ohne dieses Feld sähe ein Nutzer in der Liste nur ``executing``, und
    zwar für immer; der einzige Weg zu der Entscheidung wäre, jeden Lauf
    einzeln zu öffnen. Eine Sperre, die niemand findet, ist so gut wie keine
    Auflösung."""

    unresolved: UnresolvedView | None = None
    """Gesetzt, solange ein Schritt auf eine menschliche Entscheidung wartet.

    Nur beim einzelnen Lauf und nicht in der Übersicht — wie Plan und
    Antworttext, und aus demselben Grund: Die Auskunft kostet eine Abfrage im
    Werkzeugprotokoll."""

    plan: list[PlanStepView] = []
    """Leer, solange kein Plan existiert — und bei ``GET /runs`` bewusst nicht
    befüllt: Der Status jedes Schrittes kostet eine Berechtigungsabfrage, und
    eine Übersicht über zwanzig Läufe wäre damit zwanzig Abfragen. Wer den
    Plan sehen will, ruft den einzelnen Lauf ab."""


class UnresolvedView(BaseModel):
    """Ein Schritt, über den ein Mensch entscheiden muss — und woran er das tut.

    **Die Frage, die diese Sicht ehrlich beantworten muss, ist nicht „was ist
    passiert", sondern „woran erkenne ich es".** Das System kann die erste
    nicht beantworten: Es weiß, was es *versucht* hat, und hat keinen Weg,
    beim Zielsystem nachzusehen (ein lesender Kalenderzugriff existiert nicht,
    siehe Dossier). Eine Sicht, die das verschweigt, lädt zu einer Entscheidung
    ein, die auf nichts beruht.

    Deshalb steht hier, was es tatsächlich gibt:

    * **Was gemeint war** — die Beschreibung aus dem Plan. Sie ist der Satz, den
      der Nutzer selbst veranlasst hat, und damit das brauchbarste Stück: Wer
      „Zahnarzttermin Dienstag 14 Uhr eintragen" liest, weiß, wonach er im
      Kalender sucht.
    * **Was versucht wurde** — Werkzeug, Zeitpunkt und Protokollzustand. Nicht
      die Argumente: Sie können Fremdinhalt tragen, und der Weg, Fremdinhalt
      einem Menschen zur Prüfung vorzulegen, ist die Vorschau (docs/10-ui.md
      §5) und nicht ein Nebenfeld in einer Statusansicht.
    * **Was das System nicht weiß** — ausdrücklich, als Satz.

    ``caveat`` steht bewusst hier und nicht in der Oberfläche. Es ist die
    einzige Fassung, die auch für den nächsten Client gilt: Eine Sprachausgabe,
    die die drei Möglichkeiten vorliest, muss denselben Vorbehalt nennen, und
    eine Zeichenkette im React-Code steht ihr nicht zur Verfügung.
    """

    step_seq: int
    claim_id: str
    """Das Fencing-Token des gehaltenen Anspruchs — und der Bezug, gegen den
    entschieden wird.

    Es steht hier, weil eine Entscheidung ohne Bezug auf **diesen** Vorgang
    keine Entscheidung über ihn wäre: Läuft die Frist erneut ab, übernimmt der
    nächste Durchgang den Schritt und vergibt ein neues Token. Eine
    Browserseite, die das alte schickt, entscheidet dann über eine Lage, die es
    nicht mehr gibt — und wird abgewiesen.

    Eine Fähigkeit ist es nicht: Es gilt nur zusammen mit einer Sitzung, der
    der Lauf gehört, und ausschließlich an diesem einen Endpunkt."""

    description: str
    """Was der Plan an dieser Stelle vorsah — die verlässlichste Auskunft."""

    tool: str | None
    attempted_at: datetime | None
    attempts: list[str]
    """Die Protokollzustände zu diesem Schritt, ältester zuerst — etwa
    ``effect_unknown``."""

    caveat: str


class PlanStepView(BaseModel):
    """Ein Planschritt mit seinem **jetzigen** Stand."""

    seq: int
    kind: str
    target: str
    description: str
    depends_on: list[int]
    optional: bool
    status: str
    """``done``, ``ready``, ``waiting``, ``blocked`` oder ``needs_model``.

    Der Status wird bei jedem Abruf neu berechnet und nicht gespeichert — er
    ist eine Aussage über die Lage, nicht über den Plan.
    """


async def _planschritte(lauf: Run, *, angebot: set[str]) -> list[PlanStepView]:
    """Der Plan gegen den aktuellen Stand des Laufs.

    **Warum das nötig ist.** Ein Plan entsteht *vor* dem ersten Schritt, aus
    dem Angebot eines sauberen Laufs. Nach ``files.read`` ist der Lauf
    kontaminiert und das Angebot enger — ein Plan, der später ein sendendes
    Werkzeug vorsah, ist dann nicht mehr durchführbar.

    Das ließe sich verstecken (Plan anzeigen, wie er war) oder wegdefinieren
    (Plan neu erzeugen). Beides wäre falsch: Das eine kündigt etwas an, das
    nicht mehr geht; das andere verschweigt, dass sich die Lage geändert hat.
    Stattdessen steht je Schritt, woran er jetzt ist.

    ``needs_model`` ist damit **entfallen**: Auch ``agent``-Schritte sind
    ausführbar, seit die Modellschleife ihren Weg hinein hat
    (``plan_agent.py``). Der Status hatte einen ehrlichen Zweck — er sagte „das
    kann hier niemand ausführen" — und wäre jetzt eine Falschaussage. Er bleibt
    im Vertrag als Wert erwähnt, weil ein Client ihn aus älteren Antworten
    kennen kann; vergeben wird er nicht mehr.
    """
    if lauf.plan is None:
        return []

    erledigt = {schritt.seq for schritt in lauf.state.completed_steps}
    bereit = {schritt.seq for schritt in lauf.plan.ready_steps(erledigt)}

    ansicht: list[PlanStepView] = []
    for schritt in lauf.plan.steps:
        if schritt.seq in erledigt:
            stand = "done"
        elif schritt.seq not in bereit:
            stand = "waiting"
        elif schritt.kind in {"agent", "llm"}:
            # Kein Angebotsabgleich, und für beide aus je eigenem Grund: Der
            # ``llm``-Schritt bekommt gar kein Werkzeug zu sehen; der
            # ``agent``-Schritt bestimmt sein Angebot in jeder Runde neu, aus
            # dem Lauf, wie er dann ist. Ein Abgleich mit dem Angebot von
            # *jetzt* sagte über beide nichts.
            stand = "ready"
        elif schritt.target not in angebot:
            stand = "blocked"
        else:
            stand = "ready"
        ansicht.append(
            PlanStepView(
                seq=schritt.seq,
                kind=schritt.kind,
                target=schritt.target,
                description=schritt.description,
                depends_on=list(schritt.depends_on),
                optional=schritt.optional,
                status=stand,
            )
        )
    return ansicht


def _view(lauf: Run) -> RunView:
    return RunView(
        id=str(lauf.id),
        status=str(lauf.status),
        trigger=str(lauf.trigger),
        taint_level=str(lauf.taint_level),
        data_class=str(lauf.data_class),
        intent=str(lauf.classification.intent) if lauf.classification else None,
        is_multi_step=bool(lauf.classification and lauf.classification.is_multi_step),
        trace_id=lauf.trace_id,
        started_at=lauf.started_at,
        finished_at=lauf.finished_at,
        # **Das Ziel auch in der Übersicht**, anders als Plan und Antworttext.
        # Der Grund für deren Zurückhaltung gilt hier nicht: Der Status jedes
        # Planschrittes kostet eine Berechtigungsabfrage, der Antworttext kann
        # tausende Zeichen fassen — das Ziel ist eine Zeile, die ohnehin
        # geladen ist. Ohne sie zeigt ein Gesprächsverlauf nicht, was gesagt
        # wurde.
        goal=lauf.plan.goal if lauf.plan else None,
        needs_decision=lauf.state.unresolved_step is not None,
    )


async def _eigener_lauf(run_id: UUID, session: Session, runs: PostgresRunStore) -> Run:
    """Der Lauf des angemeldeten Nutzers — oder 404.

    Die einzige Stelle, an der ein Lauf anhand einer Kennung aus dem Request
    geladen wird. Nicht gefunden und nicht meiner ergeben dieselbe Antwort:
    Sonst wäre die Existenz fremder Läufe aufzählbar, und das ist eine
    Auskunft, für die niemand angemeldet sein müsste.
    """
    lauf = await runs.load(run_id)
    if lauf is None or lauf.user_id != session.user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lauf nicht gefunden.")
    return lauf


# --------------------------------------------------------------------------
# Endpunkte
# --------------------------------------------------------------------------


@router.post("", response_model=RunView, status_code=status.HTTP_201_CREATED)
async def create_run(
    payload: RunRequest,
    session: CurrentSession,
    runs: Runs,
    tools: Tools,
    policy: Policy,
    settings: Annotated[Settings, Depends(get_settings)],
    events: Events,
) -> RunView:
    """Legt einen Lauf an — für den angemeldeten Nutzer.

    Die Einstufung geschieht sofort und deterministisch. Sie bestimmt die
    Datenklasse des Laufs, und die ist die Obergrenze für alles, was später in
    ihm geschieht: Sie nachträglich zu setzen hieße, sie nachträglich zu
    behaupten.

    Der Lauf bleibt ``queued``. Ausgeführt wird er nicht — es gibt noch keine
    Werkzeuge und keinen Arbeiter, der ihn aufnähme.
    """
    einstufung = classify(payload.input, channel=payload.channel)

    # Routing gehört hierher und nicht in den ersten Werkzeugschritt.
    #
    # Ohne Routing gilt als Obergrenze eines Laufs seine eigene Datenklasse
    # (``executor._ceiling``) — eine Vorsichtsannahme für den Zustand „noch
    # nicht geroutet". Ein als P1 eingestufter Lauf könnte damit kein Werkzeug
    # ausführen, das P2 liefert. Erst die Routing-Entscheidung sagt, was das
    # tatsächlich gewählte Modell verarbeiten darf.
    try:
        routing = route(einstufung, model_catalog(settings))
    except NoEligibleModel as keines:
        # Kein zugelassenes Modell ist eine Konfigurationslage, kein
        # Serverfehler: Der Katalog passt nicht zur Anfrage — etwa P3-Daten
        # ohne lokales Modell.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(keines)
        ) from keines

    # Der Plan entsteht aus dem Angebot, nicht aus dem Wunsch.
    #
    # ``effective_tools()`` ist die Schnittmenge aus Werkzeugkatalog, erteilten
    # Rechten und Taint-Zustand. Was dort fehlt, taucht im Plan nicht auf — der
    # Nutzer sieht keinen Schritt angekündigt, der ohnehin blockiert würde.
    #
    # Der Lauf ist hier noch sauber; ein Plan kann deshalb später veralten,
    # sobald ein Schritt den Lauf kontaminiert. Das wird nicht versteckt,
    # sondern in ``GET /runs/{id}`` je Schritt sichtbar gemacht.
    angebot = await policy.effective_tools(session.user_id, tools.names())
    plan = plan_turn(einstufung, available_tools=angebot, tools=tools, goal=payload.input)

    jetzt = utc_now()
    lauf = Run(
        id=uuid4(),
        user_id=session.user_id,
        trigger=RunTrigger.USER,
        status=RunStatus.QUEUED,
        classification=einstufung,
        routing=routing,
        plan=plan,
        data_class=einstufung.data_class,
        budget=BUDGET_PRESETS["voice" if payload.channel == "voice" else "text"],
        trace_id=uuid4().hex,
        started_at=jetzt,
    )
    await runs.create(lauf)
    # Nach dem Anlegen und nicht davor: Ein Hinweis auf einen Lauf, den es noch
    # nicht gibt, führt jedes lauschende Gerät auf eine 404.
    await _melden(events, session, RunStarted(seq=0, run_id=lauf.id, trace_id=lauf.trace_id))
    return _view(lauf)


@router.get("", response_model=list[RunView])
async def list_runs(session: CurrentSession, runs: Runs) -> list[RunView]:
    """Die eigenen Läufe, neueste zuerst.

    Ohne Zugehörigkeitsprüfer, weil es hier nichts zu prüfen gibt: Die Abfrage
    kennt nur den Nutzer aus der Sitzung und hat keinen Parameter, über den ein
    anderer benannt werden könnte.
    """
    return [_view(lauf) for lauf in await runs.list_for_user(session.user_id)]


@router.get("/{run_id}", response_model=RunView)
async def read_run(
    run_id: UUID,
    session: CurrentSession,
    runs: Runs,
    tools: Tools,
    policy: Policy,
    invocations: Invocations,
) -> RunView:
    """Ein einzelner eigener Lauf — mit dem Plan und seinem jetzigen Stand."""
    lauf = await _eigener_lauf(run_id, session, runs)
    angebot = await policy.effective_tools(session.user_id, tools.names(), taint=lauf.taint_level)
    sicht = _view(lauf)
    return sicht.model_copy(
        update={
            "goal": lauf.plan.goal if lauf.plan else None,
            "output": lauf.state.partial_output,
            "plan": await _planschritte(lauf, angebot=angebot),
            "unresolved": await _offener_vorgang(lauf, invocations),
        }
    )


async def _offener_vorgang(lauf: Run, invocations: InvocationStore) -> UnresolvedView | None:
    """Der vermerkte Schritt samt Material — oder ``None``.

    **Der Vermerk wird gelesen und nicht errechnet.** Ob ein Schritt hängt,
    entscheidet die Frist, und die rechnet die Datenbank in der Anweisung, die
    übernimmt (``Recovery.take_over``). Hier nachzurechnen, ob ``claimed_at``
    lange genug her ist, wäre eine zweite Uhr und eine zweite Antwort — und die
    Oberfläche böte eine Entscheidung für Schritte an, die gerade in Ordnung
    laufen.
    """
    seq = lauf.state.unresolved_step
    if seq is None or lauf.state.claim_id is None:
        return None

    schritt = next((s for s in lauf.plan.steps if s.seq == seq), None) if lauf.plan else None
    eintraege = await invocations.for_step(lauf.id, seq)
    return UnresolvedView(
        step_seq=seq,
        claim_id=str(lauf.state.claim_id),
        description=schritt.description if schritt else f"Schritt {seq}",
        tool=schritt.target if schritt and schritt.kind == "tool" else None,
        attempted_at=eintraege[0].created_at if eintraege else lauf.state.claimed_at,
        attempts=[str(eintrag.status) for eintrag in eintraege],
        caveat=(
            "JARVIS weiß, was es versucht hat — nicht, was daraus geworden ist. "
            "Der Vorgang wurde unterbrochen, nachdem er begonnen hatte; ob er nach "
            "außen gewirkt hat, lässt sich von hier aus nicht feststellen. Sieh dort "
            "nach, bevor du entscheidest."
        ),
    )


async def _melden(events: Events, session: Session, nachricht: object) -> None:
    """Schickt einen Hinweis an die Geräte des Nutzers — falls es einen Weg gibt.

    **Nach** der Wirkung und nie davor: Ein Ereignis, das eine Ausführung
    ankündigt, die anschließend scheitert, ist eine Falschaussage an alle
    angemeldeten Geräte.

    Und ohne Rückwirkung: Fehlt der Verteiler oder ist Redis weg, geschieht
    nichts. Der Strom ist eine Beschleunigung, keine Zusage — die Oberfläche
    lädt ohnehin im Takt nach.
    """
    if events is None:
        return
    await events.publish(session.user_id, als_nachricht(nachricht))  # type: ignore[arg-type]


def _token_melder(
    events: Events, session: Session, run_id: UUID
) -> Callable[[str], Awaitable[None]] | None:
    """Baut den Rückruf, der Textstücke an die Geräte des Nutzers schickt.

    ``None``, wenn es keinen Verteiler gibt: Dann läuft der Schritt ohne
    Zuschauer, und die Oberfläche sieht die Antwort, wenn sie fertig ist.
    Ein Rückruf, der ins Leere schriebe, kostete Arbeit ohne Wirkung.
    """
    if events is None:
        return None

    async def melden(stueck: str) -> None:
        await events.publish(
            session.user_id,
            als_nachricht(TokenDelta(seq=0, run_id=run_id, text=stueck)),
        )

    return melden


async def _schritt_melden(
    events: Events, session: Session, run_id: UUID, stand: str, wartend: PendingAction | None
) -> None:
    """Zwei Hinweise aus einem Ausgang — und der zweite ist der wichtigere.

    ``StepFinished`` sagt „der Lauf hat sich bewegt". ``ActionWaiting`` sagt
    „hier steht jetzt ein Mensch zwischen Absicht und Wirkung", und das ist der
    Moment, für den es diesen Strom überhaupt gibt: Drei Sekunden Pollintervall
    sind bei einer Aktion mit Außenwirkung drei Sekunden zu viel.

    ``latency_ms=0``: Die Zahl steht im Vertrag, und dieser Weg misst sie
    nicht. Sie zu schätzen wäre schlimmer als sie wegzulassen — eine erfundene
    Messung sieht aus wie eine echte. Wer sie braucht, misst sie dort, wo der
    Schritt läuft, und nicht an der Kante.
    """
    await _melden(
        events, session, StepFinished(seq=0, run_id=run_id, step_seq=0, status=stand, latency_ms=0)
    )
    if wartend is not None:
        await _melden(events, session, ActionWaiting(seq=0, run_id=run_id, action_id=wartend.id))


class InvocationView(BaseModel):
    """Was in einem Lauf tatsächlich aufgerufen wurde.

    **Der Plan sagt, was vorgesehen war; das hier sagt, was geschah.** Die
    beiden fallen auseinander — ein Schritt kann abgewiesen worden sein, ein
    Aufruf kann außerhalb des Plans erfolgt sein (``POST /runs/{id}/steps``),
    und ein Agentenschritt enthält mehrere Aufrufe. Eine Oberfläche, die nur
    den Plan zeigt, zeigt eine Absicht und nennt sie Ergebnis.

    Ohne ``arguments``: Sie stehen im Protokoll und können Fremdinhalt tragen —
    ein gelesener Dateipfad, ein Betreff aus einer Mail. Was ein Mensch vor
    einer Bestätigung sehen soll, zeigt die Vorschau, und die ist dafür gebaut
    (Kürzung, Hervorhebung, Prüfbarkeit). Hier geht es um „was ist passiert",
    nicht um „was steht drin".
    """

    id: str
    tool_name: str
    status: str
    step_seq: int | None
    created_at: datetime
    executed_at: datetime | None
    undoable: bool
    """Kann *dieser* Aufruf jetzt zurückgenommen werden?

    Drei Bedingungen zusammen: ausgeführt, das Werkzeug kennt eine Rücknahme,
    und die Frist läuft noch. Die Auskunft ist bewusst eine Momentaufnahme —
    verbindlich entscheidet ``claim_undo`` in derselben Anweisung, die
    zurücknimmt. Eine Schaltfläche, die erscheint, obwohl es nicht mehr geht,
    wäre ärgerlich; eine, die fehlt, obwohl es ginge, wäre schlimmer.
    """


@router.get("/{run_id}/invocations", response_model=list[InvocationView])
async def list_invocations(
    run_id: UUID,
    session: CurrentSession,
    runs: Runs,
    invocations: Invocations,
    tools: Tools,
) -> list[InvocationView]:
    """Die Werkzeugaufrufe eines eigenen Laufs, älteste zuerst.

    Die Zugehörigkeit hängt am Lauf und wird wie überall über
    ``_eigener_lauf`` geprüft — das Protokoll selbst führt keinen Nutzer.
    """
    lauf = await _eigener_lauf(run_id, session, runs)
    jetzt = utc_now()
    return [
        InvocationView(
            id=str(aufruf.id),
            tool_name=aufruf.tool_name,
            status=str(aufruf.status),
            step_seq=aufruf.step_seq,
            created_at=aufruf.created_at,
            executed_at=aufruf.executed_at,
            undoable=_ruecknehmbar(aufruf, tools, jetzt),
        )
        for aufruf in await invocations.for_run(lauf.id)
    ]


def _ruecknehmbar(aufruf: ToolInvocation, tools: ToolRegistry, jetzt: datetime) -> bool:
    """Momentaufnahme: Ginge eine Rücknahme jetzt?

    Bewusst dieselben Bedingungen wie in ``claim_undo`` — ausgeführt, Werkzeug
    mit Rücknahme, innerhalb der Frist —, aber ausdrücklich **nicht** dieselbe
    Wahrheit: Verbindlich ist die Anweisung, die zurücknimmt. Diese Zeile
    entscheidet nur, ob eine Schaltfläche erscheint.
    """
    if aufruf.status is not InvocationStatus.EXECUTED or aufruf.executed_at is None:
        return False
    spec = tools.get(aufruf.tool_name)
    if spec is None or not spec.supports_undo:
        return False
    return aufruf.executed_at + UNDO_TTL > jetzt


# --------------------------------------------------------------------------
# Werkzeugschritt
# --------------------------------------------------------------------------


class StepRequest(BaseModel):
    """Ein Werkzeugschritt in einem Lauf.

    Führt weder Nutzer noch Sitzung noch Invokationskennung: Die Identität
    kommt aus der Sitzung, die Invokationskennung erzeugt der Executor. Ein
    Feld dafür wäre der kürzeste Weg, einen fremden Grant anzusprechen — ein
    Strukturtest hält das fest.
    """

    tool: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any] = Field(default_factory=dict)


class StepView(BaseModel):
    """Ergebnis eines Werkzeugschritts."""

    status: str
    """``executed``, ``awaiting_confirmation``, ``blocked``, ``failed`` oder
    ``budget_exceeded`` — der Ausgang, nicht der Laufzustand."""

    reason: str
    run_status: str
    taint_level: str
    """Nach dem Schritt. Ein Werkzeug, das Fremdinhalt gelesen hat, hinterlässt
    hier ``tainted``, und die sendenden Werkzeuge fallen aus dem Angebot."""

    display: str
    data: dict[str, Any] | None
    """Das Werkzeugergebnis.

    Auch bei ``P3`` an den Aufrufer ausgeliefert, und das ist kein Widerspruch:
    „P3 verlässt das Gerät nie" richtet sich gegen fremde **Modelle und
    Anbieter**. Der angemeldete Nutzer ist der Eigentümer der Daten — ihm seine
    eigene Datei vorzuenthalten, während das lokale Modell sie sehen darf, wäre
    Sicherheitstheater.
    """

    data_class: str | None
    """Einstufung des Ergebnisses. Die Oberfläche kennzeichnet danach."""

    action_id: str | None
    """Gesetzt bei ``awaiting_confirmation`` — hierauf antwortet
    ``POST /actions/{id}/respond``."""

    code: str | None


@router.post("/{run_id}/steps", response_model=StepView)
async def execute_step(
    run_id: UUID,
    payload: StepRequest,
    session: CurrentSession,
    runs: Runs,
    tools: Tools,
    policy: Policy,
    approvals: Approvals,
    invocations: Invocations,
    audit: Audit,
    events: Events,
) -> StepView:
    """Führt einen Werkzeugschritt aus — Glieder ⑤ bis ⑦ über HTTP.

    **Was dieser Endpunkt nicht entscheidet: irgendetwas.** Er löst den Lauf
    auf, prüft dessen Zugehörigkeit und übergibt an den Executor. Ob das
    Werkzeug laufen darf, entscheidet die Policy Engine; ob eine Bestätigung
    nötig ist, ebenfalls; ob der Grant gilt, das Gate; ob er noch nicht
    verbraucht ist, die Datenbank. Eine Prüfung hier wäre eine zweite Wahrheit.

    **Der Werkzeugname kommt vom Aufrufer, die Erlaubnis nicht.** Das ist der
    Pfad für einen ausdrücklichen Befehl („lies mir die Datei X") und
    zugleich der, den die Modellschleife später intern nimmt. Beide landen bei
    derselben Policy-Entscheidung — ein Vorschlag eines Modells trägt keine
    Berechtigung mit sich.

    **Fortschreiben mit Statusvergleich.** Gespeichert wird gegen den Status,
    der beim Laden galt. Läuft parallel ein zweiter Schritt, gewinnt genau
    einer; der andere bekommt 409 statt eines überschriebenen Laufs.
    """
    lauf = await _eigener_lauf(run_id, session, runs)
    status_vorher = lauf.status

    if lauf.status is RunStatus.AWAITING_CONFIRMATION:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Der Lauf wartet auf eine Bestätigung. Erst darauf antworten.",
        )
    if lauf.status.is_terminal:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Der Lauf ist abgeschlossen ({lauf.status}).",
        )

    executor = ToolExecutor(
        registry=tools,
        policy=policy,
        gateway=approvals,
        invocations=invocations,
        # Ohne diese Zeile lief jede Werkzeugausführung ohne Protokoll — die
        # Kette war gebaut und bekam nie einen Eintrag.
        audit=audit,
    )
    tracker = BudgetTracker(lauf.budget, usage=lauf.usage)

    # ``queued → planning → executing``: Der Zustandsautomat kennt keinen
    # direkten Weg, und das ist Absicht — ein zusätzlicher Übergang machte die
    # Planungsstufe für alle Läufe optional.
    if lauf.status is RunStatus.QUEUED:
        lauf = executor.start(lauf, tracker)

    # Ein halluzinierter Werkzeugname ist Modellalltag und kein Serverfehler —
    # die Registry unterscheidet ``UnknownTool`` deshalb ausdrücklich von einer
    # nicht passenden Autorisierung. Über HTTP ist die ehrliche Antwort 404:
    # Diese Ressource gibt es nicht. Der Katalog ist kein Geheimnis, das Modell
    # bekommt ihn ohnehin als Schema.
    if tools.get(payload.tool) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unbekanntes Werkzeug: {payload.tool!r}",
        )

    schritt = await executor.execute_tool(
        lauf,
        tracker,
        tool_name=payload.tool,
        arguments=payload.arguments,
        # Oberhalb des ganzen Plans und nicht bloß über den erledigten
        # Schritten: Sonst belegte dieser Aufruf die Nummer des nächsten
        # Planschrittes, und der gälte danach als erledigt, ohne gelaufen zu
        # sein. Die Begründung steht bei ``Run.next_step_seq``.
        seq=lauf.next_step_seq,
        session_id=session.id,
        channel=KANAL,
    )

    try:
        await runs.save(schritt.run, erwarteter_status=status_vorher)
    except RunStateConflict as konflikt:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Der Lauf wurde parallel verändert. Neu laden und wiederholen.",
        ) from konflikt

    ergebnis = schritt.result
    await _schritt_melden(events, session, lauf.id, schritt.status, schritt.pending)
    return StepView(
        status=schritt.status,
        reason=schritt.reason,
        run_status=str(schritt.run.status),
        taint_level=str(schritt.run.taint_level),
        display=ergebnis.display if ergebnis else "",
        data=ergebnis.data if ergebnis else None,
        data_class=str(ergebnis.produced_data_class) if ergebnis else None,
        action_id=str(schritt.pending.id) if schritt.pending else None,
        code=schritt.code,
    )


# --------------------------------------------------------------------------
# Planschritt
# --------------------------------------------------------------------------


_ABWEISUNGEN: dict[str, int] = {
    # Welcher Statuscode zu welcher Ablehnung gehört, entscheidet **hier** und
    # nicht im Kern. Der Kern liefert eine Kennung und einen Satz; er weiß
    # nicht, dass es HTTP gibt — der Arbeiter, der abgebrochene Läufe
    # fortsetzt, spricht keins.
    #
    # Alle bisherigen Ablehnungen sind Konflikte: Der Aufrufer hat nichts
    # falsch gemacht, die Lage passt nur nicht. Die Tabelle steht trotzdem da,
    # weil die nächste Kennung das ändern kann und der Vorgabewert dann nicht
    # stillschweigend gelten soll.
}
_ABWEISUNG_VORGABE = status.HTTP_409_CONFLICT


class AdvanceRequest(BaseModel):
    """Argumente für den **nächsten geplanten** Schritt — oder keine.

    Kein Werkzeugname — und das ist der ganze Unterschied zu
    ``POST /runs/{id}/steps``. Welches Werkzeug an der Reihe ist, bestimmt der
    Plan; der Aufrufer liefert höchstens, womit es aufgerufen wird.

    **Zwei Modi, und der Unterschied ist genau ein Feld.**

    ``arguments`` gesetzt (auch leer: ``{}``)
        Der Aufrufer formuliert. Der Weg, den es bisher allein gab.

    ``arguments`` weggelassen (``null``)
        Ein Modell formuliert. Es bekommt Ziel, Schrittbeschreibung, den
        bisherigen Verlauf und **ein** Werkzeugschema — das des geplanten
        Schrittes. Was danach geschieht, ist in beiden Modi dasselbe:
        Schemaprüfung, Policy, Taint-Gate, gegebenenfalls Bestätigung, Grant,
        Verbrauch.

    Die Unterscheidung liegt bewusst zwischen „gesetzt" und „nicht gesetzt"
    und nicht in einem Schalter ``use_model``. Ein Schalter neben einem
    Argumentfeld ließe beides gleichzeitig zu, und dann gäbe es eine Frage zu
    beantworten, die niemand stellen sollte: Was gilt, wenn der Aufrufer
    Argumente schickt *und* das Modell welche liefert?
    """

    arguments: dict[str, Any] | None = None


@router.post("/{run_id}/advance", response_model=StepView)
async def advance_run(
    run_id: UUID,
    payload: AdvanceRequest,
    session: CurrentSession,
    runs: Runs,
    tools: Tools,
    policy: Policy,
    approvals: Approvals,
    invocations: Invocations,
    modell: ModelArguments,
    antworten: ModelResponse,
    agenten: Agents,
    audit: Audit,
    events: Events,
) -> StepView:
    """Führt den nächsten fälligen Schritt des Plans aus.

    **Der Plan bindet.** Bei ``POST /runs/{id}/steps`` nennt der Aufrufer das
    Werkzeug; hier nennt es der Plan. Das ist die engere Tür: Wer diesen
    Endpunkt benutzt, kann keinen Schritt überspringen und keinen einschieben,
    der nicht angekündigt war — und der Nutzer hat den Plan vorher gesehen.

    **Was diese Funktion tut, ist absichtlich wenig.** Sie löst den Lauf auf,
    prüft dessen Zugehörigkeit, übergibt an den ``RunAdvancer`` und übersetzt
    dessen Ausgang in eine Antwort. Der Ablauf selbst — Anspruch, Vorbereitung,
    Wirkung, Festschreiben — steht in ``core/orchestrator/advance.py``.

    Das war nicht immer so, und der Umbau hat einen Anlass: An genau dieser
    Grenze sind zwei Sicherheitslücken kurz nacheinander entstanden, beide an
    der Reihenfolge *Anspruch → Wirkung → Festschreiben*. Sie war über eine
    Routenfunktion verteilt und ließ sich nicht an einer Stelle überblicken.
    Ein externer Prüfer hat beide gefunden und den Umbau vorgeschlagen.

    **Die Identität bleibt hier.** Wem ein Lauf gehört, entscheidet diese
    Schicht aus der Sitzung; der ``RunAdvancer`` bekommt den geladenen Lauf und
    hat keinen Parameter, mit dem sich ein fremder benennen ließe.
    """
    lauf = await _eigener_lauf(run_id, session, runs)

    advancer = RunAdvancer(
        runs=runs,
        tools=tools,
        policy=policy,
        executor=ToolExecutor(
            registry=tools,
            policy=policy,
            gateway=approvals,
            invocations=invocations,
            # Ohne diese Zeile lief jede Werkzeugausführung ohne Protokoll —
            # die Kette war gebaut und bekam nie einen Eintrag.
            audit=audit,
        ),
        arguments=modell,
        responses=antworten,
        agents=agenten,
        # Ohne diesen Parameter ist ein fremder Anspruch eine Sackgasse: 409,
        # und der Lauf steht für immer. Mit ihm sieht der Ablauf nach, ob die
        # Frist abgelaufen ist und ob das Werkzeugprotokoll eine Wirkung
        # ausschließt — und übernimmt nur dann.
        recovery=Recovery(runs=runs, invocations=invocations, tools=tools),
        # Der Text fließt, während er entsteht — über denselben Kanal, der
        # ohnehin offen ist. Ein Stück ist Anzeige und kein Zustand: Was in den
        # Lauf geschrieben wird, ist der vollständige Text.
        on_token=_token_melder(events, session, lauf.id),
        channel=KANAL,
    )

    try:
        ausgang = await advancer.advance(lauf, session_id=session.id, vorgegeben=payload.arguments)
    except AdvanceRejected as abgewiesen:
        raise HTTPException(
            status_code=_ABWEISUNGEN.get(abgewiesen.code, _ABWEISUNG_VORGABE),
            detail=abgewiesen.reason,
        ) from abgewiesen

    await _schritt_melden(events, session, lauf.id, ausgang.status, ausgang.pending)
    return StepView(
        status=ausgang.status,
        reason=ausgang.reason,
        run_status=str(ausgang.run.status),
        taint_level=str(ausgang.run.taint_level),
        display=ausgang.display,
        data=ausgang.result.data if ausgang.result else None,
        data_class=(str(ausgang.result.produced_data_class) if ausgang.result else None),
        action_id=str(ausgang.pending.id) if ausgang.pending else None,
        code=ausgang.code,
    )


# --------------------------------------------------------------------------
# Die Entscheidung über einen unklaren Schritt
# --------------------------------------------------------------------------


class ResolveRequest(BaseModel):
    """Eine von genau drei Entscheidungen — und der Vorgang, für den sie gilt.

    **Kein Zielstatus.** Ein Feld ``status`` wäre der bequemere Entwurf und die
    Abschaffung des Zustandsautomaten: Wer von außen einen Zielzustand nennen
    darf, umgeht die Übergänge, die ihn tragen. Hier stehen drei benannte
    Entscheidungen, und jede hat genau einen Übergang.

    **``claim_id`` ist Pflicht und stammt aus der Ansicht**, in der der
    Vorgang gezeigt wurde. Ohne diesen Bezug entschiede eine Browserseite mit
    veraltetem Zustand über eine Lage, die es nicht mehr gibt — läuft die
    Frist erneut ab, übernimmt der nächste Durchgang und vergibt ein neues
    Token.
    """

    decision: Literal["completed", "retry", "abort"]
    claim_id: UUID


class ResolveResult(BaseModel):
    """Was aus der Entscheidung geworden ist."""

    resolution: str
    step_seq: int
    run_status: str
    detail: str


@router.post("/{run_id}/resolve", response_model=ResolveResult)
async def resolve_run_step(
    run_id: UUID,
    payload: ResolveRequest,
    session: CurrentSession,
    runs: Runs,
    audit: Audit,
    events: Events,
) -> ResolveResult:
    """Löst einen Schritt auf, dessen Wirkung unklar ist.

    **Der einzige Weg aus ``ENTSCHEIDUNG NÖTIG`` heraus** — und deshalb selbst
    eine Sicherheitsgrenze. Der Entscheidende hebt eine Sperre auf, die einen
    doppelten Seiteneffekt verhindert; vier Bedingungen tragen sie, und drei
    davon stehen bereits vor der ersten Zeile Logik:

    * **Eigentümer** — ``_eigener_lauf`` wie überall. Ein fremder Lauf ist 404,
      nicht 403: Sonst wäre aus der Antwort zu lernen, dass es ihn gibt.
    * **Identität aus der Sitzung** — die Kante nimmt keine Nutzerkennung
      entgegen (``identity-derives-from-session``).
    * **Fencing und Vermerk** — beide prüft ``StepResolver`` gegen den
      geladenen Lauf, und das entscheidende ``UPDATE`` prüft den Anspruch
      **noch einmal** in derselben Anweisung, die schreibt. Zwei gleichzeitige
      Entscheidungen ergeben deshalb eine, nicht zwei.

    **409 für alle Ablehnungen**, mit demselben Satz: kein Vermerk, fremdes
    Token, schon entschieden. Die Unterscheidung nach außen zu tragen hieße,
    aus der Ablehnung eine Auskunft über den Zustand zu machen — dieselbe
    Überlegung wie bei der Rücknahme.
    """
    lauf = await _eigener_lauf(run_id, session, runs)
    entscheidung = Resolution(payload.decision)

    try:
        ausgang = await StepResolver(runs=runs).resolve(
            lauf,
            decision=entscheidung,
            # Aus dem Request und nicht aus dem geladenen Lauf: Ein Vergleich
            # eines Wertes mit sich selbst prüft nichts.
            claim_id=payload.claim_id,
            now=utc_now(),
        )
    except ResolutionDenied as abgelehnt:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(abgelehnt)
        ) from abgelehnt
    except RunStateConflict as konflikt:
        # Der Anspruch galt beim Laden noch und beim Schreiben nicht mehr —
        # genau das Rennen, gegen das das Fencing steht. Nach außen dieselbe
        # Antwort: Die Lage hat sich geändert.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Für diesen Schritt steht keine Entscheidung (mehr) an. Neu laden und "
                "nachsehen, was daraus geworden ist."
            ),
        ) from konflikt

    # **Diese Entscheidung gehört in die Spur, und zwar mehr als die meisten.**
    # Sie ist der Punkt, an dem ein Mensch eine Sperre aufhebt, die vor einem
    # doppelten Seiteneffekt schützt. Wer später fragt, warum ein Termin
    # zweimal im Kalender steht, findet hier die Antwort — mit Zeitpunkt,
    # Person und Entscheidung.
    await audit.append(
        AuditEntry(
            occurred_at=utc_now(),
            actor="user",
            action="run.step_resolved",
            resource=str(lauf.id),
            details={
                "decision": str(ausgang.resolution),
                "step_seq": str(ausgang.seq),
                "run_status": str(ausgang.run_status),
            },
            user_id=session.user_id,
        )
    )

    await _melden(
        events,
        session,
        StepFinished(
            seq=0,
            run_id=lauf.id,
            step_seq=ausgang.seq,
            status=str(ausgang.resolution),
            latency_ms=0,
        ),
    )

    return ResolveResult(
        resolution=str(ausgang.resolution),
        step_seq=ausgang.seq,
        run_status=str(ausgang.run_status),
        detail=ausgang.detail,
    )
