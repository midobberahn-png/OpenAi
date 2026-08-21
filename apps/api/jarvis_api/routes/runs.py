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

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from jarvis_api.db.run_store import PostgresRunStore
from jarvis_api.deps import (
    Approvals,
    CurrentSession,
    Invocations,
    ModelArguments,
    Policy,
    Runs,
    Tools,
)
from jarvis_api.models import model_catalog
from jarvis_api.settings import Settings, get_settings
from jarvis_contracts import (
    BUDGET_PRESETS,
    ApprovalChannel,
    Run,
    RunStatus,
    RunTrigger,
    Session,
    TaintLevel,
)
from jarvis_core.orchestrator import (
    ArgumentsUnavailable,
    BudgetTracker,
    NoEligibleModel,
    ToolExecutor,
    classify,
    plan_turn,
    route,
    utc_now,
)
from jarvis_core.ports.runs import RunStateConflict

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
    plan: list[PlanStepView] = []
    """Leer, solange kein Plan existiert — und bei ``GET /runs`` bewusst nicht
    befüllt: Der Status jedes Schrittes kostet eine Berechtigungsabfrage, und
    eine Übersicht über zwanzig Läufe wäre damit zwanzig Abfragen. Wer den
    Plan sehen will, ruft den einzelnen Lauf ab."""


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

    ``needs_model`` ist dabei die ehrlichste Auskunft des Systems: Schritte der
    Art ``llm`` und ``agent`` kann heute niemand ausführen, weil die
    Modellschleife nicht angeschlossen ist.
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
        elif schritt.kind != "tool":
            stand = "needs_model"
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
    run_id: UUID, session: CurrentSession, runs: Runs, tools: Tools, policy: Policy
) -> RunView:
    """Ein einzelner eigener Lauf — mit dem Plan und seinem jetzigen Stand."""
    lauf = await _eigener_lauf(run_id, session, runs)
    angebot = await policy.effective_tools(session.user_id, tools.names(), taint=lauf.taint_level)
    sicht = _view(lauf)
    return sicht.model_copy(
        update={
            "goal": lauf.plan.goal if lauf.plan else None,
            "plan": await _planschritte(lauf, angebot=angebot),
        }
    )


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


def _naechste_schrittnummer(lauf: Run) -> int:
    """Die nächste freie Schrittnummer.

    ``len(completed_steps) + 1`` wäre naheliegend und falsch, sobald Plan- und
    Einzelschritte gemischt werden: Lief zuerst Planschritt 2, ergäbe die Zahl
    wieder 2 — und ``RunState`` weist doppelte Schrittnummern zurück. Das Maximum
    ist die Zahl, die in beiden Fällen stimmt.
    """
    return max((s.seq for s in lauf.state.completed_steps), default=0) + 1


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
        seq=_naechste_schrittnummer(lauf),
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
) -> StepView:
    """Führt den nächsten fälligen Schritt des Plans aus.

    **Der Plan bindet.** Bei ``POST /runs/{id}/steps`` nennt der Aufrufer das
    Werkzeug; hier nennt es der Plan. Das ist die engere Tür: Wer diesen
    Endpunkt benutzt, kann keinen Schritt überspringen und keinen einschieben,
    der nicht angekündigt war — und der Nutzer hat den Plan vorher gesehen.

    Beide Wege enden bei derselben Policy-Entscheidung. Der Plan ersetzt keine
    Prüfung; er verengt nur, was überhaupt zur Prüfung kommt.

    **Die Argumente kommen aus einer von zwei Quellen** — aus dem Request oder
    aus einem Modell (``arguments`` weggelassen). Danach ist der Weg identisch,
    und das ist die tragende Eigenschaft: Ein Werkzeugvorschlag eines Modells
    trägt keine Berechtigung mit sich. Er geht durch dieselbe Schemaprüfung,
    dieselbe Policy Engine, dasselbe Taint-Gate und denselben Grant-Verbrauch
    wie eine Absicht, die der Nutzer selbst getippt hat.

    **Was sich mit dem Modell ändert, ist der Rang des Payload-Hashes.**
    Solange ein Mensch die Argumente tippte, war er eine Formalie: Angezeigt
    wurde, was derselbe Mensch kurz vorher geschrieben hatte. Jetzt hat sie ein
    Modell formuliert, das eine kontaminierte Datei gelesen haben kann — und
    der Hash ist die Stelle, an der Bestätigtes und Ausgeführtes
    übereinstimmen.

    **Und die Kontamination wird vor dem Schritt fortgeschrieben.** Eine
    Modellantwort erbt den Taint ihres Kontextes. Käme sie erst nach der
    Ausführung in den Lauf, träfe das Werkzeug einen Lauf an, der sauberer
    aussieht, als er ist — und ein Termin mit Teilnehmern liefe durch, den das
    Taint-Gate hätte sperren müssen.

    **Warum ein Schritt scheitern kann, obwohl er im Plan steht:** Der Plan
    entstand aus dem Angebot eines sauberen Laufs. Kontaminiert ein früherer
    Schritt den Lauf, fällt ein später geplantes sendendes Werkzeug aus dem
    Angebot. Dieser Endpunkt weist das dann mit 409 ab und nennt den Grund —
    ``GET /runs/{id}`` zeigt denselben Schritt als ``blocked``.
    """
    lauf = await _eigener_lauf(run_id, session, runs)

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
    if lauf.plan is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Für diesen Lauf gibt es keinen Plan.",
        )
    # Festgehalten, weil ``lauf`` weiter unten fortgeschrieben wird — der Plan
    # bleibt dabei derselbe, und die Zusicherung „nicht None" soll das
    # überleben.
    plan = lauf.plan

    erledigt = {schritt.seq for schritt in lauf.state.completed_steps}
    faellig = sorted(plan.ready_steps(erledigt), key=lambda s: s.seq)
    if not faellig:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Der Plan ist abgearbeitet.",
        )

    schritt_plan = faellig[0]
    if schritt_plan.kind != "tool":
        # Die ehrlichste Auskunft, die dieses System derzeit gibt.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Schritt {schritt_plan.seq} ist vom Typ {schritt_plan.kind!r}. Ein Modell "
                "füllt hier die Argumente eines Werkzeugschrittes; Schritte, die selbst "
                "aus einem Modell bestehen, führt dieser Endpunkt nicht aus."
            ),
        )

    angebot = await policy.effective_tools(session.user_id, tools.names(), taint=lauf.taint_level)
    if schritt_plan.target not in angebot:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Schritt {schritt_plan.seq} ({schritt_plan.target}) ist nicht mehr "
                "durchführbar — der Lauf hat sich seit der Planung verändert."
            ),
        )

    status_vorher = lauf.status
    executor = ToolExecutor(
        registry=tools, policy=policy, gateway=approvals, invocations=invocations
    )
    tracker = BudgetTracker(lauf.budget, usage=lauf.usage)
    if lauf.status is RunStatus.QUEUED:
        lauf = executor.start(lauf, tracker)

    # Die Argumente — aus dem Request oder aus dem Modell.
    argumente = payload.arguments
    if argumente is None:
        spec = tools.require(schritt_plan.target)
        try:
            formuliert = await modell.for_step(
                spec=spec,
                step=schritt_plan,
                run=lauf,
                goal=plan.goal,
                # Das geroutete Modell des Laufs, nicht eines aus dem Request.
                # Die Wahl steht seit ``create_run`` fest und hat dort die
                # Datenklasse berücksichtigt; sie hier neu treffen zu lassen
                # hieße, die Obergrenze nachträglich zu verschieben.
                model=lauf.routing.model if lauf.routing else "",
            )
        except ArgumentsUnavailable as ohne:
            # Kein Serverfehler: Das Modell hat nicht geliefert oder durfte
            # nicht gefragt werden. Beides ist eine Lage, in der der Nutzer
            # etwas tun kann — die Argumente selbst angeben.
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ohne)) from ohne

        argumente = formuliert.arguments

        # Der Aufruf hat Tokens gekostet und wird gebucht. Ein Modellaufruf,
        # den niemand zählt, macht aus der Budgetgrenze eine Empfehlung — und
        # dies ist der erste Aufruf im System, der ohne ausdrücklichen Wunsch
        # des Nutzers geschieht.
        tracker.record_model_call(
            tokens_in=formuliert.usage.tokens_in,
            tokens_out=formuliert.usage.tokens_out,
            cost_eur=formuliert.usage.cost_eur,
        )

        # Die Kontamination der Antwort **vor** der Ausführung fortschreiben.
        #
        # Ein Modell, das den Verlauf eines kontaminierten Laufs gelesen hat,
        # liefert Argumente, die als Fremdinhalt gelten. Käme das erst danach
        # in den Lauf, entschiede das Taint-Gate über einen Zustand von vorhin.
        # ``with_taint`` kann nur erhöhen — die Monotonie liegt im Vertrag.
        if formuliert.taints:
            lauf = lauf.with_taint(TaintLevel.TAINTED)

    ausgefuehrt = await executor.execute_tool(
        lauf,
        tracker,
        tool_name=schritt_plan.target,
        arguments=argumente,
        # Die Schrittnummer stammt aus dem Plan, nicht aus einem Zähler: Nur so
        # lässt sich später sagen, welcher *geplante* Schritt gelaufen ist.
        seq=schritt_plan.seq,
        session_id=session.id,
        channel=KANAL,
    )

    try:
        await runs.save(ausgefuehrt.run, erwarteter_status=status_vorher)
    except RunStateConflict as konflikt:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Der Lauf wurde parallel verändert. Neu laden und wiederholen.",
        ) from konflikt

    ergebnis = ausgefuehrt.result
    return StepView(
        status=ausgefuehrt.status,
        reason=ausgefuehrt.reason,
        run_status=str(ausgefuehrt.run.status),
        taint_level=str(ausgefuehrt.run.taint_level),
        display=ergebnis.display if ergebnis else "",
        data=ergebnis.data if ergebnis else None,
        data_class=str(ergebnis.produced_data_class) if ergebnis else None,
        action_id=str(ausgefuehrt.pending.id) if ausgefuehrt.pending else None,
        code=ausgefuehrt.code,
    )
