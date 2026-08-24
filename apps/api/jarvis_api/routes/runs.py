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
    Agents,
    Approvals,
    CurrentSession,
    Invocations,
    ModelArguments,
    ModelResponse,
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
)
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
            registry=tools, policy=policy, gateway=approvals, invocations=invocations
        ),
        arguments=modell,
        responses=antworten,
        agents=agenten,
        # Ohne diesen Parameter ist ein fremder Anspruch eine Sackgasse: 409,
        # und der Lauf steht für immer. Mit ihm sieht der Ablauf nach, ob die
        # Frist abgelaufen ist und ob das Werkzeugprotokoll eine Wirkung
        # ausschließt — und übernimmt nur dann.
        recovery=Recovery(runs=runs, invocations=invocations, tools=tools),
        channel=KANAL,
    )

    try:
        ausgang = await advancer.advance(lauf, session_id=session.id, vorgegeben=payload.arguments)
    except AdvanceRejected as abgewiesen:
        raise HTTPException(
            status_code=_ABWEISUNGEN.get(abgewiesen.code, _ABWEISUNG_VORGABE),
            detail=abgewiesen.reason,
        ) from abgewiesen

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
