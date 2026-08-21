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
    Plan,
    PlanStep,
    Run,
    RunStatus,
    RunTrigger,
    Session,
    StepOutcome,
    TaintLevel,
)
from jarvis_core.orchestrator import (
    ArgumentsUnavailable,
    BudgetTracker,
    NoEligibleModel,
    ResponseUnavailable,
    ToolExecutor,
    classify,
    plan_turn,
    route,
    utc_now,
)
from jarvis_core.orchestrator.plan_arguments import PlanArgumentSource
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

    ``needs_model`` blieb übrig für den einen Schritttyp, den dieser Endpunkt
    weiterhin nicht ausführt: ``agent``. Ein Sub-Agent wählt seine Werkzeuge
    selbst — das ist eine andere und größere Fläche als „ein Modell füllt die
    Argumente eines angekündigten Schrittes", und ``ModelLoop`` hat dafür noch
    keinen Endpunkt. ``llm``-Schritte sind seit dem Antwortschritt ausführbar
    und werden deshalb wie jeder andere fällige Schritt als ``ready`` geführt.
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
        elif schritt.kind == "agent":
            stand = "needs_model"
        elif schritt.kind == "llm":
            # Kein Angebotsabgleich: Der Schritt bekommt kein Werkzeug zu sehen
            # und kann deshalb an keinem fehlenden scheitern.
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
    antworten: ModelResponse,
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
    if schritt_plan.kind == "agent":
        # Der einzige Schritttyp, den dieser Endpunkt nicht ausführt. ``ModelLoop``
        # ist gebaut und hat keinen Endpunkt — ein Sub-Agent wählt seine Werkzeuge
        # selbst, und das ist eine andere und größere Fläche als „ein Modell füllt
        # die Argumente eines angekündigten Schrittes".
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Schritt {schritt_plan.seq} delegiert an den Sub-Agenten "
                f"{schritt_plan.target!r}. Die Agentenschleife hat noch keinen Endpunkt."
            ),
        )

    if schritt_plan.kind != "tool" and payload.arguments is not None:
        # Nicht stillschweigend verwerfen. Ein Aufrufer, der Argumente für einen
        # Schritt schickt, der keine kennt, hat eine andere Vorstellung vom Plan
        # als der Plan — und ein Feld, das ignoriert wird, ist eine
        # Falschaussage über das, was gleich passiert.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Schritt {schritt_plan.seq} ist vom Typ {schritt_plan.kind!r} und nimmt "
                'keine Argumente entgegen. Ohne „arguments" formuliert das Modell die '
                "Antwort."
            ),
        )

    if schritt_plan.kind == "tool":
        angebot = await policy.effective_tools(
            session.user_id, tools.names(), taint=lauf.taint_level
        )
        if schritt_plan.target not in angebot:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Schritt {schritt_plan.seq} ({schritt_plan.target}) ist nicht mehr "
                    "durchführbar — der Lauf hat sich seit der Planung verändert."
                ),
            )

    status_vorher = lauf.status

    # **Der Anspruch auf den Schritt — vor jeder Wirkung.**
    #
    # Aus einem externen Prüfbefund, und er sitzt an derselben Achse wie der
    # Grant-Verbrauch: Wo entsteht die Wirkung, und wie weit ist der Anspruch
    # davon entfernt? Bei ``runs.save()`` ist er einen Schritt zu spät. Sechs
    # parallele Aufrufe eines geplanten ``calendar.create`` ergaben sechs
    # Termine; fünf Aufrufer bekamen „neu laden und wiederholen", während ihr
    # Termin bereits im Kalender stand.
    #
    # Verdeckt war das durch einen Zufall: Jede Sitzungsprüfung schreibt
    # ``last_seen_at`` derselben Zeile in der Request-Transaktion und
    # serialisiert damit alle Requests *einer* Sitzung. Zwei Sitzungen — zwei
    # Geräte, zwei Fenster — und der Schutz ist weg. Ein Nebeneffekt, den
    # niemand entworfen hat, ist keine Zusicherung.
    if not await runs.claim_step(lauf.id, schritt_plan.seq, erwarteter_status=status_vorher):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Schritt {schritt_plan.seq} wird bereits ausgeführt oder der Lauf hat "
                "sich verändert. Neu laden und nachsehen, was daraus geworden ist."
            ),
        )

    executor = ToolExecutor(
        registry=tools, policy=policy, gateway=approvals, invocations=invocations
    )
    tracker = BudgetTracker(lauf.budget, usage=lauf.usage)
    if lauf.status is RunStatus.QUEUED:
        lauf = executor.start(lauf, tracker)

    # Ab hier gibt jeder Weg, der **nicht** bis zum ``save`` kommt, den Anspruch
    # zurück. ``save`` selbst gibt ihn frei, weil der gespeicherte Zustand
    # ``current_step`` nicht mehr führt — bei einem erledigten Schritt setzt
    # ``with_step_done`` ihn auf ``None``.
    #
    # Ein ``finally`` wäre hier falsch: Es gäbe den Anspruch auch dann zurück,
    # wenn der Schritt gewirkt hat.
    try:
        if schritt_plan.kind != "tool":
            return await _antwortschritt(
                lauf,
                tracker,
                executor=executor,
                runs=runs,
                antworten=antworten,
                plan=plan,
                schritt_plan=schritt_plan,
                status_vorher=status_vorher,
            )
        return await _werkzeugschritt(
            lauf,
            tracker,
            executor=executor,
            runs=runs,
            tools=tools,
            modell=modell,
            plan=plan,
            schritt_plan=schritt_plan,
            session=session,
            vorgegeben=payload.arguments,
            status_vorher=status_vorher,
        )
    except BaseException:
        # Jeder Weg, der nicht bis zum ``save`` kommt, gibt den Anspruch zurück.
        # Ein ``finally`` wäre falsch: Es gäbe ihn auch nach getaner Wirkung frei.
        await runs.release_step(lauf.id)
        raise


async def _werkzeugschritt(
    lauf: Run,
    tracker: BudgetTracker,
    *,
    executor: ToolExecutor,
    runs: PostgresRunStore,
    tools: ToolRegistry,
    modell: PlanArgumentSource,
    plan: Plan,
    schritt_plan: PlanStep,
    session: Session,
    vorgegeben: dict[str, Any] | None,
    status_vorher: RunStatus,
) -> StepView:
    """Ein geplanter Werkzeugschritt — Argumente aus dem Request oder vom Modell.

    Ausgelagert als Gegenstück zu ``_antwortschritt``, damit der Anspruch auf den
    Schritt **eine** Freigabestelle hat. Zwei Fehlerpfade mit je eigenem
    ``release_step`` wären zwei Gelegenheiten, einen zu vergessen — und ein
    vergessener Anspruch blockiert den Lauf dauerhaft.
    """
    # Die Argumente — aus dem Request oder aus dem Modell.
    argumente = vorgegeben
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

    # Abgeschlossen wird nur, wenn der Schritt auch durchlief. Ein blockierter
    # oder wartender Schritt lässt den Plan offen — und ein Lauf, der auf eine
    # Bestätigung wartet, darf nicht als erledigt gelten.
    endstand = ausgefuehrt.run
    if ausgefuehrt.executed:
        endstand = _falls_fertig(endstand, tracker, executor=executor, plan=plan)

    await _gespeichert(runs, endstand, status_vorher)

    ergebnis = ausgefuehrt.result
    return StepView(
        status=ausgefuehrt.status,
        reason=ausgefuehrt.reason,
        run_status=str(endstand.status),
        taint_level=str(endstand.taint_level),
        display=ergebnis.display if ergebnis else "",
        data=ergebnis.data if ergebnis else None,
        data_class=str(ergebnis.produced_data_class) if ergebnis else None,
        action_id=str(ausgefuehrt.pending.id) if ausgefuehrt.pending else None,
        code=ausgefuehrt.code,
    )


async def _antwortschritt(
    lauf: Run,
    tracker: BudgetTracker,
    *,
    executor: ToolExecutor,
    runs: PostgresRunStore,
    antworten: ModelResponse,
    plan: Plan,
    schritt_plan: PlanStep,
    status_vorher: RunStatus,
) -> StepView:
    """Der abschließende ``llm``-Schritt: Ein Modell formuliert die Antwort.

    **Was diesen Schritt vom Werkzeugschritt unterscheidet, ist eine
    Abwesenheit.** Es gibt keine Policy-Entscheidung, keine Bestätigung, keinen
    Grant und keinen Verbrauch — weil es nichts auszuführen gibt. Dem Modell
    wird kein Werkzeug angeboten, und es kann deshalb nichts vorschlagen.

    Das ist keine ausgelassene Prüfung, sondern eine, die kein Objekt hätte:
    Die Policy Engine entscheidet über Werkzeugaufrufe. Ein Schritt, der Text
    erzeugt und ihn dem Eigentümer der Daten zeigt, ist keiner.

    **Was bleibt, ist die Herkunft.** Stammt der Text aus einem kontaminierten
    Lauf, kann er eine untergeschobene Anweisung an den *Menschen* enthalten.
    Dagegen hilft das Taint-Tracking nicht — es sperrt Werkzeuge, und hier ist
    keines beteiligt. Der Lauf wird deshalb auf ``tainted`` fortgeschrieben,
    damit ``GET /runs/{id}`` es zeigt und eine Oberfläche den Text kennzeichnen
    kann. Diese Lücke schließt der Kern nicht; er liefert die Auskunft, ohne
    die niemand sie schließen kann.
    """
    try:
        antwort = await antworten.for_step(
            step=schritt_plan,
            run=lauf,
            goal=plan.goal,
            # Wie beim Werkzeugschritt: das geroutete Modell des Laufs.
            model=lauf.routing.model if lauf.routing else "",
        )
    except ResponseUnavailable as ohne:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ohne)) from ohne

    tracker.record_model_call(
        tokens_in=antwort.usage.tokens_in,
        tokens_out=antwort.usage.tokens_out,
        cost_eur=antwort.usage.cost_eur,
    )
    tracker.record_step()

    if antwort.taints:
        lauf = lauf.with_taint(TaintLevel.TAINTED)

    fertig = lauf.model_copy(
        update={
            "state": lauf.state.with_step_done(
                StepOutcome(
                    seq=schritt_plan.seq,
                    ok=True,
                    # Die Zusammenfassung ist gekappt (``StepOutcome.summary``
                    # fasst 2000 Zeichen); der vollständige Text steht in
                    # ``partial_output``. Zwei Felder, weil das eine in den
                    # Kontext des nächsten Schrittes geht und das andere an den
                    # Nutzer.
                    summary=antwort.text[:2000],
                    finished_at=utc_now(),
                )
            ).model_copy(update={"partial_output": antwort.text}),
            "usage": tracker.usage,
        }
    )
    fertig = _falls_fertig(fertig, tracker, executor=executor, plan=plan)
    await _gespeichert(runs, fertig, status_vorher)

    return StepView(
        status="executed",
        reason="Antwort formuliert.",
        run_status=str(fertig.status),
        taint_level=str(fertig.taint_level),
        display=antwort.text,
        data=None,
        data_class=None,
        action_id=None,
        code=None,
    )


async def _gespeichert(runs: PostgresRunStore, lauf: Run, erwartet: RunStatus) -> None:
    """Fortschreiben gegen den Status, der beim Laden galt.

    Läuft parallel ein zweiter Schritt, gewinnt genau einer; der andere bekommt
    409 statt eines überschriebenen Laufs.
    """
    try:
        await runs.save(lauf, erwarteter_status=erwartet)
    except RunStateConflict as konflikt:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Der Lauf wurde parallel verändert. Neu laden und wiederholen.",
        ) from konflikt


def _falls_fertig(lauf: Run, tracker: BudgetTracker, *, executor: ToolExecutor, plan: Plan) -> Run:
    """Schließt den Lauf ab, wenn der Plan nichts mehr hergibt.

    **Bis zu diesem Block hat kein Lauf je einen Endzustand erreicht.**
    ``RunStatus.COMPLETED`` kam im gesamten Anwendungscode nicht vor; jeder Lauf
    blieb in ``executing`` stehen. Aufgefallen ist das nicht, weil kein Plan
    abschließbar war — sein letzter Schritt ist stets ein ``llm``-Schritt, und
    der war nicht ausführbar.

    Die Frage „ist noch etwas fällig?" wird über dieselbe Funktion beantwortet
    wie beim Betreten des Endpunkts (``Plan.ready_steps``). Eine zweite Fassung
    dieser Rechnung wäre die Stelle, an der ein Lauf entweder zu früh
    abgeschlossen wird oder ewig offen bleibt.

    Optionale Schritte sind dabei kein Sonderfall: Was ``ready_steps`` nicht
    mehr nennt, ist nicht mehr fällig — ob es lief oder übersprungen wurde,
    entscheidet dort und nicht hier.
    """
    if plan.ready_steps(lauf.state.completed_seqs):
        return lauf
    return executor.finish(lauf, tracker)
