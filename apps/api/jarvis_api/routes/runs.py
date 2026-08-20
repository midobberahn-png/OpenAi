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
from jarvis_api.deps import Approvals, CurrentSession, Invocations, Policy, Runs, Tools
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
    BudgetTracker,
    NoEligibleModel,
    ToolExecutor,
    classify,
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

    jetzt = utc_now()
    lauf = Run(
        id=uuid4(),
        user_id=session.user_id,
        trigger=RunTrigger.USER,
        status=RunStatus.QUEUED,
        classification=einstufung,
        routing=routing,
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
async def read_run(run_id: UUID, session: CurrentSession, runs: Runs) -> RunView:
    """Ein einzelner eigener Lauf."""
    return _view(await _eigener_lauf(run_id, session, runs))


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
        seq=len(lauf.state.completed_steps) + 1,
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
