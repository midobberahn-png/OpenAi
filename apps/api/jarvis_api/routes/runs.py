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
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from jarvis_api.db.run_store import PostgresRunStore
from jarvis_api.deps import CurrentSession, Runs
from jarvis_contracts import BUDGET_PRESETS, Run, RunStatus, RunTrigger, Session
from jarvis_core.orchestrator import classify, utc_now

__all__ = ["router"]

router = APIRouter(prefix="/runs", tags=["runs"])


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
async def create_run(payload: RunRequest, session: CurrentSession, runs: Runs) -> RunView:
    """Legt einen Lauf an — für den angemeldeten Nutzer.

    Die Einstufung geschieht sofort und deterministisch. Sie bestimmt die
    Datenklasse des Laufs, und die ist die Obergrenze für alles, was später in
    ihm geschieht: Sie nachträglich zu setzen hieße, sie nachträglich zu
    behaupten.

    Der Lauf bleibt ``queued``. Ausgeführt wird er nicht — es gibt noch keine
    Werkzeuge und keinen Arbeiter, der ihn aufnähme.
    """
    einstufung = classify(payload.input, channel=payload.channel)
    jetzt = utc_now()
    lauf = Run(
        id=uuid4(),
        user_id=session.user_id,
        trigger=RunTrigger.USER,
        status=RunStatus.QUEUED,
        classification=einstufung,
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
