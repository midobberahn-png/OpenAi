"""Den eigenen Kalender lesen.

**Warum es diesen Endpunkt bisher nicht gab und warum jetzt.** Der Kalender
hatte einen Schreibweg (``calendar.create``) und einen Rücknahmeweg — aber
keinen, der ihn liest. Aufgefallen ist das nicht beim Entwurf, sondern beim
Browserdurchstich der Rücknahme: Ob der Termin danach tatsächlich weg ist,
konnte die Oberfläche nicht sehen. Gemessen wurde die Wirkung in der
pytest-Suite, indem sie Zeilen zählte. Ein System, dessen Zusage „das kannst du
rückgängig machen" nur die Datenbank überprüfen kann, hat sie nur halb.

**Das hier ist kein Werkzeug, und der Unterschied ist der Punkt.** Ein
``calendar.read`` wäre eine Fähigkeit: etwas, das ein Nutzer erteilen müsste,
das ein Modell vorschlagen könnte und dessen Ergebnis als Fremdinhalt in einen
Lauf liefe — mit allem, was daran hängt (Kontamination, Datenklasse,
Modellwahl). Dieser Endpunkt ist die Auskunft an den Menschen, der bereits
angemeldet ist, über seine eigenen Termine. Dieselbe Unterscheidung wie
zwischen der Rücknahme und einem ``calendar.delete``.

**Und deshalb liest er auch nicht über den Werkzeugspeicher.** Die Route hält
einen ``PostgresCalendarReader``; der ``PostgresCalendarStore``, den die
Registry bekommt, kann nicht lesen. Ein Handler kann den Kalender damit nicht
abfragen — nicht, weil es ihm verboten wäre, sondern weil das Objekt in seiner
Hand es nicht kann.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from jarvis_api.deps import CalendarView, CurrentSession

__all__ = ["router"]

router = APIRouter(prefix="/calendar", tags=["calendar"])

MAX_FENSTER_TAGE = 400


class CalendarRow(BaseModel):
    """Ein Termin, wie ihn die Oberfläche zeigt."""

    id: UUID
    title: str
    starts_at: datetime
    ends_at: datetime
    location: str | None
    attendees: list[str]
    """Steht auch dann in der Antwort, wenn die Liste leer ist — und das ist
    der sicherheitsrelevante Fall: ``[]`` heißt, dass tatsächlich niemand
    eingeladen wurde. Ein Feld, das nur bei Belegung erschiene, könnte das
    nicht zeigen; es unterschiede „niemand eingeladen" nicht von „ich sage
    nichts dazu"."""


@router.get("", response_model=list[CalendarRow])
async def list_events(
    session: CurrentSession,
    kalender: CalendarView,
    von: datetime | None = Query(default=None, alias="from"),
    bis: datetime | None = Query(default=None, alias="to"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[CalendarRow]:
    """Eigene Termine im Fenster ``[from, to)``, aufsteigend nach Beginn.

    **Ohne ``from`` beginnt das Fenster jetzt.** Ein Kalender beantwortet
    „was kommt"; wer Vergangenes will, sagt es. Der Vorgabewert ist damit die
    Frage, die fast immer gemeint ist — und er hält die Antwort klein, ohne
    dass ein Ausschnitt entsteht, den niemand benannt hat.

    Ein Termin **zählt zum Fenster, wenn er darin liegt**, nicht wenn er darin
    beginnt: Wer um 10 Uhr nachsieht, sieht den Termin, der um 9:30 begann und
    noch läuft.

    **Zeitzone ist Pflicht.** Eine Angabe ohne sie wird abgelehnt statt
    geraten — dieselbe Entscheidung wie beim Anlegen (``calendar.create``).
    „14 Uhr" ohne Zone ist keine Angabe, sondern eine Vermutung, und die
    falsche verschiebt die Antwort um Stunden.

    **Fremde Termine sind nicht verboten, sondern nicht vorhanden.** Der
    Eigentümer steht in der Abfrage und kommt aus der Sitzung; es gibt keinen
    Parameter, mit dem sich ein anderer benennen ließe.
    """
    for wert, feld in ((von, "from"), (bis, "to")):
        if wert is not None and wert.tzinfo is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"{feld}: Zeitzone fehlt. Ohne sie ist der Zeitpunkt nicht bestimmt.",
            )

    beginn = von if von is not None else datetime.now(UTC)
    if bis is not None:
        if bis <= beginn:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="to muss nach from liegen.",
            )
        if (bis - beginn).days > MAX_FENSTER_TAGE:
            # Nicht aus Prinzip: ``limit`` begrenzt die Antwort ohnehin. Aber
            # ein Fenster über Jahrzehnte ist ein Scan über die Tabelle, dessen
            # Ergebnis danach auf 200 Zeilen fällt — teuer für eine Auskunft,
            # die so niemand gemeint hat.
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Das Fenster ist auf {MAX_FENSTER_TAGE} Tage begrenzt.",
            )

    return [
        CalendarRow(
            id=termin.id,
            title=termin.title,
            starts_at=termin.starts_at,
            ends_at=termin.ends_at,
            location=termin.location,
            attendees=termin.attendees,
        )
        for termin in await kalender.list_events(von=beginn, bis=bis, limit=limit)
    ]
