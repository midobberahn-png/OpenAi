"""Kalender auf PostgreSQL.

Erfüllt ``CalendarStore``. Ein lokaler Kalender und kein Fremdsystem: Das erste
schreibende Werkzeug soll die Bestätigungskette erproben, nicht die Eigenheiten
von CalDAV. Ein Adapter für Google oder Apple erfüllt denselben Port, und alles
darüber bleibt unberührt.

**Der Nutzer wird beim Bau gebunden, nicht beim Aufruf.** ``create_event()``
hat keinen ``user_id``-Parameter — der Werkzeug-Handler bekommt nur die
Argumente des Aufrufs und soll den Eigentümer gar nicht benennen können. Ein
Feld dafür wäre dieselbe Lücke wie ``user_id`` in einem Request-Body, nur eine
Schicht tiefer.

**Eigene Transaktion.** Wie beim Lauf, beim Werkzeugprotokoll und beim
Grant-Verbrauch: Ein Termin ist die Wirkung, für die der Grant verbraucht
wurde. Läge er in der Request-Transaktion, könnte ein späterer Fehler ihn
zurückrollen — während der Anspruch verbraucht bleibt. Der Nutzer hätte dann
bestätigt, der Grant wäre weg, und der Termin existierte nicht.

Die umgekehrte Reihenfolge ist die gewollte: **höchstens einmal**. Stürzt der
Prozess zwischen Verbrauch und Anlage ab, gibt es keinen Termin und keine
zweite Chance ohne neue Bestätigung. Ein Termin, der vielleicht fehlt, ist
nachholbar; einer, der zweimal existiert und zweimal eingeladen hat, nicht.
"""

from __future__ import annotations

import json
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_core.ports.calendar import CalendarEvent, CalendarWriteFailed

__all__ = ["PostgresCalendarStore"]


_INSERT = text(
    """
    INSERT INTO calendar_events (
        id, user_id, title, starts_at, ends_at, location, notes, attendees
    ) VALUES (
        :id, :user_id, :title, :starts_at, :ends_at, :location, :notes,
        CAST(:attendees AS jsonb)
    )
    """
)


class PostgresCalendarStore:
    """Termine eines Nutzers."""

    def __init__(self, engine: AsyncEngine, *, user_id: UUID) -> None:
        self._engine = engine
        self._user_id = user_id
        """Der Eigentümer, festgelegt beim Verdrahten aus der Sitzung. Es gibt
        keine Methode, die einen anderen entgegennähme."""

    async def create_event(
        self,
        *,
        title: str,
        starts_at: datetime,
        ends_at: datetime,
        location: str | None = None,
        notes: str | None = None,
        attendees: list[str] | None = None,
    ) -> CalendarEvent:
        eingeladene = list(attendees or [])
        kennung = uuid4()
        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    _INSERT,
                    {
                        "id": kennung,
                        "user_id": self._user_id,
                        "title": title,
                        "starts_at": starts_at,
                        "ends_at": ends_at,
                        "location": location,
                        "notes": notes,
                        "attendees": json.dumps(eingeladene, ensure_ascii=False),
                    },
                )
        except SQLAlchemyError as fehler:
            # Die Meldung nach außen nennt keine Datenbankinterna. Der
            # Detailgrad gehört ins Protokoll, nicht in eine Antwort, die ein
            # Modell weiterverarbeitet.
            raise CalendarWriteFailed("Der Termin konnte nicht gespeichert werden.") from fehler

        return CalendarEvent(
            id=kennung,
            title=title,
            starts_at=starts_at,
            ends_at=ends_at,
            location=location,
            attendees=eingeladene,
        )
