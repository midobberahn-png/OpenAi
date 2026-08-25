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

__all__ = ["PostgresCalendarReader", "PostgresCalendarStore"]


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


_DELETE = text(
    """
    DELETE FROM calendar_events
     WHERE id = :id
       AND user_id = :user_id
    RETURNING id
    """
)
"""``AND user_id = :user_id`` steht in der Anweisung und nicht in einer Prüfung
darüber.

Der Unterschied ist derselbe wie bei ``list_for_user`` und beim Laufspeicher:
Eine Zugehörigkeit, die sich weglassen lässt, wird irgendwann weggelassen —
und hier hieße das, fremde Termine zu löschen. Der Eigentümer ist an dieser
Stelle nicht wählbar; er steht seit dem Verdrahten fest.

``RETURNING id`` unterscheidet „gelöscht" von „war nicht da". Nach außen ist
das derselbe Zustand; für den Nutzer, der eine Rücknahme angestoßen hat, ist
es die Auskunft, ob sie etwas getan hat."""


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

    async def delete_event(self, event_id: UUID) -> bool:
        """Löscht einen Termin dieses Nutzers — für die Rücknahme.

        Eigene Transaktion wie beim Anlegen: Die Rücknahme wird bereits im
        Werkzeugprotokoll als verbraucht geführt, bevor sie hier ankommt. Eine
        Löschung, die mit der Transaktion eines Aufrufers zurückgerollt werden
        kann, hinterließe einen Aufruf, der als zurückgenommen gilt, und einen
        Termin, der noch steht.
        """
        try:
            async with self._engine.begin() as conn:
                treffer = await conn.execute(_DELETE, {"id": event_id, "user_id": self._user_id})
        except SQLAlchemyError as fehler:
            raise CalendarWriteFailed("Der Termin konnte nicht gelöscht werden.") from fehler
        return treffer.first() is not None


_LIST = text(
    """
    SELECT id, title, starts_at, ends_at, location, attendees
      FROM calendar_events
     WHERE user_id = :user_id
       AND ends_at > :von
       AND (CAST(:bis AS timestamptz) IS NULL OR starts_at < :bis)
     ORDER BY starts_at ASC, id ASC
     LIMIT :limit
    """
)
"""Drei Entscheidungen stecken in dieser Abfrage.

``user_id`` steht **in** der Anweisung, wie beim Löschen: Eine Zugehörigkeit,
die sich weglassen lässt, wird irgendwann weggelassen. Ein fremder Termin ist
hier nicht „verboten", sondern nicht vorhanden.

``ends_at > :von`` und nicht ``starts_at >= :von``: Gefragt ist, was in einem
Zeitfenster **liegt**, nicht was darin beginnt. Wer um 10 Uhr nachsieht, will
den Termin sehen, der um 9:30 begann und noch läuft — die andere Fassung
verschwiege ihn genau dann, wenn er stattfindet.

``CAST(:bis AS timestamptz)``: Ein Parameter, der nur in einem ``IS NULL``
vorkommt, hat für PostgreSQL keinen herleitbaren Typ und bricht sonst mit
``AmbiguousParameterError`` ab.

``id`` in der Sortierung ist kein Schmuck: Ohne einen eindeutigen zweiten
Schlüssel ist die Reihenfolge zweier gleich beginnender Termine unbestimmt, und
damit auch, welcher von beiden am Limit abgeschnitten wird.

**``notes`` steht nicht in der Auswahl.** Das Ergebnismodell führt das Feld
nicht — beim Anlegen geht es hinein und kommt nicht zurück —, und dieser
Endpunkt ist nicht der Ort, das zu ändern: Von allen Feldern eines Termins ist
die Notiz das, was am ehesten Fremdinhalt trägt, weil ein Modell sie in einem
kontaminierten Lauf formuliert hat. Sobald jemand einen Kalender *anzeigt*, ist
das die Frage, die dort entschieden gehört — mit einer Darstellung als Text und
einer Marke am Lauf, aus dem der Termin stammt."""


class PostgresCalendarReader:
    """Lesender Zugriff auf den Kalender **eines** Nutzers.

    **Eine eigene Klasse und keine zweite Methode am Speicher** — der Grund ist
    dieselbe Überlegung, die dem Werkzeug-Handler den Eigentümer vorenthält.
    ``ToolRegistry`` bekommt beim Verdrahten einen ``PostgresCalendarStore``;
    hätte der ein ``list_events``, könnte ein künftiger Handler den Kalender
    lesen, ohne dass jemand eine Fähigkeit erteilt hat. Nicht, weil es erlaubt
    wäre, sondern weil das Objekt es kann — und was ein Objekt kann, wird
    irgendwann benutzt.

    So gibt es dieses Können dort nicht. Wer liest, hält diese Klasse, und die
    hält niemand außer der HTTP-Route.

    **Und deshalb ist Lesen hier kein Werkzeug.** Ein ``calendar.read`` wäre
    etwas anderes als dieser Endpunkt: eine Fähigkeit, die ein Nutzer erteilen
    müsste, die ein Modell vorschlagen könnte, und deren Ergebnis als
    Fremdinhalt in einen Lauf liefe. Dieselbe Unterscheidung wie zwischen der
    Rücknahme und einem ``calendar.delete``.
    """

    def __init__(self, engine: AsyncEngine, *, user_id: UUID) -> None:
        self._engine = engine
        self._user_id = user_id

    async def list_events(
        self,
        *,
        von: datetime,
        bis: datetime | None = None,
        limit: int = 50,
    ) -> list[CalendarEvent]:
        """Termine dieses Nutzers im Fenster ``[von, bis)``, aufsteigend.

        ``von`` ist Pflicht und hat hier bewusst keinen Vorgabewert: Wo die
        Auskunft anfängt, ist eine Frage, die der Aufrufer beantwortet — ein
        stillschweigendes „alles" wäre bei einem wachsenden Kalender eine
        Abfrage ohne Obergrenze außer ``limit``, und damit eine Antwort, deren
        Ausschnitt niemand benannt hat.

        Wirft ``CalendarWriteFailed`` nicht: Lesen wirkt nicht. Scheitert die
        Datenbank, scheitert der Request — es gibt nichts zu unterscheiden.
        """
        async with self._engine.connect() as conn:
            zeilen = await conn.execute(
                _LIST,
                {"user_id": self._user_id, "von": von, "bis": bis, "limit": limit},
            )
            return [
                CalendarEvent(
                    id=zeile.id,
                    title=zeile.title,
                    starts_at=zeile.starts_at,
                    ends_at=zeile.ends_at,
                    location=zeile.location,
                    attendees=list(zeile.attendees or []),
                )
                for zeile in zeilen.all()
            ]
