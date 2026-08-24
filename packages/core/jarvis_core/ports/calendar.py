"""Port des Kalenders.

Der Kern kennt weder CalDAV noch eine Tabelle. Was er kennt, ist die Zusage:
**Ein hier angelegter Termin gehört dem Nutzer, an den dieser Port gebunden
ist.**

**Der Nutzer ist kein Argument.** Das ist die wichtigste Eigenschaft dieses
Ports und der Grund, warum er so und nicht anders geschnitten ist.

Ein Werkzeug-Handler bekommt ausschließlich die Argumente des Aufrufs
(``registry.execute()`` ruft ``handler(**auth.arguments)``). Er hat keinen
Nutzerkontext — und soll auch keinen bekommen. Ein Feld ``user_id`` in den
Argumenten wäre dieselbe Lücke wie ein ``user_id`` im Request-Body, nur eine
Schicht tiefer: Wer den Eigentümer mitbringt, bestimmt ihn.

Stattdessen wird die Implementierung **beim Verdrahten** an den angemeldeten
Nutzer gebunden (``deps.tool_registry`` baut sie aus ``CurrentSession``). Ein
Handler kann damit gar nicht in einen fremden Kalender schreiben — nicht, weil
er es nicht darf, sondern weil er den Adressaten nicht benennen kann.

Dieselbe Bauart wie beim Dateizugriff: Dort sind die Wurzeln fest verdrahtet,
hier ist es der Eigentümer.

**Außenwirkung hängt an den Teilnehmern, nicht am Werkzeug.** Ein Termin ohne
Teilnehmer ist eine private Notiz; derselbe Termin mit Teilnehmern verschickt
Einladungen. Diese Unterscheidung trifft nicht dieser Port, sondern
``ToolSpec.outbound_fields`` — sie entscheidet, ob ein Payload nach Bestätigung
sanierbar ist. Die Implementierung hier muss sie nur ehrlich abbilden: Wer
Teilnehmer bekommt, lädt sie ein.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict

__all__ = ["CalendarEvent", "CalendarStore", "CalendarWriteFailed"]


class CalendarWriteFailed(Exception):
    """Der Termin konnte nicht angelegt werden.

    Betriebsstörung, kein Sicherheitsvorfall — anders als bei
    ``FileAccessDenied`` gibt es hier nichts abzuwehren: Wer bis hierher kommt,
    hat Policy, Bestätigung und Grant hinter sich. Was scheitern kann, ist die
    Ablage.
    """


class CalendarEvent(BaseModel):
    """Ein angelegter Termin."""

    model_config = ConfigDict(frozen=True)

    id: UUID
    title: str
    starts_at: datetime
    ends_at: datetime
    location: str | None = None
    attendees: list[str] = []
    """Leer heißt: private Notiz, keine Einladung. Der Unterschied ist
    sicherheitsrelevant und deshalb im Ergebnis sichtbar — die Oberfläche soll
    zeigen können, dass tatsächlich niemand eingeladen wurde."""


class CalendarStore(Protocol):
    """Schreibender Zugriff auf den Kalender **eines** Nutzers."""

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
        """Legt einen Termin an.

        Kein ``user_id``-Parameter, und das ist Absicht — siehe Modulkopf.

        Wirft ``CalendarWriteFailed``, wenn die Ablage scheitert.
        """
        ...

    async def delete_event(self, event_id: UUID) -> bool:
        """Löscht einen Termin **dieses** Nutzers. Für die Rücknahme.

        Auch hier kein ``user_id``-Parameter, und hier wiegt es schwerer als
        beim Anlegen: Wer beim Löschen den Eigentümer mitbringt, löscht fremde
        Termine. Die Einschränkung gehört deshalb in die Abfrage der
        Implementierung und nicht in eine Prüfung darüber.

        ``False`` heißt: Es gab nichts zu löschen — die Kennung gehört einem
        anderen, oder der Termin ist bereits weg. Kein Fehler und kein
        Unterschied nach außen: Beides heißt „danach ist er nicht mehr da", und
        die Unterscheidung nach außen zu tragen hieße, die Existenz fremder
        Termine zu bestätigen.

        **Bewusst kein allgemeines Löschwerkzeug.** Diese Methode hat genau
        einen Aufrufer: den Undo-Handler von ``calendar.create``, und der
        bekommt seine Kennung aus dem Werkzeugprotokoll. Ein Werkzeug
        ``calendar.delete`` wäre etwas anderes — eine Fähigkeit, die ein Nutzer
        erteilen müsste, und die ein Modell vorschlagen könnte.
        """
        ...
