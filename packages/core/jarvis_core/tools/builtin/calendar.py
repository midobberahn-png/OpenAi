"""``calendar.create`` — das erste **schreibende** Werkzeug.

``files.read`` hat alle Schichten in Betrieb genommen und dabei nichts nach
außen gewirkt. Dieses hier wirkt, und damit wird zum ersten Mal die Kette real,
für die das ganze Projekt gebaut ist: Vorschau, eingefrorener Payload-Hash,
Bestätigung durch einen Menschen, Sanierung eines kontaminierten Laufs, Grant,
Verbrauch, Ausführung.

**Der Punkt dieses Werkzeugs ist `outbound_fields`.**

Es ist der im Projekt durchgehend benutzte Beispielfall, und zwar wegen einer
Unterscheidung, die sich nicht auf Werkzeugebene treffen lässt:

    Termin ohne Teilnehmer  → private Notiz, vollständig prüfbar
                              (``structured``) → nach Bestätigung sanierbar
    Termin mit Teilnehmern  → verschickt Einladungen, also Außenwirkung
                              (``freeform``) → **nie** sanierbar

``payload_inspectability=STRUCTURED`` ist deshalb nur die *statische*
Einstufung. Die tatsächlich geltende liefert
``ToolSpec.effective_inspectability(arguments)``, und sie fällt strenger aus,
sobald ``attendees`` belegt ist.

Die Folge im kontaminierten Lauf: Wer eine Datei gelesen hat, darf danach einen
Termin für sich selbst anlegen — nach Bestätigung —, aber keinen mit
Teilnehmern. Der Weg von „Fremdinhalt gelesen" zu „Fremde bekommen eine
Einladung" ist damit strukturell zu, und das ist genau der Widerspruch, den
V1.0 nicht auflösen konnte (docs/16-v1.1-review.md §1).

**Undo, und warum es das vorher nicht gab.**

``supports_undo`` stand lange auf ``False``, und das war keine Eigenschaft des
Termins, sondern eine des Systems: Der Wert speist ``ActionPreview.reversible``
— also den Satz „das kannst du rückgängig machen“, den ein Mensch vor seiner
Bestätigung liest. Einen Einlöseweg für ``ToolResult.undo_token`` gab es nicht.
Eine Vorschau, die Umkehrbarkeit verspricht, während nichts umkehren kann, ist
schlimmer als eine, die schweigt: Sie senkt die Aufmerksamkeit genau an der
Stelle, an der die Bestätigung ihren Zweck hat.

Den Weg gibt es jetzt (``jarvis_core.policy.undo``), deshalb steht der Wert auf
``True``. Der Rücknahmepunkt ist die Kennung des angelegten Termins — sie geht
ins Werkzeugprotokoll und **nicht** an den Client. Zurückgenommen wird über die
Kennung des *Aufrufs*; wem er gehört, sagt der Lauf.

Was die Rücknahme ausdrücklich **nicht** ist: ein Löschrecht. Sie trifft genau
einen protokollierten, eigenen, höchstens 15 Minuten alten Aufruf, und sie
trifft ihn einmal. Ein Werkzeug ``calendar.delete`` wäre etwas anderes — eine
Fähigkeit, die ein Nutzer erteilen müsste und die ein Modell vorschlagen
könnte.

**Und sie holt keine Einladung zurück.** Ein Termin mit Teilnehmern hat
Einladungen verschickt; das Löschen des Eintrags macht das nicht ungeschehen.
Die Vorschau verspricht deshalb nicht mehr, als der Weg hält — was
``reversible`` bedeutet, ist „der Eintrag verschwindet", nicht „es ist nichts
passiert".
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from jarvis_contracts import (
    DataClass,
    PayloadInspectability,
    RiskLevel,
    ToolResult,
    ToolSpec,
)
from jarvis_core.ports.calendar import CalendarStore, CalendarWriteFailed

__all__ = ["CALENDAR_CREATE", "calendar_create_handler", "calendar_undo_handler"]

MAX_DAUER_STUNDEN = 24

CALENDAR_CREATE = ToolSpec(
    name="calendar.create",
    description=(
        "Legt einen Termin im Kalender an. Ohne Teilnehmer ist es eine private Notiz; "
        "mit Teilnehmern werden Einladungen verschickt."
    ),
    parameters={
        "type": "object",
        "properties": {
            "title": {"type": "string", "minLength": 1, "maxLength": 200},
            "start": {"type": "string", "format": "date-time"},
            "end": {"type": "string", "format": "date-time"},
            "location": {"type": "string", "maxLength": 300},
            "notes": {"type": "string", "maxLength": 5_000},
            "attendees": {
                "type": "array",
                "items": {"type": "string", "format": "email"},
                "description": (
                    "Eingeladene Personen. Belegt bedeutet Außenwirkung — der Termin ist "
                    "dann nicht mehr nach Bestätigung sanierbar."
                ),
            },
        },
        "required": ["title", "start", "end"],
        "additionalProperties": False,
    },
    scopes=["calendar.create"],
    risk=RiskLevel.MEDIUM,
    data_class=DataClass.P2,
    idempotent=False,
    requires_preview=True,
    payload_inspectability=PayloadInspectability.STRUCTURED,
    outbound_fields=["attendees"],
    # ``supports_undo=True``, seit es einen Einlöseweg gibt: Der Handler unten
    # notiert die Kennung des Termins als Rücknahmepunkt, und
    # ``UndoGateway`` löst sie ein — eigener Aufruf, 15 Minuten, einmal.
    supports_undo=True,
    rate_limit="30/hour",
    timeout_s=15.0,
)


def _zeitpunkt(wert: Any, feld: str) -> datetime:
    """Wandelt eine Zeitangabe um — oder sagt genau, was daran nicht stimmt.

    Ohne Zeitzone wird abgelehnt statt geraten. „14 Uhr" ohne Zone ist in einem
    System, das Termine für Menschen anlegt, keine Angabe, sondern eine
    Vermutung — und die falsche Vermutung verschiebt einen Termin um Stunden.
    """
    if isinstance(wert, datetime):
        zeit = wert
    else:
        try:
            zeit = datetime.fromisoformat(str(wert))
        except ValueError as ungueltig:
            raise ValueError(f"{feld}: keine gültige Zeitangabe ({wert!r}).") from ungueltig
    if zeit.tzinfo is None:
        raise ValueError(f"{feld}: Zeitzone fehlt. Ohne sie ist der Zeitpunkt nicht bestimmt.")
    return zeit


def calendar_create_handler(calendar: CalendarStore) -> Any:
    """Erzeugt den Handler zu einem Kalender.

    Der Store ist bereits an einen Nutzer gebunden; der Handler kennt keinen
    und kann deshalb keinen wählen.
    """

    async def handler(**kwargs: Any) -> ToolResult:
        try:
            beginn = _zeitpunkt(kwargs["start"], "start")
            ende = _zeitpunkt(kwargs["end"], "end")
        except (KeyError, ValueError) as ungueltig:
            return ToolResult(ok=False, error=str(ungueltig), display="Termin nicht angelegt")

        if ende <= beginn:
            return ToolResult(
                ok=False,
                error="Der Termin endet vor seinem Beginn.",
                display="Termin nicht angelegt",
            )
        if (ende - beginn).total_seconds() > MAX_DAUER_STUNDEN * 3600:
            # Nicht aus Prinzip, sondern weil ein mehrtägiger „Termin" fast
            # immer ein Tippfehler im Datum ist — und ein Kalender, der ihn
            # klaglos anlegt, verdeckt ihn.
            return ToolResult(
                ok=False,
                error=f"Termine über {MAX_DAUER_STUNDEN} Stunden werden nicht angelegt.",
                display="Termin nicht angelegt",
            )

        teilnehmer = [str(a) for a in (kwargs.get("attendees") or [])]

        try:
            termin = await calendar.create_event(
                title=str(kwargs["title"]),
                starts_at=beginn,
                ends_at=ende,
                location=(str(kwargs["location"]) if kwargs.get("location") else None),
                notes=(str(kwargs["notes"]) if kwargs.get("notes") else None),
                attendees=teilnehmer,
            )
        except CalendarWriteFailed as gescheitert:
            return ToolResult(ok=False, error=str(gescheitert), display="Termin nicht angelegt")

        eingeladen = (
            f", {len(termin.attendees)} eingeladen" if termin.attendees else ", ohne Teilnehmer"
        )
        return ToolResult(
            ok=True,
            # Der Rücknahmepunkt: die Kennung des Termins. Sie geht ins
            # Werkzeugprotokoll und nicht an den Client — ein Token, das der
            # Aufrufer zurückschickt, wäre eine Fähigkeit, die sich raten
            # lässt. Was hier steht, versteht nur der Undo-Handler unten.
            undo_token=str(termin.id),
            data={
                "id": str(termin.id),
                "title": termin.title,
                "starts_at": termin.starts_at.isoformat(),
                "ends_at": termin.ends_at.isoformat(),
                "attendees": termin.attendees,
            },
            display=f"{termin.title} am {termin.starts_at:%d.%m.%Y %H:%M}{eingeladen}",
            produced_data_class=DataClass.P2,
            # Ein selbst angelegter Termin ist kein Fremdinhalt: Was
            # zurückkommt, hat der Nutzer soeben bestätigt. ``taints_context``
            # bleibt aus — anders als bei ``files.read``.
            taints_context=False,
        )

    return handler


def calendar_undo_handler(calendar: CalendarStore) -> Any:
    """Nimmt einen angelegten Termin zurück.

    Ein Parameter, und er ist keine Argumentliste: Was zurückgenommen wird,
    steht nicht in Feldern, die jemand mitbringen könnte, sondern in dem, was
    der Handler oben selbst notiert hat.

    Der Store ist an denselben Nutzer gebunden wie beim Anlegen — auch diese
    Rücknahme kann keinen fremden Kalender treffen, weil sie den Adressaten
    nicht benennen kann.
    """

    async def handler(token: str) -> ToolResult:
        try:
            kennung = UUID(token)
        except ValueError:
            # Kein Angriffsfall: Der Token stammt aus der eigenen Datenbank.
            # Steht dort etwas anderes als eine Kennung, ist das ein Fehler
            # dieses Werkzeugs — und er soll nicht als „zurückgenommen" enden.
            return ToolResult(
                ok=False,
                error="Der Rücknahmepunkt ist keine Terminkennung.",
                display="Nicht zurückgenommen",
            )

        try:
            geloescht = await calendar.delete_event(kennung)
        except CalendarWriteFailed as gescheitert:
            return ToolResult(ok=False, error=str(gescheitert), display="Nicht zurückgenommen")

        if not geloescht:
            # Der Termin ist nicht mehr da. Für den Nutzer ist das der Zustand,
            # den er wollte — deshalb ``ok=True`` und ein Satz, der nichts
            # behauptet, was nicht geschehen ist.
            return ToolResult(
                ok=True,
                data={"deleted": False, "id": str(kennung)},
                display="Der Termin war bereits entfernt",
            )

        return ToolResult(
            ok=True,
            data={"deleted": True, "id": str(kennung)},
            display="Termin zurückgenommen",
        )

    return handler
