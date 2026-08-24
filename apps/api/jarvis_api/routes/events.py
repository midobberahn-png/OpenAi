"""Der Ereignisstrom — Server-Sent Events.

Bis hierher pollte die Oberfläche alle drei Sekunden. Das ist die ehrliche
Fassung, solange es nichts anderes gibt, und sie hat eine Eigenschaft, die man
nicht wegreden kann: Sie zeigt nicht den Moment, in dem etwas passiert. Bei
einem System, das auf eine Bestätigung wartet, ist das der Moment, auf den es
ankommt.

**SSE und nicht WebSocket** (ADR-016). Der ausschlaggebende Grund ist die
Anmeldung: Die Sitzung liegt in einem ``HttpOnly``-Cookie, und ``EventSource``
schickt es bei gleicher Herkunft mit — die Verbindung ist angemeldet wie jeder
andere Aufruf. Ein WebSocket-Handshake aus dem Browser kann keine eigenen
Header setzen; wer ihn authentifizieren will, legt ein Token in die URL und
damit in jedes Zugriffsprotokoll.

**Der Strom trägt Hinweise, keine Zustände.** Jede Nachricht sagt, *dass* sich
etwas geändert hat; was gilt, holt die Oberfläche über die API. Eine verpasste
Nachricht kostet dann Latenz und keine Richtigkeit — und das ist die einzige
Fassung, die zu docs/10-ui.md §4 passt: Der Server ist die Quelle der Wahrheit.

**Und er trägt keine Nonce.** ``ActionWaiting`` sagt, dass eine Bestätigung
wartet, und nennt ihre Kennung; die Bestätigung selbst holt die Oberfläche über
``GET /actions``, wo die Sitzung entscheidet, was sie zu sehen bekommt. Die
vollständige ``PendingAction`` über einen **nutzerweiten** Kanal zu schicken
hieße, ein sitzungsgebundenes Geheimnis an alle Geräte zu verteilen.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse

from jarvis_api.deps import CurrentSession, Events

__all__ = ["router"]

router = APIRouter(prefix="/events", tags=["events"])


@router.get("")
async def stream(session: CurrentSession, events: Events) -> StreamingResponse:
    """Der Ereignisstrom des angemeldeten Nutzers.

    **Die Kennung kommt aus der Sitzung.** Es gibt keinen Parameter, mit dem
    sich ein fremder Strom abonnieren ließe — dieselbe Regel wie überall
    (``identity-derives-from-session``), und hier mit besonderem Gewicht: Ein
    Strom ist eine dauerhafte Leitung, und was einmal falsch verbunden ist,
    bleibt es.

    **Ohne ``id:``-Feld, und das ist Absicht.** SSE kennt eine Wiederaufnahme
    über ``Last-Event-ID``; Redis Pub/Sub hat aber kein Gedächtnis, und was der
    Browser nachfordern würde, gäbe es nicht mehr. Ein Feld, das eine
    Wiederaufnahme verspricht, die niemand einlösen kann, ist schlechter als
    keines: Der Browser hörte auf, selbst nachzuladen. Die Lückenerkennung
    läuft deshalb über ``seq`` im Rumpf — bemerkt der Client eine Lücke, lädt
    er neu und ist danach richtig statt ungefähr.
    """
    if events is None:
        # Ohne Redis kein Strom. Ausdrücklich ein Fehler und kein leerer
        # Kanal: Eine Oberfläche, die auf eine stumme Leitung wartet, hört auf
        # nachzuladen — und zeigt dann einen Stand von vorhin.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Der Ereignisstrom ist nicht verfügbar; die Oberfläche lädt weiter nach.",
        )

    async def leitung() -> AsyncIterator[bytes]:
        # Ein Kommentar zu Beginn: Er schließt die Verbindung im Browser auf,
        # bevor das erste Ereignis kommt — sonst gilt sie als „noch nicht
        # verbunden", und die Statusanzeige stünde minutenlang falsch.
        yield b": verbunden\n\n"
        async for zeile in events.subscribe(session.user_id):
            if zeile == "":
                # Lebenszeichen. Ohne es schließen Proxys eine stille
                # Verbindung, und der Browser verbindet sich neu, ohne dass
                # etwas passiert wäre.
                yield b": still\n\n"
                continue
            yield f"data: {zeile}\n\n".encode()

    return StreamingResponse(
        leitung(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            # Ein Proxy, der puffert, macht aus einem Ereignisstrom eine
            # Sammelsendung — und aus „sofort" ein „irgendwann".
            "X-Accel-Buffering": "no",
        },
    )
