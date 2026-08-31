"""Port des Postfachs — Lesen, und nur Lesen.

**Der Zuschnitt ist die Aussage.** Es gibt hier kein ``senden``, kein
``loeschen``, kein ``markieren``. Der Scope-Katalog führt `mail.send` und
`mail.delete` seit dem ersten Entwurf; dass sie in diesem Port fehlen, heißt:
Kein Adapter kann sie, und kein Handler kann sie versehentlich aufrufen. Die
Erlaubnis wäre die eine Hälfte — die andere ist, dass das Objekt in der Hand
des Handlers es nicht kann.

**Die Zugangsdaten kommen nicht hier vor.** Ein Adapter bekommt eine Quelle,
die einen gültigen Zugriffstoken liefert, und nichts weiter: keine Konto-ID,
keinen Erneuerungstoken, keine Anbieterkonfiguration. Was er nicht hat, kann
er nicht weitergeben — und ein Adapter, der ein Konto benennen könnte, wäre
die Stelle, an der aus einem fremden Argument ein fremdes Postfach wird.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

__all__ = ["MailAccessDenied", "MailMessage", "MailReader", "MailUnavailable"]


class MailAccessDenied(Exception):
    """Der Zugriff ist nicht möglich, und daran ändert ein Wiederholen nichts.

    Kein verbundenes Konto, die Zustimmung deckt das Postfach nicht ab, die
    Zugangsdaten sind abgelaufen. Getrennt von ``MailUnavailable``, weil der
    Nutzer hier etwas tun muss und dort nur warten.
    """


class MailUnavailable(Exception):
    """Der Anbieter war gerade nicht erreichbar."""


@dataclass(frozen=True, slots=True)
class MailMessage:
    """Eine Nachricht, so viel davon wie ein Modell braucht.

    **Kein Feld für Anhänge, keine Rohkopfzeilen.** Beides wäre mehr Angriffs-
    fläche als Nutzen: Ein Anhang ist Fremdinhalt in einem Format, das dieses
    System nicht liest, und Kopfzeilen sind der Ort, an dem eine untergeschobene
    Anweisung am unauffälligsten steht. Wer sie braucht, baut ein eigenes
    Werkzeug — und begründet es dann.
    """

    id: str
    absender: str
    betreff: str
    datum: datetime | None
    """``None``, wenn die Kopfzeile fehlt oder unlesbar ist. Ein geratenes
    Datum wäre schlimmer als keines: Es sähe aus wie eine Auskunft."""
    text: str
    gekuerzt: bool


class MailReader(Protocol):
    async def lesen(self, *, anzahl: int, suche: str | None = None) -> list[MailMessage]:
        """Die jüngsten Nachrichten, optional gefiltert.

        ``suche`` geht als Suchausdruck an den Anbieter. Das ist bewusst so
        und trotzdem die heikelste Stelle dieses Ports: Ein Modell formuliert
        ihn. Was ein Suchausdruck **nicht** kann, ist ein anderes Postfach
        öffnen — der Token bestimmt das Konto, nicht die Anfrage.
        """
        ...
