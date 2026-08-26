"""Port des Sitzungsspeichers.

Die Suche läuft ausschließlich über den **Hash** des Tokens. Das ist keine
Implementierungsvorliebe, sondern die Eigenschaft, auf die es ankommt: Wer die
Tabelle liest — über ein Backup, eine fehlgeleitete Abfrage, einen
Datenbankzugriff aus zweiter Hand —, findet dort nichts, womit er sich
anmelden könnte.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID

from jarvis_contracts import Session

__all__ = ["SessionLookup", "SessionStore"]


@dataclass(frozen=True)
class SessionLookup:
    """Eine gefundene Sitzung — und ob der vorgelegte Token der aktuelle war."""

    session: Session
    ist_vorgaenger: bool
    """``True``, wenn der Token bereits ersetzt wurde."""

    token_alter: timedelta
    """Wie alt der **aktuelle** Token ist — seit der letzten Rotation, sonst
    seit der Ausgabe.

    **Ein Alter und kein Zeitpunkt, und das ist der Unterschied.** Beide Fristen
    dieser Bauart werden gegen Zeitstempel gerechnet, die die *Datenbank*
    setzt. Käme der Vergleichszeitpunkt aus dem Prozess, hinge die Gültigkeit
    eines Tokens an der Uhrendrift zwischen beiden — der Fehler, der die
    Leerlaufmessung schon einmal eine Sitzung gekostet hat. Wer das Alter
    ausrechnet, wo der Zeitstempel steht, hat nur eine Uhr."""

    rotation_alter: timedelta | None = None
    """Wie lange die Rotation her ist. ``None``, wenn nie rotiert wurde — und
    die Grundlage, auf der das Überlappungsfenster gerechnet wird."""


class SessionStore(Protocol):
    """Persistenz der Sitzungen."""

    async def create(self, session: Session, token_hash: str) -> None:
        """Legt die Sitzung an. Der Klartext-Token wird nicht übergeben."""
        ...

    async def by_token_hash(self, token_hash: str) -> Session | None:
        """Sitzung zu einem Token-Hash. ``None`` heißt: unbekannt.

        Implementierungen dürfen hier **nicht** nach Gültigkeit filtern. Die
        Entscheidung, ob eine gefundene Sitzung noch gilt, gehört an eine
        Stelle — sonst gibt es zwei Meinungen darüber, und die eine davon
        vergisst irgendwann den Widerruf.
        """
        ...

    async def lookup(self, token_hash: str) -> SessionLookup | None:
        """Sucht über den **aktuellen und den vorigen** Hash (ADR-020).

        Getrennt von ``by_token_hash``, und der Unterschied ist die ganze
        Zusage: Wer den Vorgänger vorlegt, ist entweder eine Anfrage, die zum
        Zeitpunkt der Rotation schon unterwegs war — dann gilt sie im
        Überlappungsfenster —, oder eine **Kopie**, die zu spät kommt. Das
        auseinanderzuhalten braucht den Zeitpunkt der Rotation, und der steht
        nur hier.
        """
        ...

    async def rotate(self, session_id: UUID, *, alt_hash: str, neu_hash: str) -> bool:
        """Ersetzt den Token — aber nur, wenn ``alt_hash`` noch der aktuelle ist.

        Vergleiche-und-setze, und zwar in **einer** Anweisung. Zwei
        gleichzeitige Anfragen mit demselben Token: Eine trifft die Zeile
        (``True``), die andere trifft nichts (``False``) und arbeitet mit dem
        alten Token weiter, der im Fenster gilt. Wer erst liest und dann
        schreibt, hat dazwischen ein Fenster — an genau dieser Grenze sind in
        diesem Projekt bereits zwei Lücken entstanden.

        ``rotated_at`` setzt die **Datenbank** (``now()``): Das
        Überlappungsfenster wird gegen diesen Zeitstempel gerechnet, und zwei
        Uhren an einer Frist haben hier schon einmal eine Sitzung gekostet.
        """
        ...

    async def touch(self, session_id: UUID, now: datetime) -> None:
        """Setzt ``last_seen_at``. Verlängert die absolute Frist **nicht**."""
        ...

    async def revoke(self, session_id: UUID, now: datetime) -> None:
        """Widerruft eine Sitzung. Wirkt ab dem nächsten Zugriff."""
        ...

    async def revoke_all_for_user(self, user_id: UUID, now: datetime) -> int:
        """Widerruft alle Sitzungen eines Nutzers und meldet die Anzahl.

        Der Knopf für den Fall, dass ein Gerät verloren ist. Er muss ohne
        Kenntnis der einzelnen Sitzungen bedienbar sein — wer sein Telefon
        sucht, kennt keine Sitzungs-IDs.
        """
        ...

    async def active_for_user(self, user_id: UUID, now: datetime) -> list[Session]:
        """Offene Sitzungen für die Übersicht in der Oberfläche."""
        ...
