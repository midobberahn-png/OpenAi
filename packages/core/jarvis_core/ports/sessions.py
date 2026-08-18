"""Port des Sitzungsspeichers.

Die Suche läuft ausschließlich über den **Hash** des Tokens. Das ist keine
Implementierungsvorliebe, sondern die Eigenschaft, auf die es ankommt: Wer die
Tabelle liest — über ein Backup, eine fehlgeleitete Abfrage, einen
Datenbankzugriff aus zweiter Hand —, findet dort nichts, womit er sich
anmelden könnte.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from jarvis_contracts import Session

__all__ = ["SessionStore"]


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
