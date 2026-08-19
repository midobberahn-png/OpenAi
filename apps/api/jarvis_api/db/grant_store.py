"""Grant-Verbrauch auf PostgreSQL.

Erfüllt ``GrantConsumer``. Die Einmaligkeitszusage liegt in der ``WHERE``-
Klausel und nicht in einer Prüfung davor — dieselbe Bauart wie der
Nonce-Verbrauch und der Ausführungsanspruch der Bestätigung. Ein
``SELECT … if consumed_at is None: UPDATE …`` wäre bei zwei gleichzeitigen
Anfragen ein Doppelverbrauch, und genau dieser Fall ist der interessante.

Warum die Invokationszeile und keine eigene Tabelle: ``invocation_id`` steht
schon im Grant, die Zeile wird vom Executor **vor** der Ausführung angelegt
(``InvocationStore.record()``), und ``pending_actions.invocation_id`` verweist
bereits darauf. Eine zweite Tabelle wäre ein zweiter Ort für dieselbe Wahrheit.

Fehlt die Zeile, liefert das UPDATE nichts und der Verbrauch scheitert. Das ist
beabsichtigt: Ein Grant, dessen Invokation nie protokolliert wurde, gehört zu
keinem nachvollziehbaren Aufruf.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

__all__ = ["PostgresGrantConsumer"]


_CONSUME = text(
    """
    UPDATE tool_invocations
       SET consumed_at = :now
     WHERE id = :id
       AND consumed_at IS NULL
    RETURNING id
    """
)


class PostgresGrantConsumer:
    """Löst einen Grant genau einmal ein — auch über Prozessgrenzen hinweg."""

    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def consume(self, invocation_id: UUID, *, now: datetime) -> bool:
        result = await self._conn.execute(_CONSUME, {"id": invocation_id, "now": now})
        return result.first() is not None
