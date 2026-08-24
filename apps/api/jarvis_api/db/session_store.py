"""Sitzungsspeicher auf PostgreSQL.

Gesucht wird ausschließlich über den Token-Hash. Die Klartext-Spalte existiert
nicht — nicht als Vorsichtsmaßnahme, sondern weil es sie nie gab: Der Manager
übergibt nur den Fingerabdruck.

Bewusst **ohne** Gültigkeitsfilter in der Abfrage. Der Port schreibt das vor,
und der Grund ist die Erfahrung mit zwei Meinungen über denselben Zustand: Ein
Speicher, der abgelaufene Sitzungen selbst ausblendet, und ein Manager, der
zusätzlich prüft, driften auseinander — und dann ist unklar, welche der beiden
Prüfungen den Widerruf vergessen hat.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from jarvis_contracts import Session

__all__ = ["PostgresSessionStore"]


_INSERT = text(
    """
    INSERT INTO sessions (
        id, user_id, token_hash, client, channel,
        created_at, last_seen_at, expires_at
    ) VALUES (
        :id, :user_id, :token_hash, :client, :channel,
        :created_at, :last_seen_at, :expires_at
    )
    """
)

_SELECT_COLUMNS = """
    id, user_id, client, channel, created_at, last_seen_at, expires_at, revoked_at
"""

_BY_HASH = text(f"SELECT {_SELECT_COLUMNS} FROM sessions WHERE token_hash = :h")

_TOUCH = text("UPDATE sessions SET last_seen_at = :now WHERE id = :id AND revoked_at IS NULL")
"""``last_seen_at`` wandert, ``expires_at`` nicht. Wer eine gestohlene Sitzung
aktiv hält, hält sie damit nicht unbegrenzt am Leben."""

_REVOKE = text("UPDATE sessions SET revoked_at = :now WHERE id = :id AND revoked_at IS NULL")

_REVOKE_ALL = text(
    "UPDATE sessions SET revoked_at = :now WHERE user_id = :u AND revoked_at IS NULL"
)

_ACTIVE = text(
    f"SELECT {_SELECT_COLUMNS} FROM sessions "
    "WHERE user_id = :u AND revoked_at IS NULL ORDER BY last_seen_at DESC"
)


def _to_session(row: Any) -> Session:
    return Session(
        id=row.id,
        user_id=row.user_id,
        client=row.client,
        channel=row.channel,
        created_at=row.created_at,
        last_seen_at=row.last_seen_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
    )


class PostgresSessionStore:
    """Sitzungen — Anlegen und Widerrufen im Request, ``touch`` daneben."""

    def __init__(self, conn: AsyncConnection, *, engine: AsyncEngine | None = None) -> None:
        self._conn = conn
        self._engine = engine
        """Für ``touch()`` und **nur** dafür — Begründung dort.

        ``None`` bleibt zulässig: Wer den Speicher nur zum Anlegen oder
        Widerrufen baut, braucht keine zweite Transaktion, und ein
        Pflichtparameter zwänge sie jedem Test auf."""

    async def create(self, session: Session, token_hash: str) -> None:
        await self._conn.execute(
            _INSERT,
            {
                "id": session.id,
                "user_id": session.user_id,
                "token_hash": token_hash,
                "client": session.client,
                "channel": session.channel,
                "created_at": session.created_at,
                "last_seen_at": session.last_seen_at,
                "expires_at": session.expires_at,
            },
        )

    async def by_token_hash(self, token_hash: str) -> Session | None:
        row = (await self._conn.execute(_BY_HASH, {"h": token_hash})).first()
        return _to_session(row) if row is not None else None

    async def touch(self, session_id: UUID, now: datetime) -> None:
        """Setzt ``last_seen_at`` fort — in **eigener**, kurzer Transaktion.

        **Der Befund, der das erzwungen hat.** Jede Sitzungsprüfung schreibt
        diese Zeile, und in der Transaktion des Requests bleibt sie bis zu
        dessen Ende gesperrt. Bei kurzen Requests war das ein Kuriosum: Zwei
        Aufrufe derselben Sitzung liefen hintereinander, ohne dass das jemand
        entworfen hätte — nachzulesen in ``tests/integration/test_step_claim.py``,
        wo eine ganze Testkonstruktion darum herum gebaut ist.

        Mit dem Ereignisstrom wurde daraus ein Stillstand. Ein SSE-Request
        endet nicht; seine Transaktion bleibt offen, die Zeilensperre auch —
        und **jeder weitere Aufruf derselben Sitzung wartet auf ein Ende, das
        nicht kommt.** Gemessen beim ersten Browsertest des Stroms: Die
        Oberfläche verband sich, und danach ging nichts mehr.

        Deshalb eine eigene Transaktion, dieselbe Bauart wie beim
        Grant-Verbrauch. Was daran hängt: ``last_seen_at`` überlebt jetzt einen
        zurückgerollten Request. Das ist die richtige Richtung — der Zeitstempel
        beantwortet „wann wurde diese Sitzung zuletzt benutzt", und benutzt
        wurde sie auch dann, wenn der Aufruf scheiterte.

        Ohne Engine bleibt es beim alten Weg: Ein Speicher, der nur anlegt oder
        widerruft, soll keine zweite Verbindung fordern.
        """
        if self._engine is None:
            await self._conn.execute(_TOUCH, {"id": session_id, "now": now})
            return
        async with self._engine.begin() as conn:
            await conn.execute(_TOUCH, {"id": session_id, "now": now})

    async def revoke(self, session_id: UUID, now: datetime) -> None:
        await self._conn.execute(_REVOKE, {"id": session_id, "now": now})

    async def revoke_all_for_user(self, user_id: UUID, now: datetime) -> int:
        result = await self._conn.execute(_REVOKE_ALL, {"u": user_id, "now": now})
        return int(result.rowcount or 0)

    async def active_for_user(self, user_id: UUID, now: datetime) -> list[Session]:
        rows = await self._conn.execute(_ACTIVE, {"u": user_id})
        return [_to_session(row) for row in rows]
