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
from sqlalchemy.ext.asyncio import AsyncConnection

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
    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

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
        await self._conn.execute(_TOUCH, {"id": session_id, "now": now})

    async def revoke(self, session_id: UUID, now: datetime) -> None:
        await self._conn.execute(_REVOKE, {"id": session_id, "now": now})

    async def revoke_all_for_user(self, user_id: UUID, now: datetime) -> int:
        result = await self._conn.execute(_REVOKE_ALL, {"u": user_id, "now": now})
        return int(result.rowcount or 0)

    async def active_for_user(self, user_id: UUID, now: datetime) -> list[Session]:
        rows = await self._conn.execute(_ACTIVE, {"u": user_id})
        return [_to_session(row) for row in rows]
