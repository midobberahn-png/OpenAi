"""Fixtures für Integrationstests gegen eine echte Datenbank.

Bewusst keine Mocks für Postgres: Die Eigenschaften, die hier geprüft werden —
Kaskadenlöschung, Trigger, generierte Spalten, Indextypen — existieren
ausschließlich in der Datenbank. Ein Mock würde genau das wegabstrahieren,
worum es geht.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

DEFAULT_URL = "postgresql+asyncpg://jarvis:jarvis_dev@localhost:5432/jarvis"


def _url() -> str:
    return os.environ.get("DATABASE_URL", DEFAULT_URL)


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """Bewusst funktionsweit.

    Eine session-weite async-Engine hinge an einem anderen Event-Loop als die
    einzelnen Tests; asyncpg quittiert das mit „another operation is in
    progress". Bei dieser Testzahl ist der Verbindungsaufbau irrelevant.
    """
    eng = create_async_engine(_url(), poolclass=NullPool)
    try:
        async with eng.connect():
            pass
    except Exception as exc:  # pragma: no cover - Umgebungsproblem
        await eng.dispose()
        pytest.skip(f"Keine Datenbank erreichbar ({exc.__class__.__name__}). 'make up' ausführen.")
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def conn(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    """Verbindung mit Rollback nach jedem Test — keine Testdaten bleiben zurück."""
    async with engine.connect() as connection:
        trans = await connection.begin()
        try:
            yield connection
        finally:
            await trans.rollback()


@pytest_asyncio.fixture
async def frische_grenzen() -> AsyncIterator[None]:
    """Leert die Rate-Limit-Zähler vor jedem Test.

    Nötig, weil alle Tests aus derselben Gegenstelle kommen und sich sonst
    gegenseitig aussperren — die Zähler sind bewusst niedrig. Zugleich der
    Beleg dafür, dass die Grenze tatsächlich greift: Ohne dieses Aufräumen
    scheitert die Suite ab dem elften Aufruf.
    """
    import redis.asyncio as redis_lib

    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    client = redis_lib.Redis.from_url(url, decode_responses=True)
    try:
        await client.ping()
    except Exception as exc:  # pragma: no cover - Umgebungsproblem
        await client.aclose()
        pytest.skip(f"Kein Redis erreichbar ({exc.__class__.__name__}). 'make up' ausführen.")

    async def leeren() -> None:
        schluessel = [k async for k in client.scan_iter("ratelimit:*")]
        if schluessel:
            await client.delete(*schluessel)

    await leeren()
    yield
    await leeren()
    await client.aclose()
