"""Fixtures für Integrationstests gegen eine echte Datenbank.

Bewusst keine Mocks für Postgres: Die Eigenschaften, die hier geprüft werden —
Kaskadenlöschung, Trigger, generierte Spalten, Indextypen — existieren
ausschließlich in der Datenbank. Ein Mock würde genau das wegabstrahieren,
worum es geht.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from uuid import UUID

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

DEFAULT_URL = "postgresql+asyncpg://jarvis:jarvis_dev@localhost:5432/jarvis"


def _url() -> str:
    return os.environ.get("DATABASE_URL", DEFAULT_URL)


REQUIRE_SERVICES = os.environ.get("JARVIS_REQUIRE_SERVICES") == "1"
"""Macht das Überspringen zum Fehler.

Ohne diesen Schalter meldet die Suite ein sattes Grün, auch wenn kein einziger
Integrationstest gelaufen ist — die Dienste fehlten eben. Für eine
Entwicklungsmaschine ohne Docker ist das richtig; für einen Prüflauf, der die
Nebenläufigkeit belegen soll, ist es die gefährlichste Art von Fehlmeldung.

Ein externer Prüfer hat genau das erlebt: 702 Tests, 0 Fehler, 110
übersprungen — darunter der einzige Test, der den atomaren Anspruch unter
echter Nebenläufigkeit zeigt. Wer die Zusammenfassung liest und die
Skip-Zeile übersieht, hält den Beweis für erbracht.

    JARVIS_REQUIRE_SERVICES=1 uv run pytest -m integration
"""


def _fehlt(dienst: str, exc: Exception) -> None:
    """Überspringen — oder scheitern, wenn ein Beweis erwartet wird."""
    hinweis = f"{dienst} nicht erreichbar ({exc.__class__.__name__}). 'make up' ausführen."
    if REQUIRE_SERVICES:
        pytest.fail(
            f"{hinweis}\nJARVIS_REQUIRE_SERVICES=1 verlangt einen echten Lauf: Ein "
            "übersprungener Integrationstest ist kein bestandener."
        )
    pytest.skip(hinweis)


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
        _fehlt("Datenbank", exc)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def conn(
    engine: AsyncEngine, aufgeraeumte_nutzer: list[UUID]
) -> AsyncIterator[AsyncConnection]:
    """Verbindung mit Rollback nach jedem Test — keine Testdaten bleiben zurück.

    Bequem und für alles richtig, was **innerhalb** einer Transaktion geprüft
    wird. Für Abläufe, die Transaktionsgrenzen überschreiten, ist es die
    falsche Fixture: Wer alles in einer Transaktion hält, die nie committet,
    prüft eine Umgebung, die es in Produktion nicht gibt. Der vierte
    Replay-Befund lag genau dort. Solche Tests nehmen ``engine`` und
    ``aufgeraeumte_nutzer``.

    **Warum diese Fixture ``aufgeraeumte_nutzer`` anfordert, obwohl sie es
    nicht benutzt:** Sie erzwingt damit die Abbaureihenfolge. Fixtures werden
    in umgekehrter Aufbaureihenfolge abgebaut; als Abhängige wird diese hier
    zuerst abgebaut, der Rollback läuft also **vor** dem Aufräumen. Ohne das
    wartet das ``DELETE`` auf Zeilensperren einer Transaktion, die erst danach
    zurückrollt — die Testsuite bleibt stehen, und zwar ohne Fehlermeldung.
    Der Fall ist einmal eingetreten; die Kopplung ist die Lehre daraus.
    """
    async with engine.connect() as connection:
        trans = await connection.begin()
        try:
            yield connection
        finally:
            await trans.rollback()


@pytest_asyncio.fixture
async def aufgeraeumte_nutzer(engine: AsyncEngine) -> AsyncIterator[list[UUID]]:
    """Aufräumen für Tests, die committen müssen.

    Der Gegenentwurf zur ``conn``-Fixture: Wo der Ablauf eigene Transaktionen
    öffnet — das Werkzeugprotokoll und der Grant-Verbrauch tun das, und zwar
    aus Gründen der Absturzsicherheit —, kann die Isolation nicht mehr aus
    einem umschließenden Rollback kommen. Sie kommt stattdessen aus dem
    Löschen danach.

    Der Test hängt die von ihm angelegten Nutzer-IDs an die Liste; ``users``
    kaskadiert auf Läufe, Invokationen, Bestätigungen und Berechtigungen. Das
    Löschen läuft auch, wenn der Test scheitert — sonst vergiftet ein
    Fehlschlag die folgenden Läufe.
    """
    ids: list[UUID] = []
    try:
        yield ids
    finally:
        if ids:
            async with engine.begin() as conn:
                await conn.execute(
                    text("DELETE FROM users WHERE id = ANY(:ids)"), {"ids": list(ids)}
                )


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
        _fehlt("Redis", exc)

    async def leeren() -> None:
        schluessel = [k async for k in client.scan_iter("ratelimit:*")]
        if schluessel:
            await client.delete(*schluessel)

    await leeren()
    yield
    await leeren()
    await client.aclose()
