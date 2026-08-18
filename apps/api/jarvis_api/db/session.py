"""Datenbankverbindung und Session-Verwaltung."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

__all__ = ["engine_for", "get_session", "sessionmaker_for"]

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def engine_for(url: str, *, echo: bool = False) -> AsyncEngine:
    """Erzeugt (einmalig) die Engine.

    ``pool_pre_ping`` fängt Verbindungen ab, die der Server hinter einem
    Neustart oder Idle-Timeout bereits geschlossen hat — sonst schlägt der
    erste Zugriff nach einer Ruhephase fehl.
    """
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            url,
            echo=echo,
            pool_size=10,
            max_overflow=10,
            pool_pre_ping=True,
            pool_recycle=1800,
        )
    return _engine


def sessionmaker_for(url: str, *, echo: bool = False) -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            engine_for(url, echo=echo),
            expire_on_commit=False,
            autoflush=False,
        )
    return _sessionmaker


async def get_session(url: str) -> AsyncIterator[AsyncSession]:
    """FastAPI-Dependency. Rollback bei Fehler ist explizit, nicht implizit."""
    factory = sessionmaker_for(url)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose() -> None:
    """Für sauberes Herunterfahren und Tests."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
