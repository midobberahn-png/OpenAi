"""FastAPI-Anwendung.

Die HTTP-Grenze. Sie ist bewusst dünn: Jede Route ruft den Kern auf und
übersetzt Ergebnisse in Statuscodes. Sicherheitsentscheidungen fallen
nirgends hier — sie fielen sonst zweimal, und die zweite Fassung prüft
niemand.

Eine Eigenschaft trägt diese Datei trotzdem selbst, und sie ist die
wichtigste der Schicht: **Identität entsteht ausschließlich in
``deps.current_session``.** Kein Endpunkt liest ``user_id`` oder
``session_id`` aus Body, Query, Header oder Pfad. Ein Strukturtest hält das
fest, weil eine Absicht, die nur im Kopf des Autors steht, beim nächsten
Endpunkt verloren geht.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from jarvis_api.db.session import dispose
from jarvis_api.deps import dispose_redis
from jarvis_api.routes import auth_router
from jarvis_api.settings import get_settings

__all__ = ["app", "create_app"]


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    yield
    await dispose()
    await dispose_redis()


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title="JARVIS API",
        version="0.1.0",
        summary="Persönliches KI-Assistenzsystem",
        description=(
            "Alle Endpunkte außer der Erstinbetriebnahme und dem Anmelde-Handshake "
            "verlangen eine gültige Sitzung. Die Identität stammt ausschließlich aus "
            "dieser Sitzung, nie aus Angaben im Request."
        ),
        lifespan=lifespan,
    )
    application.include_router(auth_router)

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        """Erreichbarkeit. Bewusst ohne Datenbankzugriff und ohne Details —
        ein Health-Endpunkt, der die Umgebung ausplaudert, ist eine
        Aufklärungshilfe."""
        return {"status": "ok", "env": settings.env}

    return application


app = create_app()
