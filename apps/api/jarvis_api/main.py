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
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from jarvis_api.db.session import dispose
from jarvis_api.deps import dispose_redis
from jarvis_api.routes import (
    actions_router,
    audit_router,
    auth_router,
    calendar_router,
    events_router,
    permissions_router,
    runs_router,
    undo_router,
)
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
    application.include_router(runs_router)
    application.include_router(actions_router)
    application.include_router(permissions_router)
    application.include_router(calendar_router)
    application.include_router(audit_router)
    application.include_router(events_router)
    application.include_router(undo_router)

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        """Erreichbarkeit. Bewusst ohne Datenbankzugriff und ohne Details —
        ein Health-Endpunkt, der die Umgebung ausplaudert, ist eine
        Aufklärungshilfe."""
        return {"status": "ok", "env": settings.env}

    _oberflaeche_ausliefern(application)
    return application


WEB_DIST = Path(__file__).resolve().parents[2] / "web" / "dist"
"""Die gebaute Oberfläche. Entsteht durch ``npm run build`` in ``apps/web``."""


def _oberflaeche_ausliefern(application: FastAPI) -> None:
    """Hängt die gebaute Oberfläche unter ``/`` ein — wenn es sie gibt.

    **Ein Prozess und ein Origin.** Die Alternative wäre ein eigener Webserver
    daneben; sie kostet im Betrieb einen dritten Prozess und bringt eine zweite
    Herkunft mit — und an der Herkunft hängen zwei Zusagen dieses Systems: das
    Sitzungs-Cookie (``SameSite``) und die Passkey-Bindung (``rp_id``). Beide
    sind einfacher richtig, wenn es nur eine gibt.

    **Zuletzt eingehängt, und das ist keine Formalie.** ``StaticFiles`` unter
    ``/`` fängt jeden Pfad, der bis dahin nicht beansprucht ist. Stünde diese
    Zeile vor den Routern, verschluckte sie die API — und zwar still: Ein
    ``GET /runs`` bekäme eine 404 der Dateiauslieferung statt einer Antwort.
    Die Reihenfolge ist die einzige Absicherung dagegen.

    ``html=True`` liefert für unbekannte Pfade ``index.html`` aus. Das ist die
    Voraussetzung dafür, dass ein Neuladen auf einer Unterseite funktioniert;
    die Wegewahl trifft der Browser, nicht der Server.

    Fehlt der Ordner — im Test, in der Entwicklung ohne Bau —, geschieht
    nichts. Ein Fehler wäre hier falsch: Die API ist ohne Oberfläche vollständig
    benutzbar, und der umgekehrte Fall (Oberfläche ohne API) existiert nicht.
    """
    if not WEB_DIST.is_dir():
        return
    application.mount("/", StaticFiles(directory=WEB_DIST, html=True), name="web")


app = create_app()
