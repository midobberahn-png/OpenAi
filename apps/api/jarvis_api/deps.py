"""Abhängigkeiten der HTTP-Schicht.

Hier liegt die Stelle, an der aus einem anonymen HTTP-Request eine Identität
wird — und zwar die **einzige** solche Stelle. Das ist die Invariante
``identity-derives-from-session``: Kein Endpunkt darf ``user_id`` oder
``session_id`` aus Body, Query, Header oder Pfad als autoritativ übernehmen.

Der Grund ist derselbe wie beim Executor: Wer die Identität mitbringt, bestimmt
sie. Ein Feld ``user_id`` in einem Request-Body sieht harmlos aus und ist der
kürzeste Weg zu einem fremden Konto — und von dort über Policy und Approval
zu einem ``ExecutionGrant``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncConnection

from jarvis_api.auth import WebAuthnVerifier
from jarvis_api.db.session import engine_for
from jarvis_api.db.session_store import PostgresSessionStore
from jarvis_api.db.webauthn_store import PostgresChallengeStore, PostgresCredentialStore
from jarvis_api.rate_limit_store import RedisRateLimitStore
from jarvis_api.settings import Settings, get_settings
from jarvis_contracts import Session
from jarvis_core.auth import PasskeyService, SessionManager
from jarvis_core.limits import RateLimiter, RateLimitExceeded, RateLimitPolicy

__all__ = [
    "CurrentSession",
    "DbConnection",
    "Limiter",
    "Passkeys",
    "Sessions",
    "client_identifier",
    "current_session",
    "db_connection",
    "dispose_redis",
    "passkey_service",
    "rate_limited",
    "session_manager",
]


async def db_connection(
    settings: Annotated[Settings, Depends(get_settings)],
) -> AsyncIterator[AsyncConnection]:
    """Eine Verbindung mit Transaktion je Request.

    ``engine.begin()`` schließt die Transaktion beim Verlassen — bei einer
    Ausnahme mit Rollback. Ein Endpunkt, der auf halbem Weg scheitert,
    hinterlässt damit keine halbe Registrierung.
    """
    async with engine_for(settings.database_url).begin() as conn:
        yield conn


DbConnection = Annotated[AsyncConnection, Depends(db_connection)]


def session_manager(conn: DbConnection) -> SessionManager:
    return SessionManager(PostgresSessionStore(conn))


Sessions = Annotated[SessionManager, Depends(session_manager)]


def passkey_service(
    conn: DbConnection,
    sessions: Sessions,
    settings: Annotated[Settings, Depends(get_settings)],
) -> PasskeyService:
    return PasskeyService(
        challenges=PostgresChallengeStore(conn),
        credentials=PostgresCredentialStore(conn),
        verifier=WebAuthnVerifier(
            rp_id=settings.webauthn_rp_id,
            expected_origins=settings.webauthn_origins,
        ),
        sessions=sessions,
    )


Passkeys = Annotated[PasskeyService, Depends(passkey_service)]


def session_token_from(request: Request, settings: Settings) -> str:
    """Liest den Sitzungstoken — Cookie zuerst, dann ``Authorization``.

    Das Cookie ist ``httpOnly``: Ein XSS-Fehler in der Oberfläche kann es nicht
    auslesen. Der Bearer-Header existiert daneben, weil das Sprachgerät kein
    Browser ist und kein Cookie führt.

    Beide Wege enden in derselben Prüfung. Der Header ist keine Abkürzung an
    ihr vorbei, sondern ein zweites Transportmittel für dasselbe Geheimnis.
    """
    cookie = request.cookies.get(settings.session_cookie_name)
    if cookie:
        return cookie
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


async def current_session(
    request: Request,
    sessions: Sessions,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Session:
    """Die angemeldete Sitzung — oder 401.

    Was diese Funktion zurückgibt, ist die einzige Quelle für ``user_id`` und
    ``session_id`` in der gesamten HTTP-Schicht. Ein Strukturtest hält fest,
    dass daneben kein zweiter Weg entsteht.
    """
    session = await sessions.verify(session_token_from(request, settings))
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nicht angemeldet.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return session


CurrentSession = Annotated[Session, Depends(current_session)]


# --------------------------------------------------------------------------
# Zugriffsgrenzen
# --------------------------------------------------------------------------


_redis_client: Redis | None = None


def _redis(url: str) -> Redis:
    """Ein Verbindungspool für den Prozess.

    Modulzustand wie bei der Datenbank-Engine, und mit demselben Vorbehalt: Er
    hängt am Event-Loop, der ihn erzeugt hat. Deshalb gibt es ``dispose_redis``
    — ohne das Gegenstück erbt ein zweiter Loop Verbindungen aus einem
    geschlossenen.

    Redis trägt hier nur flüchtigen Zustand (ADR-007, Nachtrag): Geht er
    verloren, sind Zähler zurückgesetzt, aber nichts ist inkonsistent.
    """
    global _redis_client
    if _redis_client is None:
        _redis_client = Redis.from_url(url, decode_responses=True)
    return _redis_client


async def dispose_redis() -> None:
    """Für sauberes Herunterfahren und Tests."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
    _redis_client = None


def rate_limiter(settings: Annotated[Settings, Depends(get_settings)]) -> RateLimiter:
    return RateLimiter(RedisRateLimitStore(_redis(settings.redis_url)))


Limiter = Annotated[RateLimiter, Depends(rate_limiter)]


def client_identifier(request: Request, settings: Settings) -> str:
    """Wer fragt — soweit sich das überhaupt feststellen lässt.

    ``X-Forwarded-For`` wird nur geglaubt, wenn die *tatsächliche* Gegenstelle
    als vertrauenswürdiger Proxy konfiguriert ist. Ohne diese Bedingung ist der
    Header ein Feld, das der Anfragende selbst füllt — ihn zu verwenden hieße,
    den Angreifer nach seiner Kennung zu fragen.

    Die Peer-Adresse ist ihrerseits kein knappes Gut: Ein IPv6-Präfix umfasst
    mehr Adressen, als ein Zähler je sehen wird. Deshalb ist diese Kennung nur
    die *feinere* der beiden Stufen; die grobe zählt global und ist von der
    Adresse unabhängig.
    """
    peer = request.client.host if request.client else "unbekannt"
    if peer in settings.trusted_proxies:
        weitergereicht = request.headers.get("x-forwarded-for", "")
        erste = weitergereicht.split(",")[0].strip()
        if erste:
            return erste
    return peer


def rate_limited(policy: RateLimitPolicy) -> Callable[..., Awaitable[None]]:
    """Erzeugt die Dependency für eine Route.

    Die Antwort bei Überschreitung ist für alle Fälle dieselbe: 429 mit
    ``Retry-After`` und ohne Hinweis darauf, *welche* Stufe gegriffen hat.
    Ein Angreifer soll nicht messen können, ob er allein am Limit ist oder ob
    das System insgesamt unter Last steht — und ein Konto, das es nicht gibt,
    darf sich nicht anders verhalten als eines, das es gibt.
    """

    async def dependency(
        request: Request,
        limiter: Limiter,
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> None:
        try:
            await limiter.require(policy, client=client_identifier(request, settings))
        except RateLimitExceeded as zu_viel:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Zu viele Anfragen.",
                headers={"Retry-After": str(zu_viel.decision.retry_after_s)},
            ) from zu_viel

    return dependency
