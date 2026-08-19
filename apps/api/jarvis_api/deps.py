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

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncConnection

from jarvis_api.auth import WebAuthnVerifier
from jarvis_api.db.session import engine_for
from jarvis_api.db.session_store import PostgresSessionStore
from jarvis_api.db.webauthn_store import PostgresChallengeStore, PostgresCredentialStore
from jarvis_api.settings import Settings, get_settings
from jarvis_contracts import Session
from jarvis_core.auth import PasskeyService, SessionManager

__all__ = [
    "CurrentSession",
    "DbConnection",
    "Passkeys",
    "Sessions",
    "current_session",
    "db_connection",
    "passkey_service",
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
