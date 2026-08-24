"""Auth-Endpunkte.

Dünne Adapter auf ``jarvis_core.auth``. Hier steht keine Sicherheitslogik —
sie stünde sonst zweimal im System, und die zweite Fassung prüft niemand.

Was diese Datei durchgehend **nicht** tut: eine Identität aus dem Request
lesen. Kein Body-Modell führt ``user_id`` oder ``session_id``; wo eine
Identität gebraucht wird, kommt sie aus ``CurrentSession``. Ein Strukturtest
hält das fest (``tests/unit/test_http_boundary.py``).
"""

from __future__ import annotations

from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from jarvis_api.db.webauthn_store import PostgresCredentialStore
from jarvis_api.deps import CurrentSession, DbConnection, Passkeys, Sessions, rate_limited
from jarvis_api.settings import Settings, get_settings
from jarvis_core.auth import AuthenticationFailed, CloneSuspicion
from jarvis_core.limits import AUTH_CHALLENGE, AUTH_FINISH, BOOTSTRAP

__all__ = ["router"]

_log = structlog.get_logger(__name__)
"""Der Fehlerdetailgrad, den die Antwort nicht trägt, gehört hierher: Ohne
Protokoll wäre die einheitliche Fehlermeldung nach außen zugleich der Verlust
der Information nach innen."""

router = APIRouter(prefix="/auth", tags=["auth"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


# --------------------------------------------------------------------------
# Ein- und Ausgaben
# --------------------------------------------------------------------------


class CeremonyOptions(BaseModel):
    """Die Optionen für ``navigator.credentials`` — plus die Challenge.

    Die Challenge geht als base64url an den Client zurück und kommt beim
    Abschluss wieder mit. Sie ist **kein** Geheimnis: Ihr Wert liegt in der
    Einmaligkeit, nicht in der Verborgenheit.
    """

    options: dict[str, Any]
    challenge: str


class RegistrationRequest(BaseModel):
    credential: dict[str, Any]
    challenge: str
    device_label: str | None = Field(default=None, max_length=120)


class AuthenticationRequest(BaseModel):
    credential: dict[str, Any]
    challenge: str


class BootstrapRequest(BaseModel):
    """Anlage des ersten Nutzers. Enthält bewusst keine ``user_id``."""

    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=200)


class SessionView(BaseModel):
    """Sitzungsübersicht für das Permission Center."""

    id: str
    client: str
    channel: str
    created_at: str
    last_seen_at: str
    expires_at: str
    is_current: bool


_AUSWAHL = AuthenticatorSelectionCriteria(
    resident_key=ResidentKeyRequirement.REQUIRED,
    user_verification=UserVerificationRequirement.REQUIRED,
)
"""Was ein Authenticator mitbringen muss — und warum beides nötig ist.

**``resident_key=REQUIRED`` ist keine Feinheit, sondern die Voraussetzung der
Anmeldung.** ``login/start`` schickt bewusst keine Kandidatenliste
(``allow_credentials`` bleibt leer, sonst wäre sie ein Verzeichnis), und der
Authenticator soll selbst wählen, welcher Passkey zu dieser Herkunft passt.
Wählen kann er nur unter **auffindbaren** Schlüsseln. Ohne diese Zeile durfte
er einen nicht-auffindbaren anlegen — die Registrierung gelänge, und die
Anmeldung fände nichts.

Aufgefallen ist das im ersten Browsertest: Registrierung ``201``, Anmeldung
gestartet, und dann kam nie eine Antwort vom Authenticator. In der
pytest-Suite war es nicht zu sehen, weil die Attrappe dort auf jede Anfrage
antwortet — sie hat keinen Speicher, in dem etwas fehlen könnte. Genau dafür
gibt es den Durchstich im echten Browser.

**``user_verification=REQUIRED``** verlangt PIN, Biometrie oder Entsperrung.
Ein Passkey ohne sie ist ein Besitzfaktor allein: Wer das Gerät hat, ist
angemeldet. Für ein System mit Postfach- und Kalenderzugriff ist das zu wenig.
"""


def _b64(value: bytes) -> str:
    from webauthn.helpers import bytes_to_base64url

    return str(bytes_to_base64url(value))


def _unb64(value: str) -> bytes:
    from webauthn.helpers import base64url_to_bytes

    try:
        return bytes(base64url_to_bytes(value))
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Ungültige Challenge."
        ) from error


def _fail(error: AuthenticationFailed) -> HTTPException:
    """Ein Antwortbild für alle Fehlschläge.

    Der Grund bleibt im Server (``error.reason``) und gehört ins Audit; nach
    außen geht ein einziger Satz. Jede Unterscheidung wäre ein Orakel über
    existierende Konten und Schlüssel.

    Auch der Klonverdacht wird **nach außen** nicht unterschieden. Er ist der
    wichtigste Fall für das Protokoll und für eine Benachrichtigung des
    Nutzers auf einem anderen Weg — aber die Antwort an den Anfragenden verrät
    ihn nicht: Wer einen geklonten Schlüssel vorlegt, soll nicht erfahren, dass
    die Erkennung gegriffen hat.
    """
    if isinstance(error, CloneSuspicion):
        _log.warning("passkey.clone_suspicion", reason=error.reason)
    else:
        _log.info("auth.failed", reason=error.reason)
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Anmeldung nicht möglich."
    )


# --------------------------------------------------------------------------
# Erstinbetriebnahme
# --------------------------------------------------------------------------


@router.post(
    "/bootstrap",
    response_model=CeremonyOptions,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limited(BOOTSTRAP))],
)
async def bootstrap(
    payload: BootstrapRequest,
    conn: DbConnection,
    passkeys: Passkeys,
    settings: SettingsDep,
) -> CeremonyOptions:
    """Legt den **ersten** Nutzer an und startet dessen Passkey-Registrierung.

    Ohne diesen Weg wäre das System nicht in Betrieb zu nehmen: Registrieren
    darf sonst nur, wer bereits angemeldet ist.

    Die Einmaligkeit trägt die Datenbank, nicht eine Prüfung davor. Der
    ``INSERT`` läuft mit ``WHERE NOT EXISTS (SELECT 1 FROM users)`` — bei zwei
    gleichzeitigen Anfragen gewinnt genau eine. Ein vorgelagertes
    ``SELECT count(*)`` wäre bei Nebenläufigkeit wertlos, und das Zeitfenster
    dieser Prüfung ist der Moment, in dem das System noch niemandem gehört.
    """
    row = (
        await conn.execute(
            text(
                """
                INSERT INTO users (id, email, display_name)
                SELECT gen_random_uuid(), :email, :name
                 WHERE NOT EXISTS (SELECT 1 FROM users)
                RETURNING id
                """
            ),
            {"email": payload.email, "name": payload.display_name},
        )
    ).first()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Das System ist bereits eingerichtet.",
        )

    challenge = await passkeys.begin_registration(row.id)
    options = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        user_id=str(row.id).encode(),
        user_name=payload.email,
        user_display_name=payload.display_name,
        challenge=challenge.value,
        authenticator_selection=_AUSWAHL,
    )
    return CeremonyOptions(options=_options_dict(options), challenge=_b64(challenge.value))


# --------------------------------------------------------------------------
# Registrierung weiterer Passkeys
# --------------------------------------------------------------------------


@router.post(
    "/register/start",
    response_model=CeremonyOptions,
    dependencies=[Depends(rate_limited(AUTH_CHALLENGE))],
)
async def register_start(
    session: CurrentSession,
    conn: DbConnection,
    passkeys: Passkeys,
    settings: SettingsDep,
) -> CeremonyOptions:
    """Startet die Registrierung eines weiteren Passkeys.

    Der Nutzer steht durch die Sitzung fest — es gibt keinen Parameter, mit
    dem er benannt werden könnte.
    """
    row = (
        await conn.execute(
            text("SELECT email, display_name FROM users WHERE id = :i"), {"i": session.user_id}
        )
    ).first()
    if row is None:  # pragma: no cover - eine Sitzung ohne Nutzer wäre ein Datenfehler
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unbekannter Nutzer.")

    existing = await PostgresCredentialStore(conn).for_user(session.user_id)
    challenge = await passkeys.begin_registration(session.user_id)
    options = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        authenticator_selection=_AUSWAHL,
        user_id=str(session.user_id).encode(),
        user_name=row.email,
        user_display_name=row.display_name,
        challenge=challenge.value,
        exclude_credentials=_descriptors([c.credential_id for c in existing]),
    )
    return CeremonyOptions(options=_options_dict(options), challenge=_b64(challenge.value))


@router.post(
    "/register/finish",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limited(AUTH_FINISH))],
)
async def register_finish(payload: RegistrationRequest, passkeys: Passkeys) -> dict[str, str]:
    """Schließt eine Registrierung ab.

    Ohne Sitzungspflicht: Der Nutzer steckt in der Challenge, die beim Start
    ausgestellt wurde — und die stammt entweder aus dem Bootstrap oder aus
    einer angemeldeten Sitzung. Eine zusätzliche Sitzungsprüfung hier würde
    den Bootstrap unmöglich machen, ohne etwas hinzuzufügen.
    """
    try:
        passkey = await passkeys.finish_registration(
            payload.credential,
            challenge_value=_unb64(payload.challenge),
            device_label=payload.device_label,
        )
    except AuthenticationFailed as error:
        raise _fail(error) from error
    return {"credential_id": _b64(passkey.credential_id)}


# --------------------------------------------------------------------------
# Anmeldung
# --------------------------------------------------------------------------


@router.post(
    "/login/start",
    response_model=CeremonyOptions,
    dependencies=[Depends(rate_limited(AUTH_CHALLENGE))],
)
async def login_start(passkeys: Passkeys, settings: SettingsDep) -> CeremonyOptions:
    """Challenge für die Anmeldung — ohne Nutzerangabe.

    ``allow_credentials`` bleibt leer: Eine Liste zulässiger Schlüssel wäre
    ein Verzeichnis. Der Authenticator wählt selbst, welcher Passkey zu dieser
    Herkunft passt.
    """
    challenge = await passkeys.begin_authentication()
    options = generate_authentication_options(
        rp_id=settings.webauthn_rp_id, challenge=challenge.value
    )
    return CeremonyOptions(options=_options_dict(options), challenge=_b64(challenge.value))


@router.post("/login/finish", dependencies=[Depends(rate_limited(AUTH_FINISH))])
async def login_finish(
    payload: AuthenticationRequest,
    response: Response,
    passkeys: Passkeys,
    settings: SettingsDep,
) -> dict[str, str]:
    """Prüft die Anmeldung und setzt das Sitzungscookie."""
    credential_id = payload.credential.get("rawId") or payload.credential.get("id")
    if not isinstance(credential_id, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Anmeldung nicht möglich."
        )

    try:
        issued = await passkeys.finish_authentication(
            payload.credential,
            challenge_value=_unb64(payload.challenge),
            credential_id=_unb64(credential_id),
        )
    except AuthenticationFailed as error:
        raise _fail(error) from error

    response.set_cookie(
        settings.session_cookie_name,
        issued.token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        max_age=int((issued.session.expires_at - issued.session.created_at).total_seconds()),
    )
    return {"session_id": str(issued.session.id)}


# --------------------------------------------------------------------------
# Sitzungsverwaltung
# --------------------------------------------------------------------------


@router.get("/sessions", response_model=list[SessionView])
async def list_sessions(session: CurrentSession, sessions: Sessions) -> list[SessionView]:
    """Welche Geräte sind angemeldet — der Grund, warum Sitzungen in Postgres
    liegen (ADR-007, Nachtrag)."""
    return [
        SessionView(
            id=str(s.id),
            client=s.client,
            channel=s.channel,
            created_at=s.created_at.isoformat(),
            last_seen_at=s.last_seen_at.isoformat(),
            expires_at=s.expires_at.isoformat(),
            is_current=s.id == session.id,
        )
        for s in await sessions.active(session.user_id)
    ]


@router.delete("/sessions/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(target_id: str, session: CurrentSession, sessions: Sessions) -> Response:
    """Beendet eine Sitzung — nur eine eigene.

    ``target_id`` ist eine Ressourcenkennung, keine Identität: Wem die Sitzung
    gehört, entscheidet der Abgleich mit den eigenen Sitzungen, nicht der Wert
    im Pfad. Ohne diesen Abgleich wäre der Endpunkt ein Fernabmelder für
    fremde Konten.
    """
    from uuid import UUID

    try:
        parsed = UUID(target_id)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unbekannt.") from error

    eigene = {s.id for s in await sessions.active(session.user_id)}
    if parsed not in eigene:
        # Bewusst 404 und nicht 403: Ob eine fremde Sitzung existiert, geht
        # den Anfragenden nichts an.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unbekannt.")

    await sessions.revoke(parsed)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/sessions", status_code=status.HTTP_200_OK)
async def revoke_all(session: CurrentSession, sessions: Sessions) -> dict[str, int]:
    """Alle Sitzungen beenden — der Knopf für den Geräteverlust.

    Er beendet auch die eigene: Wer ihn drückt, will überall abgemeldet sein,
    nicht überall außer hier.
    """
    return {"revoked": await sessions.revoke_all(session.user_id)}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(session: CurrentSession, sessions: Sessions, settings: SettingsDep) -> Response:
    await sessions.revoke(session.id)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(settings.session_cookie_name)
    return response


@router.get("/me")
async def me(session: CurrentSession) -> dict[str, str]:
    """Wer bin ich? Die Antwort stammt vollständig aus der Sitzung."""
    return {"user_id": str(session.user_id), "session_id": str(session.id)}


# --------------------------------------------------------------------------
# Hilfsmittel
# --------------------------------------------------------------------------


def _options_dict(options: Any) -> dict[str, Any]:
    """Die Bibliotheksstruktur als JSON-fähiges Wörterbuch."""
    import json

    return dict(json.loads(options_to_json(options)))


def _descriptors(credential_ids: list[bytes]) -> list[Any]:
    """Bereits registrierte Schlüssel ausschließen, damit derselbe
    Authenticator nicht zweimal für dasselbe Konto registriert wird."""
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor

    return [PublicKeyCredentialDescriptor(id=cid) for cid in credential_ids]
