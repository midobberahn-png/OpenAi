"""Sitzungsverwaltung.

Siehe docs/07-security-permissions.md §2.

Diese Komponente schließt die Fußnote hinter ``approval-channel-bound``: Die
Bestätigung ist an eine Sitzung gebunden, aber bislang war eine Sitzung nur
eine UUID, die der Aufrufer mitbrachte. Ab hier ist sie ein Objekt mit
Herkunft, Frist und Widerruf.

Der prägende Entwurfsentscheid ist die Speicherform: **In der Datenbank liegt
nur der Hash des Tokens.** Das ist kein Passwort-Hashing-Problem — der Token
hat 256 Bit Entropie, ein Wörterbuchangriff darauf existiert nicht, und
deshalb wäre Argon2 hier nur teuer. Es geht um etwas anderes: Wer die Tabelle
zu sehen bekommt, soll sich damit nicht anmelden können. Ein einfacher
SHA-256 leistet genau das.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal
from uuid import UUID, uuid4

from jarvis_contracts import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_SESSION_TTL,
    IssuedSession,
    Session,
)
from jarvis_core.clock import utc_now
from jarvis_core.ports.sessions import SessionStore

__all__ = [
    "SESSION_TOKEN_BYTES",
    "SessionCheck",
    "SessionManager",
    "SessionRejection",
    "token_fingerprint",
]


SESSION_TOKEN_BYTES = 32
"""256 Bit. Raten ist damit kein Angriffsweg — und deshalb muss der Schutz
gegen *Auslesen* wirken, nicht gegen Erraten."""


def token_fingerprint(token: str) -> str:
    """``SHA-256`` des Tokens als Hexstring.

    Bewusst ohne Salt und ohne Schlüsselableitung: Beides schützt gegen
    Wörterbuch- und Rainbow-Table-Angriffe auf *ratbare* Geheimnisse. Ein
    zufälliger 256-Bit-Wert ist nicht ratbar; ein Salt machte den Wert nur
    unauffindbar, ohne etwas abzuwehren. Kryptografie ohne Angreifermodell ist
    Dekoration (dieselbe Begründung wie bei der Nonce in ``PendingAction``).
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SessionRejection(StrEnum):
    """Warum ein Token nicht gilt.

    **Nach außen bleibt das ein einziges 401.** Der Docstring von ``verify()``
    sagt seit jeher, die Fälle seien „nach innen unterscheidbar, weil das Audit
    sie braucht" — nur gab es innen niemanden, der sie unterschied: Alle vier
    Wege endeten in demselben ``None``.

    Aufgefallen ist das beim Nachgehen eines Testflackerns. Die Anmeldung
    gelang vollständig (``login/finish`` mit 200), und der unmittelbar folgende
    ``/auth/me`` antwortete 401 — ohne dass irgendwo stand, welcher der vier
    Fälle das war. „Kein Cookie angekommen" und „Zeile noch nicht sichtbar"
    verlangen entgegengesetzte Untersuchungen und sahen identisch aus.
    """

    KEIN_TOKEN = "kein-token"
    """Es wurde gar keiner vorgelegt — weder Cookie noch Kopfzeile."""

    UNBEKANNT = "unbekannt"
    """Vorgelegt, aber zu diesem Abdruck gibt es keine Sitzung."""

    WIDERRUFEN = "widerrufen"
    ABGELAUFEN = "abgelaufen"
    LEERLAUF = "leerlauf"
    """Zu lange nicht benutzt — die zweite Frist neben der absoluten."""


@dataclass(frozen=True)
class SessionCheck:
    """Das Ergebnis einer Prüfung: die Sitzung **oder** der Grund.

    Genau eines von beidem ist gesetzt. Ein Grund neben einer gültigen Sitzung
    wäre eine Aussage, die niemand einlösen kann.
    """

    session: Session | None = None
    grund: SessionRejection | None = None


class SessionManager:
    """Stellt Sitzungen aus, prüft sie und nimmt sie zurück."""

    def __init__(
        self,
        store: SessionStore,
        *,
        ttl: timedelta = DEFAULT_SESSION_TTL,
        idle_timeout: timedelta = DEFAULT_IDLE_TIMEOUT,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._store = store
        self._ttl = ttl
        self._idle_timeout = idle_timeout
        self._clock = clock

    def _now(self, now: datetime | None = None) -> datetime:
        """Übergebene Zeit gewinnt; sonst die Uhr.

        Die Tests geben ``now`` durchgehend vor — anders ließe sich der Ablauf
        einer Vierzehn-Tage-Frist nicht prüfen.
        """
        return now if now is not None else self._clock()

    async def issue(
        self,
        user_id: UUID,
        *,
        client: str = "",
        channel: Literal["ui", "voice", "edge"] = "ui",
        now: datetime | None = None,
    ) -> IssuedSession:
        """Legt eine Sitzung an und gibt den Token **einmalig** heraus.

        Der Aufrufer bekommt ihn hier und nie wieder: Gespeichert wird nur der
        Fingerabdruck. Ein „Token erneut anzeigen“ ist damit nicht bloß nicht
        implementiert, sondern nicht möglich — und das ist die Zusicherung, um
        die es geht.
        """
        moment = self._now(now)
        token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
        session = Session(
            id=uuid4(),
            user_id=user_id,
            client=client[:200],
            channel=channel,
            created_at=moment,
            last_seen_at=moment,
            expires_at=moment + self._ttl,
        )
        await self._store.create(session, token_fingerprint(token))
        return IssuedSession(session=session, token=token)

    async def verify(self, token: str, *, now: datetime | None = None) -> Session | None:
        """Prüft einen Token und meldet die Sitzung — oder ``None``.

        ``None`` für jeden Fehlerfall, ohne Unterscheidung nach außen: Ob ein
        Token unbekannt, abgelaufen, verwaist oder widerrufen ist, geht den
        Vorzeiger nichts an. Nach innen sind die Fälle unterscheidbar, weil das
        Audit sie braucht — nach außen wäre die Unterscheidung ein
        Aufzählungsorakel.

        Ein gültiger Zugriff setzt ``last_seen_at`` fort, **ohne** die absolute
        Frist zu verlängern. Andernfalls hielte ein Angreifer eine gestohlene
        Sitzung unbegrenzt am Leben, indem er sie benutzt.
        """
        return (await self.pruefen(token, now=now)).session

    async def pruefen(self, token: str, *, now: datetime | None = None) -> SessionCheck:
        """Dieselbe Prüfung, aber mit dem Grund einer Ablehnung.

        Für Aufrufer, die den Fall **protokollieren** wollen. Nach außen ändert
        das nichts: Die Antwort bleibt ein 401 ohne Unterscheidung, sonst wäre
        sie ein Aufzählungsorakel. Was hier entsteht, gehört ins Protokoll des
        Betreibers, nicht in den Rumpf der Antwort.
        """
        moment = self._now(now)
        if not token:
            return SessionCheck(grund=SessionRejection.KEIN_TOKEN)

        session = await self._store.by_token_hash(token_fingerprint(token))
        if session is None:
            return SessionCheck(grund=SessionRejection.UNBEKANNT)

        # Die Reihenfolge bildet ``is_valid_at`` nach — und muss es, sonst
        # meldete diese Methode einen anderen Grund, als die Prüfung nebenan
        # anwendet. Ein Strukturtest hält beide gegeneinander.
        if session.is_revoked:
            return SessionCheck(grund=SessionRejection.WIDERRUFEN)
        if moment >= session.expires_at:
            return SessionCheck(grund=SessionRejection.ABGELAUFEN)
        if session.is_idle_at(moment, idle_timeout=self._idle_timeout):
            return SessionCheck(grund=SessionRejection.LEERLAUF)

        await self._store.touch(session.id, moment)
        return SessionCheck(session=session.model_copy(update={"last_seen_at": moment}))

    async def belongs_to(
        self, token: str, *, user_id: UUID, session_id: UUID, now: datetime | None = None
    ) -> bool:
        """Gehört dieser Token zu genau dieser Sitzung dieses Nutzers?

        Die Frage, die das Approval Gateway stellen muss. Sie ist enger als
        „ist der Token gültig“: Eine gültige Sitzung *desselben* Nutzers darf
        eine Bestätigung nicht einlösen, die in einer anderen Sitzung angezeigt
        wurde — genau das ist die Sitzungsbindung aus
        ``approval-channel-bound``.
        """
        session = await self.verify(token, now=now)
        if session is None:
            return False
        return session.id == session_id and session.user_id == user_id

    async def revoke(self, session_id: UUID, *, now: datetime | None = None) -> None:
        await self._store.revoke(session_id, self._now(now))

    async def revoke_all(self, user_id: UUID, *, now: datetime | None = None) -> int:
        """Alle Sitzungen eines Nutzers beenden — der Knopf für den Verlustfall."""
        return await self._store.revoke_all_for_user(user_id, self._now(now))

    async def active(self, user_id: UUID, *, now: datetime | None = None) -> list[Session]:
        moment = self._now(now)
        return [
            s
            for s in await self._store.active_for_user(user_id, moment)
            if s.is_valid_at(moment, idle_timeout=self._idle_timeout)
        ]
