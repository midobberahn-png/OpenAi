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


DEFAULT_ROTATION_INTERVAL = timedelta(minutes=15)
"""Wie alt ein Token wird, bevor er ersetzt wird (ADR-020).

Nicht bei jedem Aufruf: Diese Oberfläche stellt mehrere Anfragen gleichzeitig
(Laufdetail alle 3 Sekunden, Laufliste alle 10, dazu ein dauerhaft offener
Ereignisstrom). Bei Rotation je Aufruf wäre jeder Takt ein Wettlauf. Der
Schutz bleibt derselbe — wer eine Kopie hat, verliert sie, sobald der
rechtmäßige Nutzer arbeitet."""

DEFAULT_OVERLAP = timedelta(seconds=60)
"""Wie lange der vorige Token nach einer Rotation weiter gilt.

Die Antwort auf „zufällige Abmeldungen": Eine Anfrage, die zum Zeitpunkt der
Rotation bereits unterwegs war, trägt den alten Token und darf nicht
scheitern."""

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

    WIEDERVERWENDET = "wiederverwendet"
    """Ein ersetzter Token, vorgelegt **nach** dem Überlappungsfenster.

    Der einzige Grund, der nicht nur ablehnt, sondern die Sitzung beendet: Der
    rechtmäßige Client hat längst gewechselt, sein Cookie *ist* der neue. Was
    danach mit dem alten kommt, ist eine Kopie (ADR-020)."""


@dataclass(frozen=True)
class SessionCheck:
    """Das Ergebnis einer Prüfung: die Sitzung **oder** der Grund.

    Genau eines von beidem ist gesetzt. Ein Grund neben einer gültigen Sitzung
    wäre eine Aussage, die niemand einlösen kann.
    """

    session: Session | None = None
    grund: SessionRejection | None = None
    neuer_token: str | None = None
    """Gesetzt, wenn bei dieser Prüfung rotiert wurde (ADR-020).

    Der Aufrufer **muss** ihn in seine Antwort legen — sonst hat die Datenbank
    einen neuen Token und der Client den alten, und der nächste Aufruf fiele
    ins Überlappungsfenster und danach auf die Wiederverwendungserkennung. Wer
    nicht setzen kann, rotiert nicht (``rotieren=False``)."""


class SessionManager:
    """Stellt Sitzungen aus, prüft sie und nimmt sie zurück."""

    def __init__(
        self,
        store: SessionStore,
        *,
        ttl: timedelta = DEFAULT_SESSION_TTL,
        idle_timeout: timedelta = DEFAULT_IDLE_TIMEOUT,
        rotation_interval: timedelta = DEFAULT_ROTATION_INTERVAL,
        overlap: timedelta = DEFAULT_OVERLAP,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._store = store
        self._ttl = ttl
        self._idle_timeout = idle_timeout
        self._rotation_interval = rotation_interval
        self._overlap = overlap
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

    async def pruefen(
        self, token: str, *, now: datetime | None = None, rotieren: bool = False
    ) -> SessionCheck:
        """Dieselbe Prüfung, aber mit dem Grund einer Ablehnung.

        Für Aufrufer, die den Fall **protokollieren** wollen. Nach außen ändert
        das nichts: Die Antwort bleibt ein 401 ohne Unterscheidung, sonst wäre
        sie ein Aufzählungsorakel. Was hier entsteht, gehört ins Protokoll des
        Betreibers, nicht in den Rumpf der Antwort.

        ``rotieren`` sagt: **Ich kann einen Ersatz zurückgeben.** Nur wer ein
        Cookie setzen kann, darf das verlangen — ein Ersatz, der den Aufrufer
        nicht erreicht, ist eine Abmeldung mit Ansage (ADR-020 §4). Vorgabe ist
        deshalb ``False``: Wer nichts sagt, rotiert nicht.
        """
        moment = self._now(now)
        if not token:
            return SessionCheck(grund=SessionRejection.KEIN_TOKEN)

        abdruck = token_fingerprint(token)
        gefunden = await self._store.lookup(abdruck)
        if gefunden is None:
            return SessionCheck(grund=SessionRejection.UNBEKANNT)

        session = gefunden.session

        # Die Reihenfolge bildet ``is_valid_at`` nach — und muss es, sonst
        # meldete diese Methode einen anderen Grund, als die Prüfung nebenan
        # anwendet. Ein Strukturtest hält beide gegeneinander.
        if session.is_revoked:
            return SessionCheck(grund=SessionRejection.WIDERRUFEN)
        if moment >= session.expires_at:
            return SessionCheck(grund=SessionRejection.ABGELAUFEN)
        if session.is_idle_at(moment, idle_timeout=self._idle_timeout):
            return SessionCheck(grund=SessionRejection.LEERLAUF)

        if gefunden.ist_vorgaenger:
            # **Der ersetzte Token** (ADR-020). Innerhalb des Fensters ist das
            # eine Anfrage, die zum Zeitpunkt der Rotation schon unterwegs war;
            # danach ist es eine Kopie.
            if not self._im_fenster(gefunden.rotation_alter):
                await self._store.revoke(session.id, moment)
                return SessionCheck(grund=SessionRejection.WIEDERVERWENDET)
            # Kein zweites Mal rotieren: Der neue Token ist bereits unterwegs.
            await self._store.touch(session.id, moment)
            return SessionCheck(session=session.model_copy(update={"last_seen_at": moment}))

        await self._store.touch(session.id, moment)
        aktuell = session.model_copy(update={"last_seen_at": moment})

        if not rotieren or gefunden.token_alter < self._rotation_interval:
            return SessionCheck(session=aktuell)

        ersatz = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
        gedreht = await self._store.rotate(
            session.id, alt_hash=abdruck, neu_hash=token_fingerprint(ersatz)
        )
        # **Der Verlierer des Wettlaufs arbeitet weiter.** ``False`` heißt: Eine
        # gleichzeitige Anfrage war schneller. Ihr Token gilt, unserer liegt ab
        # jetzt als Vorgänger daneben und gilt im Fenster — abgemeldet wird
        # niemand.
        return SessionCheck(session=aktuell, neuer_token=ersatz if gedreht else None)

    def _im_fenster(self, rotation_alter: timedelta | None) -> bool:
        """Gilt der vorige Token noch?

        **Verglichen wird ein Alter, kein Zeitpunkt.** Es kommt aus der
        Datenbank, also von derselben Uhr, die ``rotated_at`` gesetzt hat; die
        Prozessuhr kommt hier nicht vor. Ein Integrationstest hat die andere
        Fassung entlarvt: Mit gestellter Testuhr wurde die Differenz negativ,
        und ein ersetzter Token galt weiter — dieselbe Zwei-Uhren-Falle, die
        die Leerlaufmessung schon einmal eine Sitzung gekostet hat.

        Ohne Alter **nein**: Ein Vorgänger ohne Rotationszeitpunkt ist ein
        Datensatz, den niemand erklären kann, und die strengere Antwort ist
        hier die richtige.
        """
        if rotation_alter is None:
            return False
        return rotation_alter <= self._overlap

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
