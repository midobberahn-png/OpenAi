"""Sitzungen und Anmeldung.

Siehe docs/07-security-permissions.md §2.

Die Sitzung ist der Träger einer Zusicherung, die das System bisher nur
behauptet hat: dass ein ``session_id`` in einer Bestätigung zu einem echten,
angemeldeten Nutzer gehört. Ohne sie prüft ``approval-channel-bound`` nur, ob
zwei UUIDs übereinstimmen.

Zwei Fristen statt einer, weil sie verschiedene Fälle abdecken:

* ``expires_at`` — absolut, wird nie verlängert. Eine gestohlene Sitzung ist
  damit endlich, auch wenn der Dieb sie aktiv hält.
* ``last_seen_at`` + Leerlauffrist — relativ. Ein vergessenes Gerät wird von
  selbst wertlos.

Wer nur die absolute Frist führt, hält Sitzungen auf ungenutzten Geräten
wochenlang offen; wer nur die relative führt, macht eine aktiv gehaltene
gestohlene Sitzung unbegrenzt haltbar.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "DEFAULT_CHALLENGE_TTL",
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_SESSION_TTL",
    "ChallengePurpose",
    "IssuedSession",
    "PasskeyCredential",
    "Session",
    "WebAuthnChallenge",
]


DEFAULT_SESSION_TTL = timedelta(days=14)
"""Absolute Lebensdauer. Vierzehn Tage sind ein Kompromiss: kurz genug, dass
ein entwendetes Gerät nicht dauerhaft Zugang bedeutet, lang genug, dass die
tägliche Nutzung keine Anmeldung erzwingt — Anmeldemüdigkeit endet in
schwachen Ausweichwegen."""

DEFAULT_IDLE_TIMEOUT = timedelta(hours=12)
"""Leerlauffrist. Ein Gerät, das einen halben Tag schweigt, meldet sich neu an."""

DEFAULT_CHALLENGE_TTL = timedelta(minutes=5)
"""Lebensdauer einer WebAuthn-Challenge. Kurz, weil die Zeremonie Sekunden
dauert — alles darüber vergrößert nur das Fenster für einen Replay."""


class Session(BaseModel):
    """Eine angemeldete Sitzung.

    Enthält **kein** Token. Der Token existiert genau einmal — bei der Ausgabe
    — und liegt danach nur als Hash in der Datenbank. Ein Sitzungsobjekt, das
    sein Geheimnis mitführt, landet über Logs, Fehlerberichte und Serialisierung
    an Stellen, an denen es nicht sein darf.
    """

    model_config = ConfigDict(frozen=True)

    id: UUID
    user_id: UUID
    client: str = Field(default="", max_length=200)
    """Gerätebezeichnung für die Sitzungsübersicht — „MacBook, Safari“.
    Rein informativ: Der Wert stammt vom Client und wird nie geprüft, also
    darf keine Entscheidung von ihm abhängen."""

    channel: Literal["ui", "voice", "edge"] = "ui"
    """Woher die Sitzung stammt. Die Kanalbindung einer Bestätigung wird
    getrennt geführt (``PendingAction.requested_channel``); dieses Feld sagt,
    welches Gerät sich angemeldet hat."""

    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_idle_at(self, moment: datetime, *, idle_timeout: timedelta) -> bool:
        return moment - self.last_seen_at >= idle_timeout

    def is_valid_at(self, moment: datetime, *, idle_timeout: timedelta) -> bool:
        """Gültig heißt: nicht widerrufen, nicht abgelaufen, nicht verwaist.

        Alle drei Bedingungen werden hier zusammengeführt, damit es keine
        Aufrufstelle gibt, die eine davon vergisst.
        """
        if self.is_revoked:
            return False
        if moment >= self.expires_at:
            return False
        return not self.is_idle_at(moment, idle_timeout=idle_timeout)


class IssuedSession(BaseModel):
    """Frisch ausgestellte Sitzung — der einzige Ort, an dem der Token vorkommt.

    Der Typ ist bewusst schwer zu verwechseln: Wer ihn weiterreicht, reicht ein
    Geheimnis weiter, und das soll im Code sichtbar sein. Persistiert und
    zurückgegeben wird sonst überall ``Session``.
    """

    model_config = ConfigDict(frozen=True)

    session: Session
    token: str = Field(min_length=32, repr=False)
    """``repr=False``: Der Token soll nicht in Tracebacks und Log-Ausgaben
    auftauchen. Das ist keine Sicherheitsmaßnahme, sondern die Beseitigung
    eines häufigen Unfalls."""

    def __str__(self) -> str:
        return f"IssuedSession(session={self.session.id}, token=…)"


class ChallengePurpose(StrEnum):
    """Wofür eine Challenge ausgestellt wurde.

    Der Zweck ist Teil der Bindung, nicht Buchhaltung: Eine Challenge aus der
    Registrierung darf keine Anmeldung abschließen. Ohne dieses Feld wäre
    beides derselbe Zufallswert, und ein Angreifer könnte eine
    Registrierungszeremonie starten, um an eine gültige Challenge für die
    Anmeldung zu kommen.
    """

    REGISTRATION = "registration"
    AUTHENTICATION = "authentication"

    def __str__(self) -> str:
        return self.value


class WebAuthnChallenge(BaseModel):
    """Eine ausgestellte, genau einmal einlösbare Challenge."""

    model_config = ConfigDict(frozen=True)

    id: UUID
    user_id: UUID | None = None
    """Bei der Registrierung gesetzt, bei der Anmeldung offen — dort ist der
    Nutzer erst nach der Prüfung bekannt. Wer ihn vorher aus dem Request
    übernähme, ließe sich den Namen des Kontos nennen, in das er einbricht."""

    purpose: ChallengePurpose
    value: bytes = Field(min_length=16)
    """Zufallswert. Mindestens 16 Byte nach WebAuthn-Empfehlung; wir stellen
    32 aus."""

    expires_at: datetime
    created_at: datetime
    used_at: datetime | None = None

    def is_valid_at(self, moment: datetime) -> bool:
        return self.used_at is None and moment < self.expires_at


class PasskeyCredential(BaseModel):
    """Ein registrierter Passkey."""

    model_config = ConfigDict(frozen=True)

    id: UUID
    user_id: UUID
    credential_id: bytes
    """Vom Authenticator vergeben, systemweit eindeutig."""

    public_key: bytes
    sign_count: int = Field(ge=0)
    """Zähler des Authenticators. Steigt er bei einer Anmeldung nicht, ist das
    ein Hinweis auf einen geklonten Schlüssel — siehe
    ``sign_count_is_plausible``."""

    device_label: str | None = None
    created_at: datetime
    last_used_at: datetime | None = None
