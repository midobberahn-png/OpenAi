"""Ports der Passkey-Anmeldung.

Die Kryptografie liegt hinter ``AttestationVerifier`` und damit in der
Adapterschicht (ADR-009). Was hier bleibt, ist der Ablauf — und der trägt die
Sicherheitsregeln, die sich ohne Bibliothek prüfen lassen: Einmaligkeit der
Challenge, Zweckbindung, Klon-Erkennung über den Signaturzähler.

Die Trennung ist nicht bloß Schichtenhygiene. Eine WebAuthn-Bibliothek prüft
Signatur, Origin und RP-ID; sie weiß nichts davon, ob *diese* Challenge schon
einmal verwendet wurde oder ob der Zähler rückwärts läuft. Genau das sind die
Fälle, die man testen will, ohne einen Authenticator zu simulieren.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from jarvis_contracts import ChallengePurpose, PasskeyCredential, WebAuthnChallenge

__all__ = [
    "AttestationVerifier",
    "ChallengeStore",
    "CredentialStore",
    "VerifiedAssertion",
    "VerifiedAttestation",
]


class VerifiedAttestation(Protocol):
    """Ergebnis einer geprüften Registrierung."""

    @property
    def credential_id(self) -> bytes: ...

    @property
    def public_key(self) -> bytes: ...

    @property
    def sign_count(self) -> int: ...


class VerifiedAssertion(Protocol):
    """Ergebnis einer geprüften Anmeldung."""

    @property
    def new_sign_count(self) -> int: ...


class AttestationVerifier(Protocol):
    """Die kryptografische Prüfung — Signatur, Origin, RP-ID.

    Implementiert in ``apps/api`` gegen ``py_webauthn``. Der Kern ruft sie auf,
    kennt sie aber nicht.
    """

    def verify_registration(
        self, credential: dict[str, Any] | str, *, challenge: bytes
    ) -> VerifiedAttestation: ...

    def verify_authentication(
        self,
        credential: dict[str, Any] | str,
        *,
        challenge: bytes,
        public_key: bytes,
        sign_count: int,
    ) -> VerifiedAssertion: ...


class ChallengeStore(Protocol):
    """Persistenz der Challenges."""

    async def issue(self, challenge: WebAuthnChallenge) -> None: ...

    async def consume(
        self, value: bytes, purpose: ChallengePurpose, now: datetime
    ) -> WebAuthnChallenge | None:
        """Löst eine Challenge ein — **atomar und genau einmal**.

        Dieselbe Anforderung wie bei der Bestätigungs-Nonce, aus demselben
        Grund: Ein Ablauf der Form ``lesen → prüfen → als benutzt markieren``
        ist bei zwei gleichzeitigen Anfragen ein Doppelverbrauch. Die einzige
        verlässliche Form ist ein bedingtes ``UPDATE``, dessen Trefferzahl die
        Antwort liefert.

        ``None`` heißt: unbekannt, abgelaufen, bereits verbraucht oder für
        einen anderen Zweck ausgestellt. Nach außen wird nicht unterschieden.
        """
        ...


class CredentialStore(Protocol):
    """Persistenz der registrierten Passkeys."""

    async def add(self, credential: PasskeyCredential) -> None: ...

    async def by_credential_id(self, credential_id: bytes) -> PasskeyCredential | None:
        """Auflösung über die vom Authenticator vergebene Kennung.

        Der Einstiegspunkt der Anmeldung: Der Nutzer wird aus dem Passkey
        abgeleitet, nicht aus einer Angabe im Request.
        """
        ...

    async def for_user(self, user_id: UUID) -> list[PasskeyCredential]: ...

    async def record_use(self, credential_id: UUID, sign_count: int, now: datetime) -> None: ...
