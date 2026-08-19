"""Passkey-Anmeldung — der Ablauf, nicht die Kryptografie.

Siehe ADR-007. Passkeys sind hier nicht bloß bequemer als ein Passwort,
sondern **phishing-resistent**: Die Signatur ist an die Herkunft gebunden, und
das ist bei einem System mit Mail- und Kalenderzugriff der eigentliche Punkt.
Ein abgefangenes Passwort öffnet dieses System; ein abgefangener Passkey ist
auf einer fremden Seite wertlos.

Die kryptografische Prüfung liegt hinter ``AttestationVerifier``. Hier steht,
was eine Bibliothek nicht wissen kann:

* **Einmaligkeit.** Eine Challenge wird genau einmal eingelöst. Ohne diese
  Regel ist eine mitgeschnittene Zeremonie beliebig wiederholbar.
* **Zweckbindung.** Eine Registrierungs-Challenge schließt keine Anmeldung ab.
  Ohne sie könnte ein Angreifer die Registrierung anstoßen, um an eine gültige
  Challenge für die Anmeldung zu kommen.
* **Klon-Erkennung.** Der Signaturzähler muss steigen. Tut er das nicht, gibt
  es den Schlüssel zweimal.
* **Herkunft der Identität.** Der Nutzer ergibt sich aus dem vorgelegten
  Passkey, nie aus einer Angabe im Request. Andernfalls dürfte der Angreifer
  benennen, in welches Konto er einbricht.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from jarvis_contracts import (
    DEFAULT_CHALLENGE_TTL,
    ChallengePurpose,
    IssuedSession,
    PasskeyCredential,
    WebAuthnChallenge,
)
from jarvis_core.auth.sessions import SessionManager
from jarvis_core.clock import utc_now
from jarvis_core.ports.webauthn import AttestationVerifier, ChallengeStore, CredentialStore

__all__ = [
    "CHALLENGE_BYTES",
    "AuthenticationFailed",
    "CloneSuspicion",
    "PasskeyService",
    "sign_count_is_plausible",
]


CHALLENGE_BYTES = 32
"""Die Spezifikation verlangt mindestens 16 Byte. 32 kosten nichts."""


class AuthenticationFailed(Exception):
    """Anmeldung oder Registrierung ist gescheitert.

    Eine einzige Ausnahme für alle Fälle, und das ist Absicht: Ob die Challenge
    unbekannt, abgelaufen oder bereits verbraucht war, ob der Passkey nicht
    registriert ist oder die Signatur nicht passt — nach außen ist das
    dieselbe Antwort. Jede Unterscheidung wäre ein Orakel, mit dem sich
    herausfinden lässt, welche Konten und Schlüssel existieren.

    Nach innen bleibt der Grund erhalten (``reason``) und gehört ins Audit.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class CloneSuspicion(AuthenticationFailed):
    """Der Signaturzähler ist nicht gestiegen.

    Der einzige Fall, der nicht wie ein gewöhnlicher Fehlschlag behandelt
    werden darf: Er bedeutet, dass derselbe Schlüssel an zwei Orten existiert.
    Eigene Klasse, damit der Aufrufer ihn im Audit und in der Benachrichtigung
    des Nutzers hervorheben kann — die Anmeldung wird trotzdem abgelehnt.
    """


def sign_count_is_plausible(stored: int, presented: int) -> bool:
    """Ist der vorgelegte Signaturzähler mit dem gespeicherten vereinbar?

    Der Zähler wächst bei jeder Nutzung des Schlüssels. Bleibt er gleich oder
    fällt er, wurde entweder eine alte Antwort wiederholt oder der Schlüssel
    kopiert.

    Die Ausnahme: Viele moderne Authenticator — insbesondere synchronisierte
    Passkeys von Apple und Google — führen **gar keinen** Zähler und melden
    dauerhaft 0. Dort ist keine Aussage möglich, und ein Ablehnen würde die
    verbreitetste Bauart aussperren. Deshalb gilt: Zwei Nullen sind kein
    Verdacht, alles andere muss steigen.
    """
    if stored == 0 and presented == 0:
        return True
    return presented > stored


class PasskeyService:
    """Registrierung und Anmeldung mit Passkeys."""

    def __init__(
        self,
        *,
        challenges: ChallengeStore,
        credentials: CredentialStore,
        verifier: AttestationVerifier,
        sessions: SessionManager,
        clock: Callable[[], datetime] = utc_now,
        challenge_ttl: timedelta = DEFAULT_CHALLENGE_TTL,
    ) -> None:
        self._challenges = challenges
        self._credentials = credentials
        self._verifier = verifier
        self._sessions = sessions
        self._clock = clock
        self._ttl = challenge_ttl

    def _now(self, now: datetime | None) -> datetime:
        return now if now is not None else self._clock()

    # -- Registrierung ----------------------------------------------------
    async def begin_registration(
        self, user_id: UUID, *, now: datetime | None = None
    ) -> WebAuthnChallenge:
        """Stellt eine Challenge für einen **bekannten** Nutzer aus.

        Registrieren darf nur, wer bereits angemeldet ist oder eine Einladung
        eingelöst hat — deshalb steht die ``user_id`` hier fest. Ein offener
        Registrierungsweg wäre bei einem Ein-Personen-System die Hintertür
        neben der Tür.
        """
        moment = self._now(now)
        challenge = WebAuthnChallenge(
            id=uuid4(),
            user_id=user_id,
            purpose=ChallengePurpose.REGISTRATION,
            value=secrets.token_bytes(CHALLENGE_BYTES),
            expires_at=moment + self._ttl,
            created_at=moment,
        )
        await self._challenges.issue(challenge)
        return challenge

    async def finish_registration(
        self,
        credential: dict[str, Any] | str,
        *,
        challenge_value: bytes,
        device_label: str | None = None,
        now: datetime | None = None,
    ) -> PasskeyCredential:
        """Schließt die Registrierung ab.

        Der Nutzer stammt aus der eingelösten Challenge, nicht aus dem
        Request: Sonst ließe sich ein fremdes Konto mit einem eigenen Passkey
        ausstatten.
        """
        moment = self._now(now)
        stored = await self._challenges.consume(
            challenge_value, ChallengePurpose.REGISTRATION, moment
        )
        if stored is None or stored.user_id is None:
            raise AuthenticationFailed("Challenge unbekannt, abgelaufen oder bereits verwendet.")

        try:
            verified = self._verifier.verify_registration(credential, challenge=stored.value)
        except Exception as error:  # Fremdbibliothek, eigene Ausnahmehierarchie
            raise AuthenticationFailed(f"Registrierung nicht verifizierbar: {error}") from error

        if await self._credentials.by_credential_id(verified.credential_id) is not None:
            raise AuthenticationFailed("Dieser Passkey ist bereits registriert.")

        passkey = PasskeyCredential(
            id=uuid4(),
            user_id=stored.user_id,
            credential_id=verified.credential_id,
            public_key=verified.public_key,
            sign_count=verified.sign_count,
            device_label=device_label,
            created_at=moment,
        )
        await self._credentials.add(passkey)
        return passkey

    # -- Anmeldung --------------------------------------------------------
    async def begin_authentication(self, *, now: datetime | None = None) -> WebAuthnChallenge:
        """Challenge für die Anmeldung — **ohne** Nutzerangabe.

        Der Nutzer wird erst aus dem vorgelegten Passkey abgeleitet. Würde er
        hier benannt, wäre die Anmeldemaske ein Verzeichnis: Wer eine
        Challenge für „mirek@…“ bekommt, weiß, dass es das Konto gibt.
        """
        moment = self._now(now)
        challenge = WebAuthnChallenge(
            id=uuid4(),
            purpose=ChallengePurpose.AUTHENTICATION,
            value=secrets.token_bytes(CHALLENGE_BYTES),
            expires_at=moment + self._ttl,
            created_at=moment,
        )
        await self._challenges.issue(challenge)
        return challenge

    async def finish_authentication(
        self,
        credential: dict[str, Any] | str,
        *,
        challenge_value: bytes,
        credential_id: bytes,
        client: str = "",
        channel: str = "ui",
        now: datetime | None = None,
    ) -> IssuedSession:
        """Prüft die Anmeldung und stellt bei Erfolg eine Sitzung aus."""
        moment = self._now(now)
        stored = await self._challenges.consume(
            challenge_value, ChallengePurpose.AUTHENTICATION, moment
        )
        if stored is None:
            raise AuthenticationFailed("Challenge unbekannt, abgelaufen oder bereits verwendet.")

        passkey = await self._credentials.by_credential_id(credential_id)
        if passkey is None:
            raise AuthenticationFailed("Passkey ist nicht registriert.")

        try:
            assertion = self._verifier.verify_authentication(
                credential,
                challenge=stored.value,
                public_key=passkey.public_key,
                sign_count=passkey.sign_count,
            )
        except Exception as error:
            raise AuthenticationFailed(f"Anmeldung nicht verifizierbar: {error}") from error

        if not sign_count_is_plausible(passkey.sign_count, assertion.new_sign_count):
            # Der Zähler ist nicht gestiegen: Es gibt den Schlüssel zweimal.
            # Die Anmeldung wird abgelehnt; die Entscheidung, ob der Passkey
            # gesperrt wird, trifft der Nutzer — ein automatisches Sperren
            # wäre für einen Angreifer ein bequemer Weg, jemanden auszusperren.
            raise CloneSuspicion(
                f"Signaturzähler von {passkey.sign_count} auf {assertion.new_sign_count} "
                "nicht gestiegen — möglicher Klon des Schlüssels."
            )

        await self._credentials.record_use(passkey.id, assertion.new_sign_count, moment)
        return await self._sessions.issue(
            passkey.user_id,
            client=client,
            channel=channel,  # type: ignore[arg-type]
            now=moment,
        )
