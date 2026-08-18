"""Challenges und Passkeys auf PostgreSQL.

Der Verbrauch einer Challenge ist ein **bedingtes UPDATE mit RETURNING** —
dieselbe Bauart wie beim Nonce-Verbrauch der Bestätigungen, und aus demselben
Grund: Ein Ablauf der Form ``lesen → prüfen → als benutzt markieren`` ist bei
zwei gleichzeitigen Anfragen ein Doppelverbrauch. Beide lesen ``used_at IS
NULL``, beide schreiben. Die Datenbank entscheidet, nicht die Anwendung.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from jarvis_contracts import ChallengePurpose, PasskeyCredential, WebAuthnChallenge

__all__ = ["PostgresChallengeStore", "PostgresCredentialStore"]


_ISSUE = text(
    """
    INSERT INTO webauthn_challenges (id, user_id, purpose, value, expires_at, created_at)
    VALUES (:id, :user_id, :purpose, :value, :expires_at, :created_at)
    """
)

_CONSUME = text(
    """
    UPDATE webauthn_challenges
       SET used_at = :now
     WHERE value = :value
       AND purpose = :purpose
       AND used_at IS NULL
       AND expires_at > :now
    RETURNING id, user_id, purpose, value, expires_at, created_at
    """
)
"""Alle Bedingungen stehen in der ``WHERE``-Klausel, nicht im Python-Code
davor: Nur so ist „prüfen und verbrauchen“ ein einziger, unteilbarer Schritt.

Zurückgegeben wird ``used_at`` bewusst **nicht** — der Aufrufer bekommt die
Challenge in dem Zustand, in dem sie gültig war."""


class PostgresChallengeStore:
    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def issue(self, challenge: WebAuthnChallenge) -> None:
        await self._conn.execute(
            _ISSUE,
            {
                "id": challenge.id,
                "user_id": challenge.user_id,
                "purpose": str(challenge.purpose),
                "value": challenge.value,
                "expires_at": challenge.expires_at,
                "created_at": challenge.created_at,
            },
        )

    async def consume(
        self, value: bytes, purpose: ChallengePurpose, now: datetime
    ) -> WebAuthnChallenge | None:
        row = (
            await self._conn.execute(
                _CONSUME, {"value": value, "purpose": str(purpose), "now": now}
            )
        ).first()
        if row is None:
            return None
        return WebAuthnChallenge(
            id=row.id,
            user_id=row.user_id,
            purpose=ChallengePurpose(row.purpose),
            value=row.value,
            expires_at=row.expires_at,
            created_at=row.created_at,
        )


_ADD = text(
    """
    INSERT INTO webauthn_credentials (
        id, user_id, credential_id, public_key, sign_count, device_label, created_at
    ) VALUES (
        :id, :user_id, :credential_id, :public_key, :sign_count, :device_label, :created_at
    )
    """
)

_BY_CREDENTIAL = text(
    """
    SELECT id, user_id, credential_id, public_key, sign_count, device_label,
           created_at, last_used_at
      FROM webauthn_credentials
     WHERE credential_id = :cid
    """
)

_FOR_USER = text(
    """
    SELECT id, user_id, credential_id, public_key, sign_count, device_label,
           created_at, last_used_at
      FROM webauthn_credentials
     WHERE user_id = :u
     ORDER BY created_at
    """
)

_RECORD_USE = text(
    """
    UPDATE webauthn_credentials
       SET sign_count = :count, last_used_at = :now
     WHERE id = :id AND :count > sign_count
    """
)
"""``:count > sign_count`` als Bedingung, nicht nur als Prüfung davor.

Die Klon-Erkennung sitzt im Kern (``sign_count_is_plausible``) und lehnt die
Anmeldung ab. Diese Bedingung ist die zweite Linie: Selbst wenn ein Aufrufer
sie überginge, ließe die Datenbank den Zähler nicht zurücklaufen — und ein
zurückgesetzter Zähler wäre der Zustand, in dem die Erkennung künftig
schweigt."""


class PostgresCredentialStore:
    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def add(self, credential: PasskeyCredential) -> None:
        await self._conn.execute(
            _ADD,
            {
                "id": credential.id,
                "user_id": credential.user_id,
                "credential_id": credential.credential_id,
                "public_key": credential.public_key,
                "sign_count": credential.sign_count,
                "device_label": credential.device_label,
                "created_at": credential.created_at,
            },
        )

    async def by_credential_id(self, credential_id: bytes) -> PasskeyCredential | None:
        row = (await self._conn.execute(_BY_CREDENTIAL, {"cid": credential_id})).first()
        return _to_credential(row) if row is not None else None

    async def for_user(self, user_id: UUID) -> list[PasskeyCredential]:
        rows = await self._conn.execute(_FOR_USER, {"u": user_id})
        return [_to_credential(row) for row in rows]

    async def record_use(self, credential_id: UUID, sign_count: int, now: datetime) -> None:
        await self._conn.execute(
            _RECORD_USE, {"id": credential_id, "count": sign_count, "now": now}
        )


def _to_credential(row: Any) -> PasskeyCredential:
    return PasskeyCredential(
        id=row.id,
        user_id=row.user_id,
        credential_id=row.credential_id,
        public_key=row.public_key,
        sign_count=row.sign_count,
        device_label=row.device_label,
        created_at=row.created_at,
        last_used_at=row.last_used_at,
    )
