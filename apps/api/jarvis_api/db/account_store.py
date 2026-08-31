"""Verbundene Konten — anlegen, auflisten, trennen.

**Die Zugehörigkeit steht in jeder Anweisung, nicht in einer Prüfung davor.**
``user_id`` ist Teil jedes ``WHERE``; es gibt keinen Weg, ein Konto zu lesen
oder zu trennen, indem man nur seine Kennung kennt. Dieselbe Entscheidung wie
beim Rücknahmeanspruch: Wer erst lädt, dann vergleicht und dann schreibt, hat
zwischen den Schritten ein Fenster — und schreibt die Bedingung außerdem an
eine Stelle, die beim nächsten Endpunkt vergessen werden kann.

**Ein zweites Verbinden desselben Kontos ist kein neues Konto.** Der
Eindeutigkeitsschlüssel ``(user_id, provider, external_id)`` steht seit dem
ersten Schema; ein ``ON CONFLICT`` macht daraus eine Erneuerung. Ohne ihn
entstünde bei jeder wiederholten Zustimmung eine Karteileiche mit eigenen
Zugangsdaten — und die alte bliebe gültig, ohne dass sie jemand sieht.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

__all__ = ["PostgresAccountStore", "VerbundenesKonto"]


@dataclass(frozen=True, slots=True)
class VerbundenesKonto:
    id: UUID
    provider: str
    external_id: str
    display_label: str
    granted_scopes: tuple[str, ...]
    status: str
    last_error: str | None
    created_at: datetime


_VERBINDEN = text(
    """
    INSERT INTO connected_accounts (
        user_id, provider, external_id, display_label, granted_scopes, status
    ) VALUES (:user_id, :provider, :external_id, :label, :scopes, 'active')
    ON CONFLICT ON CONSTRAINT uq_account_identity DO UPDATE
       SET display_label  = EXCLUDED.display_label,
           granted_scopes = EXCLUDED.granted_scopes,
           status         = 'active',
           last_error     = NULL,
           updated_at     = now()
    RETURNING id
    """
)
"""``last_error = NULL`` beim Wiederverbinden.

Ein Konto, das wegen eines abgelaufenen Tokens auf ``error`` stand, ist nach
einer frischen Zustimmung in Ordnung — eine stehen gebliebene Fehlermeldung
daneben wäre eine Auskunft, die nicht mehr stimmt."""

_LISTE = text(
    """
    SELECT id, provider, external_id, display_label, granted_scopes,
           status, last_error, created_at
      FROM connected_accounts
     WHERE user_id = :user_id
     ORDER BY created_at
    """
)

_TRENNEN = text(
    """
    DELETE FROM connected_accounts
     WHERE id = :id AND user_id = :user_id
    RETURNING id
    """
)
"""Löschen und nicht auf ``revoked`` setzen.

Der Status kennt ``revoked``, und für einen Widerruf **beim Anbieter** wäre er
richtig. Hier trennt der Nutzer die Verbindung auf **dieser** Seite, und dann
ist die einzige ehrliche Wirkung, dass die Zugangsdaten verschwinden — sie
hängen über ``ON DELETE CASCADE`` an dieser Zeile. Eine Zeile mit Status
``revoked``, deren ``oauth_credentials`` weiter benutzbar wären, wäre eine
Zusage, die der Speicher nicht einlöst."""


class PostgresAccountStore:
    """Eigene Transaktion je Schreibvorgang.

    Aus demselben Grund wie beim Zugangsdatenspeicher: Das Konto entsteht,
    nachdem der Anbieter Tokens ausgestellt hat. Was draußen geschehen ist,
    gehört festgeschrieben — auch wenn der Request danach scheitert.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def verbinden(
        self,
        user_id: UUID,
        *,
        provider: str,
        external_id: str,
        display_label: str,
        granted_scopes: tuple[str, ...],
    ) -> UUID:
        async with self._engine.begin() as conn:
            neu = (
                await conn.execute(
                    _VERBINDEN,
                    {
                        "user_id": user_id,
                        "provider": provider,
                        "external_id": external_id,
                        "label": display_label,
                        "scopes": list(granted_scopes),
                    },
                )
            ).scalar_one()
        return UUID(str(neu))

    async def liste(self, user_id: UUID) -> list[VerbundenesKonto]:
        async with self._engine.connect() as conn:
            zeilen = (await conn.execute(_LISTE, {"user_id": user_id})).mappings().all()
        return [
            VerbundenesKonto(
                id=UUID(str(z["id"])),
                provider=str(z["provider"]),
                external_id=str(z["external_id"]),
                display_label=str(z["display_label"]),
                granted_scopes=tuple(z["granted_scopes"]),
                status=str(z["status"]),
                last_error=z["last_error"],
                created_at=z["created_at"],
            )
            for z in zeilen
        ]

    async def trennen(self, account_id: UUID, *, user_id: UUID) -> bool:
        async with self._engine.begin() as conn:
            zeile = (await conn.execute(_TRENNEN, {"id": account_id, "user_id": user_id})).first()
        return zeile is not None
