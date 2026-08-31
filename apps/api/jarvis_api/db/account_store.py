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

from sqlalchemy import RowMapping, text
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

_LADEN = text(
    """
    SELECT id, provider, external_id, display_label, granted_scopes,
           status, last_error, created_at
      FROM connected_accounts
     WHERE id = :id AND user_id = :user_id
    """
)
"""``user_id`` steht auch hier im ``WHERE`` und nicht in einer Prüfung darüber.

Ein fremdes Konto ist damit von einem nicht existierenden nicht zu
unterscheiden — dieselbe Entscheidung wie überall sonst, und sie steht in der
Anweisung, damit der nächste Endpunkt sie nicht vergessen kann."""

_MARKIEREN = text(
    """
    UPDATE connected_accounts
       SET status = :status, last_error = :fehler, updated_at = now()
     WHERE id = :id
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
        return [_zu_konto(z) for z in zeilen]

    async def laden(self, account_id: UUID, *, user_id: UUID) -> VerbundenesKonto | None:
        async with self._engine.connect() as conn:
            zeile = (
                (await conn.execute(_LADEN, {"id": account_id, "user_id": user_id}))
                .mappings()
                .first()
            )
        return None if zeile is None else _zu_konto(zeile)

    async def markieren(self, account_id: UUID, *, status: str, fehler: str | None) -> None:
        """Hält fest, wie es dem Konto geht.

        **Ohne ``user_id``, und das ist hier richtig.** Diese Methode ruft kein
        Endpunkt mit einer Kennung aus einem Request auf, sondern der Dienst,
        der gerade an genau diesem Konto gearbeitet hat — die Zugehörigkeit ist
        beim Laden geklärt. Eine Bedingung, die nichts mehr prüfen kann, wäre
        Beruhigung und keine Sicherheit; sie ließe die echte Frage ungestellt,
        nämlich wer ``account_id`` bestimmt hat.

        Eigene Transaktion: Dass eine Zustimmung nicht mehr besteht, ist eine
        Tatsache von außen. Sie gehört festgeschrieben, auch wenn der Aufrufer
        danach scheitert — sonst versucht der nächste Aufruf dasselbe noch
        einmal und der übernächste wieder.
        """
        async with self._engine.begin() as conn:
            await conn.execute(_MARKIEREN, {"id": account_id, "status": status, "fehler": fehler})

    async def trennen(self, account_id: UUID, *, user_id: UUID) -> bool:
        async with self._engine.begin() as conn:
            zeile = (await conn.execute(_TRENNEN, {"id": account_id, "user_id": user_id})).first()
        return zeile is not None


def _zu_konto(zeile: RowMapping) -> VerbundenesKonto:
    """Zeile → Konto, an genau einer Stelle.

    Dieselbe Lehre wie beim N+1 im Bestätigungsspeicher: Lag die Abbildung nur
    in einem der Leser, musste der zweite ihn aufrufen oder sie doppeln — und
    beim Doppeln laufen sie auseinander.
    """
    return VerbundenesKonto(
        id=UUID(str(zeile["id"])),
        provider=str(zeile["provider"]),
        external_id=str(zeile["external_id"]),
        display_label=str(zeile["display_label"]),
        granted_scopes=tuple(zeile["granted_scopes"]),
        status=str(zeile["status"]),
        last_error=None if zeile["last_error"] is None else str(zeile["last_error"]),
        created_at=zeile["created_at"],
    )
