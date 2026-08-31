"""Zugangsdaten verbundener Konten — verschlüsselt, mit Adressat.

Die Hälfte, die bis heute fehlte. ``oauth_credentials`` steht seit dem ersten
Schema; die Verschlüsselung dazu entstand mit ADR-008, und **dieser** Speicher
ist der Grund, warum beides zusammen etwas bedeutet. Ohne ihn wäre die Krypto
das, was die Audit-Kette vor ``a67dd30`` war: vollständig gebaut und von nichts
benutzt.

**Es gibt keinen Weg, hier Klartext abzulegen.** Die Signatur nimmt ein
Geheimnis entgegen und gibt eines zurück; was in die Zeile geht, hat diese
Datei bereits versiegelt. Eine Methode, die einen Klartext schriebe, gäbe es
auch dann nicht, wenn jemand sie „nur für einen Test" wollte.

**Die Bindung ist die Konto-ID.** Sie geht als zusätzliche authentifizierte
Daten in die Verschlüsselung ein (siehe ``jarvis_core.crypto.envelope``). Wer
die Datenbank direkt erreicht, kann damit den Geheimtext eines fremden Kontos
nicht in die eigene Zeile kopieren und vom System öffnen lassen — er ist an
seinen Platz gebunden.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_core.crypto import SealedSecret, oeffnen, versiegeln
from jarvis_core.ports.keys import KeyProvider

__all__ = ["PostgresCredentialStore"]

_SPEICHERN = text(
    """
    INSERT INTO oauth_credentials (
        account_id, ciphertext, nonce, wrapped_dek, kek_id, access_expires_at
    ) VALUES (:account_id, :ciphertext, :nonce, :wrapped_dek, :kek_id, :expires)
    RETURNING id
    """
)

_LESEN = text(
    """
    SELECT ciphertext, nonce, wrapped_dek, kek_id, access_expires_at
      FROM oauth_credentials
     WHERE account_id = :account_id
     ORDER BY created_at DESC
     LIMIT 1
    """
)
"""Der **jüngste** Datensatz eines Kontos.

Ein Token-Refresh schreibt einen neuen, statt den alten zu überschreiben: Wer
überschreibt, verliert bei einem Fehlschlag beides. Gelesen wird deshalb der
neueste, und die älteren sind Vergangenheit — aufgeräumt wird an anderer
Stelle, nicht beim Lesen."""


class PostgresCredentialStore:
    """Legt Zugangsdaten verschlüsselt ab und holt sie zurück."""

    def __init__(self, engine: AsyncEngine, *, schluessel: KeyProvider) -> None:
        self._engine = engine
        self._schluessel = schluessel

    async def speichern(self, account_id: UUID, *, token: bytes, gilt_bis: datetime) -> UUID:
        """Versiegelt den Token und schreibt ihn.

        Eigene Transaktion: Ein Token, den der Anbieter ausgestellt hat, muss
        auch dann gespeichert sein, wenn der umgebende Request danach
        scheitert — sonst hat der Nutzer eine Zustimmung erteilt, von der
        nichts übrig bleibt, und der nächste Versuch beginnt mit einer neuen
        Zustimmung. Dieselbe Überlegung wie beim Kostenhauptbuch: Was draußen
        geschehen ist, gehört festgeschrieben.
        """
        siegel = await versiegeln(token, bindung=_bindung(account_id), schluessel=self._schluessel)
        async with self._engine.begin() as conn:
            neu = (
                await conn.execute(
                    _SPEICHERN,
                    {
                        "account_id": account_id,
                        "ciphertext": siegel.ciphertext,
                        "nonce": siegel.nonce,
                        "wrapped_dek": siegel.wrapped_dek,
                        "kek_id": siegel.kek_id,
                        "expires": gilt_bis,
                    },
                )
            ).scalar_one()
        return UUID(str(neu))

    async def lesen(self, account_id: UUID) -> tuple[bytes, datetime] | None:
        """Holt den jüngsten Token eines Kontos — oder ``None``.

        ``None`` und keine Ausnahme: Ein Konto ohne Zugangsdaten ist eine
        gewöhnliche Lage (frisch angelegt, widerrufen), kein Fehler. Wer
        dagegen einen Datensatz hat, der sich nicht öffnen lässt, bekommt die
        Ausnahme aus der Krypto — das ist keine gewöhnliche Lage.
        """
        async with self._engine.connect() as conn:
            zeile = (await conn.execute(_LESEN, {"account_id": account_id})).mappings().first()
        if zeile is None:
            return None

        siegel = SealedSecret(
            ciphertext=bytes(zeile["ciphertext"]),
            nonce=bytes(zeile["nonce"]),
            wrapped_dek=bytes(zeile["wrapped_dek"]),
            kek_id=str(zeile["kek_id"]),
        )
        token = await oeffnen(siegel, bindung=_bindung(account_id), schluessel=self._schluessel)
        return token, zeile["access_expires_at"]


def _bindung(account_id: UUID) -> bytes:
    """Woran der Geheimtext gebunden ist.

    Die Konto-ID in ihrer kanonischen Textform — nicht die Rohbytes der UUID:
    Was hier hineingeht, muss beim Öffnen zeichengenau dasselbe sein, und eine
    Textform ist die, die sich in einem Protokoll oder einer Migration
    unverändert wiedergeben lässt.
    """
    return str(account_id).encode("ascii")
