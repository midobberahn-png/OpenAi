"""Der Anspruch auf **einen** Rückruf.

**Was hier verhindert wird.** Der klassische Angriff auf einen
Zustimmungsablauf richtet sich nicht gegen unser Konto, sondern verschenkt
eines: Der Angreifer beginnt bei sich einen Vorgang, fängt den Rückruf ab und
bringt dessen Adresse in den Browser des Opfers. Läuft dort eine Sitzung, wird
**sein** Postfach an **dessen** Konto gehängt — und ab da liest er mit, ohne je
ein Passwort gesehen zu haben.

Dagegen hilft kein Prüfen im Nachhinein. Es hilft, dass der Rückruf nur zählt,
wenn er zu einem Vorgang gehört, den **dieselbe Sitzung** begonnen hat, und
dass er genau einmal zählt. Beides steht deshalb in derselben Anweisung, die
auch schreibt:

    UPDATE … SET consumed_at = :jetzt
     WHERE state_hash = :abdruck
       AND user_id    = :nutzer      -- die Bindung an die Sitzung
       AND consumed_at IS NULL       -- die Einmaligkeit
       AND expires_at  > :jetzt
    RETURNING …

Dieselbe Bauart wie beim Schrittanspruch und beim Grant-Verbrauch, und aus
demselben Grund: Wer erst liest und dann schreibt, hat dazwischen ein Fenster,
und zwei gleichzeitige Rückrufe gäben zwei Konten.

**Eigene Transaktion, wie beim Zugangsdatenspeicher.** Der Verbrauch muss auch
dann stehen, wenn der Request danach scheitert. Sonst wäre ein Rückruf, dessen
Tokentausch fehlschlägt, wieder einlösbar — und ein abgefangener ``code`` hätte
beliebig viele Versuche. Deshalb nimmt dieser Speicher eine ``AsyncEngine`` und
keine ``AsyncConnection``: Die Signatur soll den unsicheren Weg beim nächsten
Verdrahten gar nicht erst anbieten.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_core.crypto import SealedSecret, oeffnen, versiegeln
from jarvis_core.ports.keys import KeyProvider

__all__ = ["Angefangen", "Eingeloest", "PostgresAuthorizationStore"]

GUELTIGKEIT = timedelta(minutes=10)
"""Wie lange ein angefangener Vorgang einlösbar bleibt.

Zehn Minuten sind großzügig für einen Menschen, der zustimmt, und knapp für
eine Adresse, die in einem Verlauf, einem Protokoll oder einem
``Referer``-Header liegen bleibt. Die Frist ersetzt die Einmaligkeit nicht, sie
begrenzt nur, wie lange ein nicht eingelöster Vorgang überhaupt ein Ziel ist.
"""


@dataclass(frozen=True, slots=True)
class Angefangen:
    """Was der Aufrufer nach dem Anlegen in der Hand hat.

    ``state`` und ``verifier`` stehen **nur hier** im Klartext — in der Zeile
    liegt vom einen der Abdruck und vom anderen der Geheimtext.
    """

    id: UUID
    state: str
    verifier: str


@dataclass(frozen=True, slots=True)
class Eingeloest:
    """Ein Vorgang, der gerade verbraucht wurde."""

    id: UUID
    provider: str
    verifier: str
    requested_scopes: tuple[str, ...]


_ANLEGEN = text(
    """
    INSERT INTO oauth_authorizations (
        user_id, provider, state_hash,
        verifier_ciphertext, verifier_nonce, verifier_wrapped_dek, verifier_kek_id,
        requested_scopes, expires_at
    ) VALUES (
        :user_id, :provider, :state_hash,
        :ciphertext, :nonce, :wrapped_dek, :kek_id,
        :scopes, :expires
    )
    RETURNING id
    """
)

_EINLOESEN = text(
    """
    UPDATE oauth_authorizations
       SET consumed_at = :jetzt
     WHERE state_hash = :state_hash
       AND user_id = :user_id
       AND consumed_at IS NULL
       AND expires_at > :jetzt
    RETURNING id, provider, requested_scopes,
              verifier_ciphertext, verifier_nonce, verifier_wrapped_dek, verifier_kek_id
    """
)

_AUFRAEUMEN = text(
    """
    DELETE FROM oauth_authorizations
     WHERE expires_at < :jetzt
    """
)


class PostgresAuthorizationStore:
    """Legt angefangene Zustimmungsvorgänge an und löst sie genau einmal ein."""

    def __init__(self, engine: AsyncEngine, *, schluessel: KeyProvider) -> None:
        self._engine = engine
        self._schluessel = schluessel

    async def anlegen(
        self,
        user_id: UUID,
        *,
        provider: str,
        scopes: tuple[str, ...],
        jetzt: datetime,
    ) -> Angefangen:
        """Erzeugt ``state`` und PKCE-Verifier und schreibt den Vorgang.

        Beide Werte entstehen **hier** und nicht beim Aufrufer: Ein Vorgang,
        dessen Zufall von außen kommt, ist so gut wie diese Quelle. ``secrets``
        ist die richtige, ``random`` wäre es nicht — und der Unterschied fällt
        an keiner Stelle auf, an der man ihn suchen würde.
        """
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)

        # Der Verifier wird versiegelt, bevor die Zeile existiert — und damit,
        # bevor es die Kennung gibt, an die er gebunden werden könnte. Die
        # Bindung ist deshalb der Abdruck des ``state``: derselbe Wert, der die
        # Zeile eindeutig macht, und einer, den ein Angreifer nicht kennt.
        siegel = await versiegeln(
            verifier.encode("ascii"),
            bindung=_abdruck(state),
            schluessel=self._schluessel,
        )

        async with self._engine.begin() as conn:
            neu = (
                await conn.execute(
                    _ANLEGEN,
                    {
                        "user_id": user_id,
                        "provider": provider,
                        "state_hash": _abdruck(state),
                        "ciphertext": siegel.ciphertext,
                        "nonce": siegel.nonce,
                        "wrapped_dek": siegel.wrapped_dek,
                        "kek_id": siegel.kek_id,
                        "scopes": list(scopes),
                        "expires": jetzt + GUELTIGKEIT,
                    },
                )
            ).scalar_one()
        return Angefangen(id=UUID(str(neu)), state=state, verifier=verifier)

    async def einloesen(self, state: str, *, user_id: UUID, jetzt: datetime) -> Eingeloest | None:
        """Verbraucht den Vorgang — oder gibt ``None``.

        ``None`` deckt vier Lagen ab, und das ist Absicht: unbekannter
        ``state``, fremder Nutzer, bereits verbraucht, abgelaufen. Der Aufrufer
        soll sie **nicht** unterscheiden können, und der Nutzer schon gar
        nicht. Eine Antwort, die „schon verbraucht" von „gibt es nicht"
        trennte, verriete einem Angreifer, ob sein untergeschobener Rückruf beim
        Opfer angekommen ist.
        """
        async with self._engine.begin() as conn:
            zeile = (
                (
                    await conn.execute(
                        _EINLOESEN,
                        {"state_hash": _abdruck(state), "user_id": user_id, "jetzt": jetzt},
                    )
                )
                .mappings()
                .first()
            )

        if zeile is None:
            return None

        verifier = await oeffnen(
            SealedSecret(
                ciphertext=bytes(zeile["verifier_ciphertext"]),
                nonce=bytes(zeile["verifier_nonce"]),
                wrapped_dek=bytes(zeile["verifier_wrapped_dek"]),
                kek_id=str(zeile["verifier_kek_id"]),
            ),
            bindung=_abdruck(state),
            schluessel=self._schluessel,
        )
        return Eingeloest(
            id=UUID(str(zeile["id"])),
            provider=str(zeile["provider"]),
            verifier=verifier.decode("ascii"),
            requested_scopes=tuple(zeile["requested_scopes"]),
        )

    async def aufraeumen(self, *, jetzt: datetime) -> int:
        """Löscht abgelaufene Vorgänge und meldet, wie viele.

        Verbrauchte werden **mitgelöscht**, sobald sie abgelaufen sind, und
        nicht früher: Solange die Frist läuft, ist die verbrauchte Zeile das,
        was einen zweiten Rückruf mit demselben ``state`` scheitern lässt.
        Wer sie beim Verbrauch entfernte, machte aus der Einmaligkeit wieder
        ein „kennen wir nicht" — richtig im Ergebnis, aber aus dem falschen
        Grund, und ohne Spur.
        """
        async with self._engine.begin() as conn:
            ergebnis = await conn.execute(_AUFRAEUMEN, {"jetzt": jetzt})
        return ergebnis.rowcount or 0


def _abdruck(state: str) -> bytes:
    """SHA-256 des ``state``.

    Roh und ohne Salz — anders als bei einem Passwort ist das hier richtig: Der
    Wert hat 256 Bit Entropie aus ``secrets``, es gibt nichts zu raten, und der
    Abdruck muss sich in einer ``WHERE``-Bedingung wiederfinden lassen. Ein
    Salz je Zeile machte genau diese Suche unmöglich.
    """
    return hashlib.sha256(state.encode("ascii")).digest()
