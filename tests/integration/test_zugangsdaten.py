"""Zugangsdaten im Betrieb — der Dump-Test.

Die Unit-Suite prüft die Krypto an ihren Zusagen. Hier steht die Frage
daneben, auf die es dem Betreiber ankommt: **Was sieht jemand, der die
Datenbank hat?**

Deshalb liest diese Suite die Zeilen so, wie ein Dump sie zeigt — roh, über
eine eigene Verbindung, ohne den Speicher zu fragen.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.credential_store import PostgresCredentialStore
from jarvis_core.crypto import SecretTampered
from jarvis_integrations import DateiSchluessel, schluesseldatei_anlegen

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

TOKEN = b"ya29.a0AfB_byC-nicht-echt-nur-ein-Testtoken"
GILT_BIS = datetime(2026, 8, 26, 18, 0, tzinfo=UTC)


async def _konto(engine: AsyncEngine) -> tuple[uuid.UUID, uuid.UUID]:
    uid, kid = uuid.uuid4(), uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Konto')"),
            {"i": uid, "m": f"{uid}@example.test"},
        )
        await conn.execute(
            text(
                "INSERT INTO connected_accounts "
                "(id, user_id, provider, external_id, display_label, granted_scopes) "
                "VALUES (:k, :u, 'google', :e, 'Testkonto', ARRAY['mail.read'])"
            ),
            {"k": kid, "u": uid, "e": f"ext-{kid}"},
        )
    return uid, kid


async def _aufraeumen(engine: AsyncEngine, uid: uuid.UUID) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})


@pytest.fixture
def schluessel(tmp_path: Path) -> DateiSchluessel:
    return DateiSchluessel(schluesseldatei_anlegen(tmp_path / "kek.json"))


class TestWasEinDumpZeigt:
    async def test_der_token_kommt_zurueck(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        uid, kid = await _konto(engine)
        try:
            speicher = PostgresCredentialStore(engine, schluessel=schluessel)
            await speicher.speichern(kid, token=TOKEN, gilt_bis=GILT_BIS)

            gelesen = await speicher.lesen(kid)

            assert gelesen is not None
            assert gelesen[0] == TOKEN
            assert gelesen[1] == GILT_BIS
        finally:
            await _aufraeumen(engine, uid)

    @pytest.mark.invariant("secrets-sealed-at-rest")
    async def test_in_der_zeile_steht_kein_klartext(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """**Die Zusage von ADR-008 an der echten Tabelle.**

        Gelesen wird roh, wie ein Dump es zeigt — nicht über den Speicher, der
        ja gerade entschlüsseln würde.
        """
        uid, kid = await _konto(engine)
        try:
            await PostgresCredentialStore(engine, schluessel=schluessel).speichern(
                kid, token=TOKEN, gilt_bis=GILT_BIS
            )

            async with engine.connect() as conn:
                zeile = (
                    (
                        await conn.execute(
                            text(
                                "SELECT ciphertext, nonce, wrapped_dek, kek_id "
                                "FROM oauth_credentials WHERE account_id = :k"
                            ),
                            {"k": kid},
                        )
                    )
                    .mappings()
                    .one()
                )

            roh = b"".join(
                bytes(w) if isinstance(w, (bytes, memoryview)) else str(w).encode()
                for w in zeile.values()
            )
            assert TOKEN not in roh
            assert b"ya29" not in roh
        finally:
            await _aufraeumen(engine, uid)

    async def test_ohne_schluessel_bleibt_die_zeile_zu(
        self, engine: AsyncEngine, schluessel: DateiSchluessel, tmp_path: Path
    ) -> None:
        """Ein Dump **mit** der Zeile und **ohne** die Schlüsseldatei ist wertlos.

        Nachgestellt mit einem anderen KEK unter derselben Kennung: Das ist die
        Lage eines Angreifers, der die Datenbank hat und die Datei nicht.
        """
        uid, kid = await _konto(engine)
        try:
            await PostgresCredentialStore(engine, schluessel=schluessel).speichern(
                kid, token=TOKEN, gilt_bis=GILT_BIS
            )
            fremder = DateiSchluessel(schluesseldatei_anlegen(tmp_path / "fremd.json"))

            from jarvis_core.ports.keys import UnknownKek

            with pytest.raises((SecretTampered, UnknownKek)):
                await PostgresCredentialStore(engine, schluessel=fremder).lesen(kid)
        finally:
            await _aufraeumen(engine, uid)

    @pytest.mark.invariant("secrets-sealed-at-rest")
    async def test_ein_verschobener_geheimtext_oeffnet_sich_nicht(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """Der Angriff, für den die Bindung da ist — an echten Zeilen.

        Zwei Konten, und der Geheimtext des einen wird in die Zeile des anderen
        kopiert. Ohne Bindung öffnete das System ihn bereitwillig.
        """
        uid_a, kid_a = await _konto(engine)
        uid_b, kid_b = await _konto(engine)
        try:
            speicher = PostgresCredentialStore(engine, schluessel=schluessel)
            await speicher.speichern(kid_a, token=TOKEN, gilt_bis=GILT_BIS)
            await speicher.speichern(kid_b, token=b"harmlos", gilt_bis=GILT_BIS)

            async with engine.begin() as conn:
                await conn.execute(
                    text(
                        "UPDATE oauth_credentials SET "
                        "  ciphertext = fremd.ciphertext, nonce = fremd.nonce, "
                        "  wrapped_dek = fremd.wrapped_dek, kek_id = fremd.kek_id "
                        "FROM (SELECT ciphertext, nonce, wrapped_dek, kek_id "
                        "        FROM oauth_credentials WHERE account_id = :a) AS fremd "
                        "WHERE account_id = :b"
                    ),
                    {"a": kid_a, "b": kid_b},
                )

            with pytest.raises(SecretTampered):
                await speicher.lesen(kid_b)
        finally:
            await _aufraeumen(engine, uid_a)
            await _aufraeumen(engine, uid_b)
