"""Passkey-Persistenz gegen die echte Datenbank.

Zwei Eigenschaften lassen sich nur hier zeigen:

* Der **atomare** Verbrauch einer Challenge. Ein In-Memory-Doppel kann
  Einmaligkeit nachbilden, aber nicht belegen — bei zwei gleichzeitigen
  Anfragen entscheidet die Datenbank, nicht die Anwendung.
* Die zweite Linie gegen den Klon: Selbst wenn ein Aufrufer die Prüfung im
  Kern überginge, ließe die ``UPDATE``-Bedingung den Signaturzähler nicht
  zurücklaufen.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from jarvis_api.db.webauthn_store import PostgresChallengeStore, PostgresCredentialStore
from jarvis_contracts import ChallengePurpose, PasskeyCredential, WebAuthnChallenge

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

NOW = datetime(2026, 8, 19, 11, 0, tzinfo=UTC)


async def _seed_user(conn: AsyncConnection) -> uuid.UUID:
    uid = uuid.uuid4()
    await conn.execute(
        text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Passkey')"),
        {"i": uid, "m": f"{uid}@example.test"},
    )
    return uid


def _challenge(
    user_id: uuid.UUID | None,
    *,
    purpose: ChallengePurpose = ChallengePurpose.REGISTRATION,
    value: bytes | None = None,
    ttl: timedelta = timedelta(minutes=5),
) -> WebAuthnChallenge:
    return WebAuthnChallenge(
        id=uuid.uuid4(),
        user_id=user_id,
        purpose=purpose,
        value=value or uuid.uuid4().bytes * 2,
        expires_at=NOW + ttl,
        created_at=NOW,
    )


class TestChallengeVerbrauch:
    @pytest.mark.invariant("passkey-challenge-single-use")
    async def test_zweiter_verbrauch_findet_nichts(self, conn: AsyncConnection) -> None:
        uid = await _seed_user(conn)
        store = PostgresChallengeStore(conn)
        challenge = _challenge(uid)
        await store.issue(challenge)

        erste = await store.consume(challenge.value, ChallengePurpose.REGISTRATION, NOW)
        zweite = await store.consume(challenge.value, ChallengePurpose.REGISTRATION, NOW)

        assert erste is not None
        assert erste.user_id == uid
        assert zweite is None

    @pytest.mark.invariant("passkey-challenge-single-use")
    async def test_falscher_zweck_loest_nicht_ein(self, conn: AsyncConnection) -> None:
        """Und verbraucht die Challenge auch nicht — sonst wäre der falsche
        Zweck ein Weg, fremde Zeremonien zu stören."""
        uid = await _seed_user(conn)
        store = PostgresChallengeStore(conn)
        challenge = _challenge(uid, purpose=ChallengePurpose.REGISTRATION)
        await store.issue(challenge)

        assert await store.consume(challenge.value, ChallengePurpose.AUTHENTICATION, NOW) is None
        assert await store.consume(challenge.value, ChallengePurpose.REGISTRATION, NOW) is not None

    @pytest.mark.invariant("passkey-challenge-single-use")
    async def test_abgelaufene_challenge_loest_nicht_ein(self, conn: AsyncConnection) -> None:
        uid = await _seed_user(conn)
        store = PostgresChallengeStore(conn)
        challenge = _challenge(uid, ttl=timedelta(minutes=5))
        await store.issue(challenge)

        assert (
            await store.consume(
                challenge.value, ChallengePurpose.REGISTRATION, NOW + timedelta(minutes=6)
            )
            is None
        )

    @pytest.mark.invariant("passkey-challenge-single-use")
    async def test_nebenlaeufig_gewinnt_genau_einer(self, engine: AsyncEngine) -> None:
        """Der Nachweis, den nur die Datenbank führen kann.

        Zehn gleichzeitige Einlösungen in **getrennten Verbindungen** — ein
        gemeinsamer Transaktionskontext würde die Nebenläufigkeit wegdefinieren,
        die hier geprüft wird. Genau einer gewinnt.
        """
        async with engine.begin() as setup:
            uid = await _seed_user(setup)
            challenge = _challenge(uid)
            await PostgresChallengeStore(setup).issue(challenge)

        async def versuch() -> bool:
            async with engine.begin() as conn:
                got = await PostgresChallengeStore(conn).consume(
                    challenge.value, ChallengePurpose.REGISTRATION, NOW
                )
                return got is not None

        ergebnisse = await asyncio.gather(*(versuch() for _ in range(10)))
        assert sum(ergebnisse) == 1, "Genau eine Einlösung darf gewinnen"

        async with engine.begin() as cleanup:
            await cleanup.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})


class TestPasskeySpeicher:
    async def test_passkey_ueberlebt_den_weg_durch_die_datenbank(
        self, conn: AsyncConnection
    ) -> None:
        uid = await _seed_user(conn)
        store = PostgresCredentialStore(conn)
        passkey = PasskeyCredential(
            id=uuid.uuid4(),
            user_id=uid,
            credential_id=b"cred-1",
            public_key=b"schluessel",
            sign_count=3,
            device_label="MacBook",
            created_at=NOW,
        )
        await store.add(passkey)

        geladen = await store.by_credential_id(b"cred-1")
        assert geladen is not None
        assert geladen.public_key == b"schluessel"
        assert geladen.sign_count == 3
        assert geladen.device_label == "MacBook"
        assert [c.id for c in await store.for_user(uid)] == [passkey.id]

    async def test_derselbe_passkey_kann_nicht_zweimal_existieren(
        self, conn: AsyncConnection
    ) -> None:
        """Die Eindeutigkeit von ``credential_id`` liegt in der Datenbank: Über
        sie wird bei der Anmeldung der Nutzer aufgelöst, und zwei Zeilen mit
        derselben Kennung wären zwei Antworten auf diese Frage."""
        from sqlalchemy.exc import IntegrityError

        uid = await _seed_user(conn)
        store = PostgresCredentialStore(conn)
        base = PasskeyCredential(
            id=uuid.uuid4(),
            user_id=uid,
            credential_id=b"cred-doppelt",
            public_key=b"k",
            sign_count=0,
            created_at=NOW,
        )
        await store.add(base)
        with pytest.raises(IntegrityError):
            await store.add(base.model_copy(update={"id": uuid.uuid4()}))

    @pytest.mark.invariant("passkey-clone-detection")
    async def test_zaehler_laeuft_nicht_rueckwaerts(self, conn: AsyncConnection) -> None:
        """Die zweite Linie hinter der Klon-Erkennung im Kern.

        Der Kern lehnt eine Anmeldung mit nicht gestiegenem Zähler ab. Selbst
        wenn ein Aufrufer daran vorbeikäme, dürfte der gespeicherte Wert nicht
        sinken — ein zurückgesetzter Zähler wäre der Zustand, in dem die
        Erkennung künftig schweigt.
        """
        uid = await _seed_user(conn)
        store = PostgresCredentialStore(conn)
        passkey = PasskeyCredential(
            id=uuid.uuid4(),
            user_id=uid,
            credential_id=b"cred-2",
            public_key=b"k",
            sign_count=10,
            created_at=NOW,
        )
        await store.add(passkey)

        await store.record_use(passkey.id, 4, NOW)
        unveraendert = await store.by_credential_id(b"cred-2")
        assert unveraendert is not None
        assert unveraendert.sign_count == 10

        await store.record_use(passkey.id, 11, NOW)
        erhoeht = await store.by_credential_id(b"cred-2")
        assert erhoeht is not None
        assert erhoeht.sign_count == 11
        assert erhoeht.last_used_at == NOW
