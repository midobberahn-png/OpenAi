"""Passkeys — was eine WebAuthn-Bibliothek nicht prüfen kann.

Signatur, Origin und RP-ID prüft die Bibliothek. Sie weiß aber nicht, ob diese
Challenge schon einmal verwendet wurde, ob sie für einen anderen Zweck
ausgestellt war oder ob der Signaturzähler rückwärts läuft. Genau diese Fälle
stehen hier — und sie lassen sich prüfen, ohne einen Authenticator zu
simulieren.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from jarvis_contracts import ChallengePurpose, PasskeyCredential, WebAuthnChallenge
from jarvis_core.auth import (
    AuthenticationFailed,
    CloneSuspicion,
    PasskeyService,
    SessionManager,
    sign_count_is_plausible,
)
from tests.unit.test_sessions import InMemorySessions

pytestmark = pytest.mark.security

NOW = datetime(2026, 8, 19, 10, 0, tzinfo=UTC)
USER = UUID("11111111-1111-1111-1111-111111111111")
FREMDER = UUID("99999999-9999-9999-9999-999999999999")
CRED_ID = b"credential-eins"


class InMemoryChallenges:
    """Bildet den atomaren Einmalverbrauch nach."""

    def __init__(self) -> None:
        self.rows: dict[bytes, WebAuthnChallenge] = {}

    async def issue(self, challenge: WebAuthnChallenge) -> None:
        self.rows[challenge.value] = challenge

    async def consume(
        self, value: bytes, purpose: ChallengePurpose, now: datetime
    ) -> WebAuthnChallenge | None:
        stored = self.rows.get(value)
        if stored is None or stored.purpose is not purpose:
            return None
        if not stored.is_valid_at(now):
            return None
        self.rows[value] = stored.model_copy(update={"used_at": now})
        return stored


class InMemoryCredentials:
    def __init__(self) -> None:
        self.rows: list[PasskeyCredential] = []

    async def add(self, credential: PasskeyCredential) -> None:
        self.rows.append(credential)

    async def by_credential_id(self, credential_id: bytes) -> PasskeyCredential | None:
        return next((c for c in self.rows if c.credential_id == credential_id), None)

    async def for_user(self, user_id: UUID) -> list[PasskeyCredential]:
        return [c for c in self.rows if c.user_id == user_id]

    async def record_use(self, credential_id: UUID, sign_count: int, now: datetime) -> None:
        self.rows = [
            c.model_copy(update={"sign_count": sign_count, "last_used_at": now})
            if c.id == credential_id
            else c
            for c in self.rows
        ]


class FakeVerifier:
    """Ersetzt die Kryptografie durch eine feste Antwort.

    Was hier geprüft wird, liegt *vor* und *nach* der Signaturprüfung. Ein
    echter Authenticator im Test würde die eigentlichen Regeln verdecken,
    nicht belegen.
    """

    def __init__(self, *, sign_count: int = 1, fails: bool = False) -> None:
        self.sign_count = sign_count
        self.fails = fails
        self.seen_challenges: list[bytes] = []

    class _Attestation:
        def __init__(self, sign_count: int) -> None:
            self.credential_id = CRED_ID
            self.public_key = b"oeffentlicher-schluessel"
            self.sign_count = sign_count

    class _Assertion:
        def __init__(self, sign_count: int) -> None:
            self.new_sign_count = sign_count

    def verify_registration(self, credential: dict[str, Any] | str, *, challenge: bytes) -> Any:
        self.seen_challenges.append(challenge)
        if self.fails:
            raise ValueError("Signatur passt nicht")
        return self._Attestation(self.sign_count)

    def verify_authentication(
        self,
        credential: dict[str, Any] | str,
        *,
        challenge: bytes,
        public_key: bytes,
        sign_count: int,
    ) -> Any:
        self.seen_challenges.append(challenge)
        if self.fails:
            raise ValueError("Signatur passt nicht")
        return self._Assertion(self.sign_count)


def _service(
    *, verifier: FakeVerifier | None = None, ttl: timedelta = timedelta(minutes=5)
) -> tuple[PasskeyService, InMemoryChallenges, InMemoryCredentials, FakeVerifier]:
    challenges = InMemoryChallenges()
    credentials = InMemoryCredentials()
    used = verifier or FakeVerifier()
    service = PasskeyService(
        challenges=challenges,
        credentials=credentials,
        verifier=used,
        sessions=SessionManager(InMemorySessions()),  # type: ignore[arg-type]
        challenge_ttl=ttl,
    )
    return service, challenges, credentials, used


async def _registriere(service: PasskeyService, *, now: datetime = NOW) -> PasskeyCredential:
    challenge = await service.begin_registration(USER, now=now)
    return await service.finish_registration(
        {"id": "x"}, challenge_value=challenge.value, device_label="MacBook", now=now
    )


class TestRegistrierung:
    async def test_normalfall(self) -> None:
        service, _, credentials, _ = _service()
        passkey = await _registriere(service)

        assert passkey.user_id == USER
        assert passkey.device_label == "MacBook"
        assert await credentials.by_credential_id(CRED_ID) is not None

    async def test_nutzer_stammt_aus_der_challenge_nicht_aus_dem_request(self) -> None:
        """Der Request enthält keine ``user_id`` — es gibt keinen Parameter
        dafür. Sonst ließe sich ein fremdes Konto mit einem eigenen Passkey
        ausstatten."""
        import inspect

        signature = inspect.signature(PasskeyService.finish_registration)
        assert "user_id" not in signature.parameters

    async def test_derselbe_passkey_wird_nicht_zweimal_registriert(self) -> None:
        service, _, _, _ = _service()
        await _registriere(service)
        with pytest.raises(AuthenticationFailed, match="bereits registriert"):
            await _registriere(service)

    async def test_gescheiterte_signatur_legt_nichts_an(self) -> None:
        service, _, credentials, _ = _service(verifier=FakeVerifier(fails=True))
        challenge = await service.begin_registration(USER, now=NOW)
        with pytest.raises(AuthenticationFailed):
            await service.finish_registration({"id": "x"}, challenge_value=challenge.value, now=NOW)
        assert credentials.rows == []


class TestChallenge:
    @pytest.mark.invariant("passkey-challenge-single-use")
    async def test_challenge_gilt_genau_einmal(self) -> None:
        """Ohne diese Regel ist eine mitgeschnittene Zeremonie beliebig
        wiederholbar."""
        service, _, _, _ = _service()
        challenge = await service.begin_registration(USER, now=NOW)
        await service.finish_registration({"id": "x"}, challenge_value=challenge.value, now=NOW)

        with pytest.raises(AuthenticationFailed, match=r"bereits verwendet|unbekannt"):
            await service.finish_registration({"id": "x"}, challenge_value=challenge.value, now=NOW)

    @pytest.mark.invariant("passkey-challenge-single-use")
    async def test_abgelaufene_challenge_wird_abgewiesen(self) -> None:
        service, _, _, _ = _service(ttl=timedelta(minutes=5))
        challenge = await service.begin_registration(USER, now=NOW)
        with pytest.raises(AuthenticationFailed):
            await service.finish_registration(
                {"id": "x"},
                challenge_value=challenge.value,
                now=NOW + timedelta(minutes=6),
            )

    @pytest.mark.invariant("passkey-challenge-single-use")
    async def test_registrierungs_challenge_meldet_niemanden_an(self) -> None:
        """Ohne Zweckbindung könnte ein Angreifer die Registrierung anstoßen,
        um an eine gültige Challenge für die Anmeldung zu kommen."""
        service, _, _, _ = _service()
        await _registriere(service)
        fremde = await service.begin_registration(USER, now=NOW)

        with pytest.raises(AuthenticationFailed):
            await service.finish_authentication(
                {"id": "x"},
                challenge_value=fremde.value,
                credential_id=CRED_ID,
                now=NOW,
            )

    async def test_anmelde_challenge_nennt_keinen_nutzer(self) -> None:
        """Sonst wäre die Anmeldemaske ein Verzeichnis: Wer eine Challenge für
        ein Konto bekommt, weiß, dass es das Konto gibt."""
        service, _, _, _ = _service()
        challenge = await service.begin_authentication(now=NOW)
        assert challenge.user_id is None
        assert challenge.purpose is ChallengePurpose.AUTHENTICATION


class TestAnmeldung:
    async def test_erfolgreiche_anmeldung_stellt_eine_sitzung_aus(self) -> None:
        service, _, _, verifier = _service(verifier=FakeVerifier(sign_count=0))
        await _registriere(service)

        # Der Authenticator zählt bei der ersten Nutzung hoch.
        verifier.sign_count = 1
        challenge = await service.begin_authentication(now=NOW)
        issued = await service.finish_authentication(
            {"id": "x"},
            challenge_value=challenge.value,
            credential_id=CRED_ID,
            client="iPhone",
            now=NOW,
        )
        assert issued.session.user_id == USER
        assert issued.session.client == "iPhone"
        assert issued.token

    async def test_der_nutzer_folgt_aus_dem_passkey(self) -> None:
        """Es gibt keinen Weg, den Nutzer zu benennen — sonst dürfte der
        Angreifer sagen, in welches Konto er einbricht."""
        import inspect

        signature = inspect.signature(PasskeyService.finish_authentication)
        assert "user_id" not in signature.parameters

    async def test_unbekannter_passkey_meldet_niemanden_an(self) -> None:
        service, _, _, _ = _service()
        challenge = await service.begin_authentication(now=NOW)
        with pytest.raises(AuthenticationFailed, match="nicht registriert"):
            await service.finish_authentication(
                {"id": "x"},
                challenge_value=challenge.value,
                credential_id=b"gibt-es-nicht",
                now=NOW,
            )

    async def test_zaehler_wird_fortgeschrieben(self) -> None:
        service, _, credentials, verifier = _service(verifier=FakeVerifier(sign_count=1))
        await _registriere(service)

        verifier.sign_count = 7
        challenge = await service.begin_authentication(now=NOW)
        await service.finish_authentication(
            {"id": "x"}, challenge_value=challenge.value, credential_id=CRED_ID, now=NOW
        )
        gespeichert = await credentials.by_credential_id(CRED_ID)
        assert gespeichert is not None
        assert gespeichert.sign_count == 7
        assert gespeichert.last_used_at == NOW


class TestKlonerkennung:
    @pytest.mark.invariant("passkey-clone-detection")
    def test_zaehler_muss_steigen(self) -> None:
        assert sign_count_is_plausible(5, 6)
        assert not sign_count_is_plausible(5, 5)
        assert not sign_count_is_plausible(5, 4)

    @pytest.mark.invariant("passkey-clone-detection")
    def test_zwei_nullen_sind_kein_verdacht(self) -> None:
        """Synchronisierte Passkeys von Apple und Google führen keinen Zähler
        und melden dauerhaft 0. Ein Ablehnen sperrte die verbreitetste Bauart
        aus."""
        assert sign_count_is_plausible(0, 0)

    @pytest.mark.invariant("passkey-clone-detection")
    async def test_nicht_steigender_zaehler_verhindert_die_anmeldung(self) -> None:
        service, _, _, verifier = _service(verifier=FakeVerifier(sign_count=9))
        await _registriere(service)

        # Der Authenticator meldet einen Zähler, der nicht über dem
        # gespeicherten liegt: Es gibt den Schlüssel zweimal.
        verifier.sign_count = 9
        challenge = await service.begin_authentication(now=NOW)
        with pytest.raises(CloneSuspicion):
            await service.finish_authentication(
                {"id": "x"}, challenge_value=challenge.value, credential_id=CRED_ID, now=NOW
            )

    async def test_klonverdacht_ist_ein_eigener_fall(self) -> None:
        """Er wird abgelehnt wie jeder Fehlschlag, ist aber unterscheidbar —
        das Audit und die Benachrichtigung des Nutzers brauchen den
        Unterschied."""
        assert issubclass(CloneSuspicion, AuthenticationFailed)

    async def test_verdacht_sperrt_den_passkey_nicht_automatisch(self) -> None:
        """Ein automatisches Sperren wäre für einen Angreifer ein bequemer
        Weg, jemanden auszusperren: Ein einziger Anmeldeversuch mit altem
        Zähler genügte."""
        service, _, credentials, verifier = _service(verifier=FakeVerifier(sign_count=9))
        await _registriere(service)

        verifier.sign_count = 3
        challenge = await service.begin_authentication(now=NOW)
        with pytest.raises(CloneSuspicion):
            await service.finish_authentication(
                {"id": "x"}, challenge_value=challenge.value, credential_id=CRED_ID, now=NOW
            )

        gespeichert = await credentials.by_credential_id(CRED_ID)
        assert gespeichert is not None
        assert gespeichert.sign_count == 9, "Der Zähler darf nicht zurückgesetzt werden"


class TestFehlerbilder:
    async def test_alle_fehlschlaege_tragen_dieselbe_ausnahme(self) -> None:
        """Jede Unterscheidung nach außen wäre ein Orakel über existierende
        Konten und Schlüssel."""
        service, _, _, _ = _service()
        challenge = await service.begin_authentication(now=NOW)

        with pytest.raises(AuthenticationFailed):
            await service.finish_authentication(
                {"id": "x"}, challenge_value=b"falsch" * 4, credential_id=CRED_ID, now=NOW
            )
        with pytest.raises(AuthenticationFailed):
            await service.finish_authentication(
                {"id": "x"},
                challenge_value=challenge.value,
                credential_id=b"unbekannt",
                now=NOW,
            )
