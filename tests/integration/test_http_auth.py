"""Die HTTP-Schicht unter Angriff.

Die Fälle stammen aus dem Review: gefälschte Identität, fremde Sitzung,
abgelaufene und widerrufene Sitzung, falsche Challenge, falscher Origin,
falsche RP-ID, Challenge-Replay, fremdes Credential, Zählerregression.

Geprüft wird gegen die **echte** Bibliothek und einen **echten**
Software-Authenticator (``tests/authenticator.py``). Ein Mock würde nur
zeigen, dass der Mock tut, was man ihm sagt — Origin- und Signaturprüfung
liegen aber gerade in der Bibliothek dahinter.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.main import create_app
from tests.authenticator import SoftwareAuthenticator

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

MAIL_PRAEFIX = "httptest-"


@pytest_asyncio.fixture
async def client(engine: AsyncEngine, frische_grenzen: None) -> AsyncIterator[AsyncClient]:
    """Die App gegen die echte Datenbank.

    Kein Rollback wie bei den übrigen Integrationstests: Die App führt ihre
    eigenen Transaktionen, und ein Anmeldeablauf über mehrere Requests muss
    Zwischenstände sehen. Aufgeräumt wird deshalb am Ende — über die
    Nutzertabelle, an der alles per ``ON DELETE CASCADE`` hängt.
    """
    from jarvis_api.db.session import dispose
    from jarvis_api.deps import dispose_redis

    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://test"
    ) as http:
        yield http

    # Die Engine der App ist ein Modulzustand und hängt am Event-Loop des
    # Tests, der sie erzeugt hat. Ohne dieses Aufräumen erbt der nächste Test
    # Verbindungen aus einem geschlossenen Loop.
    await dispose()
    await dispose_redis()

    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users WHERE email LIKE :p"), {"p": f"{MAIL_PRAEFIX}%"})


async def _wipe_users(engine: AsyncEngine) -> None:
    """Der Bootstrap verlangt eine leere Nutzertabelle."""
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users"))


def _challenge_bytes(payload: dict[str, Any]) -> bytes:
    from webauthn.helpers import base64url_to_bytes

    return bytes(base64url_to_bytes(payload["challenge"]))


async def _bootstrap(client: AsyncClient, engine: AsyncEngine) -> SoftwareAuthenticator:
    """Erstinbetriebnahme mit registriertem Passkey."""
    await _wipe_users(engine)
    antwort = await client.post(
        "/auth/bootstrap",
        json={"email": f"{MAIL_PRAEFIX}{uuid.uuid4()}@example.test", "display_name": "Testnutzer"},
    )
    assert antwort.status_code == 201, antwort.text

    authenticator = SoftwareAuthenticator()
    challenge = _challenge_bytes(antwort.json())
    fertig = await client.post(
        "/auth/register/finish",
        json={
            "credential": authenticator.register(challenge),
            "challenge": antwort.json()["challenge"],
            "device_label": "Testgerät",
        },
    )
    assert fertig.status_code == 201, fertig.text
    return authenticator


async def _login(client: AsyncClient, authenticator: SoftwareAuthenticator, **kw: Any) -> Any:
    start = await client.post("/auth/login/start")
    assert start.status_code == 200
    challenge = _challenge_bytes(start.json())
    return await client.post(
        "/auth/login/finish",
        json={
            "credential": authenticator.authenticate(challenge, **kw),
            "challenge": start.json()["challenge"],
        },
    )


# ==========================================================================
# Der Normalfall — er muss funktionieren
# ==========================================================================


class TestAnmeldeweg:
    async def test_bootstrap_registrierung_anmeldung(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        authenticator = await _bootstrap(client, engine)

        angemeldet = await _login(client, authenticator)
        assert angemeldet.status_code == 200, angemeldet.text
        assert client.cookies.get("jarvis_session")

        wer = await client.get("/auth/me")
        assert wer.status_code == 200
        assert wer.json()["session_id"] == angemeldet.json()["session_id"]

    async def test_sitzungsuebersicht_zeigt_das_eigene_geraet(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        authenticator = await _bootstrap(client, engine)
        await _login(client, authenticator)

        sitzungen = await client.get("/auth/sessions")
        assert sitzungen.status_code == 200
        eintraege = sitzungen.json()
        assert len(eintraege) == 1
        assert eintraege[0]["is_current"] is True

    async def test_abmelden_beendet_die_sitzung(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        authenticator = await _bootstrap(client, engine)
        await _login(client, authenticator)

        assert (await client.post("/auth/logout")).status_code == 204
        assert (await client.get("/auth/me")).status_code == 401


# ==========================================================================
# Identität
# ==========================================================================


class TestIdentitaet:
    @pytest.mark.invariant("identity-derives-from-session")
    async def test_ohne_sitzung_keine_auskunft(self, client: AsyncClient) -> None:
        for pfad in ("/auth/me", "/auth/sessions"):
            assert (await client.get(pfad)).status_code == 401

    @pytest.mark.invariant("identity-derives-from-session")
    async def test_behauptete_identitaet_im_body_wirkt_nicht(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der kürzeste Angriffsweg des Systems — er existiert nicht.

        Die Felder werden entgegengenommen und ignoriert, weil kein
        Request-Modell sie führt. Das Ergebnis ist dasselbe wie ohne sie: 401.
        """
        await _bootstrap(client, engine)
        antwort = await client.post(
            "/auth/login/finish",
            json={
                "credential": {"id": "x"},
                "challenge": "AAAA",
                "user_id": str(uuid.uuid4()),
                "session_id": str(uuid.uuid4()),
            },
        )
        assert antwort.status_code in {400, 401}

    @pytest.mark.invariant("identity-derives-from-session")
    async def test_erfundener_token_meldet_niemanden_an(self, client: AsyncClient) -> None:
        antwort = await client.get("/auth/me", headers={"Authorization": "Bearer " + "x" * 43})
        assert antwort.status_code == 401

    @pytest.mark.invariant("session-verified-before-approval")
    async def test_widerrufene_sitzung_verliert_den_zugang(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        authenticator = await _bootstrap(client, engine)
        await _login(client, authenticator)
        assert (await client.get("/auth/me")).status_code == 200

        assert (await client.delete("/auth/sessions")).status_code == 200
        assert (await client.get("/auth/me")).status_code == 401

    @pytest.mark.invariant("identity-derives-from-session")
    async def test_fremde_sitzung_laesst_sich_nicht_beenden(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """``target_id`` ist eine Ressourcenkennung, keine Identität. Ohne den
        Abgleich mit den eigenen Sitzungen wäre der Endpunkt ein Fernabmelder
        für fremde Konten."""
        authenticator = await _bootstrap(client, engine)
        await _login(client, authenticator)

        antwort = await client.delete(f"/auth/sessions/{uuid.uuid4()}")
        assert antwort.status_code == 404, "Und nicht 403 — die Existenz geht niemanden an"


# ==========================================================================
# Erstinbetriebnahme
# ==========================================================================


class TestBootstrap:
    @pytest.mark.invariant("bootstrap-only-once")
    async def test_zweiter_bootstrap_wird_abgewiesen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        await _bootstrap(client, engine)
        zweiter = await client.post(
            "/auth/bootstrap",
            json={"email": f"{MAIL_PRAEFIX}zweiter@example.test", "display_name": "Angreifer"},
        )
        assert zweiter.status_code == 409

    @pytest.mark.invariant("bootstrap-only-once")
    async def test_registrierung_verlangt_sonst_eine_sitzung(self, client: AsyncClient) -> None:
        """Nach der Erstinbetriebnahme gibt es keinen offenen Weg mehr, einen
        Passkey anzulegen."""
        assert (await client.post("/auth/register/start")).status_code == 401


# ==========================================================================
# WebAuthn unter Angriff
# ==========================================================================


class TestWebAuthnAngriffe:
    async def test_falscher_origin_wird_abgewiesen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die Eigenschaft, wegen der Passkeys phishing-resistent sind: Ein
        Authenticator auf einer nachgebauten Seite signiert für *deren*
        Herkunft."""
        authenticator = await _bootstrap(client, engine)
        antwort = await _login(client, authenticator, origin="https://jarvis-phishing.example")
        assert antwort.status_code == 401

    async def test_falsche_rp_id_wird_abgewiesen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        authenticator = await _bootstrap(client, engine)
        antwort = await _login(client, authenticator, rp_id="angreifer.example")
        assert antwort.status_code == 401

    async def test_gefaelschte_signatur_wird_abgewiesen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        authenticator = await _bootstrap(client, engine)
        antwort = await _login(client, authenticator, break_signature=True)
        assert antwort.status_code == 401

    @pytest.mark.invariant("passkey-challenge-single-use")
    async def test_wiederholte_assertion_wird_abgewiesen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Replay: Dieselbe mitgeschnittene Antwort ein zweites Mal.

        Die Signatur ist gültig, der Origin stimmt, der Zähler passt — allein
        die Challenge ist verbraucht. Das ist der Fall, den nur die Anwendung
        erkennen kann.
        """
        authenticator = await _bootstrap(client, engine)
        start = await client.post("/auth/login/start")
        challenge = _challenge_bytes(start.json())
        antwort = authenticator.authenticate(challenge)
        koerper = {"credential": antwort, "challenge": start.json()["challenge"]}

        erste = await client.post("/auth/login/finish", json=koerper)
        zweite = await client.post("/auth/login/finish", json=koerper)
        assert erste.status_code == 200
        assert zweite.status_code == 401

    @pytest.mark.invariant("passkey-challenge-single-use")
    async def test_fremde_challenge_wird_abgewiesen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Eine selbst erzeugte Challenge, die nie ausgestellt wurde."""
        from webauthn.helpers import bytes_to_base64url

        authenticator = await _bootstrap(client, engine)
        eigene = os.urandom(32)
        antwort = await client.post(
            "/auth/login/finish",
            json={
                "credential": authenticator.authenticate(eigene),
                "challenge": bytes_to_base64url(eigene),
            },
        )
        assert antwort.status_code == 401

    async def test_unbekanntes_credential_wird_abgewiesen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Ein gültig signierender, aber nicht registrierter Authenticator."""
        await _bootstrap(client, engine)
        fremder = SoftwareAuthenticator()
        antwort = await _login(client, fremder)
        assert antwort.status_code == 401

    @pytest.mark.invariant("passkey-clone-detection")
    async def test_zaehlerregression_wird_abgewiesen(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der geklonte Schlüssel: dieselbe Identität, ein alter Zählerstand."""
        authenticator = await _bootstrap(client, engine)
        assert (await _login(client, authenticator)).status_code == 200
        assert (await _login(client, authenticator)).status_code == 200

        # Der Klon meldet einen Stand, den der echte Schlüssel längst
        # überschritten hat.
        zurueck = await _login(client, authenticator, sign_count=1)
        assert zurueck.status_code == 401

    async def test_fehlermeldungen_unterscheiden_sich_nicht(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Jede Unterscheidung wäre ein Orakel über existierende Konten und
        Schlüssel."""
        authenticator = await _bootstrap(client, engine)
        fremder = SoftwareAuthenticator()

        falsche_herkunft = await _login(client, authenticator, origin="https://boese.example")
        unbekannt = await _login(client, fremder)

        assert falsche_herkunft.status_code == unbekannt.status_code == 401
        assert falsche_herkunft.json()["detail"] == unbekannt.json()["detail"]


class TestSystem:
    async def test_health_verraet_nichts(self, client: AsyncClient) -> None:
        antwort = await client.get("/health")
        assert antwort.status_code == 200
        assert set(antwort.json()) == {"status", "env"}


# ==========================================================================
# Zugriffsgrenzen an der HTTP-Grenze
# ==========================================================================


class TestZugriffsgrenzen:
    @pytest.mark.invariant("auth-endpoints-rate-limited")
    async def test_challenge_flut_wird_gestoppt(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Punkt 4 des Auftrags: Ein Angreifer kann durch Challenge-Fluten
        nicht unbegrenzt Datenbankzustand erzeugen.

        Geprüft wird nicht nur der Statuscode, sondern die Tabelle: Nach dem
        Limit entstehen keine weiteren Zeilen.
        """
        from jarvis_core.limits import AUTH_CHALLENGE

        async def offene_challenges() -> int:
            async with engine.begin() as conn:
                return int(
                    (
                        await conn.execute(text("SELECT count(*) AS n FROM webauthn_challenges"))
                    ).scalar_one()
                )

        vorher = await offene_challenges()
        codes = [
            (await client.post("/auth/login/start")).status_code
            for _ in range(AUTH_CHALLENGE.per_client.limit + 5)
        ]
        nachher = await offene_challenges()

        assert 429 in codes, "Die Grenze muss greifen"
        angelegt = nachher - vorher
        assert angelegt <= AUTH_CHALLENGE.per_client.limit, (
            f"{angelegt} Challenges bei einer Grenze von {AUTH_CHALLENGE.per_client.limit}"
        )

    @pytest.mark.invariant("auth-endpoints-rate-limited")
    async def test_die_antwort_traegt_eine_wartezeit(self, client: AsyncClient) -> None:
        from jarvis_core.limits import AUTH_CHALLENGE

        letzte = None
        for _ in range(AUTH_CHALLENGE.per_client.limit + 2):
            letzte = await client.post("/auth/login/start")

        assert letzte is not None
        assert letzte.status_code == 429
        assert int(letzte.headers["retry-after"]) > 0

    @pytest.mark.invariant("auth-endpoints-rate-limited")
    async def test_getrennte_zaehler_je_zeremonie(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Punkt 2: Wer die Anmeldung flutet, sperrt damit nicht die
        Erstinbetriebnahme — und umgekehrt."""
        from jarvis_core.limits import AUTH_CHALLENGE

        await _wipe_users(engine)
        for _ in range(AUTH_CHALLENGE.per_client.limit + 2):
            await client.post("/auth/login/start")

        bootstrap = await client.post(
            "/auth/bootstrap",
            json={"email": f"{MAIL_PRAEFIX}getrennt@example.test", "display_name": "Getrennt"},
        )
        assert bootstrap.status_code == 201

    @pytest.mark.invariant("auth-endpoints-rate-limited")
    async def test_gefaelschte_weiterleitung_umgeht_nichts(self, client: AsyncClient) -> None:
        """Punkt 3: ``X-Forwarded-For`` wird ohne konfigurierten Proxy nicht
        geglaubt.

        Der Angreifer schickt für jede Anfrage eine andere Adresse. Ohne die
        Vertrauensprüfung hätte jede davon ihren eigenen Zähler — und das
        Limit wäre eine Zeile Code wert.
        """
        from jarvis_core.limits import AUTH_CHALLENGE

        codes = [
            (
                await client.post(
                    "/auth/login/start", headers={"X-Forwarded-For": f"203.0.113.{i}"}
                )
            ).status_code
            for i in range(AUTH_CHALLENGE.per_client.limit + 3)
        ]
        assert 429 in codes, "Ein gefälschter Header darf keinen neuen Zähler eröffnen"

    @pytest.mark.invariant("auth-endpoints-rate-limited")
    async def test_erfolg_setzt_den_zaehler_nicht_zurueck(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Punkt 7: Eine erfolgreiche Anmeldung leert keinen Bucket.

        Der bequeme Entwurf wäre „bei Erfolg zurücksetzen". Er ist der Weg, auf
        dem ein Angreifer mit einem einzigen gültigen Anlauf sein Kontingent
        erneuert — beliebig oft, solange er zwischendurch echte Anmeldungen
        einstreut.

        Gezählt wird exakt: Die Anmeldung hat eine Challenge verbraucht. Ohne
        Reset sind danach genau ``limit - 1`` weitere möglich, der nächste
        Aufruf wird gesperrt. Mit Reset wären es ``limit``.
        """
        from jarvis_core.limits import AUTH_CHALLENGE

        authenticator = await _bootstrap(client, engine)
        assert (await _login(client, authenticator)).status_code == 200

        verbraucht = 1
        codes = [
            (await client.post("/auth/login/start")).status_code
            for _ in range(AUTH_CHALLENGE.per_client.limit - verbraucht)
        ]
        assert all(code == 200 for code in codes), "Das Kontingent gilt bis zur Grenze"

        gesperrt = await client.post("/auth/login/start")
        assert gesperrt.status_code == 429, "Der Erfolg hat den Zähler nicht geleert"

    @pytest.mark.invariant("auth-endpoints-rate-limited")
    async def test_die_sperre_verraet_keine_konto_existenz(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Punkt 6: Die Antwort ist dieselbe, egal ob dahinter etwas liegt.

        Sie muss es sein: Die Endpunkte nehmen ohnehin keine Nutzerangabe
        entgegen — es gibt nichts, wonach sich unterscheiden ließe. Der Test
        hält fest, dass das so bleibt.
        """
        from jarvis_core.limits import AUTH_CHALLENGE

        await _bootstrap(client, engine)
        antworten = [
            await client.post("/auth/login/start")
            for _ in range(AUTH_CHALLENGE.per_client.limit + 3)
        ]
        gesperrt = [a for a in antworten if a.status_code == 429]
        assert gesperrt
        assert len({a.json()["detail"] for a in gesperrt}) == 1
