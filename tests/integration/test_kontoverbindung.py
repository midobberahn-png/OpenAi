"""Der Zustimmungsweg an der echten Datenbank — und der Angriff darauf.

Die Unit-Suite prüft, was der Adapter einer Antwort glaubt. Hier steht die
Frage daneben, die den Block trägt: **Kann jemand ein Konto verschenken?**

Der Angriff heißt „Authorization Code Injection" und ist der bekannteste gegen
einen Zustimmungsablauf. Er stiehlt nichts, er hängt etwas an: Der Angreifer
beginnt bei sich einen Vorgang, fängt seinen eigenen Rückruf ab und bringt
dessen Adresse in den Browser des Opfers. Läuft dort eine Sitzung, wird **sein**
Postfach an **dessen** Konto gehängt — und ab da liest er mit.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.authorization_store import GUELTIGKEIT, PostgresAuthorizationStore
from jarvis_core.ports.oauth import OAuthProvider, TokenExchangeFailed
from jarvis_integrations import DateiSchluessel, schluesseldatei_anlegen

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

JETZT = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)

ANBIETER = OAuthProvider(
    name="google",
    authorize_url="https://accounts.example.test/auth",
    token_url="https://token.example.test/token",
    client_id="client-123",
    client_secret="geheim-456",
    redirect_uri="http://localhost:8000/accounts/callback",
    scopes=("openid",),
)


@pytest.fixture
def schluessel(tmp_path: Path) -> DateiSchluessel:
    return DateiSchluessel(schluesseldatei_anlegen(tmp_path / "kek.json"))


async def _nutzer(engine: AsyncEngine) -> uuid.UUID:
    uid = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Konto')"),
            {"i": uid, "m": f"{uid}@example.test"},
        )
    return uid


async def _weg(engine: AsyncEngine, *uids: uuid.UUID) -> None:
    """Räumt genau die Nutzer weg, die dieser Test angelegt hat.

    Über die Kennung und nicht über ein Muster auf der Mailspalte: Ein ``LIKE``
    träfe irgendwann auch etwas, das ein anderer Test noch braucht.
    """
    async with engine.begin() as conn:
        for uid in uids:
            await conn.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})


class TestWemEinRueckrufGehoert:
    async def test_der_eigene_vorgang_laesst_sich_einloesen(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        uid = await _nutzer(engine)
        try:
            speicher = PostgresAuthorizationStore(engine, schluessel=schluessel)
            begonnen = await speicher.anlegen(
                uid, provider="google", scopes=("openid",), jetzt=JETZT
            )

            eingeloest = await speicher.einloesen(begonnen.state, user_id=uid, jetzt=JETZT)

            assert eingeloest is not None
            assert eingeloest.provider == "google"
            assert eingeloest.verifier == begonnen.verifier
        finally:
            await _weg(engine, uid)

    @pytest.mark.invariant("oauth-callback-belongs-to-its-session")
    async def test_ein_fremder_state_loest_nichts_ein(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """**Der Angriff, nachgestellt.**

        Der Angreifer beginnt den Vorgang, das Opfer legt ihn vor. Ohne die
        Bedingung ``user_id`` in der einlösenden Anweisung hinge danach das
        Postfach des Angreifers am Konto des Opfers.
        """
        angreifer = await _nutzer(engine)
        opfer = await _nutzer(engine)
        try:
            speicher = PostgresAuthorizationStore(engine, schluessel=schluessel)
            begonnen = await speicher.anlegen(
                angreifer, provider="google", scopes=("openid",), jetzt=JETZT
            )

            beim_opfer = await speicher.einloesen(begonnen.state, user_id=opfer, jetzt=JETZT)

            assert beim_opfer is None
        finally:
            await _weg(engine, angreifer, opfer)

    @pytest.mark.invariant("oauth-callback-belongs-to-its-session")
    async def test_der_abgewiesene_versuch_verbraucht_den_vorgang_nicht(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """Ein fremder Versuch darf den Vorgang **nicht** verbrauchen.

        Der Unterschied ist messbar und wichtig: Verbrauchte der abgewiesene
        Versuch die Zeile, könnte ein Angreifer jeden fremden Vorgang mit einem
        erratenen ``state`` lahmlegen — aus einem Schutz würde ein Hebel.
        """
        angreifer = await _nutzer(engine)
        opfer = await _nutzer(engine)
        try:
            speicher = PostgresAuthorizationStore(engine, schluessel=schluessel)
            begonnen = await speicher.anlegen(
                opfer, provider="google", scopes=("openid",), jetzt=JETZT
            )

            assert await speicher.einloesen(begonnen.state, user_id=angreifer, jetzt=JETZT) is None
            danach = await speicher.einloesen(begonnen.state, user_id=opfer, jetzt=JETZT)

            assert danach is not None
        finally:
            await _weg(engine, angreifer, opfer)


class TestEinmaligkeit:
    @pytest.mark.invariant("oauth-state-is-consumed-before-the-exchange")
    async def test_zweimal_einloesen_geht_nicht(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        uid = await _nutzer(engine)
        try:
            speicher = PostgresAuthorizationStore(engine, schluessel=schluessel)
            begonnen = await speicher.anlegen(
                uid, provider="google", scopes=("openid",), jetzt=JETZT
            )

            assert await speicher.einloesen(begonnen.state, user_id=uid, jetzt=JETZT) is not None
            assert await speicher.einloesen(begonnen.state, user_id=uid, jetzt=JETZT) is None
        finally:
            await _weg(engine, uid)

    @pytest.mark.invariant("oauth-state-is-consumed-before-the-exchange")
    async def test_von_zehn_gleichzeitigen_rueckrufen_gewinnt_genau_einer(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """**Nebenläufig, nicht nacheinander.**

        Ein Test, der zweimal hintereinander einlöst, prüft die Bedingung
        ``consumed_at IS NULL`` — nicht, dass sie in derselben Anweisung steht,
        die auch schreibt. Erst zehn parallele Verbindungen zeigen den
        Unterschied: Wer erst liest und dann schreibt, gewinnt hier zehnmal.
        """
        uid = await _nutzer(engine)
        try:
            speicher = PostgresAuthorizationStore(engine, schluessel=schluessel)
            begonnen = await speicher.anlegen(
                uid, provider="google", scopes=("openid",), jetzt=JETZT
            )

            ergebnisse = await asyncio.gather(
                *(speicher.einloesen(begonnen.state, user_id=uid, jetzt=JETZT) for _ in range(10))
            )

            assert sum(1 for e in ergebnisse if e is not None) == 1
        finally:
            await _weg(engine, uid)


class TestFrist:
    async def test_ein_abgelaufener_vorgang_loest_nichts_ein(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        uid = await _nutzer(engine)
        try:
            speicher = PostgresAuthorizationStore(engine, schluessel=schluessel)
            begonnen = await speicher.anlegen(
                uid, provider="google", scopes=("openid",), jetzt=JETZT
            )

            spaeter = JETZT + GUELTIGKEIT + timedelta(seconds=1)

            assert await speicher.einloesen(begonnen.state, user_id=uid, jetzt=spaeter) is None
        finally:
            await _weg(engine, uid)

    async def test_ein_verbrauchter_vorgang_bleibt_bis_zum_ablauf_stehen(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """Er ist das, was einen zweiten Rückruf scheitern lässt.

        Wer ihn beim Verbrauch entfernte, machte aus der Einmaligkeit wieder
        ein „kennen wir nicht" — richtig im Ergebnis, aber aus dem falschen
        Grund und ohne Spur.
        """
        uid = await _nutzer(engine)
        try:
            speicher = PostgresAuthorizationStore(engine, schluessel=schluessel)
            frisch = await speicher.anlegen(uid, provider="google", scopes=("openid",), jetzt=JETZT)
            await speicher.einloesen(frisch.state, user_id=uid, jetzt=JETZT)

            assert await speicher.aufraeumen(jetzt=JETZT) == 0
            assert await speicher.aufraeumen(jetzt=JETZT + GUELTIGKEIT * 2) >= 1
        finally:
            await _weg(engine, uid)


class TestWasEinDumpZeigt:
    @pytest.mark.invariant("secrets-sealed-at-rest")
    async def test_weder_state_noch_verifier_stehen_im_klartext(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """Gelesen wird roh, wie ein Dump es zeigt.

        ``state`` steht als Abdruck da — wer die Datenbank liest, soll keinen
        gültigen Rückruf bauen können. Der Verifier steht versiegelt da, weil
        er zusammen mit einem abgefangenen Code einlösbar wäre.
        """
        uid = await _nutzer(engine)
        try:
            speicher = PostgresAuthorizationStore(engine, schluessel=schluessel)
            begonnen = await speicher.anlegen(
                uid, provider="google", scopes=("openid",), jetzt=JETZT
            )

            async with engine.connect() as conn:
                zeile = (
                    (
                        await conn.execute(
                            text(
                                "SELECT state_hash, verifier_ciphertext, verifier_nonce, "
                                "verifier_wrapped_dek, verifier_kek_id "
                                "FROM oauth_authorizations WHERE id = :i"
                            ),
                            {"i": begonnen.id},
                        )
                    )
                    .mappings()
                    .one()
                )

            roh = b"".join(
                bytes(w) if isinstance(w, (bytes, memoryview)) else str(w).encode()
                for w in zeile.values()
            )
            assert begonnen.state.encode() not in roh
            assert begonnen.verifier.encode() not in roh
        finally:
            await _weg(engine, uid)


# ==========================================================================
# Über HTTP — dort, wo die Reihenfolge zugesagt ist
# ==========================================================================
#
# Die Prüfungen oben stehen am Speicher. Die Invariante
# ``oauth-state-is-consumed-before-the-exchange`` ist aber eine Aussage über
# die **Route**: dass sie erst verbraucht und dann tauscht. Am Speicher lässt
# sich das nicht zeigen — er kennt den Tausch nicht.


class _TauschScheitert:
    """Ein Anbieter, der den Code ablehnt. Danach zählt, was übrig bleibt."""

    async def tauschen(self, provider: object, *, code: str, verifier: str) -> object:
        raise TokenExchangeFailed("abgelehnt")

    async def erneuern(self, provider: object, *, refresh_token: str) -> object:
        raise TokenExchangeFailed("abgelehnt")


class TestUeberHttp:
    @pytest.mark.invariant("oauth-state-is-consumed-before-the-exchange")
    async def test_ein_gescheiterter_tausch_macht_den_vorgang_nicht_wieder_einloesbar(
        self,
        engine: AsyncEngine,
        frische_grenzen: None,
        monkeypatch: pytest.MonkeyPatch,
        schluessel: DateiSchluessel,
    ) -> None:
        """**Die Reihenfolge, gemessen.**

        Der bequeme Aufbau wäre: erst tauschen, dann verbrauchen — dann bliebe
        ein fehlgeschlagener Tausch wiederholbar. Genau das ist die Lücke: Ein
        abgefangener Code hätte beliebig viele Versuche. Hier scheitert der
        Tausch einmal, und der zweite Rückruf mit demselben ``state`` muss
        abgewiesen werden.
        """
        from httpx import ASGITransport, AsyncClient

        from jarvis_api.db.session import dispose
        from jarvis_api.deps import dispose_redis, key_provider, token_exchange
        from jarvis_api.main import create_app
        from jarvis_api.settings import get_settings
        from tests.integration.test_http_runs import _angemeldet

        monkeypatch.setattr(
            "jarvis_api.routes.accounts.oauth_providers", lambda _: {"google": ANBIETER}
        )
        app = create_app()
        app.dependency_overrides[key_provider] = lambda: schluessel
        app.dependency_overrides[token_exchange] = _TauschScheitert

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as http:
                await _angemeldet(http, engine)

                begonnen = await http.post("/accounts/google/authorize")
                assert begonnen.status_code == 200, begonnen.text
                state = _state_aus(begonnen.json()["authorization_url"])

                erster = await http.get("/accounts/callback", params={"code": "c", "state": state})
                assert erster.status_code == 502, erster.text

                zweiter = await http.get("/accounts/callback", params={"code": "c", "state": state})
                assert zweiter.status_code == 400, zweiter.text
        finally:
            await dispose()
            await dispose_redis()
            get_settings.cache_clear()

    async def test_ein_unkonfigurierter_anbieter_ist_nicht_vorhanden(
        self, engine: AsyncEngine, frische_grenzen: None, schluessel: DateiSchluessel
    ) -> None:
        """404 und nicht 501.

        Ob ein Anbieter unbekannt oder nur unkonfiguriert ist, ist eine
        Auskunft über den Server — sie geht den Aufrufer nichts an.
        """
        from httpx import ASGITransport, AsyncClient

        from jarvis_api.db.session import dispose
        from jarvis_api.deps import dispose_redis, key_provider
        from jarvis_api.main import create_app
        from jarvis_api.settings import get_settings
        from tests.integration.test_http_runs import _angemeldet

        app = create_app()
        app.dependency_overrides[key_provider] = lambda: schluessel
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as http:
                await _angemeldet(http, engine)

                antwort = await http.post("/accounts/google/authorize")

                assert antwort.status_code == 404, antwort.text
        finally:
            await dispose()
            await dispose_redis()
            get_settings.cache_clear()

    async def test_ohne_anmeldung_gibt_es_keinen_rueckruf(
        self, engine: AsyncEngine, frische_grenzen: None, schluessel: DateiSchluessel
    ) -> None:
        """Der Rückruf ist kein anonymer Endpunkt.

        Er ist der einzige, den ein Fremder auslöst — und ohne Sitzung könnte
        die Zugehörigkeitsbedingung nichts prüfen.
        """
        from httpx import ASGITransport, AsyncClient

        from jarvis_api.db.session import dispose
        from jarvis_api.deps import dispose_redis, key_provider
        from jarvis_api.main import create_app
        from jarvis_api.settings import get_settings

        app = create_app()
        app.dependency_overrides[key_provider] = lambda: schluessel
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as http:
                antwort = await http.get("/accounts/callback", params={"code": "c", "state": "s"})

                assert antwort.status_code == 401, antwort.text
        finally:
            await dispose()
            await dispose_redis()
            get_settings.cache_clear()


def _state_aus(url: str) -> str:
    from urllib.parse import parse_qs, urlparse

    return parse_qs(urlparse(url).query)["state"][0]
