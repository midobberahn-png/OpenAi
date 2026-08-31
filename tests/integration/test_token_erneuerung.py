"""Die Token-Erneuerung an der echten Datenbank.

Drei Fragen, und die dritte ist die, wegen der es diese Datei gibt:

1. Wird erneuert, wenn nötig — und **nicht**, wenn nicht?
2. Was passiert, wenn der Anbieter nein sagt? Und was, wenn er schweigt?
3. Was passiert, wenn zwei Aufrufe gleichzeitig feststellen, dass der Token
   abgelaufen ist?

Die dritte lässt sich nicht am Ergebnis prüfen. Zwei gleichzeitige
Erneuerungen liefern beide einen gültigen Token; sichtbar wird der Unterschied
nur, wenn man die Anbieteraufrufe **zählt**. Dieselbe Lehre wie beim N+1 im
Bestätigungsspeicher: Ein Test, der nur das Ergebnis ansieht, ist vor und nach
der Behebung gleich grün.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.account_store import PostgresAccountStore
from jarvis_api.db.credential_store import PostgresCredentialStore
from jarvis_api.token_service import KeinZugang, TokenService
from jarvis_api.tokenbuendel import buendeln, zerlegen
from jarvis_core.ports.oauth import (
    AuthorizationRevoked,
    OAuthProvider,
    TokenExchangeFailed,
    TokenSet,
)
from jarvis_integrations import DateiSchluessel, schluesseldatei_anlegen

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

JETZT = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
ABGELAUFEN = JETZT - timedelta(minutes=5)
NOCH_GUT = JETZT + timedelta(minutes=30)

ANBIETER = OAuthProvider(
    name="google",
    authorize_url="https://accounts.example.test/auth",
    token_url="https://token.example.test/token",
    client_id="client-123",
    client_secret="geheim-456",
    redirect_uri="http://localhost:8000/accounts/callback",
    scopes=("openid",),
)


class _Anbieter:
    """Eine Attrappe, die **mitzählt**.

    Der Zähler ist der eigentliche Messpunkt dieser Datei: Ob serialisiert
    wurde, steht nicht im Ergebnis, sondern in der Zahl der Aufrufe.
    """

    def __init__(self, *, antwort: TokenSet | None = None, fehler: Exception | None = None) -> None:
        self.aufrufe = 0
        self.gesehene_tokens: list[str] = []
        self._antwort = antwort
        self._fehler = fehler

    async def tauschen(self, provider: object, *, code: str, verifier: str) -> TokenSet:
        raise NotImplementedError

    async def erneuern(self, provider: object, *, refresh_token: str) -> TokenSet:
        self.aufrufe += 1
        self.gesehene_tokens.append(refresh_token)
        # Der echte Aufruf geht über das Netz. Ohne diese Pause liefe die
        # Attrappe so schnell durch, dass ein Wettlauf gar nicht entstünde —
        # der Nebenläufigkeitstest wäre grün, ohne etwas geprüft zu haben.
        await asyncio.sleep(0.05)
        if self._fehler is not None:
            raise self._fehler
        assert self._antwort is not None
        return self._antwort


def _neuer_satz(*, refresh: str | None = "rt-neu") -> TokenSet:
    return TokenSet(
        access_token="at-neu",
        refresh_token=refresh,
        access_expires_at=JETZT + timedelta(hours=1),
        granted_scopes=("openid",),
        external_id="konto-1",
        display_label="ich@example.test",
    )


@pytest.fixture
def schluessel(tmp_path: Path) -> DateiSchluessel:
    return DateiSchluessel(schluesseldatei_anlegen(tmp_path / "kek.json"))


async def _konto_mit_token(
    engine: AsyncEngine,
    schluessel: DateiSchluessel,
    *,
    gilt_bis: datetime,
    refresh: str | None = "rt-alt",
) -> tuple[uuid.UUID, uuid.UUID]:
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
                "VALUES (:k, :u, 'google', :e, 'Testkonto', ARRAY['openid'])"
            ),
            {"k": kid, "u": uid, "e": f"ext-{kid}"},
        )
    await PostgresCredentialStore(engine, schluessel=schluessel).speichern(
        kid, token=buendeln("at-alt", refresh), gilt_bis=gilt_bis
    )
    return uid, kid


async def _weg(engine: AsyncEngine, uid: uuid.UUID) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})


def _dienst(
    engine: AsyncEngine, schluessel: DateiSchluessel, anbieter: _Anbieter
) -> tuple[TokenService, PostgresAccountStore]:
    konten = PostgresAccountStore(engine)
    return (
        TokenService(
            engine,
            konten=konten,
            zugangsdaten=PostgresCredentialStore(engine, schluessel=schluessel),
            tausch=anbieter,
        ),
        konten,
    )


class TestWannErneuertWird:
    async def test_ein_gueltiger_token_kostet_keinen_anbieteraufruf(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        uid, kid = await _konto_mit_token(engine, schluessel, gilt_bis=NOCH_GUT)
        try:
            anbieter = _Anbieter(antwort=_neuer_satz())
            dienst, konten = _dienst(engine, schluessel, anbieter)
            konto = await konten.laden(kid, user_id=uid)
            assert konto is not None

            zugang = await dienst.zugang(konto, provider=ANBIETER, jetzt=JETZT)

            assert zugang.access_token == "at-alt"
            assert anbieter.aufrufe == 0
        finally:
            await _weg(engine, uid)

    async def test_ein_abgelaufener_token_wird_erneuert(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        uid, kid = await _konto_mit_token(engine, schluessel, gilt_bis=ABGELAUFEN)
        try:
            anbieter = _Anbieter(antwort=_neuer_satz())
            dienst, konten = _dienst(engine, schluessel, anbieter)
            konto = await konten.laden(kid, user_id=uid)
            assert konto is not None

            zugang = await dienst.zugang(konto, provider=ANBIETER, jetzt=JETZT)

            assert zugang.access_token == "at-neu"
            assert anbieter.aufrufe == 1
            assert anbieter.gesehene_tokens == ["rt-alt"]
        finally:
            await _weg(engine, uid)

    async def test_erzwingen_erneuert_auch_einen_gueltigen(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """Die Reparatur von Hand.

        Ohne den Schalter müsste ein Nutzer mit einem kaputten Konto warten,
        bis der Token von selbst abläuft.
        """
        uid, kid = await _konto_mit_token(engine, schluessel, gilt_bis=NOCH_GUT)
        try:
            anbieter = _Anbieter(antwort=_neuer_satz())
            dienst, konten = _dienst(engine, schluessel, anbieter)
            konto = await konten.laden(kid, user_id=uid)
            assert konto is not None

            await dienst.zugang(konto, provider=ANBIETER, jetzt=JETZT, erzwingen=True)

            assert anbieter.aufrufe == 1
        finally:
            await _weg(engine, uid)


class TestWasNachDerErneuerungSteht:
    async def test_der_alte_erneuerungstoken_bleibt_wenn_keiner_nachkommt(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """**Der teuerste stille Fehler, den dieser Block hätte machen können.**

        Die meisten Anbieter schicken beim Refresh nur den Zugriffstoken
        zurück. Wer dann ``None`` speichert, hat das Konto beim übernächsten
        Mal verloren — und der Fehler zeigt sich Stunden später als
        „Zustimmung besteht nicht mehr", also an einer Stelle, an der niemand
        nach dieser Ursache sucht.
        """
        uid, kid = await _konto_mit_token(engine, schluessel, gilt_bis=ABGELAUFEN)
        try:
            anbieter = _Anbieter(antwort=_neuer_satz(refresh=None))
            dienst, konten = _dienst(engine, schluessel, anbieter)
            konto = await konten.laden(kid, user_id=uid)
            assert konto is not None

            await dienst.zugang(konto, provider=ANBIETER, jetzt=JETZT)

            gelesen = await PostgresCredentialStore(engine, schluessel=schluessel).lesen(kid)
            assert gelesen is not None
            access, refresh = zerlegen(gelesen[0])
            assert access == "at-neu"
            assert refresh == "rt-alt"
        finally:
            await _weg(engine, uid)

    async def test_der_alte_datensatz_bleibt_liegen(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """Ein Refresh schreibt einen neuen Datensatz, statt zu überschreiben.

        Wer überschreibt, verliert bei einem Fehlschlag beides.
        """
        uid, kid = await _konto_mit_token(engine, schluessel, gilt_bis=ABGELAUFEN)
        try:
            anbieter = _Anbieter(antwort=_neuer_satz())
            dienst, konten = _dienst(engine, schluessel, anbieter)
            konto = await konten.laden(kid, user_id=uid)
            assert konto is not None

            await dienst.zugang(konto, provider=ANBIETER, jetzt=JETZT)

            async with engine.connect() as conn:
                anzahl = (
                    await conn.execute(
                        text("SELECT count(*) FROM oauth_credentials WHERE account_id = :k"),
                        {"k": kid},
                    )
                ).scalar_one()
            assert anzahl == 2
        finally:
            await _weg(engine, uid)


class TestWasEinFehlschlagBedeutet:
    @pytest.mark.invariant("oauth-account-dies-only-on-a-revoked-grant")
    async def test_ein_zurueckgezogener_zugriff_setzt_das_konto_auf_abgelaufen(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        uid, kid = await _konto_mit_token(engine, schluessel, gilt_bis=ABGELAUFEN)
        try:
            anbieter = _Anbieter(fehler=AuthorizationRevoked("weg"))
            dienst, konten = _dienst(engine, schluessel, anbieter)
            konto = await konten.laden(kid, user_id=uid)
            assert konto is not None

            with pytest.raises(KeinZugang):
                await dienst.zugang(konto, provider=ANBIETER, jetzt=JETZT)

            danach = await konten.laden(kid, user_id=uid)
            assert danach is not None
            assert danach.status == "expired"
            assert danach.last_error is not None
        finally:
            await _weg(engine, uid)

    @pytest.mark.invariant("oauth-account-dies-only-on-a-revoked-grant")
    async def test_eine_netzstoerung_laesst_das_konto_in_ruhe(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """**Der Unterschied, um dessentwillen es zwei Ausnahmen gibt.**

        Bei einem Zeitlimit ist über die Zustimmung nichts gesagt. Wer das
        Konto hier abschreibt, macht aus einer Störung einen Verlust — der
        Nutzer stimmt neu zu, obwohl nichts kaputt war.
        """
        uid, kid = await _konto_mit_token(engine, schluessel, gilt_bis=ABGELAUFEN)
        try:
            anbieter = _Anbieter(fehler=TokenExchangeFailed("nicht erreichbar"))
            dienst, konten = _dienst(engine, schluessel, anbieter)
            konto = await konten.laden(kid, user_id=uid)
            assert konto is not None

            with pytest.raises(KeinZugang):
                await dienst.zugang(konto, provider=ANBIETER, jetzt=JETZT)

            danach = await konten.laden(kid, user_id=uid)
            assert danach is not None
            assert danach.status == "active"
            assert danach.last_error is None
        finally:
            await _weg(engine, uid)

    async def test_ohne_erneuerungstoken_gibt_es_nichts_zu_holen(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """Entsteht, wenn der Anbieter ihn bei einer wiederholten Zustimmung
        nicht noch einmal herausgibt. Endgültig, bis der Nutzer neu zustimmt —
        und deshalb wird der Anbieter gar nicht erst gefragt."""
        uid, kid = await _konto_mit_token(engine, schluessel, gilt_bis=ABGELAUFEN, refresh=None)
        try:
            anbieter = _Anbieter(antwort=_neuer_satz())
            dienst, konten = _dienst(engine, schluessel, anbieter)
            konto = await konten.laden(kid, user_id=uid)
            assert konto is not None

            with pytest.raises(KeinZugang):
                await dienst.zugang(konto, provider=ANBIETER, jetzt=JETZT)

            assert anbieter.aufrufe == 0
            danach = await konten.laden(kid, user_id=uid)
            assert danach is not None
            assert danach.status == "expired"
        finally:
            await _weg(engine, uid)

    async def test_eine_geglueckte_erneuerung_holt_das_konto_zurueck(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        uid, kid = await _konto_mit_token(engine, schluessel, gilt_bis=ABGELAUFEN)
        try:
            konten = PostgresAccountStore(engine)
            await konten.markieren(kid, status="error", fehler="von gestern")

            anbieter = _Anbieter(antwort=_neuer_satz())
            dienst, _ = _dienst(engine, schluessel, anbieter)
            konto = await konten.laden(kid, user_id=uid)
            assert konto is not None

            await dienst.zugang(konto, provider=ANBIETER, jetzt=JETZT)

            danach = await konten.laden(kid, user_id=uid)
            assert danach is not None
            assert danach.status == "active"
            assert danach.last_error is None
        finally:
            await _weg(engine, uid)


class TestNebenlaeufigkeit:
    @pytest.mark.invariant("oauth-refresh-is-serialized-per-account")
    async def test_zehn_gleichzeitige_anfragen_erzeugen_einen_anbieteraufruf(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """**Gezählt, nicht am Ergebnis geprüft.**

        Alle zehn bekommen einen gültigen Token, ob serialisiert wurde oder
        nicht — das Ergebnis unterscheidet die beiden Fassungen nicht. Der
        Zähler tut es. Und der teure Fall hängt genau daran: Bei einem
        Anbieter, der den Erneuerungstoken rotiert, entwertet der erste Aufruf
        den Token, mit dem der zweite gerade unterwegs ist.
        """
        uid, kid = await _konto_mit_token(engine, schluessel, gilt_bis=ABGELAUFEN)
        try:
            anbieter = _Anbieter(antwort=_neuer_satz())
            dienst, konten = _dienst(engine, schluessel, anbieter)
            konto = await konten.laden(kid, user_id=uid)
            assert konto is not None

            ergebnisse = await asyncio.gather(
                *(dienst.zugang(konto, provider=ANBIETER, jetzt=JETZT) for _ in range(10))
            )

            assert anbieter.aufrufe == 1
            assert {e.access_token for e in ergebnisse} == {"at-neu"}
        finally:
            await _weg(engine, uid)

    async def test_die_wartenden_holen_keinen_eigenen_datensatz(
        self, engine: AsyncEngine, schluessel: DateiSchluessel
    ) -> None:
        """Der Verlierer eines Wettlaufs findet den frischen Token vor.

        Genau deshalb steht die Ablaufprüfung **innerhalb** der Transaktion,
        die die Sperre hält. Wer draußen prüft und drinnen erneuert, hat
        zwischen beidem wieder das Fenster.
        """
        uid, kid = await _konto_mit_token(engine, schluessel, gilt_bis=ABGELAUFEN)
        try:
            anbieter = _Anbieter(antwort=_neuer_satz())
            dienst, konten = _dienst(engine, schluessel, anbieter)
            konto = await konten.laden(kid, user_id=uid)
            assert konto is not None

            await asyncio.gather(
                *(dienst.zugang(konto, provider=ANBIETER, jetzt=JETZT) for _ in range(5))
            )

            async with engine.connect() as conn:
                anzahl = (
                    await conn.execute(
                        text("SELECT count(*) FROM oauth_credentials WHERE account_id = :k"),
                        {"k": kid},
                    )
                ).scalar_one()
            assert anzahl == 2
        finally:
            await _weg(engine, uid)
