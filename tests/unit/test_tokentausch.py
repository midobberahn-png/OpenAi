"""Der Tokentausch gegen aufgezeichnete Antworten.

Derselbe Standard wie bei den Modellanbietern: Der Adapter wird gegen
Antworten geprüft, die ein echter Anbieter so schickt — nicht gegen das Netz.
Was ein solcher Test nicht findet, steht im Dossier: ein Feld, das der Anbieter
inzwischen anders nennt.

Was er sehr wohl findet, ist die Sorte Fehler, die hier zählt: eine Antwort,
der man zu viel glaubt.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import httpx
import pytest

from jarvis_core.ports.oauth import OAuthProvider, TokenExchangeFailed
from jarvis_integrations.oauth import HttpTokenExchange

pytestmark = [pytest.mark.asyncio, pytest.mark.security]

JETZT = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)

ANBIETER = OAuthProvider(
    name="google",
    authorize_url="https://accounts.example.test/auth",
    token_url="https://token.example.test/token",
    client_id="client-123",
    client_secret="geheim-456",
    redirect_uri="http://localhost:8000/accounts/callback",
    scopes=("openid", "email", "calendar.events"),
)


def _id_token(**felder: object) -> str:
    """Ein JWT mit lesbarem Nutzteil. Die Signatur ist Attrappe — genau wie im
    Betrieb ungeprüft, siehe Modulkopf des Adapters."""
    rumpf = base64.urlsafe_b64encode(json.dumps(felder).encode()).decode().rstrip("=")
    return f"kopf.{rumpf}.signatur"


class TestWasDerAdapterGlaubt:
    async def test_eine_vollstaendige_antwort_wird_uebernommen(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _mock(
            monkeypatch,
            {
                "access_token": "ya29.zugriff",
                "refresh_token": "1//erneuerung",
                "expires_in": 3600,
                "scope": "openid email",
                "id_token": _id_token(sub="konto-1", email="ich@example.test"),
            },
        )

        tokens = await HttpTokenExchange(uhr=lambda: JETZT).tauschen(
            ANBIETER, code="c", verifier="v"
        )

        assert tokens.access_token == "ya29.zugriff"
        assert tokens.refresh_token == "1//erneuerung"
        assert tokens.external_id == "konto-1"
        assert tokens.display_label == "ich@example.test"

    async def test_bewilligt_wird_was_der_anbieter_meldet_nicht_was_wir_fragten(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Der Nutzer hat im Zustimmungsdialog ein Häkchen entfernt.

        Wer den Wunsch speichert statt der Bewilligung, führt danach ein Konto,
        das mehr zu können behauptet, als es darf — und merkt es beim ersten
        Aufruf, der scheitert.
        """
        _mock(
            monkeypatch,
            {
                "access_token": "a",
                "expires_in": 3600,
                "scope": "openid",
                "id_token": _id_token(sub="konto-1"),
            },
        )

        tokens = await HttpTokenExchange(uhr=lambda: JETZT).tauschen(
            ANBIETER, code="c", verifier="v"
        )

        assert tokens.granted_scopes == ("openid",)
        assert ANBIETER.scopes != tokens.granted_scopes

    async def test_ohne_scope_gilt_das_gefragte_als_bewilligt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fehlendes ``scope`` heißt bei OAuth 2.0: genau das Gefragte."""
        _mock(
            monkeypatch,
            {"access_token": "a", "expires_in": 60, "id_token": _id_token(sub="k")},
        )

        tokens = await HttpTokenExchange(uhr=lambda: JETZT).tauschen(
            ANBIETER, code="c", verifier="v"
        )

        assert tokens.granted_scopes == ANBIETER.scopes

    async def test_ein_fehlender_erneuerungstoken_ist_kein_fehler(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Anbieter geben ihn oft nur bei der **ersten** Zustimmung heraus.

        Wer ihn erwartet und ohne ihn scheitert, bricht jede zweite Verbindung
        desselben Kontos.
        """
        _mock(
            monkeypatch,
            {"access_token": "a", "expires_in": 60, "id_token": _id_token(sub="k")},
        )

        tokens = await HttpTokenExchange(uhr=lambda: JETZT).tauschen(
            ANBIETER, code="c", verifier="v"
        )

        assert tokens.refresh_token is None

    async def test_die_gueltigkeit_bekommt_einen_vorhalt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ein Token, der als „gültig bis genau jetzt" verbucht wird, ist bei
        jedem Grenzfall abgelaufen, bevor er ankommt."""
        _mock(
            monkeypatch,
            {"access_token": "a", "expires_in": 3600, "id_token": _id_token(sub="k")},
        )

        tokens = await HttpTokenExchange(uhr=lambda: JETZT).tauschen(
            ANBIETER, code="c", verifier="v"
        )

        assert tokens.access_expires_at < JETZT.replace(hour=13)


class TestWasDerAdapterNichtGlaubt:
    @pytest.mark.parametrize(
        ("antwort", "grund"),
        [
            ({"expires_in": 60, "id_token": "x.y.z"}, "kein access_token"),
            ({"access_token": "a", "id_token": "x.y.z"}, "kein expires_in"),
            ({"access_token": "a", "expires_in": "3600"}, "expires_in als Zeichenkette"),
            ({"access_token": "a", "expires_in": -5}, "negative Gültigkeit"),
            ({"access_token": "a", "expires_in": 60}, "kein id_token"),
            ({"access_token": "a", "expires_in": 60, "id_token": "kein-jwt"}, "kein JWT"),
        ],
    )
    async def test_eine_unvollstaendige_antwort_wird_abgewiesen(
        self, monkeypatch: pytest.MonkeyPatch, antwort: dict[str, object], grund: str
    ) -> None:
        _mock(monkeypatch, antwort)

        with pytest.raises(TokenExchangeFailed):
            await HttpTokenExchange(uhr=lambda: JETZT).tauschen(ANBIETER, code="c", verifier="v")

    async def test_ein_id_token_ohne_sub_ist_kein_konto(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ohne Kennung ist das Konto nicht unterscheidbar — und der
        Eindeutigkeitsschlüssel hängt daran."""
        _mock(
            monkeypatch,
            {"access_token": "a", "expires_in": 60, "id_token": _id_token(email="ich@x.test")},
        )

        with pytest.raises(TokenExchangeFailed):
            await HttpTokenExchange(uhr=lambda: JETZT).tauschen(ANBIETER, code="c", verifier="v")

    async def test_der_text_des_anbieters_steht_nicht_in_der_ausnahme(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Manche Anbieter spiegeln zurück, was man geschickt hat.

        Landete das in einer Ausnahme, stünde bei einer falsch gebauten
        Anfrage das Client-Geheimnis im Protokoll.
        """
        _mock(monkeypatch, {"error": "invalid_grant", "sent": "geheim-456"}, status=400)

        with pytest.raises(TokenExchangeFailed) as fehler:
            await HttpTokenExchange(uhr=lambda: JETZT).tauschen(ANBIETER, code="c", verifier="v")

        assert "geheim-456" not in str(fehler.value)
        assert "invalid_grant" not in str(fehler.value)


def _mock(
    monkeypatch: pytest.MonkeyPatch, nutzlast: dict[str, object], *, status: int = 200
) -> None:
    """Schiebt ``httpx.AsyncClient`` einen Mock-Transport unter.

    Über ``monkeypatch`` und nicht über einen Parameter des Adapters: Ein
    Konstruktorargument „Transport" wäre eine Tür, die es nur für Tests gibt —
    und über die im Betrieb jemand einen anderen Transport hineinreicht.
    """
    original = httpx.AsyncClient

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=nutzlast)

    def fabrik(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs.pop("timeout", None)
        return original(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(httpx, "AsyncClient", fabrik)
