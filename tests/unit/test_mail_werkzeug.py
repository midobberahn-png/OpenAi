"""``mail.read`` — das Werkzeug und der Gmail-Adapter darunter.

**Eine Beobachtung vorweg, die diese Datei mit prüft.** ``tests/fakes.py``
führt seit langem eine ``ToolSpec`` namens ``mail.read``, gegen die die
Policy- und Executor-Suite arbeitet — für ein Werkzeug, das es nicht gab. Der
Fake war damit eine Spezifikation, und das echte Werkzeug muss zu ihr passen:
Wären die sicherheitsrelevanten Eigenschaften verschieden, prüfte die
Policy-Suite seit je etwas anderes, als jetzt läuft. Der erste Test hält das
fest.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx
import pytest

from jarvis_contracts import DataClass
from jarvis_core.ports.mail import MailAccessDenied, MailUnavailable
from jarvis_core.tools.builtin import MAIL_READ, mail_read_handler
from jarvis_integrations.gmail import MAX_NACHRICHTEN, MAX_ZEICHEN, GmailReader
from tests import fakes

pytestmark = [pytest.mark.security]


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _nachricht(**abweichend: Any) -> dict[str, Any]:
    standard: dict[str, Any] = {
        "id": "m1",
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                {"name": "From", "value": "wer@example.test"},
                {"name": "Subject", "value": "Betreff"},
                {"name": "Date", "value": "Mon, 31 Aug 2026 10:00:00 +0000"},
            ],
            "body": {"data": _b64("Der Text.")},
        },
    }
    standard.update(abweichend)
    return standard


def _leser(routen: dict[str, Any], *, mitschrift: list[httpx.Request] | None = None) -> GmailReader:
    def handler(request: httpx.Request) -> httpx.Response:
        if mitschrift is not None:
            mitschrift.append(request)
        for teil, antwort in routen.items():
            if teil in str(request.url):
                if isinstance(antwort, int):
                    return httpx.Response(antwort, json={})
                return httpx.Response(200, json=antwort)
        raise AssertionError(f"Unerwartete Adresse: {request.url}")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return GmailReader(_token, client=client)


async def _token() -> str:
    return "at-test"


class TestDasWerkzeugPasstZurAnnahmeDerPolicySuite:
    def test_die_sicherheitsrelevanten_eigenschaften_stimmen_ueberein(self) -> None:
        """Der Fake war die Spezifikation. Weicht das echte Werkzeug ab,
        prüfte die Policy-Suite bisher etwas, das es so nicht gibt."""
        assert MAIL_READ.name == fakes.MAIL_READ.name
        assert MAIL_READ.scopes == fakes.MAIL_READ.scopes
        assert MAIL_READ.data_class == fakes.MAIL_READ.data_class == DataClass.P2
        assert MAIL_READ.reads_untrusted_content is True
        assert MAIL_READ.forbidden_when_tainted is False
        assert MAIL_READ.risk == fakes.MAIL_READ.risk

    def test_das_werkzeug_kann_nicht_senden(self) -> None:
        """Der Scope-Katalog führt ``mail.send``; dieses Werkzeug verlangt ihn
        nicht — und der Port darunter kann es nicht."""
        assert MAIL_READ.scopes == ["mail.read"]
        assert MAIL_READ.outbound_fields == []


class TestWasDasWerkzeugZurueckgibt:
    @pytest.mark.asyncio
    async def test_gelesene_post_kontaminiert_den_lauf(self) -> None:
        """**Die Existenzbedingung dieses Werkzeugs.**

        Anders als bei ``web.fetch`` sucht nicht das Modell die Quelle aus:
        Wer eine Mailadresse kennt, entscheidet allein, dass sein Text im
        Kontext landet. Die untergeschobene Anweisung ist hier der Normalfall.
        """
        handler = mail_read_handler(
            _leser({"messages/m1": _nachricht(), "messages": {"messages": [{"id": "m1"}]}})
        )

        ergebnis = await handler(anzahl=1)

        assert ergebnis.ok
        assert ergebnis.taints_context is True
        assert ergebnis.produced_data_class == DataClass.P2

    @pytest.mark.asyncio
    async def test_absender_betreff_und_text_kommen_an(self) -> None:
        handler = mail_read_handler(
            _leser({"messages/m1": _nachricht(), "messages": {"messages": [{"id": "m1"}]}})
        )

        ergebnis = await handler(anzahl=1)

        assert ergebnis.data is not None
        nachricht = ergebnis.data["messages"][0]
        assert nachricht["from"] == "wer@example.test"
        assert nachricht["subject"] == "Betreff"
        assert nachricht["text"] == "Der Text."

    @pytest.mark.asyncio
    async def test_ein_verweigerter_zugriff_ist_ein_ergebnis_und_keine_ausnahme(self) -> None:
        """Ein Handler, der wirft, reißt den Lauf mit. Ein Handler, der
        ``ok=False`` liefert, lässt das Modell weiterarbeiten — und der Nutzer
        liest, was fehlt."""

        class _Verweigert:
            async def lesen(self, *, anzahl: int, suche: str | None = None) -> list[Any]:
                raise MailAccessDenied("Kein verbundenes Google-Konto")

        ergebnis = await mail_read_handler(_Verweigert())(anzahl=1)

        assert ergebnis.ok is False
        assert "Konto" in (ergebnis.error or "")


class TestWasDerAdapterAusEinerMailLiest:
    @pytest.mark.asyncio
    async def test_klartext_wird_dem_html_vorgezogen(self) -> None:
        """Der Klartextteil ist das, was der Absender für Menschen ohne HTML
        gedacht hat — kürzer, ohne Markup und ohne Verfolgungspixel."""
        mail = _nachricht(
            payload={
                "mimeType": "multipart/alternative",
                "headers": [],
                "parts": [
                    {"mimeType": "text/html", "body": {"data": _b64("<p>HTML</p>")}},
                    {"mimeType": "text/plain", "body": {"data": _b64("Klartext")}},
                ],
            }
        )

        gelesen = await _leser(
            {"messages/m1": mail, "messages": {"messages": [{"id": "m1"}]}}
        ).lesen(anzahl=1)

        assert gelesen[0].text == "Klartext"

    @pytest.mark.asyncio
    async def test_ein_verschachtelter_teil_wird_gefunden(self) -> None:
        """Eine Mail mit Anhang ist ein Baum. Eine Suche nur auf der ersten
        Ebene fände bei jeder Mail mit Anhang nichts."""
        mail = _nachricht(
            payload={
                "mimeType": "multipart/mixed",
                "headers": [],
                "parts": [
                    {
                        "mimeType": "multipart/alternative",
                        "parts": [{"mimeType": "text/plain", "body": {"data": _b64("Tief drin")}}],
                    },
                    {"mimeType": "application/pdf", "body": {"data": _b64("nicht text")}},
                ],
            }
        )

        gelesen = await _leser(
            {"messages/m1": mail, "messages": {"messages": [{"id": "m1"}]}}
        ).lesen(anzahl=1)

        assert gelesen[0].text == "Tief drin"

    @pytest.mark.asyncio
    async def test_ohne_klartext_wird_das_html_ausgelesen(self) -> None:
        mail = _nachricht(
            payload={
                "mimeType": "text/html",
                "headers": [],
                "body": {
                    "data": _b64("<html><body><p>Sichtbar</p><script>x</script></body></html>")
                },
            }
        )

        gelesen = await _leser(
            {"messages/m1": mail, "messages": {"messages": [{"id": "m1"}]}}
        ).lesen(anzahl=1)

        assert "Sichtbar" in gelesen[0].text
        assert "x" not in gelesen[0].text

    @pytest.mark.asyncio
    async def test_ein_unlesbares_datum_wird_nicht_geraten(self) -> None:
        """Ein geratenes Datum wäre schlimmer als keines: Es sähe aus wie eine
        Auskunft. Kaputte Kopfzeilen gibt es in echten Postfächern reichlich —
        eine davon darf nicht das Lesen der Nachricht verhindern."""
        mail = _nachricht()
        mail["payload"]["headers"] = [{"name": "Date", "value": "irgendwann"}]

        gelesen = await _leser(
            {"messages/m1": mail, "messages": {"messages": [{"id": "m1"}]}}
        ).lesen(anzahl=1)

        assert gelesen[0].datum is None
        assert gelesen[0].text == "Der Text."

    @pytest.mark.asyncio
    async def test_eine_lange_nachricht_wird_gekuerzt_und_sagt_es(self) -> None:
        mail = _nachricht()
        mail["payload"]["body"] = {"data": _b64("x" * (MAX_ZEICHEN + 100))}

        gelesen = await _leser(
            {"messages/m1": mail, "messages": {"messages": [{"id": "m1"}]}}
        ).lesen(anzahl=1)

        assert len(gelesen[0].text) == MAX_ZEICHEN
        assert gelesen[0].gekuerzt is True


class TestWasDerAdapterNichtZulaesst:
    @pytest.mark.asyncio
    async def test_die_anzahl_wird_im_adapter_begrenzt_nicht_nur_im_schema(self) -> None:
        """**Ein Schema beschreibt, was ein Modell schicken soll.**

        Durchgesetzt wird, was der Adapter tut — dieselbe Lehre wie bei
        ``ToolSpec.parameters``, die lange niemand gelesen hat. Jede Nachricht
        ist eine eigene Anfrage; ohne diese Grenze löste „alle Mails" hunderte
        aus.
        """
        mitschrift: list[httpx.Request] = []
        leser = _leser(
            {"messages": {"messages": []}},
            mitschrift=mitschrift,
        )

        await leser.lesen(anzahl=10_000)

        angefragt = mitschrift[0].url.params["maxResults"]
        assert int(angefragt) == MAX_NACHRICHTEN

    @pytest.mark.asyncio
    @pytest.mark.parametrize("code", [401, 403])
    async def test_abgelehnter_zugriff_ist_kein_netzfehler(self, code: int) -> None:
        """Beides heißt für den Nutzer dasselbe: nicht jetzt lösbar. Und
        beides darf dem Modell nicht erzählen, wie die Zugangsdaten dieses
        Systems aufgebaut sind."""
        with pytest.raises(MailAccessDenied):
            await _leser({"messages": code}).lesen(anzahl=1)

    @pytest.mark.asyncio
    async def test_ein_serverfehler_ist_eine_stoerung(self) -> None:
        with pytest.raises(MailUnavailable):
            await _leser({"messages": 500}).lesen(anzahl=1)
