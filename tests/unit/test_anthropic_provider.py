"""Anthropic-Adapter gegen aufgezeichnete Antworten.

Derselbe Aufbau wie bei Ollama (ADR-009 nennt Contract-Tests als Gegengewicht
zum Nachteil eigener Adapter), nur eine Schicht tiefer: Das SDK bekommt einen
``httpx2``-Client mit ``MockTransport``. Damit läuft **das echte SDK** —
Serialisierung, Kopfzeilen, Antwortmodelle —, nur das Netz ist ersetzt.

Der Unterschied zu einem Mock des SDK ist derselbe wie immer: Ein solcher Mock
prüfte, ob der Mock tut, was man ihm sagt. Hier wird geprüft, was tatsächlich
hinausgegangen wäre und was aus dem zurückkommt, was Anthropic wirklich
antwortet.

Die Aufzeichnungen tragen auch Felder, die wir nicht auswerten — sonst prüft
der Test eine Antwortform, die es so nie gibt.
"""

from __future__ import annotations

import json
from typing import Any

import httpx2
import pytest

from jarvis_contracts import (
    CompletionRequest,
    FinishReason,
    Message,
    MessageRole,
)
from jarvis_providers.anthropic import AnthropicError, AnthropicProvider

pytestmark = pytest.mark.security


# --------------------------------------------------------------------------
# Aufzeichnungen
# --------------------------------------------------------------------------
ANTWORT_TEXT: dict[str, Any] = {
    "id": "msg_01XY",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-5",
    "content": [{"type": "text", "text": "Es ist 14 Uhr."}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {
        "input_tokens": 42,
        "output_tokens": 17,
        "cache_read_input_tokens": 8,
        "cache_creation_input_tokens": 0,
    },
}

ANTWORT_WERKZEUG: dict[str, Any] = {
    "id": "msg_02AB",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-5",
    "content": [
        {"type": "text", "text": "Ich lege den Termin an."},
        {
            "type": "tool_use",
            "id": "toolu_01",
            "name": "calendar.create",
            "input": {"title": "Fokuszeit", "start": "2026-08-20T09:00:00+02:00"},
        },
    ],
    "stop_reason": "tool_use",
    "stop_sequence": None,
    "usage": {"input_tokens": 88, "output_tokens": 24},
}

STROM = [
    {
        "type": "message_start",
        "message": {
            "id": "msg_03",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-5",
            "content": [],
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": 12, "output_tokens": 0, "cache_read_input_tokens": 4},
        },
    },
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": "Es ist "},
    },
    {
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": "14 Uhr."},
    },
    {"type": "content_block_stop", "index": 0},
    {
        "type": "message_delta",
        "delta": {"stop_reason": "end_turn", "stop_sequence": None},
        "usage": {"output_tokens": 9},
    },
    {"type": "message_stop"},
]


def _sse(ereignisse: list[dict[str, Any]]) -> str:
    return "".join(
        f"event: {ereignis['type']}\ndata: {json.dumps(ereignis)}\n\n" for ereignis in ereignisse
    )


def _provider(handler: Any) -> tuple[AnthropicProvider, list[httpx2.Request]]:
    """Adapter mit aufgezeichnetem Transport — samt Protokoll dessen, was
    tatsächlich hinausgegangen wäre."""
    gesehen: list[httpx2.Request] = []

    def aufzeichnen(request: httpx2.Request) -> httpx2.Response:
        gesehen.append(request)
        return handler(request)

    client = httpx2.AsyncClient(transport=httpx2.MockTransport(aufzeichnen))
    return AnthropicProvider(api_key="sk-test-geheim", http_client=client), gesehen


def _anfrage(**kw: Any) -> CompletionRequest:
    grund: dict[str, Any] = {
        "model": "claude-sonnet-5",
        "messages": [Message(role=MessageRole.USER, content="Wie spät ist es?")],
    }
    grund.update(kw)
    return CompletionRequest(**grund)


def _rumpf(request: httpx2.Request) -> dict[str, Any]:
    geladen: dict[str, Any] = json.loads(request.content)
    return geladen


class TestAntwortLesen:
    async def test_text_und_verbrauch(self) -> None:
        provider, _ = _provider(lambda _: httpx2.Response(200, json=ANTWORT_TEXT))
        ergebnis = await provider.complete(_anfrage())

        assert ergebnis.text == "Es ist 14 Uhr."
        assert ergebnis.finish_reason is FinishReason.STOP
        assert ergebnis.provider == "anthropic"
        assert ergebnis.usage.tokens_in == 42
        assert ergebnis.usage.tokens_out == 17
        # Getrennt geführt, weil es anders abgerechnet wird.
        assert ergebnis.usage.cached_tokens_in == 8

    @pytest.mark.invariant("model-tool-calls-are-proposals")
    async def test_werkzeugaufrufe_werden_zu_vorschlaegen(self) -> None:
        """Was Anthropic ``tool_use`` nennt, heißt hier ``ProposedToolCall``.

        Der Name ist die Entscheidung: Was zurückkommt, ist eine geäußerte
        Absicht und trägt nichts, was einer Erlaubnis ähnelt.
        """
        provider, _ = _provider(lambda _: httpx2.Response(200, json=ANTWORT_WERKZEUG))
        ergebnis = await provider.complete(_anfrage())

        assert ergebnis.finish_reason is FinishReason.TOOL_CALLS
        assert len(ergebnis.tool_calls) == 1
        vorschlag = ergebnis.tool_calls[0]
        assert vorschlag.tool_name == "calendar.create"
        assert vorschlag.id == "toolu_01"
        assert vorschlag.arguments["title"] == "Fokuszeit"
        # Der Text neben dem Aufruf geht nicht verloren.
        assert ergebnis.text == "Ich lege den Termin an."

    async def test_ein_abbruch_wegen_laenge_heisst_nicht_fertig(self) -> None:
        """``max_tokens`` ist kein Ende, sondern ein Abschneiden.

        Als STOP zu melden hieße, eine abgeschnittene Antwort als vollständig
        auszugeben — und der Aufrufer verarbeitete einen halben Satz als
        Ergebnis.
        """
        aufzeichnung = {**ANTWORT_TEXT, "stop_reason": "max_tokens"}
        provider, _ = _provider(lambda _: httpx2.Response(200, json=aufzeichnung))

        ergebnis = await provider.complete(_anfrage())
        assert ergebnis.finish_reason is FinishReason.LENGTH

    async def test_eine_verweigerung_ist_kein_stop(self) -> None:
        aufzeichnung = {**ANTWORT_TEXT, "stop_reason": "refusal"}
        provider, _ = _provider(lambda _: httpx2.Response(200, json=aufzeichnung))

        ergebnis = await provider.complete(_anfrage())
        assert ergebnis.finish_reason is FinishReason.CONTENT_FILTER


class TestWasHinausgeht:
    async def test_die_systemanweisung_wird_getrennt_gefuehrt(self) -> None:
        """Anthropic führt sie als eigenen Parameter, nicht als Rolle.

        Zwei Systemnachrichten werden zusammengefasst; die Reihenfolge bleibt.
        """
        provider, gesehen = _provider(lambda _: httpx2.Response(200, json=ANTWORT_TEXT))
        await provider.complete(
            _anfrage(
                messages=[
                    Message(role=MessageRole.SYSTEM, content="Sei knapp."),
                    Message(role=MessageRole.SYSTEM, content="Antworte deutsch."),
                    Message(role=MessageRole.USER, content="Wie spät ist es?"),
                ]
            )
        )

        rumpf = _rumpf(gesehen[0])
        assert rumpf["system"] == "Sei knapp.\n\nAntworte deutsch."
        assert [n["role"] for n in rumpf["messages"]] == ["user"]

    async def test_ein_werkzeugergebnis_wird_zum_tool_result_block(self) -> None:
        provider, gesehen = _provider(lambda _: httpx2.Response(200, json=ANTWORT_TEXT))
        await provider.complete(
            _anfrage(
                messages=[
                    Message(role=MessageRole.USER, content="Leg den Termin an."),
                    Message(role=MessageRole.ASSISTANT, content="Mache ich."),
                    Message(
                        role=MessageRole.TOOL,
                        content="Termin angelegt",
                        tool_call_id="toolu_01",
                    ),
                ]
            )
        )

        rumpf = _rumpf(gesehen[0])
        block = rumpf["messages"][-1]["content"][0]
        assert block["type"] == "tool_result"
        assert block["tool_use_id"] == "toolu_01"

    @pytest.mark.invariant("tool-arguments-match-schema")
    async def test_das_werkzeugschema_geht_unveraendert_mit(self) -> None:
        """``required`` und ``additionalProperties`` bleiben im Schema.

        Was hinausgeht, ist die Ansage an das Modell. Dass sie zusätzlich im
        Haus geprüft wird, hebt sie nicht auf — eine Einschränkung, die nur
        nach außen geht, gilt nicht, aber eine, die gar nicht erst hinausgeht,
        lädt zum Raten ein.
        """
        schema = {
            "type": "object",
            "properties": {"title": {"type": "string"}},
            "required": ["title"],
            "additionalProperties": False,
        }
        provider, gesehen = _provider(lambda _: httpx2.Response(200, json=ANTWORT_TEXT))
        await provider.complete(
            _anfrage(tools=[{"name": "calendar.create", "input_schema": schema}])
        )

        rumpf = _rumpf(gesehen[0])
        assert rumpf["tools"][0]["input_schema"] == schema

    async def test_kein_stilles_wiederholen(self) -> None:
        """Ein Versuch, nicht drei.

        Die Vorgabe des SDK wiederholt; das wäre eine stille Abweichung von
        dem, was das System über sich sagt — und aus einem Timeout von 60
        Sekunden würden drei Minuten.
        """
        versuche: list[httpx2.Request] = []

        def scheitern(request: httpx2.Request) -> httpx2.Response:
            versuche.append(request)
            return httpx2.Response(529, json={"type": "error", "error": {"type": "overloaded"}})

        provider, _ = _provider(scheitern)
        with pytest.raises(AnthropicError):
            await provider.complete(_anfrage())

        assert len(versuche) == 1


class TestWasDerAdapterNichtTut:
    async def test_json_ausgabe_wird_abgesagt_statt_verschwiegen(self) -> None:
        """Die API verlangt dafür ein Schema, die Anfrage bringt keines mit.

        Das Feld fallen zu lassen gäbe Fließtext an einen Aufrufer zurück, der
        ihn parst — der Fehler entstünde weit weg von seiner Ursache.
        """
        provider, gesehen = _provider(lambda _: httpx2.Response(200, json=ANTWORT_TEXT))

        with pytest.raises(AnthropicError, match="Schema"):
            await provider.complete(_anfrage(response_format="json"))
        assert gesehen == [], "Abgesagt wird vor dem Netzaufruf, nicht danach."

    async def test_die_temperatur_geht_nicht_mit_und_sagt_es(self) -> None:
        """Der Befund dieses Adapters.

        ``messages.create`` hat keinen Temperaturparameter mehr. Der Wert
        verschwindet damit unterwegs — und ``plan_arguments`` äußert ihn mit
        Absicht (``0.0``, damit Werkzeugargumente bestimmt sind). Sichtbar
        gemacht statt versteckt: ``temperature_control=False``.
        """
        provider, gesehen = _provider(lambda _: httpx2.Response(200, json=ANTWORT_TEXT))
        await provider.complete(_anfrage(temperature=0.0))

        assert "temperature" not in _rumpf(gesehen[0])
        assert provider.capabilities.temperature_control is False

    async def test_der_schluessel_steht_in_keiner_meldung(self) -> None:
        """Auch nicht gekürzt.

        Ein Fehlertext geht ins Protokoll und teilweise an ein Modell zurück.
        Was dort landet, ist die Art des Fehlers und der Statuscode — nicht der
        Antwortkörper, der bei einem Anbieter den Prompt zurückgeben kann.
        """
        provider, _ = _provider(
            lambda _: httpx2.Response(
                401,
                json={"type": "error", "error": {"type": "authentication_error", "message": "x"}},
            )
        )

        with pytest.raises(AnthropicError) as fehler:
            await provider.complete(
                _anfrage(
                    messages=[Message(role=MessageRole.USER, content="Mein Passwort ist hunter2")]
                )
            )

        text = str(fehler.value)
        assert "sk-test-geheim" not in text
        assert "hunter2" not in text
        assert "401" in text


class TestStrom:
    async def test_stuecke_und_verbrauch(self) -> None:
        """Die Eingabetokens kommen am Anfang, die Ausgabetokens am Ende.

        Gesammelt und zusammen ausgeliefert: Ein Aufrufer soll nicht zwei
        Stücke addieren müssen, um eine Rechnung zu bekommen.
        """
        provider, _ = _provider(
            lambda _: httpx2.Response(
                200,
                text=_sse(STROM),
                headers={"content-type": "text/event-stream"},
            )
        )

        stuecke = [s async for s in provider.stream(_anfrage())]

        assert "".join(s.delta for s in stuecke) == "Es ist 14 Uhr."
        letztes = stuecke[-1]
        assert letztes.finish_reason is FinishReason.STOP
        assert letztes.usage is not None
        assert letztes.usage.tokens_in == 12
        assert letztes.usage.tokens_out == 9
        assert letztes.usage.cached_tokens_in == 4


class TestZaehlen:
    async def test_tokens_werden_gezaehlt_und_nicht_geschaetzt(self) -> None:
        """Der einzige Adapter mit echter Zählung vor dem Aufruf."""
        provider, gesehen = _provider(lambda _: httpx2.Response(200, json={"input_tokens": 137}))

        assert await provider.count_tokens(_anfrage()) == 137
        assert provider.capabilities.token_counting is True
        assert gesehen[0].url.path.endswith("/count_tokens")

    async def test_eine_gescheiterte_zaehlung_wird_nicht_geschaetzt(self) -> None:
        """Eine stillschweigende Näherung sähe aus wie eine Messung."""
        provider, _ = _provider(
            lambda _: httpx2.Response(500, json={"type": "error", "error": {"type": "api_error"}})
        )

        with pytest.raises(AnthropicError):
            await provider.count_tokens(_anfrage())
