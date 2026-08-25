"""OpenAI-Adapter gegen aufgezeichnete Antworten.

Derselbe Aufbau wie bei Anthropic: Das echte SDK bekommt einen
``httpx2``-Client mit ``MockTransport``. Geprüft wird, was tatsächlich
hinausgegangen wäre und was aus einer echten Antwortform zurückkommt — nicht,
ob ein Mock tut, was man ihm sagt.
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
from jarvis_providers.openai import OpenAIError, OpenAIProvider

pytestmark = pytest.mark.security


# --------------------------------------------------------------------------
# Aufzeichnungen
# --------------------------------------------------------------------------
ANTWORT_TEXT: dict[str, Any] = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "created": 1_787_000_000,
    "model": "gpt-test",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "Es ist 14 Uhr.", "refusal": None},
            "logprobs": None,
            "finish_reason": "stop",
        }
    ],
    "usage": {
        "prompt_tokens": 42,
        "completion_tokens": 17,
        "total_tokens": 59,
        "prompt_tokens_details": {"cached_tokens": 8, "audio_tokens": 0},
    },
}

ANTWORT_WERKZEUG: dict[str, Any] = {
    "id": "chatcmpl-2",
    "object": "chat.completion",
    "created": 1_787_000_001,
    "model": "gpt-test",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": None,
                "refusal": None,
                "tool_calls": [
                    {
                        "id": "call_01",
                        "type": "function",
                        "function": {
                            "name": "calendar.create",
                            "arguments": '{"title": "Fokuszeit", "start": "2026-08-20T09:00:00+02:00"}',
                        },
                    }
                ],
            },
            "logprobs": None,
            "finish_reason": "tool_calls",
        }
    ],
    "usage": {"prompt_tokens": 88, "completion_tokens": 24, "total_tokens": 112},
}

STROM = [
    {
        "id": "chatcmpl-3",
        "object": "chat.completion.chunk",
        "created": 1_787_000_002,
        "model": "gpt-test",
        "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Es ist "}}],
    },
    {
        "id": "chatcmpl-3",
        "object": "chat.completion.chunk",
        "created": 1_787_000_002,
        "model": "gpt-test",
        "choices": [{"index": 0, "delta": {"content": "14 Uhr."}, "finish_reason": None}],
    },
    {
        "id": "chatcmpl-3",
        "object": "chat.completion.chunk",
        "created": 1_787_000_002,
        "model": "gpt-test",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
    },
    {
        "id": "chatcmpl-3",
        "object": "chat.completion.chunk",
        "created": 1_787_000_002,
        "model": "gpt-test",
        "choices": [],
        "usage": {"prompt_tokens": 12, "completion_tokens": 9, "total_tokens": 21},
    },
]


def _sse(stuecke: list[dict[str, Any]]) -> str:
    zeilen = "".join(f"data: {json.dumps(stueck)}\n\n" for stueck in stuecke)
    return zeilen + "data: [DONE]\n\n"


def _provider(handler: Any) -> tuple[OpenAIProvider, list[httpx2.Request]]:
    gesehen: list[httpx2.Request] = []

    def aufzeichnen(request: httpx2.Request) -> httpx2.Response:
        gesehen.append(request)
        return handler(request)

    client = httpx2.AsyncClient(transport=httpx2.MockTransport(aufzeichnen))
    return OpenAIProvider(api_key="sk-test-geheim", http_client=client), gesehen


def _anfrage(**kw: Any) -> CompletionRequest:
    grund: dict[str, Any] = {
        "model": "gpt-test",
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
        assert ergebnis.provider == "openai"
        assert ergebnis.usage.tokens_in == 42
        assert ergebnis.usage.tokens_out == 17
        assert ergebnis.usage.cached_tokens_in == 8

    @pytest.mark.invariant("model-tool-calls-are-proposals")
    async def test_werkzeugaufrufe_werden_zu_vorschlaegen(self) -> None:
        """Argumente kommen hier als Zeichenkette und werden zu einem Objekt —
        aber nicht geprüft. Schema und Policy kommen danach."""
        provider, _ = _provider(lambda _: httpx2.Response(200, json=ANTWORT_WERKZEUG))
        ergebnis = await provider.complete(_anfrage())

        assert ergebnis.finish_reason is FinishReason.TOOL_CALLS
        vorschlag = ergebnis.tool_calls[0]
        assert vorschlag.id == "call_01"
        assert vorschlag.tool_name == "calendar.create"
        assert vorschlag.arguments["title"] == "Fokuszeit"

    async def test_kaputte_argumente_sind_kein_adapterfehler(self) -> None:
        """Ein Modell, das kaputtes JSON liefert, hat einen Vorschlag gemacht,
        der an der Schemaprüfung scheitert — und dort gehört er hin.

        Ihn hier zu verwerfen verdeckte genau die Fälle, die man sehen will.
        """
        kaputt = json.loads(json.dumps(ANTWORT_WERKZEUG))
        kaputt["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = "{nicht json"
        provider, _ = _provider(lambda _: httpx2.Response(200, json=kaputt))

        ergebnis = await provider.complete(_anfrage())
        assert ergebnis.tool_calls[0].arguments == {"_roh": "{nicht json"}

    async def test_eine_antwort_ohne_auswahl_ist_ein_fehler(self) -> None:
        """Kein leerer Text: Eine Antwortform, die es nicht geben sollte, als
        „" zu behandeln machte aus einem Ausfall eine Erfindung."""
        leer = {**ANTWORT_TEXT, "choices": []}
        provider, _ = _provider(lambda _: httpx2.Response(200, json=leer))

        with pytest.raises(OpenAIError):
            await provider.complete(_anfrage())

    async def test_ein_abbruch_wegen_laenge_heisst_nicht_fertig(self) -> None:
        aufzeichnung = json.loads(json.dumps(ANTWORT_TEXT))
        aufzeichnung["choices"][0]["finish_reason"] = "length"
        provider, _ = _provider(lambda _: httpx2.Response(200, json=aufzeichnung))

        ergebnis = await provider.complete(_anfrage())
        assert ergebnis.finish_reason is FinishReason.LENGTH


class TestWasHinausgeht:
    async def test_rollen_gehen_eins_zu_eins_mit(self) -> None:
        provider, gesehen = _provider(lambda _: httpx2.Response(200, json=ANTWORT_TEXT))
        await provider.complete(
            _anfrage(
                messages=[
                    Message(role=MessageRole.SYSTEM, content="Sei knapp."),
                    Message(role=MessageRole.USER, content="Leg den Termin an."),
                    Message(role=MessageRole.ASSISTANT, content="Mache ich."),
                    Message(
                        role=MessageRole.TOOL, content="Termin angelegt", tool_call_id="call_01"
                    ),
                ]
            )
        )

        rumpf = _rumpf(gesehen[0])
        assert [n["role"] for n in rumpf["messages"]] == ["system", "user", "assistant", "tool"]
        assert rumpf["messages"][-1]["tool_call_id"] == "call_01"

    async def test_die_temperatur_geht_mit(self) -> None:
        """Der Unterschied zum Anthropic-Adapter, und er ist gemessen:
        ``plan_arguments`` verlangt ``0.0``, und hier kommt es an."""
        provider, gesehen = _provider(lambda _: httpx2.Response(200, json=ANTWORT_TEXT))
        await provider.complete(_anfrage(temperature=0.0))

        assert _rumpf(gesehen[0])["temperature"] == 0.0
        assert provider.capabilities.temperature_control is True

    async def test_json_ausgabe_wird_angefordert(self) -> None:
        provider, gesehen = _provider(lambda _: httpx2.Response(200, json=ANTWORT_TEXT))
        await provider.complete(_anfrage(response_format="json"))

        assert _rumpf(gesehen[0])["response_format"] == {"type": "json_object"}

    @pytest.mark.invariant("tool-arguments-match-schema")
    async def test_das_werkzeugschema_geht_unveraendert_mit(self) -> None:
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
        assert rumpf["tools"][0]["function"]["parameters"] == schema

    async def test_kein_stilles_wiederholen(self) -> None:
        versuche: list[httpx2.Request] = []

        def scheitern(request: httpx2.Request) -> httpx2.Response:
            versuche.append(request)
            return httpx2.Response(503, json={"error": {"message": "überlastet"}})

        provider, _ = _provider(scheitern)
        with pytest.raises(OpenAIError):
            await provider.complete(_anfrage())

        assert len(versuche) == 1

    async def test_der_schluessel_steht_in_keiner_meldung(self) -> None:
        provider, _ = _provider(
            lambda _: httpx2.Response(401, json={"error": {"message": "invalid api key"}})
        )

        with pytest.raises(OpenAIError) as fehler:
            await provider.complete(
                _anfrage(messages=[Message(role=MessageRole.USER, content="Passwort hunter2")])
            )

        text = str(fehler.value)
        assert "sk-test-geheim" not in text
        assert "hunter2" not in text
        assert "401" in text


class TestStrom:
    async def test_stuecke_und_verbrauch(self) -> None:
        """Ohne ``include_usage`` liefert die API im Strom keine Zahlen — ein
        Kostenzähler, der beim Streamen blind ist, zählt genau die Aufrufe
        nicht, bei denen ein Mensch zusieht."""
        provider, gesehen = _provider(
            lambda _: httpx2.Response(
                200, text=_sse(STROM), headers={"content-type": "text/event-stream"}
            )
        )

        stuecke = [s async for s in provider.stream(_anfrage())]

        assert "".join(s.delta for s in stuecke) == "Es ist 14 Uhr."
        assert any(s.finish_reason is FinishReason.STOP for s in stuecke)
        verbrauch = [s.usage for s in stuecke if s.usage is not None and s.usage.tokens_in]
        assert verbrauch and verbrauch[-1].tokens_in == 12
        assert _rumpf(gesehen[0])["stream_options"] == {"include_usage": True}


class TestZaehlen:
    async def test_die_zaehlung_ist_eine_naeherung_und_sagt_es(self) -> None:
        """Kein Zählendpunkt, keine erfundene Genauigkeit."""
        provider, gesehen = _provider(lambda _: httpx2.Response(200, json=ANTWORT_TEXT))

        assert await provider.count_tokens(_anfrage()) > 0
        assert provider.capabilities.token_counting is False
        assert gesehen == [], "Eine Näherung kostet keinen Netzaufruf."
