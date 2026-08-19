"""Ollama-Adapter gegen aufgezeichnete Antworten.

ADR-009 nennt Contract-Tests als Gegengewicht zum Nachteil dreier eigener
SDK-Adapter. Umgesetzt mit ``httpx.MockTransport``: Der echte HTTP-Stack
läuft, die Anfrage wird tatsächlich zusammengebaut und serialisiert, nur die
Antwort kommt aus einer Aufzeichnung statt aus dem Netz.

Der Unterschied zu einem Mock des Adapters ist der ganze Punkt. Ein solcher
Mock prüfte, ob der Mock tut, was man ihm sagt. Hier wird geprüft, was
tatsächlich hinausgeht und was aus dem zurückkommt, was Ollama wirklich
antwortet.

Die Aufzeichnungen stammen aus der Ollama-API-Dokumentation (Stand 0.5) und
sind bewusst vollständig, inklusive der Felder, die wir nicht auswerten —
sonst prüft der Test eine Antwortform, die es so nie gibt.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from jarvis_providers.ollama import OllamaError, OllamaProvider

from jarvis_contracts import (
    CompletionRequest,
    FinishReason,
    Message,
    MessageRole,
)

pytestmark = pytest.mark.security


# --------------------------------------------------------------------------
# Aufzeichnungen
# --------------------------------------------------------------------------

ANTWORT_TEXT: dict[str, Any] = {
    "model": "llama3.1:8b",
    "created_at": "2026-08-19T09:00:00.000000Z",
    "message": {"role": "assistant", "content": "Es ist 14 Uhr."},
    "done": True,
    "done_reason": "stop",
    "total_duration": 1_234_567_890,
    "load_duration": 12_345,
    "prompt_eval_count": 42,
    "prompt_eval_duration": 100_000,
    "eval_count": 17,
    "eval_duration": 900_000,
}

ANTWORT_WERKZEUG: dict[str, Any] = {
    "model": "llama3.1:8b",
    "created_at": "2026-08-19T09:00:00.000000Z",
    "message": {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "function": {
                    "name": "calendar.create",
                    "arguments": {"title": "Fokuszeit", "start": "2026-08-20T09:00"},
                }
            }
        ],
    },
    "done": True,
    "done_reason": "stop",
    "prompt_eval_count": 88,
    "eval_count": 24,
}


def _provider(
    handler: Any, *, base_url: str = "http://localhost:11434"
) -> tuple[OllamaProvider, list[httpx.Request]]:
    """Adapter mit aufgezeichnetem Transport — und einem Protokoll dessen,
    was tatsächlich hinausgegangen wäre."""
    gesehen: list[httpx.Request] = []

    def aufzeichnen(request: httpx.Request) -> httpx.Response:
        gesehen.append(request)
        return handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(aufzeichnen))
    return OllamaProvider(base_url=base_url, client=client), gesehen


def _anfrage(**kw: Any) -> CompletionRequest:
    grund: dict[str, Any] = {
        "model": "llama3.1:8b",
        "messages": [Message(role=MessageRole.USER, content="Wie spät ist es?")],
    }
    grund.update(kw)
    return CompletionRequest(**grund)


class TestAntwortLesen:
    async def test_text_und_verbrauch(self) -> None:
        provider, _ = _provider(lambda _: httpx.Response(200, json=ANTWORT_TEXT))
        ergebnis = await provider.complete(_anfrage())

        assert ergebnis.text == "Es ist 14 Uhr."
        assert ergebnis.finish_reason is FinishReason.STOP
        assert ergebnis.provider == "ollama"
        assert ergebnis.usage.tokens_in == 42
        assert ergebnis.usage.tokens_out == 17

    @pytest.mark.invariant("model-tool-calls-are-proposals")
    async def test_werkzeugaufrufe_werden_zu_vorschlaegen(self) -> None:
        """Der Übergang, auf den es ankommt: Was Ollama „tool_calls" nennt,
        heißt hier ``ProposedToolCall`` — und trägt nichts, was einer Erlaubnis
        ähnelt."""
        provider, _ = _provider(lambda _: httpx.Response(200, json=ANTWORT_WERKZEUG))
        ergebnis = await provider.complete(_anfrage())

        assert ergebnis.finish_reason is FinishReason.TOOL_CALLS
        assert len(ergebnis.tool_calls) == 1
        vorschlag = ergebnis.tool_calls[0]
        assert vorschlag.tool_name == "calendar.create"
        assert vorschlag.arguments == {"title": "Fokuszeit", "start": "2026-08-20T09:00"}
        assert vorschlag.id, "Ollama vergibt keine IDs — der Adapter muss eine setzen"

    async def test_argumente_als_json_string(self) -> None:
        """Manche Modelle liefern die Argumente als Zeichenkette."""
        antwort = json.loads(json.dumps(ANTWORT_WERKZEUG))
        antwort["message"]["tool_calls"][0]["function"]["arguments"] = '{"title": "Aus Text"}'
        provider, _ = _provider(lambda _: httpx.Response(200, json=antwort))

        ergebnis = await provider.complete(_anfrage())
        assert ergebnis.tool_calls[0].arguments == {"title": "Aus Text"}

    async def test_kaputtes_json_scheitert_nicht_im_adapter(self) -> None:
        """Ein Modell, das kaputtes JSON liefert, ist kein Fehlerfall des
        Adapters. Der Vorschlag scheitert später an der Schemaprüfung, und
        dort gehört er hin — hier würde er nur unsichtbar verschwinden."""
        antwort = json.loads(json.dumps(ANTWORT_WERKZEUG))
        antwort["message"]["tool_calls"][0]["function"]["arguments"] = "{kein json"
        provider, _ = _provider(lambda _: httpx.Response(200, json=antwort))

        ergebnis = await provider.complete(_anfrage())
        assert ergebnis.tool_calls[0].arguments == {"_roh": "{kein json"}

    async def test_aufruf_ohne_namen_wird_uebergangen(self) -> None:
        antwort = json.loads(json.dumps(ANTWORT_WERKZEUG))
        antwort["message"]["tool_calls"][0]["function"].pop("name")
        provider, _ = _provider(lambda _: httpx.Response(200, json=antwort))

        assert await provider.complete(_anfrage()) is not None
        assert (await provider.complete(_anfrage())).tool_calls == []


class TestAnfrageSenden:
    async def test_werkzeugschemata_werden_uebersetzt(self) -> None:
        provider, gesehen = _provider(lambda _: httpx.Response(200, json=ANTWORT_TEXT))
        await provider.complete(
            _anfrage(
                tools=[
                    {
                        "name": "calendar.create",
                        "description": "Legt einen Termin an.",
                        "input_schema": {"type": "object", "properties": {"title": {}}},
                    }
                ]
            )
        )

        gesendet = json.loads(gesehen[0].content)
        werkzeug = gesendet["tools"][0]
        assert werkzeug["type"] == "function"
        assert werkzeug["function"]["name"] == "calendar.create"
        assert werkzeug["function"]["parameters"]["type"] == "object"

    async def test_die_herkunftsmarkierung_geht_nicht_mit(self) -> None:
        """``is_untrusted`` ist eine Angabe des Systems über die Herkunft, kein
        Teil des Gesprächs. Sie im Prompt mitzuschicken hieße, dem Modell die
        Kennzeichnung zur eigenen Verwendung zu überlassen."""
        provider, gesehen = _provider(lambda _: httpx.Response(200, json=ANTWORT_TEXT))
        await provider.complete(
            _anfrage(
                messages=[
                    Message(
                        role=MessageRole.USER,
                        content="Fasse die Mail zusammen",
                        is_untrusted=True,
                    )
                ]
            )
        )

        gesendet = json.loads(gesehen[0].content)
        assert gesendet["messages"] == [{"role": "user", "content": "Fasse die Mail zusammen"}]

    async def test_grenzen_werden_uebertragen(self) -> None:
        provider, gesehen = _provider(lambda _: httpx.Response(200, json=ANTWORT_TEXT))
        await provider.complete(_anfrage(max_tokens=256, temperature=0.1, stop=["ENDE"]))

        optionen = json.loads(gesehen[0].content)["options"]
        assert optionen["num_predict"] == 256
        assert optionen["temperature"] == 0.1
        assert optionen["stop"] == ["ENDE"]

    async def test_der_adapter_prueft_keine_zulassung(self) -> None:
        """Er kennt weder Datenklasse noch Taint — beides klärt das Gateway
        vorher. Ein Adapter mit eigener Prüfung hätte die Daten bereits."""
        import inspect

        signatur = inspect.signature(OllamaProvider.complete)
        assert set(signatur.parameters) == {"self", "request"}


class TestFehler:
    async def test_ein_ausfall_wird_nicht_zur_leeren_antwort(self) -> None:
        """Fehler werden benannt, nicht kaschiert. Eine leere Antwort statt
        einer Ausnahme macht aus einem Ausfall eine Erfindung."""
        provider, _ = _provider(lambda _: httpx.Response(500, text="boom"))
        with pytest.raises(OllamaError, match="500"):
            await provider.complete(_anfrage())

    async def test_nicht_erreichbar_ist_kein_berechtigungsfehler(self) -> None:
        def verbindungsfehler(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("kein Dienst")

        provider, _ = _provider(verbindungsfehler)
        with pytest.raises(OllamaError, match="nicht erreichbar"):
            await provider.complete(_anfrage())

    async def test_die_fehlermeldung_traegt_keinen_prompt(self) -> None:
        """Der Antwortkörper von Ollama enthält im Fehlerfall den Prompt.

        Er darf nicht in die Ausnahme — sie landet in Protokollen, und dort
        haben genau die Daten nichts verloren, für die es diesen lokalen Pfad
        gibt.
        """
        geheim = "Diagnose: etwas sehr Privates"
        provider, _ = _provider(lambda _: httpx.Response(400, text=f"prompt war: {geheim}"))

        with pytest.raises(OllamaError) as fehler:
            await provider.complete(
                _anfrage(messages=[Message(role=MessageRole.USER, content=geheim)])
            )
        assert geheim not in str(fehler.value)


class TestStrom:
    async def test_stuecke_und_abschluss(self) -> None:
        zeilen = [
            json.dumps({"message": {"content": "Es "}, "done": False}),
            json.dumps({"message": {"content": "ist "}, "done": False}),
            json.dumps({"message": {"content": "14 Uhr."}, "done": False}),
            json.dumps({"done": True, "done_reason": "stop", "eval_count": 5}),
        ]
        provider, _ = _provider(lambda _: httpx.Response(200, text="\n".join(zeilen)))

        stuecke = [s async for s in provider.stream(_anfrage())]
        assert "".join(s.delta for s in stuecke) == "Es ist 14 Uhr."
        assert stuecke[-1].finish_reason is FinishReason.STOP
        assert stuecke[-1].usage is not None
        assert stuecke[-1].usage.tokens_out == 5


class TestZaehlung:
    async def test_die_naeherung_ist_als_solche_ausgewiesen(self) -> None:
        """Wer sie für exakt hält, plant sein Budget falsch — deshalb meldet
        der Adapter ``token_counting=False``."""
        provider, _ = _provider(lambda _: httpx.Response(200, json=ANTWORT_TEXT))
        assert provider.capabilities.token_counting is False
        assert await provider.count_tokens(_anfrage()) > 0
