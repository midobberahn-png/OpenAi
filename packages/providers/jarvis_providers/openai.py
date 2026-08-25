"""OpenAI-Adapter.

Derselbe Schnitt wie beim Anthropic-Adapter, und derselbe Satz vorweg: Er
übersetzt, er entscheidet nichts, und er verschluckt keine Fehler. Ob eine
Anfrage diesen Anbieter überhaupt erreichen darf, hat das Model Gateway
entschieden, bevor dieses Modul aufgerufen wird.

**Chat Completions und nicht Responses.** Das SDK bietet beides an. Gewählt ist
der Weg, der zum Port passt: ``LLMProvider`` spricht von Nachrichten,
Werkzeugvorschlägen und einem Abschlussgrund, und genau diese Form hat
``chat.completions``. Die Responses-API führt eigene Begriffe (Items, Zustand
über mehrere Aufrufe hinweg) — sie hier zu übersetzen hieße, einen
Gesprächszustand beim Anbieter zu halten, den dieses System bewusst selbst
führt: Der Lauf ist die Wahrheit, nicht eine Sitzung bei einem Dritten.

**Kein Wiederholen im SDK** (``max_retries=0``), aus demselben Grund wie dort:
Der Modellmodus von ``advance`` macht einen Versuch, und ``timeout_s`` gilt je
Versuch. Verdeckte Anläufe machen aus einem Timeout ein Vielfaches und aus
einer Anfrage mehrere Rechnungen.

**Keine Prompts, keine Antworten, keine Schlüssel im Protokoll.**
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx2
import openai
from openai.types.chat import (
    ChatCompletion,
    ChatCompletionMessageParam,
    ChatCompletionToolUnionParam,
)
from openai.types.completion_usage import CompletionUsage

from jarvis_contracts import (
    CompletionRequest,
    CompletionResult,
    FinishReason,
    MessageRole,
    ModelUsage,
    ProposedToolCall,
    ProviderCapabilities,
    StreamChunk,
)

__all__ = ["OpenAIError", "OpenAIProvider"]


class OpenAIError(Exception):
    """OpenAI hat nicht wie erwartet geantwortet.

    Eigene Klasse wie ``OllamaError`` und ``AnthropicError``: ein Anbieter, der
    nicht antwortet, ist ein Betriebsproblem — und darf dem Nutzer nicht als
    „darf ich nicht" begegnen (docs/04-orchestrator.md §9).
    """


_ABSCHLUSS: dict[str, FinishReason] = {
    "stop": FinishReason.STOP,
    "length": FinishReason.LENGTH,
    "tool_calls": FinishReason.TOOL_CALLS,
    # ``function_call`` ist der Vorläufer von ``tool_calls`` und kommt bei
    # aktuellen Modellen nicht mehr vor. Er wird trotzdem abgebildet: Ein
    # unbekannter Grund fiele sonst auf STOP und behauptete damit, die Antwort
    # sei fertig, während ein Aufruf darin steht.
    "function_call": FinishReason.TOOL_CALLS,
    "content_filter": FinishReason.CONTENT_FILTER,
}


class OpenAIProvider:
    """GPT-Modelle über das offizielle SDK."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str | None = None,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        self._client = openai.AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=http_client,
            max_retries=0,
        )

    @property
    def name(self) -> str:
        return "openai"

    @property
    def capabilities(self) -> ProviderCapabilities:
        """Was dieser Adapter kann — nicht, was im Prospekt des Anbieters steht.

        ``structured_output=True``, weil ``response_format`` hier tatsächlich
        gesetzt wird und die Antwort JSON ist. ``prompt_caching=False``, weil
        dieses Modul nichts dafür tut; dass der Anbieter zwischenspeichert, ist
        eine andere Aussage als „der Adapter nutzt es". ``token_counting``
        bleibt aus: Es gibt keinen Zählendpunkt, und ``count_tokens`` liefert
        eine Näherung, die als solche gekennzeichnet ist.
        """
        return ProviderCapabilities(
            streaming=True,
            tool_calling=True,
            structured_output=True,
            prompt_caching=False,
            vision=False,
            token_counting=False,
            temperature_control=True,
        )

    # -- Aufruf -----------------------------------------------------------
    async def complete(self, request: CompletionRequest) -> CompletionResult:
        try:
            antwort = await self._client.chat.completions.create(
                model=request.model,
                messages=self._nachrichten(request),
                max_completion_tokens=request.max_tokens,
                temperature=request.temperature,
                stop=request.stop or openai.omit,
                tools=self._werkzeuge(request) or openai.omit,
                response_format=(
                    {"type": "json_object"} if request.response_format == "json" else openai.omit
                ),
                timeout=request.timeout_s,
            )
        except openai.APIError as fehler:
            raise OpenAIError(self._meldung(fehler, request.model)) from fehler

        return self._ergebnis(antwort, request)

    async def stream(self, request: CompletionRequest) -> AsyncIterator[StreamChunk]:
        """Antwort in Stücken.

        Werkzeugvorschläge kommen auch hier nicht vor — sie treffen über
        mehrere Stücke verteilt ein, und ein halb übertragener Aufruf ist kein
        Vorschlag. Wer Werkzeuge braucht, ruft ``complete()``.

        ``stream_options={"include_usage": True}`` ist nicht optional, sondern
        die Bedingung dafür, dass am Ende überhaupt Zahlen kommen: Ohne diese
        Angabe liefert die API im Strom **keinen** Verbrauch, und ein
        Kostenzähler, der beim Streamen blind ist, zählt genau die Aufrufe
        nicht, bei denen ein Mensch zusieht.
        """
        try:
            strom = await self._client.chat.completions.create(
                model=request.model,
                messages=self._nachrichten(request),
                max_completion_tokens=request.max_tokens,
                temperature=request.temperature,
                stop=request.stop or openai.omit,
                tools=self._werkzeuge(request) or openai.omit,
                response_format=(
                    {"type": "json_object"} if request.response_format == "json" else openai.omit
                ),
                timeout=request.timeout_s,
                stream=True,
                stream_options={"include_usage": True},
            )
            async for stueck in strom:
                # Das Verbrauchsstück kommt zuletzt und trägt keine Auswahl.
                if stueck.usage is not None and not stueck.choices:
                    yield StreamChunk(usage=self._verbrauch(stueck.usage))
                    continue
                if not stueck.choices:
                    continue
                auswahl = stueck.choices[0]
                if auswahl.delta.content:
                    yield StreamChunk(delta=auswahl.delta.content)
                if auswahl.finish_reason is not None:
                    yield StreamChunk(
                        finish_reason=_ABSCHLUSS.get(auswahl.finish_reason, FinishReason.STOP)
                    )
        except openai.APIError as fehler:
            raise OpenAIError(self._meldung(fehler, request.model)) from fehler

    async def count_tokens(self, request: CompletionRequest) -> int:
        """Näherung, ausdrücklich als solche — wie bei Ollama.

        Es gibt keinen Zählendpunkt. Die Alternative wäre ``tiktoken``: eine
        weitere Abhängigkeit, die ihre Tabellen mitbringt und bei jedem neuen
        Modell nachgezogen werden muss, damit sie nicht *falsch genau* ist.
        Vier Zeichen je Token ist grob und ehrlich; ``token_counting=False``
        sagt beides.
        """
        zeichen = sum(len(nachricht.content) for nachricht in request.messages)
        zeichen += sum(len(json.dumps(werkzeug)) for werkzeug in request.tools)
        return zeichen // 4

    # -- Übersetzung ------------------------------------------------------
    @staticmethod
    def _nachrichten(request: CompletionRequest) -> list[ChatCompletionMessageParam]:
        """Rollen eins zu eins — bis auf die Werkzeugantwort.

        Die Form dieses Anbieters ist der unseren am nächsten: ``system``,
        ``user``, ``assistant`` und ``tool`` heißen dort genauso. Ein
        Werkzeugergebnis braucht ``tool_call_id``; fehlt sie, wird sie **nicht**
        erfunden. Der Aufruf scheitert dann beim Anbieter, und das ist der
        richtige Ausgang — eine ausgedachte Kennung machte aus einem Fehler im
        Kontextaufbau eine Antwort, die plausibel aussieht.
        """
        nachrichten: list[ChatCompletionMessageParam] = []
        for nachricht in request.messages:
            if nachricht.role is MessageRole.TOOL:
                nachrichten.append(
                    {
                        "role": "tool",
                        "content": nachricht.content,
                        "tool_call_id": nachricht.tool_call_id or "",
                    }
                )
            else:
                gebaut: dict[str, Any] = {
                    "role": str(nachricht.role),
                    "content": nachricht.content,
                }
                if nachricht.name:
                    gebaut["name"] = nachricht.name
                nachrichten.append(gebaut)  # type: ignore[arg-type]
        return nachrichten

    @staticmethod
    def _werkzeuge(request: CompletionRequest) -> list[ChatCompletionToolUnionParam]:
        """Werkzeugschemata in die Funktionsform dieses Anbieters."""
        return [
            {
                "type": "function",
                "function": {
                    "name": str(werkzeug["name"]),
                    "description": str(werkzeug.get("description", "")),
                    "parameters": werkzeug.get("input_schema") or {"type": "object"},
                },
            }
            for werkzeug in request.tools
        ]

    def _ergebnis(self, antwort: ChatCompletion, request: CompletionRequest) -> CompletionResult:
        if not antwort.choices:
            # Eine Antwort ohne Auswahl ist kein leerer Text, sondern eine
            # Antwortform, die es nicht geben sollte. Sie als "" zu behandeln
            # machte aus einem Ausfall eine Erfindung.
            raise OpenAIError(f"OpenAI lieferte keine Auswahl für Modell {request.model!r}.")

        auswahl = antwort.choices[0]
        return CompletionResult(
            text=auswahl.message.content or "",
            tool_calls=self._vorschlaege(auswahl.message.tool_calls),
            finish_reason=_ABSCHLUSS.get(auswahl.finish_reason, FinishReason.STOP),
            model=antwort.model or request.model,
            provider=self.name,
            usage=self._verbrauch(antwort.usage),
        )

    @staticmethod
    def _vorschlaege(aufrufe: Any) -> list[ProposedToolCall]:
        """Übersetzt Werkzeugaufrufe — als Vorschläge.

        Die Argumente kommen als **Zeichenkette** und werden hier zu einem
        Objekt gemacht, aber nicht geprüft: Validierung gegen das Werkzeugschema
        und die Policy-Entscheidung kommen beide danach. Kaputtes JSON ist kein
        Fehler des Adapters — es ist ein Vorschlag, der an der Schemaprüfung
        scheitert, und dort gehört er auch hin.
        """
        vorschlaege: list[ProposedToolCall] = []
        for aufruf in aufrufe or []:
            funktion = getattr(aufruf, "function", None)
            if funktion is None or not getattr(funktion, "name", ""):
                continue
            roh = funktion.arguments
            try:
                argumente = json.loads(roh) if roh else {}
            except json.JSONDecodeError:
                argumente = {"_roh": roh}
            vorschlaege.append(
                ProposedToolCall(
                    id=str(aufruf.id),
                    tool_name=str(funktion.name),
                    arguments=argumente if isinstance(argumente, dict) else {},
                )
            )
        return vorschlaege

    @staticmethod
    def _verbrauch(usage: CompletionUsage | None) -> ModelUsage:
        """Zahlen, keine Inhalte. ``cost_eur`` bleibt Sache des Katalogs.

        **Die zwischengespeicherten Tokens werden herausgerechnet**, und das
        ist kein Detail: ``prompt_tokens`` **enthält** sie bei diesem Anbieter,
        ``prompt_tokens_details.cached_tokens`` ist eine Teilmenge davon.
        Anthropic meldet dieselbe Sache umgekehrt — dort steht der aus dem
        Cache gelesene Anteil **neben** ``input_tokens``.

        Der Vertrag führt beide Felder getrennt („sonst stimmt die
        Kostenrechnung nicht"), also müssen sie sich hier auch trennen. Ohne
        diese Subtraktion zählte jeder zwischengespeicherte Token doppelt, und
        die Kostenrechnung fiele bei einem gut zwischengespeicherten Prompt
        deutlich zu hoch aus — in der sicheren Richtung, aber falsch.
        """
        if usage is None:
            return ModelUsage()
        details = usage.prompt_tokens_details
        aus_cache = (details.cached_tokens or 0) if details is not None else 0
        return ModelUsage(
            tokens_in=max(0, usage.prompt_tokens - aus_cache),
            tokens_out=usage.completion_tokens,
            cached_tokens_in=aus_cache,
        )

    @staticmethod
    def _meldung(fehler: openai.APIError, modell: str) -> str:
        """Eine Meldung ohne Inhalte — und ohne Schlüssel.

        Der Antwortkörper kann den Prompt zurückgeben und gehört deshalb nicht
        in eine Meldung, die protokolliert oder einem Modell vorgelegt wird.
        """
        status = getattr(fehler, "status_code", None)
        wenn_status = f" mit {status}" if status is not None else ""
        return f"OpenAI antwortete{wenn_status} für Modell {modell!r} ({type(fehler).__name__})."
