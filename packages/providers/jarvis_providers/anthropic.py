"""Anthropic-Adapter.

Der erste Anbieter, der **nicht** auf diesem Gerät läuft. Damit wird zum ersten
Mal real, wofür die Datenklassifikation gebaut ist: Ab hier gibt es einen Weg,
auf dem Daten das Haus verlassen — und die Frage ist nicht mehr theoretisch,
welche das dürfen.

Die Antwort steht nicht in diesem Modul. Sie steht im Katalog
(``models.py``: was ein Modell verarbeiten darf) und im Model Gateway (das es
durchsetzt). Dieser Adapter übersetzt, mehr nicht — siehe die zwei Regeln im
Paketkopf: Er entscheidet nichts, und er verschluckt keine Fehler.

**Natives SDK statt HTTP von Hand** (ADR-009). Der Ollama-Adapter geht direkt
über HTTP, mit Grund: eine Abhängigkeit weniger im Pfad der sensibelsten Daten.
Hier wiegt das andere Argument schwerer — Streaming-Ereignisse, Werkzeugblöcke
und Zählendpunkt sind beim SDK bereits typisiert, und eine handgeschriebene
Fassung davon wäre mehr Code an der Stelle, an der ein Fehler teuer ist.

**Kein Wiederholen im SDK** (``max_retries=0``). Die Vorgabe der Bibliothek ist
größer als eins, und das wäre eine stille Abweichung von dem, was das System
über sich sagt: Der Modellmodus von ``advance`` macht **einen** Versuch, und
``timeout_s`` gilt je Versuch. Drei verdeckte Anläufe machen aus einem Timeout
von 60 Sekunden drei Minuten und aus einer Anfrage drei Rechnungen. Wer
wiederholen will, tut es dort, wo jemand zusieht.

**Was hier nicht protokolliert wird:** Prompts, Antworten, Schlüssel. Der
Schlüssel steht in der Konfiguration und darf in keiner Meldung dieses Moduls
vorkommen — auch nicht gekürzt.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import anthropic
import httpx2
from anthropic.types import Message as AnthropicMessage
from anthropic.types import MessageParam, TextBlock, ToolParam, ToolUseBlock, Usage

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

__all__ = ["AnthropicError", "AnthropicProvider"]


class AnthropicError(Exception):
    """Anthropic hat nicht wie erwartet geantwortet.

    Eigene Klasse aus demselben Grund wie ``OllamaError``: Ein Anbieter, der
    nicht antwortet, ist ein Betriebsproblem und gehört dem Nutzer als solches
    gesagt — nicht als „darf ich nicht" (docs/04-orchestrator.md §9).
    """


_ABSCHLUSS: dict[str, FinishReason] = {
    "end_turn": FinishReason.STOP,
    "stop_sequence": FinishReason.STOP,
    # ``pause_turn`` gehört zu serverseitigen Werkzeugen, die dieses System
    # nicht benutzt. Als STOP zu führen ist die ehrliche Näherung: Die Antwort
    # ist zu Ende, auch wenn der Anbieter sie fortsetzen könnte.
    "pause_turn": FinishReason.STOP,
    "max_tokens": FinishReason.LENGTH,
    "model_context_window_exceeded": FinishReason.LENGTH,
    "refusal": FinishReason.CONTENT_FILTER,
    "tool_use": FinishReason.TOOL_CALLS,
}


class AnthropicProvider:
    """Claude-Modelle über das offizielle SDK."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str | None = None,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key,
            base_url=base_url,
            http_client=http_client,
            max_retries=0,
        )

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def capabilities(self) -> ProviderCapabilities:
        """Was **dieser Adapter** kann — nicht, was der Anbieter anbietet.

        Der Unterschied ist der Punkt: ``prompt_caching`` steht auf ``False``,
        obwohl Anthropic es kann, weil dieses Modul kein ``cache_control``
        setzt. Ein Feld, das die Fähigkeiten des Anbieterprospekts wiedergibt,
        beantwortet die falsche Frage — der Orchestrator plant mit dem, was
        tatsächlich geschieht.

        ``vision`` ebenso: ``Message.content`` ist eine Zeichenkette, hier
        kommt kein Bild durch.

        **``temperature_control=False``, und das ist der Befund dieses
        Adapters.** ``messages.create`` hat in dieser SDK-Fassung überhaupt
        keinen Temperaturparameter mehr; an seiner Stelle steht
        ``output_config.effort`` (``low`` … ``max``). Das ist keine andere
        Schreibweise derselben Sache: „0.0" heißt *bestimmt statt kreativ",
        ``effort`` heißt *wie viel Arbeit". Eine erfundene Zuordnung zwischen
        beiden sähe aus, als sei der Wunsch erfüllt worden.

        Der Wunsch ist real: ``plan_arguments.py`` verlangt ``temperature=0.0``,
        weil Werkzeugargumente bestimmt sein sollen. Mit einem Anthropic-Modell
        sind sie es nicht — eine Frage der Güte, nicht der Sicherheit, denn die
        Schemaprüfung und die Bestätigung durch einen Menschen stehen
        unverändert dahinter. Sichtbar gemacht statt versteckt ist genau das,
        wofür ``ProviderCapabilities`` laut ADR-009 da ist.
        """
        return ProviderCapabilities(
            streaming=True,
            tool_calling=True,
            structured_output=False,
            prompt_caching=False,
            vision=False,
            temperature_control=False,
            # Der einzige Adapter mit echter Zählung vor dem Aufruf: Anthropic
            # hat dafür einen Endpunkt. Damit ist die Budgetprüfung an dieser
            # Stelle eine Aussage und keine Schätzung.
            token_counting=True,
        )

    # -- Aufruf -----------------------------------------------------------
    async def complete(self, request: CompletionRequest) -> CompletionResult:
        self._pruefe_erfuellbar(request)
        system, nachrichten = self._nachrichten(request)
        try:
            antwort = await self._client.messages.create(
                model=request.model,
                max_tokens=request.max_tokens,
                messages=nachrichten,
                system=system or anthropic.omit,
                stop_sequences=request.stop or anthropic.omit,
                tools=self._werkzeuge(request) or anthropic.omit,
                timeout=request.timeout_s,
            )
        except anthropic.APIError as fehler:
            raise AnthropicError(self._meldung(fehler, request.model)) from fehler

        return self._ergebnis(antwort, request)

    async def stream(self, request: CompletionRequest) -> AsyncIterator[StreamChunk]:
        """Antwort in Stücken.

        Werkzeugvorschläge kommen hier nicht vor — dieselbe Festlegung wie beim
        Ollama-Adapter und aus demselben Grund: Sie treffen über mehrere
        Ereignisse verteilt ein, und ein halb übertragener Aufruf ist kein
        Vorschlag, sondern ein Fragment. Wer Werkzeuge braucht, ruft
        ``complete()``.

        Der Verbrauch steht im **letzten** Stück. Die Eingabetokens meldet
        Anthropic am Anfang (``message_start``), die Ausgabetokens am Ende;
        gesammelt wird beides und zusammen ausgeliefert, damit ein Aufrufer
        nicht zwei Stücke addieren muss, um eine Rechnung zu bekommen.
        """
        self._pruefe_erfuellbar(request)
        system, nachrichten = self._nachrichten(request)
        tokens_ein = 0
        gelesen_aus_cache = 0
        try:
            strom = await self._client.messages.create(
                model=request.model,
                max_tokens=request.max_tokens,
                messages=nachrichten,
                system=system or anthropic.omit,
                stop_sequences=request.stop or anthropic.omit,
                tools=self._werkzeuge(request) or anthropic.omit,
                timeout=request.timeout_s,
                stream=True,
            )
            async for ereignis in strom:
                if ereignis.type == "message_start":
                    tokens_ein = ereignis.message.usage.input_tokens
                    gelesen_aus_cache = ereignis.message.usage.cache_read_input_tokens or 0
                elif ereignis.type == "content_block_delta" and ereignis.delta.type == "text_delta":
                    yield StreamChunk(delta=ereignis.delta.text)
                elif ereignis.type == "message_delta":
                    yield StreamChunk(
                        finish_reason=_ABSCHLUSS.get(
                            ereignis.delta.stop_reason or "end_turn", FinishReason.STOP
                        ),
                        usage=ModelUsage(
                            tokens_in=tokens_ein,
                            tokens_out=ereignis.usage.output_tokens or 0,
                            cached_tokens_in=gelesen_aus_cache,
                        ),
                    )
        except anthropic.APIError as fehler:
            raise AnthropicError(self._meldung(fehler, request.model)) from fehler

    async def count_tokens(self, request: CompletionRequest) -> int:
        """Tokens vor dem Aufruf — gezählt, nicht geschätzt.

        Der Endpunkt kostet einen Netzaufruf und liefert dafür eine Zahl, auf
        die sich ein Budget stützen kann. Scheitert er, scheitert die Zählung:
        Eine stillschweigende Näherung an dieser Stelle wäre eine Zahl, die
        wie eine Messung aussieht.
        """
        system, nachrichten = self._nachrichten(request)
        try:
            gezaehlt = await self._client.messages.count_tokens(
                model=request.model,
                messages=nachrichten,
                system=system or anthropic.omit,
                tools=self._werkzeuge(request) or anthropic.omit,
            )
        except anthropic.APIError as fehler:
            raise AnthropicError(self._meldung(fehler, request.model)) from fehler
        return gezaehlt.input_tokens

    # -- Was dieser Anbieter nicht kann -----------------------------------
    @staticmethod
    def _pruefe_erfuellbar(request: CompletionRequest) -> None:
        """Weist ab, was dieser Adapter nicht einlösen kann.

        **``response_format="json"`` geht hier nicht** — und das Verschweigen
        wäre schlimmer als die Absage. Die Messages-API dieses SDK kennt keine
        Betriebsart „irgendein JSON": ``output_config.format`` verlangt ein
        **Schema**, und der Vertrag liefert keines. Ein Adapter, der das Feld
        stillschweigend fallen ließe, gäbe Fließtext an einen Aufrufer zurück,
        der ihn parst — der Fehler entstünde weit weg von seiner Ursache.

        Was hier ausdrücklich **nicht** abgewiesen wird, ist ``temperature``:
        Die Erklärung dazu steht bei ``capabilities``.
        """
        if request.response_format == "json":
            raise AnthropicError(
                "Dieser Adapter kann keine JSON-Ausgabe zusagen: Die API verlangt dafür "
                "ein Schema, und die Anfrage bringt keines mit."
            )

    # -- Übersetzung ------------------------------------------------------
    def _nachrichten(self, request: CompletionRequest) -> tuple[str, list[MessageParam]]:
        """Trennt Systemanweisung und Gesprächsverlauf.

        Anthropic führt die Systemanweisung als **eigenen Parameter** und nicht
        als Rolle im Verlauf. Mehrere Systemnachrichten werden deshalb
        zusammengefasst; die Reihenfolge bleibt erhalten.

        Ein Werkzeugergebnis (``role=tool``) wird zu einem ``tool_result``-Block
        in einer Nutzernachricht — so sieht das Protokoll dieses Anbieters aus.
        Fehlt die Zuordnung (``tool_call_id``), wird sie **nicht erfunden**:
        Der Aufruf scheitert dann beim Anbieter, und das ist richtig so. Eine
        ausgedachte Kennung machte aus einem Fehler im Kontextaufbau eine
        Antwort, die plausibel aussieht.

        **Die Reihenfolge wird nicht repariert.** Anthropic erwartet einen
        alternierenden Verlauf, der mit einer Nutzernachricht beginnt. Ein
        Adapter, der das still zurechtrückt, verdeckt einen Fehler im
        Kontextaufbau — und zwar dauerhaft, weil danach niemand mehr sieht,
        dass er auftritt.
        """
        system: list[str] = []
        nachrichten: list[MessageParam] = []
        for nachricht in request.messages:
            if nachricht.role is MessageRole.SYSTEM:
                system.append(nachricht.content)
            elif nachricht.role is MessageRole.TOOL:
                nachrichten.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": nachricht.tool_call_id or "",
                                "content": nachricht.content,
                            }
                        ],
                    }
                )
            else:
                rolle: Any = "assistant" if nachricht.role is MessageRole.ASSISTANT else "user"
                nachrichten.append({"role": rolle, "content": nachricht.content})
        return "\n\n".join(system), nachrichten

    @staticmethod
    def _werkzeuge(request: CompletionRequest) -> list[ToolParam]:
        """Werkzeugschemata in die Form dieses Anbieters.

        Sie ist der unseren am nächsten: ``name``, ``description``,
        ``input_schema``. Was im Schema steht — ``required``,
        ``additionalProperties`` —, geht unverändert mit; geprüft wird es
        trotzdem hier im Haus, denn ein Schema, das nur nach außen geht, gilt
        nicht.
        """
        return [
            {
                "name": str(werkzeug["name"]),
                "description": str(werkzeug.get("description", "")),
                "input_schema": werkzeug.get("input_schema") or {"type": "object"},
            }
            for werkzeug in request.tools
        ]

    def _ergebnis(self, antwort: AnthropicMessage, request: CompletionRequest) -> CompletionResult:
        text = "".join(block.text for block in antwort.content if isinstance(block, TextBlock))
        return CompletionResult(
            text=text,
            tool_calls=[
                ProposedToolCall(
                    id=block.id,
                    tool_name=block.name,
                    # ``input`` kommt als Objekt und nicht als Zeichenkette —
                    # ein Umweg über JSON weniger als bei den anderen beiden.
                    # Ungeprüft bleibt es trotzdem: Schema und Policy kommen
                    # danach, und ein Adapter, der hier aussortiert, verdeckt
                    # genau die Fälle, die man sehen will.
                    arguments=block.input if isinstance(block.input, dict) else {},
                )
                for block in antwort.content
                if isinstance(block, ToolUseBlock)
            ],
            finish_reason=_ABSCHLUSS.get(antwort.stop_reason or "end_turn", FinishReason.STOP),
            model=antwort.model or request.model,
            provider=self.name,
            usage=self._verbrauch(antwort.usage),
        )

    @staticmethod
    def _verbrauch(usage: Usage) -> ModelUsage:
        """Zahlen, keine Inhalte.

        ``cost_eur`` bleibt leer: Was ein Aufruf kostet, steht im Katalog
        (``cost_per_1m_in``/``_out``) und ist Sache des Deployments. Ein
        Adapter, der Preise mitbrächte, führte eine zweite Wahrheit darüber —
        und die veraltet, sobald ein Anbieter seine Liste ändert.
        """
        return ModelUsage(
            tokens_in=usage.input_tokens,
            tokens_out=usage.output_tokens,
            cached_tokens_in=usage.cache_read_input_tokens or 0,
        )

    @staticmethod
    def _meldung(fehler: anthropic.APIError, modell: str) -> str:
        """Eine Meldung ohne Inhalte — und ohne Schlüssel.

        Der Antwortkörper eines Anbieters kann den Prompt zurückgeben; er
        gehört deshalb nicht in eine Meldung, die im Protokoll landet oder
        einem Modell als Fehlertext vorgelegt wird. Was bleibt, ist die Art des
        Fehlers und, wo vorhanden, der Statuscode.
        """
        status = getattr(fehler, "status_code", None)
        wenn_status = f" mit {status}" if status is not None else ""
        return f"Anthropic antwortete{wenn_status} für Modell {modell!r} ({type(fehler).__name__})."
