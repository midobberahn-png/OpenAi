"""Ollama-Adapter.

Siehe ADR-010. Ollama ist der lokale Pfad, und der ist für P3 keine
Bequemlichkeit, sondern die Voraussetzung dafür, dass die Datenklassifikation
überhaupt einlösbar ist: Ohne ein Modell, das auf dem Gerät läuft, gäbe es für
Gesundheits-, Finanz- und Zugangsdaten schlicht keinen Weg.

Deshalb ist dieser Adapter der erste. Er braucht keinen Schlüssel, keine
Abrechnung und keine Vertrauensentscheidung gegenüber einem Dritten — und er
ist die einzige Bauart, bei der die Zusicherung „diese Daten verlassen das
Gerät nicht" beim Wort genommen werden kann.

Direkt über die HTTP-API statt über ein SDK: Ollama spricht ein kleines,
stabiles Protokoll, und eine Abhängigkeit weniger im Pfad für die sensibelsten
Daten ist die richtige Richtung. ``httpx`` ist ohnehin da.

**Was hier nicht passiert:** keine Entscheidung über Zulässigkeit (die traf
das Model Gateway), kein Verschlucken von Fehlern, kein Protokollieren von
Prompts oder Antworten. Der letzte Punkt ist keine Nachlässigkeit beim
Debuggen, sondern Absicht — die Inhalte, die hier durchlaufen, sind genau die,
die das Gerät nicht verlassen sollen.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from typing import Any

import httpx

from jarvis_contracts import (
    CompletionRequest,
    CompletionResult,
    FinishReason,
    Message,
    MessageRole,
    ModelUsage,
    ProposedToolCall,
    ProviderCapabilities,
    StreamChunk,
)

__all__ = ["OllamaError", "OllamaProvider"]

DEFAULT_URL = "http://localhost:11434"


class OllamaError(Exception):
    """Ollama hat nicht wie erwartet geantwortet.

    Eigene Klasse, damit der Orchestrator sie von einem Berechtigungsfehler
    unterscheiden kann: Ein nicht laufender Dienst ist ein Betriebsproblem und
    gehört dem Nutzer gesagt, nicht als „darf ich nicht" ausgegeben
    (docs/04-orchestrator.md §9).
    """


class OllamaProvider:
    """Lokale Modelle über die Ollama-HTTP-API."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_URL,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        # Ein von außen gereichter Client ist der Testeinstieg: Mit
        # httpx.MockTransport läuft dabei der echte HTTP-Stack, nur die Antwort
        # ist aufgezeichnet. Ein Mock des Adapters selbst würde stattdessen
        # prüfen, ob der Mock tut, was man ihm sagt.
        self._client = client

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def capabilities(self) -> ProviderCapabilities:
        # ``token_counting=False`` ist eine ehrliche Angabe: Ollama zählt erst
        # beim Aufruf. ``count_tokens`` liefert deshalb eine Näherung, und wer
        # sie für exakt hält, plant sein Budget falsch.
        return ProviderCapabilities(
            streaming=True,
            tool_calling=True,
            structured_output=True,
            prompt_caching=False,
            vision=True,
            token_counting=False,
        )

    # -- Aufruf -----------------------------------------------------------
    async def complete(self, request: CompletionRequest) -> CompletionResult:
        begonnen = time.monotonic()
        nutzlast = self._nutzlast(request, stream=False)

        async with self._session() as client:
            try:
                antwort = await client.post(
                    f"{self._base_url}/api/chat", json=nutzlast, timeout=request.timeout_s
                )
                antwort.raise_for_status()
            except httpx.HTTPStatusError as fehler:
                # Der Statuscode und der Modellname dürfen ins Protokoll, der
                # Antwortkörper nicht: Er enthält bei Ollama den Prompt.
                raise OllamaError(
                    f"Ollama antwortete mit {fehler.response.status_code} "
                    f"für Modell {request.model!r}."
                ) from fehler
            except httpx.HTTPError as fehler:
                raise OllamaError(
                    f"Ollama unter {self._base_url} nicht erreichbar: {type(fehler).__name__}."
                ) from fehler

            daten = antwort.json()

        return self._ergebnis(daten, request, latenz_ms=int((time.monotonic() - begonnen) * 1000))

    async def stream(self, request: CompletionRequest) -> AsyncIterator[StreamChunk]:
        """Antwort in Stücken.

        Werkzeugvorschläge kommen hier bewusst **nicht** vor: Ollama liefert
        sie über mehrere Stücke verteilt, und ein halb übertragener Aufruf ist
        kein Vorschlag, sondern ein Fragment. Wer Werkzeuge braucht, ruft
        ``complete()``.
        """
        nutzlast = self._nutzlast(request, stream=True)

        async with (
            self._session() as client,
            client.stream(
                "POST", f"{self._base_url}/api/chat", json=nutzlast, timeout=request.timeout_s
            ) as antwort,
        ):
            try:
                antwort.raise_for_status()
            except httpx.HTTPStatusError as fehler:
                raise OllamaError(
                    f"Ollama antwortete mit {fehler.response.status_code}."
                ) from fehler

            async for zeile in antwort.aiter_lines():
                if not zeile.strip():
                    continue
                try:
                    stueck = json.loads(zeile)
                except json.JSONDecodeError as fehler:
                    raise OllamaError("Ollama lieferte kein gültiges JSON.") from fehler

                if stueck.get("done"):
                    yield StreamChunk(
                        finish_reason=self._abschluss(stueck),
                        usage=self._verbrauch(stueck, latenz_ms=0),
                    )
                    return
                yield StreamChunk(delta=stueck.get("message", {}).get("content", ""))

    async def count_tokens(self, request: CompletionRequest) -> int:
        """Näherung, ausdrücklich als solche.

        Ollama zählt erst beim Aufruf; ein zusätzlicher Aufruf nur zum Zählen
        wäre teurer als der Nutzen. Vier Zeichen je Token ist die grobe Regel
        für europäische Sprachen — genau genug für eine Budgetampel, zu grob
        für eine Zusage.
        """
        zeichen = sum(len(nachricht.content) for nachricht in request.messages)
        zeichen += sum(len(json.dumps(werkzeug)) for werkzeug in request.tools)
        return zeichen // 4

    # -- Übersetzung ------------------------------------------------------
    def _nutzlast(self, request: CompletionRequest, *, stream: bool) -> dict[str, Any]:
        nutzlast: dict[str, Any] = {
            "model": request.model,
            "messages": [self._nachricht(m) for m in request.messages],
            "stream": stream,
            "options": {
                "temperature": request.temperature,
                "num_predict": request.max_tokens,
            },
        }
        if request.stop:
            nutzlast["options"]["stop"] = request.stop
        if request.tools:
            nutzlast["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": werkzeug["name"],
                        "description": werkzeug.get("description", ""),
                        "parameters": werkzeug.get("input_schema", {"type": "object"}),
                    },
                }
                for werkzeug in request.tools
            ]
        if request.response_format == "json":
            nutzlast["format"] = "json"
        return nutzlast

    @staticmethod
    def _nachricht(nachricht: Message) -> dict[str, Any]:
        """Übersetzt eine Nachricht.

        ``is_untrusted`` wird **nicht** übertragen — es ist eine Angabe des
        Systems über die Herkunft, nicht Teil des Gesprächs. Sie im Prompt
        mitzuschicken hieße, dem Modell die Kennzeichnung zur eigenen
        Verwendung zu überlassen; die Auszeichnung von Fremdinhalt geschieht
        beim Rendern des Kontexts, nicht hier.
        """
        gebaut: dict[str, Any] = {"role": str(nachricht.role), "content": nachricht.content}
        if nachricht.role is MessageRole.TOOL and nachricht.name:
            gebaut["name"] = nachricht.name
        return gebaut

    def _ergebnis(
        self, daten: dict[str, Any], request: CompletionRequest, *, latenz_ms: int
    ) -> CompletionResult:
        nachricht = daten.get("message") or {}
        return CompletionResult(
            text=nachricht.get("content", ""),
            tool_calls=self._vorschlaege(nachricht),
            finish_reason=self._abschluss(daten),
            model=daten.get("model", request.model),
            provider=self.name,
            usage=self._verbrauch(daten, latenz_ms=latenz_ms),
        )

    @staticmethod
    def _vorschlaege(nachricht: dict[str, Any]) -> list[ProposedToolCall]:
        """Übersetzt Werkzeugaufrufe — als Vorschläge.

        Ollama vergibt keine Aufruf-IDs; sie werden hier durchnummeriert, weil
        das Protokoll eine Zuordnung braucht. Die Argumente werden
        **ungeprüft** durchgereicht: Validierung gegen das Werkzeugschema und
        die Policy-Entscheidung kommen beide danach, und ein Adapter, der hier
        schon aussortiert, verdeckt genau die Fälle, die man sehen will.
        """
        vorschlaege: list[ProposedToolCall] = []
        for nummer, aufruf in enumerate(nachricht.get("tool_calls") or [], start=1):
            funktion = aufruf.get("function") or {}
            name = funktion.get("name")
            if not name:
                continue
            argumente = funktion.get("arguments")
            if isinstance(argumente, str):
                try:
                    argumente = json.loads(argumente)
                except json.JSONDecodeError:
                    # Ein Modell, das kaputtes JSON liefert, ist kein Fehlerfall
                    # des Adapters — der Vorschlag scheitert später an der
                    # Schemaprüfung, und dort gehört er auch hin.
                    argumente = {"_roh": argumente}
            vorschlaege.append(
                ProposedToolCall(
                    id=str(aufruf.get("id") or f"ollama-{nummer}"),
                    tool_name=name,
                    arguments=argumente if isinstance(argumente, dict) else {},
                )
            )
        return vorschlaege

    @staticmethod
    def _abschluss(daten: dict[str, Any]) -> FinishReason:
        if (daten.get("message") or {}).get("tool_calls"):
            return FinishReason.TOOL_CALLS
        grund = daten.get("done_reason")
        if grund == "length":
            return FinishReason.LENGTH
        return FinishReason.STOP

    @staticmethod
    def _verbrauch(daten: dict[str, Any], *, latenz_ms: int) -> ModelUsage:
        """Kosten bleiben null — lokale Modelle kosten Strom, keine Rechnung.

        Das ist keine Schönfärberei: Der Kostenzähler existiert, um Ausgaben an
        Dritte zu begrenzen. Ihn mit geschätzten Stromkosten zu füllen, machte
        das Budget unschärfer, nicht ehrlicher.
        """
        return ModelUsage(
            tokens_in=int(daten.get("prompt_eval_count") or 0),
            tokens_out=int(daten.get("eval_count") or 0),
            latency_ms=latenz_ms or int((daten.get("total_duration") or 0) / 1_000_000),
        )

    def _session(self) -> Any:
        """Vorhandenen Client wiederverwenden oder einen eigenen öffnen."""
        if self._client is not None:
            return _Geliehen(self._client)
        return httpx.AsyncClient()


class _Geliehen:
    """Reicht einen fremden Client durch, ohne ihn zu schließen.

    Wer den Client mitbringt, verwaltet seine Lebensdauer — ein Adapter, der
    ihn beim Verlassen schließt, macht ihn beim zweiten Aufruf unbrauchbar.
    """

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def __aenter__(self) -> httpx.AsyncClient:
        return self._client

    async def __aexit__(self, *_: object) -> None:
        return None
