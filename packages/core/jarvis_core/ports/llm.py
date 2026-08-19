"""Port der Sprachmodelle.

Siehe ADR-009: ein schmales Protokoll über den nativen SDKs, keine
Kompatibilitätsfassade. Die Unterschiede zwischen den Anbietern werden über
``ProviderCapabilities`` sichtbar gemacht, statt sie zu verstecken — was eine
Fassade abschneidet, sind genau die Fähigkeiten, für die man den jeweiligen
Anbieter gewählt hat.

Was hier **nicht** steht, ist so wichtig wie das, was hier steht: Der Port
kennt keine Datenklasse, keinen Taint-Zustand und keine Berechtigung. Ein
Adapter soll Anfragen übersetzen und Antworten zurückgeben — er soll nicht
entscheiden dürfen, ob er gefragt werden durfte. Diese Entscheidung fällt
davor, im Model Gateway.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol

from jarvis_contracts import (
    CompletionRequest,
    CompletionResult,
    ProviderCapabilities,
    StreamChunk,
)

__all__ = ["LLMProvider"]


class LLMProvider(Protocol):
    """Ein Anbieteradapter.

    Implementierungen liegen in ``packages/providers`` und sind die einzige
    Stelle im System, an der ein Anbieter-SDK vorkommt. Ein AST-Test hält das
    fest (``layering-no-provider-sdk-in-core``).
    """

    @property
    def name(self) -> str:
        """Kurzname des Anbieters — ``openai``, ``anthropic``, ``ollama``."""
        ...

    @property
    def capabilities(self) -> ProviderCapabilities: ...

    async def complete(self, request: CompletionRequest) -> CompletionResult:
        """Eine vollständige Antwort.

        Fehler der Fremdbibliothek dürfen durchschlagen; der Aufrufer
        übersetzt sie in seine eigene Fehlerbehandlung
        (docs/04-orchestrator.md §9). Ein Adapter, der Fehler verschluckt und
        eine leere Antwort liefert, macht aus einem Ausfall eine Erfindung.
        """
        ...

    def stream(self, request: CompletionRequest) -> AsyncIterator[StreamChunk]:
        """Antwort in Stücken.

        Werkzeugvorschläge kommen bei allen Anbietern fragmentiert an und
        gehören deshalb nicht in die Stücke, sondern in das abschließende
        ``CompletionResult``: Ein halb übertragener Aufruf ist kein Vorschlag.
        """
        ...

    async def count_tokens(self, request: CompletionRequest) -> int:
        """Tokens *vor* dem Aufruf.

        Ohne diese Zahl ist jede Budgetprüfung eine Schätzung — und ein
        Budget, das erst nach der Überschreitung auffällt, hat den teuren
        Aufruf schon bezahlt. Adapter ohne echte Zählung geben eine ehrliche
        Näherung zurück und melden ``token_counting=False``.
        """
        ...
