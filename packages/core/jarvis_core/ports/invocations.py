"""Port des Werkzeugaufruf-Protokolls.

Jeder Werkzeugaufruf wird festgehalten, bevor er wirkt: mit Argumenten,
Risikoklasse und der Policy-Entscheidung, die zu ihm geführt hat. Das ist
nicht nur Nachvollziehbarkeit — ``pending_actions.invocation_id`` ist ein
Fremdschlüssel auf diese Zeile. Ohne sie gibt es keine Bestätigung, und ohne
Bestätigung keine Ausführung bestätigungspflichtiger Werkzeuge.

Der Befund kam aus dem End-to-End-Test: Die Bestätigungssuite legte ihre
Invokation selbst an (eine Testabkürzung), sodass die Lücke im Executor nicht
auffiel. Ein Ablauf, der nur im Test funktioniert, weil der Test etwas
vorbereitet, was die Anwendung nicht tut, ist genau die Art von Lücke, gegen
die ein Durchstichtest existiert.
"""

from __future__ import annotations

from typing import Protocol

from jarvis_contracts import InvocationStatus, ToolInvocation

__all__ = ["InvocationStore"]


class InvocationStore(Protocol):
    """Persistenz der Werkzeugaufrufe eines Laufs."""

    async def record(self, invocation: ToolInvocation) -> None:
        """Hält den Aufruf mitsamt Entscheidung fest — **vor** der Ausführung.

        Die Reihenfolge ist bedeutungstragend: Ein Aufruf, der erst nach seiner
        Wirkung protokolliert wird, fehlt genau dann, wenn er abgestürzt ist —
        also in dem Fall, für den man das Protokoll liest.
        """
        ...

    async def mark(
        self, invocation_id: object, status: InvocationStatus, *, error: str | None = None
    ) -> None:
        """Schreibt den Ausgang fort (ausgeführt, gescheitert, blockiert)."""
        ...
