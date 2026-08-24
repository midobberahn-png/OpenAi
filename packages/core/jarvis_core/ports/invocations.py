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
from uuid import UUID

from jarvis_contracts import InvocationStatus, ToolInvocation

__all__ = ["InvocationStore"]


class InvocationStore(Protocol):
    """Persistenz der Werkzeugaufrufe eines Laufs."""

    async def record(self, invocation: ToolInvocation) -> None:
        """Hält den Aufruf mitsamt Entscheidung fest — **vor** der Ausführung.

        Die Reihenfolge ist bedeutungstragend: Ein Aufruf, der erst nach seiner
        Wirkung protokolliert wird, fehlt genau dann, wenn er abgestürzt ist —
        also in dem Fall, für den man das Protokoll liest.

        **Und „vorher" heißt festgeschrieben, nicht bloß geschrieben.** Eine
        persistente Implementierung darf den Eintrag nicht in einer Transaktion
        zurücklassen, die der Aufrufer noch zurückrollen kann. Sonst gilt die
        Zusage oben genau im Absturzfall nicht, für den sie gemacht ist.

        Der zweite Grund ist unmittelbarer: Der Grant-Verbrauch hängt an dieser
        Zeile und liegt in einer eigenen Transaktion, damit er selbst einen
        Absturz übersteht. Er sieht deshalb nur, was committed ist. Ein
        Protokoll in der Request-Transaktion hieße: kein sichtbarer Anspruch,
        keine Ausführung.
        """
        ...

    async def load(self, invocation_id: UUID) -> ToolInvocation | None:
        """Ein einzelner Aufruf, oder ``None``."""
        ...

    async def for_run(self, run_id: UUID) -> list[ToolInvocation]:
        """Alle Aufrufe eines Laufs, älteste zuerst."""
        ...

    async def for_step(self, run_id: UUID, step_seq: int) -> list[ToolInvocation]:
        """Die Aufrufe eines **geplanten Schrittes** — die Frage der Wiederaufnahme.

        Diese drei Lesezugriffe standen zuerst nur in der Implementierung, und
        das war eine stille Lücke im Vertrag: Der Kern konnte das Protokoll
        nicht befragen, ohne den Postgres-Speicher zu kennen. Ein Anker, den
        nur der Adapter lesen kann, trägt keine Entscheidung im Kern.

        Eine Liste und kein einzelner Eintrag: Ein Schritt kann mehrfach
        protokolliert sein, wenn er nach einer folgenlosen Abweisung erneut
        versucht wurde. Welcher davon zählt, entscheidet die Wiederaufnahme —
        nicht dieser Speicher.
        """
        ...

    async def mark(
        self, invocation_id: object, status: InvocationStatus, *, error: str | None = None
    ) -> None:
        """Schreibt den Ausgang fort (ausgeführt, gescheitert, blockiert)."""
        ...
