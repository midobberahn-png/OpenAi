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

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from jarvis_contracts import InvocationStatus, ToolInvocation

__all__ = ["InvocationStore", "UndoClaim"]


@dataclass(frozen=True)
class UndoClaim:
    """Was eine beanspruchte Rücknahme mitbringt.

    Zwei Angaben, und beide kommen aus der Datenbank: **welches** Werkzeug
    zurücknimmt und **woran**. Der Aufrufer nennt weder das eine noch das
    andere — er nennt die Kennung des Aufrufs, und alles Weitere ergibt sich
    aus der Zeile, die ihm gehört.
    """

    tool_name: str
    undo_token: str | None


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

    async def claim_undo(
        self, invocation_id: UUID, *, user_id: UUID, now: datetime
    ) -> UndoClaim | None:
        """Beansprucht die Rücknahme eines Aufrufs — atomar und in einem Zug.

        Vier Bedingungen, und alle vier gehören **in die Anweisung**, die den
        Zustand ändert:

        * Der Aufruf gehört dem Nutzer (über den Lauf, nicht über den Request).
        * Er steht auf ``executed`` — nur eine Wirkung lässt sich zurücknehmen.
        * Seine Ausführung liegt weniger als ``UNDO_TTL`` zurück.
        * Er ist noch nicht zurückgenommen.

        Ein ``lesen … prüfen … schreiben`` mit denselben vier Bedingungen wäre
        bei zwei gleichzeitigen Anfragen zwei Rücknahmen — dasselbe Muster wie
        beim Nonce, beim Ausführungsanspruch, beim Grant-Verbrauch und beim
        Planschritt. Der fünfte Fall, und diesmal von vornherein an der
        richtigen Stelle.

        Rückgabe ist der Rücknahmepunkt, oder ``None``, wenn eine der vier
        Bedingungen nicht gilt. Kein Unterschied nach Grund: Für den Aufrufer
        heißen alle vier dasselbe, und die Unterscheidung nach außen zu tragen
        hieße, einem Fremden die Existenz eines Aufrufs zu bestätigen.

        **Der Zustand wechselt vor der Wirkung.** Scheitert die Rücknahme
        danach, bleibt ``undone`` stehen: Der Weg ist verbraucht, und ob er
        gewirkt hat, sagt das Ergebnis. Die Gegenrichtung — erst wirken, dann
        vermerken — ließe zwei gleichzeitige Rücknahmen beide durch.
        """
        ...

    async def mark(
        self,
        invocation_id: object,
        status: InvocationStatus,
        *,
        error: str | None = None,
        undo_token: str | None = None,
    ) -> None:
        """Schreibt den Ausgang fort (ausgeführt, gescheitert, blockiert).

        ``undo_token`` ist der Rücknahmepunkt, den das Werkzeug hinterlassen
        hat. Er wird **hier** abgelegt und nirgends sonst: Der Weg zurück
        adressiert den *Aufruf*, und was zurückgenommen wird, muss deshalb an
        ihm hängen. An den Client geht er nicht — er ist kein Inhaberpapier,
        sondern eine Notiz des Werkzeugs an sich selbst.
        """
        ...
