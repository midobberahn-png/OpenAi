"""Port des Grant-Verbrauchs.

Ein ``ExecutionGrant`` ist eine Erlaubnis für **einen** Werkzeugaufruf. Die
Registry prüft Herkunft, Hash, Lauf und Nutzer — vier Werte, die bei einer
zweiten Vorlage desselben Grants unverändert gelten. Ohne einen Verbrauch ist
die Erlaubnis deshalb beliebig oft einlösbar; nachgewiesen in der dritten
externen Prüfrunde (Invariante ``grant-single-use``).

Der Verbrauch hängt an der ``invocation_id`` und ausdrücklich nicht am Objekt:
``model_copy()``, ``copy`` und ``deepcopy`` erzeugen sonst jeweils einen
unverbrauchten Zwilling. Er gehört an einen Ort, den alle Kopien teilen — und
bei mehreren Prozessen an einen, den alle Prozesse teilen.

Die Semantik ist **höchstens einmal**, dieselbe Entscheidung wie beim
Ausführungsanspruch der Bestätigung: Stürzt der Prozess zwischen Verbrauch und
Handler ab, gilt die Erlaubnis als verbraucht. Für Aktionen mit Außenwirkung
ist das die richtige Richtung — eine Mail, die vielleicht nicht hinausging,
kann der Nutzer erneut senden; eine, die zweimal hinausging, holt niemand
zurück.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

__all__ = ["GrantConsumer"]


class GrantConsumer(Protocol):
    """Löst einen Grant ein — genau einmal."""

    async def consume(self, invocation_id: UUID, *, now: datetime) -> bool:
        """``True``, wenn dieser Aufruf den Grant erwirkt hat.

        Muss atomar sein: Zwei gleichzeitige Aufrufe mit derselben
        ``invocation_id`` dürfen nicht beide ``True`` liefern. Ein
        ``if verbraucht: ... markiere()`` erfüllt das nicht — die Zusage gehört
        in die ``WHERE``-Klausel, nicht in eine Prüfung davor.
        """
        ...
