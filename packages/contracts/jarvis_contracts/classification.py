"""Datenklassifikation — die Grundlage des Modell-Routings.

Siehe docs/00-uebersicht.md §8 und docs/04-orchestrator.md §4.

Die Klassifikation wirkt als *hartes Filter*: Ein Modell wird nie gewählt,
weil es besser ist, wenn es für die Klasse nicht zugelassen ist.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Self

__all__ = ["DataClass", "TaintLevel", "escalate"]


class DataClass(StrEnum):
    """Sensibilitätsstufe eines Datenobjekts.

    Die Ordnung ist bedeutungstragend: ``P0 < P1 < P2 < P3``. Vergleiche
    werden explizit definiert und nicht von ``str`` geerbt, damit die
    Semantik auch bei künftigen Erweiterungen erhalten bleibt.
    """

    P0 = "P0"
    """Öffentlich: Websuche, Allgemeinwissen, Wetter. Alle Cloud-Anbieter."""

    P1 = "P1"
    """Intern: Termintitel, Aufgaben, Notizen ohne Personenbezug."""

    P2 = "P2"
    """Sensibel: E-Mail-Inhalte, Kontakte, Dokumente."""

    P3 = "P3"
    """Geheim: Zugangsdaten, Gesundheits-, Finanz-, Mandantendaten.

    Verlässt das Gerät nie. Ausschließlich lokale Verarbeitung.
    """

    @property
    def level(self) -> int:
        """Numerische Stufe 0–3 für Vergleiche und Persistenz."""
        return _LEVELS[self]

    @property
    def cloud_allowed(self) -> bool:
        """Darf diese Klasse überhaupt an einen externen Anbieter gehen?"""
        return self is not DataClass.P3

    @classmethod
    def from_level(cls, level: int) -> Self:
        for member in cls:
            if member.level == level:
                return member
        raise ValueError(f"Unbekannte Datenklassenstufe: {level}")

    # -- Ordnung ---------------------------------------------------------
    #
    # Wichtig: Bei Vergleich mit einem Fremdtyp wird ausdrücklich TypeError
    # geworfen statt NotImplemented zurückgegeben. Da diese Klasse von ``str``
    # erbt, würde Python sonst auf den lexikografischen String-Vergleich
    # zurückfallen — ein stiller Vergleich mit falscher Semantik an genau der
    # Stelle, die das Modell-Routing absichert.
    def _other_level(self, other: Any) -> int:
        if isinstance(other, DataClass):
            return other.level
        raise TypeError(
            f"DataClass lässt sich nicht mit {type(other).__name__} vergleichen. "
            "Für Vergleiche muss beidseitig DataClass verwendet werden."
        )

    def __lt__(self, other: Any) -> bool:
        return self.level < self._other_level(other)

    def __le__(self, other: Any) -> bool:
        return self.level <= self._other_level(other)

    def __gt__(self, other: Any) -> bool:
        return self.level > self._other_level(other)

    def __ge__(self, other: Any) -> bool:
        return self.level >= self._other_level(other)

    def __str__(self) -> str:
        return self.value


_LEVELS: dict[DataClass, int] = {
    DataClass.P0: 0,
    DataClass.P1: 1,
    DataClass.P2: 2,
    DataClass.P3: 3,
}


class TaintLevel(StrEnum):
    """Kontaminationszustand eines Laufs.

    Siehe docs/07-security-permissions.md §4. Der Zustand ist *monoton*:
    einmal ``TAINTED``, für den Lauf nicht mehr entfernbar.
    """

    CLEAN = "clean"
    TAINTED = "tainted"

    @property
    def is_tainted(self) -> bool:
        return self is TaintLevel.TAINTED

    def merge(self, other: TaintLevel) -> TaintLevel:
        """Monotone Verschmelzung — Kontamination propagiert immer nach oben."""
        if self.is_tainted or other.is_tainted:
            return TaintLevel.TAINTED
        return TaintLevel.CLEAN

    def __str__(self) -> str:
        return self.value


def escalate(*classes: DataClass) -> DataClass:
    """Höchste Klasse aus mehreren Eingaben.

    Abgeleitete Daten erben die höchste Stufe ihrer Quellen. Ohne Eingaben
    ist das Ergebnis ``P0`` — es liegen dann keine schützenswerten Daten vor.
    """
    if not classes:
        return DataClass.P0
    return max(classes, key=lambda c: c.level)
