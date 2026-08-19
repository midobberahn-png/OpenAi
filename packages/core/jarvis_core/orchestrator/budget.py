"""Budgetführung eines Laufs.

Siehe docs/04-orchestrator.md §7.

Ein Budget, das erst *nach* der Überschreitung auffällt, ist keine Grenze,
sondern eine Statistik. Deshalb wird vor jedem Schritt geprüft und nach jedem
Schritt fortgeschrieben — und die Fortschreibung landet im ``Run``, damit sie
einen Prozessneustart überlebt.

Die Zeit wird über eine injizierte Uhr gelesen. Das ist kein Testtrick: Ein
Lauf, der auf eine Bestätigung wartet, darf die Wartezeit nicht als
Rechenzeit verbuchen, und ein wiederaufgenommener Lauf muss die vor dem
Neustart verbrauchte Zeit kennen.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from decimal import Decimal

from jarvis_contracts import RunBudget, Usage
from jarvis_core.clock import utc_now

__all__ = ["BudgetTracker", "utc_now"]


class BudgetTracker:
    """Verbrauchszähler eines Laufs gegen sein Budget.

    Bewusst keine Pydantic-Struktur: Der Tracker ist ein kurzlebiges
    Arbeitsobjekt: Der *persistierte* Zustand ist ``Run.usage``, und der wird
    hier hineingegeben und wieder herausgereicht.
    """

    def __init__(
        self,
        budget: RunBudget,
        *,
        usage: Usage | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._budget = budget
        self._clock = clock
        self._started_at = clock()
        self._carried_elapsed_s = usage.elapsed_s if usage else 0.0
        self._usage = (usage or Usage()).model_copy(deep=True)

    @property
    def usage(self) -> Usage:
        """Aktueller Verbrauch inklusive verstrichener Zeit."""
        return self._usage.model_copy(update={"elapsed_s": self._elapsed()})

    def _elapsed(self) -> float:
        """Zeit dieses Abschnitts plus der bereits verbuchten aus früheren.

        Ohne den mitgeführten Anteil würde ein Lauf, der zwischendurch neu
        aufgenommen wurde, sein Zeitbudget von vorn beginnen — die Grenze wäre
        durch einen Neustart aufhebbar.
        """
        return self._carried_elapsed_s + (self._clock() - self._started_at).total_seconds()

    def exceeded(self) -> str | None:
        """Welche Grenze ist erreicht? ``None`` heißt: weiterarbeiten."""
        return self.usage.exceeds(self._budget)

    def record_step(self) -> None:
        self._usage = self._usage.model_copy(update={"steps": self._usage.steps + 1})

    def record_tool_call(self) -> None:
        self._usage = self._usage.model_copy(update={"tool_calls": self._usage.tool_calls + 1})

    def record_model_call(
        self, *, tokens_in: int = 0, tokens_out: int = 0, cost_eur: Decimal = Decimal("0")
    ) -> None:
        self._usage = self._usage.model_copy(
            update={
                "tokens_in": self._usage.tokens_in + tokens_in,
                "tokens_out": self._usage.tokens_out + tokens_out,
                "cost_eur": self._usage.cost_eur + cost_eur,
            }
        )

    def absorb(self, other: Usage) -> None:
        """Verbrauch eines Sub-Agenten übernehmen.

        Ein Teilbudget begrenzt den Sub-Agenten; verbraucht wird es trotzdem
        aus demselben Topf. Andernfalls wäre Delegation der Weg, das
        Kostenlimit beliebig zu vervielfachen.
        """
        merged = self._usage.merge(other)
        self._usage = merged.model_copy(update={"elapsed_s": self._usage.elapsed_s})
