"""Zustandsautomat der Laufausführung.

Siehe docs/04-orchestrator.md §6.

Bewusst eine Übergangstabelle plus eine Funktion — kein Framework. Der
gesamte Automat sind unter 100 Zeilen; jede Abstraktion darüber würde die
eine Frage verdecken, auf die es ankommt: *Welcher Übergang ist erlaubt?*
"""

from __future__ import annotations

from jarvis_contracts import RunStatus

__all__ = [
    "TERMINAL",
    "TRANSITIONS",
    "IllegalTransition",
    "assert_transition",
    "can_transition",
    "resumable_statuses",
]


TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    RunStatus.QUEUED: frozenset(
        {
            RunStatus.PLANNING,
            RunStatus.CANCELLED,
            RunStatus.FAILED,
        }
    ),
    RunStatus.PLANNING: frozenset(
        {
            RunStatus.EXECUTING,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
            RunStatus.BUDGET_EXCEEDED,
        }
    ),
    RunStatus.EXECUTING: frozenset(
        {
            RunStatus.AWAITING_CONFIRMATION,
            RunStatus.VERIFYING,
            RunStatus.INTERRUPTED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
            RunStatus.BUDGET_EXCEEDED,
            RunStatus.COMPLETED,
        }
    ),
    RunStatus.AWAITING_CONFIRMATION: frozenset(
        {
            RunStatus.EXECUTING,
            RunStatus.CANCELLED,
            # Eine abgelaufene Bestätigung beendet den Lauf, sie führt ihn nicht
            # fort. Alles andere hieße: Ein Dialog von gestern Abend könnte heute
            # früh noch wirken.
            RunStatus.FAILED,
        }
    ),
    RunStatus.VERIFYING: frozenset(
        {
            RunStatus.PLANNING,  # genau ein Replan
            RunStatus.COMPLETED,
            RunStatus.FAILED,
            RunStatus.BUDGET_EXCEEDED,
        }
    ),
    RunStatus.INTERRUPTED: frozenset(
        {
            RunStatus.PLANNING,  # Korrektur → neu planen
            RunStatus.EXECUTING,  # Fortsetzen nach Pause
            RunStatus.CANCELLED,
        }
    ),
    # Endzustände
    RunStatus.COMPLETED: frozenset(),
    RunStatus.FAILED: frozenset(),
    RunStatus.CANCELLED: frozenset(),
    RunStatus.BUDGET_EXCEEDED: frozenset(),
}

TERMINAL: frozenset[RunStatus] = frozenset(
    status for status, targets in TRANSITIONS.items() if not targets
)


class IllegalTransition(Exception):
    """Ein nicht vorgesehener Zustandswechsel.

    Wird als Programmierfehler behandelt, nicht als Laufzeitzustand: Ein
    Orchestrator, der einen unzulässigen Übergang versucht, hat einen Bug —
    und den soll er laut melden, nicht in einen undefinierten Zustand laufen.
    """

    def __init__(self, current: RunStatus, target: RunStatus) -> None:
        self.current = current
        self.target = target
        allowed = sorted(t.value for t in TRANSITIONS.get(current, frozenset()))
        super().__init__(
            f"Übergang {current.value} → {target.value} ist nicht vorgesehen. "
            f"Erlaubt von {current.value}: {allowed or 'keine (Endzustand)'}"
        )


def can_transition(current: RunStatus, target: RunStatus) -> bool:
    return target in TRANSITIONS.get(current, frozenset())


def assert_transition(current: RunStatus, target: RunStatus) -> None:
    if not can_transition(current, target):
        raise IllegalTransition(current, target)


def resumable_statuses() -> frozenset[RunStatus]:
    """Zustände, die ein Worker-Neustart wieder aufnehmen muss.

    Muss mit dem Teilindex ``ix_runs_resumable`` übereinstimmen — sonst sucht
    der Worker über einen Index, der die gesuchten Zeilen nicht enthält. Ein
    Test hält beides zusammen.
    """
    return frozenset(s for s in RunStatus if s.is_resumable)
