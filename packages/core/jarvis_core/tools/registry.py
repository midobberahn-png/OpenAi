"""Werkzeugkatalog.

Siehe docs/06-agenten-tools.md §4.

Die Registry hält Spezifikationen und Ausführungsfunktionen getrennt: Wer die
Berechtigungen eines Werkzeugs prüfen will, braucht dessen Implementierung
nicht. Das erlaubt es, den Katalog zu inspizieren und zu dokumentieren, ohne
Code auszuführen.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from jarvis_contracts import RiskLevel, ToolResult, ToolSpec

__all__ = ["DuplicateTool", "ToolHandler", "ToolRegistry", "UnknownTool"]

ToolHandler = Callable[..., Awaitable[ToolResult]]


class DuplicateTool(Exception):
    """Zwei Werkzeuge mit demselben Namen.

    Programmierfehler, nicht Laufzeitzustand: Ein überschriebenes Werkzeug wäre
    ein stiller Wechsel der Berechtigungen hinter demselben Namen.
    """


class UnknownTool(Exception):
    """Ein Werkzeug wurde angefordert, das nicht registriert ist.

    Tritt insbesondere bei halluzinierten Werkzeugnamen auf und muss deshalb
    klar von einem Berechtigungsfehler unterscheidbar bleiben.
    """


class ToolRegistry:
    """Katalog aller verfügbaren Werkzeuge."""

    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._handlers: dict[str, ToolHandler] = {}

    def register(self, spec: ToolSpec, handler: ToolHandler | None = None) -> None:
        if spec.name in self._specs:
            raise DuplicateTool(
                f"Werkzeug {spec.name!r} ist bereits registriert. Ein Überschreiben "
                "würde die Berechtigungen hinter demselben Namen still austauschen."
            )
        self._specs[spec.name] = spec
        if handler is not None:
            self._handlers[spec.name] = handler

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def require(self, name: str) -> ToolSpec:
        spec = self._specs.get(name)
        if spec is None:
            raise UnknownTool(f"Unbekanntes Werkzeug: {name!r}")
        return spec

    def handler(self, name: str) -> ToolHandler:
        handler = self._handlers.get(name)
        if handler is None:
            raise UnknownTool(f"Für {name!r} ist keine Implementierung registriert.")
        return handler

    def names(self) -> set[str]:
        return set(self._specs)

    def all_specs(self) -> list[ToolSpec]:
        return [self._specs[n] for n in sorted(self._specs)]

    def required_scopes(self) -> set[str]:
        """Alle Scopes, die irgendein Werkzeug benötigt.

        Grundlage der Prüfung, dass der Scope-Katalog vollständig ist — ein
        Werkzeug mit unbekanntem Scope wäre zur Laufzeit nicht freigebbar.
        """
        return {scope for spec in self._specs.values() for scope in spec.scopes}

    def safe_when_tainted(self) -> set[str]:
        """Werkzeuge, die in einem kontaminierten Lauf noch zulässig sind.

        Wird der Agent Runtime übergeben, um das Werkzeugset zu verengen
        (docs/06-agenten-tools.md §5).
        """
        return {name for name, spec in self._specs.items() if not spec.is_blocked_by_taint()}

    def by_risk(self, minimum: RiskLevel) -> list[ToolSpec]:
        return [s for s in self.all_specs() if s.risk >= minimum]

    def to_schema(self, names: set[str] | None = None) -> list[dict[str, Any]]:
        """Werkzeugdefinitionen für ein Sprachmodell.

        Nur die übergebenen Namen — der Aufrufer hat die Verengung durch
        Berechtigungen und Taint bereits vorgenommen. Die Registry entscheidet
        das nicht selbst.
        """
        selected = (
            self.all_specs()
            if names is None
            else [self._specs[n] for n in sorted(names) if n in self._specs]
        )
        return [
            {
                "name": spec.name,
                "description": spec.description,
                "input_schema": spec.parameters,
            }
            for spec in selected
        ]

    def __len__(self) -> int:
        return len(self._specs)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._specs
