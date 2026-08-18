"""Werkzeugkatalog.

Siehe docs/06-agenten-tools.md §4.

Die Registry hält Spezifikationen und Ausführungsfunktionen getrennt: Wer die
Berechtigungen eines Werkzeugs prüfen will, braucht dessen Implementierung
nicht. Das erlaubt es, den Katalog zu inspizieren und zu dokumentieren, ohne
Code auszuführen.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from secrets import compare_digest
from typing import Any
from uuid import UUID

from jarvis_contracts import RiskLevel, ToolResult, ToolSpec
from jarvis_core.ports.permissions import ExecutionAuthorization

__all__ = [
    "DuplicateTool",
    "ForgedAuthorization",
    "ToolHandler",
    "ToolRegistry",
    "UnknownTool",
]

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


class ForgedAuthorization(Exception):
    """Eine Autorisierung passt nicht zu dem Aufruf, für den sie vorgelegt wird.

    Eigene Klasse und ausdrücklich nicht ``UnknownTool``: Ein unbekannter
    Werkzeugname ist ein Modellfehler und alltäglich, eine nicht passende
    Autorisierung ist ein Sicherheitsvorfall und gehört als solcher ins
    Audit-Log. Beide unter derselben Ausnahme zu führen hieße, das eine im
    Rauschen des anderen zu verlieren.
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

    async def execute(
        self, auth: ExecutionAuthorization, *, run_id: UUID, user_id: UUID
    ) -> ToolResult:
        """Führt ein Werkzeug aus — der einzige Weg dorthin.

        Es gibt bewusst keine Methode, die den Handler herausgibt. Wer ein
        Werkzeug ausführen will, braucht eine ``ExecutionAuthorization``, und
        die entsteht ausschließlich in ``ApprovalGateway`` nach Hash-Vergleich
        und erneuter Policy-Prüfung.

        Drei Prüfungen, die getrennte Angriffe abdecken:

        1. **Hash.** Autorisierung und Ausführung sind getrennte Aufrufe;
           zwischen ihnen könnte ein Aufrufer andere Argumente einsetzen.
        2. **Lauf.** ``run_id`` und ``user_id`` müssen zu dem Kontext passen, in
           dem tatsächlich ausgeführt wird. Ohne diese Prüfung wäre ein gültiger
           Grant aus Lauf A in Lauf B verwendbar — Werkzeugname und Argumente
           passen dort ja weiterhin. Die Bindung hinge dann allein daran, dass
           niemand einen Grant über eine Laufgrenze trägt, und das ist keine
           Zusicherung, sondern eine Hoffnung.
        3. **Implementierung.** Ein registrierter Spec ohne Handler ist ein
           Konfigurationsfehler und kein Berechtigungsproblem.

        Der Aufrufer nennt ``run_id`` und ``user_id`` ausdrücklich, statt dass
        die Registry sie dem Grant entnimmt: Ein Vergleich eines Wertes mit sich
        selbst prüft nichts.
        """
        spec = self.require(auth.tool_name)
        handler = self._handlers.get(auth.tool_name)
        if handler is None:
            raise UnknownTool(f"Für {auth.tool_name!r} ist keine Implementierung registriert.")

        from jarvis_core.policy.approval import payload_hash  # lokal: Zyklus vermeiden

        actual = payload_hash(spec.name, auth.arguments)
        if not compare_digest(actual, auth.verified_hash):
            raise ForgedAuthorization(
                f"Argumente von {spec.name!r} weichen von der Autorisierung ab — "
                "Ausführung abgebrochen."
            )
        if auth.run_id != run_id or auth.user_id != user_id:
            raise ForgedAuthorization(
                f"Die Autorisierung für {spec.name!r} gehört zu einem anderen Lauf oder "
                "Nutzer. Eine Erlaubnis gilt für genau einen Aufruf in genau einem Lauf."
            )
        return await handler(**auth.arguments)

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
