"""Agentenkatalog.

Wie die Tool Registry: Spezifikationen sind Daten, und der Katalog gibt keine
Ausführungsfähigkeit heraus. Wer wissen will, was ein Agent darf, braucht
seine Laufzeit nicht.
"""

from __future__ import annotations

from jarvis_contracts import AgentSpec

from .chain import AgentChain

__all__ = ["AgentRegistry", "DuplicateAgent", "UnknownAgent"]


class DuplicateAgent(Exception):
    """Zwei Agenten mit demselben Namen.

    Wie beim Werkzeugkatalog ein Programmierfehler: Ein überschriebener Agent
    tauschte die Whitelist hinter demselben Namen aus — und damit die
    Rechtemenge jeder Kette, die über ihn läuft.
    """


class UnknownAgent(Exception):
    """Delegation an einen Agenten, den es nicht gibt.

    Muss von einem Berechtigungsfehler unterscheidbar bleiben: Ein Supervisor,
    der auf einen halluzinierten Agentennamen delegiert, hat ein Modellproblem,
    kein Rechteproblem.
    """


class AgentRegistry:
    def __init__(self) -> None:
        self._specs: dict[str, AgentSpec] = {}

    def register(self, spec: AgentSpec) -> None:
        if spec.name in self._specs:
            raise DuplicateAgent(
                f"Agent {spec.name!r} ist bereits registriert. Ein Überschreiben würde "
                "die Rechtemenge jeder Kette ändern, die über ihn läuft."
            )
        self._specs[spec.name] = spec

    def get(self, name: str) -> AgentSpec | None:
        return self._specs.get(name)

    def require(self, name: str) -> AgentSpec:
        spec = self._specs.get(name)
        if spec is None:
            raise UnknownAgent(f"Unbekannter Agent: {name!r}")
        return spec

    def chain_from(self, *names: str) -> AgentChain:
        """Kette aus Namen — für Tests und für die Wiederaufnahme eines Laufs.

        Ein Lauf, der nach einem Neustart fortgesetzt wird, muss seine Kette
        rekonstruieren können; sonst begänne er mit den Rechten des
        Supervisors statt mit denen der erreichten Stufe.
        """
        return AgentChain(agents=tuple(self.require(name) for name in names))

    def names(self) -> set[str]:
        return set(self._specs)

    def __len__(self) -> int:
        return len(self._specs)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._specs
