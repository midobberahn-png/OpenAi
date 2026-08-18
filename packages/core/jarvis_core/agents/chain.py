"""Delegationskette und ihre Rechtemenge.

Siehe docs/06-agenten-tools.md §5.

Die bisherige Prüfung deckte **eine** Stufe ab: Ein Sub-Agent bekommt die
Schnittmenge aus seiner Whitelist und den Nutzerrechten. Über zwei Stufen war
das nicht gesichert — bei A → B → C hätte C die Fähigkeiten von B erben
können, nur weil B ihn aufgerufen hat. Dann wäre die Kette der Umweg um jede
Beschränkung: Ein Agent ohne Versandrecht delegiert an einen, der es hat.

Die Antwort ist eine Struktur statt einer Prüfung: Die Kette **ist** die
Rechtemenge. Jede Stufe kann nur verengen, weil eine Schnittmenge nichts
anderes kann.
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from jarvis_contracts import AgentSpec, DataClass

__all__ = ["AgentChain"]


class AgentChain(BaseModel):
    """Der Pfad vom Supervisor bis zum aktuell handelnden Agenten.

    Unveränderlich: ``extend()`` erzeugt eine neue Kette. Eine veränderbare
    Kette wäre eine Kette, die sich während des Laufs erweitern lässt — und
    genau das soll ausgeschlossen sein.
    """

    model_config = ConfigDict(frozen=True)

    agents: tuple[AgentSpec, ...] = Field(min_length=1)

    @property
    def current(self) -> AgentSpec:
        return self.agents[-1]

    @property
    def depth(self) -> int:
        """Delegationstiefe. Der Supervisor allein ist Tiefe 0."""
        return len(self.agents) - 1

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(a.name for a in self.agents)

    def extend(self, spec: AgentSpec) -> AgentChain:
        return AgentChain(agents=(*self.agents, spec))

    def contains(self, name: str) -> bool:
        """Für die Zyklusprüfung: Ein Agent, der sich selbst aufruft, läuft
        endlos — und zwar mit vollem Budget."""
        return name in self.names

    def capability_ceiling(self) -> frozenset[str]:
        """Schnittmenge der Whitelists **aller** Stufen.

        Nicht die des aufgerufenen Agenten und nicht die des Aufrufers,
        sondern die aller Beteiligten. Ein Werkzeug, das irgendwo auf dem Weg
        nicht erlaubt war, ist am Ende nicht erlaubt.

        Hinweis zur Konfiguration: Ein delegierender Agent mit leerer
        ``allowed_tools`` gibt nichts weiter — die Schnittmenge ist dann leer.
        Das ist Absicht. Eine leere Whitelist als „keine Beschränkung“ zu lesen
        wäre die eine Ausnahme, die den Mechanismus aushebelt; wer delegieren
        darf, schreibt auf, was er weitergeben kann.
        """
        ceiling: set[str] | None = None
        for spec in self.agents:
            allowed = set(spec.allowed_tools)
            ceiling = allowed if ceiling is None else ceiling & allowed
        return frozenset(ceiling or set())

    def data_class_ceiling(self) -> DataClass:
        """Strengste Datenklasse der Kette.

        Das Minimum, nicht das Maximum: Wer über einen Agenten delegiert, der
        nur bis P1 arbeiten darf, kommt nicht dadurch an P3-Daten, dass das
        Ziel sie führen dürfte.
        """
        return min((spec.max_data_class for spec in self.agents), key=lambda c: c.level)

    def reads_untrusted(self) -> bool:
        """Liest irgendeine Stufe der Kette Fremdinhalt?

        Eine einzige Stufe genügt: Kontamination wandert nach oben, nicht nur
        nach unten.
        """
        return any(spec.accepts_untrusted_input for spec in self.agents)

    def effective_tools(
        self,
        granted: Iterable[str],
        *,
        tainted: bool = False,
        safe_tools: Iterable[str] | None = None,
    ) -> frozenset[str]:
        """Was die Kette tatsächlich aufrufen darf.

        ``Kettenschnittmenge ∩ Nutzerrechte ∩ (kontaminiert ? unbedenklich)``.
        Die Nutzerrechte stehen bewusst mit in der Formel: Ein Agent bekommt
        nie mehr, als der Nutzer erteilt hat, auch wenn seine Whitelist mehr
        enthält.
        """
        effective = self.capability_ceiling() & frozenset(granted)
        if tainted:
            effective &= frozenset(safe_tools or ())
        return effective
