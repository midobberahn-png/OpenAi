"""Stufe 4 — Planung.

Siehe docs/04-orchestrator.md §5.

Der Plan ist ein validiertes Objekt und kein Freitext, weil er der Oberfläche
*vor* der Ausführung gezeigt wird. Bei einem System mit Mail- und
Kalenderzugriff ist die frühe Sichtbarkeit der Absicht die wirksamste
Fehlerbremse — wirksam allerdings nur, wenn das Angezeigte auch das
Ausgeführte ist.

Zur Abgrenzung, weil hier die Grenze zur Policy verläuft:

* Der Planer bekommt die **bereits verengte** Werkzeugmenge aus
  ``PolicyEngine.effective_tools()``. Er verengt nicht selbst und er erweitert
  nicht.
* Ein eingeplanter Schritt ist **keine Erlaubnis**. Jeder Schritt geht beim
  Ausführen erneut durch die Policy Engine. Ein Plan, der ein gesperrtes
  Werkzeug enthielte, führte zu einem blockierten Schritt — nicht zu einer
  Ausführung.
* ``Plan.requires_confirmation`` ist eine **Ankündigung** für die Oberfläche,
  keine Zusage. Ob tatsächlich bestätigt wird, entscheidet die Policy Engine
  je Aufruf und mit Kenntnis der Argumente.
"""

from __future__ import annotations

from typing import Literal, Protocol

from jarvis_contracts import (
    Complexity,
    Intent,
    Plan,
    PlanStep,
    RiskLevel,
    ToolSpec,
    TurnClassification,
)

__all__ = ["ExecutionMode", "ToolLookup", "plan_turn", "select_mode"]


ExecutionMode = Literal["direct", "planned", "delegated"]


class ToolLookup(Protocol):
    """Nur zum Nachschlagen von Risiko und Lesart — nicht zum Ausführen."""

    def get(self, name: str) -> ToolSpec | None: ...


_READING_SUFFIXES = (".read", ".search", ".list", ".get")
"""Lesende Werkzeuge laufen zuerst und dürfen parallel laufen.

Die Erkennung am Namen ist eine Heuristik für die *Reihenfolge*, keine
Sicherheitsaussage: Ob ein Werkzeug Fremdinhalt einbringt, steht in
``ToolSpec.reads_untrusted_content``, und ob es ausgeführt werden darf,
entscheidet die Policy Engine.
"""

MAX_PLANNED_STEPS = 6
"""Darüber wird delegiert (docs/04-orchestrator.md §5)."""


def select_mode(classification: TurnClassification, *, tool_count: int) -> ExecutionMode:
    """Direkt, geplant oder delegiert."""
    if classification.intent is Intent.RESEARCH or tool_count > MAX_PLANNED_STEPS:
        return "delegated"
    if classification.is_multi_step or tool_count > 1:
        return "planned"
    if classification.complexity.level >= Complexity.COMPLEX.level:
        return "planned"
    return "direct"


def plan_turn(
    classification: TurnClassification,
    *,
    available_tools: set[str],
    tools: ToolLookup,
    goal: str | None = None,
) -> Plan:
    """Erzeugt den Ausführungsplan.

    ``available_tools`` ist das Ergebnis von ``PolicyEngine.effective_tools()``
    — die Schnittmenge aus Werkzeugwunsch, erteilten Rechten und Taint-Zustand.
    Was dort fehlt, taucht im Plan nicht auf; der Nutzer sieht damit keinen
    Schritt angekündigt, der ohnehin blockiert würde.
    """
    goal_text = goal or "Anfrage bearbeiten"
    usable = [name for name in classification.likely_tools if name in available_tools]
    mode = select_mode(classification, tool_count=len(usable))

    if mode == "delegated":
        return _delegated_plan(classification, goal_text, usable)
    if mode == "direct" or not usable:
        return _direct_plan(classification, goal_text, usable, tools)
    return _stepwise_plan(goal_text, usable, tools)


# --------------------------------------------------------------------------
# Modi
# --------------------------------------------------------------------------


def _direct_plan(
    classification: TurnClassification,
    goal: str,
    usable: list[str],
    tools: ToolLookup,
) -> Plan:
    """Ein Modellaufruf, höchstens ein Werkzeug."""
    steps: list[PlanStep] = []
    if usable:
        steps.append(
            PlanStep(
                seq=1,
                description=f"{usable[0]} aufrufen",
                kind="tool",
                target=usable[0],
            )
        )
    steps.append(
        PlanStep(
            seq=len(steps) + 1,
            description="Antwort formulieren",
            kind="llm",
            target="response",
            depends_on=[s.seq for s in steps],
        )
    )
    return Plan(
        goal=goal,
        steps=steps,
        requires_confirmation=_announces_confirmation(usable, tools),
    )


def _stepwise_plan(goal: str, usable: list[str], tools: ToolLookup) -> Plan:
    """Lesende Schritte zuerst und parallel, schreibende danach.

    ``depends_on`` bildet die tatsächliche Abhängigkeit ab: „Mails prüfen“ und
    „Kalender prüfen“ hängen nicht voneinander ab und laufen gleichzeitig; der
    Termin danach hängt von beidem ab, weil er ihre Ergebnisse braucht.
    Zugleich ist das die Reihenfolge, in der Kontamination entsteht — erst
    lesen, dann schreiben —, sodass der Taint-Zustand beim schreibenden Schritt
    bereits gilt.
    """
    reading = [name for name in usable if _is_reading(name)]
    writing = [name for name in usable if not _is_reading(name)]

    steps: list[PlanStep] = []
    for name in reading:
        steps.append(
            PlanStep(seq=len(steps) + 1, description=f"{name} aufrufen", kind="tool", target=name)
        )
    read_seqs = [s.seq for s in steps]

    for name in writing:
        steps.append(
            PlanStep(
                seq=len(steps) + 1,
                description=f"{name} aufrufen",
                kind="tool",
                target=name,
                depends_on=read_seqs,
            )
        )

    steps.append(
        PlanStep(
            seq=len(steps) + 1,
            description="Ergebnis zusammenfassen",
            kind="llm",
            target="response",
            depends_on=[s.seq for s in steps],
        )
    )
    return Plan(
        goal=goal,
        steps=steps,
        requires_confirmation=_announces_confirmation(usable, tools),
        fallback="Teilergebnis melden und benennen, welcher Schritt fehlt.",
    )


def _delegated_plan(classification: TurnClassification, goal: str, usable: list[str]) -> Plan:
    """Supervisor delegiert an einen Spezialisten.

    Der Agentenname ist ein Ziel, keine Fähigkeitszusage: Was der Sub-Agent
    tatsächlich darf, ergibt sich beim Aufruf aus der Schnittmenge seiner
    Whitelist mit den Nutzerrechten (docs/06-agenten-tools.md §5).
    """
    agent = "research" if classification.intent is Intent.RESEARCH else "general"
    return Plan(
        goal=goal,
        steps=[
            PlanStep(
                seq=1,
                description=f"An Sub-Agent „{agent}“ delegieren",
                kind="agent",
                target=agent,
            ),
            PlanStep(
                seq=2,
                description="Ergebnis prüfen und zusammenfassen",
                kind="llm",
                target="response",
                depends_on=[1],
            ),
        ],
        requires_confirmation=False,
        fallback="Ohne belastbares Ergebnis: Rückfrage statt Vermutung.",
    )


# --------------------------------------------------------------------------
# Hilfsmittel
# --------------------------------------------------------------------------


def _is_reading(tool_name: str) -> bool:
    return tool_name.endswith(_READING_SUFFIXES)


def _announces_confirmation(tool_names: list[str], tools: ToolLookup) -> bool:
    """Kündigt an, dass mindestens ein Schritt bestätigungspflichtig sein wird.

    Bewusst ohne Argumentkenntnis und deshalb bewusst unverbindlich: Die
    tatsächliche Entscheidung braucht die Argumente (ein Kalendereintrag *mit*
    Teilnehmern ist ein anderer Fall als einer ohne) und fällt in der Policy
    Engine. Hier geht es allein darum, dass die Oberfläche nicht überrascht.
    """
    for name in tool_names:
        spec = tools.get(name)
        if spec is not None and spec.risk >= RiskLevel.HIGH:
            return True
    return False
