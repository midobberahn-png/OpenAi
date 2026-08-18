"""Planung — was angekündigt wird, ist noch keine Erlaubnis.

Der Plan wird der Oberfläche vor der Ausführung gezeigt. Diese Suite prüft
deshalb zwei Dinge: dass die Ankündigung stimmt (Reihenfolge, Abhängigkeiten)
und dass sie nichts freischaltet.
"""

from __future__ import annotations

import pytest

from jarvis_contracts import Complexity, DataClass, Intent, TurnClassification
from jarvis_core.orchestrator import classify, plan_turn, select_mode
from tests.fakes import build_registry


def _classification(
    tools: list[str],
    *,
    intent: Intent = Intent.TASK,
    complexity: Complexity = Complexity.MODERATE,
    multi_step: bool = False,
) -> TurnClassification:
    return TurnClassification(
        intent=intent,
        complexity=complexity,
        data_class=DataClass.P2,
        likely_tools=tools,
        is_multi_step=multi_step,
    )


def _tools():
    registry, _ = build_registry()
    return registry


class TestModuswahl:
    def test_einfacher_turn_laeuft_direkt(self) -> None:
        assert (
            select_mode(_classification([], complexity=Complexity.SIMPLE), tool_count=0) == "direct"
        )

    def test_mehrere_werkzeuge_werden_geplant(self) -> None:
        assert select_mode(_classification([], multi_step=True), tool_count=2) == "planned"

    def test_recherche_wird_delegiert(self) -> None:
        """Spezialistenwissen und lange Ketten gehören an einen Sub-Agenten —
        auch, weil der Research Agent strukturell keine sendenden Werkzeuge
        führt (docs/06-agenten-tools.md)."""
        assert select_mode(_classification([], intent=Intent.RESEARCH), tool_count=1) == "delegated"


class TestPlanstruktur:
    def test_lesende_schritte_laufen_zuerst_und_unabhaengig(self) -> None:
        """„Mails prüfen“ und „Kalender prüfen“ hängen nicht voneinander ab.
        Zugleich ist das die Reihenfolge, in der Kontamination entsteht: erst
        lesen, dann schreiben."""
        plan = plan_turn(
            _classification(["mail.read", "calendar.read", "calendar.create"], multi_step=True),
            available_tools={"mail.read", "calendar.read", "calendar.create"},
            tools=_tools(),
        )
        reads = [s for s in plan.steps if s.target in {"mail.read", "calendar.read"}]
        write = next(s for s in plan.steps if s.target == "calendar.create")

        assert all(not s.depends_on for s in reads), "Lesende Schritte laufen parallel"
        assert {s.seq for s in reads} <= set(write.depends_on)

    def test_plan_enthaelt_nur_verfuegbare_werkzeuge(self) -> None:
        """``available_tools`` kommt aus ``PolicyEngine.effective_tools()``.
        Was dort fehlt, wird nicht angekündigt — sonst zeigte die Oberfläche
        einen Schritt an, der ohnehin blockiert würde."""
        plan = plan_turn(
            _classification(["mail.read", "mail.send"], multi_step=True),
            available_tools={"mail.read"},
            tools=_tools(),
        )
        assert {s.target for s in plan.steps if s.kind == "tool"} == {"mail.read"}

    def test_abhaengigkeiten_sind_gueltig(self) -> None:
        """``Plan`` validiert selbst, dass keine Abhängigkeit in die Zukunft
        zeigt — der Test hält fest, dass der Planer das auch bedient."""
        plan = plan_turn(
            _classification(["mail.read", "calendar.create"], multi_step=True),
            available_tools={"mail.read", "calendar.create"},
            tools=_tools(),
        )
        assert plan.ready_steps(completed=set())[0].seq == 1

    def test_bestaetigungspflicht_wird_angekuendigt(self) -> None:
        plan = plan_turn(
            _classification(["mail.read", "mail.send"], multi_step=True),
            available_tools={"mail.read", "mail.send"},
            tools=_tools(),
        )
        assert plan.requires_confirmation

    def test_ankuendigung_ist_keine_zusage(self) -> None:
        """``requires_confirmation`` entsteht ohne Argumentkenntnis. Ein
        Kalendereintrag *mit* Teilnehmern ist ein anderer Fall als einer ohne —
        entschieden wird das erst in der Policy Engine."""
        plan = plan_turn(
            _classification(["calendar.create"]),
            available_tools={"calendar.create"},
            tools=_tools(),
        )
        assert not plan.requires_confirmation


class TestZusammenspiel:
    def test_klassifikation_und_plan_passen_zusammen(self) -> None:
        """Der Ablauf aus dem Übergabedossier, bis zur Planung."""
        classification = classify("Prüfe meine Mails und blockier mir eine Stunde dafür")
        plan = plan_turn(
            classification,
            available_tools={"mail.read", "calendar.create", "calendar.read"},
            tools=_tools(),
        )
        targets = [s.target for s in plan.steps if s.kind == "tool"]
        assert "mail.read" in targets
        assert targets.index("mail.read") < targets.index("calendar.create")

    def test_ohne_verfuegbare_werkzeuge_bleibt_ein_modellschritt(self) -> None:
        """Kein Recht heißt nicht: kein Plan. Der Nutzer bekommt eine Antwort,
        in der die fehlende Berechtigung benannt wird."""
        plan = plan_turn(
            _classification(["mail.send"]),
            available_tools=set(),
            tools=_tools(),
        )
        assert [s.kind for s in plan.steps] == ["llm"]


@pytest.mark.security
@pytest.mark.invariant("orchestrator-consumes-decisions")
async def test_geplanter_schritt_ist_keine_berechtigung() -> None:
    """Der schärfere Fall: Ein Werkzeug steht im Plan, obwohl das Recht fehlt.

    Denkbar wird das, sobald ``available_tools`` aus einer veralteten
    Momentaufnahme stammt — zwischen Planung und Ausführung kann eine
    Berechtigung zurückgezogen worden sein. Der Plan trägt dann einen Schritt,
    den der Executor trotzdem nicht ausführt: Er fragt für jeden Schritt
    erneut.
    """
    from jarvis_core.orchestrator import BudgetTracker, ToolExecutor
    from jarvis_core.policy import ApprovalGateway, PolicyEngine, UnverifiedSessions
    from tests.fakes import SESSION, FakePermissions, InMemoryApprovalStore, build_run

    registry, spies = build_registry()
    plan = plan_turn(
        _classification(["mail.send"], multi_step=True),
        available_tools={"mail.send"},
        tools=registry,
    )
    step = next(s for s in plan.steps if s.kind == "tool")

    # Der Berechtigungsspeicher weiß nichts von mail.send.
    policy = PolicyEngine(registry, FakePermissions())
    executor = ToolExecutor(
        registry=registry,
        policy=policy,
        gateway=ApprovalGateway(InMemoryApprovalStore(), policy, sessions=UnverifiedSessions()),
    )
    outcome = await executor.execute_tool(
        build_run(),
        BudgetTracker(build_run().budget),
        tool_name=step.target,
        arguments={"to": ["x@y.de"], "body": "Text"},
        seq=step.seq,
        session_id=SESSION,
    )
    assert outcome.status == "blocked"
    assert spies["mail.send"].call_count == 0
