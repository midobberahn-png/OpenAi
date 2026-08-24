"""Der Arbeiter — und was ein Prozess ohne Sitzung nicht darf.

Zwei getrennte Zusagen stehen hier, und die erste ist die sicherheitsrelevante:

1. **Ohne Sitzung entsteht keine Bestätigung.** Eine Bestätigungsanfrage wird
   an die Sitzung gebunden, in der ihre Vorschau erschien. Eine ohne Sitzung
   könnte niemand einlösen — sie stünde in der Übersicht des Nutzers und ließe
   den Lauf endgültig stehen. Der Schritt bleibt stattdessen unerledigt und
   **wiederholbar**.
2. **Ein Durchgang übersteht einen kaputten Lauf.** Der Zweck dieses Arbeiters
   ist, dass Steckengebliebenes weitergeht; ein Durchgang, den der erste Fehler
   abbricht, ließe alle dahinter für immer liegen.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest

from jarvis_contracts import InvocationStatus, Run, RunStatus, ToolInvocation
from jarvis_core.orchestrator import AdvanceRejected, BudgetTracker, RunWorker, ToolExecutor
from jarvis_core.policy import ApprovalGateway, PolicyEngine, UnverifiedSessions
from tests.fakes import (
    NOW,
    SESSION,
    USER,
    FakePermissions,
    InMemoryApprovalStore,
    build_registry,
    build_run,
)

pytestmark = pytest.mark.asyncio

TERMIN = {
    "title": "Abstimmung",
    "start": "2026-09-01T10:00:00+00:00",
    "end": "2026-09-01T11:00:00+00:00",
}


class ProtokollAttrappe:
    def __init__(self) -> None:
        self.eintraege: list[ToolInvocation] = []
        self.markierungen: list[tuple[object, InvocationStatus, str | None]] = []

    async def record(self, invocation: ToolInvocation) -> None:
        self.eintraege.append(invocation)

    async def mark(
        self,
        invocation_id: object,
        status: InvocationStatus,
        *,
        error: str | None = None,
        undo_token: str | None = None,
    ) -> None:
        self.markierungen.append((invocation_id, status, error))

    async def load(self, invocation_id: UUID) -> ToolInvocation | None:
        return next((e for e in self.eintraege if e.id == invocation_id), None)

    async def for_run(self, run_id: UUID) -> list[ToolInvocation]:
        return [e for e in self.eintraege if e.run_id == run_id]

    async def for_step(self, run_id: UUID, step_seq: int) -> list[ToolInvocation]:
        return [e for e in self.eintraege if e.run_id == run_id and e.step_seq == step_seq]


def _executor(
    perms: FakePermissions,
) -> tuple[ToolExecutor, InMemoryApprovalStore, ProtokollAttrappe]:
    registry, _ = build_registry()
    policy = PolicyEngine(registry, perms)
    store = InMemoryApprovalStore()
    protokoll = ProtokollAttrappe()
    executor = ToolExecutor(
        registry=registry,
        policy=policy,
        gateway=ApprovalGateway(store, policy, sessions=UnverifiedSessions()),
        invocations=protokoll,
        clock=lambda: NOW,
    )
    return executor, store, protokoll


def _tracker() -> BudgetTracker:
    from jarvis_contracts import RunBudget

    return BudgetTracker(RunBudget(), clock=lambda: NOW)


class TestOhneSitzungKeineBestaetigung:
    """Die sicherheitsrelevante Hälfte dieses Blocks."""

    @pytest.mark.invariant("unattended-step-has-no-approval-channel")
    async def test_es_entsteht_keine_bestaetigung_die_niemand_einloesen_kann(self) -> None:
        executor, store, _ = _executor(FakePermissions().confirm("calendar.create"))

        ausgang = await executor.execute_tool(
            build_run(),
            _tracker(),
            tool_name="calendar.create",
            arguments=TERMIN,
            seq=1,
            session_id=None,
        )

        assert ausgang.status == "blocked"
        assert ausgang.code == "no-approval-channel"
        assert await store.open_for_user(USER) == [], (
            "Eine Bestätigung ohne Sitzung könnte niemand einlösen — sie stünde in der "
            "Übersicht des Nutzers und ließe den Lauf endgültig stehen."
        )

    @pytest.mark.invariant("unattended-step-has-no-approval-channel")
    async def test_der_lauf_wartet_nicht_auf_etwas_das_nicht_kommt(self) -> None:
        """``awaiting_confirmation`` hieße „es wartet eine Bestätigung"."""
        executor, _, _ = _executor(FakePermissions().confirm("calendar.create"))

        ausgang = await executor.execute_tool(
            build_run(),
            _tracker(),
            tool_name="calendar.create",
            arguments=TERMIN,
            seq=1,
            session_id=None,
        )

        assert ausgang.run.status is RunStatus.EXECUTING
        assert ausgang.run.state.awaiting_action_id is None
        assert ausgang.pending is None

    @pytest.mark.invariant("unattended-step-has-no-approval-channel")
    async def test_der_protokolleintrag_ist_wiederholbar(self) -> None:
        """``BLOCKED`` und nicht ``FAILED`` — und das ist der ganze Zweck.

        Der Nutzer soll denselben Schritt später mit einer Sitzung anstoßen
        können, und die Wiederaufnahme soll ihn nicht für „möglicherweise
        gewirkt" halten.
        """
        executor, _, protokoll = _executor(FakePermissions().confirm("calendar.create"))

        await executor.execute_tool(
            build_run(),
            _tracker(),
            tool_name="calendar.create",
            arguments=TERMIN,
            seq=1,
            session_id=None,
            plan_step_seq=1,
        )

        assert len(protokoll.markierungen) == 1
        _, status, _ = protokoll.markierungen[0]
        assert status is InvocationStatus.BLOCKED
        assert status.may_retry, "Sonst hielte die Wiederaufnahme den Schritt für gewirkt."

    async def test_mit_sitzung_entsteht_die_bestaetigung_weiterhin(self) -> None:
        """Die Gegenprobe: Der Kanal fehlt nur, wenn keine Sitzung da ist."""
        executor, store, _ = _executor(FakePermissions().confirm("calendar.create"))

        ausgang = await executor.execute_tool(
            build_run(),
            _tracker(),
            tool_name="calendar.create",
            arguments=TERMIN,
            seq=1,
            session_id=SESSION,
        )

        assert ausgang.status == "awaiting_confirmation"
        assert ausgang.pending is not None
        assert len(await store.open_for_user(USER)) == 1


class LaufSpeicherAttrappe:
    def __init__(self, laeufe: list[Run]) -> None:
        self.laeufe = laeufe
        self.abfragen: list[tuple[timedelta, int]] = []

    async def stale_runs(self, *, frist: timedelta, limit: int = 20) -> list[Run]:
        self.abfragen.append((frist, limit))
        return self.laeufe


class AblaufAttrappe:
    """Zählt Aufrufe und liefert, was der Test vorgibt."""

    def __init__(self, ausgang: Any) -> None:
        self.ausgang = ausgang
        self.aufrufe: list[tuple[UUID, UUID | None]] = []

    async def advance(self, lauf: Run, *, session_id: UUID | None, vorgegeben: Any) -> Any:
        self.aufrufe.append((lauf.id, session_id))
        if isinstance(self.ausgang, BaseException):
            raise self.ausgang
        return self.ausgang


class _Ausgang:
    def __init__(self, status: str, reason: str = "") -> None:
        self.status = status
        self.reason = reason


def _worker(laeufe: list[Run], ausgang: Any) -> tuple[RunWorker, list[AblaufAttrappe]]:
    ablaeufe: list[AblaufAttrappe] = []

    @asynccontextmanager
    async def fabrik(lauf: Run) -> AsyncIterator[Any]:
        ablauf = AblaufAttrappe(ausgang)
        ablaeufe.append(ablauf)
        yield ablauf

    speicher = LaufSpeicherAttrappe(laeufe)
    return RunWorker(runs=speicher, advancer_for=fabrik), ablaeufe  # type: ignore[arg-type]


class TestDurchgang:
    async def test_der_arbeiter_uebergibt_keine_sitzung(self) -> None:
        """Nicht eine erfundene, sondern **keine** — der Typ trägt die Zusage."""
        lauf = build_run(status=RunStatus.EXECUTING)
        arbeiter, ablaeufe = _worker([lauf], _Ausgang("executed"))

        await arbeiter.sweep()

        assert ablaeufe[0].aufrufe == [(lauf.id, None)]

    async def test_ein_kaputter_lauf_beendet_den_durchgang_nicht(self) -> None:
        """Sonst lägen alle dahinter für immer."""
        laeufe = [build_run(status=RunStatus.EXECUTING) for _ in range(3)]
        arbeiter, ablaeufe = _worker(laeufe, RuntimeError("Datenbank weg"))

        bericht = await arbeiter.sweep()

        assert bericht.gefunden == 3
        assert bericht.fortgesetzt == 0
        assert len(ablaeufe) == 3, "Jeder Lauf wurde versucht."
        assert all(e.outcome == "error" for e in bericht.ergebnisse)

    async def test_eine_abweisung_wird_mit_ihrer_kennung_gemeldet(self) -> None:
        """„3 von 5 fortgesetzt" beantwortet die Frage nicht, die man dann stellt."""
        lauf = build_run(status=RunStatus.EXECUTING)
        arbeiter, _ = _worker([lauf], AdvanceRejected("step-unresolved", "Möglicherweise gewirkt."))

        bericht = await arbeiter.sweep()

        assert bericht.ergebnisse[0].outcome == "step-unresolved"
        assert bericht.liegen_geblieben == 1

    async def test_die_frist_geht_an_die_suche(self) -> None:
        arbeiter, _ = _worker([], _Ausgang("executed"))
        arbeiter._lease = timedelta(minutes=7)

        await arbeiter.sweep()

        speicher = arbeiter._runs
        assert speicher.abfragen == [(timedelta(minutes=7), 20)]  # type: ignore[attr-defined]

    async def test_ein_leerer_durchgang_ist_kein_fehler(self) -> None:
        arbeiter, ablaeufe = _worker([], _Ausgang("executed"))

        bericht = await arbeiter.sweep()

        assert bericht.gefunden == 0 and bericht.ergebnisse == [] and ablaeufe == []
