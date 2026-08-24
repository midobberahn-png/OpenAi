"""Das Urteil über einen hängenden Schritt.

Ein Lauf in ``executing`` mit belegtem ``current_step`` ist entweder gerade in
Arbeit oder hängengeblieben, und von außen sind die beiden nicht zu
unterscheiden. Die Wiederaufnahme löst das nicht durch Nachdenken, sondern
durch zwei Nachschlagewerke: die **Frist** (``claimed_at``) und das
**Werkzeugprotokoll**.

Hier steht die Entscheidungstabelle. Die Frist selbst wird nicht in Python
gemessen — sie steht in der ``WHERE``-Klausel von ``reclaim_step`` und wird
deshalb im Integrationstest gegen eine echte Datenbank geprüft. Was hier
gemessen wird, ist die andere Hälfte: *Schließt das Protokoll eine Wirkung
aus?*

Die unbequeme Zeile der Tabelle ist ``EFFECT_UNKNOWN``. Sie bedeutet nicht
„gescheitert", sondern „niemand weiß es" — und für die Frage „darf ich das
wiederholen?" ist das der Unterschied zwischen *ja* und *auf keinen Fall*.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest

from jarvis_contracts import (
    InvocationStatus,
    Plan,
    PlanStep,
    PolicyEffect,
    RiskLevel,
    Run,
    RunStatus,
    ToolInvocation,
)
from jarvis_core.orchestrator import Recovery, RecoveryVerdict, ist_haengend
from jarvis_core.orchestrator.budget import utc_now
from jarvis_core.tools.builtin.files import FILES_READ
from tests.fakes import build_registry, build_run

pytestmark = pytest.mark.asyncio


async def _nie_gerufen(**kwargs: Any) -> Any:  # pragma: no cover
    raise AssertionError("Die Wiederaufnahme führt kein Werkzeug aus — sie urteilt nur.")


class ProtokollAttrappe:
    """Nur die Lesehälfte — die Wiederaufnahme schreibt nichts."""

    def __init__(self, eintraege: list[ToolInvocation] | None = None) -> None:
        self.eintraege = eintraege or []
        self.abfragen: list[tuple[UUID, int]] = []

    async def for_step(self, run_id: UUID, step_seq: int) -> list[ToolInvocation]:
        self.abfragen.append((run_id, step_seq))
        return [e for e in self.eintraege if e.run_id == run_id and e.step_seq == step_seq]

    async def for_run(self, run_id: UUID) -> list[ToolInvocation]:
        return [e for e in self.eintraege if e.run_id == run_id]

    async def load(self, invocation_id: UUID) -> ToolInvocation | None:
        return next((e for e in self.eintraege if e.id == invocation_id), None)

    async def record(self, invocation: ToolInvocation) -> None:  # pragma: no cover
        raise AssertionError("Die Wiederaufnahme protokolliert nicht.")

    async def mark(self, invocation_id: object, status: Any, **kw: Any) -> None:
        raise AssertionError("Die Wiederaufnahme schreibt keinen Ausgang fort.")


class LaufSpeicherAttrappe:
    """Zählt Übernahmen und lässt sie gelingen oder scheitern.

    Die Frist ist hier ein Schalter und keine Rechnung: Ob sie abgelaufen ist,
    entscheidet in der Anwendung die Datenbank in derselben Anweisung, die
    übernimmt. Ein Nachbau davon in Python würde eine andere Uhr messen und
    damit etwas anderes prüfen, als in Betrieb gilt.
    """

    def __init__(self, *, uebernahme_gelingt: bool = True) -> None:
        self.uebernahme_gelingt = uebernahme_gelingt
        self.uebernahmen: list[tuple[UUID, int, timedelta]] = []

    async def reclaim_step(
        self, run_id: UUID, seq: int, *, erwarteter_status: RunStatus, frist: timedelta
    ) -> UUID | None:
        self.uebernahmen.append((run_id, seq, frist))
        return uuid.uuid4() if self.uebernahme_gelingt else None


def _lauf_mit_anspruch(*, seq: int = 1, mit_frist: bool = True, werkzeug: str = "mail.send") -> Run:
    lauf = build_run(status=RunStatus.EXECUTING)
    plan = Plan(
        goal="Ein Schritt",
        steps=[PlanStep(seq=seq, kind="tool", target=werkzeug, description="Schritt")],
    )
    zustand = lauf.state.model_copy(
        update={
            "current_step": seq,
            "claim_id": uuid.uuid4(),
            "claimed_at": utc_now() - timedelta(hours=1) if mit_frist else None,
        }
    )
    return lauf.model_copy(update={"plan": plan, "state": zustand})


def _eintrag(
    lauf: Run, seq: int, status: InvocationStatus, *, tool: str = "mail.send"
) -> ToolInvocation:
    return ToolInvocation(
        id=uuid.uuid4(),
        run_id=lauf.id,
        step_seq=seq,
        tool_name=tool,
        arguments={},
        risk_level=RiskLevel.MEDIUM,
        policy_decision=PolicyEffect.ALLOW,
        decision_reason="Test",
        status=status,
        created_at=utc_now(),
    )


def _recovery(
    lauf: Run, eintraege: list[ToolInvocation], **kw: Any
) -> tuple[Recovery, LaufSpeicherAttrappe]:
    registry, _ = build_registry()
    speicher = LaufSpeicherAttrappe(**kw)
    return (
        Recovery(runs=speicher, invocations=ProtokollAttrappe(eintraege), tools=registry),  # type: ignore[arg-type]
        speicher,
    )


class TestOhneAnspruch:
    async def test_ein_freier_lauf_hat_nichts_wiederaufzunehmen(self) -> None:
        lauf = build_run(status=RunStatus.EXECUTING)
        recovery, _ = _recovery(lauf, [])

        urteil = await recovery.assess(lauf)

        assert urteil.verdict is RecoveryVerdict.NICHT_BEANSPRUCHT
        assert urteil.seq is None
        assert not ist_haengend(lauf)

    async def test_take_over_uebernimmt_nichts_ohne_anspruch(self) -> None:
        lauf = build_run(status=RunStatus.EXECUTING)
        recovery, speicher = _recovery(lauf, [])

        await recovery.take_over(lauf)

        assert speicher.uebernahmen == [], "Ohne offenen Anspruch gibt es nichts zu übernehmen."


class TestProtokollEntscheidet:
    """Die eigentliche Entscheidungstabelle."""

    async def test_kein_eintrag_heisst_nachweislich_nichts_geschehen(self) -> None:
        lauf = _lauf_mit_anspruch()
        recovery, _ = _recovery(lauf, [])

        urteil = await recovery.assess(lauf)

        assert urteil.verdict is RecoveryVerdict.NEU_VERGEBBAR
        assert urteil.seq == 1

    @pytest.mark.parametrize("status", [InvocationStatus.BLOCKED, InvocationStatus.REJECTED])
    async def test_folgenlos_abgewiesen_darf_neu_vergeben_werden(
        self, status: InvocationStatus
    ) -> None:
        """Und die Quelle dieser Zusage ist der Vertrag, nicht dieses Modul."""
        lauf = _lauf_mit_anspruch()
        recovery, _ = _recovery(lauf, [_eintrag(lauf, 1, status)])

        urteil = await recovery.assess(lauf)

        assert status.may_retry, "Die Zusage steht am Vertrag — hier wird sie nur gelesen."
        assert urteil.verdict is RecoveryVerdict.NEU_VERGEBBAR

    @pytest.mark.parametrize(
        "status",
        [
            InvocationStatus.EFFECT_UNKNOWN,
            InvocationStatus.EXECUTED,
            InvocationStatus.FAILED,
            InvocationStatus.PENDING,
            InvocationStatus.APPROVED,
        ],
    )
    async def test_moegliche_wirkung_wird_nicht_automatisch_wiederholt(
        self, status: InvocationStatus
    ) -> None:
        """Die fünf Zustände, bei denen niemand blind wiederholen darf.

        ``PENDING`` und ``APPROVED`` sind dabei die stillsten und die
        wichtigsten: Sie stehen für einen Aufruf, der **gerade** unterwegs ist.
        Der Protokolleintrag entsteht vor dem Handler — ein Arbeiter, der
        genau jetzt im Kalender schreibt, sieht von außen so aus.
        """
        lauf = _lauf_mit_anspruch()
        recovery, speicher = _recovery(lauf, [_eintrag(lauf, 1, status)])

        urteil = await recovery.take_over(lauf)

        assert urteil.verdict is RecoveryVerdict.ENTSCHEIDUNG_NOETIG
        assert speicher.uebernahmen == [], "Wo eine Wirkung möglich ist, wird nicht übernommen."
        assert str(status) in urteil.reason

    async def test_idempotentes_werkzeug_darf_auch_bei_unklarer_wirkung(self) -> None:
        """``ToolSpec.idempotent`` ist die Erlaubnis, ein zweites Mal zu rufen.

        Sie steht am Werkzeug und nicht am Protokolleintrag — sie ist eine
        Eigenschaft des Werkzeugs und keine dieses Aufrufs.
        """
        lauf = _lauf_mit_anspruch(werkzeug="files.read")
        registry, _ = build_registry()
        registry.register(FILES_READ, _nie_gerufen)
        assert FILES_READ.idempotent, "Lesen darf zweimal geschehen …"
        assert not registry.require("mail.send").idempotent, "… Senden nicht."

        speicher = LaufSpeicherAttrappe()
        protokoll = ProtokollAttrappe(
            [_eintrag(lauf, 1, InvocationStatus.EFFECT_UNKNOWN, tool="files.read")]
        )
        recovery = Recovery(runs=speicher, invocations=protokoll, tools=registry)  # type: ignore[arg-type]
        urteil = await recovery.take_over(lauf)

        assert urteil.verdict is RecoveryVerdict.NEU_VERGEBBAR
        assert speicher.uebernahmen, "Ein idempotentes Werkzeug darf erneut laufen."

    async def test_eintrag_eines_anderen_schrittes_zaehlt_nicht(self) -> None:
        """Der Anker ist ``(run_id, step_seq)`` — nicht der Lauf allein."""
        lauf = _lauf_mit_anspruch(seq=1)
        recovery, _ = _recovery(lauf, [_eintrag(lauf, 2, InvocationStatus.EXECUTED)])

        urteil = await recovery.assess(lauf)

        assert urteil.verdict is RecoveryVerdict.NEU_VERGEBBAR


class TestFrist:
    async def test_anspruch_ohne_frist_wird_nicht_automatisch_uebernommen(self) -> None:
        """Altbestand: ``claimed_at`` fehlt.

        „Keine Angabe" als „lange her" zu lesen hieße, mitten in einem Rollout
        den Schritt eines gerade arbeitenden Prozesses zu übernehmen.
        """
        lauf = _lauf_mit_anspruch(mit_frist=False)
        recovery, speicher = _recovery(lauf, [])

        urteil = await recovery.take_over(lauf)

        assert urteil.verdict is RecoveryVerdict.ENTSCHEIDUNG_NOETIG
        assert speicher.uebernahmen == []
        assert "ohne Frist" in urteil.reason

    async def test_die_frist_wird_der_datenbank_uebergeben_und_nicht_gerechnet(self) -> None:
        lauf = _lauf_mit_anspruch()
        recovery, speicher = _recovery(lauf, [])
        recovery._lease = timedelta(minutes=42)

        await recovery.take_over(lauf)

        assert speicher.uebernahmen == [(lauf.id, 1, timedelta(minutes=42))]

    async def test_verlorenes_wettrennen_heisst_in_arbeit(self) -> None:
        """Zwei Übernehmer, einer gewinnt — für den anderen ist der Schritt in Arbeit."""
        lauf = _lauf_mit_anspruch()
        recovery, _ = _recovery(lauf, [], uebernahme_gelingt=False)

        urteil = await recovery.take_over(lauf)

        assert urteil.verdict is RecoveryVerdict.IN_ARBEIT
        assert urteil.claim_id is None


class TestNachDerUebernahme:
    async def test_es_wird_erneut_nachgesehen(self) -> None:
        """Zwischen Urteil und Übernahme vergeht Zeit — und in ihr kann der alte
        Arbeiter den Handler betreten haben.

        Sein Protokolleintrag steht dann bereits, weil er **vor** der Wirkung
        geschrieben wird. Ohne die zweite Abfrage beriefe sich die Übernahme
        auf eine Momentaufnahme, die zum Zeitpunkt der Wirkung veraltet war —
        dasselbe ``load() … entscheiden … schreiben``, gegen das an vier
        anderen Stellen dieses Projekts ein bedingtes ``UPDATE`` steht.
        """
        lauf = _lauf_mit_anspruch()
        protokoll = ProtokollAttrappe([])
        speicher = LaufSpeicherAttrappe()
        registry, _ = build_registry()
        recovery = Recovery(runs=speicher, invocations=protokoll, tools=registry)  # type: ignore[arg-type]

        # Der alte Arbeiter meldet sich genau zwischen Urteil und Übernahme.
        original = speicher.reclaim_step

        async def dazwischen(*args: Any, **kw: Any) -> UUID | None:
            protokoll.eintraege.append(_eintrag(lauf, 1, InvocationStatus.EFFECT_UNKNOWN))
            return await original(*args, **kw)

        speicher.reclaim_step = dazwischen  # type: ignore[method-assign]

        urteil = await recovery.take_over(lauf)

        assert urteil.verdict is RecoveryVerdict.ENTSCHEIDUNG_NOETIG
        assert urteil.claim_id is not None, (
            "Der Anspruch bleibt beim Übernehmer. Ihn freizugeben öffnete den Schritt "
            "für den nächsten Anwärter, während unklar ist, ob er schon gewirkt hat."
        )
        assert len(protokoll.abfragen) == 2, "Vor der Übernahme und danach."
