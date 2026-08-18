"""Läufe, Budgets, Pläne, Gedächtnis."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest
from pydantic import ValidationError

from jarvis_contracts import (
    BUDGET_PRESETS,
    Capability,
    DataClass,
    MemoryCandidate,
    MemoryKind,
    MemoryRecord,
    MemoryStatus,
    ModelCapability,
    Plan,
    PlanStep,
    Provenance,
    RetrievalWeights,
    RunBudget,
    RunStatus,
    RunTrigger,
    SourceType,
    Usage,
)


class TestRunStatus:
    def test_terminale_zustaende(self) -> None:
        assert RunStatus.COMPLETED.is_terminal
        assert RunStatus.FAILED.is_terminal
        assert not RunStatus.EXECUTING.is_terminal

    def test_wiederaufnehmbare_zustaende(self) -> None:
        """Der Worker sucht beim Neustart genau diese Läufe."""
        assert RunStatus.AWAITING_CONFIRMATION.is_resumable
        assert RunStatus.EXECUTING.is_resumable
        assert not RunStatus.COMPLETED.is_resumable


class TestRunTrigger:
    def test_nur_nutzer_ist_beaufsichtigt(self) -> None:
        assert RunTrigger.USER.is_supervised
        assert not RunTrigger.SCHEDULE.is_supervised
        assert not RunTrigger.WEBHOOK.is_supervised


class TestBudget:
    def test_sprachbudget_ist_enger_als_textbudget(self) -> None:
        assert BUDGET_PRESETS["voice"].max_tokens < BUDGET_PRESETS["text"].max_tokens
        assert BUDGET_PRESETS["voice"].max_seconds < BUDGET_PRESETS["text"].max_seconds

    def test_ueberschreitung_wird_benannt(self) -> None:
        u = Usage(tokens_in=19_000, tokens_out=2_000)
        msg = u.exceeds(BUDGET_PRESETS["voice"])
        assert msg is not None and "Token" in msg

    def test_kostengrenze(self) -> None:
        u = Usage(cost_eur=Decimal("0.06"))
        assert u.exceeds(BUDGET_PRESETS["voice"]) is not None

    def test_innerhalb_des_budgets(self) -> None:
        assert Usage(tokens_in=100, tokens_out=50).exceeds(BUDGET_PRESETS["text"]) is None

    def test_verbrauch_addiert_sich(self) -> None:
        a = Usage(tokens_in=100, cost_eur=Decimal("0.01"), elapsed_s=2.0)
        b = Usage(tokens_in=50, cost_eur=Decimal("0.02"), elapsed_s=3.0)
        m = a.merge(b)
        assert m.tokens_in == 150
        assert m.cost_eur == Decimal("0.03")
        assert m.elapsed_s == 3.0  # Zeit läuft parallel, nicht kumulativ

    def test_teilung_unterschreitet_nie_null(self) -> None:
        sub = RunBudget(max_tokens=1, max_steps=1, max_tool_calls=1).split(10)
        assert sub.max_tokens >= 1
        assert sub.max_steps >= 1


class TestPlan:
    def test_abhaengigkeit_auf_spaeteren_schritt_ist_unzulaessig(self) -> None:
        with pytest.raises(ValidationError, match="hängt von"):
            Plan(
                goal="x",
                steps=[
                    PlanStep(seq=1, description="a", kind="tool", target="t", depends_on=[2]),
                    PlanStep(seq=2, description="b", kind="tool", target="t"),
                ],
            )

    def test_doppelte_schrittnummer(self) -> None:
        with pytest.raises(ValidationError, match="Doppelte"):
            Plan(
                goal="x",
                steps=[
                    PlanStep(seq=1, description="a", kind="tool", target="t"),
                    PlanStep(seq=1, description="b", kind="tool", target="t"),
                ],
            )

    def test_parallelisierbare_schritte(self) -> None:
        """'Mails prüfen' und 'Kalender prüfen' laufen gleichzeitig."""
        plan = Plan(
            goal="Tagesüberblick",
            steps=[
                PlanStep(seq=1, description="Mails prüfen", kind="agent", target="mail"),
                PlanStep(seq=2, description="Kalender prüfen", kind="agent", target="calendar"),
                PlanStep(
                    seq=3, description="Zusammenfassen", kind="llm", target="-", depends_on=[1, 2]
                ),
            ],
        )
        ready = plan.ready_steps(completed=set())
        assert {s.seq for s in ready} == {1, 2}

        ready = plan.ready_steps(completed={1})
        assert {s.seq for s in ready} == {2}

        ready = plan.ready_steps(completed={1, 2})
        assert {s.seq for s in ready} == {3}


class TestModelCapability:
    def _model(self, **kw: object) -> ModelCapability:
        base: dict[str, object] = {
            "name": "test",
            "provider": "test",
            "max_data_class": DataClass.P1,
            "context_window": 128_000,
        }
        base.update(kw)
        return ModelCapability(**base)  # type: ignore[arg-type]

    def test_datenklasse_ist_hartes_filter(self) -> None:
        cloud = self._model(max_data_class=DataClass.P1)
        assert cloud.accepts(DataClass.P0)
        assert cloud.accepts(DataClass.P1)
        assert not cloud.accepts(DataClass.P2)
        assert not cloud.accepts(DataClass.P3)

    def test_lokales_modell_nimmt_alles(self) -> None:
        local = self._model(max_data_class=DataClass.P3, is_local=True)
        for dc in DataClass:
            assert local.accepts(dc)

    def test_faehigkeitsfilter(self) -> None:
        m = self._model(supports_vision=False)
        assert m.supports([Capability.TOOL_CALLING])
        assert not m.supports([Capability.VISION])

    def test_langkontext_verlangt_grosses_fenster(self) -> None:
        assert not self._model(context_window=128_000).supports([Capability.LONG_CONTEXT])
        assert self._model(context_window=400_000).supports([Capability.LONG_CONTEXT])


class TestMemory:
    def _prov(self, st: SourceType = SourceType.USER_STATED) -> Provenance:
        return Provenance(source_type=st)

    def test_ausdrueckliche_aussage_wird_automatisch_uebernommen(self) -> None:
        c = MemoryCandidate(
            content="Nenn mich Mirek.",
            kind=MemoryKind.PREFERENCE,
            provenance=self._prov(SourceType.USER_STATED),
            confidence=0.98,
        )
        assert c.auto_acceptable()

    def test_abgeleitetes_geht_in_die_queue(self) -> None:
        """Vermutungen dürfen sich nicht unbemerkt verfestigen."""
        c = MemoryCandidate(
            content="Bevorzugt Meetings vormittags.",
            kind=MemoryKind.PREFERENCE,
            provenance=self._prov(SourceType.INFERRED),
            confidence=0.99,
        )
        assert not c.auto_acceptable()

    def test_widerspruch_verhindert_automatik(self) -> None:
        c = MemoryCandidate(
            content="Arbeitet ab 10 Uhr.",
            kind=MemoryKind.PREFERENCE,
            provenance=self._prov(SourceType.USER_STATED),
            confidence=1.0,
            conflicts_with=[uuid4()],
        )
        assert not c.auto_acceptable()

    def test_niedrige_konfidenz_geht_in_die_queue(self) -> None:
        c = MemoryCandidate(
            content="Heißt vielleicht Mirek.",
            kind=MemoryKind.PREFERENCE,
            provenance=self._prov(SourceType.USER_STATED),
            confidence=0.5,
        )
        assert not c.auto_acceptable()

    def test_ersetzter_eintrag_muss_nachfolger_nennen(self) -> None:
        with pytest.raises(ValidationError, match="Nachfolger"):
            MemoryRecord(
                id=uuid4(),
                user_id=uuid4(),
                kind=MemoryKind.PREFERENCE,
                content="alt",
                provenance=self._prov(),
                status=MemoryStatus.SUPERSEDED,
                valid_from=datetime.now(UTC),
            )

    def test_nur_aktive_eintraege_gelten(self) -> None:
        now = datetime.now(UTC)
        r = MemoryRecord(
            id=uuid4(),
            user_id=uuid4(),
            kind=MemoryKind.PREFERENCE,
            content="x",
            provenance=self._prov(),
            status=MemoryStatus.CANDIDATE,
            valid_from=now,
        )
        assert not r.is_valid_at(now)

    def test_abgelaufener_fakt_gilt_nicht_mehr(self) -> None:
        now = datetime.now(UTC)
        r = MemoryRecord(
            id=uuid4(),
            user_id=uuid4(),
            kind=MemoryKind.SEMANTIC_FACT,
            content="Projekt X läuft.",
            provenance=self._prov(),
            status=MemoryStatus.ACTIVE,
            valid_from=now - timedelta(days=10),
            valid_until=now - timedelta(days=1),
        )
        assert not r.is_valid_at(now)

    def test_provenienz_ist_beantwortbar(self) -> None:
        assert "gesagt" in Provenance(source_type=SourceType.USER_STATED).describe()
        assert "abgeleitet" in Provenance(source_type=SourceType.INFERRED).describe()


class TestRetrievalWeights:
    def test_gewichte_muessen_sich_zu_eins_summieren(self) -> None:
        with pytest.raises(ValidationError, match=r"1\.0"):
            RetrievalWeights(semantic=0.9, keyword=0.9, recency=0.1, importance=0.1)

    def test_standardgewichte_sind_gueltig(self) -> None:
        w = RetrievalWeights()
        assert abs(w.semantic + w.keyword + w.recency + w.importance - 1.0) < 1e-6
