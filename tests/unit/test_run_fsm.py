"""Zustandsautomat und typisierter Laufzustand."""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import pairwise
from uuid import uuid4

import pytest
from pydantic import ValidationError

from jarvis_contracts import Correction, RunState, RunStatus, StepOutcome
from jarvis_core.runs import (
    TERMINAL,
    TRANSITIONS,
    IllegalTransition,
    assert_transition,
    can_transition,
    resumable_statuses,
)

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)


def _outcome(seq: int, ok: bool = True) -> StepOutcome:
    return StepOutcome(seq=seq, ok=ok, summary=f"Schritt {seq}", finished_at=NOW)


class TestUebergangstabelle:
    def test_jeder_zustand_ist_erfasst(self) -> None:
        """Ein fehlender Eintrag hieße: Der Automat kennt einen Zustand nicht,
        in dem ein Lauf tatsächlich stehen kann."""
        assert set(TRANSITIONS) == set(RunStatus)

    def test_endzustaende_haben_keine_ausgaenge(self) -> None:
        for status in TERMINAL:
            assert TRANSITIONS[status] == frozenset()
            assert status.is_terminal

    def test_terminal_und_is_terminal_stimmen_ueberein(self) -> None:
        """Zwei Definitionen derselben Sache müssen zusammengehalten werden —
        sonst driften sie."""
        assert frozenset(s for s in RunStatus if s.is_terminal) == TERMINAL

    def test_normaler_ablauf(self) -> None:
        pfad = [
            RunStatus.QUEUED,
            RunStatus.PLANNING,
            RunStatus.EXECUTING,
            RunStatus.VERIFYING,
            RunStatus.COMPLETED,
        ]
        for a, b in pairwise(pfad):
            assert can_transition(a, b), f"{a} → {b} sollte erlaubt sein"

    def test_bestaetigungsschleife(self) -> None:
        assert can_transition(RunStatus.EXECUTING, RunStatus.AWAITING_CONFIRMATION)
        assert can_transition(RunStatus.AWAITING_CONFIRMATION, RunStatus.EXECUTING)
        assert can_transition(RunStatus.AWAITING_CONFIRMATION, RunStatus.CANCELLED)

    def test_replan_nach_verifikation(self) -> None:
        assert can_transition(RunStatus.VERIFYING, RunStatus.PLANNING)

    def test_korrektur_fuehrt_zurueck_in_die_planung(self) -> None:
        assert can_transition(RunStatus.EXECUTING, RunStatus.INTERRUPTED)
        assert can_transition(RunStatus.INTERRUPTED, RunStatus.PLANNING)
        assert can_transition(RunStatus.INTERRUPTED, RunStatus.EXECUTING)

    @pytest.mark.parametrize(
        ("start", "ziel"),
        [
            (RunStatus.QUEUED, RunStatus.EXECUTING),  # Planung übersprungen
            (RunStatus.QUEUED, RunStatus.COMPLETED),  # nichts getan, fertig gemeldet
            (RunStatus.COMPLETED, RunStatus.EXECUTING),  # Endzustand wieder verlassen
            (RunStatus.CANCELLED, RunStatus.EXECUTING),
            (RunStatus.PLANNING, RunStatus.COMPLETED),  # ohne Ausführung fertig
            (RunStatus.AWAITING_CONFIRMATION, RunStatus.COMPLETED),  # ohne Bestätigung fertig
        ],
    )
    def test_unzulaessige_uebergaenge(self, start: RunStatus, ziel: RunStatus) -> None:
        assert not can_transition(start, ziel)
        with pytest.raises(IllegalTransition):
            assert_transition(start, ziel)

    def test_fehlermeldung_nennt_die_erlaubten_ziele(self) -> None:
        with pytest.raises(IllegalTransition, match="planning"):
            assert_transition(RunStatus.QUEUED, RunStatus.COMPLETED)

    def test_wiederaufnahme_deckt_sich_mit_dem_teilindex(self) -> None:
        """``ix_runs_resumable`` filtert auf genau diese vier Zustände. Weichen
        Code und Index voneinander ab, sucht der Worker über einen Index, der
        die gesuchten Zeilen nicht enthält."""
        assert resumable_statuses() == {
            RunStatus.QUEUED,
            RunStatus.PLANNING,
            RunStatus.EXECUTING,
            RunStatus.AWAITING_CONFIRMATION,
        }

    def test_unterbrochene_laeufe_werden_nicht_automatisch_fortgesetzt(self) -> None:
        """Ein unterbrochener Lauf wartet auf den Menschen, nicht auf den Worker."""
        assert RunStatus.INTERRUPTED not in resumable_statuses()


class TestRunState:
    def test_leerer_zustand_ist_gueltig(self) -> None:
        s = RunState()
        assert s.completed_seqs == set()
        assert s.replan_count == 0

    def test_schritt_abschliessen(self) -> None:
        s = RunState(current_step=1, claim_id=uuid4()).with_step_done(_outcome(1))
        assert s.completed_seqs == {1}
        assert s.current_step is None
        assert s.claim_id is None, "Der Anspruch fällt mit dem Schritt — sonst bliebe er stehen."

    def test_doppelter_schritt_ist_unzulaessig(self) -> None:
        with pytest.raises(ValidationError, match="zweimal"):
            RunState(completed_steps=[_outcome(1), _outcome(1)])

    def test_schritt_kann_nicht_laufend_und_fertig_sein(self) -> None:
        with pytest.raises(ValidationError, match="gleichzeitig"):
            RunState(completed_steps=[_outcome(1)], current_step=1, claim_id=uuid4())

    @pytest.mark.invariant("plan-step-claim-is-fenced")
    def test_ein_anspruch_ohne_inhaber_ist_nicht_darstellbar(self) -> None:
        """Seit die Freigabe die Kennung verlangt, wäre er unlösbar.

        Ein ``current_step`` ohne ``claim_id`` ließe sich nur noch durch eine
        bedingungslose Freigabe klären — und genau die gibt es nicht mehr, weil
        sie fremde Ansprüche träfe. Der Zustand wäre also für immer belegt.
        Statt ihn zu behandeln, ist er nicht darstellbar.
        """
        with pytest.raises(ValidationError, match="gemeinsam"):
            RunState(current_step=1)

    @pytest.mark.invariant("plan-step-claim-is-fenced")
    def test_ein_inhaber_ohne_anspruch_ist_nicht_darstellbar(self) -> None:
        """Die Gegenrichtung, damit die Kopplung in beide Richtungen gilt."""
        with pytest.raises(ValidationError, match="gemeinsam"):
            RunState(claim_id=uuid4())

    def test_korrektur_behaelt_unbetroffene_schritte(self) -> None:
        """Der Kern der Korrektursemantik: Ein Abbruch mit Neustart verwürfe
        alles und kostete die volle Latenz erneut."""
        s = RunState(completed_steps=[_outcome(1), _outcome(2), _outcome(3)])
        s2 = s.with_correction(
            Correction(text="Ich meinte unter 1.000 Euro.", at=NOW, invalidated_steps=[2, 3])
        )
        assert s2.completed_seqs == {1}
        assert len(s2.corrections) == 1
        assert s2.corrections[0].text.startswith("Ich meinte")

    def test_korrektur_ohne_betroffene_schritte_verwirft_nichts(self) -> None:
        s = RunState(completed_steps=[_outcome(1), _outcome(2)])
        s2 = s.with_correction(Correction(text="Ergänzung", at=NOW))
        assert s2.completed_seqs == {1, 2}

    def test_zustand_ist_unveraendert_nach_kopie(self) -> None:
        """Die Fortschreibung erzeugt neue Zustände, damit der alte fürs
        Aktivitätsprotokoll erhalten bleibt."""
        s = RunState(current_step=1, claim_id=uuid4())
        s.with_step_done(_outcome(1))
        assert s.current_step == 1

    def test_sanierter_payload_hash_wird_mitgefuehrt(self) -> None:
        s = RunState(sanitized_payload_hash="a" * 64)
        assert s.sanitized_payload_hash == "a" * 64

    def test_wartende_bestaetigung_wird_festgehalten(self) -> None:
        aid = uuid4()
        s = RunState(current_step=3, claim_id=uuid4(), awaiting_action_id=aid)
        assert s.awaiting_action_id == aid
