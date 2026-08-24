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

    @pytest.mark.invariant("hung-step-is-reassigned-only-when-provably-idle")
    def test_ein_anspruch_ohne_frist_bleibt_darstellbar(self) -> None:
        """Der Altbestand aus der Zeit vor der Frist muss ladbar bleiben.

        Ihn zurückzuweisen hieße, genau den Lauf zu verlieren, den eine
        Wiederaufnahme braucht. Übernommen wird er trotzdem nicht — dafür
        sorgt die Bedingung in ``reclaim_step``, nicht dieser Vertrag.
        """
        s = RunState(current_step=1, claim_id=uuid4())
        assert s.claimed_at is None

    @pytest.mark.invariant("hung-step-is-reassigned-only-when-provably-idle")
    def test_eine_frist_ohne_anspruch_faellt_weg_statt_zu_scheitern(self) -> None:
        """Die einzige Stelle dieser Prüfung, an der nicht laut gescheitert wird.

        Der Fall entsteht im Rollout: Eine ältere Prozessversion gibt einen
        Anspruch frei, ohne das Feld zu kennen, und lässt die Frist stehen. Ein
        ``ValidationError`` machte den Lauf dann **unladbar** — im
        schlechtestmöglichen Moment. Gemessen an einem echten Testfall, der
        genau so scheiterte, bevor diese Zeile stand.

        Eine Frist ohne Anspruch ist dagegen bedeutungslos: Übernommen wird
        nur, wo eine ``claim_id`` steht.
        """
        s = RunState(claimed_at=datetime(2026, 8, 24, 12, tzinfo=UTC))
        assert s.claimed_at is None

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


class TestZustandsuebergaengeErhaltenIhreInvarianten:
    """Jede Fortschreibung muss einen **neu validierbaren** Zustand erzeugen.

    **Herkunft: externer Prüfbericht, und der Befund war real.**
    ``with_correction()`` setzte ``current_step=None`` und ließ ``claim_id``
    stehen — einen Zustand, den der eigene Validator ausdrücklich verbietet.
    Aufgefallen ist das niemandem, weil ``model_copy(update=...)`` **nicht
    erneut validiert**: Das Objekt entsteht, die Prüfung greift erst beim
    nächsten Laden aus der Datenbank.

    Das ist die gefährlichere Sorte Fehler. Er entsteht beim Schreiben und
    schlägt beim Lesen zu — also nach einem Neustart, im schlechtestmöglichen
    Moment, und genau dann, wenn eine Wiederaufnahme den Lauf braucht.

    Diese Klasse prüft deshalb nicht einen Fall, sondern **jede** Methode, die
    einen neuen Zustand erzeugt. Wer eine weitere ergänzt, ergänzt hier eine
    Zeile — und merkt sofort, wenn sie eine Invariante bricht.
    """

    @staticmethod
    def _neu_validierbar(zustand: RunState) -> RunState:
        """Der Kern: durch ``model_dump()`` und zurück, wie nach einem Neustart."""
        return RunState.model_validate(zustand.model_dump(mode="json"))

    def test_frischer_zustand(self) -> None:
        self._neu_validierbar(RunState())

    def test_nach_abgeschlossenem_schritt(self) -> None:
        beansprucht = RunState(current_step=1, claim_id=uuid4())
        self._neu_validierbar(beansprucht.with_step_done(_outcome(1)))

    def test_nach_einer_korrektur_ohne_laufenden_schritt(self) -> None:
        zustand = RunState(completed_steps=[_outcome(1), _outcome(2)])
        korrigiert = zustand.with_correction(
            Correction(text="Ich meinte unter 1.000 Euro.", at=NOW, invalidated_steps=[2])
        )
        self._neu_validierbar(korrigiert)

    @pytest.mark.invariant("plan-step-claim-is-fenced")
    def test_nach_einer_korrektur_mit_laufendem_schritt(self) -> None:
        """**Der gemeldete Fall.**

        Vorher entstand hier ``current_step=None`` bei stehender ``claim_id``.
        """
        beansprucht = RunState(completed_steps=[_outcome(1)], current_step=2, claim_id=uuid4())
        korrigiert = beansprucht.with_correction(
            Correction(text="Doch nicht Dienstag.", at=NOW, invalidated_steps=[1])
        )
        self._neu_validierbar(korrigiert)


class TestKorrekturLaesstDenAnspruchInRuhe:
    """Was eine Korrektur mit einem **laufenden** Schritt macht: nichts.

    Die naheliegende Reparatur wäre gewesen, in ``with_correction`` auch
    ``claim_id=None`` zu setzen. Sie wäre intern konsistent und fachlich
    falsch: Ein Wertobjekt im Arbeitsspeicher eines Aufrufers kann einen
    Arbeiter nicht anhalten, der gerade ein Werkzeug ausführt. Es könnte ihm
    nur den Anspruch unter den Füßen wegziehen — und damit denselben doppelten
    Seiteneffekt öffnen, gegen den der Anspruch gebaut wurde.

    Eine Korrektur wird deshalb **vermerkt** und hebt keinen Anspruch auf. Wer
    einen laufenden Schritt tatsächlich abbrechen will, braucht einen
    gefencten Übergang mit der Anspruchskennung — und den gibt es noch nicht.
    Solange er fehlt, ist „vermerken und weiterlaufen lassen" die einzige
    Antwort, die nichts kaputt macht.
    """

    def test_der_laufende_schritt_bleibt_beansprucht(self) -> None:
        kennung = uuid4()
        beansprucht = RunState(current_step=2, claim_id=kennung)
        korrigiert = beansprucht.with_correction(Correction(text="Anders.", at=NOW))
        assert korrigiert.current_step == 2
        assert korrigiert.claim_id == kennung

    def test_die_korrektur_wird_trotzdem_vermerkt(self) -> None:
        """Sonst ginge sie verloren, und der Nutzer hätte umsonst korrigiert."""
        beansprucht = RunState(current_step=2, claim_id=uuid4())
        korrigiert = beansprucht.with_correction(Correction(text="Anders.", at=NOW))
        assert len(korrigiert.corrections) == 1
        assert korrigiert.corrections[0].text == "Anders."

    def test_erledigte_schritte_fallen_weiterhin_weg(self) -> None:
        """Der eigentliche Zweck der Korrektur bleibt unberührt."""
        beansprucht = RunState(
            completed_steps=[_outcome(1), _outcome(2)], current_step=3, claim_id=uuid4()
        )
        korrigiert = beansprucht.with_correction(
            Correction(text="Anders.", at=NOW, invalidated_steps=[2])
        )
        assert korrigiert.completed_seqs == {1}
