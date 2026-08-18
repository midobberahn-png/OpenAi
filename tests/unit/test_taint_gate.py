"""Taint-Sanitization-Gate.

Siehe docs/16-v1.1-review.md §1.

Diese Suite sichert die Auflösung des schwersten Befunds aus dem
Architektur-Review ab: V1.0 sperrte den häufigsten Alltagsablauf (Mails lesen,
daraus einen Termin anlegen) dauerhaft — ein Sicherheitsmechanismus, der den
Normalfall blockiert, wird abgeschaltet und ist damit wirkungslos.

Die Gegenprobe ist genauso wichtig: Das Gate darf den Schutz ergänzen, nicht
umgehen.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from jarvis_contracts import (
    DataClass,
    PayloadInspectability,
    RiskLevel,
    Run,
    RunStatus,
    SanitizedPayload,
    TaintGateOutcome,
    TaintLevel,
    ToolSpec,
)

pytestmark = pytest.mark.security


def _tool(**kw: object) -> ToolSpec:
    base: dict[str, object] = {
        "name": "t",
        "description": "Werkzeug für die Taint-Gate-Tests mit Beschreibung.",
        "parameters": {"type": "object", "properties": {}},
        "risk": RiskLevel.LOW,
    }
    base.update(kw)
    return ToolSpec(**base)  # type: ignore[arg-type]


class TestNormalfallBleibtBenutzbar:
    """Der Befund, der das Gate nötig machte."""

    @pytest.mark.invariant("taint-no-implicit-clearing")
    def test_kalendereintrag_nach_mail_lesen_ist_sanierbar(self) -> None:
        calendar_create = _tool(
            name="calendar.create",
            description="Legt einen Termin im verbundenen Kalender an.",
            risk=RiskLevel.MEDIUM,
            scopes=["calendar.create"],
            requires_preview=True,
            payload_inspectability=PayloadInspectability.STRUCTURED,
        )
        assert calendar_create.taint_gate(tainted=True) is TaintGateOutcome.SANITIZABLE

    def test_ohne_kontamination_laeuft_alles_normal(self) -> None:
        calendar_create = _tool(
            name="calendar.create",
            description="Legt einen Termin im verbundenen Kalender an.",
            risk=RiskLevel.MEDIUM,
            scopes=["calendar.create"],
            requires_preview=True,
            payload_inspectability=PayloadInspectability.STRUCTURED,
        )
        assert calendar_create.taint_gate(tainted=False) is TaintGateOutcome.PERMITTED

    def test_unbedenkliches_werkzeug_bleibt_immer_erlaubt(self) -> None:
        read = _tool(name="calendar.read", forbidden_when_tainted=False)
        assert read.taint_gate(tainted=True) is TaintGateOutcome.PERMITTED


class TestGateBleibtEng:
    """Gegenprobe: Das Gate darf den Schutz nicht aufweichen."""

    @pytest.mark.invariant("payload-freeform-never-sanitizable")
    def test_freitext_mit_aussenwirkung_ist_nie_sanierbar(self) -> None:
        """Eine um eine Ziffer veränderte IBAN im Fließtext übersieht auch ein
        aufmerksamer Leser. Bestätigung ist dort keine echte Prüfung."""
        send_mail = _tool(
            name="send_email",
            description="Sendet eine E-Mail über das verbundene Konto.",
            risk=RiskLevel.HIGH,
            scopes=["mail.send"],
            requires_preview=True,
            payload_inspectability=PayloadInspectability.FREEFORM,
        )
        assert send_mail.taint_gate(tainted=True) is TaintGateOutcome.BLOCKED

    def test_critical_ist_nie_sanierbar_auch_wenn_strukturiert(self) -> None:
        """Bei Irreversiblem wird Komfort nicht gegen Risiko abgewogen."""
        delete = _tool(
            name="files.delete",
            description="Löscht eine Datei endgültig vom Datenträger.",
            risk=RiskLevel.CRITICAL,
            scopes=["files.delete"],
            requires_preview=True,
            payload_inspectability=PayloadInspectability.STRUCTURED,
        )
        assert delete.taint_gate(tainted=True) is TaintGateOutcome.BLOCKED

    @pytest.mark.invariant("payload-freeform-never-sanitizable")
    def test_opaque_ist_nie_sanierbar(self) -> None:
        shell = _tool(
            name="shell.exec",
            description="Führt einen Shell-Befehl auf dem Rechner aus.",
            risk=RiskLevel.CRITICAL,
            scopes=["shell.exec"],
            requires_preview=True,
            payload_inspectability=PayloadInspectability.OPAQUE,
        )
        assert shell.taint_gate(tainted=True) is TaintGateOutcome.BLOCKED

    @pytest.mark.invariant("taint-no-implicit-clearing")
    def test_standard_ist_die_sichere_annahme(self) -> None:
        """Werkzeuge müssen sich ausdrücklich als prüfbar erklären."""
        assert _tool().payload_inspectability is PayloadInspectability.FREEFORM

    def test_structured_ohne_vorschau_ist_unzulaessig(self) -> None:
        """Sanierung ohne Vorschau wäre eine Bestätigung ohne Inhalt."""
        with pytest.raises(ValidationError, match="requires_preview"):
            _tool(
                name="calendar.create",
                description="Legt einen Termin im verbundenen Kalender an.",
                risk=RiskLevel.MEDIUM,
                scopes=["calendar.create"],
                payload_inspectability=PayloadInspectability.STRUCTURED,
            )


class TestPayloadInspectability:
    def test_nur_structured_hebt_kontamination_auf(self) -> None:
        assert PayloadInspectability.STRUCTURED.clearable_by_confirmation
        assert not PayloadInspectability.FREEFORM.clearable_by_confirmation
        assert not PayloadInspectability.OPAQUE.clearable_by_confirmation


class TestSanierterLauf:
    def _run(self, **kw: object) -> Run:
        base: dict[str, object] = {
            "id": uuid4(),
            "user_id": uuid4(),
            "trace_id": "abc",
            "started_at": datetime.now(UTC),
            "status": RunStatus.QUEUED,
            "data_class": DataClass.P2,
        }
        base.update(kw)
        return Run(**base)  # type: ignore[arg-type]

    @pytest.mark.invariant("taint-cross-run-isolation")
    def test_sanierter_lauf_muss_sauber_starten(self) -> None:
        """Sonst hebt das Gate die Sperre nicht auf, sondern umgeht sie."""
        with pytest.raises(ValidationError, match="umgeht"):
            self._run(
                sanitized_from_run_id=uuid4(),
                taint_level=TaintLevel.TAINTED,
            )

    def test_sanierter_lauf_kennt_seine_herkunft(self) -> None:
        origin = uuid4()
        run = self._run(sanitized_from_run_id=origin, taint_level=TaintLevel.CLEAN)
        assert run.sanitized_from_run_id == origin

    def test_normaler_lauf_hat_keine_herkunft(self) -> None:
        assert self._run().sanitized_from_run_id is None

    def test_payload_ist_eingefroren(self) -> None:
        payload = SanitizedPayload(
            tool_name="calendar.create",
            arguments={"title": "Angebot Projekt X", "start": "2026-08-19T14:00:00Z"},
            origin_run_id=uuid4(),
            approved_at=datetime.now(UTC),
            approved_by=uuid4(),
            payload_hash="a" * 64,
        )
        with pytest.raises(ValidationError):
            payload.tool_name = "send_email"  # type: ignore[misc]

    def test_payload_hash_hat_feste_laenge(self) -> None:
        """Der Executor prüft ihn vor der Ausführung erneut — ein zu kurzer
        Hash wäre ein stiller Ausfall dieser Prüfung."""
        with pytest.raises(ValidationError):
            SanitizedPayload(
                tool_name="x",
                arguments={},
                origin_run_id=uuid4(),
                approved_at=datetime.now(UTC),
                approved_by=uuid4(),
                payload_hash="zu-kurz",
            )
