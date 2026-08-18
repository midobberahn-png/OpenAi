"""Bausteine des Approval Gateways ohne Datenbank.

Hash-Bildung und die Absicherung des Ausführungs-Grants sind reine Logik —
sie gehören nicht in die Integrationssuite, die eine laufende Datenbank
voraussetzt.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from jarvis_core.policy.approval import ExecutionGrant, canonical_arguments, payload_hash

pytestmark = pytest.mark.security

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)


class TestPayloadHash:
    @pytest.mark.invariant("approval-bound-to-payload-hash")
    def test_reihenfolge_der_argumente_ist_irrelevant(self) -> None:
        """Sonst schlüge der Vergleich vor der Ausführung zufällig fehl — und
        ein Sicherheitsvergleich, der gelegentlich falsch Alarm gibt, wird
        abgeschaltet."""
        assert payload_hash("calendar.create", {"b": 2, "a": 1}) == payload_hash(
            "calendar.create", {"a": 1, "b": 2}
        )

    @pytest.mark.invariant("approval-bound-to-payload-hash")
    def test_werkzeugname_geht_in_den_hash_ein(self) -> None:
        """Sonst ließe sich eine Bestätigung mit identischen Argumenten auf ein
        anderes Werkzeug übertragen."""
        args = {"title": "x"}
        assert payload_hash("calendar.create", args) != payload_hash("tasks.create", args)

    @pytest.mark.invariant("payload-immutable-after-approval")
    def test_kleinste_aenderung_aendert_den_hash(self) -> None:
        base = {"start": "2026-08-19T14:00:00Z"}
        changed = {"start": "2026-08-19T04:00:00Z"}
        assert payload_hash("calendar.create", base) != payload_hash("calendar.create", changed)

    def test_hash_hat_immer_64_hexzeichen(self) -> None:
        h = payload_hash("x", {"a": [1, 2, {"b": None}]})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_kanonisierung_ist_deterministisch(self) -> None:
        args = {"z": 1, "a": {"y": 2, "b": 3}}
        assert canonical_arguments(args) == canonical_arguments(dict(reversed(args.items())))

    def test_umlaute_bleiben_erhalten(self) -> None:
        assert "Empfänger".encode() in canonical_arguments({"an": "Empfänger"})


class TestExecutionGrant:
    @pytest.mark.invariant("policy-single-entry-point")
    def test_grant_laesst_sich_nicht_selbst_bauen(self) -> None:
        """Ein selbst gebauter Grant wäre die Umgehung des Ausführungs-Gates.

        Python kann das nicht vollständig verhindern; der Wächter macht es
        unbequem und sichtbar, die eigentliche Absicherung ist der AST-Test in
        test_layering.py.
        """
        with pytest.raises(RuntimeError, match="ApprovalGateway"):
            ExecutionGrant(
                tool_name="calendar.create",
                arguments={},
                verified_hash="a" * 64,
                run_id=uuid.uuid4(),
                user_id=uuid.uuid4(),
                invocation_id=uuid.uuid4(),
                granted_at=NOW,
            )

    @pytest.mark.invariant("policy-single-entry-point")
    def test_model_construct_ist_gesperrt(self) -> None:
        """Der bequemste Weg am Wächter vorbei.

        ``model_construct`` ist Pydantics Schnellpfad und ruft ``__init__``
        nicht auf — der Sentinel liefe ins Leere. Ein Wächter, an dem eine
        dokumentierte Methode vorbeiführt, erzeugt Vertrauen, das er nicht
        trägt.
        """
        with pytest.raises(RuntimeError, match="model_construct"):
            ExecutionGrant.model_construct(
                tool_name="mail.send",
                arguments={},
                verified_hash="a" * 64,
                run_id=uuid.uuid4(),
                user_id=uuid.uuid4(),
                invocation_id=uuid.uuid4(),
                granted_at=NOW,
            )
