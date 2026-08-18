"""Datenklassifikation und Taint.

Die Tests in dieser Datei sichern die Eigenschaft ab, von der das gesamte
Routing abhängt: Klassen sind geordnet, und Kontamination ist monoton.
"""

from __future__ import annotations

import pytest

from jarvis_contracts import DataClass, TaintLevel, escalate


class TestDataClass:
    def test_ordnung_ist_bedeutungstragend(self) -> None:
        assert DataClass.P0 < DataClass.P1 < DataClass.P2 < DataClass.P3
        assert DataClass.P3 > DataClass.P0
        assert DataClass.P2 >= DataClass.P2

    def test_stufen(self) -> None:
        assert DataClass.P0.level == 0
        assert DataClass.P3.level == 3
        assert DataClass.from_level(2) is DataClass.P2

    def test_p3_erlaubt_keine_cloud(self) -> None:
        assert not DataClass.P3.cloud_allowed
        for lower in (DataClass.P0, DataClass.P1, DataClass.P2):
            assert lower.cloud_allowed

    def test_vergleich_mit_string_scheitert_laut(self) -> None:
        """DataClass erbt von str; ohne ausdrücklichen TypeError verglich
        Python lexikografisch statt über die Stufe. Hier fällt das zufällig
        gleich aus — verlassen darf man sich darauf nicht."""
        with pytest.raises(TypeError, match="DataClass"):
            _ = DataClass.P0 < "P1"  # type: ignore[operator]
        with pytest.raises(TypeError):
            _ = DataClass.P3 >= 2  # type: ignore[operator]

    @pytest.mark.parametrize(
        ("inputs", "expected"),
        [
            ((), DataClass.P0),
            ((DataClass.P0,), DataClass.P0),
            ((DataClass.P0, DataClass.P2), DataClass.P2),
            ((DataClass.P3, DataClass.P0), DataClass.P3),
            ((DataClass.P1, DataClass.P1), DataClass.P1),
        ],
    )
    def test_ableitung_erbt_hoechste_stufe(
        self, inputs: tuple[DataClass, ...], expected: DataClass
    ) -> None:
        assert escalate(*inputs) is expected


class TestTaintLevel:
    def test_kontamination_ist_monoton(self) -> None:
        clean = TaintLevel.CLEAN
        assert clean.merge(TaintLevel.CLEAN) is TaintLevel.CLEAN
        tainted = clean.merge(TaintLevel.TAINTED)
        assert tainted is TaintLevel.TAINTED

    def test_kontamination_laesst_sich_nicht_entfernen(self) -> None:
        """Kein Werkzeug darf einen Lauf 'säubern' — das wäre der Ausweg,
        über den ein Angreifer die Sperre umginge."""
        tainted = TaintLevel.TAINTED
        assert tainted.merge(TaintLevel.CLEAN) is TaintLevel.TAINTED
        assert tainted.merge(TaintLevel.TAINTED) is TaintLevel.TAINTED

    def test_is_tainted(self) -> None:
        assert TaintLevel.TAINTED.is_tainted
        assert not TaintLevel.CLEAN.is_tainted
