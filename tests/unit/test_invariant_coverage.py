"""Security Invariant Coverage.

Die Leitkennzahl des Sicherheitskerns. Nicht „wie viele Zeilen sind
ausgeführt", sondern „welche Invariante ist belegt".

Dieser Test hält die Kennzahl ehrlich in beide Richtungen:

* Eine Invariante mit Status ``ENFORCED`` ohne Test schlägt fehl. Sonst ließe
  sich Sicherheit behaupten, ohne sie zu prüfen.
* Ein Test, der sich auf eine unbekannte Invariante beruft, schlägt fehl.
  Sonst driften Marker und Register auseinander und die Zählung wird wertlos.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from jarvis_core.policy.invariants import INVARIANTS, InvariantStatus, invariant_ids

REPO = Path(__file__).resolve().parents[2]


def _marked_invariants() -> dict[str, list[str]]:
    """Sammelt alle ``@pytest.mark.invariant("...")`` der Testsuite.

    Statische Analyse per AST statt Introspektion des laufenden Prozesses: So
    wird die *gesamte* Suite erfasst, auch wenn dieser Test einzeln aufgerufen
    wird — und der Marker muss nicht ausgeführt worden sein, um zu zählen.

    Ein erster Entwurf startete dafür pytest als Subprozess. Das lief in eine
    Endlosrekursion, weil der Subprozess dieses Modul importiert und damit die
    Sammlung erneut anstößt. Die AST-Variante hat das Problem nicht und ist
    zudem schneller.
    """
    found: dict[str, list[str]] = {}
    for path in sorted((REPO / "tests").rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Muster: pytest.mark.invariant("<id>")
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "invariant"
                and isinstance(func.value, ast.Attribute)
                and func.value.attr == "mark"
            ):
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        found.setdefault(arg.value, []).append(path.name)
    return found


MARKED = _marked_invariants()


def test_register_ist_widerspruchsfrei() -> None:
    assert len(INVARIANTS) == len(invariant_ids()), "Doppelte Kennungen im Register"
    for inv in INVARIANTS:
        assert inv.id.islower() and " " not in inv.id, f"Kennung {inv.id!r} nicht kebab-case"
        assert inv.statement.endswith("."), f"{inv.id}: Aussage ist kein vollständiger Satz"
        assert inv.why, f"{inv.id}: Ohne Folgenbeschreibung ist die Invariante nicht bewertbar"


@pytest.mark.parametrize(
    "inv",
    [i for i in INVARIANTS if i.status is InvariantStatus.ENFORCED],
    ids=lambda i: i.id,
)
def test_durchgesetzte_invariante_hat_einen_test(inv: object) -> None:
    """Was als durchgesetzt geführt wird, muss belegt sein."""
    assert isinstance(inv, type(INVARIANTS[0]))
    assert inv.id in MARKED, (
        f"Invariante {inv.id!r} ist als ENFORCED geführt, aber kein Test bindet sich "
        f'daran. Entweder Test ergänzen (@pytest.mark.invariant("{inv.id}")) oder '
        f"Status auf PLANNED zurücknehmen."
    )


def test_keine_marker_auf_unbekannte_invarianten() -> None:
    unknown = set(MARKED) - invariant_ids()
    assert not unknown, (
        f"Tests berufen sich auf unbekannte Invarianten: {sorted(unknown)}. "
        "Register und Marker sind auseinandergelaufen."
    )


def test_geplante_invarianten_sind_ausgewiesen() -> None:
    """Offene Punkte werden benannt, nicht verschwiegen.

    Dieser Test schlägt nie fehl — er dokumentiert den Stand in der Ausgabe,
    damit der offene Rest bei jedem Lauf sichtbar ist.
    """
    planned = [i.id for i in INVARIANTS if i.status is InvariantStatus.PLANNED]
    enforced = len(INVARIANTS) - len(planned)
    print(f"\nSecurity Invariant Coverage: {enforced}/{len(INVARIANTS)}")
    if planned:
        print("Noch offen: " + ", ".join(sorted(planned)))
