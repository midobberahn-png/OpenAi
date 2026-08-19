"""Die Uhr des Systems.

Eine einzige Stelle, an der ``jetzt`` entsteht. Der Grund ist nicht Ordnung,
sondern Testbarkeit: Fristen, Budgets und Sitzungen hängen an der Zeit, und
eine Komponente, die selbst ``datetime.now()`` ruft, lässt sich nicht gegen
den Ablauf einer Frist prüfen — nur gegen das Warten darauf.

Alle Komponenten nehmen die Uhr deshalb als Parameter entgegen und fallen nur
hier zurück.
"""

from __future__ import annotations

from datetime import UTC, datetime

__all__ = ["utc_now"]


def utc_now() -> datetime:
    """Zeitzonenbewusst, immer. Ein naiver Zeitstempel im Vergleich mit einem
    aware ist ein ``TypeError`` — und zwar erst im Ablaufpfad, wo er am
    teuersten ist."""
    return datetime.now(tz=UTC)
