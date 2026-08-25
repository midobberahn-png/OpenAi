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
from zoneinfo import ZoneInfo

__all__ = ["tagesbeginn", "utc_now"]


def utc_now() -> datetime:
    """Zeitzonenbewusst, immer. Ein naiver Zeitstempel im Vergleich mit einem
    aware ist ein ``TypeError`` — und zwar erst im Ablaufpfad, wo er am
    teuersten ist."""
    return datetime.now(tz=UTC)


def tagesbeginn(zeitzone: str, *, jetzt: datetime | None = None) -> datetime:
    """Beginn des laufenden Tages, als UTC-Zeitpunkt.

    **Ein Tagesbudget ohne Zeitzone ist keine Auskunft, sondern eine
    Vermutung.** Der UTC-Tag wäre die bequeme Wahl und die falsche: Er setzt
    das Budget mitten in der Nacht zurück — im Sommer um 02:00 Ortszeit —, und
    ein Nutzer, der um 01:00 nachsieht, bekäme den Verbrauch von „gestern"
    präsentiert, obwohl er noch am selben Abend sitzt.

    Zurück kommt trotzdem UTC: Die Datenbank vergleicht ``started_at`` gegen
    diesen Wert, und ein naiver Ortszeitstempel im Vergleich mit einem
    zeitzonenbewussten ist ein Fehler im ungünstigsten Moment.

    Eine unbekannte Zeitzone wirft — beim Start und nicht bei der ersten
    Abrechnung.
    """
    zone = ZoneInfo(zeitzone)
    ortszeit = (jetzt or utc_now()).astimezone(zone)
    beginn = ortszeit.replace(hour=0, minute=0, second=0, microsecond=0)
    return beginn.astimezone(UTC)
