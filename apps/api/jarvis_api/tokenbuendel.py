"""Wie Zugriffs- und Erneuerungstoken in **einen** Geheimtext gehen.

Stand bis zum Refresh in ``routes/accounts.py`` — mit einem Leser war das
richtig. Jetzt gibt es zwei, und ein Format, das an zwei Stellen beschrieben
wird, ist eines, das an einer davon irgendwann anders aussieht.

**Beide Tokens in einem Datensatz und nicht in zweien.** Ein Zugriffstoken
ohne seinen Erneuerungstoken ist nach einer Stunde wertlos; zwei getrennte
Zeilen könnten auseinanderlaufen, und dann steht ein frischer Zugriff neben
einem Erneuerungstoken, der nicht mehr zu ihm gehört.

**Ein Trennzeichen und kein JSON.** Was hier hineingeht, sind zwei
undurchsichtige Zeichenketten des Anbieters, und ein Zeilenumbruch kommt in
keinem OAuth-Token vor: RFC 6749 §A.12 und §A.17 lassen nur druckbares ASCII
ohne Steuerzeichen zu. JSON wäre die Einladung, dem Bündel später Felder
hinzuzufügen — und dann liegt Struktur in einem Feld, das die Datenbank als
einen Blob führt und niemand durchsuchen kann.
"""

from __future__ import annotations

__all__ = ["buendeln", "zerlegen"]

TRENNER = b"\n"


def buendeln(access: str, refresh: str | None) -> bytes:
    """Beide Tokens in einen Klartext, bevor er versiegelt wird."""
    return access.encode() + TRENNER + (refresh or "").encode()


def zerlegen(klartext: bytes) -> tuple[str, str | None]:
    """Zurück in beide Tokens.

    ``maxsplit=1`` ist nicht Vorsicht, sondern nötig: Fügte ein Anbieter je
    einen Umbruch ein, zerschnitte ein unbegrenztes ``split`` den
    Erneuerungstoken still in der Mitte — und der Fehler zeigte sich erst beim
    nächsten Refresh, Stunden später, als „Zustimmung besteht nicht mehr".

    Ein leerer zweiter Teil wird zu ``None``: Es gibt keinen Erneuerungstoken
    der Länge null, und ``""`` als Wert weiterzureichen hieße, dem Anbieter
    einen leeren Token vorzulegen.
    """
    erster, _, zweiter = klartext.partition(TRENNER)
    return erster.decode(), zweiter.decode() or None
