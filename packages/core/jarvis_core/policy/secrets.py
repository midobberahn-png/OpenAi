"""Datenklasse anheben, wenn ein Ergebnis nach Zugangsdaten aussieht.

**Was das ist — und vor allem, was es nicht ist.**

Das Projekt lehnt Erkennung als Schutzmechanismus ausdrücklich ab: Gegen
Prompt Injection hilft nicht, Angriffe zu *erkennen*, sondern sie folgenlos zu
machen (Taint-Tracking, Architekturentscheidung 1). Dieses Modul ist kein
Widerspruch dazu, weil es an einer anderen Stelle und in eine andere Richtung
arbeitet:

* Es **schützt nicht**. Der Schutz kommt weiterhin aus Taint und Datenklasse.
* Es **stuft nur hoch**, nie herab. Ein Treffer hebt die Klasse auf ``P3``;
  ohne Treffer bleibt alles, wie es war.

Daraus folgt die Fehlerrechnung, und sie ist der ganze Grund für dieses Modul:

    Falsch negativ → die Klasse bleibt, was sie ohnehin gewesen wäre.
                     Kein Verlust gegenüber dem Zustand ohne dieses Modul.
    Falsch positiv → der Inhalt bleibt lokal. Unbequem, nie gefährlich.

Ein Mechanismus, dessen Versagen den Ausgangszustand herstellt, darf
heuristisch sein. Ein Mechanismus, auf dem eine Zusicherung ruht, darf es
nicht — deshalb steht hier ``escalate`` und nirgends ein ``declassify``.

**Der Anlass.** OpenJarvis (Apache 2.0) erkennt PII und Geheimnisse per Regex
und leitet daraus ab, welche Werkzeuge Daten noch entgegennehmen dürfen —
Erkennung als tragende Prüfung, mit einer Sink-Policy, die für jedes nicht
eingetragene Werkzeug ``None`` liefert und damit fail open ist. Die Muster sind
brauchbar, die tragende Rolle ist es nicht. Übernommen ist deshalb die Idee,
nicht die Statik.

**Was P3 bedeutet.** ``DataClass.P3`` verlässt das Gerät nie (ADR-009, Model
Gateway). Findet sich in einer gelesenen Datei ein Private-Key-Header, geht ihr
Inhalt damit strukturell an kein Cloud-Modell mehr — unabhängig davon, was das
Werkzeug statisch deklariert hat.
"""

from __future__ import annotations

import re

from jarvis_contracts import DataClass, escalate

__all__ = ["SECRET_PATTERNS", "data_class_for_content", "looks_like_secret"]

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}"),
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(
        r"(?:password|passwort|secret|api[_-]?key|access[_-]?token|client[_-]?secret)"
        r"\s*[=:]\s*['\"]?\S{8,}",
        re.IGNORECASE,
    ),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:@/]+:[^\s:@/]+@", re.IGNORECASE),
)
"""Muster, die auf Zugangsdaten hindeuten.

Bewusst kurz gehalten und auf Formate beschränkt, die für sich sprechen:
Schlüsselheader, Anbieter-Token mit eindeutigem Präfix, JWT, Zugangsdaten in
einer URL. Ein Muster für „E-Mail-Adresse" oder „Telefonnummer" steht
absichtlich **nicht** hier — das wäre personenbezogen und damit P2, und eine
Heuristik, die jede Mailadresse auf P3 hebt, macht das lokale Modell zum
einzigen Gesprächspartner und die Stufe wertlos.
"""


def looks_like_secret(text: str) -> bool:
    """Enthält der Text etwas, das wie ein Zugangsdatum aussieht?"""
    return any(muster.search(text) for muster in SECRET_PATTERNS)


def data_class_for_content(text: str, *, declared: DataClass) -> DataClass:
    """Die Datenklasse eines Werkzeugergebnisses — mindestens die deklarierte.

    ``declared`` ist, was das Werkzeug für seinen Ergebnistyp angibt. Der
    Rückgabewert ist nie niedriger: Ein Werkzeug, das P2 liefert, liefert nach
    dieser Funktion P2 oder P3.
    """
    if looks_like_secret(text):
        return escalate(declared, DataClass.P3)
    return declared
