"""Port des Zählwerks hinter den Zugriffsgrenzen.

Eine einzige Methode, und ihre Anforderung ist die ganze Schwierigkeit:
``hit`` muss **atomar** zählen. Ein Ablauf der Form ``lesen → vergleichen →
schreiben`` ist bei gleichzeitigen Anfragen genau dort wirkungslos, wo ein
Rate-Limit gebraucht wird — unter Last.

Deshalb liefert die Methode den Zählerstand *nach* der Erhöhung zurück und
setzt die Frist im selben Schritt. Ein Aufrufer, der zuerst fragt und dann
zählt, kann das nicht richtig machen; ein Port, der das anbietet, lädt zum
Fehler ein.
"""

from __future__ import annotations

from typing import Protocol

__all__ = ["RateLimitStore"]


class RateLimitStore(Protocol):
    async def hit(self, key: str, *, window_s: int) -> tuple[int, int]:
        """Erhöht den Zähler und meldet ``(stand, verbleibende_sekunden)``.

        Beim ersten Treffer eines Fensters wird die Frist gesetzt — und zwar
        untrennbar mit der Erhöhung. Andernfalls entstünde ein Zähler ohne
        Ablauf: Er würde nie zurückgesetzt und sperrte den Schlüssel dauerhaft.

        Die verbleibende Zeit gehört mit in die Antwort, weil der Aufrufer sie
        dem Client nennen muss. Ein zweiter Aufruf dafür wäre ein zweiter
        Zeitpunkt und damit eine andere Antwort.
        """
        ...

    async def reset(self, key: str) -> None:
        """Setzt einen Zähler zurück. Nur für Tests und Wartung.

        Ausdrücklich **nicht** für „bei erfolgreicher Anmeldung zurücksetzen":
        Wer den Bucket eines fremden Schlüssels leeren kann, hebt das Limit
        für ihn auf.
        """
        ...
