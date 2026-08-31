"""Sichtbaren Text aus HTML ziehen — ohne zusätzliche Abhängigkeit.

Lag bis heute privat in ``web.py``. Der Mail-Adapter braucht dasselbe: Eine
Nachricht ohne ``text/plain``-Teil ist HTML, und was ein Modell davon braucht,
ist der Fließtext.

**Zwei Leser, eine Fassung.** Die Alternative wäre gewesen, im Mail-Adapter
noch einmal dasselbe zu schreiben — und dann fällt ``script`` an einer der
beiden Stellen irgendwann nicht mehr heraus. Ausgerechnet dort: In einer Mail
steht der Text, der am ehesten wie eine Anweisung aussieht, nicht zufällig da.
"""

from __future__ import annotations

from html.parser import HTMLParser

__all__ = ["Textsammler", "text_aus_html"]


class Textsammler(HTMLParser):
    """Zieht Titel und sichtbaren Text aus HTML.

    Ohne zusätzliche Abhängigkeit, und ohne Anspruch auf Vollständigkeit: Was
    ein Modell braucht, ist der Fließtext, nicht das Markup. ``script`` und
    ``style`` fallen heraus — sie enthalten keinen Text für Menschen, und ihr
    Inhalt ist der, der am ehesten wie eine Anweisung aussieht.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.titel: list[str] = []
        self.stuecke: list[str] = []
        self._im_titel = False
        self._stumm = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._stumm += 1
        elif tag == "title":
            self._im_titel = True

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._stumm:
            self._stumm -= 1
        elif tag == "title":
            self._im_titel = False

    def handle_data(self, data: str) -> None:
        if self._stumm:
            return
        if self._im_titel:
            self.titel.append(data)
        elif data.strip():
            self.stuecke.append(data.strip())


def text_aus_html(html: str) -> tuple[str, str]:
    """Titel und Fließtext. Fehlt ein Titel, ist er die leere Zeichenkette."""
    sammler = Textsammler()
    sammler.feed(html)
    return " ".join("".join(sammler.titel).split()), "\n".join(sammler.stuecke)
