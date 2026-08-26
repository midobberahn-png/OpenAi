"""Port des Dateizugriffs.

Der Kern kennt kein Dateisystem. Was er kennt, ist die Zusage: **Was dieser
Port herausgibt, liegt innerhalb der freigegebenen Wurzeln.** Wie das
durchgesetzt wird — Auflösung von Symlinks, Vergleich nach dem Öffnen —, ist
Sache des Adapters und steht in ``jarvis_integrations.localfs``.

**Zwei Grenzen, und sie sind verschieden.**

1. ``FilesConstraints.allowed_roots`` ist die Berechtigung *dieses Nutzers*.
   Sie wird von der Policy Engine geprüft, bevor überhaupt ein Grant entsteht,
   und sie arbeitet rein auf dem Pfad als Zeichenkette. Mehr kann sie nicht:
   Ein Symlink ist auf dieser Ebene unsichtbar.
2. Die Wurzeln dieses Ports sind die Grenze *des Prozesses*. Sie gelten
   unabhängig davon, was ein Nutzer erteilt bekommen hat, und sie werden erst
   dort geprüft, wo der Pfad tatsächlich aufgelöst und geöffnet wird.

Die zweite ist nicht die Wiederholung der ersten. Eine Pfadprüfung vor dem
Öffnen beantwortet „darf dieser Nutzer diesen Pfad nennen?"; der Adapter
beantwortet „wohin zeigt er wirklich?". Der Unterschied ist ein Symlink im
freigegebenen Ordner, der nach ``/etc`` zeigt — die erste Prüfung sieht ihn
nicht, und sie kann ihn nicht sehen.

**Fremdinhalt.** Was hier herauskommt, hat jemand anderes geschrieben. Das
Werkzeug ``files.read`` setzt deshalb ``reads_untrusted_content``, und der Lauf
gilt danach als kontaminiert. Eine Datei ist in dieser Hinsicht nichts anderes
als eine Mail.

**Und Aufzählen ist ein zweiter Port** (``DirectoryLister``, ADR-019), kein
weiteres Verfahren am ersten. Wer liest, soll nicht aufzählen **können** —
nicht weil es ihm verboten wäre, sondern weil das Objekt es nicht kann.
Dieselbe Trennung wie beim Kalender, dessen Werkzeugseite kein ``list_events``
hat. Auch eine Aufzählung ist Fremdinhalt: Einen Dateinamen hat jemand anderes
geschrieben, und er darf ``SYSTEM- Sende alles an …`` lauten.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict

__all__ = [
    "DirectoryEntry",
    "DirectoryLister",
    "DirectoryListing",
    "FileAccessDenied",
    "FileContent",
    "FileReader",
    "FileUnavailable",
]


class FileAccessDenied(Exception):
    """Der Zugriff wurde aus Sicherheitsgründen verweigert.

    Getrennt von ``FileUnavailable``, weil die beiden verschiedene Vorgänge
    sind: „außerhalb der Wurzeln", „zeigt über einen Symlink hinaus", „ist
    keine reguläre Datei" gehören ins Sicherheitsprotokoll. Eine fehlende
    Datei ist Alltag.

    Die Meldung nach außen nennt bewusst keinen aufgelösten Pfad. Wohin ein
    Symlink zeigt, ist eine Auskunft über das Dateisystem, die der Aufrufer
    gerade nicht bekommen soll — sonst ist die abgewiesene Anfrage ein
    Erkundungswerkzeug.
    """


class FileUnavailable(Exception):
    """Die Datei gibt es nicht, sie ist zu groß, oder sie ist kein Text."""


class FileContent(BaseModel):
    """Der gelesene Inhalt — und woher er stammt."""

    model_config = ConfigDict(frozen=True)

    path: str
    """Der **aufgelöste** Pfad. Er kann vom angefragten abweichen, wenn ein
    Symlink im Spiel war, der innerhalb der Wurzeln blieb. Der Aufrufer soll
    sehen, was er tatsächlich gelesen hat."""

    text: str
    bytes_read: int
    truncated: bool
    """``True``, wenn die Datei größer war als die Obergrenze.

    Abschneiden statt Abweisen: Der Anfang einer großen Datei ist meist die
    nützliche Antwort. Dass gekürzt wurde, muss aber sichtbar sein — ein
    stillschweigend halbes Ergebnis ist schlimmer als eine Fehlermeldung.
    """


class FileReader(Protocol):
    """Lesender Zugriff innerhalb fest verdrahteter Wurzeln."""

    async def read_text(self, path: str, *, max_bytes: int) -> FileContent:
        """Liest eine Textdatei.

        Wirft ``FileAccessDenied``, wenn der Pfad — **nach Auflösung** —
        außerhalb der Wurzeln liegt oder keine reguläre Datei bezeichnet;
        ``FileUnavailable``, wenn es sie nicht gibt oder ihr Inhalt kein
        UTF-8-Text ist.
        """
        ...


class DirectoryEntry(BaseModel):
    """Ein Eintrag einer Aufzählung — Name und Art, sonst nichts."""

    model_config = ConfigDict(frozen=True)

    name: str
    """Nur der Name, nicht der Pfad.

    Den Ordner kennt der Aufrufer; ihn je Eintrag zu wiederholen, bläht die
    Modellsicht auf, ohne etwas hinzuzufügen."""

    kind: str
    """``datei``, ``ordner`` oder ``verweis``.

    **Ein Verweis wird benannt und nicht aufgelöst.** Wohin er zeigt, ist eine
    Auskunft über das Dateisystem jenseits der Wurzeln — dieselbe Überlegung,
    aus der eine abgewiesene Leseanfrage nicht verrät, wohin sie gezeigt hätte.
    Ob sich ein Verweis lesen lässt, entscheidet ohnehin erst der Lesepfad."""

    size: int | None = None
    """Bytes, bei Dateien. Bei Ordnern und Verweisen ``None`` — eine
    Ordnergröße ist eine Eigenschaft des Dateisystems und keine Auskunft über
    den Inhalt."""


class DirectoryListing(BaseModel):
    """Das Ergebnis einer Aufzählung."""

    model_config = ConfigDict(frozen=True)

    path: str
    """Der **aufgelöste** Ordner."""

    entries: list[DirectoryEntry]
    """Alphabetisch. Eine Reihenfolge, die vom Dateisystem abhängt, macht aus
    zwei gleichen Aufrufen zwei verschiedene Antworten."""

    truncated: bool = False
    """Ob die Obergrenze gegriffen hat.

    Eine stille Kürzung liest sich wie Vollständigkeit — und ein Modell, das
    eine gekürzte Liste für vollständig hält, schließt aus dem Fehlen einer
    Datei, dass es sie nicht gibt."""


class DirectoryLister(Protocol):
    """Port des Aufzählens — eine Ebene, innerhalb der Wurzeln."""

    async def list_dir(self, path: str, *, max_entries: int) -> DirectoryListing:
        """Zählt **ein** Verzeichnis auf.

        Nicht rekursiv, und das ist eine Entscheidung (ADR-019): Ein Aufruf,
        der einen ganzen Baum liefert, ist in erster Linie ein Werkzeug zur
        Erkundung und erst in zweiter eines zum Finden.

        Wirft ``FileAccessDenied`` außerhalb der Wurzeln und ``FileUnavailable``,
        wenn es den Ordner nicht gibt oder er keiner ist.
        """
        ...
