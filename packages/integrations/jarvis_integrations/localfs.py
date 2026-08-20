"""Lesender Dateizugriff auf dem lokalen Dateisystem.

Erfüllt ``FileReader``. Die Zusage lautet: **Was hier herauskommt, liegt
innerhalb der konfigurierten Wurzeln** — und zwar nach Auflösung, nicht nach
Aussehen.

**Warum die Prüfung hier noch einmal stattfindet.** Die Policy Engine hat den
Pfad bereits gegen ``FilesConstraints.allowed_roots`` geprüft. Das ist keine
überflüssige Wiederholung, sondern eine andere Frage:

    Policy:  Darf dieser Nutzer diesen Pfad *nennen*?   (Zeichenkette)
    Adapter: Wohin zeigt er *wirklich*?                 (Dateisystem)

Ein Symlink in einem freigegebenen Ordner, der nach ``/etc`` zeigt, besteht die
erste Prüfung und muss an der zweiten scheitern. Die erste kann ihn
grundsätzlich nicht sehen — sie hat kein Dateisystem.

Beim Bau ist dabei ein Befund in der ersten Prüfung aufgefallen: Sie ließ
``..`` durch, weil ``PurePosixPath.relative_to()`` Segmente vergleicht, aber
nicht normalisiert. Behoben; die Lehre gehört trotzdem hierher: Eine
Pfadprüfung ohne Dateisystem kann nur streng und dumm sein. Alles, was klug
aussieht, ist eine Nachbildung — und weicht irgendwo ab.

**Die Reihenfolge ist die Absicherung.**

1. ``resolve()`` — Symlinks und ``..`` werden aufgelöst.
2. Vergleich gegen die ebenfalls aufgelösten Wurzeln.
3. Öffnen mit ``O_NOFOLLOW``.
4. ``fstat`` auf den offenen Deskriptor: reguläre Datei? gleiche Datei?
5. Erst dann lesen.

Schritt 3 und 4 schließen das Zeitfenster zwischen Auflösung und Öffnen. Ohne
sie ließe sich der letzte Pfadbestandteil nach der Prüfung gegen einen Symlink
tauschen — geprüft wäre dann die eine Datei und gelesen die andere. Vollständig
ausschließen lässt sich das mit dieser Bauart nicht (die Verzeichnisse auf dem
Weg bleiben veränderbar); wer es vollständig braucht, öffnet die Kette Segment
für Segment mit ``openat``. Das ist hier bewusst nicht getan, und deshalb steht
es da.
"""

from __future__ import annotations

import asyncio
import errno
import os
import stat
from collections.abc import Sequence
from pathlib import Path

from jarvis_core.ports.files import FileAccessDenied, FileContent, FileUnavailable

__all__ = ["LocalFileReader"]


class LocalFileReader:
    """Liest Textdateien — ausschließlich unterhalb der übergebenen Wurzeln."""

    def __init__(self, roots: Sequence[str | Path]) -> None:
        self._roots = tuple(Path(r).expanduser().resolve() for r in roots)
        """Einmal aufgelöst, beim Bau.

        Sonst verglichen wir einen aufgelösten Pfad gegen eine nicht
        aufgelöste Wurzel: Liegt die Wurzel selbst hinter einem Symlink — auf
        macOS ist ``/tmp`` genau das —, schlüge jeder Vergleich fehl, und der
        Fehler sähe wie ein Angriff aus.

        Leer ist zulässig und bedeutet: nichts ist lesbar. Das ist der richtige
        Vorgabewert für eine Freigabe, die niemand erteilt hat.
        """

    async def read_text(self, path: str, *, max_bytes: int) -> FileContent:
        # Dateizugriff blockiert; in einer Ereignisschleife gehört er in einen
        # Thread. Ohne das hielte eine einzige langsame Datei den ganzen
        # Prozess an — bei einem Netzlaufwerk keine theoretische Sorge.
        return await asyncio.to_thread(self._lesen, path, max_bytes)

    # -- Alles Weitere läuft im Thread ------------------------------------

    def _lesen(self, pfad: str, max_bytes: int) -> FileContent:
        angefragt = Path(pfad)
        if not angefragt.is_absolute():
            raise FileAccessDenied("Nur absolute Pfade werden gelesen.")

        try:
            aufgeloest = angefragt.resolve(strict=True)
        except FileNotFoundError as fehlt:
            raise FileUnavailable("Datei nicht gefunden.") from fehlt
        except OSError as fehler:  # pragma: no cover - z. B. Symlink-Schleife
            raise FileUnavailable(f"Pfad nicht auflösbar: {fehler.strerror}") from fehler

        if not self._innerhalb(aufgeloest):
            # Bewusst dieselbe Meldung wie bei einem Pfad, der von vornherein
            # außerhalb lag: Ob ein Symlink im Spiel war und wohin er zeigte,
            # ist eine Auskunft über das Dateisystem. Eine abgewiesene Anfrage
            # soll nichts verraten, was eine erlaubte nicht verrät.
            raise FileAccessDenied("Pfad liegt außerhalb der freigegebenen Ordner.")

        return self._oeffnen_und_lesen(aufgeloest, max_bytes)

    def _innerhalb(self, kandidat: Path) -> bool:
        for wurzel in self._roots:
            try:
                kandidat.relative_to(wurzel)
            except ValueError:
                continue
            return True
        return False

    def _oeffnen_und_lesen(self, pfad: Path, max_bytes: int) -> FileContent:
        # ``O_NOFOLLOW``: Der Pfad ist aufgelöst, sein letzter Bestandteil darf
        # also kein Symlink mehr sein. Ist er es doch, wurde er zwischen
        # Auflösung und Öffnen getauscht — genau der Fall, den diese Flagge
        # abfängt.
        # ``O_NONBLOCK`` ist hier kein Feinschliff, sondern notwendig, und der
        # Grund hat den ersten Testlauf zum Hängen gebracht: ``open()`` auf eine
        # FIFO **blockiert**, bis ein Schreiber erscheint. Die Prüfung auf eine
        # reguläre Datei steht aber notwendigerweise *nach* dem Öffnen — vorher
        # gäbe es nur ``lstat``, und zwischen ``lstat`` und ``open`` liegt genau
        # das Zeitfenster, das diese Bauart schließen soll.
        #
        # Also: nicht blockierend öffnen, dann fragen, was man da hat. Für
        # reguläre Dateien hat die Flagge keine Wirkung.
        try:
            deskriptor = os.open(pfad, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError as fehlt:
            raise FileUnavailable("Datei nicht gefunden.") from fehlt
        except OSError as fehler:
            if fehler.errno in {errno.ELOOP, errno.EMLINK}:
                # ``O_NOFOLLOW`` auf einem Symlink meldet ELOOP (BSD/macOS
                # gelegentlich EMLINK). Der Pfad war aufgelöst — ein Symlink an
                # dieser Stelle heißt, dass er inzwischen ausgetauscht wurde.
                raise FileAccessDenied("Pfad wurde während des Zugriffs verändert.") from fehler
            raise FileUnavailable(f"Datei nicht lesbar: {fehler.strerror}") from fehler

        try:
            zustand = os.fstat(deskriptor)
            if not stat.S_ISREG(zustand.st_mode):
                # Verzeichnisse, Geräte, FIFOs. ``/dev/zero`` zu lesen füllte
                # den Speicher, eine FIFO hinge bis zum Timeout — und ein
                # Verzeichnis ist schlicht kein Text.
                raise FileAccessDenied("Nur reguläre Dateien werden gelesen.")

            rohdaten = os.read(deskriptor, max_bytes + 1)
        finally:
            os.close(deskriptor)

        gekuerzt = len(rohdaten) > max_bytes
        if gekuerzt:
            rohdaten = rohdaten[:max_bytes]

        try:
            text = rohdaten.decode("utf-8")
        except UnicodeDecodeError as kein_text:
            # Beim Kürzen kann ein Mehrbyte-Zeichen zerschnitten worden sein.
            # Nur dann wird nachgesehen; sonst ist die Datei tatsächlich kein
            # UTF-8, und das ist eine Aussage, keine Panne.
            if not gekuerzt:
                raise FileUnavailable("Datei ist kein UTF-8-Text.") from kein_text
            text = rohdaten.decode("utf-8", errors="ignore")

        return FileContent(
            path=str(pfad),
            text=text,
            bytes_read=len(rohdaten),
            truncated=gekuerzt,
        )
