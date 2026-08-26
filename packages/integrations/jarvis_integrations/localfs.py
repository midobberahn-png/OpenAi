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

from jarvis_contracts import is_sensitive_filename
from jarvis_core.ports.files import (
    DirectoryEntry,
    DirectoryListing,
    FileAccessDenied,
    FileContent,
    FileUnavailable,
)

__all__ = ["LocalDirectoryLister", "LocalFileReader", "WurzelGrenze"]


class WurzelGrenze:
    """Die Wurzeln und die Frage, ob ein aufgelöster Pfad in ihnen liegt.

    Gemeinsame Grundlage von Lesen und Aufzählen — und ausdrücklich **keine**
    gemeinsame Klasse für beides: ``LocalFileReader`` und
    ``LocalDirectoryLister`` erben von hier, bleiben aber getrennte Objekte.
    Wer liest, soll nicht aufzählen können (ADR-019). Geteilt wird die Grenze,
    nicht die Fähigkeit.
    """

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

    def _innerhalb(self, kandidat: Path) -> bool:
        for wurzel in self._roots:
            try:
                kandidat.relative_to(wurzel)
            except ValueError:
                continue
            return True
        return False

    def _wurzel_von(self, kandidat: Path) -> Path | None:
        """Welche Wurzel diesen Pfad enthält — oder ``None``."""
        for wurzel in self._roots:
            try:
                kandidat.relative_to(wurzel)
            except ValueError:
                continue
            return wurzel
        return None

    def _segmentweise_oeffnen(self, angefragt: Path) -> tuple[int, Path]:
        """Öffnet ein Verzeichnis **Segment für Segment**, ab der Wurzel.

        **Warum nicht wie beim Lesen.** Dort wird der Pfad aufgelöst, gegen die
        Wurzeln geprüft und anschließend als ganzer Pfad geöffnet — und der
        Modulkopf sagt seit jeher, was daran offen bleibt: ``O_NOFOLLOW``
        schützt nur den **letzten** Bestandteil; die Verzeichnisse auf dem Weg
        dorthin bleiben zwischen Prüfung und Öffnen veränderbar. Wer eine
        übergeordnete Komponente gegen einen Verweis tauscht, führt das Öffnen
        woandershin. Ein externes Review hat genau das für die Aufzählung
        aufgeschrieben.

        Hier ist es geschlossen: Jedes Segment wird **relativ zum offenen
        Vorgänger** geöffnet (``dir_fd``), jedes mit ``O_NOFOLLOW``. Zwischen
        zwei Schritten gibt es keinen Pfad mehr, den jemand umdeuten könnte —
        nur noch einen Deskriptor, der auf ein bestimmtes Verzeichnis zeigt.

        **Und damit folgt dieser Weg keinem Verweis, auch keinem, der innerhalb
        der Wurzeln bliebe.** Das ist für eine Aufzählung die richtige Strenge:
        Sie meldet Verweise ohnehin als Verweise, statt sie aufzulösen (ADR-019)
        — wer einen Ordner aufzählen will, nennt seinen Pfad und nicht einen
        Verweis darauf. Für den *Lesepfad* wäre dieselbe Strenge eine
        Verhaltensänderung: Dort ist ein Verweis innerhalb der Wurzeln
        ausdrücklich erlaubt.

        Gibt den Deskriptor und den begangenen Pfad zurück. Der Aufrufer
        schließt.
        """
        if not angefragt.is_absolute():
            raise FileAccessDenied("Nur absolute Pfade werden aufgezählt.")
        if ".." in angefragt.parts:
            # Nicht wegrechnen, sondern ablehnen — dieselbe Entscheidung wie in
            # ``FilesConstraints.check()``: Ein Pfad, der erst gerechnet werden
            # muss, ist nicht der Pfad, der geöffnet wird.
            raise FileAccessDenied("Pfade mit '..' werden nicht aufgezählt.")

        wurzel = self._wurzel_von(angefragt)
        if wurzel is None:
            raise FileAccessDenied("Pfad liegt außerhalb der freigegebenen Ordner.")

        deskriptor = self._oeffnen(wurzel, dir_fd=None)
        begangen = wurzel
        try:
            for segment in angefragt.relative_to(wurzel).parts:
                naechster = self._oeffnen(Path(segment), dir_fd=deskriptor)
                os.close(deskriptor)
                deskriptor = naechster
                begangen = begangen / segment
        except BaseException:
            os.close(deskriptor)
            raise
        return deskriptor, begangen

    @staticmethod
    def _oeffnen(teil: Path, *, dir_fd: int | None) -> int:
        """Ein Verzeichnis öffnen — ohne Verweis, ohne Blockieren."""
        try:
            return os.open(
                teil,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_NONBLOCK,
                dir_fd=dir_fd,
            )
        except FileNotFoundError as fehlt:
            raise FileUnavailable("Ordner nicht gefunden.") from fehlt
        except OSError as fehler:
            if fehler.errno in {errno.EACCES, errno.EPERM}:
                raise FileAccessDenied("Ordner nicht lesbar.") from fehler
            # **Verweis oder schlicht kein Ordner — das ist nicht dasselbe**,
            # und die Fehlerkennungen sagen es nicht: ``O_NOFOLLOW`` auf einem
            # Verweis meldet je nach System ``ELOOP`` oder ``ENOTDIR``, und
            # ``ENOTDIR`` meldet auch eine ganz gewöhnliche Datei. Ein
            # Ausbruchsversuch über einen Verweis ginge damit als „ist kein
            # Ordner" durch — als Alltag statt als Sicherheitsereignis.
            #
            # Gefragt wird deshalb nach dem Fehlschlag, was dort steht. Das ist
            # ein zweiter Syscall und **kein** zweites Zeitfenster: Der Zugriff
            # ist bereits verweigert, entschieden wird nur noch die Meldung.
            if fehler.errno in {errno.ELOOP, errno.EMLINK, errno.ENOTDIR} and _ist_verweis(
                teil, dir_fd=dir_fd
            ):
                # Wohin er zeigt, wird **nicht** aufgelöst: Das wäre eine
                # Auskunft über das Dateisystem, und ob er innerhalb bliebe,
                # ließe sich nur durch genau das Auflösen feststellen, das hier
                # vermieden wird.
                raise FileAccessDenied("Pfad führt über einen Verweis.") from fehler
            if fehler.errno in {errno.ELOOP, errno.EMLINK, errno.ENOTDIR}:
                raise FileUnavailable("Das ist kein Ordner.") from fehler
            raise FileUnavailable(f"Ordner nicht lesbar: {fehler.strerror}") from fehler


class LocalFileReader(WurzelGrenze):
    """Liest Textdateien — ausschließlich unterhalb der übergebenen Wurzeln."""

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

        # Zugangsdaten: geprüft wird der **aufgelöste** Name.
        #
        # Die Berechtigung prüft denselben Punkt auf dem genannten Pfad — und
        # sieht damit nur, was draufsteht. Ein Symlink ``harmlos.txt`` auf
        # ``~/.ssh/id_rsa`` besteht dort einwandfrei; erst hier steht der echte
        # Name fest. Dieselbe Arbeitsteilung wie bei der Wurzelgrenze.
        if is_sensitive_filename(str(aufgeloest)):
            # Die Meldung nennt die Kategorie, nicht den aufgelösten Pfad. Der
            # Rest ist eine Abwägung: Wer über einen Symlink fragt, erfährt,
            # dass das Ziel wie eine Schlüsseldatei heißt. Das in Kauf zu
            # nehmen ist die kleinere Übel gegenüber einer Meldung, die einem
            # rechtmäßigen Nutzer verschweigt, warum seine ``.env`` nicht
            # lesbar ist.
            raise FileAccessDenied(
                "Dateien mit Zugangsdaten werden nicht gelesen, auch nicht innerhalb "
                "freigegebener Ordner."
            )

        return self._oeffnen_und_lesen(aufgeloest, max_bytes)

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


def _ist_verweis(teil: Path, *, dir_fd: int | None) -> bool:
    """Steht an dieser Stelle ein Verweis?

    Nur zur Wahl der Fehlermeldung — der Zugriff ist zu diesem Zeitpunkt
    bereits abgelehnt. Ein Fehlschlag hier bedeutet „nicht feststellbar", und
    dann bleibt es bei der harmloseren Auskunft.
    """
    try:
        return stat.S_ISLNK(os.lstat(teil, dir_fd=dir_fd).st_mode)
    except OSError:
        return False


class LocalDirectoryLister(WurzelGrenze):
    """Zählt **ein** Verzeichnis auf — innerhalb der Wurzeln, eine Ebene tief.

    Erfüllt ``DirectoryLister``. Getrennt von ``LocalFileReader`` und nicht als
    zweites Verfahren an ihm: Der Handler von ``files.read`` bekommt damit ein
    Objekt, das **nicht aufzählen kann** (ADR-019).

    **Die Reihenfolge ist dieselbe wie beim Lesen**, weil die Frage dieselbe
    ist: erst auflösen, dann vergleichen, dann öffnen. Was fehlt, ist Schritt 5
    — gelesen wird nichts. Ein Verzeichnis mit ``O_NOFOLLOW`` zu öffnen ist
    hier trotzdem richtig: Sonst ließe sich der letzte Bestandteil nach der
    Auflösung gegen einen Verweis tauschen, und aufgezählt würde ein anderer
    Ordner als der geprüfte.
    """

    async def list_dir(self, path: str, *, max_entries: int) -> DirectoryListing:
        return await asyncio.to_thread(self._auflisten, path, max_entries)

    def _auflisten(self, pfad: str, max_entries: int) -> DirectoryListing:
        """Öffnet den Ordner segmentweise und zählt ihn auf.

        Kein ``resolve()`` mehr: Die Auflösung liefert eine Zeichenkette, die
        zwischen Prüfung und Öffnen ihre Bedeutung ändern kann. Der begangene
        Weg selbst ist der Nachweis, dass der geöffnete Ordner unterhalb einer
        Wurzel liegt — dafür braucht es keine zweite Prüfung.
        """
        deskriptor, begangen = self._segmentweise_oeffnen(Path(pfad))
        try:
            namen = sorted(os.listdir(deskriptor))
            gekuerzt = len(namen) > max_entries
            eintraege = [self._eintrag(deskriptor, name) for name in namen[:max_entries]]
        finally:
            os.close(deskriptor)

        return DirectoryListing(path=str(begangen), entries=eintraege, truncated=gekuerzt)

    @staticmethod
    def _eintrag(deskriptor: int, name: str) -> DirectoryEntry:
        """Art und Größe eines Eintrags — ohne dem Verweis zu folgen.

        ``lstat`` relativ zum offenen Deskriptor: Ein Verweis wird als Verweis
        gemeldet, nicht als das, worauf er zeigt. Wer ihm folgte, träte damit
        aus den Wurzeln heraus, ohne dass es jemand sieht.

        Ein Eintrag, der zwischen ``listdir`` und ``lstat`` verschwindet, ist
        Alltag und kein Fehler — er wird als Datei ohne Größe gemeldet. Den
        ganzen Aufruf daran scheitern zu lassen, machte eine Aufzählung von der
        Ruhe des Ordners abhängig.
        """
        try:
            zustand = os.lstat(name, dir_fd=deskriptor)
        except OSError:
            return DirectoryEntry(name=name, kind="datei")

        if stat.S_ISLNK(zustand.st_mode):
            return DirectoryEntry(name=name, kind="verweis")
        if stat.S_ISDIR(zustand.st_mode):
            return DirectoryEntry(name=name, kind="ordner")
        return DirectoryEntry(name=name, kind="datei", size=zustand.st_size)
