"""Das Aufzählen unter Angriff — und die Zusagen aus ADR-019.

Gegen das **echte** Dateisystem, aus demselben Grund wie ``test_localfs.py``:
Symlinks und Verzeichnisse sind genau das, was eine Attrappe wegabstrahieren
würde.

Der Anlass ist eine Messung: Die Argumentquelle traf ``…/projektnotiz.md`` in
**0 von 3** Fällen, wenn nur die freigegebene Wurzel bekannt war — geraten
wurde ``Projektnotiz.md``, gescheitert an der Groß- und Kleinschreibung. Ein
Modell, das raten muss, rät falsch. ``files.list`` ist die Antwort darauf, und
diese Suite prüft, dass sie nicht mehr verrät als nötig.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from jarvis_core.ports.files import FileAccessDenied, FileUnavailable
from jarvis_integrations import LocalDirectoryLister

pytestmark = [pytest.mark.asyncio, pytest.mark.security]


@pytest.fixture
def freigegeben(tmp_path: Path) -> Path:
    """Ein freigegebener Ordner mit Datei, Unterordner und Zugangsdatei."""
    wurzel = tmp_path / "freigegeben"
    wurzel.mkdir()
    (wurzel / "projektnotiz.md").write_text("Inhalt", encoding="utf-8")
    (wurzel / "unterordner").mkdir()
    (wurzel / ".env").write_text("TOKEN=geheim", encoding="utf-8")
    return wurzel


@pytest.fixture
def geheim(tmp_path: Path) -> Path:
    """Etwas außerhalb — das Ziel jedes Ausbruchsversuchs."""
    ordner = tmp_path / "geheim"
    ordner.mkdir()
    (ordner / "passwoerter.txt").write_text("streng geheim", encoding="utf-8")
    return ordner


class TestWasEineAufzaehlungLeistet:
    async def test_der_gesuchte_name_steht_da(self, freigegeben: Path) -> None:
        """Der Zweck des Werkzeugs in einem Satz: nachsehen statt raten."""
        lister = LocalDirectoryLister([freigegeben])

        aufzaehlung = await lister.list_dir(str(freigegeben), max_entries=200)

        assert "projektnotiz.md" in [e.name for e in aufzaehlung.entries]

    async def test_ordner_und_dateien_sind_unterscheidbar(self, freigegeben: Path) -> None:
        lister = LocalDirectoryLister([freigegeben])

        arten = {
            e.name: e.kind
            for e in (await lister.list_dir(str(freigegeben), max_entries=200)).entries
        }

        assert arten["projektnotiz.md"] == "datei"
        assert arten["unterordner"] == "ordner"

    async def test_alphabetisch_und_damit_wiederholbar(self, freigegeben: Path) -> None:
        """Eine Reihenfolge aus dem Dateisystem macht aus zwei gleichen
        Aufrufen zwei verschiedene Antworten."""
        lister = LocalDirectoryLister([freigegeben])

        namen = [e.name for e in (await lister.list_dir(str(freigegeben), max_entries=200)).entries]

        assert namen == sorted(namen)


class TestWasSieNichtVerschweigt:
    async def test_zugangsdaten_werden_genannt_aber_nicht_gelesen(self, freigegeben: Path) -> None:
        """Die unbequeme Entscheidung aus ADR-019.

        Eine Aufzählung, die still filtert, ist nicht zu gebrauchen: Niemand
        kann „ist leer" von „wurde gefiltert" unterscheiden. Dass ``.env``
        genannt wird, macht sie nicht lesbar — die Sperre sitzt im Lesepfad und
        in der Berechtigung, und dort ist sie geprüft.
        """
        lister = LocalDirectoryLister([freigegeben])

        namen = [e.name for e in (await lister.list_dir(str(freigegeben), max_entries=200)).entries]

        assert ".env" in namen

    async def test_eine_kuerzung_wird_gesagt(self, tmp_path: Path) -> None:
        """Sonst schließt ein Modell aus dem Fehlen einer Datei, dass es sie
        nicht gibt."""
        wurzel = tmp_path / "viele"
        wurzel.mkdir()
        for i in range(10):
            (wurzel / f"datei-{i:02d}.txt").touch()
        lister = LocalDirectoryLister([wurzel])

        aufzaehlung = await lister.list_dir(str(wurzel), max_entries=4)

        assert aufzaehlung.truncated
        assert len(aufzaehlung.entries) == 4

    async def test_ohne_kuerzung_steht_es_auf_falsch(self, freigegeben: Path) -> None:
        lister = LocalDirectoryLister([freigegeben])

        assert not (await lister.list_dir(str(freigegeben), max_entries=200)).truncated


class TestAusbruchsversuche:
    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_ordner_ausserhalb_der_wurzel(self, freigegeben: Path, geheim: Path) -> None:
        lister = LocalDirectoryLister([freigegeben])

        with pytest.raises(FileAccessDenied):
            await lister.list_dir(str(geheim), max_entries=200)

    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_verweis_aus_der_wurzel_heraus(self, freigegeben: Path, geheim: Path) -> None:
        """Der Fall, für den die Auflösung da ist: Der Pfad *sieht* erlaubt aus."""
        (freigegeben / "abkuerzung").symlink_to(geheim, target_is_directory=True)
        lister = LocalDirectoryLister([freigegeben])

        with pytest.raises(FileAccessDenied):
            await lister.list_dir(str(freigegeben / "abkuerzung"), max_entries=200)

    async def test_traversierung(self, freigegeben: Path, geheim: Path) -> None:
        lister = LocalDirectoryLister([freigegeben])

        with pytest.raises(FileAccessDenied):
            await lister.list_dir(str(freigegeben / ".." / "geheim"), max_entries=200)

    async def test_relativer_pfad(self, freigegeben: Path) -> None:
        lister = LocalDirectoryLister([freigegeben])

        with pytest.raises(FileAccessDenied):
            await lister.list_dir("freigegeben", max_entries=200)

    async def test_ohne_wurzeln_ist_nichts_aufzaehlbar(self, freigegeben: Path) -> None:
        """Der richtige Vorgabewert für eine Freigabe, die niemand erteilt hat."""
        lister = LocalDirectoryLister([])

        with pytest.raises(FileAccessDenied):
            await lister.list_dir(str(freigegeben), max_entries=200)


class TestWasEinVerweisVerraet:
    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_ein_verweis_wird_benannt_und_nicht_aufgeloest(
        self, freigegeben: Path, geheim: Path
    ) -> None:
        """**Der Kern der Auskunftsgrenze.**

        Ein Verweis darf im Ergebnis stehen — er liegt im freigegebenen Ordner.
        Wohin er zeigt, steht **nicht** darin: Das wäre eine Auskunft über das
        Dateisystem jenseits der Wurzeln, und zwar eine, die sich über einen
        einzigen Aufruf abfragen ließe.
        """
        (freigegeben / "abkuerzung").symlink_to(geheim, target_is_directory=True)
        lister = LocalDirectoryLister([freigegeben])

        aufzaehlung = await lister.list_dir(str(freigegeben), max_entries=200)

        verweis = next(e for e in aufzaehlung.entries if e.name == "abkuerzung")
        assert verweis.kind == "verweis"
        assert "geheim" not in aufzaehlung.model_dump_json()

    async def test_ein_verweis_zaehlt_nicht_als_ordner(
        self, freigegeben: Path, geheim: Path
    ) -> None:
        """Sonst hielte ein Modell ihn für begehbar und liefe in eine
        Ablehnung, die es nicht versteht."""
        (freigegeben / "abkuerzung").symlink_to(geheim, target_is_directory=True)
        lister = LocalDirectoryLister([freigegeben])

        aufzaehlung = await lister.list_dir(str(freigegeben), max_entries=200)

        assert [e.kind for e in aufzaehlung.entries if e.name == "abkuerzung"] == ["verweis"]


class TestWasKeinOrdnerIst:
    async def test_eine_datei_ist_kein_ordner(self, freigegeben: Path) -> None:
        lister = LocalDirectoryLister([freigegeben])

        with pytest.raises(FileUnavailable):
            await lister.list_dir(str(freigegeben / "projektnotiz.md"), max_entries=200)

    async def test_ein_ordner_der_nicht_existiert(self, freigegeben: Path) -> None:
        lister = LocalDirectoryLister([freigegeben])

        with pytest.raises(FileUnavailable):
            await lister.list_dir(str(freigegeben / "gibtsnicht"), max_entries=200)

    async def test_eine_fifo_haelt_die_aufzaehlung_nicht_an(self, freigegeben: Path) -> None:
        """Beim Lesen hat genau das den ersten Testlauf hängen lassen.

        Hier kann es nicht passieren — geöffnet wird mit ``O_DIRECTORY``, und
        eine FIFO ist keiner. Der Test steht trotzdem da: Die Zusage ist, dass
        ein Ordner mit einer FIFO darin aufzählbar bleibt.
        """
        os.mkfifo(freigegeben / "rohr")
        lister = LocalDirectoryLister([freigegeben])

        aufzaehlung = await lister.list_dir(str(freigegeben), max_entries=200)

        assert "rohr" in [e.name for e in aufzaehlung.entries]
