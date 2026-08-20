"""Der Dateizugriff unter Angriff.

Gegen das **echte** Dateisystem und nicht gegen eine Attrappe: Die
Eigenschaften, um die es hier geht — Symlinks, Gerätedateien, Auflösung von
``..`` — existieren nur dort. Ein Mock würde genau das wegabstrahieren, worum
es geht, und zwar bei der einzigen Komponente des Systems, die einen Pfad
tatsächlich öffnet.

Kein Dienst nötig, deshalb liegt die Suite bei den Unit-Tests: Sie läuft überall
mit, auch ohne Postgres. Der Nachweis, den sie führt, ist trotzdem der eines
Integrationstests.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from jarvis_core.ports.files import FileAccessDenied, FileUnavailable
from jarvis_integrations import LocalFileReader

pytestmark = [pytest.mark.asyncio, pytest.mark.security]


@pytest.fixture
def freigegeben(tmp_path: Path) -> Path:
    """Ein freigegebener Ordner mit einer harmlosen Datei."""
    wurzel = tmp_path / "freigegeben"
    wurzel.mkdir()
    (wurzel / "notiz.txt").write_text("Hallo Welt", encoding="utf-8")
    return wurzel


@pytest.fixture
def geheim(tmp_path: Path) -> Path:
    """Etwas, das außerhalb liegt — das Ziel jedes Ausbruchsversuchs."""
    ordner = tmp_path / "geheim"
    ordner.mkdir()
    datei = ordner / "passwoerter.txt"
    datei.write_text("streng geheim", encoding="utf-8")
    return datei


class TestErlaubterZugriff:
    async def test_datei_in_der_wurzel_wird_gelesen(self, freigegeben: Path) -> None:
        leser = LocalFileReader([freigegeben])
        inhalt = await leser.read_text(str(freigegeben / "notiz.txt"), max_bytes=1000)

        assert inhalt.text == "Hallo Welt"
        assert inhalt.truncated is False
        assert inhalt.bytes_read == 10

    async def test_der_aufgeloeste_pfad_wird_zurueckgegeben(self, freigegeben: Path) -> None:
        """Der Aufrufer soll sehen, was er tatsächlich gelesen hat.

        Ein Symlink *innerhalb* der Wurzeln ist zulässig — er verlässt die
        Freigabe nicht. Zurück kommt trotzdem das Ziel und nicht der Name, über
        den gefragt wurde: Sonst hinge in der Antwort ein Pfad, der etwas
        anderes bezeichnet als den Inhalt daneben.
        """
        verweis = freigegeben / "verweis.txt"
        verweis.symlink_to(freigegeben / "notiz.txt")

        inhalt = await LocalFileReader([freigegeben]).read_text(str(verweis), max_bytes=1000)

        assert inhalt.text == "Hallo Welt"
        assert inhalt.path == str((freigegeben / "notiz.txt").resolve())


class TestAusbruchsversuche:
    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_symlink_aus_der_wurzel_heraus_wird_abgewiesen(
        self, freigegeben: Path, geheim: Path
    ) -> None:
        """Der Fall, für den es diesen Adapter überhaupt gibt.

        Der Symlink liegt **innerhalb** des freigegebenen Ordners. Für jede
        Prüfung, die nur auf die Zeichenkette schaut — und die Policy Engine
        kann nur das —, ist dieser Pfad einwandfrei. Erst die Auflösung zeigt,
        dass er hinausführt.

        Das ist keine doppelte Prüfung, sondern die einzige, die diese Frage
        beantworten kann.
        """
        falle = freigegeben / "harmlos.txt"
        falle.symlink_to(geheim)

        with pytest.raises(FileAccessDenied):
            await LocalFileReader([freigegeben]).read_text(str(falle), max_bytes=1000)

    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_symlink_auf_einen_ordner_ausserhalb(
        self, freigegeben: Path, geheim: Path
    ) -> None:
        """Der Umweg über ein verlinktes Verzeichnis.

        Nicht die Datei ist verlinkt, sondern der Ordner darüber. Wer nur den
        letzten Pfadbestandteil prüft, sieht hier nichts.
        """
        (freigegeben / "unterordner").symlink_to(geheim.parent)

        with pytest.raises(FileAccessDenied):
            await LocalFileReader([freigegeben]).read_text(
                str(freigegeben / "unterordner" / geheim.name), max_bytes=1000
            )

    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_traversierung_mit_punktpunkt(self, freigegeben: Path, geheim: Path) -> None:
        """Auch wenn die Policy ``..`` inzwischen ablehnt: Der Adapter verlässt
        sich nicht darauf.

        Er ist nicht die zweite Prüfung derselben Sache, sondern die Grenze des
        Prozesses. Sie muss auch dann halten, wenn ihn jemand ohne Policy
        aufruft — etwa ein Arbeiter, ein Skript oder ein Test.
        """
        with pytest.raises(FileAccessDenied):
            await LocalFileReader([freigegeben]).read_text(
                str(freigegeben / ".." / "geheim" / "passwoerter.txt"), max_bytes=1000
            )

    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_pfad_ausserhalb_wird_abgewiesen(self, freigegeben: Path, geheim: Path) -> None:
        with pytest.raises(FileAccessDenied):
            await LocalFileReader([freigegeben]).read_text(str(geheim), max_bytes=1000)

    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_ohne_wurzeln_ist_nichts_lesbar(self, freigegeben: Path) -> None:
        """Der Vorgabewert einer Freigabe, die niemand erteilt hat."""
        with pytest.raises(FileAccessDenied):
            await LocalFileReader([]).read_text(str(freigegeben / "notiz.txt"), max_bytes=1000)

    async def test_relativer_pfad_wird_abgewiesen(self, freigegeben: Path) -> None:
        with pytest.raises(FileAccessDenied):
            await LocalFileReader([freigegeben]).read_text("notiz.txt", max_bytes=1000)

    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_die_meldung_verraet_das_ziel_nicht(
        self, freigegeben: Path, geheim: Path
    ) -> None:
        """Eine abgewiesene Anfrage darf keine Auskunft sein.

        Stünde im Fehlertext, wohin der Symlink zeigt, wäre der Adapter ein
        Erkundungswerkzeug: Wer Verweise auslegt, könnte das Dateisystem
        kartieren, ohne je eine Datei zu lesen. Deshalb ist die Meldung
        dieselbe wie bei einem Pfad, der von vornherein außerhalb lag.
        """
        falle = freigegeben / "harmlos.txt"
        falle.symlink_to(geheim)
        leser = LocalFileReader([freigegeben])

        with pytest.raises(FileAccessDenied) as ueber_symlink:
            await leser.read_text(str(falle), max_bytes=1000)
        with pytest.raises(FileAccessDenied) as direkt:
            await leser.read_text(str(geheim), max_bytes=1000)

        assert str(ueber_symlink.value) == str(direkt.value)
        assert "geheim" not in str(ueber_symlink.value)
        assert str(geheim) not in str(ueber_symlink.value)


class TestZugangsdaten:
    """Die zweite Schicht **innerhalb** der freigegebenen Ordner.

    Die Wurzelgrenze beantwortet „darf hier gelesen werden?". Sie beantwortet
    nicht, ob im freigegebenen Ordner zufällig ein SSH-Schlüssel liegt. Ein
    Heimatverzeichnis freizugeben ist nachvollziehbar, den Schlüssel darin
    mitzuliefern nicht.

    Die Idee stammt aus OpenJarvis (Apache 2.0), wo eine solche Musterliste
    allerdings die *primäre* Prüfung ist. Als alleinige Grenze wäre sie
    untauglich — jede Sperrliste übersieht etwas.
    """

    @pytest.mark.invariant("file-access-confined-to-roots")
    @pytest.mark.parametrize("name", ["id_rsa", ".env", "server.key", "id_ed25519", ".netrc"])
    async def test_zugangsdaten_im_freigegebenen_ordner_bleiben_gesperrt(
        self, freigegeben: Path, name: str
    ) -> None:
        (freigegeben / name).write_text("geheim", encoding="utf-8")

        with pytest.raises(FileAccessDenied):
            await LocalFileReader([freigegeben]).read_text(str(freigegeben / name), max_bytes=1000)

    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_harmloser_name_auf_schluesseldatei_wird_erkannt(
        self, freigegeben: Path, tmp_path: Path
    ) -> None:
        """Der Fall, den die Berechtigungsprüfung nicht sehen kann.

        Der Symlink heißt ``notizen.txt`` und liegt im freigegebenen Ordner —
        für jede Prüfung auf der Zeichenkette ist er einwandfrei. Sein Ziel
        heißt ``id_rsa`` und liegt ebenfalls dort, verletzt also nicht einmal
        die Wurzelgrenze. Erst der aufgelöste **Name** verrät es.
        """
        (freigegeben / "id_rsa").write_text("PRIVATER SCHLUESSEL", encoding="utf-8")
        tarnung = freigegeben / "notizen.txt"
        tarnung.symlink_to(freigegeben / "id_rsa")

        with pytest.raises(FileAccessDenied):
            await LocalFileReader([freigegeben]).read_text(str(tarnung), max_bytes=1000)

    async def test_unverdaechtiger_ordnername_blockiert_nicht(self, tmp_path: Path) -> None:
        """Geprüft wird der Basisname, nicht der ganze Pfad.

        Ein Ordner ``keys`` ist unverdächtig; erst die Datei darin entscheidet.
        Andernfalls sperrte ein unglücklich benannter Ordner alles unter sich.
        """
        wurzel = tmp_path / "keys"
        wurzel.mkdir()
        (wurzel / "liesmich.md").write_text("harmlos", encoding="utf-8")

        inhalt = await LocalFileReader([wurzel]).read_text(
            str(wurzel / "liesmich.md"), max_bytes=1000
        )
        assert inhalt.text == "harmlos"


class TestKeineRegulaerenDateien:
    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_verzeichnis_wird_abgewiesen(self, freigegeben: Path) -> None:
        with pytest.raises(FileAccessDenied):
            await LocalFileReader([freigegeben]).read_text(str(freigegeben), max_bytes=1000)

    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_fifo_wird_abgewiesen(self, freigegeben: Path) -> None:
        """Eine FIFO im freigegebenen Ordner hinge bis zum Timeout.

        Sie liegt innerhalb der Wurzeln, ist also kein Ausbruch — aber sie ist
        keine Datei, die man liest, sondern eine, die wartet. Dasselbe gilt für
        Gerätedateien: ``/dev/zero`` liefert unbegrenzt Daten.
        """
        fifo = freigegeben / "warteschlange"
        os.mkfifo(fifo)

        with pytest.raises(FileAccessDenied):
            await LocalFileReader([freigegeben]).read_text(str(fifo), max_bytes=1000)


class TestInhaltsgrenzen:
    async def test_grosse_datei_wird_gekuerzt_und_sagt_es(self, freigegeben: Path) -> None:
        """Kürzen statt Abweisen — aber sichtbar.

        Der Anfang einer großen Datei ist meist die nützliche Antwort. Ein
        stillschweigend halbes Ergebnis wäre schlimmer als eine Fehlermeldung:
        Ein Modell, das die Hälfte einer Datei für das Ganze hält, zieht
        falsche Schlüsse und merkt nichts.
        """
        (freigegeben / "gross.txt").write_text("x" * 5_000, encoding="utf-8")

        inhalt = await LocalFileReader([freigegeben]).read_text(
            str(freigegeben / "gross.txt"), max_bytes=100
        )

        assert inhalt.truncated is True
        assert inhalt.bytes_read == 100
        assert len(inhalt.text) == 100

    async def test_datei_ohne_text_wird_abgewiesen(self, freigegeben: Path) -> None:
        (freigegeben / "bild.dat").write_bytes(b"\xff\xd8\xff\xe0\x00\x10")

        with pytest.raises(FileUnavailable):
            await LocalFileReader([freigegeben]).read_text(
                str(freigegeben / "bild.dat"), max_bytes=1000
            )

    async def test_gekuerztes_mehrbyte_zeichen_bricht_nicht(self, freigegeben: Path) -> None:
        """Der Schnitt kann mitten in ein Zeichen fallen.

        Dann ist die Datei nicht defekt — nur die Grenze lag ungünstig. Ein
        ``UnicodeDecodeError`` wäre hier die falsche Auskunft.
        """
        (freigegeben / "umlaute.txt").write_text("ä" * 100, encoding="utf-8")

        inhalt = await LocalFileReader([freigegeben]).read_text(
            str(freigegeben / "umlaute.txt"), max_bytes=51
        )

        assert inhalt.truncated is True
        assert inhalt.text.startswith("ä")

    async def test_fehlende_datei_ist_kein_sicherheitsvorfall(self, freigegeben: Path) -> None:
        """``FileUnavailable`` und nicht ``FileAccessDenied``.

        Die beiden werden verschieden protokolliert: Ein abgewiesener Zugriff
        gehört ins Sicherheitsprotokoll, ein Tippfehler im Dateinamen nicht.
        Beides unter derselben Ausnahme zu führen hieße, das eine im Rauschen
        des anderen zu verlieren — dieselbe Überlegung wie bei ``UnknownTool``
        und ``ForgedAuthorization``.
        """
        with pytest.raises(FileUnavailable):
            await LocalFileReader([freigegeben]).read_text(
                str(freigegeben / "gibtsnicht.txt"), max_bytes=1000
            )
