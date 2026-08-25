"""``web.fetch`` — und vor allem die Adressen, die es nicht abrufen darf.

Ein Werkzeug, dessen Argument ein Modell formuliert, ist bei einer **Adresse**
etwas anderes als bei einem Dateipfad: Wer die Adresse nennt, bestimmt, wohin
dieser Prozess eine Verbindung aufbaut — und aus dem Netzwerk eines Servers ist
mehr erreichbar als aus dem Internet. Das ist SSRF, und diese Suite prüft
zuerst, was **nicht** geht.

Der Nachweis ist dabei zweierlei:

* Die Abweisung erfolgt, **bevor** eine Verbindung entsteht. Ein Adapter, der
  erst verbindet und danach urteilt, hat die Anfrage schon gestellt — und
  manche Dienste führen aus, was in ihr steht.
* Sie hängt an der **aufgelösten** Adresse, nicht am Namen. Eine Sperrliste aus
  Zeichenketten sieht ``interne-daten.example.com`` und merkt nichts.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any

import httpx
import pytest

from jarvis_core.ports.web import WebAccessDenied, WebUnavailable
from jarvis_core.tools.builtin import WEB_FETCH, web_fetch_handler
from jarvis_integrations.web import HttpWebFetcher, adresse_pruefen

pytestmark = pytest.mark.security


@pytest.fixture(autouse=True)
def _aufloesung(monkeypatch: pytest.MonkeyPatch) -> None:
    """Namen werden im Test nicht wirklich aufgelöst.

    Sonst hinge die Suite am DNS des Rechners, auf dem sie läuft — und ein Test
    über Netzwerksicherheit, der selbst ins Netz greift, prüft die Verbindung
    und nicht die Regel. Abgebildet wird genau das, was ``getaddrinfo``
    zurückgäbe.
    """

    namen = {
        "example.test": ["93.184.216.34"],
        "intern.example.test": ["10.0.0.5"],
        "gemischt.example.test": ["93.184.216.34", "127.0.0.1"],
        "metadaten.example.test": ["169.254.169.254"],
        "v6.example.test": ["2606:2800:220:1:248:1893:25c8:1946"],
        "v6-loopback.example.test": ["::1"],
        "getarnt.example.test": ["::ffff:127.0.0.1"],
        "weiterleitung.example.test": ["93.184.216.34"],
    }

    def _fake(host: str, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        if host not in namen:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (adresse, 0)) for adresse in namen[host]
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake)


class TestWasNichtAbgerufenWird:
    @pytest.mark.parametrize(
        ("url", "warum"),
        [
            ("file:///etc/passwd", "läse das Dateisystem"),
            ("gopher://example.test/_x", "spräche mit beliebigen Diensten"),
            ("ftp://example.test/x", "kein Webschema"),
            ("", "ohne Schema"),
        ],
    )
    def test_fremde_schemata(self, url: str, warum: str) -> None:
        with pytest.raises(WebAccessDenied):
            adresse_pruefen(url)

    @pytest.mark.parametrize(
        "url",
        [
            "http://intern.example.test/",
            "http://metadaten.example.test/latest/meta-data/",
            "http://127.0.0.1:80/",
            "http://[::1]:80/",
            "http://v6-loopback.example.test/",
        ],
    )
    @pytest.mark.invariant("web-fetch-reaches-only-public-addresses")
    def test_private_und_reservierte_adressen(self, url: str) -> None:
        """``169.254.169.254`` ist bei jedem Cloud-Anbieter der Weg zu den
        Zugangsdaten der Instanz — der bekannteste Einzelfall und nur einer von
        vielen. Geprüft wird deshalb nicht gegen eine Liste, sondern gegen
        „ist diese Adresse aus dem Internet routbar?"."""
        with pytest.raises(WebAccessDenied):
            adresse_pruefen(url)

    @pytest.mark.invariant("web-fetch-reaches-only-public-addresses")
    def test_ein_name_mit_zwei_adressen_faellt_ganz_durch(self) -> None:
        """Der Fall, den eine Prüfung der *ersten* Adresse durchließe.

        Verbunden würde danach mit irgendeiner der beiden — und die zweite ist
        das Loopback-Interface.
        """
        with pytest.raises(WebAccessDenied, match=re.escape("127.0.0.1")):
            adresse_pruefen("http://gemischt.example.test/")

    @pytest.mark.invariant("web-fetch-reaches-only-public-addresses")
    def test_ipv4_in_ipv6_kleidung(self) -> None:
        """``::ffff:127.0.0.1`` ist für ``is_global`` eine IPv6-Adresse; die
        Verbindung landet trotzdem beim lokalen Rechner."""
        with pytest.raises(WebAccessDenied):
            adresse_pruefen("http://getarnt.example.test/")

    @pytest.mark.parametrize("port", [22, 5432, 6379, 8080, 11434])
    def test_fremde_ports(self, port: int) -> None:
        """Ein Abruf auf ``:6379`` ist kein Webseitenabruf, sondern der Versuch,
        mit Redis zu sprechen. Dass die Antwort unbrauchbar ist, hilft nicht —
        gesendet wurde die Anfrage trotzdem."""
        with pytest.raises(WebAccessDenied):
            adresse_pruefen(f"http://example.test:{port}/")

    def test_oeffentliche_adressen_gehen_durch(self) -> None:
        """Die Gegenprobe, und sie ist die wichtigere: Ein Schutz, der den
        Normalfall blockiert, wird abgeschaltet."""
        assert adresse_pruefen("https://example.test/artikel") == ("https", "example.test", 443)
        assert adresse_pruefen("http://v6.example.test/") == ("http", "v6.example.test", 80)


class TestVorDerVerbindung:
    @pytest.mark.invariant("web-fetch-reaches-only-public-addresses")
    async def test_eine_verweigerte_adresse_erzeugt_keine_anfrage(self) -> None:
        """Der Nachweis ist die **Null**: Der Transport hat nichts gesehen."""
        gesehen: list[httpx.Request] = []

        def aufzeichnen(request: httpx.Request) -> httpx.Response:
            gesehen.append(request)
            return httpx.Response(200, text="<html><body>egal</body></html>")

        client = httpx.AsyncClient(transport=httpx.MockTransport(aufzeichnen))
        fetcher = HttpWebFetcher(client=client)

        with pytest.raises(WebAccessDenied):
            await fetcher.fetch("http://metadaten.example.test/latest/", max_bytes=1000)

        assert gesehen == [], "Die Anfrage darf gar nicht erst hinausgehen."

    @pytest.mark.invariant("web-fetch-reaches-only-public-addresses")
    async def test_eine_weiterleitung_ins_private_netz_wird_gestoppt(self) -> None:
        """Der Weg um jede Eingangsprüfung herum — und der Grund, warum dieser
        Adapter Weiterleitungen selbst verfolgt.

        ``follow_redirects=True`` hätte die erste Adresse geprüft und der
        zweiten blind gefolgt.
        """
        ziele: list[str] = []

        def antworten(request: httpx.Request) -> httpx.Response:
            ziele.append(str(request.url))
            return httpx.Response(302, headers={"location": "http://metadaten.example.test/x"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(antworten))
        fetcher = HttpWebFetcher(client=client)

        with pytest.raises(WebAccessDenied, match=re.escape("169.254.169.254")):
            await fetcher.fetch("http://weiterleitung.example.test/", max_bytes=1000)

        assert ziele == ["http://weiterleitung.example.test/"], (
            "Die zweite Adresse wurde geprüft, bevor sie abgerufen wurde."
        )

    async def test_eine_endlose_kette_endet(self) -> None:
        def im_kreis(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"location": "http://example.test/weiter"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(im_kreis))
        fetcher = HttpWebFetcher(client=client)

        with pytest.raises(WebAccessDenied, match="Weiterleitungen"):
            await fetcher.fetch("http://example.test/", max_bytes=1000)


class TestWasZurueckkommt:
    async def test_html_wird_zu_text(self) -> None:
        seite = (
            "<html><head><title>Der Artikel</title>"
            "<script>window.x=1</script></head>"
            "<body><h1>Überschrift</h1><p>Ein Satz.</p>"
            "<style>p{color:red}</style></body></html>"
        )
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, text=seite, headers={"content-type": "text/html"})
            )
        )

        dokument = await HttpWebFetcher(client=client).fetch(
            "https://example.test/a", max_bytes=100_000
        )

        assert dokument.title == "Der Artikel"
        assert "Überschrift" in dokument.text and "Ein Satz." in dokument.text
        # Skript und Stil fallen heraus — sie enthalten keinen Text für
        # Menschen, und ihr Inhalt sieht am ehesten wie eine Anweisung aus.
        assert "window.x" not in dokument.text
        assert "color:red" not in dokument.text

    async def test_zu_grosse_seiten_werden_gekuerzt_und_sagen_es(self) -> None:
        """Ein halber Text, der als ganzer ausgegeben wird, ist eine
        Falschaussage über die Quelle."""
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    200, text="x" * 5000, headers={"content-type": "text/plain"}
                )
            )
        )

        dokument = await HttpWebFetcher(client=client).fetch(
            "https://example.test/gross", max_bytes=1000
        )

        assert dokument.truncated is True
        assert len(dokument.text) <= 1000

    async def test_ein_fehlerstatus_ist_kein_inhalt(self) -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(404, text="weg"))
        )

        with pytest.raises(WebUnavailable):
            await HttpWebFetcher(client=client).fetch("https://example.test/x", max_bytes=1000)


class TestDasWerkzeug:
    def test_es_kontaminiert_den_lauf(self) -> None:
        """Der Kern: Was aus dem Netz kommt, hat ein Fremder geschrieben —
        womöglich, weil er wusste, dass ein Modell es liest."""
        assert WEB_FETCH.reads_untrusted_content is True

    def test_das_modell_sieht_die_tatsaechliche_adresse(self) -> None:
        """Nach einer Weiterleitung sind angefragte und abgerufene Adresse zwei
        verschiedene Dinge. Ein Modell, das eine Quelle nennt, soll die richtige
        nennen."""
        assert set(WEB_FETCH.model_visible_fields) == {"url", "title", "text"}

    def test_das_schema_nennt_kein_beispiel(self) -> None:
        """Ein Beispiel in einer Schemabeschreibung ist für ein Modell die
        naheliegendste Antwort — bei ``files.read`` gemessen: 3 von 3 Malen
        wörtlich zurückgegeben. Bei einer Adresse wäre das eine erfundene
        Quelle."""
        beschreibung = WEB_FETCH.parameters["properties"]["url"]["description"]
        assert "http://beispiel" not in beschreibung.lower()
        assert "example." not in beschreibung.lower()

    async def test_eine_verweigerung_wird_zum_ergebnis_und_nicht_zur_ausnahme(self) -> None:
        """Der Handler gibt ein ``ToolResult`` zurück, kein rohes Scheitern:
        Der Executor soll die Ablehnung protokollieren können, und das Modell
        soll erfahren, dass die Adresse nicht zulässig war — nicht, dass etwas
        kaputt ist."""

        class Verweigernd:
            async def fetch(self, url: str, *, max_bytes: int) -> Any:
                raise WebAccessDenied("nicht öffentlich")

        ergebnis = await web_fetch_handler(Verweigernd())(url="http://intern.example.test/")

        assert ergebnis.ok is False
        assert "nicht öffentlich" in (ergebnis.error or "")


class TestDieBerechtigung:
    def test_ohne_liste_ist_jede_oeffentliche_adresse_erlaubt(self) -> None:
        from jarvis_contracts import WebConstraints

        assert WebConstraints().check({"url": "https://example.test/x"}) is None

    def test_mit_liste_gilt_nur_die_liste(self) -> None:
        from jarvis_contracts import WebConstraints

        eng = WebConstraints(allowed_hosts=["example.test"])

        assert eng.check({"url": "https://example.test/x"}) is None
        assert eng.check({"url": "https://unter.example.test/x"}) is None
        verletzt = eng.check({"url": "https://anderswo.test/x"})
        assert verletzt is not None and verletzt.field == "url"

    def test_ein_praefix_genuegt_nicht(self) -> None:
        """Dasselbe Loch, das bei den Pfaden schon einmal klaffte:
        ``boese-example.test`` endet auf ``example.test``."""
        from jarvis_contracts import WebConstraints

        eng = WebConstraints(allowed_hosts=["example.test"])

        assert eng.check({"url": "https://boese-example.test/x"}) is not None


def test_die_pruefung_kennt_keine_ausnahme_fuer_localhost() -> None:
    """Ein Strukturtest gegen die bequemste künftige Änderung.

    „Nur für die Entwicklung" ist der Satz, mit dem solche Ausnahmen entstehen —
    und danach steht sie in Produktion. Wer localhost abrufen will, baut einen
    eigenen Schalter und begründet ihn; stillschweigend passiert das nicht.
    """
    from pathlib import Path

    quelle = Path(HttpWebFetcher.__module__.replace(".", "/") + ".py")
    text = (Path(__file__).resolve().parents[2] / "packages" / "integrations" / quelle).read_text()

    for verdaechtig in ("is_loopback", '== "localhost"', "allow_private", "JARVIS_WEB_ALLOW"):
        assert verdaechtig not in text, f"Ausnahme im Adapter gefunden: {verdaechtig}"
    assert ipaddress is not None
