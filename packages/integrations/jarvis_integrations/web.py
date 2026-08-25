"""Webzugriff über HTTP — mit einer Adressprüfung, die vor der Verbindung steht.

Erfüllt ``WebFetcher``. Die Begründung, warum dieser Adapter mehr Sorgfalt
verlangt als der Dateizugriff, steht im Port: Eine Adresse wird **aufgelöst**,
und wer sie nennt, bestimmt damit, wohin dieser Prozess eine Verbindung
aufbaut. Bei einem Werkzeug, dessen Argumente ein Modell formuliert, ist das
die Stelle, an der ein untergeschobener Satz zum Netzwerkzugriff wird
(SSRF).

**Die Prüfung hängt an der aufgelösten Adresse, nicht am Namen.** Ein Name ist
eine Behauptung: ``interne-daten.example.com`` kann auf ``10.0.0.5`` zeigen,
und eine Sperrliste aus Zeichenketten hätte davon nichts gemerkt. Geprüft wird
deshalb **jede** Adresse, die die Auflösung liefert — nicht die erste, denn ein
Name mit zwei Einträgen käme sonst durch, sobald einer davon öffentlich ist.

**Weiterleitungen folgt dieser Adapter selbst**, Schritt für Schritt, und prüft
jede Zwischenstation erneut. ``follow_redirects=True`` an ``httpx`` zu
übergeben wäre die bequeme Fassung und die falsche: Die erste Adresse wäre
geprüft, die zweite nicht — und eine Weiterleitung auf ``169.254.169.254`` ist
der klassische Weg um jede Eingangsprüfung herum.

**Was dieser Adapter ausdrücklich nicht leistet.** Zwischen der Auflösung und
dem Verbindungsaufbau liegt ein Zeitfenster; wer beide Antworten kontrolliert,
kann in dieser Lücke von einer öffentlichen auf eine private Adresse wechseln
(DNS-Rebinding). Das zu schließen hieße, die Verbindung selbst an die geprüfte
Adresse zu binden — mit eigenem Transport und eigener TLS-Namensprüfung. Der
Weg ist bekannt und hier bewusst nicht gegangen: Er gehört in einen eigenen
Block, und ein halb gebauter Schutz wäre schlechter als ein benannter offener.
"""

from __future__ import annotations

import ipaddress
import socket
from html.parser import HTMLParser
from urllib.parse import urlparse

import httpx

from jarvis_core.ports.web import (
    WebAccessDenied,
    WebDocument,
    WebFetcher,
    WebUnavailable,
)

__all__ = ["HttpWebFetcher", "adresse_pruefen"]

ERLAUBTE_SCHEMATA = frozenset({"http", "https"})
ERLAUBTE_PORTS = frozenset({80, 443})
"""Nur die üblichen Ports.

Nicht aus Ordnungsliebe: Ein Abruf auf ``:6379`` oder ``:5432`` ist kein
Webseitenabruf, sondern der Versuch, mit einem anderen Dienst zu sprechen. Dass
die Antwort für einen HTTP-Client unbrauchbar ist, hilft nichts — gesendet
wurde sie trotzdem, und manche Dienste führen aus, was in einer solchen
Anfrage steht."""

MAX_WEITERLEITUNGEN = 3
STANDARD_TIMEOUT = 10.0


def adresse_pruefen(url: str) -> tuple[str, str, int]:
    """Prüft eine Adresse und löst ihren Namen auf.

    Rückgabe: Schema, Hostname, Port — für den Aufrufer, der danach verbindet.
    Wirft ``WebAccessDenied``, wenn irgendetwas daran nicht öffentlich ist.

    **Die Reihenfolge ist bedeutungstragend**: erst die billigen Prüfungen auf
    der Zeichenkette, dann die Auflösung. Ein Aufruf, der schon am Schema
    scheitert, soll keinen DNS-Server befragen — auch eine Namensauflösung ist
    eine Auskunft nach außen.
    """
    zerlegt = urlparse(url)

    if zerlegt.scheme not in ERLAUBTE_SCHEMATA:
        raise WebAccessDenied(
            f"Nur {', '.join(sorted(ERLAUBTE_SCHEMATA))} sind zugelassen, nicht "
            f"{zerlegt.scheme or 'ohne Schema'!r}. "
            "``file://`` läse das Dateisystem, ``gopher://`` spräche mit beliebigen Diensten."
        )

    host = zerlegt.hostname
    if not host:
        raise WebAccessDenied("Die Adresse nennt keinen Host.")

    port = zerlegt.port or (443 if zerlegt.scheme == "https" else 80)
    if port not in ERLAUBTE_PORTS:
        raise WebAccessDenied(
            f"Port {port} ist nicht zugelassen. Ein Abruf außerhalb von 80 und 443 ist "
            "kein Webseitenabruf, sondern ein Gespräch mit einem anderen Dienst."
        )

    for adresse in _aufloesen(host):
        if not _oeffentlich(adresse):
            raise WebAccessDenied(
                f"{host!r} zeigt auf {adresse.compressed} — das ist keine öffentliche "
                "Adresse. Abgefragt wird von diesem Server aus, und was von hier aus "
                "erreichbar ist, ist mehr als das, was aus dem Internet erreichbar ist."
            )

    return zerlegt.scheme, host, port


def _aufloesen(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Alle Adressen eines Namens — nicht nur die erste.

    Ein Name mit zwei Einträgen käme sonst durch, sobald einer davon öffentlich
    ist; verbunden würde danach mit irgendeiner davon.
    """
    try:
        auskunft = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as fehler:
        raise WebAccessDenied(f"{host!r} ließ sich nicht auflösen: {fehler.strerror}.") from fehler

    adressen = []
    for eintrag in auskunft:
        roh = eintrag[4][0]
        try:
            adressen.append(ipaddress.ip_address(roh))
        except ValueError:  # pragma: no cover - getaddrinfo liefert Adressen
            continue
    if not adressen:  # pragma: no cover - dito
        raise WebAccessDenied(f"{host!r} lieferte keine Adresse.")
    return adressen


def _oeffentlich(adresse: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Ist diese Adresse aus dem Internet routbar?

    ``is_global`` beantwortet genau das und deckt in einem Ausdruck ab, was
    eine Liste aus Bereichen ständig unvollständig hielte: Loopback, privates
    Netz, Link-Local (und damit ``169.254.169.254``, der Metadatendienst jedes
    Cloud-Anbieters), Multicast, reservierte Bereiche.

    Zusätzlich abgewiesen werden **IPv4-Adressen in IPv6-Kleidung**
    (``::ffff:127.0.0.1``): ``is_global`` sieht dort eine IPv6-Adresse, die
    Verbindung landet aber bei der eingebetteten IPv4.
    """
    if isinstance(adresse, ipaddress.IPv6Address):
        if adresse.ipv4_mapped is not None:
            return _oeffentlich(adresse.ipv4_mapped)
        if adresse.sixtofour is not None:
            return _oeffentlich(adresse.sixtofour)
    return adresse.is_global


class _Textsammler(HTMLParser):
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


class HttpWebFetcher(WebFetcher):
    """Ruft öffentliche Webadressen ab."""

    def __init__(self, *, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        """Ein von außen gereichter Client ist der Testeinstieg — mit
        ``MockTransport`` läuft der echte HTTP-Stack, nur die Antwort ist
        aufgezeichnet. Dieselbe Bauart wie beim Ollama-Adapter."""

    async def fetch(self, url: str, *, max_bytes: int) -> WebDocument:
        gesehen = url
        for _ in range(MAX_WEITERLEITUNGEN + 1):
            # **Vor jeder einzelnen Verbindung**, auch nach einer
            # Weiterleitung. Genau hier gehen die bequemen Fassungen kaputt.
            adresse_pruefen(gesehen)

            antwort = await self._holen(gesehen, max_bytes=max_bytes)
            if isinstance(antwort, str):
                gesehen = antwort
                continue
            return antwort

        raise WebAccessDenied(
            f"Mehr als {MAX_WEITERLEITUNGEN} Weiterleitungen. Eine Kette, die nicht endet, "
            "ist entweder kaputt oder ein Versuch, die Prüfung zu ermüden."
        )

    async def _holen(self, url: str, *, max_bytes: int) -> WebDocument | str:
        """Eine Runde: Dokument — oder die nächste Adresse einer Weiterleitung."""
        async with self._session() as client:
            try:
                async with client.stream(
                    "GET",
                    url,
                    timeout=STANDARD_TIMEOUT,
                    follow_redirects=False,
                    headers={"user-agent": "jarvis/0.1 (+lokal)"},
                ) as antwort:
                    if antwort.is_redirect:
                        ziel = antwort.headers.get("location")
                        if not ziel:
                            raise WebUnavailable("Weiterleitung ohne Ziel.")
                        return str(httpx.URL(url).join(ziel))

                    if antwort.status_code >= 400:
                        raise WebUnavailable(f"{url} antwortete mit {antwort.status_code}.")

                    roh, gekuerzt = await self._lesen(antwort, max_bytes)
            except httpx.HTTPError as fehler:
                raise WebUnavailable(
                    f"{url} nicht erreichbar: {type(fehler).__name__}."
                ) from fehler

        typ = antwort.headers.get("content-type", "")
        return self._auswerten(str(antwort.url), roh, typ, gekuerzt)

    @staticmethod
    async def _lesen(antwort: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
        """Liest höchstens ``max_bytes`` — und hört dann auf.

        **Die Grenze steht im Lesen und nicht danach.** ``content-length`` zu
        prüfen wäre wirkungslos: Der Wert ist eine Behauptung des Servers, und
        ein Server, der eine Antwort ohne Ende schickt, füllt sonst den
        Arbeitsspeicher dieses Prozesses.
        """
        stuecke = bytearray()
        async for block in antwort.aiter_bytes():
            stuecke.extend(block)
            if len(stuecke) > max_bytes:
                return bytes(stuecke[:max_bytes]), True
        return bytes(stuecke), False

    @staticmethod
    def _auswerten(url: str, roh: bytes, content_type: str, gekuerzt: bool) -> WebDocument:
        text = roh.decode("utf-8", errors="replace")
        if "html" not in content_type.lower():
            # Alles, was nicht HTML ist, geht als Text durch — JSON, Klartext.
            # Ein Bild oder PDF landet damit als Zeichensalat im Kontext; das
            # ist unschön und ehrlich. Formaterkennung gehört in einen eigenen
            # Block, nicht in eine stille Sonderbehandlung hier.
            return WebDocument(url=url, text=text.strip(), truncated=gekuerzt)

        sammler = _Textsammler()
        sammler.feed(text)
        return WebDocument(
            url=url,
            title=" ".join("".join(sammler.titel).split()),
            text="\n".join(sammler.stuecke),
            truncated=gekuerzt,
        )

    def _session(self) -> httpx.AsyncClient | _Geliehen:
        if self._client is not None:
            return _Geliehen(self._client)
        return httpx.AsyncClient()


class _Geliehen:
    """Reicht einen fremden Client durch, ohne ihn zu schließen."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def __aenter__(self) -> httpx.AsyncClient:
        return self._client

    async def __aexit__(self, *_: object) -> None:
        return None
