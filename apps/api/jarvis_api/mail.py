"""Das Postfach eines angemeldeten Nutzers — aufgelöst, wenn es gebraucht wird.

**Warum die Auflösung erst beim Aufruf passiert.** Der Werkzeugkatalog wird je
Request gebaut und ist synchron; das Konto zu suchen hieße, jeden Request eine
Abfrage zahlen zu lassen, die die allermeisten nicht brauchen. Dieser Leser
hält deshalb nur, was er zum Suchen benötigt, und sucht beim ersten ``lesen``.

**Die Folge, und sie gehört gesagt:** ``mail.read`` steht auch dann im
Angebot, wenn kein Konto verbunden ist. Ein Modell, das es aufruft, bekommt
eine klare Absage statt einer Ausnahme — und der Nutzer erfährt, was fehlt.
Der Weg dorthin ist ohnehin ein anderer: Ohne erteilten Scope kommt der Aufruf
gar nicht bis hierher.

**Zwei Erlaubnisse, beide notwendig.** Der Scope ``mail.read`` ist das, was der
Nutzer *diesem System* erlaubt hat, und den prüft die Policy. ``gmail.readonly``
ist das, was er *bei Google* bewilligt hat, und den prüft diese Datei — an
``granted_scopes``, also an dem, was der Anbieter zurückgemeldet hat, nicht an
dem, was wir gefragt haben. Damit bekommt das Feld aus dem Zustimmungsblock
seinen ersten Leser.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from jarvis_api.db.account_store import PostgresAccountStore, VerbundenesKonto
from jarvis_api.oauth import oauth_providers
from jarvis_api.settings import Settings
from jarvis_api.token_service import KeinZugang, TokenService
from jarvis_core.clock import utc_now
from jarvis_core.ports.mail import MailAccessDenied, MailMessage
from jarvis_integrations.gmail import GmailReader

__all__ = ["GMAIL_READONLY", "KontoGebundenerPostfachleser"]

GMAIL_READONLY = "https://www.googleapis.com/auth/gmail.readonly"
"""Googles Scope für lesenden Postfachzugriff.

Ausdrücklich der **readonly**-Scope und nicht ``gmail.modify``: Was dieses
System nicht bewilligt bekommt, kann es auch bei einem Fehler nicht anrichten.
Die engste Bewilligung, die den Zweck erfüllt, ist die richtige — und sie
steht hier neben dem Port, der ohnehin nur lesen kann."""


class KontoGebundenerPostfachleser:
    """Erfüllt ``MailReader``, gebunden an genau einen angemeldeten Nutzer."""

    def __init__(
        self,
        *,
        user_id: UUID,
        konten: PostgresAccountStore,
        dienst: Callable[[], TokenService],
        settings: Settings,
    ) -> None:
        self._user_id = user_id
        self._konten = konten
        self._dienst = dienst
        """**Eine Fabrik und kein fertiger Dienst** — und das ist keine
        Geschmacksfrage, sondern die Behebung eines Fehlers, den die erste
        Fassung hatte.

        Der Dienst braucht den KEK, um Zugangsdaten zu entsiegeln. Wurde er
        beim Bauen des Werkzeugkatalogs erzeugt, hing **jedes** Werkzeug an der
        Schlüsseldatei — auch ``files.read``, das mit Zugangsdaten nichts zu
        tun hat. Gemessen: Zwölf Tests, die den Katalog aufbauen, scheiterten
        mit ``FileNotFoundError``. Eine Installation ohne verbundene Konten
        hätte danach gar keine Werkzeuge mehr gehabt.

        Die Lehre ist allgemeiner als der Fall: **Was beim Verdrahten gebaut
        wird, wird zur Voraussetzung von allem, was daneben steht.**"""
        self._settings = settings

    async def lesen(self, *, anzahl: int, suche: str | None = None) -> list[MailMessage]:
        konto = await self._konto()
        beschreibung = oauth_providers(self._settings).get(konto.provider)
        if beschreibung is None:
            raise MailAccessDenied("Der Anbieter dieses Kontos ist nicht mehr konfiguriert")

        async def token() -> str:
            try:
                zugang = await self._dienst().zugang(konto, provider=beschreibung, jetzt=utc_now())
            except KeinZugang as fehler:
                raise MailAccessDenied(
                    "Die Zugangsdaten des Kontos gelten nicht mehr — bitte neu verbinden"
                ) from fehler
            return zugang.access_token

        return await GmailReader(token).lesen(anzahl=anzahl, suche=suche)

    async def _konto(self) -> VerbundenesKonto:
        aktive = [
            k
            for k in await self._konten.liste(self._user_id)
            if k.provider == "google" and k.status == "active"
        ]
        if not aktive:
            raise MailAccessDenied("Kein verbundenes Google-Konto")
        if len(aktive) > 1:
            # **Lieber eine Absage als eine Wahl.** Welches von zwei Postfächern
            # gemeint ist, weiß dieses System nicht, und ein Modell soll es
            # nicht raten: Es läse sonst im falschen, und niemand merkte es —
            # das Ergebnis sähe genauso aus.
            #
            # Ein Argument ``konto`` wäre der nächste Schritt und braucht einen
            # eigenen Block: Es muss benannt werden können, ohne dass ein Modell
            # eine fremde Kennung erfinden kann.
            raise MailAccessDenied(
                f"{len(aktive)} verbundene Google-Konten — mail.read kann noch nicht wählen"
            )

        konto = aktive[0]
        if GMAIL_READONLY not in konto.granted_scopes:
            # Geprüft wird die **Bewilligung**, nicht der Wunsch. Ohne diese
            # Zeile ginge die Anfrage hinaus und käme als 403 zurück — als
            # Fehler des Anbieters, obwohl er hier schon feststand.
            raise MailAccessDenied(
                "Das verbundene Konto hat den Postfachzugriff nicht bewilligt — bitte neu verbinden"
            )
        return konto
