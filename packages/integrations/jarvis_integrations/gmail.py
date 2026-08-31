"""Gmail lesen. Erfüllt ``MailReader``.

**Was dieser Adapter bekommt, ist ein Token — und zwar auf Zuruf.** Nicht die
Konto-ID, nicht der Erneuerungstoken, nicht die Anbieterkonfiguration. Die
Quelle ist eine Funktion, die bei jedem Aufruf einen gültigen Zugriffstoken
liefert und ihn dabei erneuert, falls nötig. Zwei Gründe:

1. Ein Token, den der Adapter beim Bauen bekäme, wäre nach einer Stunde alt.
   Ein Werkzeug, das nur in der ersten Stunde nach dem Verbinden funktioniert,
   ist schlimmer als keines — es geht kaputt, wenn niemand hinsieht.
2. Was der Adapter nicht hat, kann er nicht weitergeben. Ein Adapter, der ein
   Konto benennen könnte, wäre die Stelle, an der aus einem Modellargument ein
   fremdes Postfach wird.

**Die Abfrage geht über zwei Ebenen, und das ist die API, nicht die Wahl.**
``messages.list`` liefert nur Kennungen; jede Nachricht muss einzeln geholt
werden. Deshalb ist ``anzahl`` hart begrenzt: Ein Modell, das nach „allen
Mails" fragt, löst sonst hunderte Anfragen aus — langsam, teuer und beim
Anbieter auffällig.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Awaitable, Callable
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from jarvis_core.ports.mail import (
    MailAccessDenied,
    MailMessage,
    MailUnavailable,
)
from jarvis_integrations.html_text import text_aus_html

__all__ = ["MAX_NACHRICHTEN", "MAX_ZEICHEN", "GmailReader"]

BASIS = "https://gmail.googleapis.com/gmail/v1/users/me"
ZEITLIMIT = 20.0

MAX_NACHRICHTEN = 25
"""Obergrenze, unabhängig davon, was das Argument sagt.

Jede Nachricht ist eine eigene Anfrage. Die Grenze steht hier und nicht nur im
Schema: Ein Schema beschreibt, was ein Modell schicken *soll* — durchgesetzt
wird, was der Adapter tut. Dieselbe Lehre wie bei ``ToolSpec.parameters``, die
lange niemand gelesen hat."""

MAX_ZEICHEN = 20_000
"""Je Nachricht. Ein Newsletter mit 200 KB Text bringt keinem Modell mehr
Erkenntnis als seine ersten Seiten, verdrängt aber alles andere aus dem
Kontextfenster."""


class GmailReader:
    def __init__(
        self,
        token_quelle: Callable[[], Awaitable[str]],
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._token = token_quelle
        self._client = client
        """Ein von außen gereichter Client ist der Testeinstieg — dieselbe
        Bauart wie beim Webabrufer."""

    async def lesen(self, *, anzahl: int, suche: str | None = None) -> list[MailMessage]:
        begrenzt = max(1, min(anzahl, MAX_NACHRICHTEN))
        token = await self._token()

        async with self._sitzung() as client:
            kopf = {"Authorization": f"Bearer {token}"}
            frage: dict[str, str | int] = {"maxResults": begrenzt}
            if suche:
                frage["q"] = suche

            liste = await self._holen(client, f"{BASIS}/messages", kopf, frage)
            kennungen = [
                str(m["id"])
                for m in (liste.get("messages") or [])
                if isinstance(m, dict) and m.get("id")
            ]

            nachrichten = []
            for kennung in kennungen:
                roh = await self._holen(
                    client, f"{BASIS}/messages/{kennung}", kopf, {"format": "full"}
                )
                nachrichten.append(_zu_nachricht(roh))
        return nachrichten

    def _sitzung(self) -> Any:
        if self._client is not None:
            return _Geliehen(self._client)
        return httpx.AsyncClient(timeout=ZEITLIMIT)

    async def _holen(
        self,
        client: httpx.AsyncClient,
        url: str,
        kopf: dict[str, str],
        frage: dict[str, str | int],
    ) -> dict[str, Any]:
        try:
            antwort = await client.get(url, headers=kopf, params=frage)
        except httpx.HTTPError as fehler:
            raise MailUnavailable("Gmail ist nicht erreichbar") from fehler

        if antwort.status_code in (httpx.codes.UNAUTHORIZED, httpx.codes.FORBIDDEN):
            # **401 und 403 heißen hier dasselbe für den Nutzer und
            # Verschiedenes für den Betreiber**, und die Unterscheidung gehört
            # nicht in eine Fehlermeldung, die ein Modell liest: 403 kann eine
            # fehlende Google-Berechtigung sein, 401 ein Token, der zwischen
            # Erneuerung und Aufruf abgelaufen ist. Beides ist „nicht jetzt
            # lösbar" — und beides darf dem Modell nicht erzählen, wie die
            # Zugangsdaten dieses Systems aufgebaut sind.
            raise MailAccessDenied("Der Zugriff auf das Postfach wurde abgelehnt")
        if antwort.status_code != httpx.codes.OK:
            raise MailUnavailable(f"Gmail antwortete mit HTTP {antwort.status_code}")

        try:
            daten = antwort.json()
        except ValueError as fehler:
            raise MailUnavailable("Gmail antwortete nicht mit JSON") from fehler
        if not isinstance(daten, dict):
            raise MailUnavailable("Gmail antwortete nicht mit einem Objekt")
        return daten


class _Geliehen:
    """Ein geliehener Client wird **nicht** geschlossen.

    Ohne diese Hülle schlösse das ``async with`` den Client des Aufrufers, und
    der zweite Aufruf liefe gegen einen geschlossenen Transport — ein Fehler,
    der nur im Test auftritt und dort wie ein Fehler des Tests aussieht.
    """

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def __aenter__(self) -> httpx.AsyncClient:
        return self._client

    async def __aexit__(self, *_: object) -> None:
        return None


def _zu_nachricht(roh: dict[str, Any]) -> MailMessage:
    roh_nutzteil = roh.get("payload")
    nutzteil: dict[str, Any] = roh_nutzteil if isinstance(roh_nutzteil, dict) else {}
    kopfzeilen = _kopfzeilen(nutzteil)
    text = _text(nutzteil)
    gekuerzt = len(text) > MAX_ZEICHEN

    return MailMessage(
        id=str(roh.get("id", "")),
        absender=kopfzeilen.get("from", ""),
        betreff=kopfzeilen.get("subject", ""),
        datum=_datum(kopfzeilen.get("date")),
        text=text[:MAX_ZEICHEN],
        gekuerzt=gekuerzt,
    )


def _kopfzeilen(nutzteil: dict[str, Any]) -> dict[str, str]:
    ergebnis: dict[str, str] = {}
    for eintrag in nutzteil.get("headers") or []:
        if isinstance(eintrag, dict):
            name = str(eintrag.get("name", "")).lower()
            if name in {"from", "subject", "date"}:
                ergebnis[name] = str(eintrag.get("value", ""))
    return ergebnis


def _datum(roh: str | None) -> datetime | None:
    """RFC-2822-Datum, oder ``None``.

    Ein unlesbares Datum wird nicht geraten. ``parsedate_to_datetime`` wirft
    bei allerlei kaputten Kopfzeilen, und die gibt es in echten Postfächern
    reichlich — eine davon dürfte nicht das Lesen der ganzen Nachricht
    verhindern.
    """
    if not roh:
        return None
    try:
        return parsedate_to_datetime(roh)
    except (TypeError, ValueError):
        return None


def _text(nutzteil: dict[str, Any]) -> str:
    """``text/plain`` zuerst, HTML nur ersatzweise.

    Der Klartextteil ist das, was der Absender für Menschen ohne HTML gedacht
    hat — kürzer, ohne Markup und ohne die Verfolgungspixel. Erst wenn es ihn
    nicht gibt, wird das HTML ausgelesen.
    """
    klartext = _teil(nutzteil, "text/plain")
    if klartext:
        return klartext
    html = _teil(nutzteil, "text/html")
    if html:
        return text_aus_html(html)[1]
    return ""


def _teil(knoten: dict[str, Any], typ: str) -> str:
    """Sucht den ersten Teil des gesuchten MIME-Typs, rekursiv.

    Eine Mail ist ein Baum: ``multipart/mixed`` über ``multipart/alternative``
    über den eigentlichen Teilen, und ein Anhang hängt als Geschwister daneben.
    Eine Suche nur auf der ersten Ebene fände bei jeder Mail mit Anhang nichts.
    """
    if str(knoten.get("mimeType", "")).startswith(typ):
        entschluesselt = _daten(knoten.get("body"))
        if entschluesselt:
            return entschluesselt
    for kind in knoten.get("parts") or []:
        if isinstance(kind, dict):
            treffer = _teil(kind, typ)
            if treffer:
                return treffer
    return ""


def _daten(body: object) -> str:
    if not isinstance(body, dict):
        return ""
    roh = body.get("data")
    if not isinstance(roh, str) or not roh:
        return ""
    try:
        return base64.urlsafe_b64decode(roh + "=" * (-len(roh) % 4)).decode(
            "utf-8", errors="replace"
        )
    except (binascii.Error, ValueError):
        # Ein einzelner unlesbarer Teil macht die Nachricht nicht unlesbar.
        return ""
