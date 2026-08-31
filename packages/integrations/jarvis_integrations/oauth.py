"""Tokentausch über HTTP. Erfüllt ``TokenExchange``.

**Warum dieser Adapter weniger Adressprüfung braucht als ``web.fetch`` — und
warum das keine Nachlässigkeit ist.** Dort nennt ein Modell die Adresse; hier
steht sie in der Konfiguration und wird von keinem Request berührt. Der
Unterschied ist nicht die Sorgfalt, sondern wer die Adresse bestimmt. Was
dieser Adapter dafür sendet, wiegt schwerer: das Client-Geheimnis. Eine aus
einem Request übernommene Token-Adresse wäre der kürzeste Weg, es einem
Fremden zuzustellen — deshalb ist ``OAuthProvider.token_url`` Konfiguration
und kein Parameter.

**Zur Kennung des Kontos aus dem ``id_token``.** Sie wird gelesen, ohne die
Signatur zu prüfen, und das ist die Stelle, an der ein Leser zu Recht stutzt.
Der Grund ist die Herkunft: Dieses Token kommt **nicht** über den Browser,
sondern aus der Antwort auf eine TLS-gesicherte POST-Anfrage an die
konfigurierte Adresse des Anbieters — OpenID Connect erlaubt einem Client
genau dort, auf die Signaturprüfung zu verzichten (Core 1.0 §3.1.3.7). Wer
denselben Wert aus einem Redirect entgegennähme, müsste prüfen; das tut hier
niemand. **Die Bedingung steht in einer Zusicherung im Code**, nicht nur in
diesem Absatz: Der Aufrufer kann keine andere Quelle unterschieben.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx

from jarvis_core.ports.oauth import (
    AuthorizationRevoked,
    OAuthProvider,
    TokenExchangeFailed,
    TokenSet,
)

__all__ = ["HttpTokenExchange"]

ZEITLIMIT = 15.0
"""Sekunden. Ein Tokentausch, der länger dauert, ist kein langsamer Erfolg —
er ist ein Ausfall, und der Nutzer wartet währenddessen auf einer
Rückrufseite."""

VORHALT = timedelta(seconds=60)
"""Wird von der Gültigkeit abgezogen.

Zwischen der Antwort des Anbieters und dem Moment, in dem ein Aufruf mit
diesem Token tatsächlich hinausgeht, liegt Zeit. Ein Token, der als „gültig
bis genau jetzt" verbucht wird, ist bei jedem Grenzfall abgelaufen, bevor er
ankommt. Lieber eine Minute zu früh erneuern als einen Aufruf verlieren.
"""


class HttpTokenExchange:
    """Löst Autorisierungscodes und Erneuerungstokens beim Anbieter ein."""

    def __init__(self, *, uhr: Callable[[], datetime] | None = None) -> None:
        self._uhr = uhr or (lambda: datetime.now(tz=UTC))

    async def tauschen(self, provider: OAuthProvider, *, code: str, verifier: str) -> TokenSet:
        return await self._anfragen(
            provider,
            {
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": provider.redirect_uri,
            },
            erwartet_identitaet=True,
        )

    async def erneuern(self, provider: OAuthProvider, *, refresh_token: str) -> TokenSet:
        return await self._anfragen(
            provider,
            {"grant_type": "refresh_token", "refresh_token": refresh_token},
            erwartet_identitaet=False,
        )

    async def _anfragen(
        self,
        provider: OAuthProvider,
        felder: dict[str, str],
        *,
        erwartet_identitaet: bool,
    ) -> TokenSet:
        nutzlast = {
            **felder,
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
        }
        try:
            async with httpx.AsyncClient(timeout=ZEITLIMIT) as client:
                antwort = await client.post(provider.token_url, data=nutzlast)
        except httpx.HTTPError as fehler:  # pragma: no cover - Netzfehler
            raise TokenExchangeFailed(f"{provider.name}: nicht erreichbar") from fehler

        if antwort.status_code != httpx.codes.OK:
            # Der Text des Anbieters geht **nicht** in die Ausnahme. Er landete
            # sonst in einem Protokoll, und manche Anbieter spiegeln in ihrer
            # Fehlermeldung zurück, was man geschickt hat — einschließlich des
            # Codes und, bei einer falsch gebauten Anfrage, des Geheimnisses.
            #
            # Gelesen wird genau **ein** Feld: der Fehlercode aus RFC 6749
            # §5.2. Er ist eine feste Aufzählung und kein freier Text, und er
            # entscheidet, ob ein Konto gleich tot ist oder nur gerade nicht
            # erreichbar. Alles andere aus der Antwort bleibt liegen.
            if _ist_ungueltiger_grant(antwort):
                raise AuthorizationRevoked(f"{provider.name}: Zustimmung besteht nicht mehr")
            raise TokenExchangeFailed(f"{provider.name}: HTTP {antwort.status_code}")

        try:
            daten = antwort.json()
        except ValueError as fehler:
            raise TokenExchangeFailed(f"{provider.name}: Antwort ist kein JSON") from fehler
        if not isinstance(daten, dict):
            raise TokenExchangeFailed(f"{provider.name}: Antwort ist kein Objekt")

        access = daten.get("access_token")
        if not isinstance(access, str) or not access:
            raise TokenExchangeFailed(f"{provider.name}: kein access_token")

        refresh = daten.get("refresh_token")
        if refresh is not None and not isinstance(refresh, str):
            raise TokenExchangeFailed(f"{provider.name}: refresh_token ist keine Zeichenkette")

        gilt = daten.get("expires_in")
        if not isinstance(gilt, int) or isinstance(gilt, bool) or gilt <= 0:
            # Kein Vorgabewert. Ein geratenes „eine Stunde" wäre eine Aussage
            # dieses Repositorys über die Frist eines fremden Anbieters, und
            # sie stünde danach in einer Zeile, die aussieht wie eine Auskunft.
            raise TokenExchangeFailed(f"{provider.name}: kein brauchbares expires_in")

        # ``scope`` fehlt, wenn der Anbieter genau das Gefragte bewilligt hat —
        # dann und nur dann ist der Wunsch die Bewilligung.
        roh_scopes = daten.get("scope")
        if isinstance(roh_scopes, str) and roh_scopes.strip():
            bewilligt = tuple(roh_scopes.split())
        elif roh_scopes is None:
            bewilligt = provider.scopes
        else:
            raise TokenExchangeFailed(f"{provider.name}: scope ist keine Zeichenkette")

        if erwartet_identitaet:
            kennung, name = _identitaet(provider, daten.get("id_token"))
        else:
            kennung, name = "", ""

        return TokenSet(
            access_token=access,
            refresh_token=refresh,
            access_expires_at=self._uhr() + timedelta(seconds=gilt) - VORHALT,
            granted_scopes=bewilligt,
            external_id=kennung,
            display_label=name,
        )


def _identitaet(provider: OAuthProvider, id_token: object) -> tuple[str, str]:
    """Liest ``sub`` und eine Anzeige aus dem ``id_token``.

    Ohne Signaturprüfung — zulässig, weil dieser Wert aus der direkten
    TLS-Antwort des Token-Endpunkts stammt (siehe Modulkopf). Geprüft wird
    dafür die **Form**: Was hier ankommt, muss ein JWT mit einem lesbaren
    Nutzteil und einem nicht leeren ``sub`` sein.
    """
    if not isinstance(id_token, str) or not id_token:
        raise TokenExchangeFailed(f"{provider.name}: kein id_token, Konto nicht identifizierbar")

    teile = id_token.split(".")
    if len(teile) != 3:
        raise TokenExchangeFailed(f"{provider.name}: id_token ist kein JWT")

    rumpf = teile[1]
    try:
        roh = base64.urlsafe_b64decode(rumpf + "=" * (-len(rumpf) % 4))
        nutzteil = json.loads(roh)
    except (binascii.Error, ValueError) as fehler:
        raise TokenExchangeFailed(f"{provider.name}: id_token nicht lesbar") from fehler

    if not isinstance(nutzteil, dict):
        raise TokenExchangeFailed(f"{provider.name}: id_token ohne Objekt")

    sub = nutzteil.get("sub")
    if not isinstance(sub, str) or not sub:
        raise TokenExchangeFailed(f"{provider.name}: id_token ohne sub")

    # Die Anzeige ist Beiwerk und darf fehlen; die Kennung nicht. Ein Konto
    # ohne Anzeige ist unhandlich, ein Konto ohne Kennung ist nicht
    # unterscheidbar — und der Eindeutigkeitsschlüssel hängt daran.
    for feld in ("email", "name", "preferred_username"):
        wert = nutzteil.get(feld)
        if isinstance(wert, str) and wert:
            return sub, wert
    return sub, sub


def _ist_ungueltiger_grant(antwort: httpx.Response) -> bool:
    """Sagt der Anbieter, dass es die Zustimmung nicht mehr gibt?

    Nur bei **400**, und nur beim Code ``invalid_grant``. Ein 401 heißt, dass
    unsere Client-Zugangsdaten nicht stimmen — das ist ein Fehler auf dieser
    Seite und darf kein Konto für tot erklären; sonst räumte eine falsch
    eingetragene ``GOOGLE_CLIENT_SECRET`` reihenweise gesunde Verbindungen ab.
    """
    if antwort.status_code != httpx.codes.BAD_REQUEST:
        return False
    try:
        daten = antwort.json()
    except ValueError:
        return False
    return isinstance(daten, dict) and daten.get("error") == "invalid_grant"
