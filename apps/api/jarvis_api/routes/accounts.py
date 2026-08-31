"""Konten verbinden — Zustimmung, Rückruf, Übersicht, Trennung.

**Der Rückruf ist der einzige Endpunkt dieses Systems, den ein Fremder
auslöst.** Alles andere kommt von der eigenen Oberfläche; hier schickt ein
Anbieter den Browser des Nutzers zurück, mit zwei Zeichenketten in der Adresse.
Daraus folgt der Zuschnitt dieser Datei:

1. **Der Rückruf braucht trotzdem eine Sitzung.** Er ist kein anonymer
   Endpunkt. Wer ohne Anmeldung zurückkommt, bekommt 401 — und das ist keine
   Härte gegen den Nutzer, sondern die Bedingung, unter der Punkt 2 überhaupt
   etwas prüfen kann.
2. **Der Vorgang gehört der Sitzung, die ihn begonnen hat.** ``user_id`` steht
   in derselben Anweisung, die den ``state`` verbraucht. Ohne diese Bedingung
   wäre der Ablauf gegen den bekanntesten Angriff auf OAuth offen: Der
   Angreifer beginnt bei sich, bringt seinen Rückruf in den Browser des Opfers
   und hängt **sein** Postfach an **dessen** Konto.
3. **Was der Anbieter bewilligt hat, steht in seiner Antwort** — nicht in
   unserer Anfrage. Gespeichert wird die Bewilligung.

**Was hier bewusst nicht passiert: ein Werkzeug entsteht nicht.** Ein
verbundenes Konto ist kein Recht. Ob ein Lauf das Postfach lesen darf, klärt
weiterhin die Policy über einen Scope, den der Nutzer erteilt. Die Verbindung
ist die technische Möglichkeit, die Berechtigung ist die Erlaubnis — und die
beiden zusammenzulegen wäre die stille Rechteerteilung, gegen die der ganze
Sockel gebaut ist.
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlencode
from uuid import UUID

import structlog
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from jarvis_api.db.account_store import VerbundenesKonto
from jarvis_api.deps import (
    Accounts,
    Authorizations,
    Credentials,
    CurrentSession,
    TokenDienst,
    Tokens,
)
from jarvis_api.oauth import oauth_providers
from jarvis_api.settings import get_settings
from jarvis_api.token_service import KeinZugang
from jarvis_api.tokenbuendel import buendeln
from jarvis_core.clock import utc_now
from jarvis_core.crypto import pkce_challenge
from jarvis_core.ports.oauth import TokenExchangeFailed

__all__ = ["router"]

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/accounts", tags=["accounts"])


class AuthorizeResponse(BaseModel):
    """Wohin der Browser als Nächstes geht."""

    authorization_url: str


class AccountRow(BaseModel):
    id: UUID
    provider: str
    display_label: str
    granted_scopes: list[str]
    """Die **Bewilligung**, nicht der Wunsch. Eine Oberfläche, die den Wunsch
    zeigte, behauptete Fähigkeiten, die beim ersten Aufruf fehlen."""
    status: str
    last_error: str | None
    """Steht in der Antwort, weil der Nutzer sonst nur „expired" sieht und
    nicht, ob er neu zustimmen muss oder ob nur das Netz klemmte."""
    connected_at: datetime


class CallbackResponse(BaseModel):
    account_id: UUID
    provider: str
    granted_scopes: list[str]


@router.post("/{provider}/authorize", response_model=AuthorizeResponse)
async def authorize(
    provider: str,
    session: CurrentSession,
    autorisierungen: Authorizations,
) -> AuthorizeResponse:
    """Beginnt einen Zustimmungsvorgang und gibt die Adresse des Anbieters.

    Die Adresse wird **zurückgegeben und nicht angesteuert**: Ein 307 von einem
    ``POST`` ist für eine SPA unbrauchbar, und wichtiger — der Aufrufer soll
    sehen, wohin er geschickt wird, bevor es passiert.
    """
    katalog = oauth_providers(get_settings())
    beschreibung = katalog.get(provider)
    if beschreibung is None:
        # 404 und nicht 501: Aus Sicht des Aufrufers gibt es diesen Anbieter in
        # dieser Installation nicht. Ob er unbekannt oder nur unkonfiguriert
        # ist, ist eine Auskunft über den Server und geht ihn nichts an.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unbekannter Anbieter")

    angefangen = await autorisierungen.anlegen(
        session.user_id,
        provider=provider,
        scopes=beschreibung.scopes,
        jetzt=utc_now(),
    )

    frage = {
        "response_type": "code",
        "client_id": beschreibung.client_id,
        "redirect_uri": beschreibung.redirect_uri,
        "scope": " ".join(beschreibung.scopes),
        "state": angefangen.state,
        "code_challenge": pkce_challenge(angefangen.verifier),
        "code_challenge_method": "S256",
        # Ohne beides gibt Google bei einer **wiederholten** Zustimmung keinen
        # Erneuerungstoken heraus. Das ist kein Feinschliff: Ein Konto ohne
        # Erneuerungstoken ist nach einer Stunde tot, und der Fehler zeigt
        # sich erst dann — lange nachdem jemand das Verbinden für erledigt
        # gehalten hat.
        "access_type": "offline",
        "prompt": "consent",
    }
    log.info("konto.zustimmung.begonnen", provider=provider, user_id=str(session.user_id))
    return AuthorizeResponse(authorization_url=f"{beschreibung.authorize_url}?{urlencode(frage)}")


@router.get("/callback", response_model=CallbackResponse)
async def callback(
    session: CurrentSession,
    autorisierungen: Authorizations,
    konten: Accounts,
    zugangsdaten: Credentials,
    tausch: Tokens,
    code: str = Query(min_length=1, max_length=2048),
    state: str = Query(min_length=1, max_length=512),
) -> CallbackResponse:
    """Löst den Vorgang ein und legt das Konto an.

    **Die Reihenfolge ist die Aussage dieser Funktion.** Erst wird der
    ``state`` verbraucht, dann getauscht. Andersherum wäre bequemer — ein
    fehlgeschlagener Tausch ließe den Vorgang wiederholbar — und wäre genau
    die Lücke: Ein abgefangener Code hätte beliebig viele Versuche, und zwei
    gleichzeitige Rückrufe bekämen beide ihren Tausch.
    """
    jetzt = utc_now()
    vorgang = await autorisierungen.einloesen(state, user_id=session.user_id, jetzt=jetzt)
    if vorgang is None:
        # Eine Meldung für vier Lagen (unbekannt, fremd, verbraucht,
        # abgelaufen). Eine feinere Auskunft verriete einem Angreifer, ob sein
        # untergeschobener Rückruf beim Opfer angekommen ist.
        log.warning("konto.rueckruf.abgewiesen", user_id=str(session.user_id))
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Vorgang nicht einlösbar")

    beschreibung = oauth_providers(get_settings()).get(vorgang.provider)
    if beschreibung is None:
        # Der Anbieter ist zwischen Start und Rückruf aus der Konfiguration
        # verschwunden. Selten, aber kein Grund für einen 500: Der Vorgang ist
        # verbraucht, und das soll er bleiben.
        raise HTTPException(status.HTTP_409_CONFLICT, "Anbieter nicht mehr konfiguriert")

    try:
        tokens = await tausch.tauschen(beschreibung, code=code, verifier=vorgang.verifier)
    except TokenExchangeFailed as fehler:
        log.warning("konto.tausch.gescheitert", provider=vorgang.provider, grund=str(fehler))
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, "Der Anbieter hat den Code nicht eingelöst"
        ) from fehler

    account_id = await konten.verbinden(
        session.user_id,
        provider=vorgang.provider,
        external_id=tokens.external_id,
        display_label=tokens.display_label,
        granted_scopes=tokens.granted_scopes,
    )

    # Der Erneuerungstoken zuerst — er ist der langlebige. Was hier abgelegt
    # wird, ist beides in einem Datensatz: Ein Zugriffstoken ohne seinen
    # Erneuerungstoken ist nach einer Stunde wertlos, und zwei getrennte
    # Datensätze könnten auseinanderlaufen.
    await zugangsdaten.speichern(
        account_id,
        token=buendeln(tokens.access_token, tokens.refresh_token),
        gilt_bis=tokens.access_expires_at,
    )

    log.info(
        "konto.verbunden",
        provider=vorgang.provider,
        account_id=str(account_id),
        bewilligt=list(tokens.granted_scopes),
        gefragt=list(vorgang.requested_scopes),
    )
    return CallbackResponse(
        account_id=account_id,
        provider=vorgang.provider,
        granted_scopes=list(tokens.granted_scopes),
    )


@router.get("", response_model=list[AccountRow])
async def list_accounts(session: CurrentSession, konten: Accounts) -> list[AccountRow]:
    return [_zeile(k) for k in await konten.liste(session.user_id)]


@router.post("/{account_id}/refresh", response_model=AccountRow)
async def refresh(
    account_id: UUID,
    session: CurrentSession,
    konten: Accounts,
    dienst: TokenDienst,
) -> AccountRow:
    """Erneuert die Zugangsdaten von Hand.

    **Der Token steht nicht in der Antwort, und das ist kein Versehen.** Er
    verließe damit den Server und läge im Speicher eines Browsers, in einem
    Netzwerk-Panel, womöglich in einem Protokoll — ausgerechnet der Wert, den
    ADR-008 in der Datenbank versiegelt. Was der Aufrufer bekommt, ist der
    Zustand des Kontos: Hat es geklappt, steht es wieder auf ``active``.

    Der Endpunkt ist die Reparatur für den Menschen, der ein Konto auf
    ``expired`` sieht. Im Betrieb erneuert der Dienst von selbst, wenn ein
    Aufruf einen Token braucht.
    """
    konto = await konten.laden(account_id, user_id=session.user_id)
    if konto is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Kein solches Konto")

    beschreibung = oauth_providers(get_settings()).get(konto.provider)
    if beschreibung is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Anbieter nicht mehr konfiguriert")

    try:
        await dienst.zugang(konto, provider=beschreibung, jetzt=utc_now(), erzwingen=True)
    except KeinZugang as fehler:
        # 409 und nicht 502: Der Aufruf war richtig, das Konto ist es nicht
        # (mehr). Der Grund steht am Konto, das die Liste ohnehin zeigt —
        # hier ihn zu wiederholen hieße, ihn an zwei Stellen zu pflegen.
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Die Zugangsdaten liessen sich nicht erneuern"
        ) from fehler

    erneuert = await konten.laden(account_id, user_id=session.user_id)
    assert erneuert is not None  # gerade geladen, und getrennt wird nur über /accounts
    return _zeile(erneuert)


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
async def disconnect(account_id: UUID, session: CurrentSession, konten: Accounts) -> None:
    """Trennt die Verbindung — und nimmt die Zugangsdaten mit.

    **Was das nicht leistet, gehört gesagt:** Beim Anbieter bleibt die
    Zustimmung bestehen. Ein Widerruf dort ist ein eigener Aufruf gegen eine
    eigene Adresse, und ihn nur zu behaupten wäre schlimmer als ihn zu
    unterlassen — der Nutzer hielte sein Postfach für gelöst, während die
    Zustimmung weiterläuft.
    """
    if not await konten.trennen(account_id, user_id=session.user_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Kein solches Konto")
    log.info("konto.getrennt", account_id=str(account_id), user_id=str(session.user_id))


def _zeile(konto: VerbundenesKonto) -> AccountRow:
    return AccountRow(
        id=konto.id,
        provider=konto.provider,
        display_label=konto.display_label,
        granted_scopes=list(konto.granted_scopes),
        status=konto.status,
        last_error=konto.last_error,
        connected_at=konto.created_at,
    )
