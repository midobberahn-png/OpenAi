"""Port des Tokentauschs — die eine Stelle, an der ein Anbieter antwortet.

**Warum hier ein Port steht und beim Zugangsdatenspeicher keiner.** Der
Speicher schreibt in unsere eigene Datenbank; er ist prüfbar, indem man
nachsieht. Der Tausch redet mit einem fremden Server, und was der antwortet,
bestimmt, welches Konto danach als verbunden gilt. Ein Port trennt genau das:
Die Regeln des Ablaufs lassen sich gegen eine Attrappe vollständig prüfen —
auch der Angriff, bei dem der Anbieter etwas anderes zurückgibt als erwartet —,
während der Adapter gegen aufgezeichnete Antworten steht. Dieselbe Aufteilung
wie bei den Modellanbietern.

**Was der Anbieter sagt, und was wir gefragt haben, sind zwei Aussagen.**
``TokenSet.granted_scopes`` kommt aus der Antwort, nicht aus der Anfrage. Ein
Nutzer kann im Zustimmungsdialog Häkchen entfernen; wer den Wunsch speichert
statt der Bewilligung, führt danach ein Konto, das mehr zu können behauptet,
als es darf — und stellt das erst beim ersten Aufruf fest, der scheitert.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

__all__ = [
    "AuthorizationRevoked",
    "OAuthProvider",
    "TokenExchange",
    "TokenExchangeFailed",
    "TokenSet",
]


class TokenExchangeFailed(Exception):
    """Der Anbieter hat den Code nicht gegen Tokens getauscht.

    Eine Ausnahme und kein ``None``: Ein abgelehnter Code ist kein
    gewöhnlicher Ausgang. Er heißt entweder, dass jemand einen fremden Code
    vorlegt, oder dass unsere Anfrage falsch war — beides gehört gesehen und
    nicht als „kein Konto" verbucht.
    """


class AuthorizationRevoked(TokenExchangeFailed):
    """Der Anbieter sagt, dass es die Zustimmung nicht mehr gibt.

    **Der Unterschied zur Oberklasse trägt eine Entscheidung, keine
    Feinheit.** Ein Refresh kann aus zwei Gründen scheitern, und sie führen zu
    entgegengesetzten Reaktionen:

    * *Der Anbieter ist nicht erreichbar, antwortet mit 500, das Zeitlimit
      läuft ab.* Dann ist über die Zustimmung **nichts** gesagt. Wer das Konto
      hier auf „abgelaufen" setzt, macht aus einer Netzstörung einen Verlust:
      Der Nutzer sieht ein totes Konto und stimmt neu zu, obwohl nichts
      kaputt war.
    * *Der Anbieter antwortet mit ``invalid_grant``.* Dann ist die Zustimmung
      weg — zurückgezogen, abgelaufen, oder der Erneuerungstoken wurde
      rotiert und wir haben den alten. Ein Wiederholen hilft nie.

    Ohne diese Trennung müsste der Aufrufer raten, und er würde in die
    vorsichtige Richtung raten — also jedes Konto bei jedem Schluckauf des
    Netzes für tot erklären.
    """


@dataclass(frozen=True, slots=True)
class OAuthProvider:
    """Ein Anbieter, wie ihn die Konfiguration beschreibt.

    **Die Adressen stehen hier und kommen nie aus einem Request.** Sie
    bestimmen, wohin der Nutzer geschickt wird und wohin dieser Prozess seine
    Zugangsdaten sendet. Eine aus dem Request übernommene Token-Adresse wäre
    der kürzeste Weg, das Client-Geheimnis an einen Fremden zu schicken —
    dieselbe Überlegung wie bei ``WEBAUTHN_ORIGINS``.
    """

    name: str
    authorize_url: str
    token_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    """Die Rückrufadresse, exakt wie beim Anbieter hinterlegt.

    Sie geht in die Anfrage **und** in den Tausch ein, und beide Male aus
    dieser Konfiguration. Der Anbieter vergleicht sie; eine aus dem Request
    übernommene Adresse machte aus dem Rückruf einen offenen Weiterleiter und
    aus dem Autorisierungscode etwas, das man sich zuschicken lassen kann.
    """
    scopes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TokenSet:
    """Was der Anbieter ausgestellt hat."""

    access_token: str
    refresh_token: str | None
    """``None`` ist zulässig und häufig: Ein Anbieter gibt den
    Erneuerungstoken oft nur bei der **ersten** Zustimmung heraus. Wer ihn
    danach erwartet und bei Abwesenheit scheitert, bricht jede zweite
    Verbindung desselben Kontos."""
    access_expires_at: datetime
    granted_scopes: tuple[str, ...]
    external_id: str
    """Die Kennung des Kontos **beim Anbieter**. Sie unterscheidet zwei
    Postfächer desselben Nutzers und ist der Teil des Eindeutigkeitsschlüssels
    ``(user_id, provider, external_id)``."""
    display_label: str


class TokenExchange(Protocol):
    """Tauscht einen Autorisierungscode gegen Tokens."""

    async def tauschen(
        self,
        provider: OAuthProvider,
        *,
        code: str,
        verifier: str,
    ) -> TokenSet:
        """Löst den Code ein.

        ``verifier`` ist der PKCE-Nachweis: Der Anbieter hat beim Start dessen
        Hash bekommen und prüft ihn hier. Wer den Code abfängt, ohne den
        Verifier zu haben, kann ihn nicht einlösen.

        Die Rückrufadresse kommt aus ``provider`` und ist kein Parameter — sie
        soll an keiner Aufrufstelle wählbar sein.
        """
        ...

    async def erneuern(self, provider: OAuthProvider, *, refresh_token: str) -> TokenSet:
        """Holt einen frischen Zugriffstoken.

        Getrennte Methode statt eines Schalters: Die beiden Vorgänge haben
        verschiedene Voraussetzungen und verschiedene Ausgänge. Ein
        abgelehnter Erneuerungstoken heißt „der Nutzer hat die Zustimmung
        zurückgezogen" — ein abgelehnter Code heißt etwas ganz anderes.
        """
        ...
