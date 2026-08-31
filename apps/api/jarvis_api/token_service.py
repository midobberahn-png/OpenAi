"""Einen gültigen Zugriffstoken beschaffen — und höchstens einmal gleichzeitig.

**Wozu es diesen Dienst gibt.** Ein Zugriffstoken lebt eine Stunde, ein
Erneuerungstoken Monate. Jeder Aufruf gegen den Anbieter braucht deshalb
vorher dieselbe Frage: *Ist der noch gut, und wenn nicht, hol einen neuen.*
Diese Frage an jeder Aufrufstelle zu beantworten hieße, sie an jeder
Aufrufstelle **verschieden** zu beantworten.

**Die tragende Entscheidung: ein Refresh je Konto, nicht zwei.**

Der harmlose Fall ist die Verschwendung — zwei gleichzeitige Aufrufe finden
denselben abgelaufenen Token und fragen beide nach. Der teure Fall ist ein
Anbieter, der den Erneuerungstoken **rotiert**: Dann entwertet die erste
Antwort den Token, mit dem die zweite Anfrage gerade unterwegs ist. Die zweite
bekommt ``invalid_grant`` — und würde das Konto für tot erklären, obwohl die
erste es gerade erneuert hat. **Aus zwei erfolgreichen Absichten wird ein
kaputtes Konto.**

Google rotiert heute nicht; OAuth 2.1 empfiehlt es, und andere Anbieter tun
es. Der Schaden entsteht nicht, wenn wir den Anbieter wechseln, sondern wenn
er seine Praxis ändert — ohne dass jemand hier etwas anfasst.

**Serialisiert wird mit einem Advisory Lock, nicht mit einer Anspruchsspalte.**
Das ist die Ausnahme vom Muster, das sonst überall in diesem Projekt steht,
und sie hat einen Grund: Ein Anspruch mit Frist braucht eine Frist, und die
wäre hier zu raten. Wer sie zu kurz setzt, hat zwei Refreshes; wer sie zu lang
setzt, blockiert ein Konto nach einem Absturz minutenlang. Ein
``pg_advisory_xact_lock`` fällt beim Ende der Transaktion, auch beim Absturz,
und **der Verlierer wartet statt zu pollen** — er findet danach den frischen
Token vor, statt selbst einen zu holen.

**Was das kostet, und warum es hier vertretbar ist:** Eine Verbindung bleibt
für die Dauer des Anbieteraufrufs belegt, begrenzt durch dessen Zeitlimit von
15 Sekunden. Bei einem System mit einem Nutzer und einer Handvoll Konten ist
das der richtige Tausch; bei tausend gleichzeitigen Refreshes wäre es der
falsche, und dann gehört der Refresh in den zweiten Prozess.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.account_store import PostgresAccountStore, VerbundenesKonto
from jarvis_api.db.credential_store import PostgresCredentialStore
from jarvis_api.tokenbuendel import buendeln, zerlegen
from jarvis_core.ports.oauth import (
    AuthorizationRevoked,
    OAuthProvider,
    TokenExchange,
    TokenExchangeFailed,
)

__all__ = ["KeinZugang", "TokenService", "Zugang"]

log = structlog.get_logger(__name__)

_SPERRE = text("SELECT pg_advisory_xact_lock(hashtext(:schluessel))")
"""Ein Schloss je Konto, abgeleitet aus seiner Kennung.

``hashtext`` liefert 32 Bit — Kollisionen sind also möglich, und sie sind
folgenlos: Zwei Konten, die sich ein Schloss teilen, warten gelegentlich
aufeinander. Das ist ein Verlust an Nebenläufigkeit, keiner an Richtigkeit.
Der umgekehrte Fehler — zwei Konten, die dasselbe Schloss brauchen und keins
bekommen — kann bei einem Hash nicht auftreten.
"""


class KeinZugang(Exception):
    """Für dieses Konto gibt es keinen brauchbaren Zugriffstoken.

    Deckt beides ab: Die Zustimmung besteht nicht mehr, oder der Anbieter war
    gerade nicht erreichbar. Was davon zutraf, steht am Konto — ``status`` und
    ``last_error`` —, und zwar dort, weil es eine Auskunft an den **Nutzer**
    ist und nicht an den Aufrufer, der gerade eine Mail lesen wollte.
    """


@dataclass(frozen=True, slots=True)
class Zugang:
    access_token: str
    gilt_bis: datetime


class TokenService:
    def __init__(
        self,
        engine: AsyncEngine,
        *,
        konten: PostgresAccountStore,
        zugangsdaten: PostgresCredentialStore,
        tausch: TokenExchange,
    ) -> None:
        self._engine = engine
        self._konten = konten
        self._zugangsdaten = zugangsdaten
        self._tausch = tausch

    async def zugang(
        self,
        konto: VerbundenesKonto,
        *,
        provider: OAuthProvider,
        jetzt: datetime,
        erzwingen: bool = False,
    ) -> Zugang:
        """Liefert einen gültigen Zugriffstoken, erneuert falls nötig.

        Das Konto wird **übergeben und nicht anhand einer Kennung geladen**:
        Wer es lädt, hat die Zugehörigkeit geprüft, und diese Signatur soll
        keinen zweiten Ladeweg anbieten, an dem sie fehlen könnte.

        ``erzwingen`` ist für die Reparatur von Hand da — der Nutzer sieht ein
        Konto auf ``error`` und drückt auf „neu verbinden". Ohne den Schalter
        müsste er warten, bis der Token von selbst abläuft.
        """
        async with self._engine.begin() as conn:
            # Alles Weitere steht **innerhalb** dieser Transaktion, und das ist
            # der Punkt: Wer draußen prüft und drinnen erneuert, hat zwischen
            # beidem wieder das Fenster, das die Sperre schließen soll.
            await conn.execute(_SPERRE, {"schluessel": f"oauth-refresh:{konto.id}"})

            vorhanden = await self._zugangsdaten.lesen(konto.id)
            if vorhanden is None:
                raise KeinZugang(f"Konto {konto.id} hat keine Zugangsdaten")

            klartext, gilt_bis = vorhanden
            access, refresh = zerlegen(klartext)

            if not erzwingen and gilt_bis > jetzt:
                # Der Verlierer eines Wettlaufs landet genau hier: Er hat auf
                # die Sperre gewartet, und inzwischen liegt ein frischer Token.
                return Zugang(access_token=access, gilt_bis=gilt_bis)

            if refresh is None:
                # Ohne Erneuerungstoken ist nichts zu holen. Das ist kein
                # Fehler des Anbieters, sondern eine Lage, die entsteht, wenn
                # er ihn bei einer wiederholten Zustimmung nicht noch einmal
                # herausgibt — und sie ist endgültig, bis der Nutzer neu
                # zustimmt.
                await self._konten.markieren(
                    konto.id, status="expired", fehler="Kein Erneuerungstoken vorhanden"
                )
                raise KeinZugang(f"Konto {konto.id} hat keinen Erneuerungstoken")

            return await self._erneuern(konto, provider=provider, refresh_token=refresh)

    async def _erneuern(
        self, konto: VerbundenesKonto, *, provider: OAuthProvider, refresh_token: str
    ) -> Zugang:
        try:
            neu = await self._tausch.erneuern(provider, refresh_token=refresh_token)
        except AuthorizationRevoked as fehler:
            # Endgültig. Das Konto bleibt stehen, damit der Nutzer sieht, was
            # zu tun ist — gelöscht wird es nicht: Ein verschwundenes Konto
            # sieht aus wie ein Fehler der Anwendung.
            await self._konten.markieren(
                konto.id, status="expired", fehler="Die Zustimmung besteht nicht mehr"
            )
            log.warning("konto.zustimmung.weg", account_id=str(konto.id))
            raise KeinZugang(str(fehler)) from fehler
        except TokenExchangeFailed as fehler:
            # **Vorübergehend — und deshalb bleibt der Status, wie er war.**
            # Ein Netzfehler sagt nichts über die Zustimmung. Wer das Konto
            # hier auf „abgelaufen" setzt, macht aus einer Störung einen
            # Verlust, und der Nutzer stimmt neu zu, obwohl nichts kaputt war.
            log.warning("konto.erneuerung.gestoert", account_id=str(konto.id))
            raise KeinZugang(str(fehler)) from fehler

        # **Der Erneuerungstoken bleibt, wenn der Anbieter keinen neuen gibt.**
        # Die meisten schicken bei einem Refresh nur den Zugriffstoken zurück.
        # Wer dann ``None`` speichert, hat das Konto beim übernächsten Mal
        # verloren — und der Fehler zeigt sich Stunden später als „Zustimmung
        # besteht nicht mehr".
        behalten = neu.refresh_token or refresh_token

        await self._zugangsdaten.speichern(
            konto.id,
            token=buendeln(neu.access_token, behalten),
            gilt_bis=neu.access_expires_at,
        )
        if konto.status != "active":
            await self._konten.markieren(konto.id, status="active", fehler=None)

        log.info("konto.erneuert", account_id=str(konto.id), gilt_bis=str(neu.access_expires_at))
        return Zugang(access_token=neu.access_token, gilt_bis=neu.access_expires_at)
