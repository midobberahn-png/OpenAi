"""Setzt die Nutzertabelle zurück — ausschließlich für Browsertests.

Die Erstinbetriebnahme gelingt **genau einmal**: Solange ein Nutzer existiert,
weist ``POST /auth/bootstrap`` mit 409 ab. Das ist richtig so — es ist das
Zeitfenster, in dem das System noch niemandem gehört. Ein Browsertest, der die
Zeremonie durchspielen will, braucht dieses Fenster trotzdem; die
pytest-Integrationssuite räumt aus demselben Grund vor jeder Anmeldung auf.

**Warum das ein Skript ist und kein Endpunkt.** Ein Endpunkt, der Nutzer
löscht, wäre auszuliefern — und damit im Betrieb vorhanden. Kein Schalter, kein
Feature-Flag und keine Umgebungsprüfung wiegt das auf: Was es nicht gibt, kann
nicht falsch konfiguriert werden. Dieses Skript liegt außerhalb der Anwendung
und läuft nur, wenn jemand es aufruft.

**Zwei Wächter, und beide müssen zustimmen:**

* ``JARVIS_E2E_RESET=1`` — die ausdrückliche Absicht. Ein Skript, das ohne
  weiteres Zutun löscht, wird irgendwann versehentlich aufgerufen.
* ``JARVIS_ENV`` muss ``development`` sein. Die Vorgabe von ``Settings`` ist
  genau das; wer die Anwendung in Betrieb nimmt, setzt sie um — und dann
  scheitert dieses Skript, statt zu löschen.

``DELETE FROM users`` räumt über Fremdschlüssel mit ``ON DELETE CASCADE`` auch
Läufe, Berechtigungen, Sitzungen und Passkeys ab. Das Audit-Log bleibt: Es
hängt mit ``ON DELETE SET NULL`` daran und ist append-only — eine Spur, die
sich durch das Löschen ihres Urhebers beseitigen ließe, wäre keine.

**Und die Zähler der Zugriffsgrenze gehören dazu.** Die Erstinbetriebnahme ist
auf fünf Versuche je fünf Minuten begrenzt; ein Testlauf, der die Zeremonie
mehrfach durchspielt, trifft sie zuverlässig — beim Aufbau dieser Suite hat er
das getan, und der Durchgang endete mit 429 statt mit einer Anmeldung. Der
Zähler ist Teil desselben Fensters: Wer die Nutzertabelle leert, um die
Zeremonie zu wiederholen, meint auch die Grenze für ihre Wiederholung.

Zurückgesetzt werden ausschließlich die Zähler der Anmeldezeremonien
(``ratelimit:auth.*``). Alles andere in Redis bleibt unberührt.

**Und es wird gewartet, bis niemand mehr arbeitet.** Der Chat-Durchstich endet
absichtlich, während der Lauf noch läuft („ohne laufendes Modell bleibt der
Lauf stehen" — mit laufendem Modell formuliert er weiter). Der nächste Test
räumte ihm dann die Welt unter den Füßen weg: ``DELETE FROM users`` nimmt über
``ON DELETE CASCADE`` den Lauf mit, und die Hauptbuchzeile, die der noch
laufende Modellaufruf gleich schreiben will, findet ihren Fremdschlüssel nicht
mehr. Ergebnis war ein Traceback im Gate-Protokoll — sechs pro Durchgang,
gemessen — bei 21 grünen Browsertests.

Das ist kein Fehler der Anwendung: ``ModelGateway._buchen()`` sagt zu, dass
Schreibfehler durchschlagen, und genau das tat es. Es ist auch kein Zustand,
den es im Betrieb gibt — einen Endpunkt, der Nutzer löscht, gibt es nicht
(siehe oben). Es ist ein Aufräumskript, das löscht, während jemand arbeitet.

Ein Gate, das Tracebacks druckt, erzieht dazu, Tracebacks zu übersehen; das hat
dieses Projekt 45 rote CI-Läufe gekostet. Deshalb wartet dieses Skript kurz,
bevor es löscht — auf **den Anspruch**, denn den gibt es schon: Ein Lauf mit
frischem Anspruch heißt „an einem Schritt wird gerade gearbeitet". Der
absichtlich hängengelassene Lauf aus ``e2e_haengenlassen.py`` trägt seinen
Anspruch eine Stunde alt und hält deshalb niemanden auf.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from datetime import timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


async def main() -> int:
    if os.environ.get("JARVIS_E2E_RESET") != "1":
        print("Abgebrochen: JARVIS_E2E_RESET=1 fehlt.", file=sys.stderr)
        return 2

    umgebung = os.environ.get("JARVIS_ENV", "development")
    if umgebung != "development":
        print(f"Abgebrochen: JARVIS_ENV ist {umgebung!r}, nicht 'development'.", file=sys.stderr)
        return 2

    url = os.environ.get(
        "DATABASE_URL", "postgresql+asyncpg://jarvis:jarvis_dev@localhost:5432/jarvis"
    )
    engine = create_async_engine(url)
    try:
        gewartet = await _warten_bis_ruhe(engine)
        async with engine.begin() as conn:
            geloescht = (await conn.execute(text("DELETE FROM users RETURNING id"))).rowcount
    finally:
        await engine.dispose()
    if gewartet >= 0.2:
        # Unter einer Zehntelsekunde ist die Wartezeit die Messung selbst und
        # keine Auskunft.
        print(f"{gewartet:.1f}s auf laufende Schritte gewartet.")

    zaehler = await _grenzen_zuruecksetzen()
    print(
        f"{geloescht} Nutzer entfernt, {zaehler} Zugriffszähler geleert — "
        "die Erstinbetriebnahme ist wieder offen."
    )
    return 0


BESCHAEFTIGT = text(
    """
    SELECT count(*)
    FROM runs
    WHERE CAST(state->>'claimed_at' AS timestamptz) > now() - CAST(:frisch AS interval)
    """
)
"""Läuft gerade jemand an einem Schritt?

Der Anspruch ist die vorhandene Antwort darauf: Er entsteht vor der Wirkung und
wird nach ihr freigegeben. Ein *frischer* Anspruch heißt, dass gerade gearbeitet
wird; ein alter heißt, dass jemand abgestürzt ist — und auf den zu warten, hätte
keinen Zweck.

``now()`` kommt aus der Datenbank und ``claimed_at`` ebenfalls (``_CLAIM`` setzt
es dort). Beide Seiten stehen damit auf derselben Uhr — dieselbe Lehre, die die
Leerlaufmessung eine Sitzung gekostet hat.

Zwei Kleinigkeiten, die je einen Versuch gekostet haben: ``CAST(... AS
interval)`` statt ``::interval`` — der Doppelpunkt ist in ``text()`` die
Bindesyntax —, und der Wert dazu ist ein ``timedelta``. asyncpg bindet ein
Intervall nicht aus einer Zeichenkette; es will das Python-Gegenstück."""

FRISCH = timedelta(seconds=30)
"""Ab wann ein Anspruch nicht mehr „gerade in Arbeit" bedeutet."""

GEDULD = 5.0
"""Wie lange höchstens gewartet wird, in Sekunden.

Eine Obergrenze und kein Vertrauen: Wenn nach fünf Sekunden noch gearbeitet
wird, wird trotzdem gelöscht. Ein Aufräumskript, das hängen bleiben kann, macht
aus einer sauberen Suite eine, die manchmal nicht zurückkommt — und das ist der
schlechtere Tausch."""


async def _warten_bis_ruhe(engine: AsyncEngine, *, geduld: float = GEDULD) -> float:
    """Wartet, bis kein Schritt mehr frisch beansprucht ist. Gibt die Wartezeit zurück.

    Gepollt und nicht benachrichtigt: Es gibt nichts zu abonnieren, der Vorgang
    dauert Millisekunden bis wenige Sekunden, und ein Skript, das für diesen
    Zweck einen Kanal aufbaut, ist mehr Bauwerk als Nutzen.

    ``geduld`` ist ein Parameter und keine feste Zahl, damit die Pruefung dieser
    Funktion nicht fuenf Sekunden dauert. Der Grund, ihn ueberhaupt zu haben,
    ist handfest: Playwright ruft dieses Skript mit ``stdio: "pipe"`` auf und
    verwirft dessen Ausgabe — am Gate-Protokoll ist **nicht** abzulesen, ob hier
    je gewartet wurde. Was sich nicht beobachten laesst, muss geprueft werden.
    """
    begonnen = time.monotonic()
    while time.monotonic() - begonnen < geduld:
        async with engine.connect() as conn:
            beschaeftigt = int((await conn.execute(BESCHAEFTIGT, {"frisch": FRISCH})).scalar_one())
        if beschaeftigt == 0:
            break
        await asyncio.sleep(0.1)
    return time.monotonic() - begonnen


async def _grenzen_zuruecksetzen() -> int:
    """Leert die Zähler der Anmeldezeremonien.

    Ohne Redis kein Fehler: Wer ohne Zugriffsgrenze entwickelt, hat auch keine
    zurückzusetzen. Ein Abbruch hier machte aus einer fehlenden Nebensache ein
    fehlgeschlagenes Aufräumen.
    """
    from redis.asyncio import Redis

    client = Redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
    )
    try:
        schluessel = await client.keys("ratelimit:auth.*")
        for eintrag in schluessel:
            await client.delete(eintrag)
        return len(schluessel)
    except Exception as nicht_erreichbar:
        print(f"Hinweis: Zugriffszähler nicht geleert ({nicht_erreichbar}).", file=sys.stderr)
        return 0
    finally:
        await client.aclose()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
