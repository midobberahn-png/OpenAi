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
"""

from __future__ import annotations

import asyncio
import os
import sys

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


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
        async with engine.begin() as conn:
            geloescht = (await conn.execute(text("DELETE FROM users RETURNING id"))).rowcount
    finally:
        await engine.dispose()

    zaehler = await _grenzen_zuruecksetzen()
    print(
        f"{geloescht} Nutzer entfernt, {zaehler} Zugriffszähler geleert — "
        "die Erstinbetriebnahme ist wieder offen."
    )
    return 0


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
