"""Den Arbeiter starten — der Prozess, der hängengebliebene Läufe fortsetzt.

    uv run python scripts/worker.py

Ein **eigener** Prozess und keine Hintergrundaufgabe in der API, und der Grund
ist derselbe, aus dem es diesen Arbeiter überhaupt gibt: Er soll da sein, wenn
der andere abgestürzt ist. Ein Wiederaufnehmer, der im selben Prozess läuft wie
das, was er wiederaufnimmt, hat genau dann Feierabend, wenn er gebraucht wird.

Zwei Umgebungsvariablen neben den üblichen:

    JARVIS_WORKER_INTERVAL   Sekunden zwischen zwei Durchgängen (Vorgabe 60)
    JARVIS_WORKER_LEASE      Sekunden, ab denen ein Anspruch überfällig ist
                             (Vorgabe 900 — und die Vorgabe ist die richtige
                             Größenordnung, siehe ``DEFAULT_LEASE``)
    JARVIS_AUDIT_INTERVAL    Sekunden zwischen zwei Kettenprüfungen
                             (Vorgabe 3600, ADR-018)

Was es **nicht** gibt, ist ein Schalter, der den Halt nach einem Kettenbruch
aufhebt. Die Begründung steht in ADR-018: Er wäre die erste Zeile, die jemand
setzt, wenn der Betrieb klemmt — und genau dann ist die Meldung ernst.

Die Frist ist eine **Obergrenze für die Dauer eines Schrittes** und keine
Zeitüberschreitung: Die Übernahme sperrt den alten Arbeiter vom Schreiben aus,
nicht vom Wirken. Wer sie hier kleiner dreht, weil ihm die Wiederaufnahme zu
träge ist, dreht an der falschen Schraube — dafür ist der Takt da.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import suppress
from datetime import timedelta

from jarvis_api.db.session import engine_for
from jarvis_api.settings import get_settings
from jarvis_api.worker import DEFAULT_INTERVALL, run_forever
from jarvis_core.audit import DEFAULT_AUDIT_INTERVAL
from jarvis_core.orchestrator import DEFAULT_LEASE


def _sekunden(name: str, vorgabe: timedelta) -> timedelta:
    roh = os.environ.get(name)
    if not roh:
        return vorgabe
    return timedelta(seconds=int(roh))


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    settings = get_settings()
    engine = engine_for(settings.database_url)
    try:
        await run_forever(
            engine,
            settings,
            intervall=_sekunden("JARVIS_WORKER_INTERVAL", DEFAULT_INTERVALL),
            lease=_sekunden("JARVIS_WORKER_LEASE", DEFAULT_LEASE),
            audit_intervall=_sekunden("JARVIS_AUDIT_INTERVAL", DEFAULT_AUDIT_INTERVAL),
        )
    finally:
        await engine.dispose()


if __name__ == "__main__":
    # Kein Stacktrace für ein Strg-C: Das ist die vorgesehene Art, diesen
    # Prozess zu beenden, und keine Störung.
    with suppress(KeyboardInterrupt):
        asyncio.run(main())
