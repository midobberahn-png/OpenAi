"""Der Ereignisverteiler auf Redis.

**Warum über Redis und nicht im Arbeitsspeicher.** Ein Lauf kann von der API
oder vom Arbeiter vorangebracht werden — zwei Prozesse, und der Browser hängt
nur an einem. Ein Ereignis, das im Speicher der API entsteht, erreicht den
Arbeiter nie und umgekehrt; die Oberfläche sähe je nach Zufall die Hälfte.

Redis liegt ohnehin im Betrieb (Zugriffsgrenzen) und trägt hier wieder nur
flüchtigen Zustand: Geht er verloren, verliert niemand Daten. Die Oberfläche
fällt auf Nachladen zurück und wird langsamer, nicht falsch.

**Ein Kanal je Nutzer, und das ist die Sicherheitsgrenze dieser Datei.** Wer
lauscht, bekommt ausschließlich seinen eigenen Kanal — der Name enthält seine
Kennung, und die stammt aus der Sitzung. Es gibt keine Signatur, mit der sich
ein fremder abonnieren ließe, weil es keine gibt, die einen Nutzer als
Parameter nimmt: ``subscribe()`` bekommt ihn von der Kante.

**Sequenznummern kommen aus Redis** (``INCR``) und nicht aus dem Prozess. Zwei
Prozesse mit eigenen Zählern erzeugten zwei Nummernkreise, und die
Lückenerkennung im Browser meldete dauernd Lücken, die keine sind — eine
Prüfung, die immer anschlägt, wird ignoriert.

Was der Zähler **nicht** leistet: Wiederaufnahme. Redis Pub/Sub hat kein
Gedächtnis; eine verpasste Nachricht ist weg. Genau deshalb trägt der Strom
keine Zustände, sondern Hinweise (ADR-016): Wer eine Lücke bemerkt, lädt neu —
und ist danach richtig, nicht ungefähr.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import suppress
from typing import Any
from uuid import UUID

import structlog
from redis.asyncio import Redis

from jarvis_contracts import ServerMessage

__all__ = ["RedisEventBus", "als_nachricht"]

_log = structlog.get_logger(__name__)


def _kanal(user_id: UUID) -> str:
    return f"events:user:{user_id}"


def _zaehler(user_id: UUID) -> str:
    return f"events:seq:{user_id}"


class RedisEventBus:
    """Veröffentlicht Hinweise und verteilt sie an die Geräte eines Nutzers."""

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def publish(self, user_id: UUID, nachricht: dict[str, Any]) -> int:
        """Schickt eine Nachricht an alle Geräte **dieses** Nutzers.

        ``nachricht`` kommt ohne ``seq`` herein und bekommt sie hier: Die
        Nummer gehört zum Kanal und nicht zum Ereignis, und wer sie vergibt,
        muss den Kanal kennen.

        **Ein Fehler hier bricht nichts ab.** Der Ereignisstrom ist eine
        Beschleunigung und keine Zusage: Ohne ihn lädt die Oberfläche im Takt
        nach. Eine Ausführung scheitern zu lassen, weil ihre *Benachrichtigung*
        nicht durchkam, wäre die Umkehrung der Verhältnisse — und zwar
        ausgerechnet nach einer Wirkung nach außen.
        """
        try:
            seq = int(await self._redis.incr(_zaehler(user_id)))
            await self._redis.publish(_kanal(user_id), json.dumps({**nachricht, "seq": seq}))
            return seq
        except Exception as fehler:
            _log.warning("ereignis.nicht_zugestellt", user_id=str(user_id), fehler=str(fehler))
            return 0

    async def subscribe(self, user_id: UUID) -> AsyncIterator[str]:
        """Der Strom eines Nutzers, als JSON-Zeilen.

        Der Nutzer kommt von der Kante aus der Sitzung. Es gibt keinen Weg,
        einen anderen zu abonnieren — der Kanalname entsteht hier aus dem
        Parameter, und der Parameter hat nur eine Quelle.
        """
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(_kanal(user_id))
        try:
            while True:
                nachricht = await pubsub.get_message(ignore_subscribe_messages=True, timeout=15.0)
                if nachricht is None:
                    # Kein Ereignis in fünfzehn Sekunden. Der Aufrufer schickt
                    # daraufhin einen Kommentar über die Leitung — ohne
                    # Lebenszeichen schließen Proxys eine stille Verbindung,
                    # und der Browser verbindet sich neu, ohne dass etwas
                    # passiert wäre.
                    yield ""
                    continue
                yield str(nachricht["data"])
        finally:
            # Auch bei Abbruch: Eine Verbindung, die abonniert bleibt, hält
            # einen Redis-Kanal offen, den niemand mehr liest.
            with suppress(Exception):
                await pubsub.unsubscribe(_kanal(user_id))
                await pubsub.aclose()  # type: ignore[no-untyped-call]


def als_nachricht(nachricht: ServerMessage) -> dict[str, Any]:
    """Eine Protokollnachricht als JSON-fähiges Wörterbuch — ohne ``seq``.

    Die Nummer vergibt der Verteiler. Sie hier zu setzen hieße, sie im Prozess
    zu zählen, und zwei Prozesse ergäben zwei Nummernkreise.
    """
    roh = nachricht.model_dump(mode="json")
    roh.pop("seq", None)
    return roh
