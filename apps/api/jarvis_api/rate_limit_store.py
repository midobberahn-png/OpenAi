"""Zählwerk der Zugriffsgrenzen auf Redis.

Redis und nicht PostgreSQL — das ist die Aufteilung aus dem Nachtrag zu
ADR-007: Sitzungen liegen in Postgres, weil sie langlebig sind, verwaltet
werden müssen und im Ernstfall vollständig widerrufbar sein sollen. Ein
Rate-Limit-Zähler ist das Gegenteil: hochfrequent, sekundenkurz, ohne Wert
nach Ablauf. Ihn in eine transaktionale Datenbank zu schreiben hieße, jedem
Anmeldeversuch eine Schreiblast aufzuerlegen, deren Ergebnis eine Minute
später niemanden mehr interessiert.

**Die Atomarität liegt im Lua-Skript, nicht im Python-Code.** Die naheliegende
Fassung wäre::

    stand = await redis.incr(key)
    if stand == 1:
        await redis.expire(key, window)

Sie hat zwei Löcher, und beide sind real: Zwischen ``incr`` und ``expire``
kann der Prozess sterben — dann existiert ein Zähler ohne Frist, der den
Schlüssel dauerhaft sperrt. Und zwei gleichzeitige Erstzugriffe setzen die
Frist zweimal, wobei die zweite das Fenster verlängert. Ein einziges Skript
kennt beide Fälle nicht: Redis führt es unteilbar aus.
"""

from __future__ import annotations

from redis.asyncio import Redis

__all__ = ["RedisRateLimitStore"]


_HIT = """
local stand = redis.call('INCR', KEYS[1])
if stand == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local rest = redis.call('TTL', KEYS[1])
if rest < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
  rest = tonumber(ARGV[1])
end
return {stand, rest}
"""
"""Erhöhen, Frist setzen und Restzeit lesen — in einem unteilbaren Schritt.

Der ``rest < 0``-Zweig fängt den Fall ab, dass ein Zähler ohne Frist
existiert. Er sollte nach der Umstellung auf dieses Skript nicht mehr
vorkommen; er steht hier, weil ein Zähler ohne Ablauf einen Schlüssel für
immer sperren würde — und das wäre ein selbst gebauter Denial of Service, den
niemand bemerkt, bis sich jemand beschwert.
"""


class RedisRateLimitStore:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis
        self._script = redis.register_script(_HIT)

    async def hit(self, key: str, *, window_s: int) -> tuple[int, int]:
        stand, rest = await self._script(keys=[key], args=[window_s])
        return int(stand), int(rest)

    async def reset(self, key: str) -> None:
        await self._redis.delete(key)
