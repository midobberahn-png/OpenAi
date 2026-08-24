"""Das Zählwerk gegen Redis.

Der Auftrag war ausdrücklich: *kein In-Memory-Test als Nachweis für
Atomarität*. Zu Recht — ein Wörterbuch in einem Prozess ist unter
``asyncio`` ohnehin unteilbar und würde jede noch so kaputte Implementierung
bestätigen.

Geprüft wird deshalb, was nur der echte Store leisten kann: dass hundert
gleichzeitige Anfragen genau hundertmal zählen, dass ein Zähler nie ohne Frist
existiert, und dass ein Fenster sich nicht durch Nachschieben verlängert.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import AsyncClient
from redis.asyncio import Redis

from jarvis_api.rate_limit_store import RedisRateLimitStore
from jarvis_core.limits import RateLimiter, RateLimitPolicy, RateLimitRule

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]


@pytest_asyncio.fixture
async def redis() -> AsyncIterator[Redis]:
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    client = Redis.from_url(url, decode_responses=True)
    try:
        await client.ping()
    except Exception as exc:  # pragma: no cover - Umgebungsproblem
        await client.aclose()
        from tests.integration.conftest import _fehlt

        _fehlt("Redis", exc)
    yield client
    await client.aclose()


def _key() -> str:
    return f"ratelimit:test:{uuid.uuid4()}"


class TestAtomaritaet:
    @pytest.mark.invariant("rate-limit-counting-is-atomic")
    async def test_hundert_gleichzeitige_treffer_zaehlen_hundert(self, redis: Redis) -> None:
        """Der Nachweis, den kein In-Memory-Doppel führen kann.

        Wären Erhöhen und Auslesen getrennte Schritte, lägen die
        zurückgegebenen Stände nicht lückenlos zwischen 1 und 100 — mehrere
        Aufrufe bekämen denselben Wert, und das Limit ließe sich unter Last
        überschreiten.
        """
        store = RedisRateLimitStore(redis)
        key = _key()

        ergebnisse = await asyncio.gather(*(store.hit(key, window_s=60) for _ in range(100)))
        staende = sorted(stand for stand, _ in ergebnisse)

        assert staende == list(range(1, 101)), "Jeder Treffer muss genau einmal zählen"
        await store.reset(key)

    @pytest.mark.invariant("rate-limit-counting-is-atomic")
    async def test_der_zaehler_hat_immer_eine_frist(self, redis: Redis) -> None:
        """Ein Zähler ohne Ablauf sperrte seinen Schlüssel für immer — ein
        selbst gebauter Denial of Service, den niemand bemerkt, bis sich
        jemand beschwert."""
        store = RedisRateLimitStore(redis)
        key = _key()

        await store.hit(key, window_s=30)
        assert await redis.ttl(key) > 0
        await store.reset(key)

    @pytest.mark.invariant("rate-limit-counting-is-atomic")
    async def test_nachschieben_verlaengert_das_fenster_nicht(self, redis: Redis) -> None:
        """Sonst hielte ein Angreifer sein eigenes Fenster offen — und käme
        nie in den Genuss des Ablaufs, aber auch nie an die Grenze."""
        store = RedisRateLimitStore(redis)
        key = _key()

        _, erste_frist = await store.hit(key, window_s=60)
        await asyncio.sleep(1.1)
        _, zweite_frist = await store.hit(key, window_s=60)

        assert zweite_frist < erste_frist, "Die Frist läuft, sie wird nicht erneuert"
        await store.reset(key)

    async def test_verschiedene_schluessel_zaehlen_getrennt(self, redis: Redis) -> None:
        store = RedisRateLimitStore(redis)
        a, b = _key(), _key()

        await store.hit(a, window_s=60)
        await store.hit(a, window_s=60)
        stand_b, _ = await store.hit(b, window_s=60)

        assert stand_b == 1
        await store.reset(a)
        await store.reset(b)


class TestZusammenspiel:
    @pytest.mark.invariant("auth-endpoints-rate-limited")
    async def test_die_grenze_haelt_unter_nebenlaeufigkeit(self, redis: Redis) -> None:
        """Zwanzig gleichzeitige Anfragen gegen ein Limit von fünf: Genau fünf
        kommen durch.

        Das ist der Fall, für den ein Rate-Limit existiert — nicht der
        gemächliche Aufrufer, sondern der Ansturm.
        """
        policy = RateLimitPolicy(
            name=f"test-{uuid.uuid4()}",
            per_client=RateLimitRule(limit=5, window_s=60),
            per_route=RateLimitRule(limit=1000, window_s=60),
        )
        limiter = RateLimiter(RedisRateLimitStore(redis))

        ergebnisse = await asyncio.gather(
            *(limiter.check(policy, client="derselbe") for _ in range(20))
        )
        assert sum(1 for e in ergebnisse if e.allowed) == 5

        for schluessel in (policy.key("derselbe"), policy.key("*")):
            await redis.delete(schluessel)

    @pytest.mark.invariant("auth-endpoints-rate-limited")
    async def test_verteilte_kennungen_erreichen_die_globale_grenze(self, redis: Redis) -> None:
        """Der Angriff mit wechselnden Adressen — gegen den echten Store.

        Jede Kennung wird genau einmal verwendet; die Client-Stufe sieht nie
        mehr als eine Anfrage. Die globale Stufe hält trotzdem.
        """
        policy = RateLimitPolicy(
            name=f"test-{uuid.uuid4()}",
            per_client=RateLimitRule(limit=50, window_s=60),
            per_route=RateLimitRule(limit=8, window_s=60),
        )
        limiter = RateLimiter(RedisRateLimitStore(redis))

        ergebnisse = await asyncio.gather(
            *(limiter.check(policy, client=f"adresse-{i}") for i in range(25))
        )
        erlaubt = sum(1 for e in ergebnisse if e.allowed)
        assert erlaubt == 8

        schluessel = [k async for k in redis.scan_iter(f"ratelimit:{policy.name}:*")]
        if schluessel:
            await redis.delete(*schluessel)


class TestDieGrenzeGiltAmEndpunkt:
    """**Herkunft: externe Prüfung von ``61d4428``.**

    Der Strukturtest belegte bislang, dass im Dekorator eines öffentlichen
    Endpunkts der Name ``rate_limited`` vorkommt. Das ist ein Hinweis und kein
    Beweis: Es sagt nichts darüber, ob die Dependency tatsächlich läuft.

    Hier wird sie ausgeführt. Der Beweis ist der Statuscode ``429`` an einem
    Endpunkt, den jeder ohne Anmeldung erreicht — und zwar über denselben Weg,
    den ein Angreifer nähme.
    """

    async def test_die_challenge_grenze_schlaegt_zu(
        self, client: AsyncClient, redis: Redis
    ) -> None:
        from jarvis_core.limits import AUTH_CHALLENGE

        # Der Zähler dieses Endpunkts wird zurückgesetzt, sonst hinge das
        # Ergebnis daran, was vorher lief. ``X-Forwarded-For`` hilft hier
        # ausdrücklich **nicht**: Ohne eingetragenen Proxy glaubt das System
        # den Header nicht — und das ist die richtige Voreinstellung, nicht
        # eine Unbequemlichkeit des Tests.
        for schluessel in await redis.keys("ratelimit:auth.challenge:*"):
            await redis.delete(schluessel)
        grenze = AUTH_CHALLENGE.per_client.limit

        antworten = [
            (await client.post("/auth/login/start", json={})).status_code for _ in range(grenze + 2)
        ]

        assert antworten[-1] == 429, (
            f"Nach {grenze} Anfragen in einem Fenster muss die Grenze zuschlagen; "
            f"gesehen wurde {antworten}."
        )
        assert 429 not in antworten[: grenze - 1], (
            "Und vorher darf sie es nicht — eine Grenze, die zu früh greift, ist "
            "keine Grenze, sondern ein Ausfall."
        )
