"""Zugriffsgrenzen — die Regeln.

Die Atomarität lässt sich hier nicht zeigen; sie steht in der
Integrationssuite gegen Redis. Was hier steht, ist die Logik darüber: zwei
Stufen, getrennte Zähler, und die Frage, welche Antwort maßgeblich ist.
"""

from __future__ import annotations

import pytest

from jarvis_core.limits import (
    AUTH_CHALLENGE,
    AUTH_FINISH,
    BOOTSTRAP,
    GLOBAL_CLIENT,
    REGISTRIERTE_POLICIES,
    RateLimiter,
    RateLimitExceeded,
    RateLimitPolicy,
    RateLimitRule,
)

pytestmark = pytest.mark.security


class ZaehlenderStore:
    """In-Memory-Zähler ohne Zeit.

    Ausdrücklich **kein** Nachweis für Atomarität — den kann nur der echte
    Store führen. Hier geht es um die Frage, was gezählt wird, nicht darum,
    wie zuverlässig.
    """

    def __init__(self) -> None:
        self.stand: dict[str, int] = {}

    async def hit(self, key: str, *, window_s: int) -> tuple[int, int]:
        self.stand[key] = self.stand.get(key, 0) + 1
        return self.stand[key], window_s

    async def reset(self, key: str) -> None:
        self.stand.pop(key, None)


def _policy(*, client_limit: int = 3, route_limit: int = 10) -> RateLimitPolicy:
    return RateLimitPolicy(
        name="test",
        per_client=RateLimitRule(limit=client_limit, window_s=60),
        per_route=RateLimitRule(limit=route_limit, window_s=60),
    )


class TestZweiStufen:
    async def test_client_stufe_greift_zuerst(self) -> None:
        limiter = RateLimiter(ZaehlenderStore())
        policy = _policy(client_limit=2)

        assert (await limiter.check(policy, client="a")).allowed
        assert (await limiter.check(policy, client="a")).allowed
        dritte = await limiter.check(policy, client="a")
        assert not dritte.allowed
        assert dritte.remaining == 0

    @pytest.mark.invariant("auth-endpoints-rate-limited")
    async def test_wechselnde_adressen_umgehen_die_globale_stufe_nicht(self) -> None:
        """Der Kern des Entwurfs.

        Ein Angreifer wechselt für jede Anfrage die Kennung — bei gefälschtem
        ``X-Forwarded-For`` kostenlos, bei IPv6 fast. Die Client-Stufe sieht
        davon nie mehr als eine Anfrage. Die globale Stufe zählt trotzdem mit.
        """
        limiter = RateLimiter(ZaehlenderStore())
        policy = _policy(client_limit=100, route_limit=5)

        ergebnisse = [await limiter.check(policy, client=f"adresse-{i}") for i in range(7)]
        erlaubt = [e for e in ergebnisse if e.allowed]

        assert len(erlaubt) == 5, "Die globale Stufe begrenzt unabhängig von der Kennung"
        assert ergebnisse[-1].blocked_globally

    @pytest.mark.invariant("auth-endpoints-rate-limited")
    async def test_die_globale_stufe_zaehlt_auch_gesperrte_anfragen(self) -> None:
        """Sonst wäre sie umgehbar: Erst eine Kennung überlasten — die
        Client-Stufe sperrt, die globale sähe nichts —, dann mit vielen neuen
        Kennungen weitermachen."""
        store = ZaehlenderStore()
        limiter = RateLimiter(store)
        policy = _policy(client_limit=1, route_limit=10)

        for _ in range(5):
            await limiter.check(policy, client="derselbe")

        assert store.stand[policy.key(GLOBAL_CLIENT)] == 5

    async def test_die_globale_antwort_gewinnt(self) -> None:
        """Sie trägt die längere Wartezeit — der Client soll die erfahren."""
        limiter = RateLimiter(ZaehlenderStore())
        policy = RateLimitPolicy(
            name="test",
            per_client=RateLimitRule(limit=5, window_s=10),
            per_route=RateLimitRule(limit=1, window_s=600),
        )

        await limiter.check(policy, client="a")
        zweite = await limiter.check(policy, client="b")
        assert not zweite.allowed
        assert zweite.retry_after_s == 600


class TestGetrennteZaehler:
    @pytest.mark.invariant("auth-endpoints-rate-limited")
    async def test_zeremonien_teilen_sich_keinen_topf(self) -> None:
        """Ein gemeinsamer Zähler hieße, dass ein Angreifer über den einen Weg
        den anderen sperrt: Wer die Registrierung flutet, verhindert damit die
        Anmeldung des rechtmäßigen Nutzers."""
        limiter = RateLimiter(ZaehlenderStore())

        for _ in range(AUTH_CHALLENGE.per_client.limit + 5):
            await limiter.check(AUTH_CHALLENGE, client="angreifer")

        anmeldung = await limiter.check(AUTH_FINISH, client="angreifer")
        assert anmeldung.allowed

    def test_alle_regelwerke_haben_verschiedene_namen(self) -> None:
        namen = [p.name for p in REGISTRIERTE_POLICIES]
        assert len(namen) == len(set(namen))

    def test_die_globale_stufe_liegt_ueber_der_client_stufe(self) -> None:
        """Andernfalls wäre sie im Alltag die wirksame Grenze und sperrte
        reguläre Nutzung aus — ein selbst gebauter Denial of Service."""
        for policy in REGISTRIERTE_POLICIES:
            assert policy.per_route.limit > policy.per_client.limit, policy.name


class TestSchluessel:
    def test_die_globale_kennung_ist_nicht_faelschbar(self) -> None:
        """``*`` kann keine Adresse sein. Wäre die globale Stufe unter einem
        Wert geführt, den ein Client mitbringen kann, ließe sie sich mit
        fremden Anfragen füllen oder umgehen."""
        assert GLOBAL_CLIENT == "*"
        policy = _policy()
        assert policy.key(GLOBAL_CLIENT) != policy.key("192.0.2.1")

    def test_regel_haengt_an_der_stufe(self) -> None:
        policy = _policy(client_limit=3, route_limit=10)
        assert policy.rule_for("192.0.2.1").limit == 3
        assert policy.rule_for(GLOBAL_CLIENT).limit == 10


class TestAusnahme:
    async def test_require_wirft_bei_ueberschreitung(self) -> None:
        """Als Ausnahme geführt, damit ein Aufrufer sie nicht versehentlich
        ignoriert — dieselbe Begründung wie bei ExecutionDenied."""
        limiter = RateLimiter(ZaehlenderStore())
        policy = _policy(client_limit=1)

        await limiter.require(policy, client="a")
        with pytest.raises(RateLimitExceeded) as zu_viel:
            await limiter.require(policy, client="a")
        assert zu_viel.value.decision.retry_after_s > 0


class TestVoreinstellungen:
    def test_die_erstinbetriebnahme_ist_am_engsten_begrenzt(self) -> None:
        """Sie gelingt genau einmal; wer sie oft versucht, sucht das
        Zeitfenster, in dem das System noch niemandem gehört."""
        assert BOOTSTRAP.per_client.limit < AUTH_CHALLENGE.per_client.limit

    def test_der_abschluss_ist_grosszuegiger_als_die_ausstellung(self) -> None:
        """Ein misslungener Anlauf am Authenticator wird legitim wiederholt."""
        assert AUTH_FINISH.per_client.limit >= AUTH_CHALLENGE.per_client.limit
