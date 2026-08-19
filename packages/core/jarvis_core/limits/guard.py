"""Die Prüfung selbst.

Zwei Stufen, beide immer gezählt — auch wenn die erste schon gesperrt hat.
Das ist bewusst und nicht Verschwendung: Würde die globale Stufe nur dann
zählen, wenn die Client-Stufe durchlässt, könnte ein Angreifer sie umgehen,
indem er *dieselbe* Kennung überlastet und danach mit vielen neuen weitermacht
— die globale Zählung hätte den Ansturm nie gesehen.

Die Reihenfolge der Antwort ist dagegen umgekehrt: Sperrt die globale Stufe,
ist das die maßgebliche Auskunft. Sie hat die längere Wartezeit, und der
Client soll die erfahren, nicht die kürzere.
"""

from __future__ import annotations

from jarvis_core.limits.policy import GLOBAL_CLIENT, RateLimitDecision, RateLimitPolicy
from jarvis_core.ports.rate_limit import RateLimitStore

__all__ = ["RateLimitExceeded", "RateLimiter"]


class RateLimitExceeded(Exception):
    """Die Grenze ist erreicht.

    Als Ausnahme geführt, damit ein Aufrufer sie nicht versehentlich ignoriert
    — dieselbe Begründung wie bei ``ExecutionDenied``. Ein Rate-Limit, dessen
    Rückgabewert man übersehen kann, ist keines.
    """

    def __init__(self, decision: RateLimitDecision) -> None:
        self.decision = decision
        super().__init__(
            f"Grenze erreicht ({decision.rule}); erneut in {decision.retry_after_s}s möglich."
        )


class RateLimiter:
    """Prüft eine Anfrage gegen die Regeln einer Route."""

    def __init__(self, store: RateLimitStore) -> None:
        self._store = store

    async def check(self, policy: RateLimitPolicy, *, client: str) -> RateLimitDecision:
        """Zählt beide Stufen und meldet die maßgebliche Entscheidung.

        ``client`` ist bereits das Ergebnis einer Vertrauensentscheidung des
        Aufrufers (siehe ``client_identifier`` in der API-Schicht). Hier wird
        er nur noch als Schlüsselbestandteil verwendet — eine zweite Deutung
        wäre eine zweite Wahrheit darüber, wer jemand ist.
        """
        eigen = await self._zaehle(policy, client)
        global_ = await self._zaehle(policy, GLOBAL_CLIENT)

        if not global_.allowed:
            return global_
        return eigen

    async def require(self, policy: RateLimitPolicy, *, client: str) -> RateLimitDecision:
        """Wie ``check``, wirft aber bei Überschreitung."""
        entscheidung = await self.check(policy, client=client)
        if not entscheidung.allowed:
            raise RateLimitExceeded(entscheidung)
        return entscheidung

    async def _zaehle(self, policy: RateLimitPolicy, client: str) -> RateLimitDecision:
        regel = policy.rule_for(client)
        stand, verbleibend = await self._store.hit(policy.key(client), window_s=regel.window_s)
        return RateLimitDecision(
            allowed=stand <= regel.limit,
            scope=policy.key(client),
            rule=regel,
            remaining=max(0, regel.limit - stand),
            retry_after_s=verbleibend,
        )
