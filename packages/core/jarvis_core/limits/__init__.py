"""Zugriffsgrenzen.

Die Regeln stehen im Kern, das Zählwerk hinter einem Port. Ein Rate-Limit ist
hier eine Sicherheitskomponente und keine Komfortfunktion der Middleware —
entsprechend liegt seine Logik dort, wo sie geprüft werden kann.
"""

from .guard import RateLimiter, RateLimitExceeded
from .policy import (
    AUTH_CHALLENGE,
    AUTH_FINISH,
    BOOTSTRAP,
    GLOBAL_CLIENT,
    REGISTRIERTE_POLICIES,
    RateLimitDecision,
    RateLimitPolicy,
    RateLimitRule,
)

__all__ = [
    "AUTH_CHALLENGE",
    "AUTH_FINISH",
    "BOOTSTRAP",
    "GLOBAL_CLIENT",
    "REGISTRIERTE_POLICIES",
    "RateLimitDecision",
    "RateLimitExceeded",
    "RateLimitPolicy",
    "RateLimitRule",
    "RateLimiter",
]
