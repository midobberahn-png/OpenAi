"""Ports der Berechtigungsschicht.

Protokolle, keine Implementierungen. Die Policy Engine kennt nur diese
Schnittstellen — damit ist sie ohne Datenbank testbar, und das ist bei der
Komponente, die über jede Werkzeugausführung entscheidet, keine Nebensache.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from jarvis_contracts import PermissionGrant, ToolSpec

__all__ = ["PermissionStore", "RateLimiter", "ToolLookup"]


class PermissionStore(Protocol):
    """Zugriff auf die erteilten Berechtigungen eines Nutzers."""

    async def get_grant(self, user_id: UUID, scope: str) -> PermissionGrant | None:
        """``None`` bedeutet: nicht erteilt (nicht: erlaubt)."""
        ...

    async def granted_scopes(self, user_id: UUID) -> set[str]:
        """Alle Scopes mit Modus ``allow`` oder ``confirm``."""
        ...


class ToolLookup(Protocol):
    """Auflösung eines Werkzeugnamens auf seine Spezifikation."""

    def get(self, name: str) -> ToolSpec | None: ...


class RateLimiter(Protocol):
    """Betriebsgrenzen je Nutzer und Werkzeug."""

    async def exceeded(self, user_id: UUID, tool_name: str, limit: str) -> bool: ...


# ``ExecutionAuthorization`` gab es hier einmal als ``Protocol``. Es ist
# entfernt, und der Grund gehört in den Quelltext, weil er allgemein gilt:
#
# Das Protokoll führte ``tool_name``, ``verified_hash``, ``arguments``,
# ``run_id`` und ``user_id`` und behauptete im Docstring, es werde
# ausschließlich von ``ExecutionGrant`` erfüllt. Strukturelle Typisierung
# leistet diese Exklusivität aber gerade nicht: Ein externes Review baute ein
# ``SimpleNamespace`` mit denselben Attributen und einem korrekt berechneten
# Hash — und führte damit ``mail.send`` aus, ohne Policy Engine, ohne Approval
# Gateway, ohne Grant.
#
# Die Lehre ist nicht „dieses Protokoll war schlecht benannt", sondern: Ein
# Protocol beantwortet die Frage „sieht es so aus?". Wo es um Erlaubnis geht,
# lautet die Frage „kommt es von dort?" — und die beantwortet nur eine nominale
# Prüfung. ``ToolRegistry.execute()`` verlangt deshalb ``type(auth) is
# ExecutionGrant``.
