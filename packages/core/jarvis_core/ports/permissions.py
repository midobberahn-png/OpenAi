"""Ports der Berechtigungsschicht.

Protokolle, keine Implementierungen. Die Policy Engine kennt nur diese
Schnittstellen — damit ist sie ohne Datenbank testbar, und das ist bei der
Komponente, die über jede Werkzeugausführung entscheidet, keine Nebensache.
"""

from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID

from jarvis_contracts import PermissionGrant, ToolSpec

__all__ = ["ExecutionAuthorization", "PermissionStore", "RateLimiter", "ToolLookup"]


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


class ExecutionAuthorization(Protocol):
    """Nachweis, dass ein Werkzeugaufruf das Ausführungs-Gate durchlaufen hat.

    Strukturell typisiert statt per Import, damit die Registry nicht von der
    Policy-Schicht abhängt — sonst entstünde ein Zyklus, weil die Policy die
    Registry für die Werkzeugauflösung braucht.

    Erfüllt wird das Protokoll ausschließlich von
    ``jarvis_core.policy.approval.ExecutionGrant``, dessen Konstruktor gegen
    Fremderzeugung gesichert ist.
    """

    @property
    def tool_name(self) -> str: ...

    @property
    def verified_hash(self) -> str: ...

    @property
    def arguments(self) -> dict[str, Any]: ...
