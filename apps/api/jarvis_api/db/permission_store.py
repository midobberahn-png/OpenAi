"""Berechtigungen auf PostgreSQL.

Erfüllt ``PermissionStore``. Die Policy Engine liest hierüber, welche Scopes
ein Nutzer erteilt hat und in welchem Modus.

**Warum es diese Datei erst jetzt gibt — und warum das ein Befund ist.** Die
Abfragen existierten bereits, aber im Testcode: ``tests/integration/
test_end_to_end.py`` führte eine eigene Klasse ``DbPermissions``. Der
Durchstichtest lief damit gegen eine Implementierung, die es in der Anwendung
nicht gab. Genau davor warnt der Modulkopf von ``ports/invocations.py``: Ein
Ablauf, der nur im Test funktioniert, weil der Test etwas mitbringt, was die
Anwendung nicht hat, ist die Art von Lücke, gegen die ein Durchstichtest
existiert.

**Kein Rückfall auf einen Vorgabewert.** ``get_grant()`` liefert ``None``,
wenn nichts erteilt ist — und ``None`` heißt „nicht erteilt", nicht „erlaubt".
Die Versuchung wäre, hier auf ``scopes.default_mode`` zurückzufallen; der
Katalogwert ist aber die *Empfehlung* für die Erteilung und nicht die
Erteilung selbst. Wer beides vermengt, hat Rechte, die niemand vergeben hat.

**Ablauf wird nicht hier geprüft.** ``PermissionGrant.is_valid_at()`` gehört
dem Vertrag, und die Policy Engine ruft es mit ihrer Zeit auf. Ein
``WHERE expires_at > now()`` hier hieße, dass zwei Stellen über Gültigkeit
entscheiden — und die Datenbankuhr entschiede mit. ``granted_scopes()`` ist
davon ausgenommen und filtert nur ``deny``: Es beantwortet „was steht
grundsätzlich zur Verfügung", nicht „was gilt jetzt".
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_contracts import PermissionGrant, PermissionMode, ScopeConstraints

__all__ = ["PostgresPermissionStore"]


_GRANT = text(
    """
    SELECT scope, mode, constraints, granted_at, expires_at
      FROM permissions
     WHERE user_id = :user_id
       AND scope = :scope
    """
)

_SCOPES = text(
    """
    SELECT scope
      FROM permissions
     WHERE user_id = :user_id
       AND mode <> 'deny'
    """
)


class PostgresPermissionStore:
    """Erteilte Berechtigungen eines Nutzers."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        """Lesend, und trotzdem eine Engine: Diese Schicht wird aus dem
        Executor heraus aufgerufen, dessen übrige Schreibvorgänge in eigenen
        Transaktionen liegen. Eine Verbindung des Aufrufers hereinzureichen
        hieße, die Lesevorgänge an dessen Transaktionsgrenze zu binden — ohne
        dass jemand entschieden hätte, dass das so sein soll."""

    async def get_grant(self, user_id: UUID, scope: str) -> PermissionGrant | None:
        async with self._engine.connect() as conn:
            zeile = (
                (await conn.execute(_GRANT, {"user_id": user_id, "scope": scope}))
                .mappings()
                .first()
            )
        if zeile is None:
            return None
        return PermissionGrant(
            scope=zeile["scope"],
            mode=PermissionMode(zeile["mode"]),
            constraints=ScopeConstraints.model_validate(zeile["constraints"] or {}),
            granted_at=zeile["granted_at"],
            expires_at=zeile["expires_at"],
        )

    async def granted_scopes(self, user_id: UUID) -> set[str]:
        async with self._engine.connect() as conn:
            zeilen = await conn.execute(_SCOPES, {"user_id": user_id})
            return {zeile.scope for zeile in zeilen}
