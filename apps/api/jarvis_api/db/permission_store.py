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

import json
from uuid import UUID

import structlog
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_contracts import PermissionGrant, PermissionMode, RiskLevel, constraints_for
from jarvis_core.ports.permissions import ScopeEintrag

__all__ = ["PostgresPermissionStore"]

_log = structlog.get_logger(__name__)
"""Eine abgewiesene Berechtigung sieht für den Nutzer aus wie „nicht erteilt".
Dass sie in Wahrheit unlesbar war, gehört ins Protokoll — sonst sucht jemand
den Fehler in der Oberfläche."""


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


_KATALOG = text(
    """
    SELECT name, description, default_mode, risk_level
      FROM scopes
     ORDER BY name
    """
)
"""Der Scope-Katalog — was es überhaupt gibt.

Ohne Nutzerbezug, und das ist richtig: Der Katalog beschreibt das System und
nicht eine Person. Die Frage „darf JARVIS Mails senden?" beantwortet gerade der
Scope, zu dem **nichts** erteilt ist; eine Oberfläche, die nur Erteiltes zeigt,
kann sie nicht stellen."""

_ALLE_GRANTS = text(
    """
    SELECT scope, mode, constraints, granted_at, expires_at
      FROM permissions
     WHERE user_id = :user_id
     ORDER BY scope
    """
)
"""Alles, was diesem Nutzer erteilt ist — auch ``deny`` und Abgelaufenes.

Anders als ``_SCOPES``, das für eine *Entscheidung* filtert. Hier geht es um
Auskunft, und ein ausdrückliches ``deny`` ist eine Entscheidung des Nutzers:
Sie zu verschweigen hieße, ihm eine Einstellung zu zeigen, die er nicht
getroffen hat."""

_UPSERT = text(
    """
    INSERT INTO permissions (user_id, scope, mode, constraints, granted_at, expires_at)
    VALUES (:user_id, :scope, :mode, CAST(:constraints AS jsonb), :granted_at, :expires_at)
    ON CONFLICT (user_id, scope) DO UPDATE
       SET mode = EXCLUDED.mode,
           constraints = EXCLUDED.constraints,
           granted_at = EXCLUDED.granted_at,
           expires_at = EXCLUDED.expires_at,
           updated_at = now()
    RETURNING scope
    """
)
"""Erteilen oder ersetzen — in einer Anweisung.

``ON CONFLICT … DO UPDATE`` und nicht „lesen, dann entscheiden": Zwei
gleichzeitige Änderungen desselben Scopes ergäben sonst je nach Reihenfolge
einen Einfügefehler oder eine verlorene Änderung. ``UNIQUE(user_id, scope)``
trägt die Zusage, dass es je Scope genau eine Wahrheit gibt.

**Ersetzend und nicht ergänzend, auch bei den Einschränkungen.** Wer eine
Berechtigung setzt, setzt sie vollständig. Ein Zusammenführen mit dem alten
Stand wäre die Art von Bequemlichkeit, bei der eine Pfadgrenze aus der
Vorwoche eine neue Erteilung still erweitert.

Ein unbekannter Scope scheitert am Fremdschlüssel auf ``scopes.name`` — die
Datenbank weist ihn ab, bevor die Anwendung ihn prüfen kann. Beides ist
richtig: Die Kante antwortet dem Nutzer verständlich, die Zeile lässt sich
nicht anders schreiben."""

_REVOKE = text(
    """
    DELETE FROM permissions
     WHERE user_id = :user_id
       AND scope = :scope
    RETURNING scope
    """
)
"""``user_id`` steht in der Anweisung. Eine Zugehörigkeit, die sich weglassen
lässt, wird irgendwann weggelassen — und hier hieße das, fremde Rechte zu
löschen."""


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

        try:
            einschraenkungen = constraints_for(scope, zeile["constraints"])
        except ValidationError as unlesbar:
            # Ein Datensatz, der sich nicht auslegen lässt, ist keine
            # Berechtigung — und ausdrücklich nicht „keine Einschränkung".
            #
            # Der Fall entstand beim ersten echten Werkzeug: Die
            # Einschränkungen wurden als Basisklasse gelesen, und die verbietet
            # zusätzliche Felder. Eine erteilte files.read-Berechtigung mit
            # Pfadgrenzen war damit überhaupt nicht ladbar. Behoben durch
            # ``constraints_for()``; was bleibt, ist die Frage, was bei einer
            # Zeile geschieht, die auch dazu nicht passt.
            #
            # Antwort: abweisen wie „nicht erteilt". Die Alternative — die
            # Ausnahme durchreichen — machte aus einem falsch geschriebenen
            # Datensatz einen Ausfall des ganzen Laufs. Und die schlimmste
            # Alternative wäre ein Rückfall auf die Basisklasse: Dann verlöre
            # eine files.read-Berechtigung ihre Pfadgrenzen und würde
            # *weiter* gelten.
            _log.error(
                "berechtigung.unlesbar",
                scope=scope,
                user_id=str(user_id),
                fehler=str(unlesbar),
            )
            return None

        return PermissionGrant(
            scope=zeile["scope"],
            mode=PermissionMode(zeile["mode"]),
            constraints=einschraenkungen,
            granted_at=zeile["granted_at"],
            expires_at=zeile["expires_at"],
        )

    async def catalog(self) -> list[ScopeEintrag]:
        async with self._engine.connect() as conn:
            zeilen = (await conn.execute(_KATALOG)).mappings().all()
        return [
            ScopeEintrag(
                name=z["name"],
                description=z["description"],
                default_mode=PermissionMode(z["default_mode"]),
                risk_level=RiskLevel(z["risk_level"]),
            )
            for z in zeilen
        ]

    async def grants_for(self, user_id: UUID) -> list[PermissionGrant]:
        """Alle Berechtigungen eines Nutzers — unlesbare übersprungen.

        Dieselbe Entscheidung wie in ``get_grant()``: Ein Datensatz, der sich
        nicht auslegen lässt, ist keine Berechtigung. Er hier als „ohne
        Einschränkungen" anzuzeigen wäre die schlimmste Auskunft — der Nutzer
        sähe mehr Freiheit, als tatsächlich gilt.
        """
        async with self._engine.connect() as conn:
            zeilen = (await conn.execute(_ALLE_GRANTS, {"user_id": user_id})).mappings().all()

        grants: list[PermissionGrant] = []
        for zeile in zeilen:
            try:
                einschraenkungen = constraints_for(zeile["scope"], zeile["constraints"])
            except ValidationError as unlesbar:
                _log.error(
                    "berechtigung.unlesbar",
                    scope=zeile["scope"],
                    user_id=str(user_id),
                    fehler=str(unlesbar),
                )
                continue
            grants.append(
                PermissionGrant(
                    scope=zeile["scope"],
                    mode=PermissionMode(zeile["mode"]),
                    constraints=einschraenkungen,
                    granted_at=zeile["granted_at"],
                    expires_at=zeile["expires_at"],
                )
            )
        return grants

    async def upsert_grant(self, user_id: UUID, grant: PermissionGrant) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                _UPSERT,
                {
                    "user_id": user_id,
                    "scope": str(grant.scope),
                    "mode": str(grant.mode),
                    "constraints": json.dumps(
                        grant.constraints.model_dump(mode="json", exclude_none=True),
                        ensure_ascii=False,
                    ),
                    "granted_at": grant.granted_at,
                    "expires_at": grant.expires_at,
                },
            )

    async def revoke_grant(self, user_id: UUID, scope: str) -> bool:
        async with self._engine.begin() as conn:
            treffer = await conn.execute(_REVOKE, {"user_id": user_id, "scope": scope})
            return treffer.first() is not None

    async def granted_scopes(self, user_id: UUID) -> set[str]:
        async with self._engine.connect() as conn:
            zeilen = await conn.execute(_SCOPES, {"user_id": user_id})
            return {zeile.scope for zeile in zeilen}
