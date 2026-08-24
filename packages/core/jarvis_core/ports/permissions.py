"""Ports der Berechtigungsschicht.

Protokolle, keine Implementierungen. Die Policy Engine kennt nur diese
Schnittstellen — damit ist sie ohne Datenbank testbar, und das ist bei der
Komponente, die über jede Werkzeugausführung entscheidet, keine Nebensache.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from jarvis_contracts import PermissionGrant, PermissionMode, RiskLevel, ToolSpec

__all__ = ["PermissionAdmin", "PermissionStore", "RateLimiter", "ScopeEintrag", "ToolLookup"]


class PermissionStore(Protocol):
    """Zugriff auf die erteilten Berechtigungen eines Nutzers."""

    async def get_grant(self, user_id: UUID, scope: str) -> PermissionGrant | None:
        """``None`` bedeutet: nicht erteilt (nicht: erlaubt)."""
        ...

    async def granted_scopes(self, user_id: UUID) -> set[str]:
        """Alle Scopes mit Modus ``allow`` oder ``confirm``."""
        ...


@dataclass(frozen=True)
class ScopeEintrag:
    """Ein Scope, wie ihn der Katalog führt — **nicht** wie er erteilt ist.

    ``default_mode`` ist die *Empfehlung* für eine Erteilung und keine
    Erteilung. Die Unterscheidung steht schon im Kopf von
    ``permission_store.py`` und ist hier genauso wichtig: Wer beides vermengt,
    hat Rechte, die niemand vergeben hat.
    """

    name: str
    description: str
    default_mode: PermissionMode
    risk_level: RiskLevel


class PermissionAdmin(Protocol):
    """Erteilen und Zurückziehen — **getrennt** vom lesenden Port.

    Ein eigener Port und nicht drei Methoden mehr an ``PermissionStore``, und
    der Grund ist derselbe wie bei ``UndoConsumer`` neben ``GrantConsumer``:
    Die Policy Engine bekommt den lesenden Port. Läge das Schreiben darin,
    hätte ausgerechnet die Komponente, die über jede Ausführung entscheidet,
    nominell die Fähigkeit, sich selbst Rechte zu erteilen.

    **Die gefährliche Richtung ist das Erteilen.** Zurückziehen kann nichts
    öffnen; erteilen öffnet alles, was daran hängt — ein Scope auf ``allow``
    nimmt jede künftige Bestätigung aus dem Weg. Deshalb gilt für diesen Port
    eine Regel, die kein Typ erzwingen kann und die deshalb ein Strukturtest
    hält: **Er wird ausschließlich an der HTTP-Kante benutzt, nie aus einem
    Werkzeug heraus.** Ein Werkzeug, das Berechtigungen schreibt, wäre der
    kürzeste Weg von „ein Modell hat Fremdinhalt gelesen" zu „das Modell darf
    jetzt mehr".
    """

    async def catalog(self) -> list[ScopeEintrag]:
        """Alle Scopes, die es überhaupt gibt — der Katalog, nicht die Rechte.

        Ohne ihn kann eine Oberfläche nur zeigen, was bereits erteilt ist. Die
        Frage „darf JARVIS Mails senden?" beantwortet aber gerade der Scope,
        zu dem **nichts** erteilt ist.
        """
        ...

    async def grants_for(self, user_id: UUID) -> list[PermissionGrant]:
        """Alles, was diesem Nutzer erteilt ist — auch ``deny`` und Abgelaufenes.

        Anders als ``granted_scopes()``, das für eine Entscheidung filtert.
        Hier geht es um Auskunft: Ein ausdrückliches ``deny`` ist eine
        Entscheidung des Nutzers und gehört angezeigt, nicht verschwiegen.
        """
        ...

    async def upsert_grant(self, user_id: UUID, grant: PermissionGrant) -> None:
        """Setzt eine Berechtigung — neu oder ersetzend.

        Ersetzend und nicht ergänzend: Zwei Berechtigungen für denselben Scope
        wären zwei Wahrheiten, und die Datenbank schließt das mit
        ``UNIQUE(user_id, scope)`` ohnehin aus. Was hier steht, gilt
        vollständig — auch die Einschränkungen, die der Aufrufer *nicht*
        mitschickt.
        """
        ...

    async def revoke_grant(self, user_id: UUID, scope: str) -> bool:
        """Zieht eine Berechtigung zurück. ``False``: Es gab keine.

        ``revoke_grant`` und nicht ``revoke``, obwohl der Port keinen Zweifel
        ließe: Ein Strukturtest hält fest, dass Berechtigungen nur an der Kante
        geschrieben werden, und er sucht nach dem Methodennamen. ``revoke``
        heißt anderswo auch das Beenden einer Sitzung — ein Name, der zweimal
        vorkommt, zwingt einen Sicherheitstest zu einer Ausnahmeliste, und eine
        Ausnahmeliste wächst.

        Kein Fehler und kein Unterschied nach außen — nach beidem gilt
        dasselbe: Der Nutzer hat dieses Recht nicht erteilt.
        """
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
