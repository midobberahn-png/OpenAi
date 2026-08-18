"""Port des Bestätigungsspeichers.

Die Einmaligkeit einer Bestätigung wird **nicht** in der Anwendung erzwungen,
sondern von der Datenbank. Der Grund steht in ``BurnResult``.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID

from jarvis_contracts import ApprovalChannel, PendingAction

__all__ = ["ApprovalStore", "BurnResult"]


class BurnResult(StrEnum):
    """Ergebnis des Nonce-Verbrauchs.

    Die Unterscheidung zwischen ``ALREADY_USED`` und ``NONCE_MISMATCH`` ist
    absichtlich: Die erste ist ein Wiederholungsversuch (möglicherweise ein
    Doppelklick), die zweite ein Fälschungsversuch. Beide werden abgelehnt,
    aber nur die zweite ist ein Sicherheitsvorfall und gehört als solcher ins
    Audit-Log.
    """

    BURNED = "burned"
    """Erfolgreich und genau einmal verbraucht."""

    ALREADY_USED = "already_used"
    NONCE_MISMATCH = "nonce_mismatch"
    EXPIRED = "expired"
    NOT_FOUND = "not_found"


class ApprovalStore(Protocol):
    """Persistenz der Bestätigungen.

    Implementierungen **müssen** ``burn`` als atomares Compare-and-Set
    umsetzen. Ein Ablauf der Form::

        if action.response is None:
            action.response = "approved"
            await save(action)

    ist bei zwei gleichzeitigen Anfragen ein Doppelverbrauch: Beide lesen
    ``None``, beide schreiben. Genau das ist Angriff G (Replay). Die einzige
    verlässliche Lösung ist ein bedingtes ``UPDATE``, dessen Trefferzahl die
    Antwort liefert.
    """

    async def create(self, action: PendingAction, arguments: dict[str, Any]) -> None:
        """Legt die Bestätigung an und friert die Argumente ein.

        Die Argumente werden getrennt vom Vorschauobjekt gespeichert: Die
        Vorschau ist für Menschen, die Argumente sind für die Ausführung. Beide
        aus derselben Quelle zu rendern wäre bequem, würde aber die
        Hash-Bindung aufweichen.
        """
        ...

    async def get(self, action_id: UUID) -> PendingAction | None: ...

    async def frozen_arguments(self, action_id: UUID) -> dict[str, Any]:
        """Die bei der Anfrage eingefrorenen Argumente — byte-identisch."""
        ...

    async def burn(
        self,
        *,
        action_id: UUID,
        nonce: str,
        response: str,
        channel: ApprovalChannel,
        now: datetime,
    ) -> BurnResult:
        """Verbraucht die Nonce atomar. Beim zweiten Aufruf ``ALREADY_USED``."""
        ...

    async def expire(self, action_id: UUID, now: datetime) -> None:
        """Markiert eine abgelaufene Bestätigung, damit sie nicht offen bleibt."""
        ...

    async def open_for_user(self, user_id: UUID) -> list[PendingAction]:
        """Offene Bestätigungen — Grundlage der Anzeige in der Oberfläche."""
        ...
