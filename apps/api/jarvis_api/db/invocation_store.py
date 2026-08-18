"""Werkzeugaufruf-Protokoll auf PostgreSQL.

Jeder Aufruf wird vor seiner Wirkung festgehalten — mit den Argumenten, der
Risikoklasse und der Policy-Entscheidung, die zu ihm geführt hat. Zwei Gründe,
und der zweite ist der unmittelbarere:

1. **Nachvollziehbarkeit.** „Wer hat das ausgelöst?“ muss beantwortbar sein,
   auch wenn der Lauf abgestürzt ist.
2. **Fremdschlüssel.** ``pending_actions.invocation_id`` verweist hierher.
   Ohne diese Zeile lässt sich keine Bestätigung anlegen, und damit ist kein
   bestätigungspflichtiges Werkzeug ausführbar.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from jarvis_contracts import InvocationStatus, ToolInvocation

__all__ = ["PostgresInvocationStore"]


_INSERT = text(
    """
    INSERT INTO tool_invocations (
        id, run_id, step_id, tool_name, arguments, risk_level,
        policy_decision, decision_reason, idempotency_key, status, created_at
    ) VALUES (
        :id, :run_id, :step_id, :tool_name, CAST(:arguments AS jsonb), :risk_level,
        :policy_decision, :decision_reason, :idempotency_key, :status, :created_at
    )
    ON CONFLICT (id) DO NOTHING
    """
)
"""``ON CONFLICT DO NOTHING``: Eine wiederaufgenommene Ausführung darf nicht am
bereits protokollierten Aufruf scheitern. Das Protokoll ist Beleg, nicht
Sperre — die Einmaligkeit der *Ausführung* trägt die Nonce."""

_MARK = text(
    """
    UPDATE tool_invocations
       SET status = :status,
           result = CAST(:result AS jsonb),
           executed_at = COALESCE(executed_at, :now)
     WHERE id = :id
    """
)


class PostgresInvocationStore:
    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def record(self, invocation: ToolInvocation) -> None:
        await self._conn.execute(
            _INSERT,
            {
                "id": invocation.id,
                "run_id": invocation.run_id,
                "step_id": invocation.step_id,
                "tool_name": invocation.tool_name,
                "arguments": json.dumps(invocation.arguments, ensure_ascii=False, default=str),
                "risk_level": str(invocation.risk_level),
                "policy_decision": str(invocation.policy_decision),
                "decision_reason": invocation.decision_reason,
                "idempotency_key": invocation.idempotency_key,
                "status": str(invocation.status),
                "created_at": invocation.created_at,
            },
        )

    async def mark(
        self, invocation_id: object, status: InvocationStatus, *, error: str | None = None
    ) -> None:
        payload: dict[str, Any] | None = {"error": error} if error else None
        await self._conn.execute(
            _MARK,
            {
                "id": UUID(str(invocation_id)),
                "status": str(status),
                "result": json.dumps(payload) if payload is not None else None,
                "now": datetime.now(tz=None).astimezone(),
            },
        )
