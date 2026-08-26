"""Bestätigungsspeicher auf PostgreSQL.

Die einzige Stelle, an der die Einmaligkeit einer Bestätigung tatsächlich
erzwungen wird. Alles andere im Approval Gateway sind Vorprüfungen.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import RowMapping, text
from sqlalchemy.ext.asyncio import AsyncConnection

from jarvis_contracts import ApprovalChannel, PendingAction
from jarvis_core.ports.approval import BurnResult

__all__ = ["PostgresApprovalStore"]


_CLAIM = text(
    """
    UPDATE pending_actions
       SET executed_at = :now
     WHERE id = :id
       AND response = 'approved'
       AND executed_at IS NULL
       AND expires_at > :now
    RETURNING id
    """
)
"""Der Ausführungsanspruch — bedingtes UPDATE, dessen Trefferzahl die Antwort
ist.

Drei Bedingungen, und jede schließt etwas anderes aus: ``response = 'approved'``
verhindert, dass eine abgelehnte oder offene Bestätigung ausführt;
``executed_at IS NULL`` macht den Anspruch einmalig; ``expires_at > now()``
hält die Frist. Ein vorgelagertes ``SELECT`` wäre bei zwei gleichzeitigen
Aufrufen wertlos — und genau diese Gleichzeitigkeit ist der Fall, für den es
den Anspruch gibt.

**Die dritte Bedingung kam aus einer externen Prüfung zu ``61d4428``.** Das
Gate prüft den Ablauf beim Eintritt (``is_expired(now)``) und reicht dieselbe
Zeit weiter; dazwischen liegen eine erneute Policy-Entscheidung und mehrere
Datenbankzugriffe. Verstreicht die Frist **währenddessen**, war die
Bestätigung im Moment der Ausführung abgelaufen — und der Anspruch gewann
trotzdem.

``:now`` ist deshalb **nicht** die Zeit vom Eintritt ins Gate: Der Aufrufer
liest seine Uhr unmittelbar vor diesem Anspruch neu (``ApprovalGateway._clock``).
Ein eingefrorener Zeitpunkt beantwortete dieselbe Frage noch einmal, statt sie
neu zu stellen.

Und ausdrücklich nicht ``now()`` der Datenbank, obwohl das naheliegt: Die
Fristen dieses Gates sind Anwendungszeit — ``expires_at`` entsteht aus ``now +
ttl`` im Kern, und die Suite hält die Zeit an, um Abläufe zu prüfen, statt auf
sie zu warten. Zwei Uhren für dieselbe Frist wären eine Quelle von Fehlern, die
nur unter Last auftreten. Anders als beim Planschritt-Anspruch, wo zwei
Prozesse gegeneinander messen und deshalb die Datenbankuhr gilt."""


_INSERT = text(
    """
    INSERT INTO pending_actions (
        id, run_id, invocation_id, user_id, session_id, tool_name,
        preview, risk_level, reason, payload_hash, nonce,
        frozen_arguments, requested_channel, expires_at, created_at
    ) VALUES (
        :id, :run_id, :invocation_id, :user_id, :session_id, :tool_name,
        CAST(:preview AS jsonb), :risk_level, :reason, :payload_hash, :nonce,
        CAST(:frozen_arguments AS jsonb), :requested_channel, :expires_at, :created_at
    )
    """
)

_SELECT = text(
    """
    SELECT id, run_id, invocation_id, user_id, session_id, tool_name,
           preview, risk_level, reason, payload_hash, nonce,
           requested_channel, expires_at, created_at,
           response, responded_at, responded_via
    FROM pending_actions
    WHERE id = :id
    """
)

# Der Kern: ein bedingtes UPDATE. Die Bedingung ``response IS NULL`` und die
# atomare Sichtbarkeitsgarantie von PostgreSQL sorgen dafür, dass bei zwei
# gleichzeitigen Anfragen genau eine eine Zeile trifft. Die zweite bekommt
# rowcount 0 — ohne dass die Anwendung sperren oder zählen müsste.
#
# Ein Ablauf „lesen, prüfen, schreiben" in der Anwendung wäre hier falsch:
# Beide Anfragen lesen ``NULL``, beide halten sich für die erste.
_BURN = text(
    """
    UPDATE pending_actions
       SET response      = :response,
           responded_at  = :now,
           responded_via = :channel
     WHERE id            = :id
       AND response IS NULL
       AND expires_at    > :now
    RETURNING id
    """
)

_EXPIRE = text(
    """
    UPDATE pending_actions
       SET response = 'expired', responded_at = :now
     WHERE id = :id AND response IS NULL
    """
)

_FROZEN = text("SELECT frozen_arguments FROM pending_actions WHERE id = :id")

_OPEN = text(
    """
    SELECT id, run_id, invocation_id, user_id, session_id, tool_name,
           preview, risk_level, reason, payload_hash, nonce,
           requested_channel, expires_at, created_at,
           response, responded_at, responded_via
    FROM pending_actions
    WHERE user_id = :user_id AND response IS NULL
    ORDER BY created_at
    """
)


class PostgresApprovalStore:
    """Erfüllt ``jarvis_core.ports.approval.ApprovalStore``."""

    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def create(self, action: PendingAction, arguments: dict[str, Any]) -> None:
        await self._conn.execute(
            _INSERT,
            {
                "id": action.id,
                "run_id": action.run_id,
                "invocation_id": action.invocation_id,
                "user_id": action.user_id,
                "session_id": action.session_id,
                "tool_name": action.tool_name,
                "preview": action.preview.model_dump_json(),
                "risk_level": action.risk.value,
                "reason": action.reason,
                "payload_hash": action.payload_hash,
                "nonce": action.nonce,
                "frozen_arguments": _dump(arguments),
                "requested_channel": action.requested_channel,
                "expires_at": action.expires_at,
                "created_at": action.created_at,
            },
        )

    async def get(self, action_id: UUID) -> PendingAction | None:
        row = (await self._conn.execute(_SELECT, {"id": action_id})).mappings().one_or_none()
        return None if row is None else _als_vorgang(row)

    async def frozen_arguments(self, action_id: UUID) -> dict[str, Any]:
        row = (await self._conn.execute(_FROZEN, {"id": action_id})).one_or_none()
        if row is None:
            return {}
        value: dict[str, Any] = row[0] or {}
        return value

    async def burn(
        self,
        *,
        action_id: UUID,
        nonce: str,
        response: str,
        channel: ApprovalChannel,
        now: datetime,
    ) -> BurnResult:
        """Atomarer Verbrauch.

        Der Nonce-Vergleich geschieht in Python mit ``compare_digest``, nicht in
        der WHERE-Klausel: Ein SQL-Vergleich wäre nicht zeitkonstant. Die
        *Atomarität* dagegen muss in SQL liegen — beides zusammen ergibt die
        Zuordnung von Verantwortlichkeiten.
        """
        stored = await self.get(action_id)
        if stored is None:
            return BurnResult.NOT_FOUND
        if not secrets.compare_digest(stored.nonce, nonce):
            return BurnResult.NONCE_MISMATCH

        result = await self._conn.execute(
            _BURN,
            {"id": action_id, "response": response, "now": now, "channel": channel},
        )
        if result.rowcount == 1:
            return BurnResult.BURNED

        # Kein Treffer: entweder schon verbraucht oder abgelaufen. Die
        # Unterscheidung interessiert, weil nur das eine ein Vorfall ist.
        current = await self.get(action_id)
        if current is not None and not current.is_open:
            return BurnResult.ALREADY_USED
        return BurnResult.EXPIRED

    async def claim_execution(self, action_id: UUID, now: datetime) -> bool:
        row = (await self._conn.execute(_CLAIM, {"id": action_id, "now": now})).first()
        return row is not None

    async def expire(self, action_id: UUID, now: datetime) -> None:
        await self._conn.execute(_EXPIRE, {"id": action_id, "now": now})

    async def open_for_user(self, user_id: UUID) -> list[PendingAction]:
        """Die offenen Vorgänge eines Nutzers — in **einer** Abfrage.

        Die erste Fassung las die Liste und holte danach jede Zeile einzeln
        über ``get()`` nach: ein N+1, das das Dossier unter „bekannte kleinere
        Mängel" führte und ausdrücklich vor der Oberfläche behoben haben
        wollte. Die Oberfläche fragt diese Liste bei jedem Takt ab.

        **Die Zeilen waren die ganze Zeit schon da.** ``_OPEN`` wählt dieselben
        Spalten wie ``_SELECT``; nachgeholt wurde, was bereits vorlag. Der
        eigentliche Fehler war nicht die Schleife, sondern dass die Abbildung
        Zeile → Vorgang nur in ``get()`` stand — wer sie nicht doppeln wollte,
        musste ``get()`` aufrufen. Jetzt steht sie in ``_als_vorgang()``, und
        beide benutzen sie.
        """
        rows = (await self._conn.execute(_OPEN, {"user_id": user_id})).mappings().all()
        return [_als_vorgang(row) for row in rows]


def _als_vorgang(row: RowMapping) -> PendingAction:
    """Eine Zeile als ``PendingAction``.

    Eine Stelle für beide Leser. Zwei Abbildungen derselben Tabelle wären zwei
    Wahrheiten darüber, welche Spalte welches Feld füllt — und die zweite
    vergisst irgendwann eine.
    """
    return PendingAction.model_validate(
        {
            "id": row["id"],
            "run_id": row["run_id"],
            "invocation_id": row["invocation_id"],
            "user_id": row["user_id"],
            "session_id": row["session_id"],
            "tool_name": row["tool_name"],
            "preview": row["preview"],
            "risk": row["risk_level"],
            "reason": row["reason"],
            "payload_hash": row["payload_hash"],
            "nonce": row["nonce"],
            "requested_channel": row["requested_channel"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "response": row["response"],
            "responded_at": row["responded_at"],
            "responded_via": row["responded_via"],
        }
    )


def _dump(value: dict[str, Any]) -> str:
    """Argumente kanonisch serialisieren.

    Dieselbe Kanonisierung wie in ``jarvis_core.policy.approval`` — sonst
    stimmte der Hash beim Wiedereinlesen nicht mit dem gespeicherten überein.
    """
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
