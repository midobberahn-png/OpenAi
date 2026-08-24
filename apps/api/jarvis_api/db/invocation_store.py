"""Werkzeugaufruf-Protokoll auf PostgreSQL.

Jeder Aufruf wird vor seiner Wirkung festgehalten — mit den Argumenten, der
Risikoklasse und der Policy-Entscheidung, die zu ihm geführt hat. Drei Gründe,
und der dritte ist seit dem vierten Replay-Befund der zwingende:

1. **Nachvollziehbarkeit.** „Wer hat das ausgelöst?“ muss beantwortbar sein,
   auch wenn der Lauf abgestürzt ist.
2. **Fremdschlüssel.** ``pending_actions.invocation_id`` verweist hierher.
   Ohne diese Zeile lässt sich keine Bestätigung anlegen, und damit ist kein
   bestätigungspflichtiges Werkzeug ausführbar.
3. **Der Grant-Anspruch hängt an dieser Zeile.** ``PostgresGrantConsumer``
   verbraucht den Grant per ``UPDATE … WHERE id = :invocation_id`` in einer
   **eigenen** Transaktion — das ist es, was ihn einen Absturz überstehen
   lässt. Eine Transaktion sieht keine fremden uncommitteten Zeilen. Läge das
   Protokoll in der offenen Request-Transaktion, fände der Anspruch nichts und
   es liefe gar nichts mehr.

**Jeder Schreibvorgang committet für sich.**

Punkt 1 sagte das immer schon zu — „auch wenn der Lauf abgestürzt ist“ —, und
die erste Fassung hielt es nicht: Sie schrieb auf der Verbindung des Requests,
also in dessen Transaktion. Ein Absturz nahm das Protokoll mit, und zwar genau
dann, wenn man es liest. Ein Protokolleintrag, der zurückrollen kann, ist
keiner.

Deshalb nimmt dieser Store eine ``AsyncEngine`` und keine ``AsyncConnection``.
Dieselbe Entscheidung wie beim Grant-Verbrauch und aus demselben Grund; der
Typ verhindert, dass beim nächsten Verdrahten wieder die Request-Verbindung
hereingereicht wird.

**Was das vom Aufrufer verlangt — und was es ihm erspart.**

Verlangt: Der Lauf muss committed sein, bevor hier protokolliert wird.
``tool_invocations.run_id`` ist ein Fremdschlüssel auf ``runs``; eine Zeile,
die nur in der offenen Transaktion des Aufrufers existiert, verletzt ihn. Das
scheitert laut und sofort — eine ``IntegrityError`` und kein stilles
Durchlaufen.

Erspart: Die Request-Transaktion fasst ``tool_invocations`` nicht mehr an. Die
Verklemmung, die sonst drohte — der Anspruch wartet in seiner eigenen
Transaktion auf eine Zeilensperre, die der Request erst nach der Rückkehr des
Anspruchs freigibt —, kann damit nicht mehr entstehen. Sie war vorher eine
Reihenfolgebedingung, um die sich jeder Aufrufer kümmern musste. Jetzt ist sie
weg.

**Preis:** Ein Protokolleintrag bleibt stehen, auch wenn der Request danach
scheitert. Das ist beabsichtigt und die Richtung, die zu einem Protokoll passt:
Ein Aufruf, der erwogen und entschieden wurde, hat stattgefunden — ob er
gewirkt hat, sagt ``status``.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_contracts import (
    UNDO_TTL,
    InvocationStatus,
    PolicyEffect,
    RiskLevel,
    ToolInvocation,
)
from jarvis_core.ports.invocations import UndoClaim

__all__ = ["PostgresInvocationStore"]


_INSERT = text(
    """
    INSERT INTO tool_invocations (
        id, run_id, step_seq, tool_name, arguments, risk_level,
        policy_decision, decision_reason, idempotency_key, status, created_at
    ) VALUES (
        :id, :run_id, :step_seq, :tool_name, CAST(:arguments AS jsonb), :risk_level,
        :policy_decision, :decision_reason, :idempotency_key, :status, :created_at
    )
    ON CONFLICT (id) DO NOTHING
    """
)
"""``ON CONFLICT DO NOTHING``: Eine wiederaufgenommene Ausführung darf nicht am
bereits protokollierten Aufruf scheitern. Das Protokoll ist Beleg, nicht
Sperre — die Einmaligkeit der *Ausführung* trägt die Nonce, die des *Grants*
der Verbrauch von ``consumed_at``.

Und es ist mehr als Bequemlichkeit, seit der Eintrag eigenständig committet:
Ein Neustart, der denselben Schritt wieder aufnimmt, trifft die Zeile jetzt
tatsächlich an. Vorher war sie mit der abgebrochenen Transaktion verschwunden,
und die Frage stellte sich nie."""

_MARK = text(
    """
    UPDATE tool_invocations
       SET status = :status,
           result = CAST(:result AS jsonb),
           executed_at = COALESCE(executed_at, :now)
     WHERE id = :id
    """
)
"""``COALESCE(executed_at, :now)`` hält den **ersten** Ausführungszeitpunkt
fest. Ein späteres Fortschreiben des Status verschiebt ihn nicht."""


_CLAIM_UNDO = text(
    """
    UPDATE tool_invocations AS i
       SET status = 'undoing'
      FROM runs AS r
     WHERE i.id = :id
       AND r.id = i.run_id
       AND r.user_id = :user_id
       AND i.status = 'executed'
       AND i.executed_at > CAST(:now AS timestamptz) - CAST(:frist AS interval)
    RETURNING i.tool_name, i.result ->> 'undo_token' AS undo_token
    """
)
"""Beansprucht die Rücknahme — vier Bedingungen in **einer** Anweisung.

``r.user_id = :user_id`` ist die Zugehörigkeit, und sie steht hier und nicht in
einer Prüfung darüber. Das Protokoll führt keinen Nutzer; er hängt am Lauf, und
der Weg dorthin ist ein Join. Eine Auflösung in zwei Schritten — Lauf laden,
Nutzer vergleichen, dann schreiben — wäre bei zwei gleichzeitigen Anfragen
wieder das bekannte Muster.

``i.status = 'executed'`` ist zugleich der Einmaligkeitsanspruch: Nach dem
ersten Treffer steht dort ``undoing``, und die Bedingung gilt nicht mehr.

**Warum ``undoing`` und nicht gleich ``undone``.** Dieser Schritt sichert den
Übergang *Aufruf → Erlaubnis*. Der zweite — *Erlaubnis → Handler* — steht in
``_CONSUME_UNDO`` und ist ein anderer Angriff: Wer die ausgestellte Erlaubnis
behält, legt sie erneut vor, und Typ, Nutzer und Werkzeugname gelten
unverändert. Ein einziger Zustandswechsel für beide Übergänge deckte den
zweiten nicht ab; gemeldet von einer externen Prüfung zu ``61d4428``.

``executed_at > CAST(:now AS timestamptz) - :frist`` ist die Frist. Der
``CAST`` ist kein Zierrat: Ohne ihn hält PostgreSQL den Parameter für
``unknown``, löst die Subtraktion als ``interval - interval`` auf und bricht ab
— gemessen an genau dieser Fehlermeldung. ``:now`` kommt vom Aufrufer und
nicht aus ``now()``, anders als bei der Frist auf dem Anspruch — dort messen
zwei Prozesse gegeneinander, hier misst ein Request gegen eine Zeile, und die
Zeit gehört zum Vorgang. Wer sie fälschte, säße bereits im Prozess.

``RETURNING`` liefert, was die Rücknahme braucht: welches Werkzeug und woran.
Beides aus der Zeile und nicht aus dem Request — das ist der Unterschied
zwischen einer Rücknahme und einem Löschrecht."""


_CONSUME_UNDO = text(
    """
    UPDATE tool_invocations
       SET status = 'undone',
           result = COALESCE(result, '{}'::jsonb)
                    || jsonb_build_object('undone_at', CAST(:now AS text))
     WHERE id = :id
       AND status = 'undoing'
    RETURNING id
    """
)
"""Löst die **ausgestellte** Rücknahme-Erlaubnis ein — genau einmal.

Der Gegenpart zu ``_CLAIM_UNDO`` und dieselbe Bauart wie ``_CONSUME`` beim
Ausführungs-Grant: Die Einmaligkeit steht in der ``WHERE``-Klausel, und der
Verbrauch committet, bevor der Handler läuft.

``AND status = 'undoing'`` ist die ganze Zusage: Nach dem ersten Treffer steht
dort ``undone``, und jede weitere Vorlage derselben Erlaubnis findet nichts.
Zwei gleichzeitige Vorlagen — genau einer gewinnt.

Ohne Zugehörigkeitsprüfung, und das ist kein Versehen: Sie ist beim Anspruch
bereits gefallen, und die Erlaubnis, die hier vorgelegt wird, gibt es nur aus
dem Gate. Eine zweite Prüfung wäre die zweite Wahrheit über dieselbe Frage.

``undone_at`` im Ergebnis statt in einer eigenen Spalte: Die Zeit ist Auskunft
und keine Bedingung — geprüft wird an ``status``, und ein Feld, an dem nichts
hängt, braucht keine Migration. Der ``CAST`` darum ist nötig, weil
``jsonb_build_object`` den Typ eines nackten Parameters nicht herleiten kann;
ohne ihn bricht PostgreSQL mit ``IndeterminateDatatypeError`` ab."""


_SPALTEN = (
    "id, run_id, step_seq, tool_name, arguments, risk_level, policy_decision, "
    "decision_reason, idempotency_key, status, result, created_at, executed_at"
)

_LADEN = text(f"SELECT {_SPALTEN} FROM tool_invocations WHERE id = :id")

_FUER_LAUF = text(
    f"""
    SELECT {_SPALTEN}
      FROM tool_invocations
     WHERE run_id = :run_id
     ORDER BY created_at
    """
)

_FUER_SCHRITT = text(
    f"""
    SELECT {_SPALTEN}
      FROM tool_invocations
     WHERE run_id = :run_id
       AND step_seq = :step_seq
     ORDER BY created_at
    """
)
"""``run_id`` steht in beiden Abfragen und nicht in einem Filter darüber —
dieselbe Überlegung wie beim Laufspeicher: Die Einschränkung soll nicht
weglassbar sein. Der Teilindex ``ix_tool_invocations_run_step`` bedient genau
diese Reihenfolge."""


def _als_vertrag(zeile: Any) -> ToolInvocation:
    """Eine Zeile als ``ToolInvocation``.

    ``consumed_at`` steht bewusst **nicht** im Vertrag: Es gehört dem
    Grant-Verbrauch und nicht dem Protokoll. Wer für die Wiederaufnahme wissen
    will, ob der Anspruch eingelöst wurde, fragt den Verbraucher — sonst gäbe es
    zwei Wahrheiten über dieselbe Tatsache.
    """
    return ToolInvocation(
        id=zeile.id,
        run_id=zeile.run_id,
        step_seq=zeile.step_seq,
        tool_name=zeile.tool_name,
        arguments=zeile.arguments,
        risk_level=RiskLevel(zeile.risk_level),
        policy_decision=PolicyEffect(zeile.policy_decision),
        decision_reason=zeile.decision_reason,
        idempotency_key=zeile.idempotency_key,
        status=InvocationStatus(zeile.status),
        created_at=zeile.created_at,
        executed_at=zeile.executed_at,
    )


class PostgresInvocationStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        """Eine Engine und ausdrücklich keine Verbindung: Das Protokoll gehört
        nicht in die Transaktion dessen, über den es Auskunft gibt."""

    async def record(self, invocation: ToolInvocation) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                _INSERT,
                {
                    "id": invocation.id,
                    "run_id": invocation.run_id,
                    "step_seq": invocation.step_seq,
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

    async def load(self, invocation_id: UUID) -> ToolInvocation | None:
        """Ein einzelner Aufruf, oder ``None``.

        Bis hierher hatte dieser Speicher ``record`` und ``mark`` und **kein
        einziges SELECT**. Das Protokoll war schreibend-only — und damit als
        Anker für eine Wiederaufnahme unbrauchbar: Ein Lauf, der mit belegtem
        Schritt steht, ließ sich nicht befragen.
        """
        async with self._engine.begin() as conn:
            zeile = (await conn.execute(_LADEN, {"id": invocation_id})).first()
        return _als_vertrag(zeile) if zeile is not None else None

    async def for_run(self, run_id: UUID) -> list[ToolInvocation]:
        """Alle Aufrufe eines Laufs, älteste zuerst."""
        async with self._engine.begin() as conn:
            zeilen = (await conn.execute(_FUER_LAUF, {"run_id": run_id})).all()
        return [_als_vertrag(z) for z in zeilen]

    async def for_step(self, run_id: UUID, step_seq: int) -> list[ToolInvocation]:
        """Die Aufrufe **eines Planschrittes** — die Frage der Wiederaufnahme.

        Eine Liste und kein einzelner Eintrag: Ein Schritt kann mehrfach
        protokolliert sein, wenn er nach einer folgenlosen Abweisung erneut
        versucht wurde. Welcher davon zählt, entscheidet die Wiederaufnahme —
        nicht dieser Speicher.
        """
        async with self._engine.begin() as conn:
            zeilen = (
                await conn.execute(_FUER_SCHRITT, {"run_id": run_id, "step_seq": step_seq})
            ).all()
        return [_als_vertrag(z) for z in zeilen]

    async def claim_undo(
        self, invocation_id: UUID, *, user_id: UUID, now: datetime
    ) -> UndoClaim | None:
        """Beansprucht die Rücknahme in eigener Transaktion.

        Dieselbe Bauart wie beim Grant-Verbrauch: Der Anspruch muss
        festgeschrieben sein, bevor die Wirkung beginnt. Läge er in der
        Transaktion des Requests, gäbe ein Absturz nach dem Löschen ihn zurück
        — und der Termin wäre weg, der Aufruf aber wieder zurücknehmbar.
        """
        async with self._engine.begin() as conn:
            zeile = (
                await conn.execute(
                    _CLAIM_UNDO,
                    {
                        "id": invocation_id,
                        "user_id": user_id,
                        "now": now,
                        "frist": UNDO_TTL,
                    },
                )
            ).first()
        if zeile is None:
            return None
        return UndoClaim(tool_name=zeile.tool_name, undo_token=zeile.undo_token)

    async def consume_undo(self, invocation_id: UUID, *, now: datetime) -> bool:
        """Löst die ausgestellte Rücknahme-Erlaubnis ein — eigene Transaktion.

        Der Aufruf kehrt erst zurück, wenn der Verbrauch committed ist. Danach
        — und erst danach — ruft die Registry den Handler. Ohne diese
        Reihenfolge rollte ein Absturz den Verbrauch zurück, während die
        Löschung bereits geschehen wäre, und der nächste Versuch nähme ein
        zweites Mal zurück.
        """
        async with self._engine.begin() as conn:
            treffer = await conn.execute(
                _CONSUME_UNDO, {"id": invocation_id, "now": now.isoformat()}
            )
            return treffer.first() is not None

    async def mark(
        self,
        invocation_id: object,
        status: InvocationStatus,
        *,
        error: str | None = None,
        undo_token: str | None = None,
    ) -> None:
        payload: dict[str, Any] = {}
        if error:
            payload["error"] = error
        if undo_token:
            payload["undo_token"] = undo_token
        async with self._engine.begin() as conn:
            await conn.execute(
                _MARK,
                {
                    "id": UUID(str(invocation_id)),
                    "status": str(status),
                    "result": json.dumps(payload) if payload else None,
                    "now": datetime.now(tz=None).astimezone(),
                },
            )
