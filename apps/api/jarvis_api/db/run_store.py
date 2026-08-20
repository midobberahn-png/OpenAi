"""Laufpersistenz auf PostgreSQL.

Erfüllt ``RunStore``. Drei Entscheidungen, und alle drei sind anderswo im
Projekt schon einmal gefallen:

**Eigene Transaktion je Schreibvorgang.** Dieselbe Bauart wie beim
Werkzeugprotokoll und beim Grant-Verbrauch, und hier die Wurzel der Kette: Das
Protokoll braucht eine committete Zeile in ``runs`` als Fremdschlüssel, und der
Anspruch braucht das Protokoll. Ein Lauf, der nur in der Transaktion des
Requests existiert, bricht die Kette an ihrem ersten Glied — mit einer
``IntegrityError`` beim Protokollieren, laut und nicht still.

**Der Statusvergleich steht in der ``WHERE``-Klausel.** ``load()`` … entscheiden
… ``save()`` ist bei zwei Schreibern ein Überschreiben. Ein
``if run.status == erwartet:`` davor prüfte einen Wert, der zum Zeitpunkt des
Schreibens schon veraltet sein kann. Dieselbe Überlegung wie bei Nonce,
Ausführungsanspruch und Grant-Verbrauch — der vierte Fall desselben Musters,
diesmal von vornherein an der richtigen Stelle.

**Der Status wird nicht gefolgert, sondern verlangt.** ``save()`` bekommt den
erwarteten Status vom Aufrufer. Aus ``run.status`` ließe er sich nicht
gewinnen: Der übergebene Lauf trägt bereits den neuen.

Was hier **nicht** geprüft wird, ist die Zulässigkeit des Übergangs. Die
entscheidet ``fsm.assert_transition()`` im Kern. Diese Schicht beantwortet nur,
ob die Zeile noch dort steht, wo der Aufrufer sie vermutet.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_contracts import Run, RunStatus
from jarvis_core.ports.runs import RunNotStored, RunStateConflict

__all__ = ["PostgresRunStore"]


_SPALTEN = (
    "id, user_id, conversation_id, trigger, status, classification, routing, plan, "
    "state, taint_level, data_class, budget, usage, trace_id, error, started_at, "
    "finished_at, sanitized_from_run_id"
)

_INSERT = text(
    f"""
    INSERT INTO runs ({_SPALTEN}) VALUES (
        :id, :user_id, :conversation_id, :trigger, :status,
        CAST(:classification AS jsonb), CAST(:routing AS jsonb), CAST(:plan AS jsonb),
        CAST(:state AS jsonb), :taint_level, :data_class,
        CAST(:budget AS jsonb), CAST(:usage AS jsonb), :trace_id,
        CAST(:error AS jsonb), :started_at, :finished_at, :sanitized_from_run_id
    )
    """
)
"""Ohne ``ON CONFLICT``: Eine zweite Anlage desselben Laufs ist ein Fehler und
keine Wiederholung. Die ID entsteht beim Anlegen; trifft sie auf eine
bestehende Zeile, stimmt eine Annahme des Aufrufers nicht — das soll auffallen.
Der Gegenfall ist ``tool_invocations``, wo ``ON CONFLICT DO NOTHING`` richtig
ist, weil eine wiederaufgenommene Ausführung denselben Schritt erneut
protokolliert."""

_SELECT = text(f"SELECT {_SPALTEN} FROM runs WHERE id = :id")

_UPDATE = text(
    """
    UPDATE runs
       SET conversation_id = :conversation_id,
           trigger = :trigger,
           status = :status,
           classification = CAST(:classification AS jsonb),
           routing = CAST(:routing AS jsonb),
           plan = CAST(:plan AS jsonb),
           state = CAST(:state AS jsonb),
           taint_level = :taint_level,
           data_class = :data_class,
           budget = CAST(:budget AS jsonb),
           usage = CAST(:usage AS jsonb),
           trace_id = :trace_id,
           error = CAST(:error AS jsonb),
           started_at = :started_at,
           finished_at = :finished_at,
           sanitized_from_run_id = :sanitized_from_run_id
     WHERE id = :id
       AND status = :erwarteter_status
    RETURNING id
    """
)
"""``AND status = :erwarteter_status`` ist die ganze Zusicherung.

Trefferzahl null heißt: Die Zeile steht woanders — oder es gibt sie nicht.
Beides muss unterschieden werden, deshalb folgt im selben Transaktionsrahmen
eine Abfrage auf die ID. Sie ist billig und läuft nur im Fehlerfall."""

_EXISTIERT = text("SELECT status FROM runs WHERE id = :id")


def _json(wert: Any) -> str | None:
    """Nested Verträge als JSON, ``None`` als SQL-NULL.

    ``mode="json"`` und nicht ``model_dump()``: Sonst landen ``UUID``,
    ``datetime`` und ``Decimal`` als Python-Objekte im Dump, die
    ``json.dumps`` nicht kennt. Ein ``default=str`` würde sie zwar
    hindurchlassen, aber unumkehrbar — beim Lesen käme eine Zeichenkette
    zurück, wo ein Betrag stand.
    """
    if wert is None:
        return None
    if hasattr(wert, "model_dump"):
        return json.dumps(wert.model_dump(mode="json"), ensure_ascii=False)
    return json.dumps(wert, ensure_ascii=False)


def _parameter(run: Run) -> dict[str, Any]:
    return {
        "id": run.id,
        "user_id": run.user_id,
        "conversation_id": run.conversation_id,
        "trigger": str(run.trigger),
        "status": str(run.status),
        "classification": _json(run.classification),
        "routing": _json(run.routing),
        "plan": _json(run.plan),
        "state": _json(run.state),
        "taint_level": str(run.taint_level),
        "data_class": str(run.data_class),
        "budget": _json(run.budget),
        "usage": _json(run.usage),
        "trace_id": run.trace_id,
        "error": _json(run.error),
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "sanitized_from_run_id": run.sanitized_from_run_id,
    }


class PostgresRunStore:
    """Läufe, dauerhaft und mit geprüftem Fortschreiben."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        """Eine Engine, keine Verbindung — der Lauf muss committed sein, bevor
        das Werkzeugprotokoll ihn als Fremdschlüssel braucht."""

    async def create(self, run: Run) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(_INSERT, _parameter(run))

    async def load(self, run_id: UUID) -> Run | None:
        async with self._engine.connect() as conn:
            zeile = (await conn.execute(_SELECT, {"id": run_id})).mappings().first()
        if zeile is None:
            return None
        return Run.model_validate(dict(zeile))

    async def save(self, run: Run, *, erwarteter_status: RunStatus) -> None:
        async with self._engine.begin() as conn:
            parameter = _parameter(run)
            parameter["erwarteter_status"] = str(erwarteter_status)
            if (await conn.execute(_UPDATE, parameter)).first() is not None:
                return

            # Null Treffer — jetzt erst die Ursache klären.
            aktuell = (await conn.execute(_EXISTIERT, {"id": run.id})).scalar_one_or_none()

        if aktuell is None:
            raise RunNotStored(f"Kein Lauf mit der ID {run.id}.")
        raise RunStateConflict(
            f"Lauf {run.id} steht in {aktuell!r}, erwartet war {str(erwarteter_status)!r}. "
            "Ein anderer Schreiber war schneller; neu laden und die Entscheidung "
            "wiederholen."
        )
