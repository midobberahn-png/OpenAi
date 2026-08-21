"""Das Werkzeugprotokoll als Recovery-Anker.

Ein Lauf, der mit belegtem ``current_step`` steht, ist entweder in Arbeit oder
hängengeblieben — von außen nicht unterscheidbar. Die Wiederaufnahme kann das
nur beantworten, wenn sie nachsehen kann, **was aus dem Aufruf geworden ist**.
Der Anker dafür ist ``tool_invocations``.

**Gemessen, bevor gebaut wurde**, und das Ergebnis hat den Zuschnitt bestimmt:

*Der Zustandsraum trägt die entscheidende Unterscheidung.* Der Grant-Verbrauch
committet in eigener Transaktion unmittelbar **vor** dem Handler (die Reparatur
des vierten Replay-Pfads). Damit ist ``consumed_at`` genau der Marker „der
Handler stand unmittelbar bevor":

    consumed_at IS NULL      → der Handler wurde nachweislich nie gerufen
    consumed_at IS NOT NULL  → er stand bevor; was daraus wurde, sagt der Status

*Drei Dinge fehlten dafür.* Das Protokoll war **nicht auffindbar** (kein Feld
trug die Planschritt-Nummer), **nicht lesbar** (der Speicher hatte kein einziges
``SELECT``) und **nicht eindeutig**: ``FAILED`` stand sowohl für „das Werkzeug
hat abgelehnt" als auch für „der Handler ist geflogen" — für die Wiederaufnahme
sind das entgegengesetzte Antworten.

Diese Suite hält alle drei fest.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.invocation_store import PostgresInvocationStore
from jarvis_api.db.run_store import PostgresRunStore
from jarvis_contracts import (
    InvocationStatus,
    PolicyEffect,
    RiskLevel,
    Run,
    RunStatus,
    RunTrigger,
    ToolInvocation,
)
from jarvis_core.orchestrator import utc_now

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]


@pytest.fixture(autouse=True)
async def _aufraeumen(engine: AsyncEngine):
    yield
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users WHERE email LIKE 'protokoll-%'"))


async def _lauf(engine: AsyncEngine) -> Run:
    nutzer = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'P')"),
            {"i": nutzer, "m": f"protokoll-{nutzer}@example.test"},
        )
    lauf = Run(
        id=uuid.uuid4(),
        user_id=nutzer,
        trigger=RunTrigger.USER,
        status=RunStatus.EXECUTING,
        trace_id=uuid.uuid4().hex,
        started_at=utc_now(),
    )
    await PostgresRunStore(engine).create(lauf)
    return lauf


def _aufruf(lauf: Run, *, seq: int | None, **kw: object) -> ToolInvocation:
    basis: dict[str, object] = {
        "id": uuid.uuid4(),
        "run_id": lauf.id,
        "step_seq": seq,
        "tool_name": "calendar.create",
        "arguments": {"title": "A"},
        "risk_level": RiskLevel.MEDIUM,
        "policy_decision": PolicyEffect.ALLOW,
        "decision_reason": "erlaubt",
        "created_at": datetime.now(UTC),
    }
    basis.update(kw)
    return ToolInvocation(**basis)  # type: ignore[arg-type]


class TestAuffindbar:
    """Ohne Schrittnummer findet die Wiederaufnahme den Aufruf nicht.

    Sie bekommt einen Lauf mit ``current_step=3`` und muss wissen, was aus
    *diesem* Schritt geworden ist. ``ToolInvocation`` führte dafür ein
    ``step_id: UUID | None``, das niemand setzte — und das auch nicht passte:
    Ein Planschritt hat eine Nummer, keine UUID.
    """

    @pytest.mark.invariant("invocation-is-recovery-anchor")
    async def test_der_aufruf_traegt_seinen_planschritt(self, engine: AsyncEngine) -> None:
        lauf = await _lauf(engine)
        speicher = PostgresInvocationStore(engine)
        await speicher.record(_aufruf(lauf, seq=3))

        (gefunden,) = await speicher.for_run(lauf.id)
        assert gefunden.step_seq == 3

    @pytest.mark.invariant("invocation-is-recovery-anchor")
    async def test_der_aufruf_zu_einem_schritt_ist_auffindbar(self, engine: AsyncEngine) -> None:
        lauf = await _lauf(engine)
        speicher = PostgresInvocationStore(engine)
        await speicher.record(_aufruf(lauf, seq=1))
        await speicher.record(_aufruf(lauf, seq=2))

        (fuer_zwei,) = await speicher.for_step(lauf.id, 2)
        assert fuer_zwei.step_seq == 2

    async def test_ein_schritt_ohne_plan_bleibt_zulaessig(self, engine: AsyncEngine) -> None:
        """``POST /runs/{id}/steps`` gehört zu keinem Planschritt.

        ``None`` ist deshalb kein Mangel, sondern die richtige Auskunft — und
        die Wiederaufnahme darf einen solchen Aufruf keinem Planschritt
        zuordnen.
        """
        lauf = await _lauf(engine)
        speicher = PostgresInvocationStore(engine)
        await speicher.record(_aufruf(lauf, seq=None))

        (frei,) = await speicher.for_run(lauf.id)
        assert frei.step_seq is None
        assert await speicher.for_step(lauf.id, 1) == []


class TestLesbar:
    """Der Speicher hatte ``record`` und ``mark`` — und kein einziges SELECT.

    Ein Anker, den niemand abfragen kann, ist keiner.
    """

    @pytest.mark.invariant("invocation-is-recovery-anchor")
    async def test_ein_aufruf_laesst_sich_wieder_lesen(self, engine: AsyncEngine) -> None:
        lauf = await _lauf(engine)
        speicher = PostgresInvocationStore(engine)
        aufruf = _aufruf(lauf, seq=1)
        await speicher.record(aufruf)

        geladen = await speicher.load(aufruf.id)
        assert geladen is not None
        assert geladen.id == aufruf.id
        assert geladen.tool_name == "calendar.create"
        assert geladen.arguments == {"title": "A"}
        assert geladen.status is InvocationStatus.PENDING

    async def test_ein_unbekannter_aufruf_ist_kein_fehler(self, engine: AsyncEngine) -> None:
        assert await PostgresInvocationStore(engine).load(uuid.uuid4()) is None

    async def test_nur_die_aufrufe_des_gefragten_laufs(self, engine: AsyncEngine) -> None:
        """Wie beim Laufspeicher: Die Einschränkung steht in der Abfrage und
        ist nicht weglassbar."""
        eins, zwei = await _lauf(engine), await _lauf(engine)
        speicher = PostgresInvocationStore(engine)
        await speicher.record(_aufruf(eins, seq=1))
        await speicher.record(_aufruf(zwei, seq=1))

        assert len(await speicher.for_run(eins.id)) == 1


class TestEindeutig:
    """``FAILED`` stand für zwei entgegengesetzte Lagen.

    ``_mark(FAILED)`` wurde gesetzt, wenn ``registry.execute`` warf — dann ist
    unklar, ob der Handler gewirkt hat — **und** wenn das Werkzeug ``ok=False``
    lieferte, also selbst abgelehnt hat. Für die Wiederaufnahme sind das
    entgegengesetzte Antworten: das eine „nicht automatisch wiederholen", das
    andere „nichts geschehen".

    ``EFFECT_UNKNOWN`` trennt sie. **Der Name ist die Zusage:** Er behauptet
    nicht, dass etwas schiefging, sondern dass niemand es weiß.
    """

    @pytest.mark.invariant("invocation-is-recovery-anchor")
    async def test_unklare_wirkung_ist_ein_eigener_zustand(self, engine: AsyncEngine) -> None:
        lauf = await _lauf(engine)
        speicher = PostgresInvocationStore(engine)
        aufruf = _aufruf(lauf, seq=1)
        await speicher.record(aufruf)

        await speicher.mark(
            aufruf.id, InvocationStatus.EFFECT_UNKNOWN, error="Handler ist geflogen."
        )

        geladen = await speicher.load(aufruf.id)
        assert geladen is not None
        assert geladen.status is InvocationStatus.EFFECT_UNKNOWN

    @pytest.mark.asyncio(loop_scope="function")
    async def test_unklare_wirkung_gilt_nicht_als_abgeschlossen(self) -> None:
        """Ein Zustand, der als erledigt zählt, käme nie zur Wiederaufnahme."""
        assert not InvocationStatus.EFFECT_UNKNOWN.is_settled
        assert InvocationStatus.EXECUTED.is_settled
        assert InvocationStatus.FAILED.is_settled
        assert InvocationStatus.BLOCKED.is_settled

    @pytest.mark.asyncio(loop_scope="function")
    async def test_unklare_wirkung_ist_nicht_automatisch_wiederholbar(self) -> None:
        """**Die eigentliche Zusage dieses Zustands.**

        Sie steht am Vertrag und nicht in der Wiederaufnahme: Wer später
        entscheidet, was wiederholt werden darf, soll die Frage nicht neu
        beantworten müssen — und sie nicht anders beantworten können.
        """
        assert not InvocationStatus.EFFECT_UNKNOWN.may_retry
        assert InvocationStatus.BLOCKED.may_retry
        assert not InvocationStatus.EXECUTED.may_retry
