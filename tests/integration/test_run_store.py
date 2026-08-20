"""Laufpersistenz gegen die echte Datenbank.

Zwei Eigenschaften lassen sich nur hier prüfen, und beide sind der Grund für
diesen Store:

**Der Rundlauf durch JSONB.** Ein Lauf trägt verschachtelte Verträge —
Einstufung, Routing, Plan, Zwischenzustand — und darin ``Decimal`` und
``datetime``. Ein In-Memory-Doppel würde dieselben Objekte zurückgeben, die es
bekommen hat, und damit nichts belegen. Der interessante Fall ist der Weg durch
JSON und zurück: Aus einem Betrag darf keine Zeichenkette werden, aus einem
Zeitpunkt keine naive Uhrzeit.

**Das geprüfte Fortschreiben.** Der Statusvergleich liegt in der
``WHERE``-Klausel. Ob das trägt, zeigt sich erst bei echter Nebenläufigkeit
über getrennte Verbindungen — in einer Ereignisschleife allein wäre es keine
Aussage.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.run_store import PostgresRunStore
from jarvis_contracts import (
    Capability,
    Complexity,
    DataClass,
    Intent,
    Plan,
    PlanStep,
    RoutingDecision,
    Run,
    RunBudget,
    RunStatus,
    RunTrigger,
    TaintLevel,
    TurnClassification,
    Usage,
)
from jarvis_core.ports.runs import RunNotStored, RunStateConflict

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

NOW = datetime(2026, 8, 20, 10, 0, tzinfo=UTC)


async def _nutzer(engine: AsyncEngine) -> uuid.UUID:
    uid = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:id, :m, 'Lauf')"),
            {"id": uid, "m": f"{uid}@example.test"},
        )
    return uid


def _voller_lauf(user_id: uuid.UUID) -> Run:
    """Ein Lauf mit gefüllten Feldern — leere Objekte belegen den Rundlauf nicht."""
    return Run(
        id=uuid.uuid4(),
        user_id=user_id,
        trigger=RunTrigger.SCHEDULE,
        status=RunStatus.QUEUED,
        classification=TurnClassification(
            intent=Intent.TASK,
            complexity=Complexity.COMPLEX,
            data_class=DataClass.P2,
            required_capabilities=[Capability.TOOL_CALLING],
            likely_tools=["mail.read", "calendar.create"],
            is_multi_step=True,
            ambiguous_references=["das Wichtigste"],
            confidence=0.82,
        ),
        routing=RoutingDecision(
            model="llama-3.1-8b",
            provider="ollama",
            reason="P2 bleibt lokal",
            max_data_class=DataClass.P3,
            rejected={"cloud-fast": "nur P1"},
        ),
        plan=Plan(
            goal="Mails prüfen und Zeit blockieren",
            steps=[
                PlanStep(seq=1, description="Mails lesen", kind="tool", target="mail.read"),
                PlanStep(
                    seq=2,
                    description="Termin anlegen",
                    kind="tool",
                    target="calendar.create",
                    depends_on=[1],
                ),
            ],
            estimated_tokens=4200,
            requires_confirmation=True,
        ),
        taint_level=TaintLevel.TAINTED,
        data_class=DataClass.P2,
        budget=RunBudget(max_tokens=60_000, max_cost_eur=Decimal("0.25")),
        usage=Usage(tokens_in=1200, tokens_out=340, steps=2, cost_eur=Decimal("0.0731")),
        trace_id="rundlauf",
        error={"code": "keiner"},
        started_at=NOW,
    )


class TestRundlauf:
    async def test_alle_felder_ueberstehen_den_weg_durch_die_datenbank(
        self, engine: AsyncEngine, aufgeraeumte_nutzer: list[uuid.UUID]
    ) -> None:
        """Gespeichert und gelesen ist derselbe Lauf.

        Der Vergleich geht über das ganze Modell und nicht über einzelne
        Felder: Ein Feld, das beim Schreiben vergessen wird, fällt sonst genau
        so lange nicht auf, bis jemand es braucht.
        """
        uid = await _nutzer(engine)
        aufgeraeumte_nutzer.append(uid)
        store = PostgresRunStore(engine)
        original = _voller_lauf(uid)

        await store.create(original)
        geladen = await store.load(original.id)

        assert geladen == original, "Der gelesene Lauf weicht vom geschriebenen ab."

    async def test_betraege_bleiben_betraege(
        self, engine: AsyncEngine, aufgeraeumte_nutzer: list[uuid.UUID]
    ) -> None:
        """``Decimal`` überlebt JSON.

        Eigener Test, obwohl der Modellvergleich oben es mitprüft: Diese
        Eigenschaft geht bei einer naheliegenden Bequemlichkeit verloren —
        ``json.dumps(..., default=str)`` schreibt den Betrag als Zeichenkette
        und niemand merkt es, solange nur verglichen wird, was hineinging.
        Kosten, die als Text zurückkommen, addieren sich still falsch.
        """
        uid = await _nutzer(engine)
        aufgeraeumte_nutzer.append(uid)
        store = PostgresRunStore(engine)
        lauf = _voller_lauf(uid)

        await store.create(lauf)
        geladen = await store.load(lauf.id)

        assert geladen is not None
        assert isinstance(geladen.usage.cost_eur, Decimal)
        assert geladen.usage.cost_eur == Decimal("0.0731")
        assert geladen.budget.max_cost_eur == Decimal("0.25")
        assert geladen.started_at == NOW, "Zeitzone verloren"

    async def test_unbekannter_lauf_ist_keine_ausnahme(self, engine: AsyncEngine) -> None:
        assert await PostgresRunStore(engine).load(uuid.uuid4()) is None


class TestFortschreiben:
    @pytest.mark.invariant("run-state-compare-and-set")
    async def test_erwarteter_status_schreibt_fort(
        self, engine: AsyncEngine, aufgeraeumte_nutzer: list[uuid.UUID]
    ) -> None:
        uid = await _nutzer(engine)
        aufgeraeumte_nutzer.append(uid)
        store = PostgresRunStore(engine)
        lauf = _voller_lauf(uid)
        await store.create(lauf)

        weiter = lauf.model_copy(
            update={"status": RunStatus.EXECUTING, "usage": Usage(steps=5, tokens_in=99)}
        )
        await store.save(weiter, erwarteter_status=RunStatus.QUEUED)

        geladen = await store.load(lauf.id)
        assert geladen is not None
        assert geladen.status is RunStatus.EXECUTING
        assert geladen.usage.steps == 5

    @pytest.mark.invariant("run-state-compare-and-set")
    async def test_falscher_erwarteter_status_schreibt_nichts(
        self, engine: AsyncEngine, aufgeraeumte_nutzer: list[uuid.UUID]
    ) -> None:
        """Der Fall, für den der Statusvergleich existiert.

        Ein Schreiber, der den Lauf noch in ``queued`` wähnt, darf einen
        inzwischen abgebrochenen Lauf nicht wieder in Gang setzen. Geprüft wird
        deshalb beides: die Ausnahme **und** dass die Zeile unverändert blieb.
        Nur die Ausnahme zu prüfen ließe offen, ob nebenbei doch etwas
        geschrieben wurde.
        """
        uid = await _nutzer(engine)
        aufgeraeumte_nutzer.append(uid)
        store = PostgresRunStore(engine)
        lauf = _voller_lauf(uid)
        await store.create(lauf)
        await store.save(
            lauf.model_copy(update={"status": RunStatus.CANCELLED}),
            erwarteter_status=RunStatus.QUEUED,
        )

        veraltet = lauf.model_copy(
            update={"status": RunStatus.EXECUTING, "trace_id": "ueberschrieben"}
        )
        with pytest.raises(RunStateConflict) as fehler:
            await store.save(veraltet, erwarteter_status=RunStatus.QUEUED)

        assert "cancelled" in str(fehler.value), "Die Meldung soll den tatsächlichen Stand nennen."

        geladen = await store.load(lauf.id)
        assert geladen is not None
        assert geladen.status is RunStatus.CANCELLED
        assert geladen.trace_id == "rundlauf", "Der veraltete Schreiber hat doch geschrieben."

    @pytest.mark.invariant("run-state-compare-and-set")
    async def test_fehlender_lauf_ist_kein_konflikt(
        self, engine: AsyncEngine, aufgeraeumte_nutzer: list[uuid.UUID]
    ) -> None:
        """„Steht woanders" und „ist nicht da" sind verschiedene Lagen.

        Die eine lädt man neu und wiederholt die Entscheidung; bei der anderen
        wäre das eine Endlosschleife.
        """
        uid = await _nutzer(engine)
        aufgeraeumte_nutzer.append(uid)
        nie_angelegt = _voller_lauf(uid)

        with pytest.raises(RunNotStored):
            await PostgresRunStore(engine).save(nie_angelegt, erwarteter_status=RunStatus.QUEUED)

    @pytest.mark.invariant("run-state-compare-and-set")
    async def test_zehn_gleichzeitige_uebergaenge_ergeben_einen(
        self, engine: AsyncEngine, aufgeraeumte_nutzer: list[uuid.UUID]
    ) -> None:
        """Zehn Schreiber, ein Übergang.

        Der Nachweis, dass die Zusicherung aus dem bedingten UPDATE kommt und
        nicht daraus, dass die Ereignisschleife die Aufrufe ohnehin
        hintereinander ausführt: Die Verbindungen sind getrennt, und der
        Statusvergleich entscheidet.
        """
        uid = await _nutzer(engine)
        aufgeraeumte_nutzer.append(uid)
        store = PostgresRunStore(engine)
        lauf = _voller_lauf(uid)
        await store.create(lauf)

        async def versuch(nummer: int) -> bool:
            weiter = lauf.model_copy(
                update={"status": RunStatus.EXECUTING, "trace_id": f"schreiber-{nummer}"}
            )
            try:
                await store.save(weiter, erwarteter_status=RunStatus.QUEUED)
                return True
            except RunStateConflict:
                return False

        ergebnisse = await asyncio.gather(*(versuch(n) for n in range(10)))

        assert sum(ergebnisse) == 1, (
            f"{sum(ergebnisse)} Schreiber haben gewonnen, erlaubt ist einer."
        )
        geladen = await store.load(lauf.id)
        assert geladen is not None
        assert geladen.trace_id.startswith("schreiber-")


class TestDauerhaftigkeit:
    async def test_angelegter_lauf_ueberlebt_den_rollback_des_aufrufers(
        self, engine: AsyncEngine, aufgeraeumte_nutzer: list[uuid.UUID]
    ) -> None:
        """Der Lauf ist das erste Glied der Kette.

        Werkzeugprotokoll und Grant-Anspruch committen in eigenen
        Transaktionen, damit sie einen Absturz überstehen; beide hängen über
        Fremdschlüssel an dieser Zeile. Läge sie in der Transaktion des
        Requests, bräche die Kette hier — und zwar bevor sie irgendetwas
        zusichern könnte.
        """
        uid = await _nutzer(engine)
        aufgeraeumte_nutzer.append(uid)
        store = PostgresRunStore(engine)
        lauf = _voller_lauf(uid)

        async with engine.connect() as conn:
            transaktion = await conn.begin()
            await store.create(lauf)
            await transaktion.rollback()

        assert await store.load(lauf.id) is not None, (
            "Der Lauf ist mit der Transaktion des Aufrufers verschwunden."
        )

    async def test_protokoll_findet_den_lauf_als_fremdschluessel(
        self, engine: AsyncEngine, aufgeraeumte_nutzer: list[uuid.UUID]
    ) -> None:
        """Die Kette hält an ihrem ersten Glied.

        Kein Umweg über SQL: Wenn ``create()`` committet, kann das
        Werkzeugprotokoll — das seinerseits eigenständig committet — die Zeile
        als Fremdschlüssel benutzen. Genau das ist die Reihenfolge, die beim
        Verdrahten der Endpunkte gilt.
        """
        from jarvis_api.db.invocation_store import PostgresInvocationStore
        from jarvis_contracts import PolicyEffect, RiskLevel, ToolInvocation

        uid = await _nutzer(engine)
        aufgeraeumte_nutzer.append(uid)
        lauf = _voller_lauf(uid)
        await PostgresRunStore(engine).create(lauf)

        await PostgresInvocationStore(engine).record(
            ToolInvocation(
                id=uuid.uuid4(),
                run_id=lauf.id,
                tool_name="calendar.read",
                arguments={},
                risk_level=RiskLevel.LOW,
                policy_decision=PolicyEffect.ALLOW,
                decision_reason="Kettentest",
                created_at=NOW,
            )
        )

        async with engine.begin() as conn:
            anzahl = (
                await conn.execute(
                    text("SELECT count(*) FROM tool_invocations WHERE run_id = :r"),
                    {"r": lauf.id},
                )
            ).scalar_one()
        assert anzahl == 1
