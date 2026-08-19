"""Grant-Verbrauch gegen die echte Datenbank.

Der prozesslokale Verbrauch (``InProcessGrants``) schließt den Replay
innerhalb eines Prozesses. Er kann aber nichts über zwei Arbeitsprozesse
sagen, und ein Neustart vergisst ihn — genau die Einwände, die der Prüfer
gegen ein In-Memory-Flag erhoben hat.

Was hier geprüft wird, lässt sich deshalb nur mit PostgreSQL prüfen: Der
Anspruch liegt in der ``WHERE``-Klausel eines bedingten UPDATE, und die
Nebenläufigkeit läuft über **getrennte Verbindungen**. Ein gemeinsamer
Transaktionskontext würde genau das wegdefinieren, worum es geht.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from jarvis_api.db.grant_store import PostgresGrantConsumer
from jarvis_contracts import (
    DataClass,
    PolicyRequest,
    RiskLevel,
    TaintLevel,
    ToolResult,
    ToolSpec,
)
from jarvis_core.policy import ApprovalGateway, PolicyEngine, UnverifiedSessions
from jarvis_core.tools import GrantAlreadyUsed, ToolRegistry
from tests.fakes import FakePermissions, InMemoryApprovalStore

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

NOW = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)

CALENDAR_READ = ToolSpec(
    name="calendar.read",
    description="Liest Termine aus dem verbundenen Kalender.",
    parameters={"type": "object"},
    risk=RiskLevel.LOW,
    scopes=["calendar.read"],
    data_class=DataClass.P2,
)


async def _seed(conn: AsyncConnection) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """Nutzer, Lauf und die Invokationszeile, an der der Anspruch hängt."""
    uid, rid, iid = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    await conn.execute(
        text("INSERT INTO users (id, email, display_name) VALUES (:id, :m, 'Test')"),
        {"id": uid, "m": f"{uid}@example.test"},
    )
    await conn.execute(
        text(
            "INSERT INTO runs (id, user_id, trace_id, budget) "
            "VALUES (:rid, :uid, 'trace', '{}'::jsonb)"
        ),
        {"rid": rid, "uid": uid},
    )
    await conn.execute(
        text(
            "INSERT INTO tool_invocations (id, run_id, tool_name, arguments, risk_level, "
            "policy_decision, decision_reason) "
            "VALUES (:iid, :rid, 'calendar.read', '{}'::jsonb, 'low', 'allow', 'test')"
        ),
        {"iid": iid, "rid": rid},
    )
    return uid, rid, iid


def _registry(conn: AsyncConnection, spy: list[object]) -> ToolRegistry:
    async def handler(**kwargs: object) -> ToolResult:
        spy.append(kwargs)
        return ToolResult(ok=True, display="gelesen")

    registry = ToolRegistry(grants=PostgresGrantConsumer(conn))
    registry.register(CALENDAR_READ, handler)
    return registry


async def _grant(registry: ToolRegistry, uid: uuid.UUID, rid: uuid.UUID, iid: uuid.UUID) -> object:
    perms = FakePermissions()
    perms.allow("calendar.read")
    gateway = ApprovalGateway(
        InMemoryApprovalStore(),
        PolicyEngine(registry, perms),
        sessions=UnverifiedSessions(),
    )
    return await gateway.authorize_allowed(
        request=PolicyRequest(user_id=uid, run_id=rid, tool_name=CALENDAR_READ.name, arguments={}),
        spec=CALENDAR_READ,
        taint=TaintLevel.CLEAN,
        invocation_id=iid,
        now=NOW,
    )


class TestVerbrauchUeberVerbindungsgrenzen:
    @pytest.mark.invariant("grant-single-use")
    async def test_verbraucht_bleibt_verbraucht_in_neuer_verbindung(
        self, engine: AsyncEngine
    ) -> None:
        """Der Verbrauch überlebt die Verbindung, aus der er stammt.

        Das ist der Unterschied zum prozesslokalen Verbraucher und der Grund,
        warum die Zusicherung nicht an einem Feld im Grant hängen darf: Ein
        zweiter Arbeitsprozess hat dieses Feld nicht gesehen.
        """
        async with engine.begin() as setup:
            uid, rid, iid = await _seed(setup)

        gesehen: list[object] = []
        async with engine.begin() as erste:
            registry = _registry(erste, gesehen)
            grant = await _grant(registry, uid, rid, iid)
            await registry.execute(grant, run_id=rid, user_id=uid)  # type: ignore[arg-type]

        async with engine.begin() as zweite:
            frisch = _registry(zweite, gesehen)
            with pytest.raises(GrantAlreadyUsed):
                await frisch.execute(grant, run_id=rid, user_id=uid)  # type: ignore[arg-type]

        assert len(gesehen) == 1, f"{len(gesehen)} Ausführungen über zwei Verbindungen."

        async with engine.begin() as cleanup:
            await cleanup.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})

    @pytest.mark.invariant("grant-single-use")
    async def test_zehn_gleichzeitige_ausfuehrungen_ergeben_eine(self, engine: AsyncEngine) -> None:
        """Zehn Verbindungen, ein Grant, ein Handleraufruf.

        Der Nachweis, den der prozesslokale Verbraucher nicht führen kann: Die
        Atomarität kommt hier aus dem bedingten UPDATE, nicht aus der
        Ereignisschleife.
        """
        async with engine.begin() as setup:
            uid, rid, iid = await _seed(setup)
            vorbereitung: list[object] = []
            grant = await _grant(_registry(setup, vorbereitung), uid, rid, iid)

        gesehen: list[object] = []

        async def versuch() -> bool:
            async with engine.begin() as conn:
                try:
                    await _registry(conn, gesehen).execute(  # type: ignore[arg-type]
                        grant, run_id=rid, user_id=uid
                    )
                    return True
                except GrantAlreadyUsed:
                    return False

        ergebnisse = await asyncio.gather(*(versuch() for _ in range(10)))

        assert sum(ergebnisse) == 1, "Genau eine Ausführung darf gewinnen"
        assert len(gesehen) == 1, f"Der Handler lief {len(gesehen)}-mal."

        async with engine.begin() as cleanup:
            await cleanup.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})

    @pytest.mark.invariant("grant-single-use")
    async def test_ohne_protokollierte_invokation_kein_verbrauch(self, engine: AsyncEngine) -> None:
        """Fehlt die Invokationszeile, scheitert der Verbrauch — und damit die
        Ausführung.

        Beabsichtigt: Ein Grant, dessen Aufruf nie protokolliert wurde, gehört
        zu keinem nachvollziehbaren Vorgang. Die Alternative wäre, den
        Verbrauch in dem Fall durchzuwinken — also genau dann zu öffnen, wenn
        am wenigsten bekannt ist.
        """
        async with engine.begin() as setup:
            uid, rid, _ = await _seed(setup)

        gesehen: list[object] = []
        async with engine.begin() as conn:
            registry = _registry(conn, gesehen)
            grant = await _grant(registry, uid, rid, uuid.uuid4())  # nie protokolliert
            with pytest.raises(GrantAlreadyUsed):
                await registry.execute(grant, run_id=rid, user_id=uid)  # type: ignore[arg-type]

        assert not gesehen, "Ohne protokollierte Invokation darf nichts laufen"

        async with engine.begin() as cleanup:
            await cleanup.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})
