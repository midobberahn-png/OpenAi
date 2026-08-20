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
from jarvis_api.db.invocation_store import PostgresInvocationStore
from jarvis_contracts import (
    DataClass,
    PolicyEffect,
    PolicyRequest,
    RiskLevel,
    TaintLevel,
    ToolInvocation,
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


def _registry(engine: AsyncEngine, spy: list[object]) -> ToolRegistry:
    """Der Verbraucher bekommt die Engine, nicht die Verbindung des Aufrufers.

    Das ist keine Bequemlichkeit, sondern die Zusicherung selbst: Der Anspruch
    gehört in eine Transaktion, die unabhängig von der des Aufrufers committet.
    Die Signatur von ``PostgresGrantConsumer`` lässt eine Verbindung deshalb
    nicht mehr zu.
    """

    async def handler(**kwargs: object) -> ToolResult:
        spy.append(kwargs)
        return ToolResult(ok=True, display="gelesen")

    registry = ToolRegistry(grants=PostgresGrantConsumer(engine))
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
        registry = _registry(engine, gesehen)
        grant = await _grant(registry, uid, rid, iid)
        await registry.execute(grant, run_id=rid, user_id=uid)  # type: ignore[arg-type]

        frisch = _registry(engine, gesehen)
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
            grant = await _grant(_registry(engine, vorbereitung), uid, rid, iid)

        gesehen: list[object] = []

        async def versuch() -> bool:
            try:
                await _registry(engine, gesehen).execute(  # type: ignore[arg-type]
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
    async def test_absturz_nach_seiteneffekt_gibt_den_grant_nicht_frei(
        self, engine: AsyncEngine
    ) -> None:
        """Der Verbrauch überlebt einen Absturz vor dem Commit.

        Der vierte gemeldete Replay-Pfad, und der einzige, den die beiden Tests
        darüber nicht sehen: Sie verlassen ihren ``begin()``-Block regulär, also
        committet die Transaktion, bevor die zweite Vorlage beginnt. Belegt ist
        damit nur der geordnete Ablauf.

        Der interessante Fall ist der ungeordnete. Der Handler wirkt nach
        außen — eine Mail ist verschickt, ein Termin gelöscht —, und *danach*
        stirbt der Prozess, ohne zu committen. Hier steht dafür ein
        ausdrückliches ``rollback()``: dieselbe Wirkung auf die Datenbank wie
        ein Verbindungsabbruch, nur reproduzierbar.

        Die Prüfstelle ist ``consumed_at`` aus einer **neuen** Verbindung. Der
        Seiteneffekt selbst liegt außerhalb der Datenbank — ``gesehen`` ist
        deshalb eine Python-Liste und keine Tabelle: Was hinausging, holt kein
        Rollback zurück. Wenn der Anspruch zurückrollt, der Seiteneffekt aber
        bleibt, führt jeder Retry denselben Grant erneut aus.
        """
        async with engine.begin() as setup:
            uid, rid, iid = await _seed(setup)
            grant = await _grant(_registry(engine, []), uid, rid, iid)

        gesehen: list[object] = []
        async with engine.connect() as conn:
            # Die Transaktion des Requests — dieselbe Rolle wie ``db_connection``
            # in der API: Sie umschließt den ganzen Aufruf und committet erst am
            # Ende.
            transaktion = await conn.begin()
            await _registry(engine, gesehen).execute(  # type: ignore[arg-type]
                grant, run_id=rid, user_id=uid
            )
            # Arbeit des Requests, die der Absturz mitnimmt. Sie steht hier, um
            # den Unterschied zu zeigen: Diese Zeile ist gleich weg, der
            # Anspruch nicht.
            await conn.execute(
                text("UPDATE tool_invocations SET status = 'executed' WHERE id = :i"),
                {"i": iid},
            )
            # Hier stirbt der Prozess: Der Seiteneffekt ist draußen, der
            # Commit kommt nicht mehr.
            await transaktion.rollback()

        assert len(gesehen) == 1, "Vorbedingung: Der Seiteneffekt ist eingetreten."

        async with engine.begin() as pruefung:
            status = (
                await pruefung.execute(
                    text("SELECT status FROM tool_invocations WHERE id = :i"), {"i": iid}
                )
            ).scalar_one()
        assert status != "executed", (
            "Vorbedingung: Der Rollback muss die Arbeit des Requests verworfen haben, "
            "sonst prüft der Test nichts."
        )

        async with engine.begin() as pruefung:
            zeile = (
                await pruefung.execute(
                    text("SELECT consumed_at FROM tool_invocations WHERE id = :i"), {"i": iid}
                )
            ).first()
        assert zeile is not None, "Die Invokationszeile war vorher committed."
        assert zeile[0] is not None, (
            "Der Verbrauch hat den Rollback nicht überlebt: consumed_at ist wieder NULL. "
            "Der Seiteneffekt ist eingetreten, der Anspruch ist frei — der Grant ist "
            "erneut einlösbar."
        )

        with pytest.raises(GrantAlreadyUsed):
            await _registry(engine, gesehen).execute(  # type: ignore[arg-type]
                grant, run_id=rid, user_id=uid
            )

        assert len(gesehen) == 1, f"Der Handler lief {len(gesehen)}-mal statt einmal."

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
        registry = _registry(engine, gesehen)
        grant = await _grant(registry, uid, rid, uuid.uuid4())  # nie protokolliert
        with pytest.raises(GrantAlreadyUsed):
            await registry.execute(grant, run_id=rid, user_id=uid)  # type: ignore[arg-type]

        assert not gesehen, "Ohne protokollierte Invokation darf nichts laufen"

        async with engine.begin() as cleanup:
            await cleanup.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})

    @pytest.mark.invariant("grant-single-use")
    async def test_das_protokoll_traegt_den_anspruch_ohne_zutun_des_tests(
        self, engine: AsyncEngine
    ) -> None:
        """Protokoll und Anspruch greifen ineinander — beide eigenständig.

        Die Tests darüber legen die Invokationszeile selbst per SQL an. Das ist
        für sie richtig, prüft aber nicht, ob der Weg zusammenpasst, den die
        Anwendung tatsächlich geht: ``InvocationStore.record()`` schreibt die
        Zeile, ``GrantConsumer.consume()`` löst den Anspruch daran ein — und
        beide öffnen inzwischen ihre **eigene** Transaktion, damit sie einen
        Absturz überstehen.

        Genau daraus entsteht die Bedingung, die sie aneinander bindet: Eine
        eigene Transaktion sieht keine fremden uncommitteten Zeilen. Hätte der
        Store weiter auf der Verbindung des Aufrufers geschrieben, fände der
        Anspruch nichts, und dieser Test wäre der erste, der es merkt — statt
        des ersten Endpunkts, den jemand verdrahtet.
        """
        async with engine.begin() as setup:
            uid, rid, _ = await _seed(setup)

        iid = uuid.uuid4()
        await PostgresInvocationStore(engine).record(
            ToolInvocation(
                id=iid,
                run_id=rid,
                tool_name=CALENDAR_READ.name,
                arguments={},
                risk_level=RiskLevel.LOW,
                policy_decision=PolicyEffect.ALLOW,
                decision_reason="Integrationstest",
                created_at=NOW,
            )
        )

        gesehen: list[object] = []
        registry = _registry(engine, gesehen)
        grant = await _grant(registry, uid, rid, iid)
        await registry.execute(grant, run_id=rid, user_id=uid)  # type: ignore[arg-type]
        with pytest.raises(GrantAlreadyUsed):
            await registry.execute(grant, run_id=rid, user_id=uid)  # type: ignore[arg-type]

        assert len(gesehen) == 1, f"Der Handler lief {len(gesehen)}-mal."

        async with engine.begin() as cleanup:
            await cleanup.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})

    @pytest.mark.invariant("grant-single-use")
    async def test_protokoll_ueberlebt_den_rollback_des_aufrufers(
        self, engine: AsyncEngine
    ) -> None:
        """Das Protokoll gehört nicht in die Transaktion dessen, worüber es
        Auskunft gibt.

        Der Modulkopf von ``invocation_store.py`` sagt seit jeher zu, der
        Eintrag sei auch dann da, „wenn der Lauf abgestürzt ist". Gehalten hat
        das die erste Fassung nicht: Sie schrieb auf der Verbindung des
        Requests und verschwand mit ihr — und zwar genau in dem Fall, für den
        man ein Protokoll liest.
        """
        async with engine.begin() as setup:
            uid, rid, _ = await _seed(setup)

        iid = uuid.uuid4()
        async with engine.connect() as conn:
            transaktion = await conn.begin()
            await PostgresInvocationStore(engine).record(
                ToolInvocation(
                    id=iid,
                    run_id=rid,
                    tool_name=CALENDAR_READ.name,
                    arguments={},
                    risk_level=RiskLevel.LOW,
                    policy_decision=PolicyEffect.ALLOW,
                    decision_reason="Absturz gleich danach",
                    created_at=NOW,
                )
            )
            await transaktion.rollback()

        async with engine.begin() as pruefung:
            vorhanden = (
                await pruefung.execute(
                    text("SELECT count(*) FROM tool_invocations WHERE id = :i"), {"i": iid}
                )
            ).scalar_one()
        assert vorhanden == 1, (
            "Der Protokolleintrag ist mit der Transaktion des Aufrufers verschwunden — "
            "also genau dann, wenn man ihn braucht."
        )

        async with engine.begin() as cleanup:
            await cleanup.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})

    @pytest.mark.invariant("grant-single-use")
    async def test_noch_nicht_committete_invokation_schliesst(self, engine: AsyncEngine) -> None:
        """Die Kehrseite der eigenen Transaktion — und sie schließt.

        Der Anspruch committet unabhängig vom Aufrufer. Der Preis dafür: Er
        sieht nichts, was der Aufrufer noch nicht committed hat. Steht
        ``InvocationStore.record()`` also in derselben offenen Transaktion, aus
        der heraus ausgeführt wird, findet das bedingte UPDATE keine Zeile.

        Dass dieser Fall abweist und nicht durchwinkt, ist die eigentliche
        Aussage des Tests. Eine Reihenfolge, die niemand geprüft hat, darf die
        Zusicherung nicht still aufheben — sie darf höchstens die Ausführung
        kosten. Für den Aufrufer ist es dieselbe Meldung wie beim fehlenden
        Protokoll, denn es ist derselbe Sachverhalt: Es gibt keinen sichtbaren
        Anspruch, der eingelöst werden könnte.
        """
        async with engine.begin() as setup:
            uid, rid, _ = await _seed(setup)

        gesehen: list[object] = []
        iid = uuid.uuid4()
        async with engine.connect() as conn:
            transaktion = await conn.begin()
            await conn.execute(
                text(
                    "INSERT INTO tool_invocations (id, run_id, tool_name, arguments, "
                    "risk_level, policy_decision, decision_reason) "
                    "VALUES (:iid, :rid, 'calendar.read', '{}'::jsonb, 'low', 'allow', 'test')"
                ),
                {"iid": iid, "rid": rid},
            )
            # Nicht committed — für jede andere Transaktion existiert die Zeile
            # noch nicht.
            registry = _registry(engine, gesehen)
            grant = await _grant(registry, uid, rid, iid)
            with pytest.raises(GrantAlreadyUsed):
                await registry.execute(grant, run_id=rid, user_id=uid)  # type: ignore[arg-type]
            await transaktion.rollback()

        assert not gesehen, "Ohne sichtbaren Anspruch darf der Handler nicht laufen"

        async with engine.begin() as cleanup:
            await cleanup.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})
