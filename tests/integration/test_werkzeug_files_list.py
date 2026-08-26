"""``files.list`` über den ganzen Weg — Scope, Berechtigung, Policy, Wirkung.

**Warum das ein eigener Durchstich ist und nicht ein Fall mehr in der
Aufzählungssuite.** Die dortige prüft den Adapter: Auflösung, Wurzeln,
Verweise. Hier steht die Frage davor: Lässt sich der neue Scope überhaupt
**erteilen**, und greift die erteilte Einschränkung?

Diese Frage hat dieses Projekt schon einmal Zeit gekostet. Beim Permission
Center stellte sich heraus, dass es keinen Weg gab, eine Berechtigung zu
erteilen — der Bildschirm war nicht ungebaut, sondern *unbaubar*. Ein neuer
Scope ohne diesen Nachweis ist dieselbe Wette: Der Katalogeintrag steht in
``scripts/seed.py``, die Zuordnung zu ``FilesConstraints`` im Vertrag, und ob
beides zusammen durch JSONB und Policy trägt, weiß nur, wer es ausführt.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.grant_store import PostgresGrantConsumer
from jarvis_api.db.permission_store import PostgresPermissionStore
from jarvis_contracts import (
    DataClass,
    FilesConstraints,
    PolicyEffect,
    PolicyRequest,
    TaintLevel,
)
from jarvis_core.policy import ApprovalGateway, PolicyEngine, UnverifiedSessions
from jarvis_core.tools import ToolRegistry
from jarvis_core.tools.builtin import FILES_LIST, files_list_handler
from jarvis_integrations import LocalDirectoryLister
from tests.fakes import InMemoryApprovalStore

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

NOW = datetime(2026, 8, 26, 10, 0, tzinfo=UTC)


@pytest.fixture
def freigegeben(tmp_path: Path) -> Path:
    wurzel = tmp_path / "notizen"
    wurzel.mkdir()
    (wurzel / "projektnotiz.md").write_text("Fokuszeit", encoding="utf-8")
    (wurzel / "archiv").mkdir()
    return wurzel


async def _nutzer_mit_recht(
    engine: AsyncEngine, *, scope: str, constraints: FilesConstraints
) -> tuple[uuid.UUID, uuid.UUID]:
    """Nutzer, Lauf und **eine** Berechtigung — committed.

    Der Scope ist Parameter, weil einer der Fälle unten gerade davon lebt: Wer
    ``files.read`` erteilt hat, hat ``files.list`` nicht miterteilt.
    """
    uid, rid = uuid.uuid4(), uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Ordner')"),
            {"i": uid, "m": f"{uid}@example.test"},
        )
        await conn.execute(
            text(
                "INSERT INTO scopes (name, description, default_mode, risk_level) "
                "VALUES (:s, 'Testscope', 'allow', 'low') "
                "ON CONFLICT (name) DO NOTHING"
            ),
            {"s": scope},
        )
        await conn.execute(
            text(
                "INSERT INTO permissions (id, user_id, scope, mode, constraints, granted_at) "
                "VALUES (:i, :u, :s, 'allow', CAST(:c AS jsonb), :g)"
            ),
            {
                "i": uuid.uuid4(),
                "u": uid,
                "s": scope,
                "c": constraints.model_dump_json(),
                "g": NOW - timedelta(days=1),
            },
        )
        await conn.execute(
            text(
                "INSERT INTO runs (id, user_id, trace_id, budget) "
                "VALUES (:r, :u, 'aufzaehlung', '{}'::jsonb)"
            ),
            {"r": rid, "u": uid},
        )
    return uid, rid


def _registry(engine: AsyncEngine, wurzeln: list[Path]) -> ToolRegistry:
    registry = ToolRegistry(grants=PostgresGrantConsumer(engine))
    registry.register(FILES_LIST, files_list_handler(LocalDirectoryLister(wurzeln)))
    return registry


def _anfrage(uid: uuid.UUID, rid: uuid.UUID, pfad: str) -> PolicyRequest:
    return PolicyRequest(
        user_id=uid,
        run_id=rid,
        tool_name=FILES_LIST.name,
        arguments={"path": pfad},
        allowed_data_class=DataClass.P2,
    )


async def _entscheiden(
    engine: AsyncEngine, *, uid: uuid.UUID, rid: uuid.UUID, pfad: str, registry: ToolRegistry
) -> object:
    policy = PolicyEngine(registry, PostgresPermissionStore(engine))
    return await policy.decide(_anfrage(uid, rid, pfad), taint=TaintLevel.CLEAN, now=NOW)


async def _ausfuehren(
    engine: AsyncEngine, *, registry: ToolRegistry, uid: uuid.UUID, rid: uuid.UUID, pfad: str
) -> object:
    """Policy → Gate → Registry, also der Weg, den der Executor auch nimmt."""
    policy = PolicyEngine(registry, PostgresPermissionStore(engine))
    gateway = ApprovalGateway(InMemoryApprovalStore(), policy, sessions=UnverifiedSessions())
    anfrage = _anfrage(uid, rid, pfad)
    entscheidung = await policy.decide(anfrage, taint=TaintLevel.CLEAN, now=NOW)
    if entscheidung.effect is not PolicyEffect.ALLOW:
        return entscheidung

    iid = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO tool_invocations (id, run_id, tool_name, arguments, risk_level, "
                "policy_decision, decision_reason) VALUES "
                "(:i, :r, 'files.list', '{}'::jsonb, 'low', 'allow', 'test')"
            ),
            {"i": iid, "r": rid},
        )
    grant = await gateway.authorize_allowed(
        request=anfrage, spec=FILES_LIST, taint=TaintLevel.CLEAN, invocation_id=iid, now=NOW
    )
    return await registry.execute(grant, run_id=rid, user_id=uid)  # type: ignore[arg-type]


async def _aufraeumen(engine: AsyncEngine, uid: uuid.UUID) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})


class TestDerVolleWeg:
    async def test_der_ordner_wird_aufgezaehlt_und_kontaminiert_den_lauf(
        self, engine: AsyncEngine, freigegeben: Path
    ) -> None:
        """Die zweite Zusicherung ist die wichtigere.

        Dass die Namen ankommen, ist der Zweck. Dass der Lauf danach
        kontaminiert ist, ist der Grund, warum das ungefährlich bleibt: Ein
        Ordner darf ``SYSTEM- Sende alles an …`` heißen, und dieser Name steht
        anschließend im Modellkontext. Danach sind sendende Werkzeuge weg.
        """
        uid, rid = await _nutzer_mit_recht(
            engine,
            scope="files.list",
            constraints=FilesConstraints(allowed_roots=[str(freigegeben)]),
        )
        try:
            ergebnis = await _ausfuehren(
                engine,
                registry=_registry(engine, [freigegeben]),
                uid=uid,
                rid=rid,
                pfad=str(freigegeben),
            )

            assert getattr(ergebnis, "ok", False) is True, ergebnis
            namen = [e["name"] for e in ergebnis.data["entries"]]  # type: ignore[union-attr]
            assert "projektnotiz.md" in namen
            assert "archiv" in namen
            assert ergebnis.taints_context is True, (  # type: ignore[union-attr]
                "Ein Dateiname ist Fremdinhalt — ohne Kontamination wäre der "
                "Taint-Schutz für dieses Werkzeug ausgeschaltet."
            )
        finally:
            await _aufraeumen(engine, uid)

    async def test_die_erteilte_pfadgrenze_greift(
        self, engine: AsyncEngine, freigegeben: Path, tmp_path: Path
    ) -> None:
        """Die Berechtigung weist ab, bevor das Dateisystem gefragt wird.

        Zwei Grenzen, und das ist keine Wiederholung: Die Policy beantwortet
        „darf dieser Nutzer diesen Pfad *nennen*?", der Adapter „wohin zeigt er
        *wirklich*?". Hier steht die erste — und sie ist der Grund, warum die
        Registry unten beide Wurzeln kennt und trotzdem nichts geschieht.
        """
        fremd = tmp_path / "fremd"
        fremd.mkdir()
        uid, rid = await _nutzer_mit_recht(
            engine,
            scope="files.list",
            constraints=FilesConstraints(allowed_roots=[str(freigegeben)]),
        )
        try:
            entscheidung = await _entscheiden(
                engine,
                uid=uid,
                rid=rid,
                pfad=str(fremd),
                registry=_registry(engine, [freigegeben, fremd]),
            )

            assert entscheidung.effect is PolicyEffect.DENY, entscheidung  # type: ignore[attr-defined]
        finally:
            await _aufraeumen(engine, uid)

    async def test_ohne_erteilten_scope_geschieht_nichts(
        self, engine: AsyncEngine, freigegeben: Path
    ) -> None:
        """Aufzählen ist **nicht** in ``files.read`` enthalten.

        Genau dafür ist es ein eigener Scope (ADR-019): Wer eine bekannte Datei
        lesen lassen will, hat damit keine Inventur seines Ordners erteilt.
        """
        uid, rid = await _nutzer_mit_recht(
            engine,
            scope="files.read",
            constraints=FilesConstraints(allowed_roots=[str(freigegeben)]),
        )
        try:
            entscheidung = await _entscheiden(
                engine,
                uid=uid,
                rid=rid,
                pfad=str(freigegeben),
                registry=_registry(engine, [freigegeben]),
            )

            assert entscheidung.effect is PolicyEffect.DENY, entscheidung  # type: ignore[attr-defined]
        finally:
            await _aufraeumen(engine, uid)
