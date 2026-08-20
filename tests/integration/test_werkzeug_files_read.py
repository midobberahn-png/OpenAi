"""Das erste echte Werkzeug durch die ganze Kette.

Bis hierher liefen alle Durchstichtests gegen Attrappen aus
``tests/fakes.py``. Sie belegten, dass die Kette hält — aber nur für
Handler, die der Test selbst geschrieben hatte. Dieser Test führt dieselbe
Kette mit ``files.read`` aus: echter Scope aus dem Katalog, echte Berechtigung
aus der Tabelle, echte Pfadgrenzen, echte Datei auf der Platte.

Drei Aussagen, die vorher niemand prüfen konnte:

1. Die Berechtigungsprüfung greift auf ein Werkzeug, das nicht für den Test
   gebaut wurde.
2. Die Pfadgrenzen der Berechtigung und die des Prozesses greifen beide — und
   die zweite auch dann, wenn die erste getäuscht wurde.
3. Der Lauf ist danach kontaminiert, und zwar weil eine *Datei* gelesen wurde.
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
from jarvis_core.tools.builtin import FILES_READ, files_read_handler
from jarvis_integrations import LocalFileReader
from tests.fakes import InMemoryApprovalStore

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)


@pytest.fixture
def freigegeben(tmp_path: Path) -> Path:
    wurzel = tmp_path / "freigegeben"
    wurzel.mkdir()
    (wurzel / "plan.md").write_text("# Plan\nMittwoch: Fokuszeit", encoding="utf-8")
    return wurzel


async def _nutzer_mit_recht(
    engine: AsyncEngine, *, constraints: FilesConstraints | None
) -> tuple[uuid.UUID, uuid.UUID]:
    """Nutzer, Lauf und die Berechtigung ``files.read`` — committed.

    Die Berechtigung wird als Zeile angelegt und nicht als Attrappe übergeben:
    Der Test soll auch belegen, dass Scope-Name, Modus und Einschränkungen den
    Weg durch JSONB überstehen.
    """
    uid, rid = uuid.uuid4(), uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Datei')"),
            {"i": uid, "m": f"{uid}@example.test"},
        )
        await conn.execute(
            text(
                "INSERT INTO scopes (name, description, default_mode, risk_level) "
                "VALUES ('files.read', 'Dateien lesen', 'allow', 'low') "
                "ON CONFLICT (name) DO NOTHING"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO permissions (id, user_id, scope, mode, constraints, granted_at) "
                "VALUES (:i, :u, 'files.read', 'allow', CAST(:c AS jsonb), :g)"
            ),
            {
                "i": uuid.uuid4(),
                "u": uid,
                "c": (constraints.model_dump_json() if constraints else "{}"),
                "g": NOW - timedelta(days=1),
            },
        )
        await conn.execute(
            text(
                "INSERT INTO runs (id, user_id, trace_id, budget) "
                "VALUES (:r, :u, 'werkzeug', '{}'::jsonb)"
            ),
            {"r": rid, "u": uid},
        )
    return uid, rid


def _registry(engine: AsyncEngine, wurzeln: list[Path]) -> ToolRegistry:
    registry = ToolRegistry(grants=PostgresGrantConsumer(engine))
    registry.register(FILES_READ, files_read_handler(LocalFileReader(wurzeln)))
    return registry


async def _ausfuehren(
    engine: AsyncEngine,
    *,
    registry: ToolRegistry,
    uid: uuid.UUID,
    rid: uuid.UUID,
    pfad: str,
) -> object:
    """Policy → Gate → Registry, also der Weg, den der Executor auch nimmt."""
    policy = PolicyEngine(registry, PostgresPermissionStore(engine))
    gateway = ApprovalGateway(InMemoryApprovalStore(), policy, sessions=UnverifiedSessions())
    anfrage = PolicyRequest(
        user_id=uid,
        run_id=rid,
        tool_name=FILES_READ.name,
        arguments={"path": pfad},
        allowed_data_class=DataClass.P2,
    )
    entscheidung = await policy.decide(anfrage, taint=TaintLevel.CLEAN, now=NOW)
    if entscheidung.effect is not PolicyEffect.ALLOW:
        return entscheidung

    iid = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO tool_invocations (id, run_id, tool_name, arguments, risk_level, "
                "policy_decision, decision_reason) VALUES "
                "(:i, :r, 'files.read', '{}'::jsonb, 'low', 'allow', 'test')"
            ),
            {"i": iid, "r": rid},
        )
    grant = await gateway.authorize_allowed(
        request=anfrage, spec=FILES_READ, taint=TaintLevel.CLEAN, invocation_id=iid, now=NOW
    )
    return await registry.execute(grant, run_id=rid, user_id=uid)  # type: ignore[arg-type]


async def _aufraeumen(engine: AsyncEngine, uid: uuid.UUID) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users WHERE id = :i"), {"i": uid})


class TestDerVolleWeg:
    async def test_datei_wird_gelesen_und_kontaminiert_den_lauf(
        self, engine: AsyncEngine, freigegeben: Path
    ) -> None:
        """Der Durchstich mit einem Werkzeug, das nicht für den Test gebaut ist.

        Die letzte Zusicherung ist die wichtigste: ``taints_context`` ist der
        Grund, warum dieses Werkzeug ungefährlich ist. Ein Lauf, der eine Datei
        gelesen hat, verliert seine sendenden Werkzeuge — was in der Datei
        steht, kann also nichts auslösen.
        """
        uid, rid = await _nutzer_mit_recht(
            engine, constraints=FilesConstraints(allowed_roots=[str(freigegeben)])
        )
        try:
            ergebnis = await _ausfuehren(
                engine,
                registry=_registry(engine, [freigegeben]),
                uid=uid,
                rid=rid,
                pfad=str(freigegeben / "plan.md"),
            )

            assert getattr(ergebnis, "ok", False) is True, ergebnis
            assert "Fokuszeit" in ergebnis.data["text"]  # type: ignore[union-attr]
            assert ergebnis.taints_context is True, (  # type: ignore[union-attr]
                "Eine gelesene Datei ist Fremdinhalt — ohne Kontamination wäre der "
                "Taint-Schutz für dieses Werkzeug ausgeschaltet."
            )
            assert ergebnis.produced_data_class is DataClass.P2  # type: ignore[union-attr]
        finally:
            await _aufraeumen(engine, uid)

    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_pfad_ausserhalb_der_berechtigung_wird_von_der_policy_abgewiesen(
        self, engine: AsyncEngine, freigegeben: Path, tmp_path: Path
    ) -> None:
        """Die erste der beiden Grenzen: die Berechtigung.

        Sie greift, **bevor** ein Grant entsteht — der Pfad kommt gar nicht
        beim Adapter an.
        """
        geheim = tmp_path / "geheim.txt"
        geheim.write_text("nicht für dich", encoding="utf-8")

        uid, rid = await _nutzer_mit_recht(
            engine, constraints=FilesConstraints(allowed_roots=[str(freigegeben)])
        )
        try:
            entscheidung = await _ausfuehren(
                engine,
                registry=_registry(engine, [freigegeben, tmp_path]),
                uid=uid,
                rid=rid,
                pfad=str(geheim),
            )
            assert getattr(entscheidung, "effect", None) is PolicyEffect.DENY, entscheidung
        finally:
            await _aufraeumen(engine, uid)

    @pytest.mark.invariant("file-access-confined-to-roots")
    async def test_symlink_besteht_die_policy_und_scheitert_am_adapter(
        self, engine: AsyncEngine, freigegeben: Path, tmp_path: Path
    ) -> None:
        """Die zweite Grenze — und der Grund, warum es sie geben muss.

        Der Symlink liegt **innerhalb** des freigegebenen Ordners. Die
        Berechtigung sieht eine einwandfreie Zeichenkette und lässt durch; ein
        Grant entsteht, die Ausführung beginnt. Erst der Adapter löst auf und
        weist ab.

        Wäre die Prüfung nur an einer der beiden Stellen, wäre genau dieser
        Pfad gangbar.
        """
        geheim = tmp_path / "geheim.txt"
        geheim.write_text("nicht für dich", encoding="utf-8")
        falle = freigegeben / "harmlos.md"
        falle.symlink_to(geheim)

        uid, rid = await _nutzer_mit_recht(
            engine, constraints=FilesConstraints(allowed_roots=[str(freigegeben)])
        )
        try:
            ergebnis = await _ausfuehren(
                engine,
                registry=_registry(engine, [freigegeben]),
                uid=uid,
                rid=rid,
                pfad=str(falle),
            )

            assert getattr(ergebnis, "ok", None) is False, (
                "Der Symlink hat die Policy passiert — und der Adapter hat ihn "
                "durchgelassen. Damit ist die Freigabe wirkungslos."
            )
            assert "nicht für dich" not in str(ergebnis)
        finally:
            await _aufraeumen(engine, uid)

    async def test_unlesbare_einschraenkung_gilt_als_nicht_erteilt(
        self, engine: AsyncEngine, freigegeben: Path
    ) -> None:
        """Eine Berechtigung, die sich nicht auslegen lässt, ist keine.

        Der Fall ist beim Bau dieses Werkzeugs entstanden: ``files.read``
        verlangt ``allowed_roots``, eine leere Einschränkung passt also nicht
        zum Scope. Entscheidend ist, wohin der Fehler fällt — ein Rückfall auf
        die Basisklasse hieße, dass die Berechtigung **ohne Pfadgrenzen**
        weitergilt. Genau das darf nicht passieren.
        """
        uid, rid = await _nutzer_mit_recht(engine, constraints=None)
        try:
            entscheidung = await _ausfuehren(
                engine,
                registry=_registry(engine, [freigegeben]),
                uid=uid,
                rid=rid,
                pfad=str(freigegeben / "plan.md"),
            )
            assert getattr(entscheidung, "effect", None) is PolicyEffect.DENY, (
                "Eine Berechtigung ohne Pfadgrenzen wurde als gültig gelesen."
            )
        finally:
            await _aufraeumen(engine, uid)

    async def test_ohne_berechtigung_laeuft_nichts(
        self, engine: AsyncEngine, freigegeben: Path
    ) -> None:
        """Ein Werkzeug im Katalog ist keine Erlaubnis.

        Der Nutzer hat ``files.read`` nicht erteilt bekommen; die Datei liegt
        im freigegebenen Ordner und ist trotzdem nicht lesbar.
        """
        uid, rid = uuid.uuid4(), uuid.uuid4()
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Ohne')"),
                {"i": uid, "m": f"{uid}@example.test"},
            )
            await conn.execute(
                text(
                    "INSERT INTO runs (id, user_id, trace_id, budget) "
                    "VALUES (:r, :u, 'ohne', '{}'::jsonb)"
                ),
                {"r": rid, "u": uid},
            )
        try:
            entscheidung = await _ausfuehren(
                engine,
                registry=_registry(engine, [freigegeben]),
                uid=uid,
                rid=rid,
                pfad=str(freigegeben / "plan.md"),
            )
            assert getattr(entscheidung, "effect", None) is PolicyEffect.DENY, entscheidung
        finally:
            await _aufraeumen(engine, uid)
