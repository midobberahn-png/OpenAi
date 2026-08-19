"""Von der Anmeldung bis zur Ausführung — eine Kette, kein Bündel.

Der Maßstab aus dem Review lautet nicht mehr „wie viele Invarianten stehen auf
ENFORCED", sondern:

    Lässt sich von außen ein Weg bauen, der eine falsche Identität in einen
    ExecutionGrant verwandelt?

Bis hierher bestand das System aus einzeln geprüften, sicheren Komponenten.
Dieser Test verbindet sie: Passkey → Sitzung → Identität → Policy → Approval →
Ausführung. Die Identität, mit der die Policy arbeitet, stammt dabei
ausschließlich aus der über HTTP erlangten Sitzung — sie wird nirgends
behauptet.

**Grenze dieses Tests, ausdrücklich benannt:** Es gibt noch keine
HTTP-Endpunkte für Läufe; der Orchestrator wird deshalb im Testcode
angesteuert, aber mit der Identität aus der echten Sitzung. Sobald
``/runs``-Endpunkte existieren, gehört dieser Test über sie geführt.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_api.db.approval_store import PostgresApprovalStore
from jarvis_api.db.invocation_store import PostgresInvocationStore
from jarvis_api.db.session_store import PostgresSessionStore
from jarvis_api.main import create_app
from jarvis_contracts import (
    DataClass,
    PermissionGrant,
    PermissionMode,
    Run,
    RunStatus,
    ScopeConstraints,
    TaintLevel,
)
from jarvis_core.auth import SessionManager
from jarvis_core.orchestrator import BudgetTracker, ToolExecutor
from jarvis_core.policy import ApprovalGateway, PolicyEngine
from jarvis_core.tools import ForgedAuthorization
from tests.authenticator import SoftwareAuthenticator
from tests.fakes import build_registry

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

MAIL_PRAEFIX = "e2etest-"


class ConfirmPermissions:
    """``calendar.create`` bestätigungspflichtig — damit die Kette durch das
    Approval Gateway führt und nicht daran vorbei."""

    async def get_grant(self, user_id: uuid.UUID, scope: str) -> PermissionGrant | None:
        if scope != "calendar.create":
            return None
        return PermissionGrant(
            scope=scope,
            mode=PermissionMode.CONFIRM,
            constraints=ScopeConstraints(),
            granted_at=datetime(2026, 1, 1, tzinfo=UTC),
        )

    async def granted_scopes(self, user_id: uuid.UUID) -> set[str]:
        return {"calendar.create"}


@pytest_asyncio.fixture
async def client(engine: AsyncEngine, frische_grenzen: None) -> AsyncIterator[AsyncClient]:
    from jarvis_api.db.session import dispose
    from jarvis_api.deps import dispose_redis

    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://test"
    ) as http:
        yield http
    await dispose()
    await dispose_redis()
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users WHERE email LIKE :p"), {"p": f"{MAIL_PRAEFIX}%"})


async def _angemeldet(client: AsyncClient, engine: AsyncEngine) -> tuple[str, uuid.UUID]:
    """Führt den echten Anmeldeweg und gibt Token und Sitzungs-ID zurück."""
    from webauthn.helpers import base64url_to_bytes

    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM users"))

    gestartet = await client.post(
        "/auth/bootstrap",
        json={"email": f"{MAIL_PRAEFIX}{uuid.uuid4()}@example.test", "display_name": "E2E"},
    )
    assert gestartet.status_code == 201
    authenticator = SoftwareAuthenticator()
    await client.post(
        "/auth/register/finish",
        json={
            "credential": authenticator.register(
                bytes(base64url_to_bytes(gestartet.json()["challenge"]))
            ),
            "challenge": gestartet.json()["challenge"],
        },
    )

    start = await client.post("/auth/login/start")
    fertig = await client.post(
        "/auth/login/finish",
        json={
            "credential": authenticator.authenticate(
                bytes(base64url_to_bytes(start.json()["challenge"]))
            ),
            "challenge": start.json()["challenge"],
        },
    )
    assert fertig.status_code == 200
    token = client.cookies.get("jarvis_session")
    assert token
    return token, uuid.UUID(fertig.json()["session_id"])


class TestIdentitaetBisAusfuehrung:
    async def test_die_kette_traegt_von_der_anmeldung_bis_zum_grant(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der Durchstich.

        Jeder Abschnitt prüft, woher die Identität an dieser Stelle stammt —
        nicht nur, dass am Ende etwas ausgeführt wurde.
        """
        token, session_id = await _angemeldet(client, engine)

        async with engine.begin() as conn:
            # -- 1. Identität: aus dem Token, nicht aus einer Angabe --------
            sessions = SessionManager(PostgresSessionStore(conn))
            session = await sessions.verify(token)
            assert session is not None
            assert session.id == session_id
            user_id = session.user_id

            # -- 2. Aufbau des Kerns mit *dieser* Identität -----------------
            tools, spies = build_registry()
            policy = PolicyEngine(tools, ConfirmPermissions())
            gateway = ApprovalGateway(PostgresApprovalStore(conn), policy, sessions=sessions)
            executor = ToolExecutor(
                registry=tools,
                policy=policy,
                gateway=gateway,
                invocations=PostgresInvocationStore(conn),
            )

            run_id = uuid.uuid4()
            await conn.execute(
                text(
                    "INSERT INTO runs (id, user_id, trace_id, budget) "
                    "VALUES (:r, :u, 'e2e-identity', '{}'::jsonb)"
                ),
                {"r": run_id, "u": user_id},
            )
            run = Run(
                id=run_id,
                user_id=user_id,
                status=RunStatus.EXECUTING,
                data_class=DataClass.P1,
                trace_id="e2e-identity",
                started_at=datetime.now(tz=UTC),
            )
            tracker = BudgetTracker(run.budget)

            # -- 3. Policy: CONFIRM, keine Ausführung ----------------------
            argumente: dict[str, Any] = {"title": "Fokuszeit", "start": "2026-08-20T09:00:00Z"}
            schritt = await executor.execute_tool(
                run,
                tracker,
                tool_name="calendar.create",
                arguments=argumente,
                seq=1,
                session_id=session.id,
            )
            assert schritt.status == "awaiting_confirmation"
            assert spies["calendar.create"].call_count == 0
            pending = schritt.pending
            assert pending is not None

            # -- 4. Bestätigung: nur mit dem echten Sitzungstoken -----------
            ohne_token = await gateway.respond(
                action_id=pending.id,
                nonce=pending.nonce,
                approve=True,
                user_id=user_id,
                session_id=session.id,
                session_token="",
                channel="ui",
                now=datetime.now(tz=UTC),
            )
            assert not ohne_token.approved, "Ohne Sitzungsnachweis wird nicht bestätigt"

            bestaetigt = await gateway.respond(
                action_id=pending.id,
                nonce=pending.nonce,
                approve=True,
                user_id=user_id,
                session_id=session.id,
                session_token=token,
                channel="ui",
                now=datetime.now(tz=UTC),
            )
            assert bestaetigt.approved

            # -- 5. Ausführung: der Grant lautet auf diesen Lauf -----------
            ergebnis = await executor.resume_after_approval(
                schritt.run,
                tracker,
                action_id=pending.id,
                arguments=argumente,
                tool_name="calendar.create",
                seq=1,
            )
            assert ergebnis.status == "executed"
            assert spies["calendar.create"].call_count == 1

            # -- 6. Die Spur endet beim angemeldeten Nutzer ----------------
            zeile = (
                await conn.execute(text("SELECT user_id FROM runs WHERE id = :r"), {"r": run_id})
            ).first()
            assert zeile is not None
            assert zeile.user_id == user_id

    async def test_eine_fremde_sitzung_bestaetigt_nichts(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Der Angriff, den die Kette abwehren muss: Ein Angreifer hat eine
        eigene, gültige Sitzung — und versucht, die Bestätigung eines anderen
        Vorgangs einzulösen."""
        token, _ = await _angemeldet(client, engine)

        async with engine.begin() as conn:
            sessions = SessionManager(PostgresSessionStore(conn))
            session = await sessions.verify(token)
            assert session is not None

            # Zweite, ebenfalls gültige Sitzung desselben Nutzers.
            fremde = await sessions.issue(session.user_id, client="Angreifergerät")

            tools, spies = build_registry()
            policy = PolicyEngine(tools, ConfirmPermissions())
            gateway = ApprovalGateway(PostgresApprovalStore(conn), policy, sessions=sessions)
            executor = ToolExecutor(
                registry=tools,
                policy=policy,
                gateway=gateway,
                invocations=PostgresInvocationStore(conn),
            )

            run_id = uuid.uuid4()
            await conn.execute(
                text(
                    "INSERT INTO runs (id, user_id, trace_id, budget) "
                    "VALUES (:r, :u, 'e2e-fremd', '{}'::jsonb)"
                ),
                {"r": run_id, "u": session.user_id},
            )
            run = Run(
                id=run_id,
                user_id=session.user_id,
                status=RunStatus.EXECUTING,
                data_class=DataClass.P1,
                trace_id="e2e-fremd",
                started_at=datetime.now(tz=UTC),
            )

            schritt = await executor.execute_tool(
                run,
                BudgetTracker(run.budget),
                tool_name="calendar.create",
                arguments={"title": "Fokuszeit"},
                seq=1,
                session_id=session.id,
            )
            pending = schritt.pending
            assert pending is not None

            # Der Angreifer legt seinen eigenen, gültigen Token vor.
            versuch = await gateway.respond(
                action_id=pending.id,
                nonce=pending.nonce,
                approve=True,
                user_id=session.user_id,
                session_id=fremde.session.id,
                session_token=fremde.token,
                channel="ui",
                now=datetime.now(tz=UTC),
            )
            assert not versuch.approved
            assert spies["calendar.create"].call_count == 0

    async def test_ein_grant_aus_fremdem_lauf_fuehrt_nichts_aus(
        self, client: AsyncClient, engine: AsyncEngine
    ) -> None:
        """Die letzte Stufe der Kette: Selbst mit gültiger Identität und
        gültiger Bestätigung bleibt der Grant an seinen Lauf gebunden."""
        token, _ = await _angemeldet(client, engine)

        async with engine.begin() as conn:
            sessions = SessionManager(PostgresSessionStore(conn))
            session = await sessions.verify(token)
            assert session is not None

            tools, spies = build_registry()
            policy = PolicyEngine(tools, ConfirmPermissions())
            gateway = ApprovalGateway(PostgresApprovalStore(conn), policy, sessions=sessions)

            run_id, fremder_lauf = uuid.uuid4(), uuid.uuid4()
            for rid in (run_id, fremder_lauf):
                await conn.execute(
                    text(
                        "INSERT INTO runs (id, user_id, trace_id, budget) "
                        "VALUES (:r, :u, 'e2e-grant', '{}'::jsonb)"
                    ),
                    {"r": rid, "u": session.user_id},
                )
            await conn.execute(
                text(
                    "INSERT INTO tool_invocations (id, run_id, tool_name, arguments, "
                    "risk_level, policy_decision, decision_reason) VALUES "
                    "(:i, :r, 'calendar.create', '{}'::jsonb, 'medium', 'confirm', 'e2e')"
                ),
                {"i": run_id, "r": run_id},
            )

            from jarvis_core.policy import build_preview
            from tests.fakes import CALENDAR_CREATE

            argumente: dict[str, Any] = {"title": "Fokuszeit"}
            aktion = await gateway.request(
                spec=CALENDAR_CREATE,
                arguments=argumente,
                preview=build_preview(CALENDAR_CREATE, argumente),
                reason="E2E",
                run_id=run_id,
                invocation_id=run_id,
                user_id=session.user_id,
                session_id=session.id,
                channel="ui",
                now=datetime.now(tz=UTC),
            )
            await gateway.respond(
                action_id=aktion.id,
                nonce=aktion.nonce,
                approve=True,
                user_id=session.user_id,
                session_id=session.id,
                session_token=token,
                channel="ui",
                now=datetime.now(tz=UTC),
            )
            grant = await gateway.authorize_execution(
                action_id=aktion.id,
                arguments=argumente,
                spec=CALENDAR_CREATE,
                taint=TaintLevel.CLEAN,
                run_id=run_id,
                allowed_data_class=DataClass.P2,
                now=datetime.now(tz=UTC),
            )

            with pytest.raises(ForgedAuthorization):
                await tools.execute(grant, run_id=fremder_lauf, user_id=session.user_id)
            assert spies["calendar.create"].call_count == 0
