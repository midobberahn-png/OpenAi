"""Sitzungen gegen die echte Datenbank — und die Bindung im Approval Gateway.

Der Kern der Sitzungslogik ist in der Unit-Suite geprüft. Hier geht es um
zwei Dinge, die nur gegen Postgres gelten:

* Der Token existiert in der Tabelle nicht — auch nicht in irgendeiner Spalte,
  die man beim Lesen übersieht.
* Die Sitzungsbindung einer Bestätigung ist ab jetzt eine Prüfung und keine
  Behauptung. Bis zu diesem Punkt verglich ``approval-channel-bound`` zwei
  UUIDs, die beide vom Aufrufer stammten.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from jarvis_api.db.approval_store import PostgresApprovalStore
from jarvis_api.db.session_store import PostgresSessionStore
from jarvis_contracts import (
    PayloadInspectability,
    PermissionGrant,
    PermissionMode,
    RiskLevel,
    ScopeConstraints,
    ToolSpec,
)
from jarvis_core.auth import SessionManager, token_fingerprint
from jarvis_core.policy import ApprovalGateway, PolicyEngine, build_preview
from jarvis_core.tools import ToolRegistry

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

NOW = datetime(2026, 8, 19, 9, 0, tzinfo=UTC)

CALENDAR_CREATE = ToolSpec(
    name="calendar.create",
    description="Legt einen Termin im verbundenen Kalender an.",
    parameters={"type": "object"},
    risk=RiskLevel.MEDIUM,
    scopes=["calendar.create"],
    requires_preview=True,
    payload_inspectability=PayloadInspectability.STRUCTURED,
)

ARGS: dict[str, Any] = {"title": "Fokuszeit", "start": "2026-08-20T09:00:00Z"}


class ConfirmPermissions:
    """Erteilt ``calendar.create`` im Modus ``confirm`` — damit überhaupt eine
    Bestätigung entsteht, an der sich die Sitzungsbindung zeigen lässt."""

    async def get_grant(self, user_id: uuid.UUID, scope: str) -> PermissionGrant | None:
        if scope != "calendar.create":
            return None
        return PermissionGrant(
            scope=scope,
            mode=PermissionMode.CONFIRM,
            constraints=ScopeConstraints(),
            granted_at=NOW - timedelta(days=1),
        )

    async def granted_scopes(self, user_id: uuid.UUID) -> set[str]:
        return {"calendar.create"}


async def _seed_user(conn: AsyncConnection) -> uuid.UUID:
    uid = uuid.uuid4()
    await conn.execute(
        text("INSERT INTO users (id, email, display_name) VALUES (:i, :m, 'Sitzungstest')"),
        {"i": uid, "m": f"{uid}@example.test"},
    )
    return uid


async def _seed_run(conn: AsyncConnection, user_id: uuid.UUID) -> uuid.UUID:
    rid = uuid.uuid4()
    await conn.execute(
        text(
            "INSERT INTO runs (id, user_id, trace_id, budget) "
            "VALUES (:r, :u, 'sessions', '{}'::jsonb)"
        ),
        {"r": rid, "u": user_id},
    )
    await conn.execute(
        text(
            "INSERT INTO tool_invocations (id, run_id, tool_name, arguments, risk_level, "
            "policy_decision, decision_reason) VALUES "
            "(:i, :r, 'calendar.create', '{}'::jsonb, 'medium', 'confirm', 'test')"
        ),
        {"i": rid, "r": rid},
    )
    return rid


def _manager(conn: AsyncConnection, **kw: Any) -> SessionManager:
    return SessionManager(PostgresSessionStore(conn), **kw)


class TestSpeicher:
    async def test_token_steht_nirgends_in_der_tabelle(self, conn: AsyncConnection) -> None:
        """Die Zusicherung, wegen der die Spalte ``token_hash`` heißt."""
        uid = await _seed_user(conn)
        issued = await _manager(conn).issue(uid, client="MacBook", now=NOW)

        row = (
            (
                await conn.execute(
                    text("SELECT * FROM sessions WHERE id = :i"), {"i": issued.session.id}
                )
            )
            .mappings()
            .first()
        )
        assert row is not None
        assert issued.token not in str(dict(row))
        assert row["token_hash"] == token_fingerprint(issued.token)

    async def test_sitzung_ueberlebt_den_weg_durch_die_datenbank(
        self, conn: AsyncConnection
    ) -> None:
        uid = await _seed_user(conn)
        manager = _manager(conn)
        issued = await manager.issue(uid, client="iPhone", channel="voice", now=NOW)

        verified = await manager.verify(issued.token, now=NOW + timedelta(minutes=5))
        assert verified is not None
        assert verified.id == issued.session.id
        assert verified.client == "iPhone"
        assert verified.channel == "voice"

    async def test_widerruf_aller_sitzungen_meldet_die_anzahl(self, conn: AsyncConnection) -> None:
        uid = await _seed_user(conn)
        manager = _manager(conn)
        tokens = [(await manager.issue(uid, now=NOW)).token for _ in range(3)]

        assert await manager.revoke_all(uid, now=NOW + timedelta(minutes=1)) == 3
        for token in tokens:
            assert await manager.verify(token, now=NOW + timedelta(minutes=2)) is None
        # Ein zweiter Aufruf findet nichts mehr — bereits Widerrufenes wird
        # nicht erneut gezählt.
        assert await manager.revoke_all(uid, now=NOW + timedelta(minutes=3)) == 0

    async def test_zwei_sitzungen_mit_demselben_token_sind_unmoeglich(
        self, conn: AsyncConnection
    ) -> None:
        """Die Eindeutigkeit liegt in der Datenbank, nicht in der Anwendung —
        ein Zufallsgenerator, der zweimal denselben Wert liefert, ist ein Fehler,
        den man bemerken will."""
        from sqlalchemy.exc import IntegrityError

        uid = await _seed_user(conn)
        store = PostgresSessionStore(conn)
        first = await _manager(conn).issue(uid, now=NOW)
        stored = await store.by_token_hash(token_fingerprint(first.token))
        assert stored is not None

        doppelt = stored.model_copy(update={"id": uuid.uuid4()})
        with pytest.raises(IntegrityError):
            await store.create(doppelt, token_fingerprint(first.token))


class TestBindungImGateway:
    """Die Stelle, an der die Sitzung tatsächlich etwas entscheidet."""

    async def _pending(
        self, conn: AsyncConnection, gw: ApprovalGateway, uid: uuid.UUID, sid: uuid.UUID
    ) -> Any:
        rid = await _seed_run(conn, uid)
        return await gw.request(
            spec=CALENDAR_CREATE,
            arguments=ARGS,
            preview=build_preview(CALENDAR_CREATE, ARGS),
            reason="Test",
            run_id=rid,
            invocation_id=rid,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )

    def _gateway(self, conn: AsyncConnection, manager: SessionManager) -> ApprovalGateway:
        registry = ToolRegistry()
        registry.register(CALENDAR_CREATE)
        return ApprovalGateway(
            PostgresApprovalStore(conn),
            PolicyEngine(registry, ConfirmPermissions()),
            sessions=manager,
        )

    @pytest.mark.invariant("session-verified-before-approval")
    async def test_gueltige_sitzung_darf_bestaetigen(self, conn: AsyncConnection) -> None:
        """Der Normalfall muss funktionieren — sonst wird der Schutz
        abgeschaltet."""
        uid = await _seed_user(conn)
        manager = _manager(conn)
        issued = await manager.issue(uid, now=NOW)
        gw = self._gateway(conn, manager)
        action = await self._pending(conn, gw, uid, issued.session.id)

        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=issued.session.id,
            session_token=issued.token,
            channel="ui",
            now=NOW + timedelta(minutes=1),
        )
        assert outcome.approved

    @pytest.mark.invariant("session-verified-before-approval")
    async def test_ohne_token_wird_nicht_bestaetigt(self, conn: AsyncConnection) -> None:
        """Der Kern der Härtung: Die Sitzungs-ID allein genügt nicht mehr.

        Vor dieser Änderung hätte derselbe Aufruf funktioniert — der Aufrufer
        brachte eine passende UUID mit, und niemand fragte, woher.
        """
        uid = await _seed_user(conn)
        manager = _manager(conn)
        issued = await manager.issue(uid, now=NOW)
        gw = self._gateway(conn, manager)
        action = await self._pending(conn, gw, uid, issued.session.id)

        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=issued.session.id,
            session_token="",
            channel="ui",
            now=NOW + timedelta(minutes=1),
        )
        assert not outcome.approved
        assert "Sitzung" in outcome.reason

    @pytest.mark.invariant("session-verified-before-approval")
    async def test_widerrufene_sitzung_bestaetigt_nichts_mehr(self, conn: AsyncConnection) -> None:
        """Das gestohlene Gerät: Der Nutzer beendet alle Sitzungen, während
        eine Bestätigung offen ist. Sie darf danach nicht mehr einlösbar sein."""
        uid = await _seed_user(conn)
        manager = _manager(conn)
        issued = await manager.issue(uid, now=NOW)
        gw = self._gateway(conn, manager)
        action = await self._pending(conn, gw, uid, issued.session.id)

        await manager.revoke_all(uid, now=NOW + timedelta(seconds=30))

        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=issued.session.id,
            session_token=issued.token,
            channel="ui",
            now=NOW + timedelta(minutes=1),
        )
        assert not outcome.approved

    @pytest.mark.invariant("session-verified-before-approval")
    async def test_token_einer_anderen_sitzung_passt_nicht(self, conn: AsyncConnection) -> None:
        """Zwei gültige Sitzungen desselben Nutzers: Der Dialog wurde in der
        einen angezeigt und darf nicht aus der anderen bestätigt werden."""
        uid = await _seed_user(conn)
        manager = _manager(conn)
        angezeigt = await manager.issue(uid, client="Desktop", now=NOW)
        andere = await manager.issue(uid, client="Telefon", now=NOW)
        gw = self._gateway(conn, manager)
        action = await self._pending(conn, gw, uid, angezeigt.session.id)

        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=angezeigt.session.id,
            session_token=andere.token,
            channel="ui",
            now=NOW + timedelta(minutes=1),
        )
        assert not outcome.approved

    @pytest.mark.invariant("session-verified-before-approval")
    async def test_abgelaufene_sitzung_bestaetigt_nichts(self, conn: AsyncConnection) -> None:
        uid = await _seed_user(conn)
        manager = _manager(conn, ttl=timedelta(minutes=5))
        issued = await manager.issue(uid, now=NOW)
        gw = self._gateway(conn, manager)
        action = await self._pending(conn, gw, uid, issued.session.id)

        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=issued.session.id,
            session_token=issued.token,
            channel="ui",
            now=NOW + timedelta(minutes=6),
        )
        assert not outcome.approved

    async def test_gescheiterte_sitzungspruefung_verbraucht_die_nonce_nicht(
        self, conn: AsyncConnection
    ) -> None:
        """Sonst wäre ein erfundener Token ein Denial-of-Service: Ein Angreifer
        entwertete fremde Bestätigungen, ohne sie einlösen zu können."""
        uid = await _seed_user(conn)
        manager = _manager(conn)
        issued = await manager.issue(uid, now=NOW)
        gw = self._gateway(conn, manager)
        action = await self._pending(conn, gw, uid, issued.session.id)

        abgewiesen = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=issued.session.id,
            session_token="erfunden",
            channel="ui",
            now=NOW + timedelta(minutes=1),
        )
        assert not abgewiesen.approved

        # Mit echtem Token gelingt es danach immer noch.
        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=issued.session.id,
            session_token=issued.token,
            channel="ui",
            now=NOW + timedelta(minutes=2),
        )
        assert outcome.approved
