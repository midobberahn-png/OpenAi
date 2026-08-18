"""Approval Gateway gegen die echte Datenbank.

Die Angriffe B, C und G aus dem Architektur-Review. Bewusst als
Integrationstest: Die Einmaligkeit einer Bestätigung wird von PostgreSQL
erzwungen, nicht von der Anwendung. Ein In-Memory-Doppel könnte Atomarität
nicht beweisen, sondern nur behaupten.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from jarvis_api.db.approval_store import PostgresApprovalStore
from jarvis_contracts import (
    PayloadInspectability,
    PermissionGrant,
    PermissionMode,
    PolicyRequest,
    RiskLevel,
    ScopeConstraints,
    TaintLevel,
    ToolSpec,
)
from jarvis_core.policy import (
    ApprovalGateway,
    ExecutionDenied,
    PolicyEngine,
    build_preview,
)
from jarvis_core.ports.approval import BurnResult
from jarvis_core.tools import ToolRegistry

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)

CALENDAR_CREATE = ToolSpec(
    name="calendar.create",
    description="Legt einen Termin im verbundenen Kalender an.",
    parameters={"type": "object"},
    risk=RiskLevel.MEDIUM,
    scopes=["calendar.create"],
    requires_preview=True,
    payload_inspectability=PayloadInspectability.STRUCTURED,
    outbound_fields=["attendees"],
)

ARGS: dict[str, Any] = {"title": "Angebot Projekt X", "start": "2026-08-19T14:00:00Z"}


class MutablePermissions:
    """Berechtigungen, die sich zur Laufzeit ändern lassen — für den
    TOCTOU-Test unerlässlich."""

    def __init__(self) -> None:
        self.grants: dict[str, PermissionGrant] = {}

    def allow(self, scope: str) -> None:
        self.grants[scope] = PermissionGrant(
            scope=scope,
            mode=PermissionMode.ALLOW,
            constraints=ScopeConstraints(),
            granted_at=NOW - timedelta(days=1),
        )

    def revoke(self, scope: str) -> None:
        self.grants.pop(scope, None)

    async def get_grant(self, user_id: uuid.UUID, scope: str) -> PermissionGrant | None:
        return self.grants.get(scope)

    async def granted_scopes(self, user_id: uuid.UUID) -> set[str]:
        return set(self.grants)


async def _seed(conn: AsyncConnection) -> tuple[uuid.UUID, uuid.UUID]:
    """Nutzer und Lauf anlegen; pending_actions verweist auf beide."""
    uid, rid = uuid.uuid4(), uuid.uuid4()
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
            "VALUES (:iid, :rid, 'calendar.create', '{}'::jsonb, 'medium', 'confirm', 'test')"
        ),
        {"iid": rid, "rid": rid},  # invocation_id = rid, nur für den Test
    )
    return uid, rid


def _gateway(conn: AsyncConnection, perms: MutablePermissions) -> ApprovalGateway:
    registry = ToolRegistry()
    registry.register(CALENDAR_CREATE)
    return ApprovalGateway(PostgresApprovalStore(conn), PolicyEngine(registry, perms))


async def _request(
    gw: ApprovalGateway,
    uid: uuid.UUID,
    rid: uuid.UUID,
    sid: uuid.UUID,
    args: dict[str, Any] | None = None,
) -> Any:
    payload = args if args is not None else ARGS
    return await gw.request(
        spec=CALENDAR_CREATE,
        arguments=payload,
        preview=build_preview(CALENDAR_CREATE, payload),
        reason="Test",
        run_id=rid,
        invocation_id=rid,
        user_id=uid,
        session_id=sid,
        channel="ui",
        now=NOW,
    )


# ==========================================================================
# Normalfall
# ==========================================================================


class TestNormalfall:
    async def test_anfrage_bestaetigung_ausfuehrung(self, conn: AsyncConnection) -> None:
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        assert action.is_open
        assert len(action.payload_hash) == 64

        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )
        assert outcome.approved
        assert outcome.sanitized is not None
        assert outcome.sanitized.arguments == ARGS

        grant = await gw.authorize_execution(
            action_id=action.id,
            arguments=ARGS,
            spec=CALENDAR_CREATE,
            taint=TaintLevel.TAINTED,
            run_id=rid,
            now=NOW + timedelta(seconds=5),
        )
        assert grant.verified_hash == action.payload_hash

    async def test_ablehnung_verhindert_ausfuehrung(self, conn: AsyncConnection) -> None:
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=False,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )
        assert not outcome.approved

        with pytest.raises(ExecutionDenied) as exc:
            await gw.authorize_execution(
                action_id=action.id,
                arguments=ARGS,
                spec=CALENDAR_CREATE,
                taint=TaintLevel.CLEAN,
                now=NOW,
                run_id=rid,
            )
        assert exc.value.code == "approval-not-granted"


# ==========================================================================
# Angriff B — Payload nach der Bestätigung verändern
# ==========================================================================


class TestAngriffBPayloadMutation:
    @pytest.mark.invariant("payload-immutable-after-approval")
    async def test_veraenderte_argumente_werden_abgelehnt(self, conn: AsyncConnection) -> None:
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )

        manipuliert = {**ARGS, "attendees": ["attacker@example.com"]}
        with pytest.raises(ExecutionDenied) as exc:
            await gw.authorize_execution(
                action_id=action.id,
                arguments=manipuliert,
                spec=CALENDAR_CREATE,
                taint=TaintLevel.CLEAN,
                now=NOW,
                run_id=rid,
            )
        assert exc.value.code == "payload-mismatch"
        assert "weicht von dem ab" in exc.value.reason

    @pytest.mark.invariant("payload-immutable-after-approval")
    async def test_einzelne_geaenderte_ziffer_wird_erkannt(self, conn: AsyncConnection) -> None:
        """Die Uhrzeit um eine Stelle zu verschieben, ist der subtile Fall."""
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )
        with pytest.raises(ExecutionDenied) as exc:
            await gw.authorize_execution(
                action_id=action.id,
                arguments={**ARGS, "start": "2026-08-19T04:00:00Z"},
                spec=CALENDAR_CREATE,
                taint=TaintLevel.CLEAN,
                now=NOW,
                run_id=rid,
            )
        assert exc.value.code == "payload-mismatch"

    @pytest.mark.invariant("approval-bound-to-payload-hash")
    async def test_bestaetigung_gilt_nicht_fuer_ein_anderes_werkzeug(
        self, conn: AsyncConnection
    ) -> None:
        """Der Werkzeugname geht in den Hash ein — sonst ließe sich eine
        Bestätigung mit identischen Argumenten übertragen."""
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        perms.allow("tasks.write")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )

        anderes = ToolSpec(
            name="tasks.create",
            description="Legt eine Aufgabe an.",
            parameters={"type": "object"},
            risk=RiskLevel.MEDIUM,
            scopes=["tasks.write"],
            requires_preview=True,
            payload_inspectability=PayloadInspectability.STRUCTURED,
        )
        with pytest.raises(ExecutionDenied) as exc:
            await gw.authorize_execution(
                action_id=action.id,
                arguments=ARGS,
                spec=anderes,
                taint=TaintLevel.CLEAN,
                now=NOW,
                run_id=rid,
            )
        assert exc.value.code == "payload-mismatch"


class TestAngriffCToctou:
    @pytest.mark.invariant("approval-toctou-protected")
    async def test_entzogenes_recht_entwertet_die_bestaetigung(self, conn: AsyncConnection) -> None:
        """Eine alte Bestätigung darf keine neue Berechtigung erzeugen."""
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )
        assert outcome.approved

        # Zwischen Klick und Ausführung wird das Recht entzogen.
        perms.revoke("calendar.create")

        with pytest.raises(ExecutionDenied) as exc:
            await gw.authorize_execution(
                action_id=action.id,
                arguments=ARGS,
                spec=CALENDAR_CREATE,
                taint=TaintLevel.CLEAN,
                now=NOW + timedelta(seconds=1),
                run_id=rid,
            )
        assert exc.value.code == "policy-changed"

    @pytest.mark.invariant("approval-toctou-protected")
    async def test_ablauf_zwischen_bestaetigung_und_ausfuehrung(
        self, conn: AsyncConnection
    ) -> None:
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )
        with pytest.raises(ExecutionDenied) as exc:
            await gw.authorize_execution(
                action_id=action.id,
                arguments=ARGS,
                spec=CALENDAR_CREATE,
                taint=TaintLevel.CLEAN,
                now=NOW + timedelta(minutes=11),
                run_id=rid,
            )
        assert exc.value.code == "approval-expired"

    @pytest.mark.invariant("approval-toctou-protected")
    async def test_nachtraegliche_kontamination_wird_bemerkt(self, conn: AsyncConnection) -> None:
        """Bestätigt wurde ohne Teilnehmer. Wenn im Ausführungsmoment
        Teilnehmer im Payload stehen, greift zusätzlich der Hash-Vergleich —
        aber auch die erneute Policy-Prüfung muss die Klasse neu bewerten."""
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        mit_teilnehmern = {**ARGS, "attendees": ["thomas@kunde.de"]}
        action = await _request(gw, uid, rid, sid, mit_teilnehmern)
        await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )
        with pytest.raises(ExecutionDenied) as exc:
            await gw.authorize_execution(
                action_id=action.id,
                arguments=mit_teilnehmern,
                spec=CALENDAR_CREATE,
                taint=TaintLevel.TAINTED,
                now=NOW + timedelta(seconds=1),
                run_id=rid,
            )
        assert exc.value.code == "policy-changed"


# ==========================================================================
# Angriff G — Replay
# ==========================================================================


class TestAngriffGReplay:
    @pytest.mark.invariant("approval-nonce-single-use")
    async def test_zweite_einloesung_wird_abgelehnt(self, conn: AsyncConnection) -> None:
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        first = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )
        assert first.approved

        second = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )
        assert not second.approved
        assert "bereits eingelöst" in second.reason

    @pytest.mark.invariant("approval-nonce-single-use")
    async def test_gleichzeitige_einloesung_gewinnt_genau_einmal(self, engine: AsyncEngine) -> None:
        """Der eigentliche Beweis der Atomarität.

        Zehn gleichzeitige Anfragen mit derselben Nonce, jede in eigener
        Verbindung und eigener Transaktion. Ein Ablauf „lesen, prüfen,
        schreiben" in der Anwendung ließe hier mehrere gewinnen; das bedingte
        UPDATE lässt genau eine Zeile treffen.

        Dieser Test läuft ohne die Rollback-Fixture, weil parallele
        Transaktionen einander sehen müssen — und räumt am Ende selbst auf.
        """
        perms = MutablePermissions()
        perms.allow("calendar.create")

        async with engine.begin() as setup:
            uid, rid = await _seed(setup)
            gw = _gateway(setup, perms)
            sid = uuid.uuid4()
            action = await _request(gw, uid, rid, sid)

        async def attempt() -> BurnResult:
            async with engine.begin() as conn:
                store = PostgresApprovalStore(conn)
                return await store.burn(
                    action_id=action.id,
                    nonce=action.nonce,
                    response="approved",
                    channel="ui",
                    now=NOW,
                )

        try:
            results = await asyncio.gather(*(attempt() for _ in range(10)))
            burned = [r for r in results if r is BurnResult.BURNED]
            already = [r for r in results if r is BurnResult.ALREADY_USED]
            assert len(burned) == 1, f"Genau eine Einlösung erwartet, war {len(burned)}"
            assert len(already) == 9, f"Verteilung: {results}"
        finally:
            async with engine.begin() as cleanup:
                await cleanup.execute(text("DELETE FROM users WHERE id = :uid"), {"uid": uid})

    @pytest.mark.invariant("approval-nonce-single-use")
    async def test_falsche_nonce_entwertet_die_bestaetigung_nicht(
        self, conn: AsyncConnection
    ) -> None:
        """Sonst wäre ein Fälschungsversuch ein Denial-of-Service: Der Angreifer
        könnte fremde Bestätigungen unbrauchbar machen, ohne sie zu kennen."""
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        bad = await gw.respond(
            action_id=action.id,
            nonce="x" * 43,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )
        assert not bad.approved
        assert "ungültig" in bad.reason

        good = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )
        assert good.approved, "Die echte Nonce muss danach weiterhin gelten"


# ==========================================================================
# Bindung an Nutzer, Sitzung und Kanal
# ==========================================================================


class TestBindung:
    @pytest.mark.invariant("approval-not-forgeable-by-model")
    async def test_fremder_nutzer_kann_nicht_bestaetigen(self, conn: AsyncConnection) -> None:
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uuid.uuid4(),
            session_id=sid,
            channel="ui",
            now=NOW,
        )
        assert not outcome.approved
        assert "anderen Nutzer" in outcome.reason

    @pytest.mark.invariant("approval-channel-bound")
    async def test_fremde_sitzung_kann_nicht_bestaetigen(self, conn: AsyncConnection) -> None:
        """Begrenzt den Schaden eines gestohlenen Sitzungstokens."""
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=uuid.uuid4(),
            channel="ui",
            now=NOW,
        )
        assert not outcome.approved
        assert "anderen Sitzung" in outcome.reason

    @pytest.mark.invariant("approval-channel-bound")
    async def test_geste_kann_ui_dialog_nicht_bestaetigen(self, conn: AsyncConnection) -> None:
        """Eine Geste aus vier Metern Entfernung, die einen ungelesenen Dialog
        freigibt, ist keine informierte Zustimmung."""
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="gesture",
            now=NOW,
        )
        assert not outcome.approved
        assert "angezeigt wurde" in outcome.reason

    @pytest.mark.invariant("approval-channel-bound")
    async def test_sprache_darf_einen_ui_dialog_bestaetigen(self, conn: AsyncConnection) -> None:
        """Bewusste Ausnahme: Der Nutzer sieht die Vorschau, während er spricht.
        Umgekehrt gilt das nicht."""
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="voice",
            now=NOW,
        )
        assert outcome.approved

    async def test_abgelaufene_bestaetigung_wird_markiert(self, conn: AsyncConnection) -> None:
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        outcome = await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW + timedelta(minutes=11),
        )
        assert not outcome.approved
        assert "abgelaufen" in outcome.reason

        stored = await PostgresApprovalStore(conn).get(action.id)
        assert stored is not None
        assert stored.response == "expired", "Abgelaufenes darf nicht offen bleiben"


# ==========================================================================
# Der zweite Grant-Pfad — gegen die echte Datenbank
# ==========================================================================


class TestGateOhneBestaetigung:
    """``authorize_allowed()`` ist der Weg für Aufrufe ohne Bestätigung.

    Er wurde nötig, weil ein Grant sonst nur aus dem Bestätigungspfad entstehen
    konnte und ein unbedenkliches Werkzeug damit gar nicht ausführbar gewesen
    wäre. Die Prüfungen gehören deshalb hierher — gegen dieselbe Persistenz,
    gegen die auch der Bestätigungspfad geprüft wird.
    """

    @pytest.mark.invariant("policy-single-entry-point")
    async def test_erlaubter_aufruf_erhaelt_einen_grant(self, conn: AsyncConnection) -> None:
        uid, rid = await _seed(conn)
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        grant = await gw.authorize_allowed(
            request=PolicyRequest(
                user_id=uid, run_id=rid, tool_name="calendar.create", arguments=ARGS
            ),
            spec=CALENDAR_CREATE,
            taint=TaintLevel.CLEAN,
            invocation_id=rid,
            now=NOW,
        )
        assert grant.run_id == rid
        assert grant.user_id == uid

    @pytest.mark.invariant("approval-toctou-protected")
    async def test_entzogenes_recht_verhindert_den_grant(self, conn: AsyncConnection) -> None:
        """Stale Authorization: Die Policy sagte eben noch ALLOW, das Recht ist
        inzwischen weg. Das Gate fragt selbst — eine mitgebrachte Entscheidung
        gäbe es hier nicht zu verwerten."""
        uid, rid = await _seed(conn)
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)
        request = PolicyRequest(
            user_id=uid, run_id=rid, tool_name="calendar.create", arguments=ARGS
        )

        assert await gw.authorize_allowed(
            request=request,
            spec=CALENDAR_CREATE,
            taint=TaintLevel.CLEAN,
            invocation_id=rid,
            now=NOW,
        )

        perms.revoke("calendar.create")
        with pytest.raises(ExecutionDenied) as denied:
            await gw.authorize_allowed(
                request=request,
                spec=CALENDAR_CREATE,
                taint=TaintLevel.CLEAN,
                invocation_id=rid,
                now=NOW,
            )
        assert denied.value.code == "policy-denied"

    @pytest.mark.invariant("policy-single-entry-point")
    async def test_geprueftes_und_auszufuehrendes_werkzeug_muessen_gleich_sein(
        self, conn: AsyncConnection
    ) -> None:
        """Tool Swap: Die Anfrage nennt das harmlose Werkzeug, die Spezifikation
        das schärfere. Geprüft würde das eine, ausgeführt das andere."""
        uid, rid = await _seed(conn)
        perms = MutablePermissions()
        perms.allow("calendar.read")
        gw = _gateway(conn, perms)

        with pytest.raises(ExecutionDenied) as denied:
            await gw.authorize_allowed(
                request=PolicyRequest(
                    user_id=uid, run_id=rid, tool_name="calendar.read", arguments=ARGS
                ),
                spec=CALENDAR_CREATE,
                taint=TaintLevel.CLEAN,
                invocation_id=rid,
                now=NOW,
            )
        assert denied.value.code == "tool-mismatch"

    @pytest.mark.invariant("taint-precedes-permission")
    async def test_kontamination_verhindert_den_grant(self, conn: AsyncConnection) -> None:
        """Ein Termin *mit Teilnehmern* wirkt nach außen und ist nach dem Lesen
        von Fremdinhalt gesperrt — auch auf diesem Pfad."""
        uid, rid = await _seed(conn)
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        with pytest.raises(ExecutionDenied) as denied:
            await gw.authorize_allowed(
                request=PolicyRequest(
                    user_id=uid,
                    run_id=rid,
                    tool_name="calendar.create",
                    arguments={**ARGS, "attendees": ["attacker@example.com"]},
                ),
                spec=CALENDAR_CREATE,
                taint=TaintLevel.TAINTED,
                invocation_id=rid,
                now=NOW,
            )
        assert denied.value.code == "policy-denied"

    @pytest.mark.invariant("grant-bound-to-run")
    async def test_grant_aus_lauf_a_fuehrt_in_lauf_b_nicht_aus(self, conn: AsyncConnection) -> None:
        """Grant Confusion gegen die echte Persistenz: zwei Läufe desselben
        Nutzers, derselbe Werkzeugaufruf, identische Argumente. Der Grant aus
        dem einen darf im anderen nicht ausführen — sonst wäre die Laufbindung
        reine Konvention."""
        from jarvis_contracts import ToolResult
        from jarvis_core.tools import ForgedAuthorization

        uid, rid_a = await _seed(conn)
        rid_b = uuid.uuid4()
        await conn.execute(
            text(
                "INSERT INTO runs (id, user_id, trace_id, budget) "
                "VALUES (:rid, :uid, 'trace-b', '{}'::jsonb)"
            ),
            {"rid": rid_b, "uid": uid},
        )

        called: list[dict[str, Any]] = []

        async def handler(**kwargs: Any) -> ToolResult:
            called.append(kwargs)
            return ToolResult(ok=True, display="angelegt")

        registry = ToolRegistry()
        registry.register(CALENDAR_CREATE, handler)
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = ApprovalGateway(PostgresApprovalStore(conn), PolicyEngine(registry, perms))

        grant = await gw.authorize_allowed(
            request=PolicyRequest(
                user_id=uid, run_id=rid_a, tool_name="calendar.create", arguments=ARGS
            ),
            spec=CALENDAR_CREATE,
            taint=TaintLevel.CLEAN,
            invocation_id=rid_a,
            now=NOW,
        )

        with pytest.raises(ForgedAuthorization, match="anderen Lauf"):
            await registry.execute(grant, run_id=rid_b, user_id=uid)
        with pytest.raises(ForgedAuthorization, match="anderen Lauf"):
            await registry.execute(grant, run_id=rid_a, user_id=uuid.uuid4())
        assert not called, "Ein laufsfremder Grant darf den Handler nicht erreichen"

        # Gegenprobe: Im eigenen Lauf führt derselbe Grant aus.
        result = await registry.execute(grant, run_id=rid_a, user_id=uid)
        assert result.ok
        assert len(called) == 1


class TestLaufbindungDerBestaetigung:
    """In welchem Lauf darf eine Bestätigung eingelöst werden?

    Der Fall fiel beim Durchstichtest auf: ``authorize_execution`` band den
    Grant an den *bestätigenden* Lauf und prüfte nie, in welchem Lauf
    tatsächlich ausgeführt wird. Damit war eine Bestätigung aus Lauf A in jedem
    beliebigen Lauf einlösbar — der Nutzer hätte dann etwas anderes freigegeben,
    als geschieht.
    """

    @pytest.mark.invariant("grant-bound-to-run")
    async def test_fremder_lauf_kann_die_bestaetigung_nicht_einloesen(
        self, conn: AsyncConnection
    ) -> None:
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )

        with pytest.raises(ExecutionDenied) as denied:
            await gw.authorize_execution(
                action_id=action.id,
                arguments=ARGS,
                spec=CALENDAR_CREATE,
                taint=TaintLevel.CLEAN,
                run_id=uuid.uuid4(),  # irgendein anderer Lauf
                now=NOW + timedelta(seconds=5),
            )
        assert denied.value.code == "run-mismatch"

    @pytest.mark.invariant("taint-cross-run-isolation")
    async def test_sanierter_lauf_darf_einloesen(self, conn: AsyncConnection) -> None:
        """Die eine zulässige Ausnahme: Der sanierte Lauf ist ein anderer Lauf,
        aber der aus dieser Bestätigung hervorgegangene. Ohne diese Ausnahme
        wäre das Sanitization-Gate nicht ausführbar — und ein Schutz, der den
        Normalfall blockiert, wird abgeschaltet."""
        uid, rid = await _seed(conn)
        sid = uuid.uuid4()
        perms = MutablePermissions()
        perms.allow("calendar.create")
        gw = _gateway(conn, perms)

        action = await _request(gw, uid, rid, sid)
        await gw.respond(
            action_id=action.id,
            nonce=action.nonce,
            approve=True,
            user_id=uid,
            session_id=sid,
            channel="ui",
            now=NOW,
        )

        sanierter_lauf = uuid.uuid4()
        grant = await gw.authorize_execution(
            action_id=action.id,
            arguments=ARGS,
            spec=CALENDAR_CREATE,
            taint=TaintLevel.CLEAN,
            run_id=sanierter_lauf,
            sanitized_from_run_id=rid,
            now=NOW + timedelta(seconds=5),
        )
        assert grant.run_id == sanierter_lauf, "Der Grant gilt dort, wo ausgeführt wird"
