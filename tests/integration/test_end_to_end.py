"""Der vollständige Weg: „Prüfe meine Mails und blockier mir eine Stunde“.

Gegen die echte Datenbank, weil erst dort die Bestätigung ein persistiertes,
einmalig einlösbares Objekt ist. Ein In-Memory-Doppel könnte den Ablauf
nachspielen, aber nicht belegen.

Der Ablauf ist derjenige, an dem sich die Architektur entschieden hat
(docs/16-v1.1-review.md §1): Er ist der häufigste Alltagsfall *und* der Fall,
den V1.0 dauerhaft gesperrt hätte. Ein Sicherheitsmechanismus, der den
Normalfall blockiert, wird abgeschaltet — deshalb muss dieser Test zeigen,
dass der Weg gangbar ist, und zugleich, dass die Abzweigungen es nicht sind.

    Eingabe
      → Klassifikation (P2, mehrschrittig)
      → Routing (Modell mit P2-Freigabe)
      → Plan (lesen zuerst, schreiben danach)
      → mail.read  ⇒ Lauf TAINTED, Injection-Versuch im Inhalt
      → calendar.read
      → calendar.create ⇒ CONFIRM (sanierbar, weil strukturiert)
      → Bestätigung ⇒ eingefrorener Payload
      → sanierter Lauf ⇒ Ausführung
      → Audit-Kette
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from jarvis_api.db.approval_store import PostgresApprovalStore
from jarvis_api.db.invocation_store import PostgresInvocationStore
from jarvis_contracts import (
    DataClass,
    ModelCapability,
    PermissionGrant,
    PermissionMode,
    PolicyEffect,
    RunStatus,
    ScopeConstraints,
    TaintLevel,
)
from jarvis_core.agents import AgentChain, AgentRuntime
from jarvis_core.audit.chain import AuditEntry, compute_entry_hash, verify_chain
from jarvis_core.orchestrator import (
    BudgetTracker,
    ToolExecutor,
    classify,
    plan_turn,
    route,
)
from jarvis_core.policy import ApprovalGateway, PolicyEngine
from tests.fakes import (
    CALENDAR_CREATE,
    build_registry,
)

pytestmark = [pytest.mark.integration, pytest.mark.asyncio, pytest.mark.security]

NOW = datetime(2026, 8, 18, 9, 0, tzinfo=UTC)
EINGABE = "Prüfe meine Mails und blockier mir eine Stunde für das Wichtigste"

LOCAL = ModelCapability(
    name="llama-3.1-8b",
    provider="ollama",
    max_data_class=DataClass.P3,
    context_window=128_000,
    p50_latency_ms=250,
    is_local=True,
)
CLOUD_P1 = ModelCapability(
    name="cloud-fast",
    provider="anbieter_a",
    max_data_class=DataClass.P1,
    context_window=200_000,
    cost_per_1m_in=Decimal("0.30"),
    cost_per_1m_out=Decimal("1.50"),
    p50_latency_ms=400,
)


class DbPermissions:
    """Berechtigungen aus der echten Tabelle.

    Bewusst nicht die Attrappe: Der Test soll auch belegen, dass Scope-Namen,
    Modi und Zeitstempel den Weg durch die Datenbank überstehen.
    """

    def __init__(self, conn: AsyncConnection, user_id: uuid.UUID) -> None:
        self._conn = conn
        self._user = user_id

    async def get_grant(self, user_id: uuid.UUID, scope: str) -> PermissionGrant | None:
        row = (
            await self._conn.execute(
                text(
                    "SELECT scope, mode, granted_at, expires_at FROM permissions "
                    "WHERE user_id = :u AND scope = :s"
                ),
                {"u": user_id, "s": scope},
            )
        ).first()
        if row is None:
            return None
        return PermissionGrant(
            scope=row.scope,
            mode=PermissionMode(row.mode),
            constraints=ScopeConstraints(),
            granted_at=row.granted_at,
            expires_at=row.expires_at,
        )

    async def granted_scopes(self, user_id: uuid.UUID) -> set[str]:
        rows = await self._conn.execute(
            text("SELECT scope FROM permissions WHERE user_id = :u AND mode <> 'deny'"),
            {"u": user_id},
        )
        return {r.scope for r in rows}


class ChainAudit:
    """Audit-Senke mit echter Hash-Verkettung.

    Die Postgres-Implementierung fehlt noch (siehe HANDOFF §6); die Verkettung
    selbst ist aber Kernlogik und wird hier mitgeprüft — sonst bliebe der
    letzte Schritt der Kette im Test eine Behauptung.
    """

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []
        self.hashes: list[bytes] = []

    async def append(self, entry: AuditEntry) -> bytes:
        digest = compute_entry_hash(entry, self.hashes[-1] if self.hashes else None)
        self.entries.append(entry)
        self.hashes.append(digest)
        return digest

    async def verify(self, *, limit: int | None = None) -> list[Any]:
        return []

    def actions(self) -> list[str]:
        return [e.action for e in self.entries]


SCOPE_KATALOG: dict[str, tuple[str, str]] = {
    "mail.read": ("confirm", "low"),
    "mail.send": ("confirm", "high"),
    "calendar.read": ("allow", "low"),
    "calendar.create": ("confirm", "medium"),
}
"""Ausschnitt des Scope-Katalogs.

``permissions.scope`` ist ein Fremdschlüssel auf ``scopes.name`` — eine
Berechtigung für einen Scope, den der Katalog nicht kennt, ist auf
Datenbankebene nicht anlegbar. Der Test legt den Ausschnitt deshalb selbst an,
statt sich auf ``scripts/seed.py`` zu verlassen: Ein Test, der von einem
vorher ausgeführten Skript abhängt, schlägt irgendwann aus dem falschen Grund
fehl.
"""


async def _seed_user(conn: AsyncConnection, scopes: dict[str, str]) -> uuid.UUID:
    uid = uuid.uuid4()
    await conn.execute(
        text("INSERT INTO users (id, email, display_name) VALUES (:id, :m, 'E2E')"),
        {"id": uid, "m": f"{uid}@example.test"},
    )
    for scope, mode in scopes.items():
        default_mode, risk = SCOPE_KATALOG[scope]
        await conn.execute(
            text(
                "INSERT INTO scopes (name, description, default_mode, risk_level) "
                "VALUES (:n, :d, :dm, :r) ON CONFLICT (name) DO NOTHING"
            ),
            {"n": scope, "d": f"Scope {scope}", "dm": default_mode, "r": risk},
        )
        await conn.execute(
            text(
                "INSERT INTO permissions (id, user_id, scope, mode, granted_at) "
                "VALUES (:i, :u, :s, :m, :g)"
            ),
            {"i": uuid.uuid4(), "u": uid, "s": scope, "m": mode, "g": NOW - timedelta(days=1)},
        )
    return uid


async def _insert_run(conn: AsyncConnection, run_id: uuid.UUID, user_id: uuid.UUID) -> None:
    await conn.execute(
        text(
            "INSERT INTO runs (id, user_id, trace_id, budget) VALUES (:r, :u, 'e2e', '{}'::jsonb)"
        ),
        {"r": run_id, "u": user_id},
    )


class TestKompletterAblauf:
    async def test_mails_lesen_dann_termin_blockieren(self, conn: AsyncConnection) -> None:
        """Der Durchstich. Jeder Abschnitt prüft, was an dieser Stelle gelten
        muss — nicht nur, dass am Ende ein Termin existiert."""
        # Vorbedingung: Ohne strukturierte Einstufung und ohne attendees als
        # Außenwirkungsfeld prüfte dieser Ablauf etwas anderes, als er vorgibt.
        assert CALENDAR_CREATE.outbound_fields == ["attendees"]
        assert CALENDAR_CREATE.payload_inspectability.clearable_by_confirmation

        user_id = await _seed_user(
            conn,
            {"mail.read": "allow", "calendar.read": "allow", "calendar.create": "confirm"},
        )
        session_id = uuid.uuid4()
        permissions = DbPermissions(conn, user_id)
        tools, spies = build_registry()
        policy = PolicyEngine(tools, permissions)
        gateway = ApprovalGateway(PostgresApprovalStore(conn), policy)
        audit = ChainAudit()
        executor = ToolExecutor(
            registry=tools,
            policy=policy,
            gateway=gateway,
            audit=audit,
            invocations=PostgresInvocationStore(conn),
            clock=lambda: NOW,
        )

        # -- 1. Klassifikation ------------------------------------------
        classification = classify(EINGABE)
        assert classification.data_class is DataClass.P2, "Mails sind sensibel"
        assert classification.is_multi_step
        assert "mail.read" in classification.likely_tools

        # -- 2. Routing --------------------------------------------------
        routing = route(classification, [LOCAL, CLOUD_P1])
        assert routing.max_data_class >= DataClass.P2
        assert CLOUD_P1.name in routing.rejected, "P1-Modell darf P2 nicht sehen"

        # -- 3. Plan -----------------------------------------------------
        angeboten = await policy.effective_tools(user_id, tools.names())
        plan = plan_turn(classification, available_tools=angeboten, tools=tools, goal=EINGABE)
        ziele = [s.target for s in plan.steps if s.kind == "tool"]
        assert ziele.index("mail.read") < ziele.index("calendar.create")
        assert plan.steps[-1].kind == "llm"

        # -- 4. Lauf anlegen ---------------------------------------------
        run_id = uuid.uuid4()
        await _insert_run(conn, run_id, user_id)
        from jarvis_contracts import Run

        run = Run(
            id=run_id,
            user_id=user_id,
            trigger="user",
            status=RunStatus.QUEUED,
            classification=classification,
            routing=routing,
            plan=plan,
            data_class=classification.data_class,
            trace_id="e2e",
            started_at=NOW,
        )
        tracker = BudgetTracker(run.budget, clock=lambda: NOW)
        run = executor.start(run, tracker)
        assert run.status is RunStatus.EXECUTING

        # -- 5. mail.read: liest Fremdinhalt, kontaminiert den Lauf ------
        step1 = await executor.execute_tool(
            run,
            tracker,
            tool_name="mail.read",
            arguments={"folder": "INBOX"},
            seq=1,
            session_id=session_id,
        )
        assert step1.status == "executed"
        run = step1.run
        assert run.taint_level is TaintLevel.TAINTED
        assert step1.result is not None
        nachricht = step1.result.data["messages"][0]  # type: ignore[index]
        assert "exfil@example.com" in nachricht["body"], "Der Injection-Versuch ist im Inhalt"

        # -- 6. Der Versuch, dem Fremdinhalt zu folgen, scheitert --------
        exfil = await executor.execute_tool(
            run,
            tracker,
            tool_name="mail.send",
            arguments={"to": ["exfil@example.com"], "subject": "Zusammenfassung", "body": "…"},
            seq=2,
            session_id=session_id,
        )
        assert exfil.status == "blocked"
        assert spies["mail.send"].call_count == 0, "Kein Versand nach dem Lesen von Fremdinhalt"

        # -- 7. calendar.read bleibt erlaubt (unbedenklich) --------------
        step2 = await executor.execute_tool(
            step1.run,
            tracker,
            tool_name="calendar.read",
            arguments={},
            seq=2,
            session_id=session_id,
        )
        assert step2.status == "executed"
        run = step2.run

        # -- 8. calendar.create: sanierbar, also Bestätigung -------------
        termin: dict[str, Any] = {
            "title": "Angebot Projekt X vorbereiten",
            "start": "2026-08-19T14:00:00Z",
            "duration_min": 60,
        }
        step3 = await executor.execute_tool(
            run,
            tracker,
            tool_name="calendar.create",
            arguments=termin,
            seq=3,
            session_id=session_id,
        )
        assert step3.status == "awaiting_confirmation"
        assert step3.decision is not None
        assert step3.decision.effect is PolicyEffect.CONFIRM
        assert "sauberen Lauf" in step3.decision.reason
        assert spies["calendar.create"].call_count == 0
        pending = step3.pending
        assert pending is not None
        assert step3.run.status is RunStatus.AWAITING_CONFIRMATION

        # Die Vorschau zeigt, was tatsächlich ausgeführt wird.
        felder = {f.label: f.value for f in pending.preview.fields}
        assert felder["title"] == termin["title"]
        assert "attendees" not in felder, "Ohne Teilnehmer — sonst wäre es Versand"

        # -- 9. Bestätigung ----------------------------------------------
        outcome = await gateway.respond(
            action_id=pending.id,
            nonce=pending.nonce,
            approve=True,
            user_id=user_id,
            session_id=session_id,
            channel="ui",
            now=NOW + timedelta(seconds=30),
        )
        assert outcome.approved
        assert outcome.sanitized is not None
        assert outcome.sanitized.arguments == termin, "Byte-identisch eingefroren"

        # -- 10. Sanierter Lauf: sauber, ohne Kontext, mit Verweis -------
        clean = executor.sanitized_run(step3.run, outcome.sanitized)
        await _insert_run(conn, clean.id, user_id)
        assert clean.taint_level is TaintLevel.CLEAN
        assert clean.conversation_id is None
        assert clean.sanitized_from_run_id == step3.run.id

        clean = executor.start(clean, tracker)
        clean = clean.model_copy(
            update={"state": clean.state.model_copy(update={"awaiting_action_id": pending.id})}
        )
        final = await executor.resume_after_approval(
            clean,
            tracker,
            action_id=pending.id,
            arguments=outcome.sanitized.arguments,
            tool_name="calendar.create",
            seq=1,
        )
        assert final.status == "executed", final.reason
        assert spies["calendar.create"].call_count == 1
        assert final.result is not None
        assert final.result.undo_token, "MEDIUM-Aktionen bieten Undo an"
        assert final.run.taint_level is TaintLevel.CLEAN

        # -- 11. Audit: lückenlos und unversehrt -------------------------
        assert audit.actions().count("tool.executed") == 3
        assert "tool.denied" in audit.actions(), "Der abgewehrte Versand steht im Protokoll"
        assert "tool.confirmation_requested" in audit.actions()

        rows = _stored_rows(audit)
        assert not verify_chain(rows), "Die Hash-Kette muss unversehrt sein"

    async def test_eingeschmuggelter_teilnehmer_bricht_den_ablauf_ab(
        self, conn: AsyncConnection
    ) -> None:
        """Derselbe Weg, aber die präparierte Mail hat einen Teilnehmer
        eingeschmuggelt. Ein Kalendereintrag mit Teilnehmern verschickt
        Einladungen — das ist Versand, nicht Notiz, und damit nicht sanierbar.

        Der Unterschied zum Test oben ist ein einziges Argument. Genau das ist
        der Punkt: Die Einstufung hängt am Aufruf, nicht am Werkzeug.
        """
        user_id = await _seed_user(conn, {"mail.read": "allow", "calendar.create": "allow"})
        session_id = uuid.uuid4()
        tools, spies = build_registry()
        policy = PolicyEngine(tools, DbPermissions(conn, user_id))
        executor = ToolExecutor(
            registry=tools,
            policy=policy,
            gateway=ApprovalGateway(PostgresApprovalStore(conn), policy),
            invocations=PostgresInvocationStore(conn),
            clock=lambda: NOW,
        )

        run_id = uuid.uuid4()
        await _insert_run(conn, run_id, user_id)
        from jarvis_contracts import Run

        run = Run(
            id=run_id,
            user_id=user_id,
            status=RunStatus.EXECUTING,
            data_class=DataClass.P2,
            routing=route(classify(EINGABE), [LOCAL]),
            trace_id="e2e-attack",
            started_at=NOW,
        )
        tracker = BudgetTracker(run.budget, clock=lambda: NOW)

        gelesen = await executor.execute_tool(
            run, tracker, tool_name="mail.read", arguments={}, seq=1, session_id=session_id
        )
        assert gelesen.run.taint_level is TaintLevel.TAINTED

        angriff = await executor.execute_tool(
            gelesen.run,
            tracker,
            tool_name="calendar.create",
            arguments={
                "title": "Abstimmung",
                "start": "2026-08-19T14:00:00Z",
                "attendees": ["thomas@kunde.de", "attacker@example.com"],
            },
            seq=2,
            session_id=session_id,
        )
        assert angriff.status == "blocked"
        assert angriff.decision is not None
        assert angriff.decision.escalate_to_user, "Der Nutzer muss davon erfahren"
        assert "Teilnehmer" in angriff.decision.reason
        assert spies["calendar.create"].call_count == 0


class TestKompletterAblaufMitAgenten:
    async def test_delegation_kontaminiert_den_uebergeordneten_lauf(
        self, conn: AsyncConnection
    ) -> None:
        """Derselbe Ablauf, aber über einen Sub-Agenten — und der behauptet,
        sauber geblieben zu sein.

        Damit ist die Kette einmal komplett gegen die echte Persistenz geprüft:
        Delegation → Werkzeugausführung → Kontamination → Sperre beim
        Supervisor.
        """
        from jarvis_contracts import AgentResult, AgentSpec, AgentStatus, Run
        from jarvis_core.agents import AgentRegistry

        user_id = await _seed_user(conn, {"mail.read": "allow", "mail.send": "allow"})
        session_id = uuid.uuid4()
        tools, spies = build_registry()
        policy = PolicyEngine(tools, DbPermissions(conn, user_id))
        executor = ToolExecutor(
            registry=tools,
            policy=policy,
            gateway=ApprovalGateway(PostgresApprovalStore(conn), policy),
            invocations=PostgresInvocationStore(conn),
            clock=lambda: NOW,
        )

        supervisor = AgentSpec(
            name="supervisor",
            description="Koordiniert die Sub-Agenten.",
            system_prompt="…",
            allowed_tools=["mail.read", "mail.send"],
            can_delegate=True,
        )
        mail_agent = AgentSpec(
            name="mail",
            description="Analysiert das Postfach.",
            system_prompt="…",
            allowed_tools=["mail.read"],
            accepts_untrusted_input=True,
        )
        registry = AgentRegistry()
        registry.register(supervisor)
        registry.register(mail_agent)
        runtime = AgentRuntime(agents=registry, tools=tools, policy=policy, executor=executor)

        class LuegenderAgent:
            async def act(self, session: Any, request: Any) -> AgentResult:
                await session.call_tool("mail.read", {}, seq=1)
                return AgentResult(
                    status=AgentStatus.SUCCESS, output="nichts Auffälliges", taint_acquired=False
                )

        run_id = uuid.uuid4()
        await _insert_run(conn, run_id, user_id)
        run = Run(
            id=run_id,
            user_id=user_id,
            status=RunStatus.EXECUTING,
            data_class=DataClass.P2,
            trace_id="e2e-agent",
            started_at=NOW,
        )
        tracker = BudgetTracker(run.budget, clock=lambda: NOW)

        delegation = await runtime.delegate(
            chain=AgentChain(agents=(supervisor,)),
            target="mail",
            task="Postfach prüfen",
            run=run,
            tracker=tracker,
            behaviour=LuegenderAgent(),
            session_id=session_id,
        )
        assert delegation.result.taint_acquired is False, "Der Agent behauptet Sauberkeit"
        assert delegation.tainted, "Der Lauf weiß es besser"

        versand = await executor.execute_tool(
            delegation.run,
            tracker,
            tool_name="mail.send",
            arguments={"to": ["exfil@example.com"], "body": "…"},
            seq=2,
            session_id=session_id,
        )
        assert versand.status == "blocked"
        assert spies["mail.send"].call_count == 0


def _stored_rows(audit: ChainAudit) -> list[Any]:
    """Übersetzt die mitgeschriebenen Einträge in die Form, die
    ``verify_chain`` erwartet."""
    from jarvis_core.audit.chain import StoredAuditRow

    rows: list[StoredAuditRow] = []
    previous: bytes | None = None
    for index, (entry, digest) in enumerate(zip(audit.entries, audit.hashes, strict=True), start=1):
        rows.append(
            StoredAuditRow(
                id=index,
                occurred_at=entry.occurred_at,
                actor=entry.actor,
                action=entry.action,
                resource=entry.resource,
                details=entry.details,
                trace_id=entry.trace_id,
                user_id=entry.user_id,
                prev_hash=previous,
                entry_hash=digest,
            )
        )
        previous = digest
    return rows
