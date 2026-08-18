"""Stufe 5 — Ausführung als Zustandsmaschine.

Siehe docs/04-orchestrator.md §6 und docs/07-security-permissions.md §4a–§5.

Dies ist die Stelle, an der die Invariante ``orchestrator-consumes-decisions``
zur Codestruktur wird. Der Executor tut genau vier Dinge:

1. Er fragt die **Policy Engine** — und liest ihr Ergebnis, statt es zu deuten.
2. Er reicht ``CONFIRM`` an das **Approval Gateway** weiter.
3. Er lässt sich vom **Ausführungs-Gate** einen ``ExecutionGrant`` geben.
4. Er schreibt Zustand, Kontamination, Datenklasse und Verbrauch fort.

Was er nicht tut, ist der eigentliche Entwurf: Er hat keinen Zweig, der ohne
Grant ausführt, keine Bedingung der Form „das wurde doch gerade bestätigt“ und
keinen Aufruf von ``PolicyDecision.allow()``. Ein AST-Test prüft das am
Quelltext, weil eine Absicht, die nur im Kopf des Autors steht, beim nächsten
Feature verloren geht.

**Die Policy wird zweimal gefragt**, einmal hier und einmal im Gate. Das ist
keine Redundanz aus Versehen: Die erste Antwort steuert den Ablauf (Vorschau
anzeigen oder direkt ausführen), die zweite unmittelbar vor dem Aufruf ist die
verbindliche. Zwischen beiden kann ein Recht entzogen worden sein.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from jarvis_contracts import (
    ApprovalChannel,
    DataClass,
    PendingAction,
    PolicyDecision,
    PolicyEffect,
    PolicyRequest,
    Run,
    RunStatus,
    SanitizedPayload,
    StepOutcome,
    TaintLevel,
    ToolResult,
    ToolSpec,
    escalate,
)
from jarvis_core.audit.chain import AuditEntry, AuditSink
from jarvis_core.orchestrator.budget import BudgetTracker, utc_now
from jarvis_core.policy.approval import ApprovalGateway, ExecutionDenied, ExecutionGrant
from jarvis_core.policy.engine import PolicyEngine
from jarvis_core.runs.fsm import assert_transition
from jarvis_core.tools.registry import ToolRegistry

__all__ = ["StepExecution", "StepStatus", "ToolExecutor"]


StepStatus = Literal[
    "executed",
    "awaiting_confirmation",
    "blocked",
    "failed",
    "budget_exceeded",
]


class StepExecution(BaseModel):
    """Ergebnis eines Ausführungsschritts.

    Trägt den fortgeschriebenen ``Run`` statt ihn zu mutieren: Der vorherige
    Zustand bleibt für das Aktivitätsprotokoll erhalten, und der Aufrufer kann
    nicht versehentlich mit einem halb aktualisierten Lauf weiterarbeiten.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    status: StepStatus
    run: Run
    reason: str
    decision: PolicyDecision | None = None
    result: ToolResult | None = None
    pending: PendingAction | None = None
    code: str | None = None
    """Fehlerkennung des Ausführungs-Gates, z. B. ``payload-mismatch``."""

    @property
    def executed(self) -> bool:
        return self.status == "executed"


class ToolExecutor:
    """Führt einzelne Werkzeugschritte eines Laufs aus."""

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        policy: PolicyEngine,
        gateway: ApprovalGateway,
        audit: AuditSink | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._gateway = gateway
        self._audit = audit
        self._clock = clock

    # -- Regulärer Schritt ------------------------------------------------
    async def execute_tool(
        self,
        run: Run,
        tracker: BudgetTracker,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        seq: int,
        session_id: UUID,
        channel: ApprovalChannel = "ui",
        allowed_data_class: DataClass | None = None,
        agent_name: str | None = None,
    ) -> StepExecution:
        """Ein Werkzeugschritt: fragen, gegebenenfalls bestätigen lassen, ausführen."""
        now = self._clock()

        limit = tracker.exceeded()
        if limit is not None:
            # Vor dem Schritt geprüft, nicht danach: Ein Budget, das erst nach
            # der Überschreitung auffällt, hat den teuren Aufruf schon bezahlt.
            return StepExecution(
                status="budget_exceeded",
                run=self._advance(run, RunStatus.BUDGET_EXCEEDED, tracker),
                reason=limit,
            )

        spec = self._registry.require(tool_name)
        request = self._policy_request(
            run,
            tool_name=tool_name,
            arguments=arguments,
            allowed_data_class=allowed_data_class,
            agent_name=agent_name,
        )
        decision = await self._policy.decide(request, taint=run.taint_level, now=now)

        if decision.effect is PolicyEffect.DENY:
            await self._log(run, "tool.denied", tool_name, {"reason": decision.reason}, now)
            return StepExecution(
                status="blocked",
                run=self._with_usage(run, tracker),
                reason=decision.reason,
                decision=decision,
            )

        if decision.effect is PolicyEffect.CONFIRM:
            return await self._request_confirmation(
                run,
                tracker,
                spec=spec,
                arguments=arguments,
                decision=decision,
                session_id=session_id,
                channel=channel,
                now=now,
            )

        try:
            grant = await self._gateway.authorize_allowed(
                request=request,
                spec=spec,
                taint=run.taint_level,
                invocation_id=uuid4(),
                now=now,
            )
        except ExecutionDenied as denied:
            # Zwischen der ersten Prüfung und dem Gate hat sich die Lage
            # geändert. Der Rückgabewert sagt „blockiert“ — ausgeführt wurde
            # nichts, und es gibt in dieser Methode keinen Weg, das nachzuholen.
            await self._log(run, "tool.gate_denied", tool_name, {"code": denied.code}, now)
            return StepExecution(
                status="blocked",
                run=self._with_usage(run, tracker),
                reason=denied.reason,
                decision=decision,
                code=denied.code,
            )

        return await self._run_grant(
            run, tracker, spec=spec, grant=grant, seq=seq, decision=decision, now=now
        )

    # -- Fortsetzung nach Bestätigung -------------------------------------
    async def resume_after_approval(
        self,
        run: Run,
        tracker: BudgetTracker,
        *,
        action_id: UUID,
        arguments: dict[str, Any],
        tool_name: str,
        seq: int,
        allowed_data_class: DataClass | None = None,
    ) -> StepExecution:
        """Führt einen bestätigten Aufruf aus — nach erneuter Prüfung im Gate.

        Die Bindung an ``state.awaiting_action_id`` ist eine eigene Prüfung:
        Ohne sie ließe sich ein Lauf mit der Bestätigung eines *anderen* Laufs
        fortsetzen. Beide gehören demselben Nutzer, beide Nonces sind gültig —
        die Verwechslung wäre also nicht an den Bindungen des Gateways
        erkennbar, sondern nur hier.
        """
        now = self._clock()

        if run.state.awaiting_action_id != action_id:
            return StepExecution(
                status="blocked",
                run=run,
                reason="Diese Bestätigung gehört nicht zu dem Vorgang, der hier wartet.",
                code="approval-run-mismatch",
            )

        spec = self._registry.require(tool_name)
        try:
            grant = await self._gateway.authorize_execution(
                action_id=action_id,
                arguments=arguments,
                spec=spec,
                taint=run.taint_level,
                allowed_data_class=allowed_data_class or run.data_class,
                now=now,
            )
        except ExecutionDenied as denied:
            await self._log(run, "tool.gate_denied", tool_name, {"code": denied.code}, now)
            return StepExecution(
                status="blocked",
                run=self._advance(run, RunStatus.FAILED, tracker),
                reason=denied.reason,
                code=denied.code,
            )

        executing = self._advance(run, RunStatus.EXECUTING, tracker)
        cleared = executing.model_copy(
            update={"state": executing.state.model_copy(update={"awaiting_action_id": None})}
        )
        return await self._run_grant(
            cleared, tracker, spec=spec, grant=grant, seq=seq, decision=None, now=now
        )

    # -- Sanierter Lauf ---------------------------------------------------
    def sanitized_run(self, origin: Run, payload: SanitizedPayload) -> Run:
        """Erzeugt den sauberen Lauf zu einem bestätigten Payload.

        Vier Eigenschaften machen das Gate zur Ergänzung des Taint-Schutzes
        statt zu seiner Umgehung (docs/16-v1.1-review.md §1):

        * Der Lauf startet ``CLEAN`` — sonst wäre er nur eine Umbenennung.
        * ``conversation_id`` bleibt leer: kein Kontext aus dem Herkunftslauf,
          auch keine Zusammenfassung. Sonst reiste der Fremdinhalt mit.
        * Er führt genau den eingefrorenen Aufruf aus; geplant wird nicht.
        * ``sanitized_from_run_id`` erhält die Spur im Audit.

        Das Budget wird vom Herkunftslauf übernommen: Ein sanierter Lauf ist
        die Fortsetzung derselben Absicht und darf nicht das Mittel sein, ein
        erschöpftes Budget zurückzusetzen.
        """
        return Run(
            id=uuid4(),
            user_id=origin.user_id,
            conversation_id=None,
            trigger=origin.trigger,
            status=RunStatus.QUEUED,
            taint_level=TaintLevel.CLEAN,
            data_class=origin.data_class,
            budget=origin.budget,
            usage=origin.usage,
            trace_id=origin.trace_id,
            started_at=self._clock(),
            sanitized_from_run_id=payload.origin_run_id,
        )

    def start(self, run: Run, tracker: BudgetTracker) -> Run:
        """Bringt einen Lauf von ``queued`` in die Ausführung.

        Der Zustand ``planning`` wird auch dann durchlaufen, wenn nichts zu
        planen ist (sanierter Lauf). Ein zusätzlicher Übergang
        ``queued → executing`` wäre bequemer, gälte aber für *alle* Läufe und
        machte die Planungsstufe damit optional — die Übergangstabelle bliebe
        zurück, ohne dass es jemandem auffiele.
        """
        planning = self._advance(run, RunStatus.PLANNING, tracker)
        return self._advance(planning, RunStatus.EXECUTING, tracker)

    # -- Innere Schritte --------------------------------------------------
    async def _request_confirmation(
        self,
        run: Run,
        tracker: BudgetTracker,
        *,
        spec: ToolSpec,
        arguments: dict[str, Any],
        decision: PolicyDecision,
        session_id: UUID,
        channel: ApprovalChannel,
        now: datetime,
    ) -> StepExecution:
        if decision.preview is None:  # pragma: no cover - vom Vertrag ausgeschlossen
            raise RuntimeError("CONFIRM ohne Vorschau — der Vertrag schließt das aus.")

        pending = await self._gateway.request(
            spec=spec,
            arguments=arguments,
            preview=decision.preview,
            reason=decision.reason,
            run_id=run.id,
            invocation_id=uuid4(),
            user_id=run.user_id,
            session_id=session_id,
            channel=channel,
            now=now,
        )
        waiting = self._advance(run, RunStatus.AWAITING_CONFIRMATION, tracker)
        waiting = waiting.model_copy(
            update={"state": waiting.state.model_copy(update={"awaiting_action_id": pending.id})}
        )
        await self._log(
            run, "tool.confirmation_requested", spec.name, {"action": str(pending.id)}, now
        )
        return StepExecution(
            status="awaiting_confirmation",
            run=waiting,
            reason=decision.reason,
            decision=decision,
            pending=pending,
        )

    async def _run_grant(
        self,
        run: Run,
        tracker: BudgetTracker,
        *,
        spec: ToolSpec,
        grant: ExecutionGrant,
        seq: int,
        decision: PolicyDecision | None,
        now: datetime,
    ) -> StepExecution:
        """Führt aus und schreibt die Folgen fort.

        Die Reihenfolge ist bedeutungstragend: Kontamination wird gesetzt,
        *bevor* der nächste Schritt entscheiden kann. Ein Ergebnis, das
        Fremdinhalt eingebracht hat, darf den folgenden Aufruf nicht mehr in
        einem sauberen Lauf antreffen.
        """
        tracker.record_tool_call()
        try:
            result = await self._registry.execute(grant)
        except Exception as error:
            # Breit gefangen mit Absicht: Ein Werkzeug, das mit einer
            # unerwarteten Ausnahme abbricht, darf den Lauf nicht mitreißen —
            # aber sein Fehler wird benannt und nicht in ein Ergebnis
            # umgedeutet (docs/04-orchestrator.md §9).
            tracker.record_step()
            await self._log(run, "tool.failed", spec.name, {"error": str(error)}, now)
            return StepExecution(
                status="failed",
                run=self._with_usage(run, tracker),
                reason=f"{spec.name} ist gescheitert: {error}",
                decision=decision,
            )

        tracker.record_step()
        taint = TaintLevel.TAINTED if _taints(spec, result) else TaintLevel.CLEAN
        updated = run.with_taint(taint).model_copy(
            update={
                "data_class": escalate(run.data_class, result.produced_data_class),
                "state": run.state.with_step_done(
                    StepOutcome(
                        seq=seq,
                        ok=result.ok,
                        summary=result.display or spec.name,
                        finished_at=now,
                    )
                ),
                "usage": tracker.usage,
            }
        )
        await self._log(
            updated,
            "tool.executed" if result.ok else "tool.failed",
            spec.name,
            {"ok": result.ok, "taints": taint.is_tainted},
            now,
        )
        return StepExecution(
            status="executed" if result.ok else "failed",
            run=updated,
            reason=result.display or ("Ausgeführt." if result.ok else (result.error or "Fehler.")),
            decision=decision,
            result=result,
        )

    # -- Hilfsmittel ------------------------------------------------------
    @staticmethod
    def _policy_request(
        run: Run,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        allowed_data_class: DataClass | None,
        agent_name: str | None,
    ) -> PolicyRequest:
        """Baut die Anfrage **aus dem Lauf**, nicht aus einer Modellausgabe.

        ``trigger`` und ``allowed_data_class`` sind die beiden Felder, mit
        denen sich die Prüfung mildern ließe: Ein als ``user`` ausgegebener
        nächtlicher Automationslauf umginge die strengere Behandlung
        unbeaufsichtigter Auslöser. Beide stammen deshalb ausschließlich aus
        dem persistierten ``Run``.
        """
        return PolicyRequest(
            user_id=run.user_id,
            run_id=run.id,
            tool_name=tool_name,
            arguments=arguments,
            trigger=run.trigger.value,
            allowed_data_class=allowed_data_class or run.data_class,
            agent_name=agent_name,
        )

    def _advance(self, run: Run, target: RunStatus, tracker: BudgetTracker) -> Run:
        assert_transition(run.status, target)
        return run.model_copy(update={"status": target, "usage": tracker.usage})

    @staticmethod
    def _with_usage(run: Run, tracker: BudgetTracker) -> Run:
        return run.model_copy(update={"usage": tracker.usage})

    async def _log(
        self,
        run: Run,
        action: str,
        resource: str,
        details: dict[str, Any],
        now: datetime,
    ) -> None:
        """Schreibt in die Audit-Kette, sofern eine Senke konfiguriert ist.

        Ohne Senke läuft das System weiter — die Postgres-Implementierung
        entsteht mit der API. Der Aufrufpunkt steht schon hier, weil ein
        nachträglich eingezogener Audit-Pfad erfahrungsgemäß Lücken hat.
        """
        if self._audit is None:
            return
        await self._audit.append(
            AuditEntry(
                occurred_at=now,
                actor="jarvis",
                action=action,
                resource=resource,
                details=details,
                trace_id=run.trace_id,
                user_id=run.user_id,
            )
        )


def _taints(spec: ToolSpec, result: ToolResult) -> bool:
    """Zwei Quellen der Kontamination, beide zählen.

    ``reads_untrusted_content`` ist die statische Erklärung des Werkzeugs,
    ``taints_context`` die Aussage über dieses konkrete Ergebnis. Eine Oder-
    Verknüpfung ist hier richtig: Ein Werkzeug, das sich als harmlos deklariert
    hat, aber Fremdinhalt zurückgibt, kontaminiert trotzdem — und ein Werkzeug,
    das als Leser deklariert ist, kontaminiert auch dann, wenn es diesmal
    nichts gefunden hat. Die Alternative wäre, dem Ergebnis zu vertrauen; das
    Ergebnis ist aber genau das, was ein Angreifer beeinflusst.
    """
    return spec.reads_untrusted_content or result.taints_context
