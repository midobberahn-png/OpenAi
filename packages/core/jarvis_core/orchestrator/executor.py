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
    InvocationStatus,
    PendingAction,
    PolicyDecision,
    PolicyEffect,
    PolicyRequest,
    Run,
    RunStatus,
    SanitizedPayload,
    StepOutcome,
    TaintLevel,
    ToolInvocation,
    ToolResult,
    ToolSpec,
    escalate,
)
from jarvis_core.audit.chain import AuditEntry, AuditSink
from jarvis_core.orchestrator.budget import BudgetTracker, utc_now
from jarvis_core.orchestrator.plan_context import modellsicht
from jarvis_core.policy.approval import ApprovalGateway, ExecutionDenied, ExecutionGrant
from jarvis_core.policy.engine import PolicyEngine
from jarvis_core.ports.invocations import InvocationStore
from jarvis_core.runs.fsm import assert_transition
from jarvis_core.tools.arguments import ArgumentsRejected, validate_arguments
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
        invocations: InvocationStore | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._gateway = gateway
        self._audit = audit
        self._invocations = invocations
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

        # Vor allem anderen: Passen die Argumente zum Schema des Werkzeugs?
        #
        # Diese Prüfung steht hier und nicht später, weil ab hier alles von den
        # Argumenten abhängt. ``decide()`` liest sie für das Taint-Gate, die
        # Vorschau zeigt sie einem Menschen, der Payload-Hash bindet sie an die
        # Ausführung, der Handler bekommt sie ausgepackt. Eine Prüfung hinter
        # einer dieser Stellen prüfte etwas, das schon gewirkt hat.
        #
        # Solange ein Mensch die Argumente tippte, war das Schema eine Ansage
        # nach außen, die niemand verletzte. Ab der Modellschleife formuliert
        # sie ein Modell, das eine kontaminierte Datei gelesen haben kann —
        # und ein erfundenes Feld erschiene in der Vorschau als Zeile, als
        # gehörte es zur Aktion.
        #
        # Kein Protokolleintrag: Es gibt keine Entscheidung, die festzuhalten
        # wäre, und kein Aufruf hat stattgefunden. Was geschah, steht im
        # Aktivitätsprotokoll.
        try:
            arguments = validate_arguments(spec, arguments)
        except ArgumentsRejected as unpassend:
            await self._log(run, "tool.rejected", tool_name, {"reason": str(unpassend)}, now)
            return StepExecution(
                status="blocked",
                run=self._with_usage(run, tracker),
                reason=str(unpassend),
                code="arguments-invalid",
            )

        request = self._policy_request(
            run, tool_name=tool_name, arguments=arguments, agent_name=agent_name
        )
        decision = await self._policy.decide(request, taint=run.taint_level, now=now)

        # Der Aufruf wird festgehalten, sobald die Entscheidung feststeht — vor
        # jeder Wirkung. Ein Aufruf, der erst nach seiner Ausführung
        # protokolliert wird, fehlt genau dann, wenn er abgestürzt ist.
        invocation_id = uuid4()
        await self._record(run, spec, arguments, decision, invocation_id, now)

        if decision.effect is PolicyEffect.DENY:
            await self._mark(invocation_id, InvocationStatus.BLOCKED, decision.reason)
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
                invocation_id=invocation_id,
                now=now,
            )

        try:
            grant = await self._gateway.authorize_allowed(
                request=request,
                spec=spec,
                taint=run.taint_level,
                invocation_id=invocation_id,
                now=now,
            )
        except ExecutionDenied as denied:
            # Zwischen der ersten Prüfung und dem Gate hat sich die Lage
            # geändert. Der Rückgabewert sagt „blockiert“ — ausgeführt wurde
            # nichts, und es gibt in dieser Methode keinen Weg, das nachzuholen.
            await self._mark(invocation_id, InvocationStatus.BLOCKED, denied.reason)
            await self._log(run, "tool.gate_denied", tool_name, {"code": denied.code}, now)
            return StepExecution(
                status="blocked",
                run=self._with_usage(run, tracker),
                reason=denied.reason,
                decision=decision,
                code=denied.code,
            )

        return await self._run_grant(
            run,
            tracker,
            spec=spec,
            grant=grant,
            seq=seq,
            decision=decision,
            invocation_id=invocation_id,
            now=now,
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
                run_id=run.id,
                allowed_data_class=_ceiling(run),
                sanitized_from_run_id=run.sanitized_from_run_id,
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

        # Zwei Fälle laufen hier zusammen, und nur einer davon wartet:
        # Der pausierte Lauf steht auf ``awaiting_confirmation`` und wird
        # fortgesetzt; der sanierte Lauf ist ein neuer Lauf, der bereits
        # ausführt und nie gewartet hat. Ein unbedingter Übergang wäre für ihn
        # ``executing → executing`` — und der Zustandsautomat würde ihn
        # zurecht als Programmierfehler melden.
        executing = (
            run
            if run.status is RunStatus.EXECUTING
            else self._advance(run, RunStatus.EXECUTING, tracker)
        )
        cleared = executing.model_copy(
            update={"state": executing.state.model_copy(update={"awaiting_action_id": None})}
        )
        return await self._run_grant(
            cleared,
            tracker,
            spec=spec,
            grant=grant,
            seq=seq,
            decision=None,
            invocation_id=grant.invocation_id,
            now=now,
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

    def finish(self, run: Run, tracker: BudgetTracker) -> Run:
        """Bringt einen Lauf von ``executing`` in den Endzustand ``completed``.

        Das Gegenstück zu ``start()``, und bis zu diesem Commit hat es gefehlt:
        ``RunStatus.COMPLETED`` kam im gesamten Anwendungscode nicht vor. Jeder
        Lauf blieb in ``executing`` stehen. Aufgefallen ist das nicht, weil kein
        Plan abschließbar war — sein letzter Schritt ist stets ein
        ``llm``-Schritt, und der war nicht ausführbar.

        **Wann abgeschlossen wird, entscheidet der Executor nicht.** Das hängt
        am Plan, und den kennt er nicht; er kennt Werkzeugaufrufe. Der Aufrufer
        stellt fest, dass nichts mehr fällig ist, und sagt es hier.

        Der Weg führt über ``_advance`` und damit über die Übergangstabelle.
        Ein direktes Setzen des Status wäre kürzer und ließe den Automaten
        hinter sich: Ein wartender Lauf würde dann abgeschlossen, obwohl die
        Bestätigung noch offen ist.
        """
        fertig = self._advance(run, RunStatus.COMPLETED, tracker)
        return fertig.model_copy(update={"finished_at": self._clock()})

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
        invocation_id: UUID,
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
            invocation_id=invocation_id,
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
        invocation_id: UUID | None = None,
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
            result = await self._registry.execute(grant, run_id=run.id, user_id=run.user_id)
        except Exception as error:
            # Breit gefangen mit Absicht: Ein Werkzeug, das mit einer
            # unerwarteten Ausnahme abbricht, darf den Lauf nicht mitreißen —
            # aber sein Fehler wird benannt und nicht in ein Ergebnis
            # umgedeutet (docs/04-orchestrator.md §9).
            tracker.record_step()
            await self._mark(invocation_id, InvocationStatus.FAILED, str(error))
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
                        # Was ein Modell im nächsten Schritt lesen darf —
                        # deklariert, gekappt, ausgezeichnet. Hier und nicht
                        # beim Rendern, weil dafür sonst das rohe Ergebnis in
                        # der Laufpersistenz liegen müsste: bei ``files.read``
                        # bis 256.000 Bytes untypisierter Fremddaten je Lauf.
                        model_view=modellsicht(spec, result),
                        finished_at=now,
                    )
                ),
                "usage": tracker.usage,
            }
        )
        await self._mark(
            invocation_id,
            InvocationStatus.EXECUTED if result.ok else InvocationStatus.FAILED,
            result.error,
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
        agent_name: str | None,
    ) -> PolicyRequest:
        """Baut die Anfrage **aus dem Lauf**, nicht aus einer Modellausgabe.

        ``trigger`` und ``allowed_data_class`` sind die beiden Felder, mit
        denen sich die Prüfung mildern ließe: Ein als ``user`` ausgegebener
        nächtlicher Automationslauf umginge die strengere Behandlung
        unbeaufsichtigter Auslöser, und eine hochgesetzte Obergrenze ließe
        P3-Werkzeuge in einem Kontext zu, der dafür nicht geroutet wurde.

        Beide sind deshalb **keine Parameter**. Ein früherer Entwurf nahm
        ``allowed_data_class`` entgegen — bequem, aber damit bestimmte der
        Aufrufer seine eigene Obergrenze, und eine selbst gewählte Obergrenze
        ist keine. Ein Strukturtest hält fest, dass ``PolicyRequest`` im
        gesamten Orchestrator nur an dieser einen Stelle entsteht.
        """
        return PolicyRequest(
            user_id=run.user_id,
            run_id=run.id,
            tool_name=tool_name,
            arguments=arguments,
            trigger=run.trigger.value,
            allowed_data_class=_ceiling(run),
            agent_name=agent_name,
        )

    def _advance(self, run: Run, target: RunStatus, tracker: BudgetTracker) -> Run:
        assert_transition(run.status, target)
        return run.model_copy(update={"status": target, "usage": tracker.usage})

    @staticmethod
    def _with_usage(run: Run, tracker: BudgetTracker) -> Run:
        return run.model_copy(update={"usage": tracker.usage})

    async def _record(
        self,
        run: Run,
        spec: ToolSpec,
        arguments: dict[str, Any],
        decision: PolicyDecision,
        invocation_id: UUID,
        now: datetime,
    ) -> None:
        """Hält den Aufruf mitsamt Entscheidung fest.

        Ohne Speicher passiert nichts — die Unit-Suite läuft ohne Datenbank.
        In der Anwendung ist der Eintrag Voraussetzung für jede Bestätigung:
        ``pending_actions.invocation_id`` verweist auf ihn.
        """
        if self._invocations is None:
            return
        await self._invocations.record(
            ToolInvocation(
                id=invocation_id,
                run_id=run.id,
                tool_name=spec.name,
                arguments=arguments,
                risk_level=spec.risk,
                policy_decision=decision.effect,
                decision_reason=decision.reason,
                created_at=now,
            )
        )

    async def _mark(
        self, invocation_id: UUID | None, status: InvocationStatus, error: str | None = None
    ) -> None:
        if self._invocations is None or invocation_id is None:
            return
        await self._invocations.mark(invocation_id, status, error=error)

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


def _ceiling(run: Run) -> DataClass:
    """Höchste Datenklasse, die in diesem Lauf verarbeitet werden darf.

    Quelle ist die Routing-Entscheidung: Sie hält fest, was das *tatsächlich
    gewählte* Modell führen darf. Ohne Routing — ein Lauf, der noch nicht
    geroutet wurde — gilt die Klasse des Laufs selbst. Das ist die engere
    Annahme: Ein Werkzeug oberhalb der bisherigen Laufklasse wird dann
    abgelehnt, statt auf Verdacht zugelassen.
    """
    if run.routing is not None:
        return run.routing.max_data_class
    return run.data_class


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
