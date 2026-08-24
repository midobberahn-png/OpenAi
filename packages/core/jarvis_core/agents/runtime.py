"""Agent Runtime — Delegation mit Least Privilege.

Siehe docs/06-agenten-tools.md §1 und §5.

Zwei Invarianten werden hier durchgesetzt, und beide betreffen den Weg über
mehrere Stufen:

* ``agent-chain-preserves-capability-binding`` — über A → B → C bleibt die
  Rechtemenge die Schnittmenge aller Beteiligten mit den Nutzerrechten.
* ``agent-chain-propagates-taint`` — liest eine Stufe Fremdinhalt, gilt der
  gesamte Lauf als kontaminiert.

Die zweite ist die heiklere, und zwar wegen einer Eigenschaft, die auf den
ersten Blick harmlos aussieht: ``AgentResult.taint_acquired`` ist ein Feld,
das der Sub-Agent selbst füllt — und ein Sub-Agent wird von einem Modell
gesteuert, das Fremdinhalt gelesen haben kann. Würde die Runtime dieses Feld
als Wahrheit nehmen, wäre eine Zwischenstufe genau die Waschmaschine, die der
Taint-Schutz ausschließen soll: B liest die Mail, meldet „sauber“ nach oben,
A sendet.

Deshalb ist die Quelle der Wahrheit der **Lauf**, nicht das Ergebnis. Der
Sub-Agent führt Werkzeuge über denselben Executor aus, der den Lauf
kontaminiert; was er darüber behauptet, kann die Kontamination nur *erhöhen*,
nie aufheben.

Ein Sprachmodell kommt in diesem Modul nicht vor. Was ein Agent denkt, steckt
hinter ``AgentBehaviour`` und kommt mit dem LLM-Provider; was er *darf*, steht
hier — und ist deshalb schon jetzt prüfbar.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from jarvis_contracts import (
    AgentRequest,
    AgentResult,
    AgentSpec,
    AgentStatus,
    ApprovalChannel,
    ContextBundle,
    Run,
    RunBudget,
    TaintLevel,
)
from jarvis_core.agents.chain import AgentChain
from jarvis_core.agents.registry import AgentRegistry
from jarvis_core.orchestrator.budget import BudgetTracker
from jarvis_core.orchestrator.executor import StepExecution, ToolExecutor
from jarvis_core.policy.engine import PolicyEngine
from jarvis_core.tools.registry import ToolRegistry

__all__ = [
    "AgentBehaviour",
    "AgentRuntime",
    "AgentSession",
    "DelegationDenied",
    "DelegationOutcome",
]


class DelegationDenied(Exception):
    """Eine Delegation ist strukturell unzulässig.

    Ausnahme statt Rückgabewert, weil es keinen sinnvollen Fortsetzungspfad
    gibt: Wer ohne ``can_delegate`` delegiert oder eine Rekursion baut, hat
    einen Fehler im Ablauf, keinen ungünstigen Zustand.
    """


class AgentSession:
    """Der Handlungsrahmen eines Sub-Agenten.

    Hält den fortgeschriebenen Lauf und die Werkzeugmenge, die dieser Kette
    zusteht. Veränderlich, anders als die Verträge ringsum: Der Lauf wandert
    durch mehrere Werkzeugaufrufe, und jeder von ihnen kann ihn kontaminieren.
    Genau dieses Mitwandern ist der Mechanismus — nach dem ersten Lesen von
    Fremdinhalt sieht der nächste Aufruf einen kontaminierten Lauf.
    """

    def __init__(
        self,
        *,
        executor: ToolExecutor,
        run: Run,
        tracker: BudgetTracker,
        chain: AgentChain,
        tools: Callable[[Run], Awaitable[frozenset[str]]],
        session_id: UUID | None,
        channel: ApprovalChannel = "ui",
    ) -> None:
        self._executor = executor
        self._run = run
        self._tracker = tracker
        self._chain = chain
        # Eine **Funktion**, kein Set. Der Unterschied ist der ganze Punkt:
        # Nach einem Werkzeug, das Fremdinhalt gelesen hat, ist der Lauf
        # kontaminiert und die zulässige Menge kleiner. Ein einmal berechnetes
        # Set würde in der nächsten Runde das Angebot von vorhin anbieten — und
        # genau darauf zielt ein Angreifer, der eine Mail unterschiebt.
        self._tools = tools
        self._session_id = session_id
        """``None`` heißt: kein Bestätigungskanal — der Arbeiter, der einen
        hängengebliebenen Lauf fortsetzt, hat keine Sitzung. Ein Vorschlag, der
        eine Bestätigung braucht, wird dann abgewiesen, statt eine Anfrage zu
        erzeugen, die niemand einlösen könnte."""
        self._channel = channel

    @property
    def run(self) -> Run:
        return self._run

    async def current_tools(self) -> frozenset[str]:
        """Was dieser Agent **jetzt** aufrufen darf.

        Bewusst eine Methode und keine Eigenschaft: Der Wert ändert sich im
        Verlauf eines Laufs, und eine Eigenschaft lädt dazu ein, ihn einmal zu
        lesen und weiterzuverwenden. Was hier fehlt, sieht das Modell nicht —
        und was es nicht sieht, kann es nicht vorschlagen.
        """
        return await self._tools(self._run)

    @property
    def chain(self) -> AgentChain:
        return self._chain

    async def call_tool(self, name: str, arguments: dict[str, Any], *, seq: int) -> StepExecution:
        """Werkzeugaufruf innerhalb der Kettenrechte.

        Die Prüfung hier **verengt nur**: Sie kann einen Aufruf verhindern,
        aber keinen erlauben. Was sie durchlässt, geht anschließend durch die
        Policy Engine und das Ausführungs-Gate wie jeder andere Aufruf auch —
        die Kettenrechte sind eine zusätzliche Schranke, kein Ersatz.

        Nötig ist sie, weil die Policy Engine die Agenten-Whitelists nicht
        kennt: Sie prüft, was der *Nutzer* erlaubt hat. Ohne diese Stelle
        bekäme ein Sub-Agent alles, was der Nutzer erteilt hat — und die
        Spezialisierung wäre keine Sicherheitsgrenze mehr, sondern Dekoration.
        """
        if name not in await self.current_tools():
            return StepExecution(
                status="blocked",
                run=self._run,
                reason=(
                    f"„{name}“ liegt außerhalb der Rechte dieser Agentenkette "
                    f"({' → '.join(self._chain.names)})."
                ),
                code="outside-chain-capabilities",
            )

        outcome = await self._executor.execute_tool(
            self._run,
            self._tracker,
            tool_name=name,
            arguments=arguments,
            seq=seq,
            session_id=self._session_id,
            channel=self._channel,
            agent_name=self._chain.current.name,
        )
        self._run = outcome.run
        return outcome


class AgentBehaviour(Protocol):
    """Was ein Agent mit seinem Handlungsrahmen anfängt.

    Bewusst ein Protokoll: Hier sitzt später die Modellschleife. Dass sie noch
    fehlt, hindert nicht daran, die Rechte- und Kontaminationsmechanik zu
    prüfen — im Gegenteil, sie lässt sich ohne Modell überhaupt erst
    deterministisch prüfen.
    """

    async def act(self, session: AgentSession, request: AgentRequest) -> AgentResult: ...


class DelegationOutcome(BaseModel):
    """Ergebnis einer Delegation."""

    model_config = ConfigDict(frozen=True)

    result: AgentResult
    run: Run
    """Der fortgeschriebene Lauf — Träger der Kontamination."""

    chain: AgentChain
    granted_tools: frozenset[str]

    @property
    def tainted(self) -> bool:
        return self.run.taint_level.is_tainted


class AgentRuntime:
    """Supervisor-Seite der Delegation."""

    def __init__(
        self,
        *,
        agents: AgentRegistry,
        tools: ToolRegistry,
        policy: PolicyEngine,
        executor: ToolExecutor,
    ) -> None:
        self._agents = agents
        self._tools = tools
        self._policy = policy
        self._executor = executor

    async def effective_tools(self, chain: AgentChain, run: Run) -> frozenset[str]:
        """Werkzeugmenge einer Kette in diesem Lauf.

        Zwei Verengungen, die getrennt bleiben müssen: Die Kettenschnittmenge
        kommt aus den Whitelists, die Rechteprüfung aus der Policy Engine. Die
        Runtime bildet die Kandidatenmenge und lässt *die Engine* entscheiden,
        was davon übrig bleibt — eine eigene Rechteprüfung hier wäre die
        zweite Wahrheit über Berechtigungen.
        """
        candidates = chain.capability_ceiling()
        if not candidates:
            return frozenset()
        allowed = await self._policy.effective_tools(
            run.user_id, set(candidates), taint=run.taint_level
        )
        return frozenset(allowed)

    async def delegate(
        self,
        *,
        chain: AgentChain,
        target: str,
        task: str,
        run: Run,
        tracker: BudgetTracker,
        behaviour: AgentBehaviour,
        session_id: UUID | None,
        context: ContextBundle | None = None,
        budget: RunBudget | None = None,
    ) -> DelegationOutcome:
        """Delegiert an einen Sub-Agenten und führt die Folgen nach oben zurück."""
        caller = chain.current
        if not caller.can_delegate:
            raise DelegationDenied(
                f"Agent „{caller.name}“ darf nicht delegieren. Delegation ist ein Recht, "
                "das ausdrücklich erteilt wird — sonst könnte jeder Agent sich einen "
                "Helfer mit anderen Rechten holen."
            )

        spec = self._agents.require(target)
        if chain.contains(target):
            raise DelegationDenied(
                f"Agent „{target}“ ist bereits in der Kette ({' → '.join(chain.names)}). "
                "Eine Rekursion liefe mit vollem Budget weiter."
            )

        extended = chain.extend(spec)
        limit = (budget or run.budget).max_agent_depth
        if extended.depth > limit:
            raise DelegationDenied(
                f"Delegationstiefe {extended.depth} überschreitet die Grenze {limit}."
            )

        granted = await self.effective_tools(extended, run)
        request = AgentRequest(
            task=task,
            context=context or ContextBundle(budget=0),
            budget=(budget or run.budget).split(2),
            parent_run_id=run.id,
            depth=extended.depth,
            inherited_taint=run.taint_level,
        )

        session = AgentSession(
            executor=self._executor,
            run=run,
            tracker=tracker,
            chain=extended,
            # Die Menge wird bei jedem Zugriff neu bestimmt — aus dem Lauf, wie
            # er *jetzt* ist, nicht wie er beim Start war.
            tools=lambda aktueller: self.effective_tools(extended, aktueller),
            session_id=session_id,
        )
        result = await behaviour.act(session, request)

        # Der Lauf aus der Session ist die Wahrheit über die Kontamination: Er
        # trägt, was tatsächlich ausgeführt wurde. Die Selbstauskunft des
        # Agenten kommt hinzu — sie kann erhöhen, nie senken. Ein Sub-Agent,
        # der „sauber“ meldet, nachdem er eine Mail gelesen hat, ändert damit
        # nichts.
        claimed = TaintLevel.TAINTED if result.taint_acquired else TaintLevel.CLEAN
        final_run = session.run.with_taint(claimed)
        tracker.absorb(result.usage)

        return DelegationOutcome(
            result=result,
            run=final_run.model_copy(update={"usage": tracker.usage}),
            chain=extended,
            granted_tools=granted,
        )

    @staticmethod
    def failed(reason: str) -> AgentResult:
        """Einheitliches Fehlerergebnis — Fehler werden benannt, nicht gedeutet."""
        return AgentResult(status=AgentStatus.FAILED, error=reason, output="")

    def spec(self, name: str) -> AgentSpec:
        return self._agents.require(name)
