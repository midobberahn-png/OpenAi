"""Einen Planschritt ausführen — der Ablauf, ohne HTTP.

Diese Datei ist die Antwort auf einen Clean-Code-Befund aus einer externen
Prüfung, und der Befund war kein Stilhinweis. Die Ablaufsteuerung lag in der
Routendatei und war dort auf HTTP-Modelle, Dependency-Injection,
Fehlerübersetzung und Ansichtsaufbau verteilt. Genau an dieser Grenze sind
**zwei** Sicherheitslücken entstanden, kurz nacheinander:

* Der Anspruch auf den Schritt stand hinter der Wirkung statt davor.
* Nachdem er davor stand, gab ein ``except`` ihn nach der Wirkung wieder frei.

Beide Male war die Ursache dieselbe: Die Reihenfolge *Anspruch → Wirkung →
Festschreiben* war über eine Routenfunktion verteilt und ließ sich nicht an
einer Stelle überblicken. Hier steht sie an einer Stelle.

**Die Phasen sind der Zweck dieser Datei**, nicht ihre Kürze:

    ①  Auswählen      welcher Schritt ist fällig?          — folgenlos
    ②  Beanspruchen   atomar, committed, vor allem Weiteren
    ③  Vorbereiten    Argumente beschaffen                  — folgenlos
    ④  Wirken         Policy, Gate, Grant, Handler          — ab hier gilt es
    ⑤  Festschreiben  Lauf speichern, Anspruch freigeben

Freigegeben wird der Anspruch **nur** bei einem Fehler in ①–③. Ab ④ bleibt er
stehen, auch wenn ⑤ scheitert: Ist unklar, ob gewirkt wurde, ist ein stehender
Lauf die richtige Antwort. Ein Termin, der vielleicht fehlt, lässt sich erneut
anstoßen; einer, der zweimal im Kalender steht, nicht.

**Was hier ausdrücklich nicht passiert: entscheiden, ob etwas erlaubt ist.**
Diese Datei orchestriert. Ob ein Werkzeug laufen darf, entscheidet die Policy
Engine; ob eine Bestätigung nötig ist, ebenfalls; ob der Grant gilt, das Gate;
ob er noch frei ist, die Datenbank. Eine Prüfung hier wäre eine zweite
Wahrheit.

**Und kein HTTP.** Kein Statuscode, keine ``HTTPException``, kein
Request-Modell. Die Ausgänge sind ``AdvanceOutcome`` und ``AdvanceRejected``;
was daraus eine Antwort wird, entscheidet die Kante. Ein Kern, der 409 kennt,
ist ein Kern, der nur über HTTP benutzbar ist — und der Arbeiter, der
abgebrochene Läufe fortsetzt, spricht keins. Ein Schichttest hält das fest.
"""

from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from jarvis_contracts import (
    AgentResult,
    AgentStatus,
    ApprovalChannel,
    PendingAction,
    Plan,
    PlanStep,
    Run,
    RunStatus,
    StepOutcome,
    TaintLevel,
    ToolResult,
)
from jarvis_core.orchestrator.budget import BudgetTracker, utc_now
from jarvis_core.orchestrator.executor import StepStatus, ToolExecutor
from jarvis_core.orchestrator.plan_arguments import PlanArgumentSource
from jarvis_core.orchestrator.plan_context import PlanStepUnavailable
from jarvis_core.orchestrator.plan_response import PlanResponseSource
from jarvis_core.orchestrator.recovery import Recovery, RecoveryVerdict
from jarvis_core.policy.engine import PolicyEngine
from jarvis_core.ports.runs import RunStateConflict, RunStore
from jarvis_core.tools.registry import ToolRegistry

__all__ = ["AdvanceOutcome", "AdvanceRejected", "AgentStepRunner", "RunAdvancer"]


class AgentStepOutcome(Protocol):
    """Was ein Agentenschritt zurückgibt: ein Ergebnis und der Lauf dazu.

    Strukturell und nicht als Import: ``DelegationOutcome`` lebt bei den
    Agenten, und die Abhängigkeit zwischen den Paketen ist eine Einbahnstraße
    (``agents`` → ``orchestrator``). Ein Import in dieser Richtung schlösse den
    Kreis; ein Protokoll sagt dasselbe, ohne ihn zu schließen.
    """

    @property
    def result(self) -> AgentResult: ...

    @property
    def run(self) -> Run: ...


class AgentStepRunner(Protocol):
    """Wer einen ``agent``-Schritt ausführt.

    Erfüllt von ``jarvis_core.agents.plan_step.AgentStepSource``. Der Ablauf
    braucht davon nur, dass es ihn gibt und was er zurückgibt — welche
    Modellschleife dahinter steckt und mit welchen Rechten sie läuft, ist
    ausdrücklich nicht seine Frage.
    """

    async def for_step(
        self,
        *,
        step: PlanStep,
        run: Run,
        tracker: BudgetTracker,
        goal: str,
        session_id: UUID | None,
    ) -> AgentStepOutcome: ...


class AdvanceRejected(Exception):
    """Der Schritt kann nicht laufen — und es ist nichts geschehen.

    Ausdrücklich **keine** ``HTTPException``: Diese Schicht kennt keine
    Statuscodes. Sie liefert eine Kennung und einen Satz; welcher Code daraus
    wird, entscheidet die Kante.

    Die Kennung ist kein Ersatz für den Satz, sondern für die
    Zeichenkettenprüfung: Ein Aufrufer, der auf ``code`` schaut, bricht nicht,
    wenn jemand die Formulierung verbessert.
    """

    def __init__(self, code: str, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(f"[{code}] {reason}")


class AdvanceOutcome(BaseModel):
    """Was aus dem Schritt geworden ist.

    Trägt den fortgeschriebenen Lauf statt ihn zu mutieren — dieselbe
    Überlegung wie bei ``StepExecution``: Der Aufrufer soll nicht versehentlich
    mit einem halb aktualisierten Lauf weiterarbeiten.
    """

    model_config = ConfigDict(frozen=True)

    status: StepStatus
    run: Run
    reason: str
    display: str = ""
    """Beim Werkzeugschritt das Anzeigeergebnis, beim ``llm``-Schritt der
    formulierte Text. Beides ist für einen Menschen bestimmt und für keine
    Entscheidung."""

    result: ToolResult | None = None
    pending: PendingAction | None = None
    code: str | None = None


class RunAdvancer:
    """Führt den nächsten fälligen Schritt eines Plans aus.

    Die Abhängigkeiten kommen als Ports herein — ``RunStore`` und nicht
    ``PostgresRunStore``. Das ist nicht Geschmack: Der Anspruch auf einen
    Schritt ist eine Aussage über Atomarität und Dauerhaftigkeit, und die
    gehört in den Vertrag des Speichers, nicht in seine Postgres-Fassung. Wer
    hier eine konkrete Klasse verlangte, machte die Ablaufsteuerung an einer
    Datenbank fest, die sie nicht kennen muss.
    """

    def __init__(
        self,
        *,
        runs: RunStore,
        tools: ToolRegistry,
        policy: PolicyEngine,
        executor: ToolExecutor,
        arguments: PlanArgumentSource,
        responses: PlanResponseSource,
        agents: AgentStepRunner | None = None,
        recovery: Recovery | None = None,
        channel: ApprovalChannel = "ui",
    ) -> None:
        self._runs = runs
        self._tools = tools
        self._policy = policy
        self._executor = executor
        self._arguments = arguments
        self._responses = responses
        self._agents = agents
        """Ohne Agentenquelle bleibt ein ``agent``-Schritt abgewiesen — der
        Stand vor diesem Block. ``None`` ist deshalb kein Notbehelf, sondern
        die ehrliche Auskunft eines Aufrufers, der keinen Agentenkatalog hat."""

        self._recovery = recovery
        """Ohne Wiederaufnahme bleibt ein fremder Anspruch eine Sackgasse, und
        das ist der bisherige Stand: ``None`` heißt „ein beanspruchter Schritt
        wird abgewiesen, Punkt". Zulässig, weil es die Lage vor diesem Block
        ist und weil ein Aufrufer ohne Werkzeugprotokoll nichts nachsehen
        könnte — nicht zulässig ist, das Nachsehen zu erfinden."""

        self._channel = channel

    async def advance(
        self,
        lauf: Run,
        *,
        session_id: UUID | None,
        vorgegeben: dict[str, Any] | None,
    ) -> AdvanceOutcome:
        """Ein Schritt weiter.

        ``lauf`` kommt geladen und auf Zugehörigkeit geprüft herein. Das ist
        Absicht: *Wem* ein Lauf gehört, entscheidet die Kante aus der Sitzung —
        eine ``user_id`` als Parameter wäre dieselbe Lücke wie eine im
        Request-Body, nur eine Schicht tiefer.

        ``session_id=None`` ist der Arbeiter: ein Lauf, ein Eigentümer, **keine
        Sitzung**. Ein Schritt, der eine Bestätigung braucht, wird dann nicht
        ausgeführt und erzeugt auch keine — dazu ``ToolExecutor.execute_tool``.
        Die Zugehörigkeit ist damit nicht schwächer geprüft, sondern anders
        begründet: Der Arbeiter greift keinen Lauf auf, den ihm jemand genannt
        hat, sondern nur solche, die er selbst gefunden hat.
        """
        plan, schritt = self._faelliger_schritt(lauf)
        await self._pruefe_durchfuehrbar(lauf, schritt, vorgegeben)

        status_vorher = lauf.status

        # ② Beanspruchen — atomar und committed, bevor irgendetwas beginnt.
        #
        # Der Rückgabewert ist das Fencing-Token. Es wandert durch die ganze
        # Ausführung und begleitet jede Schreiboperation: Nur wer den Anspruch
        # *noch* hat, gibt ihn frei und schreibt sein Ergebnis. Ohne das wäre
        # der Anspruch eine Aussage über den Schritt, aber keine über den, der
        # ihn hält — und spätestens die Wiederaufnahme hängender Läufe erzeugt
        # zwei Anwärter auf denselben.
        anspruch = await self._runs.claim_step(
            lauf.id, schritt.seq, erwarteter_status=status_vorher
        )
        if anspruch is None:
            anspruch = await self._uebernehmen(lauf, schritt)

        tracker = BudgetTracker(lauf.budget, usage=lauf.usage)
        if lauf.status is RunStatus.QUEUED:
            # ``queued → planning → executing``: Der Zustandsautomat kennt
            # keinen direkten Weg, und das ist Absicht.
            lauf = self._executor.start(lauf, tracker)

        if schritt.kind == "agent":
            return await self._agent(
                lauf, tracker, plan, schritt, status_vorher, session_id, anspruch
            )
        if schritt.kind != "tool":
            return await self._antwort(lauf, tracker, plan, schritt, status_vorher, anspruch)
        return await self._werkzeug(
            lauf, tracker, plan, schritt, status_vorher, vorgegeben, session_id, anspruch
        )

    async def _uebernehmen(self, lauf: Run, schritt: PlanStep) -> UUID:
        """② b — der Anspruch gehört jemand anderem. Und jetzt?

        Bis hierher endete der Weg an dieser Stelle: „wird bereits ausgeführt",
        409, fertig. Das ist die richtige Antwort, solange der andere wirklich
        arbeitet — und die falsche, sobald er abgestürzt ist. Von außen sind
        die beiden nicht zu unterscheiden, und **genau deshalb** entscheidet
        das hier nicht der Ablauf, sondern die Wiederaufnahme: Sie hat die
        Frist und das Werkzeugprotokoll.

        Drei Ausgänge, und keiner davon wirkt:

        * **Übernommen** — die Frist war abgelaufen und das Protokoll schließt
          eine Wirkung aus. Der Rückgabewert ist das *neue* Fencing-Token; von
          hier an läuft der Schritt wie ein frisch beanspruchter.
        * **In Arbeit** — die Frist läuft. Abweisung wie bisher.
        * **Entscheidung nötig** — der Schritt hat möglicherweise gewirkt. Auch
          das ist eine Abweisung, aber eine andere, und sie trägt eine eigene
          Kennung: Ein Aufrufer, der ``step-unresolved`` sieht, weiß, dass
          Wiederholen hier nicht die Lösung ist.
        """
        if self._recovery is None:
            raise AdvanceRejected(
                "step-claimed",
                f"Schritt {schritt.seq} wird bereits ausgeführt oder der Lauf hat sich "
                "verändert. Neu laden und nachsehen, was daraus geworden ist.",
            )

        if lauf.state.current_step != schritt.seq:
            # Der offene Anspruch gilt einem *anderen* Schritt als dem, der
            # hier gleich laufen soll. Eine Übernahme brächte ein Token für
            # den falschen Schritt — und der Ablauf führte damit einen aus,
            # für den er keinen Anspruch hat. Der Fall ist selten (die Auswahl
            # nimmt den kleinsten fälligen Schritt), aber er ist nicht
            # unmöglich, sobald ein Plan verzweigt.
            raise AdvanceRejected(
                "step-claimed",
                f"Der Lauf steht bei Schritt {lauf.state.current_step} und nicht bei "
                f"{schritt.seq}. Neu laden und nachsehen, was daraus geworden ist.",
            )

        urteil = await self._recovery.take_over(lauf)
        if urteil.verdict is RecoveryVerdict.NEU_VERGEBBAR and urteil.claim_id is not None:
            return urteil.claim_id
        if urteil.verdict is RecoveryVerdict.ENTSCHEIDUNG_NOETIG:
            raise AdvanceRejected("step-unresolved", urteil.reason)
        raise AdvanceRejected(
            "step-claimed",
            f"{urteil.reason} Neu laden und nachsehen, was daraus geworden ist.",
        )

    # -- ① Auswählen ------------------------------------------------------
    @staticmethod
    def _faelliger_schritt(lauf: Run) -> tuple[Plan, PlanStep]:
        """Welcher Schritt ist dran? Folgenlos, und deshalb vor dem Anspruch."""
        if lauf.status is RunStatus.AWAITING_CONFIRMATION:
            raise AdvanceRejected(
                "awaiting-confirmation",
                "Der Lauf wartet auf eine Bestätigung. Erst darauf antworten.",
            )
        if lauf.status.is_terminal:
            raise AdvanceRejected("run-finished", f"Der Lauf ist abgeschlossen ({lauf.status}).")
        if lauf.plan is None:
            raise AdvanceRejected("no-plan", "Für diesen Lauf gibt es keinen Plan.")

        erledigt = {s.seq for s in lauf.state.completed_steps}
        faellig = sorted(lauf.plan.ready_steps(erledigt), key=lambda s: s.seq)
        if not faellig:
            raise AdvanceRejected("plan-done", "Der Plan ist abgearbeitet.")
        return lauf.plan, faellig[0]

    async def _pruefe_durchfuehrbar(
        self, lauf: Run, schritt: PlanStep, vorgegeben: dict[str, Any] | None
    ) -> None:
        """Was jetzt schon feststeht — ebenfalls vor dem Anspruch.

        Ein Schritt, der ohnehin nicht laufen kann, soll ihn gar nicht erst
        belegen.
        """
        if schritt.kind == "agent" and self._agents is None:
            # Ohne Agentenquelle wie bisher: Die Schleife ist gebaut, dieser
            # Aufrufer hat sie nur nicht verdrahtet.
            raise AdvanceRejected(
                "needs-agent",
                f"Schritt {schritt.seq} delegiert an den Sub-Agenten {schritt.target!r}. "
                "Dieser Aufrufer hat keine Agentenquelle.",
            )

        if schritt.kind != "tool" and vorgegeben is not None:
            # Nicht stillschweigend verwerfen: Ein Feld, das ignoriert wird, ist
            # eine Falschaussage über das, was gleich passiert.
            raise AdvanceRejected(
                "no-arguments-expected",
                f"Schritt {schritt.seq} ist vom Typ {schritt.kind!r} und nimmt keine "
                "Argumente entgegen. Ohne Argumente formuliert das Modell die Antwort.",
            )

        if schritt.kind == "tool":
            angebot = await self._policy.effective_tools(
                lauf.user_id, self._tools.names(), taint=lauf.taint_level
            )
            if schritt.target not in angebot:
                # Der Plan entstand aus dem Angebot eines sauberen Laufs.
                # Kontaminiert ein früherer Schritt den Lauf, fällt ein später
                # geplantes sendendes Werkzeug heraus.
                raise AdvanceRejected(
                    "step-stale",
                    f"Schritt {schritt.seq} ({schritt.target}) ist nicht mehr durchführbar "
                    "— der Lauf hat sich seit der Planung verändert.",
                )

    # -- ③④⑤ Werkzeugschritt ----------------------------------------------
    async def _werkzeug(
        self,
        lauf: Run,
        tracker: BudgetTracker,
        plan: Plan,
        schritt: PlanStep,
        status_vorher: RunStatus,
        vorgegeben: dict[str, Any] | None,
        session_id: UUID | None,
        anspruch: UUID,
    ) -> AdvanceOutcome:
        """Die Grenze in der Mitte dieser Methode ist die ganze Zusage."""
        # ③ Vorbereiten — hier ist nichts geschehen.
        try:
            argumente, lauf = await self._argumente(lauf, tracker, plan, schritt, vorgegeben)
        except BaseException:
            # ``BaseException`` und nicht ``Exception``: Auch ein Abbruch von
            # außen — ein Client, der während des sekundenlangen Modellaufrufs
            # auflegt — soll den Schritt nicht dauerhaft belegen. Zulässig ist
            # das nur, weil diese Phase nachweislich nichts bewirkt hat.
            await self._runs.release_step(lauf.id, anspruch)
            raise

        # ④ Wirken — ab hier gibt kein Weg den Anspruch mehr zurück.
        ausgefuehrt = await self._executor.execute_tool(
            lauf,
            tracker,
            tool_name=schritt.target,
            arguments=argumente,
            # Die Schrittnummer stammt aus dem Plan und nicht aus einem Zähler:
            # Nur so lässt sich später sagen, welcher *geplante* Schritt lief.
            seq=schritt.seq,
            session_id=session_id,
            channel=self._channel,
            # Der Anker der Wiederaufnahme. Hier — und nur hier — läuft ein
            # *geplanter* Schritt; ``POST /runs/{id}/steps`` lässt die Angabe
            # weg und wird deshalb keinem Planschritt zugeordnet.
            plan_step_seq=schritt.seq,
        )

        # ⑤ Festschreiben.
        endstand = ausgefuehrt.run
        if ausgefuehrt.executed:
            endstand = self._falls_fertig(endstand, tracker, plan)
        await self._speichern(endstand, status_vorher, anspruch)

        ergebnis = ausgefuehrt.result
        return AdvanceOutcome(
            status=ausgefuehrt.status,
            run=endstand,
            reason=ausgefuehrt.reason,
            display=ergebnis.display if ergebnis else "",
            result=ergebnis,
            pending=ausgefuehrt.pending,
            code=ausgefuehrt.code,
        )

    async def _argumente(
        self,
        lauf: Run,
        tracker: BudgetTracker,
        plan: Plan,
        schritt: PlanStep,
        vorgegeben: dict[str, Any] | None,
    ) -> tuple[dict[str, Any], Run]:
        """Argumente aus dem Request oder aus dem Modell — und der Lauf dazu.

        Der Lauf kommt mit zurück, weil eine Modellantwort ihn kontaminieren
        kann. Als Rückgabewert und nicht als Seiteneffekt, damit an der
        Aufrufstelle sichtbar bleibt, dass die Kontamination **vor** der
        Ausführung gilt.
        """
        if vorgegeben is not None:
            return vorgegeben, lauf

        try:
            formuliert = await self._arguments.for_step(
                spec=self._tools.require(schritt.target),
                step=schritt,
                run=lauf,
                goal=plan.goal,
                # Das geroutete Modell des Laufs, nicht eines aus dem Request:
                # Die Wahl steht seit dem Anlegen fest und hat dort die
                # Datenklasse berücksichtigt.
                model=lauf.routing.model if lauf.routing else "",
            )
        except PlanStepUnavailable as ohne:
            raise AdvanceRejected("no-arguments", str(ohne)) from ohne

        # Ein Modellaufruf, den niemand zählt, macht aus der Budgetgrenze eine
        # Empfehlung — und dies ist der erste Aufruf im System, der ohne
        # ausdrücklichen Wunsch des Nutzers geschieht.
        tracker.record_model_call(
            tokens_in=formuliert.usage.tokens_in,
            tokens_out=formuliert.usage.tokens_out,
            cost_eur=formuliert.usage.cost_eur,
        )
        if formuliert.taints:
            # ``with_taint`` kann nur erhöhen — die Monotonie liegt im Vertrag.
            lauf = lauf.with_taint(TaintLevel.TAINTED)
        return formuliert.arguments, lauf

    # -- ③④⑤ Antwortschritt -----------------------------------------------
    async def _antwort(
        self,
        lauf: Run,
        tracker: BudgetTracker,
        plan: Plan,
        schritt: PlanStep,
        status_vorher: RunStatus,
        anspruch: UUID,
    ) -> AdvanceOutcome:
        """Der abschließende ``llm``-Schritt.

        **Hier gibt jeder Fehler den Anspruch zurück** — anders als beim
        Werkzeugschritt, der eine Grenze in der Mitte hat. Dieser Schritt wirkt
        nirgends nach außen: Scheitert er, sind Tokens verbraucht und sonst
        nichts. Ein Wiederholer fragt das Modell erneut und legt nichts doppelt
        an. Ihn belegt zu lassen wäre eine Sperre ohne Zweck.
        """
        try:
            return await self._antwort_formulieren(
                lauf, tracker, plan, schritt, status_vorher, anspruch
            )
        except BaseException:
            await self._runs.release_step(lauf.id, anspruch)
            raise

    async def _antwort_formulieren(
        self,
        lauf: Run,
        tracker: BudgetTracker,
        plan: Plan,
        schritt: PlanStep,
        status_vorher: RunStatus,
        anspruch: UUID,
    ) -> AdvanceOutcome:
        try:
            antwort = await self._responses.for_step(
                step=schritt,
                run=lauf,
                goal=plan.goal,
                model=lauf.routing.model if lauf.routing else "",
            )
        except PlanStepUnavailable as ohne:
            raise AdvanceRejected("no-response", str(ohne)) from ohne

        tracker.record_model_call(
            tokens_in=antwort.usage.tokens_in,
            tokens_out=antwort.usage.tokens_out,
            cost_eur=antwort.usage.cost_eur,
        )
        tracker.record_step()
        if antwort.taints:
            lauf = lauf.with_taint(TaintLevel.TAINTED)

        fertig = lauf.model_copy(
            update={
                "state": lauf.state.with_step_done(
                    StepOutcome(
                        seq=schritt.seq,
                        ok=True,
                        # Gekappt (``summary`` fasst 2000 Zeichen); der
                        # vollständige Text steht in ``partial_output``. Zwei
                        # Felder, weil das eine in den Kontext des nächsten
                        # Schrittes geht und das andere an den Nutzer.
                        summary=antwort.text[:2000],
                        finished_at=utc_now(),
                    )
                ).model_copy(update={"partial_output": antwort.text}),
                "usage": tracker.usage,
            }
        )
        fertig = self._falls_fertig(fertig, tracker, plan)
        await self._speichern(fertig, status_vorher, anspruch)

        return AdvanceOutcome(
            status="executed",
            run=fertig,
            reason="Antwort formuliert.",
            display=antwort.text,
        )

    # -- ③④⑤ Agentenschritt ------------------------------------------------
    async def _agent(
        self,
        lauf: Run,
        tracker: BudgetTracker,
        plan: Plan,
        schritt: PlanStep,
        status_vorher: RunStatus,
        session_id: UUID | None,
        anspruch: UUID,
    ) -> AdvanceOutcome:
        """Ein Sub-Agent führt seine Schleife — genau einmal.

        **Die Grenze in der Mitte liegt hier anders als beim Werkzeugschritt.**
        Dort trennt eine Zeile „nichts geschehen" von „gewirkt". Hier kann die
        Schleife *mehrere* Werkzeuge ausgeführt haben, bevor sie endet — die
        Grenze ist deshalb der Eintritt in ``for_step``. Alles davor gibt den
        Anspruch zurück, alles ab dort nicht mehr.

        **Und deshalb wird dieser Schritt in jedem Ausgang abgeschlossen**, auch
        wenn der Agent nicht fertig wurde. Ein offen gelassener Agentenschritt
        wäre eine Einladung, ihn zu wiederholen — und ein zweiter Durchgang
        führte die Werkzeuge des ersten erneut aus. Was er erreicht hat, steht
        in seinem Ergebnis; ``ok`` sagt, ob das ein Erfolg war.
        """
        if self._agents is None:  # pragma: no cover - in ③ bereits abgewiesen
            raise AdvanceRejected("needs-agent", "Dieser Aufrufer hat keine Agentenquelle.")

        try:
            ausgang = await self._agents.for_step(
                step=schritt,
                run=lauf,
                tracker=tracker,
                goal=plan.goal,
                session_id=session_id,
            )
        except PlanStepUnavailable as ohne:
            # Vor der Schleife gescheitert: kein Modell, kein solcher Agent,
            # Delegation unzulässig. Nichts ist geschehen.
            await self._runs.release_step(lauf.id, anspruch)
            raise AdvanceRejected("no-agent", str(ohne)) from ohne
        except BaseException:
            # Auch hier gilt die Regel von ③: Was nachweislich nichts bewirkt
            # hat, gibt den Anspruch zurück. Ein Abbruch *innerhalb* der
            # Schleife fällt nicht hierher — ``delegate`` fängt ihn nicht, und
            # ein Werkzeug, das schon lief, hat bereits gewirkt.
            await self._runs.release_step(lauf.id, anspruch)
            raise

        ergebnis = ausgang.result
        erfolg = ergebnis.status is AgentStatus.SUCCESS
        fertig = ausgang.run.model_copy(
            update={
                "state": ausgang.run.state.with_step_done(
                    StepOutcome(
                        seq=schritt.seq,
                        ok=erfolg,
                        summary=self._agent_zusammenfassung(ergebnis),
                        model_view=self._agent_modellsicht(ergebnis),
                        finished_at=utc_now(),
                    )
                ),
                "usage": tracker.usage,
            }
        )
        if erfolg:
            # Nur bei Erfolg: Ein Lauf, der auf eine Bestätigung wartet, ist
            # nicht fertig, und ``finish()`` auf ihn anzuwenden hieße, den
            # wartenden Menschen wegzudefinieren.
            fertig = self._falls_fertig(fertig, tracker, plan)
        await self._speichern(fertig, status_vorher, anspruch)

        return AdvanceOutcome(
            status="executed" if erfolg else "blocked",
            run=fertig,
            reason=self._agent_zusammenfassung(ergebnis),
            display=ergebnis.output or "",
            code=None if erfolg else f"agent-{ergebnis.status}",
        )

    @staticmethod
    def _agent_zusammenfassung(ergebnis: AgentResult) -> str:
        """Eine Zeile für Menschen — was der Agent erreicht hat.

        Die Fälle werden benannt und nicht gedeutet: ``partial`` heißt „die
        Runden waren aufgebraucht", ``needs_confirmation`` heißt „es wartet ein
        Mensch". Beides ist kein Erfolg, und beides als „erledigt"
        zusammenzufassen wäre eine Falschaussage in der Laufübersicht.
        """
        werkzeuge = ", ".join(ergebnis.tools_used) or "keine"
        if ergebnis.status is AgentStatus.NEEDS_CONFIRMATION:
            return f"Wartet auf eine Bestätigung. Bis dahin ausgeführt: {werkzeuge}."
        if ergebnis.status is AgentStatus.PARTIAL:
            return f"Nach der zulässigen Zahl von Runden nicht fertig. Ausgeführt: {werkzeuge}."
        if ergebnis.status is AgentStatus.FAILED:
            return f"Gescheitert: {ergebnis.error or 'ohne Angabe'}."
        return (ergebnis.output or "Erledigt.")[:2000]

    @staticmethod
    def _agent_modellsicht(ergebnis: AgentResult) -> str:
        """Was ein späterer Schritt von diesem Agenten sehen darf: seinen Text.

        Ausdrücklich **nicht** die Werkzeugdaten, die er unterwegs gelesen hat.
        Die stehen bereits als eigene ``StepOutcome`` im Lauf, jede mit der
        Grenze ihres eigenen Werkzeugs (ADR-014). Sie hier noch einmal
        durchzureichen hieße, dieselbe Zusage zweimal zu geben — und einmal
        davon ohne Deklaration.
        """
        if ergebnis.status is AgentStatus.FAILED:
            return ""
        return (ergebnis.output or "")[:8000]

    # -- Gemeinsames ------------------------------------------------------
    def _falls_fertig(self, lauf: Run, tracker: BudgetTracker, plan: Plan) -> Run:
        """Schließt den Lauf ab, wenn der Plan nichts mehr hergibt.

        Die Frage „ist noch etwas fällig?" beantwortet dieselbe Funktion wie
        beim Auswählen (``Plan.ready_steps``). Eine zweite Fassung dieser
        Rechnung wäre die Stelle, an der ein Lauf entweder zu früh
        abgeschlossen wird oder ewig offen bleibt.
        """
        if plan.ready_steps(lauf.state.completed_seqs):
            return lauf
        return self._executor.finish(lauf, tracker)

    async def _speichern(self, lauf: Run, erwartet: RunStatus, anspruch: UUID) -> None:
        """Fortschreiben gegen Status **und** Anspruch.

        Der Statusvergleich allein reicht hier nicht: Ein abgelaufener und ein
        neuer Arbeiter sehen beide ``executing``, und ein Vergleich, der für
        beide gilt, unterscheidet sie nicht. Das Fencing-Token tut es.

        Gibt zugleich den Anspruch frei: Der gespeicherte Zustand führt
        ``current_step`` und ``claim_id`` nicht mehr, weil ``with_step_done``
        beide auf ``None`` setzt. Deshalb braucht der Erfolgsweg keine
        ausdrückliche Freigabe.
        """
        try:
            await self._runs.save(lauf, erwarteter_status=erwartet, claim_id=anspruch)
        except RunStateConflict as konflikt:
            raise AdvanceRejected(
                "run-changed",
                "Der Lauf wurde parallel verändert. Neu laden und wiederholen.",
            ) from konflikt
