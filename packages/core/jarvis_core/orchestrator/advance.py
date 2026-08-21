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

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from jarvis_contracts import (
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
from jarvis_core.policy.engine import PolicyEngine
from jarvis_core.ports.runs import RunStateConflict, RunStore
from jarvis_core.tools.registry import ToolRegistry

__all__ = ["AdvanceOutcome", "AdvanceRejected", "RunAdvancer"]


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
        channel: ApprovalChannel = "ui",
    ) -> None:
        self._runs = runs
        self._tools = tools
        self._policy = policy
        self._executor = executor
        self._arguments = arguments
        self._responses = responses
        self._channel = channel

    async def advance(
        self,
        lauf: Run,
        *,
        session_id: UUID,
        vorgegeben: dict[str, Any] | None,
    ) -> AdvanceOutcome:
        """Ein Schritt weiter.

        ``lauf`` kommt geladen und auf Zugehörigkeit geprüft herein. Das ist
        Absicht: *Wem* ein Lauf gehört, entscheidet die Kante aus der Sitzung —
        eine ``user_id`` als Parameter wäre dieselbe Lücke wie eine im
        Request-Body, nur eine Schicht tiefer.
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
            raise AdvanceRejected(
                "step-claimed",
                f"Schritt {schritt.seq} wird bereits ausgeführt oder der Lauf hat sich "
                "verändert. Neu laden und nachsehen, was daraus geworden ist.",
            )

        tracker = BudgetTracker(lauf.budget, usage=lauf.usage)
        if lauf.status is RunStatus.QUEUED:
            # ``queued → planning → executing``: Der Zustandsautomat kennt
            # keinen direkten Weg, und das ist Absicht.
            lauf = self._executor.start(lauf, tracker)

        if schritt.kind != "tool":
            return await self._antwort(lauf, tracker, plan, schritt, status_vorher, anspruch)
        return await self._werkzeug(
            lauf, tracker, plan, schritt, status_vorher, vorgegeben, session_id, anspruch
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
        if schritt.kind == "agent":
            # ``ModelLoop`` ist gebaut und hat keinen Endpunkt. Ein Sub-Agent
            # wählt seine Werkzeuge selbst — eine andere und größere Fläche als
            # „ein Modell füllt die Argumente eines angekündigten Schrittes".
            raise AdvanceRejected(
                "needs-agent",
                f"Schritt {schritt.seq} delegiert an den Sub-Agenten {schritt.target!r}. "
                "Die Agentenschleife hat noch keinen Endpunkt.",
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
        session_id: UUID,
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
