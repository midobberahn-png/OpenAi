"""Der Agentenschritt eines Plans — die Modellschleife bekommt ihren Weg hinein.

**Warum diese Datei bei den Agenten liegt und nicht beim Orchestrator.** Die
Abhängigkeit zwischen beiden Paketen ist eine Einbahnstraße: ``agents`` benutzt
den Executor und den Budgetzähler des Orchestrators, nie umgekehrt. Eine
Zusammensetzung im Orchestrator, die ``ModelLoop`` importiert, schlösse den
Kreis — gemessen an einem ``ImportError`` beim ersten Testlauf, nicht
vorhergesehen. Der Ablauf kennt deshalb nur ein **Protokoll**
(``orchestrator.advance.AgentStepRunner``); was es erfüllt, entsteht hier.

``ModelLoop`` ist gebaut, geprüft und hatte keinen Aufrufer: Ein Planschritt der
Art ``agent`` wurde von ``advance_run`` mit 409 abgewiesen. Diese Datei ist die
fehlende Kante, und sie ist bewusst dünn — sie **entscheidet nichts**, sie setzt
zusammen:

    Plan nennt einen Agenten → Kette bilden → Rechte schneiden → Schleife laufen
    lassen → Ergebnis zurückgeben

Alles Tragende steht anderswo und bleibt dort: Die Rechtemenge ist die
Schnittmenge der Kette mit den Nutzerrechten (``AgentRuntime``), jeder
Werkzeugaufruf geht durch Policy Engine und Ausführungs-Gate
(``AgentSession.call_tool``), und die Schleife bestätigt nicht (``ModelLoop``).

**Der Unterschied zur Argument- und zur Antwortquelle ist die Wahl.**

    Argumentquelle:  ein Werkzeug, vom Plan bestimmt, ein Aufruf
    Antwortquelle:   kein Werkzeug, ein Aufruf
    Agentenschritt:  die Schnittmenge, je Runde neu — das Modell wählt

Das ist keine Größenfrage, sondern eine andere Fläche: Erst hier entscheidet ein
Modell, *welches* Werkzeug läuft. Was diese Fläche eingrenzt, ist nicht eine
Prüfung an dieser Stelle, sondern das Angebot: Was ein Modell nicht sieht, kann
es nicht vorschlagen — und gesehen wird die Kettenschnittmenge, wie sie *in
dieser Runde* gilt.

**Was hier ausdrücklich nicht entsteht: eine Fortsetzung.**

Verlangt ein Vorschlag eine Bestätigung, endet die Schleife und der Lauf wartet.
Danach wird sie **nicht** wieder aufgenommen — und das ist eine Entscheidung,
keine Auslassung. Eine Fortsetzung hätte zwei Möglichkeiten, und beide kosten
mehr, als dieser Schritt wert ist:

* *Von vorn beginnen.* Die Werkzeuge, die vor der Bestätigung liefen, liefen
  bereits. Ein zweiter Durchgang legte denselben Termin ein zweites Mal an —
  genau der doppelte Seiteneffekt, gegen den der halbe Sockel gebaut ist.
* *Den Verlauf mitschreiben.* Dann läge das Gespräch eines Modells in der
  Laufpersistenz: Fremdinhalt, unbegrenzt, mit allem, was daran hängt
  (Größe, Löschfristen, Herkunftsmarkierung). Das ist eine eigene
  Entscheidung und braucht ein ADR, keinen Nebensatz hier.

Deshalb gilt: Der Agentenschritt läuft **einmal**. Was er bis zur Bestätigung
erreicht hat, steht im Ergebnis; der Plan geht danach zum nächsten Schritt über.
"""

from __future__ import annotations

from uuid import UUID

from jarvis_contracts import (
    ContextBundle,
    ContextFragment,
    PlanStep,
    Run,
)
from jarvis_core.agents.model_loop import ModelLoop
from jarvis_core.agents.registry import AgentRegistry, UnknownAgent
from jarvis_core.agents.runtime import AgentRuntime, DelegationDenied, DelegationOutcome
from jarvis_core.orchestrator.budget import BudgetTracker
from jarvis_core.orchestrator.plan_context import PlanStepUnavailable
from jarvis_core.providers.gateway import ModelGateway
from jarvis_core.tools.registry import ToolRegistry

__all__ = ["ROOT_AGENT", "AgentStepSource", "AgentStepUnavailable"]

ROOT_AGENT = "supervisor"
"""Von wem aus delegiert wird.

Eine Kette beginnt nicht beim Ziel: ``capability_ceiling()`` schneidet die
Whitelists **aller** Stufen, und wer delegiert, muss aufschreiben, was er
weitergeben kann. Der Supervisor ist damit die Obergrenze jeder Delegation und
kein Durchreicher — eine Kette, die beim Ziel begänne, hätte keine.
"""


class AgentStepUnavailable(PlanStepUnavailable):
    """Dieser Agentenschritt lässt sich nicht ausführen — und nichts ist geschehen."""


class AgentStepSource:
    """Führt einen Planschritt der Art ``agent`` aus."""

    def __init__(
        self,
        *,
        runtime: AgentRuntime,
        agents: AgentRegistry,
        gateway: ModelGateway,
        tools: ToolRegistry,
        root: str = ROOT_AGENT,
    ) -> None:
        self._runtime = runtime
        self._agents = agents
        self._gateway = gateway
        self._tools = tools
        self._root = root

    async def for_step(
        self,
        *,
        step: PlanStep,
        run: Run,
        tracker: BudgetTracker,
        goal: str,
        session_id: UUID | None,
    ) -> DelegationOutcome:
        """Delegiert an den Agenten, den der Plan nennt.

        ``run`` ganz und nicht in Einzelteilen — dieselbe Überlegung wie bei
        der Argumentquelle: Datenklasse, Kontamination und Budget stammen aus
        dem persistierten Lauf. Ein Parameter dafür wäre die Obergrenze als
        Angabe des Aufrufers.

        ``session_id=None`` reicht bis zum Executor durch: Ein Arbeiter ohne
        Sitzung erzeugt auch aus einem Agentenschritt heraus keine Bestätigung,
        die niemand einlösen könnte.
        """
        if run.routing is None:
            raise AgentStepUnavailable(
                f"Schritt {step.seq}: Der Lauf hat keine Routing-Entscheidung, also auch "
                "kein Modell. Ohne Modell gibt es keine Schleife."
            )

        try:
            kette = self._agents.chain_from(self._root)
            ziel = self._agents.require(step.target)
        except UnknownAgent as unbekannt:
            # Der Planer schreibt einen Agentennamen hin (``research``,
            # ``general``); dass es ihn gibt, entscheidet der Katalog. Ein
            # fehlender Agent ist eine Konfigurationslücke und kein
            # Rechteproblem — deshalb eine eigene Meldung und kein „verboten".
            raise AgentStepUnavailable(f"Schritt {step.seq}: {unbekannt}") from unbekannt

        verhalten = ModelLoop(
            spec=ziel,
            gateway=self._gateway,
            tools=self._tools,
            model=run.routing.model,
            # Der Anfangswert; die Schleife liest ihn je Runde neu aus dem Lauf
            # und kann ihn nur erhöhen.
            data_class=run.data_class,
        )

        try:
            return await self._runtime.delegate(
                chain=kette,
                target=ziel.name,
                task=step.description or goal,
                run=run,
                tracker=tracker,
                behaviour=verhalten,
                session_id=session_id,
                context=self._kontext(run),
                # Der Anker der Wiederaufnahme: Jeder Werkzeugaufruf dieses
                # Agenten gehört zu *diesem* Planschritt. Ohne die Angabe
                # stünde er ohne Zuordnung im Protokoll — und ein
                # hängengebliebener Agentenschritt gälte als „nachweislich
                # nichts geschehen", obwohl er bereits gewirkt hat.
                plan_step_seq=step.seq,
            )
        except DelegationDenied as abgelehnt:
            # Strukturell unzulässig: keine Delegationserlaubnis, Rekursion,
            # zu tief. Nichts ist geschehen — der Schritt bleibt offen.
            raise AgentStepUnavailable(f"Schritt {step.seq}: {abgelehnt}") from abgelehnt

    @staticmethod
    def _kontext(run: Run) -> ContextBundle:
        """Was der Sub-Agent vom bisherigen Lauf sieht: die Modellsichten.

        Dasselbe Material wie beim Argument- und Antwortschritt (ADR-014) und
        aus demselben Grund dieselbe Grenze: ``StepOutcome.model_view`` ist das,
        was ein Werkzeug ausdrücklich für Modelle freigegeben hat — gekappt und
        ausgezeichnet. Das rohe Ergebnis liegt nicht in der Laufpersistenz und
        soll auch nicht durch diese Tür hinein.

        ``is_untrusted`` wandert mit: Ein kontaminierter Lauf reicht
        Fremdinhalt weiter, und das Gateway entscheidet daran, ob die Antwort
        des Sub-Agenten ihrerseits kontaminiert.
        """
        fragmente = [
            ContextFragment(
                content=f"Schritt {ergebnis.seq}: {ergebnis.model_view}",
                source="run",
                # Geschätzt und nicht gezählt: Die Zahl steuert hier nichts —
                # gekappt wurde bereits beim Schreiben der Modellsicht. Ein
                # echter Tokenizer an dieser Stelle wäre ein Modellaufruf für
                # eine Zahl, die niemand liest.
                tokens=len(ergebnis.model_view) // 4,
                data_class=run.data_class,
                is_untrusted=run.taint_level.is_tainted,
            )
            for ergebnis in run.state.completed_steps
            if ergebnis.model_view
        ]
        return ContextBundle(
            fragments=fragmente,
            total_tokens=sum(f.tokens for f in fragmente),
            budget=sum(f.tokens for f in fragmente),
        )
