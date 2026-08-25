"""Die Modellschleife — wo aus Vorschlägen Anfragen werden.

Dies ist die Stelle, an der ein Sprachmodell zum ersten Mal etwas bewirken
kann, und damit die heikelste des Systems. Der übliche Aufbau ist eine
Schleife der Form „frage das Modell, führe seine Werkzeugaufrufe aus,
wiederhole". Genau dieser Aufbau ist bei einem System mit Mail- und
Kalenderzugriff die Fernsteuerung für jeden, der dem Modell Text unterschieben
kann.

Hier führt die Schleife **nichts** aus. Sie reicht jeden Vorschlag an
``AgentSession.call_tool()`` weiter, und der geht durch Kettenrechte, Policy
Engine, Approval Gateway und Ausführungs-Gate — denselben Weg wie eine
Absicht, die der Nutzer selbst geäußert hätte. Die Schleife sieht davon nur
das Ergebnis.

Drei Eigenschaften tragen den Rest:

1. **Das Angebot verengt sich mit der Kontamination.** Liest ein Werkzeug
   Fremdinhalt, bekommt das Modell in der nächsten Runde weniger Werkzeuge zu
   sehen — nicht weil ein Aufruf abgelehnt würde, sondern weil er im Schema
   nicht mehr vorkommt. Was ein Modell nicht sieht, kann es nicht vorschlagen.
2. **Die Schleife bestätigt nicht.** Verlangt die Policy eine Bestätigung,
   endet die Runde und meldet ``NEEDS_CONFIRMATION`` nach oben. Eine Schleife,
   die auf eine Bestätigung wartet, wäre eine Schleife, die eine Bestätigung
   erwartet.
3. **Sie ist endlich.** ``max_iterations`` aus dem Agentenvertrag, dazu das
   Laufbudget. Ohne beides ist ein Modell, das immer wieder dasselbe Werkzeug
   vorschlägt, ein Kostenrisiko und kein Bug.
"""

from __future__ import annotations

from jarvis_contracts import (
    AgentRequest,
    AgentResult,
    AgentSpec,
    AgentStatus,
    CompletionRequest,
    DataClass,
    Message,
    MessageRole,
    ProposedToolCall,
    Usage,
    escalate,
)
from jarvis_core.agents.runtime import AgentSession
from jarvis_core.ports.spend import SpendContext
from jarvis_core.providers.gateway import ModelGateway, ModelNotPermitted
from jarvis_core.tools.registry import ToolRegistry, UnknownTool

__all__ = ["ModelLoop"]


class ModelLoop:
    """Ein Agent, der ein Sprachmodell befragt.

    Erfüllt ``AgentBehaviour``. Die Runtime gibt ihr eine Sitzung mit bereits
    verengter Werkzeugmenge; alles Weitere ergibt sich daraus.
    """

    def __init__(
        self,
        *,
        spec: AgentSpec,
        gateway: ModelGateway,
        tools: ToolRegistry,
        model: str,
        data_class: DataClass,
    ) -> None:
        self._spec = spec
        self._gateway = gateway
        self._tools = tools
        self._model = model
        self._data_class = data_class
        """Die Datenklasse beim Start — aus dem Routing des Laufs, nicht aus der
        Aufgabe. Ein Agent, der seine eigene Datenklasse bestimmt, bestimmt
        damit, wohin die Daten gehen.

        **Sie ist der Anfangswert und nicht der Wert.** Was in jeder Runde gilt,
        steht im Lauf: ``escalate(self._data_class, session.run.data_class)``.
        Der Grund ist derselbe wie beim Angebot — der Lauf ändert sich unter der
        Schleife. Ein ``files.read`` auf einen Text, der nach Zugangsdaten
        aussieht, stuft den Lauf auf P3; ein einmal gelesener Wert ließe die
        nächste Runde weiterhin als P2 laufen, und ein Modell, das nur bis P2
        zugelassen ist, bekäme P3-Material zu sehen. Die Kontamination wurde
        von Anfang an je Runde gelesen; die Datenklasse nicht — beim
        Anschließen der Schleife aufgefallen."""

    async def act(self, session: AgentSession, request: AgentRequest) -> AgentResult:
        verlauf: list[Message] = [
            Message(role=MessageRole.SYSTEM, content=self._spec.system_prompt),
            *self._kontext(request),
            Message(role=MessageRole.USER, content=request.task),
        ]

        benutzt: list[str] = []
        verbrauch = Usage()

        for runde in range(self._spec.max_iterations):
            # Das Angebot wird in **jeder** Runde neu bestimmt. Nach einem
            # Werkzeug, das Fremdinhalt gelesen hat, ist der Lauf kontaminiert
            # — und das Modell sieht die sendenden Werkzeuge ab jetzt nicht
            # mehr. Ein einmal berechnetes Schema wäre der Weg, mit dem Angebot
            # von vorhin zu arbeiten.
            angebot = await self._angebot(session)

            try:
                antwort = await self._gateway.complete(
                    CompletionRequest(
                        model=self._model,
                        messages=verlauf,
                        tools=angebot,
                        max_tokens=min(4096, max(256, request.budget.max_tokens // 4)),
                    ),
                    # Beides aus dem Lauf, wie er *jetzt* ist — und beides
                    # kann nur steigen.
                    data_class=escalate(self._data_class, session.run.data_class),
                    taint=session.run.taint_level,
                    # **Auch die Schleife eines Sub-Agenten bucht.** Sie ist
                    # die dritte Stelle, an der Kosten entstehen, und die
                    # unauffälligste: Ihr Verbrauch wird beim Elternlauf nur
                    # als Summe übernommen (``tracker.absorb``). Ohne diese
                    # Zeile hätte das Hauptbuch genau dort ein Loch, wo ein
                    # Lauf am meisten ausgeben kann.
                    abrechnung=SpendContext(
                        user_id=session.run.user_id,
                        run_id=session.run.id,
                        purpose="agent",
                    ),
                )
            except ModelNotPermitted as abgelehnt:
                return AgentResult(
                    status=AgentStatus.FAILED,
                    error=f"Modellaufruf nicht zulässig: {abgelehnt.reason}",
                    tools_used=benutzt,
                    usage=verbrauch,
                )

            verbrauch = verbrauch.merge(
                Usage(
                    tokens_in=antwort.usage.tokens_in,
                    tokens_out=antwort.usage.tokens_out,
                    cost_eur=antwort.usage.cost_eur,
                )
            )

            if not antwort.wants_tools:
                return AgentResult(
                    status=AgentStatus.SUCCESS,
                    output=antwort.text,
                    tools_used=benutzt,
                    taint_acquired=antwort.taints_context,
                    usage=verbrauch,
                )

            verlauf.append(Message(role=MessageRole.ASSISTANT, content=antwort.text))

            for vorschlag in antwort.tool_calls:
                ausgang = await self._versuche(session, vorschlag)
                verlauf.append(ausgang.nachricht)

                if ausgang.wartet:
                    # Die Schleife bestätigt nicht. Sie endet hier und meldet
                    # nach oben — der Weg zurück führt über eine
                    # Nutzerentscheidung, nicht über eine weitere Runde.
                    return AgentResult(
                        status=AgentStatus.NEEDS_CONFIRMATION,
                        output=antwort.text,
                        tools_used=benutzt,
                        taint_acquired=session.run.taint_level.is_tainted,
                        usage=verbrauch,
                        followups=[vorschlag.tool_name],
                    )
                if ausgang.ausgefuehrt:
                    benutzt.append(vorschlag.tool_name)

            if runde + 1 >= self._spec.max_iterations:
                break

        # Die Grenze ist erreicht, ohne dass das Modell fertig war. Ein
        # Teilergebnis ist ehrlicher als eine weitere Runde: Wer hier nicht
        # abbricht, hat kein Limit, sondern eine Empfehlung.
        return AgentResult(
            status=AgentStatus.PARTIAL,
            output="Die Aufgabe war nach der zulässigen Zahl von Schritten nicht abgeschlossen.",
            tools_used=benutzt,
            taint_acquired=session.run.taint_level.is_tainted,
            usage=verbrauch,
        )

    # -- Innere Schritte --------------------------------------------------
    async def _angebot(self, session: AgentSession) -> list[dict[str, object]]:
        """Werkzeugschemata für diese Runde.

        ``session.tools`` ist die Schnittmenge aus Kettenrechten, Nutzerrechten
        und Taint-Zustand; die Registry macht daraus Schemata. Beides bleibt
        getrennt: Die Registry entscheidet nicht, was angeboten wird, und die
        Sitzung kennt keine JSON-Schemata.
        """
        return list(self._tools.to_schema(set(await session.current_tools())))

    async def _versuche(self, session: AgentSession, vorschlag: ProposedToolCall) -> _Ausgang:
        """Reicht einen Vorschlag weiter — und übersetzt das Ergebnis zurück.

        Jeder Ausgang landet als ``tool``-Nachricht im Verlauf, auch die
        Ablehnung. Das ist Absicht: Ein Modell, dem man verschweigt, dass sein
        Vorschlag abgelehnt wurde, schlägt ihn wieder vor.

        **Die Schrittnummer kommt aus dem Lauf und nicht aus einem Zähler
        dieser Schleife.** Ein Zähler begänne bei 1 — und die 1 ist die Nummer
        des ersten *Planschrittes*. Jeder Werkzeugaufruf eines Agenten schreibt
        ein ``StepOutcome``; mit den Zahlen 1, 2, 3 träte er der Reihe nach
        jeden Planschritt als erledigt, ohne dass einer gelaufen wäre.
        ``Run.next_step_seq`` vergibt oberhalb des ganzen Plans und ist nach
        jedem ausgeführten Aufruf eine höher.
        """
        try:
            ergebnis = await session.call_tool(
                vorschlag.tool_name, vorschlag.arguments, seq=session.run.next_step_seq
            )
        except UnknownTool:
            # Halluzinierte Werkzeugnamen sind alltäglich und kein
            # Sicherheitsvorfall. Sie gehören ins Gespräch zurück, damit das
            # Modell es anders versucht — nicht in einen Abbruch.
            return _Ausgang(
                nachricht=Message(
                    role=MessageRole.TOOL,
                    content=f"Ein Werkzeug namens {vorschlag.tool_name!r} gibt es nicht.",
                    tool_call_id=vorschlag.id,
                    name=vorschlag.tool_name,
                ),
                ausgefuehrt=False,
                wartet=False,
            )

        wartet = ergebnis.status == "awaiting_confirmation"
        if ergebnis.executed and ergebnis.result is not None:
            inhalt = ergebnis.result.display or "Ausgeführt."
        elif wartet:
            inhalt = "Wartet auf die Bestätigung des Nutzers."
        else:
            inhalt = f"Nicht ausgeführt: {ergebnis.reason}"

        return _Ausgang(
            nachricht=Message(
                role=MessageRole.TOOL,
                content=inhalt,
                tool_call_id=vorschlag.id,
                name=vorschlag.tool_name,
                # Werkzeugergebnisse können Fremdinhalt tragen — eine gelesene
                # Mail steht danach im Verlauf und geht mit in den nächsten
                # Modellaufruf. Die Markierung ist der Grund, warum die Antwort
                # darauf als kontaminiert gilt.
                is_untrusted=session.run.taint_level.is_tainted,
            ),
            ausgefuehrt=ergebnis.executed,
            wartet=wartet,
        )

    @staticmethod
    def _kontext(request: AgentRequest) -> list[Message]:
        """Kontextfragmente als Nachrichten — mit Herkunftsmarkierung.

        ``is_untrusted`` wandert mit, weil das Gateway daran entscheidet, ob
        die Antwort kontaminiert. Übertragen wird die Markierung nicht: Der
        Adapter schickt nur Rolle und Inhalt.
        """
        if not request.context.fragments:
            return []
        return [
            Message(
                role=MessageRole.USER,
                content=fragment.content,
                is_untrusted=fragment.is_untrusted,
            )
            for fragment in request.context.fragments
        ]


class _Ausgang:
    """Was aus einem Vorschlag geworden ist."""

    __slots__ = ("ausgefuehrt", "nachricht", "wartet")

    def __init__(self, *, nachricht: Message, ausgefuehrt: bool, wartet: bool) -> None:
        self.nachricht = nachricht
        self.ausgefuehrt = ausgefuehrt
        self.wartet = wartet
