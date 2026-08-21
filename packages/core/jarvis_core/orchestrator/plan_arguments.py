"""Die Argumente eines Planschrittes — formuliert von einem Modell.

Hier schließt sich die Lücke, die das Übergabedossier als Engpass benannt hat:
Ein ``PlanStep`` führt Werkzeug und Reihenfolge, aber keine Argumente. Bis
hierher lieferte sie der Aufrufer; ab hier ein Modell.

**Warum das nicht die übliche Werkzeugschleife ist.** Der gewöhnliche Aufbau
lautet „frage das Modell, führe seine Werkzeugaufrufe aus, wiederhole" — das
Modell wählt Werkzeug *und* Argumente. Diese Datei macht etwas Engeres: Das
Werkzeug steht schon fest, weil der Plan es nennt und der Nutzer den Plan
gesehen hat. Vom Modell kommt nur, womit es aufgerufen wird.

Die Verengung ist der Punkt. Was ein Modell nicht wählen kann, kann ihm auch
niemand unterschieben:

* **Ein Werkzeug im Angebot**, nicht der Katalog. Nennt das Modell trotzdem ein
  anderes, wird der Schritt abgewiesen — nicht das Werkzeug getauscht und nicht
  der Vorschlag stillschweigend umgebogen. Argumente, die für ``mail.send``
  formuliert wurden, sind keine Argumente für ``calendar.create``.
* **Keine Schleife.** Ein Aufruf, ein Argumentobjekt. Ein Modell, das nicht
  antwortet, bekommt keinen zweiten Versuch aus dieser Datei; der Schritt
  scheitert und der Nutzer sieht warum.
* **Keine Ausführung.** Der Rückgabewert ist Datenmaterial. Ausgeführt wird
  über ``ToolExecutor``, also denselben Weg wie eine Absicht des Nutzers —
  Schemaprüfung, Policy, Taint-Gate, Bestätigung, Grant, Verbrauch. Ein
  Werkzeugvorschlag eines Modells trägt keine Berechtigung mit sich. Ein
  AST-Test hält fest, dass hier kein Nebenweg entsteht.

**Und die Stelle, an der es ernst wird.** Bis heute hat ein Mensch die
Argumente getippt, und der Payload-Hash der Bestätigung war eine Formalie: Was
angezeigt wurde, hatte derselbe Mensch kurz vorher geschrieben. Ab jetzt hat
sie ein Modell formuliert, das eine kontaminierte Datei gelesen haben kann.
Der Hash ist dann die Stelle, an der Angezeigtes und Ausgeführtes
übereinstimmen — und das Taint-Gate die, an der ein Termin *mit Teilnehmern*
nach einem Dateizugriff gar nicht erst zur Bestätigung kommt.

Deshalb reicht ``for_step`` den Taint-Zustand des Laufs an das Gateway durch
und gibt zurück, ob die Antwort kontaminiert: Ein Lauf, der aus einer
Modellantwort Argumente bezieht, ist danach nicht sauberer als ihr Kontext.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from jarvis_contracts import (
    CompletionRequest,
    Message,
    MessageRole,
    ModelUsage,
    PlanStep,
    Run,
    ToolSpec,
)
from jarvis_core.providers.gateway import ModelGateway, ModelNotPermitted

__all__ = ["ArgumentsUnavailable", "FormulatedArguments", "PlanArgumentSource"]

MAX_TOKENS = 1024
"""Argumente sind kurz. Ein großzügiges Limit hier kostet nur Zeit und lädt ein
Modell dazu ein, den Payload mit Text zu füllen, den ein Mensch prüfen muss."""


class ArgumentsUnavailable(Exception):
    """Für diesen Schritt lassen sich keine Argumente gewinnen.

    Ausnahme und kein leeres Argumentobjekt: Ein leeres Dict sähe aus wie „das
    Werkzeug braucht nichts" und liefe weiter. Ein Schritt ohne Argumente ist
    kein Schritt mit anderen Argumenten.
    """


class FormulatedArguments(BaseModel):
    """Was das Modell geliefert hat — und woher es kommt."""

    model_config = ConfigDict(frozen=True)

    arguments: dict[str, Any]
    """Ungeprüft gegen das Werkzeugschema. Die Prüfung geschieht im Executor,
    zusammen mit der für Argumente aus dem Request — eine zweite Fassung
    derselben Prüfung liefe irgendwann auseinander."""

    taints: bool
    """Erbt die Antwort die Kontamination ihres Kontextes?

    Kommt vom Model Gateway, nicht vom Adapter. Der Aufrufer muss den Lauf
    danach fortschreiben, *bevor* der Schritt ausgeführt wird — sonst träfe
    das Werkzeug einen Lauf an, der sauberer aussieht, als er ist.
    """

    usage: ModelUsage = ModelUsage()
    """Was der Aufruf gekostet hat.

    Wird mitgeführt, damit der Aufrufer ihn auf das Laufbudget buchen kann.
    Ein Modellaufruf, den niemand zählt, macht aus der Budgetgrenze eine
    Empfehlung — und die Argumentbeschaffung ist der erste Aufruf im System,
    der ohne ausdrücklichen Wunsch des Nutzers geschieht.
    """

    text: str = ""
    """Was das Modell nebenher gesagt hat. Für die Anzeige, nicht für
    Entscheidungen — und ausdrücklich nicht die Quelle der Vorschau: Die
    entsteht aus dem Argumentobjekt, sonst könnte ein Modell etwas anderes
    anzeigen, als es ausführt."""


class PlanArgumentSource:
    """Lässt ein Modell die Argumente eines geplanten Werkzeugschrittes füllen."""

    def __init__(self, *, gateway: ModelGateway) -> None:
        self._gateway = gateway

    async def for_step(
        self,
        *,
        spec: ToolSpec,
        step: PlanStep,
        run: Run,
        goal: str,
        model: str,
    ) -> FormulatedArguments:
        """Fragt das Modell nach den Argumenten für genau diesen Schritt.

        ``run`` wird ganz übergeben und nicht in Einzelteilen: Datenklasse und
        Taint-Zustand stammen daraus und nicht aus Parametern. Ein Parameter
        ``data_class`` wäre die Obergrenze als Angabe des Aufrufers — dieselbe
        Lücke wie ``user_id`` im Request-Body, nur eine Schicht tiefer. Ein
        Test hält die Signatur fest.
        """
        anfrage = CompletionRequest(
            model=model,
            messages=self._verlauf(spec=spec, step=step, run=run, goal=goal),
            # Genau ein Werkzeug. Der Plan hat gewählt.
            tools=[
                {
                    "name": spec.name,
                    "description": spec.description,
                    "input_schema": spec.parameters,
                }
            ],
            max_tokens=MAX_TOKENS,
            # Argumente sollen aus der Aufgabe folgen, nicht aus einem
            # Zufallsprozess. Zwei Läufe derselben Anfrage sollen denselben
            # Termin ergeben — sonst ist die Vorschau, die ein Mensch geprüft
            # hat, nicht die Aktion, die beim nächsten Mal liefe.
            temperature=0.0,
        )

        try:
            antwort = await self._gateway.complete(
                anfrage,
                data_class=run.data_class,
                taint=run.taint_level,
            )
        except ModelNotPermitted as abgelehnt:
            # Die Ablehnung wird zur Abweisung des Schrittes und nicht zu einem
            # leeren Argumentobjekt. Fail closed heißt hier: sichtbar scheitern.
            raise ArgumentsUnavailable(
                f"Schritt {step.seq} ({spec.name}): Modellaufruf nicht zulässig — "
                f"{abgelehnt.reason}"
            ) from abgelehnt

        if not antwort.wants_tools:
            raise ArgumentsUnavailable(
                f"Schritt {step.seq} ({spec.name}): Das Modell hat keine Argumente "
                "geliefert. Der Schritt bleibt offen; die Argumente lassen sich auch "
                "selbst angeben."
            )

        vorschlag = antwort.tool_calls[0]
        if vorschlag.tool_name != spec.name:
            # Nicht umbiegen. Argumente entstehen zu einem Werkzeugschema; für
            # ein anderes Werkzeug sind sie nicht dieselben Argumente, auch
            # wenn die Feldnamen zufällig passen.
            raise ArgumentsUnavailable(
                f"Schritt {step.seq} sieht {spec.name!r} vor, das Modell schlug "
                f"{vorschlag.tool_name!r} vor. Der Plan bindet."
            )

        return FormulatedArguments(
            arguments=vorschlag.arguments,
            taints=antwort.taints_context,
            usage=antwort.usage,
            text=antwort.text,
        )

    # -- Kontext ----------------------------------------------------------
    @staticmethod
    def _verlauf(*, spec: ToolSpec, step: PlanStep, run: Run, goal: str) -> list[Message]:
        """Der Kontext des Modellaufrufs — mit Herkunftsmarkierung.

        Drei Teile, und die Trennung ist bedeutungstragend:

        * Die **Systemnachricht** beschreibt die Aufgabe. Sie stammt aus dem
          Programm und ist vertrauenswürdig.
        * Das **Ziel** hat der Nutzer formuliert.
        * Der **bisherige Verlauf** besteht aus den Zusammenfassungen erledigter
          Schritte. Sie sind aus Werkzeugergebnissen abgeleitet, und in einem
          kontaminierten Lauf gilt für sie, was für den Lauf gilt:
          ``is_untrusted``. Daran entscheidet das Gateway, ob die Antwort
          kontaminiert — nicht daran, ob wir es für wahrscheinlich halten.

        Die Markierung wird nicht übertragen: Der Adapter schickt Rolle und
        Inhalt. Sie dem Modell mitzuschicken hieße, ihm die Kennzeichnung zur
        eigenen Verwendung zu überlassen.
        """
        auftrag = (
            f"Du füllst die Argumente für genau einen Werkzeugaufruf: {spec.name}. "
            "Rufe das Werkzeug auf; antworte nicht mit Text. Halte dich an das "
            "Schema — erfinde keine Felder. Was du nicht sicher weißt, lässt du weg, "
            "sofern es nicht Pflicht ist. Zeitangaben immer mit Zeitzone."
        )

        verlauf = [
            Message(role=MessageRole.SYSTEM, content=auftrag),
            Message(role=MessageRole.USER, content=f"Ziel des Vorgangs: {goal}"),
            Message(role=MessageRole.USER, content=f"Dieser Schritt: {step.description}"),
        ]

        erledigt = run.state.completed_steps
        if erledigt:
            verlauf.append(
                Message(
                    role=MessageRole.USER,
                    content="Bisher erledigt:\n"
                    + "\n".join(f"{s.seq}. {s.summary}" for s in erledigt),
                    # Abgeleitet aus Werkzeugergebnissen. In einem
                    # kontaminierten Lauf ist das Fremdinhalt — und zwar
                    # unabhängig davon, wie harmlos eine Zusammenfassung
                    # aussieht.
                    is_untrusted=run.taint_level.is_tainted,
                )
            )
        return verlauf
