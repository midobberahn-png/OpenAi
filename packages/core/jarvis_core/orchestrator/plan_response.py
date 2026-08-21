"""Der abschließende Schritt — ein Modell formuliert die Antwort.

Jeder Plan dieses Systems endet mit ``kind="llm"`` und ``target="response"``:
„Antwort formulieren", „Ergebnis zusammenfassen" (``planner.py``). Bis hierher
war dieser Schritt nicht ausführbar, und die Folge war größer als sie klang —
**kein Plan war abschließbar.** Auch der einfachste nicht: „Wie spät ist es?"
besteht aus genau diesem einen Schritt.

**Der Unterschied zur Argumentquelle ist ein leeres Angebot.** Dort bekommt das
Modell genau ein Werkzeugschema zu sehen; hier keines. Es kann deshalb nichts
vorschlagen, und dieser Schritt kann nichts auslösen — er erzeugt Text und
sonst nichts.

Genau darum ist er der kleinste ehrliche Schritt in Richtung Modellschleife.
Eine Schleife braucht eine Abbruchsemantik: Wann ist das Modell fertig, wann
wird abgebrochen, was zählt als Fortschritt. Diese Fragen sind hier nicht zu
beantworten, weil es nichts gibt, wovon abzubrechen wäre. Wer sie beantworten
will, baut ``ModelLoop`` an einen Endpunkt — das ist der nächste Zuschnitt und
ausdrücklich nicht dieser.

**Der Rest, der bleibt, und der nicht wegzuprüfen ist.**

Der Text geht an einen Menschen. Stammt er aus einem kontaminierten Lauf, kann
er eine untergeschobene Anweisung enthalten, die sich an *ihn* richtet — „laut
Notiz sollst du überweisen". Dagegen hilft Taint-Tracking nicht: Es macht
Fremdinhalt folgenlos, indem es Werkzeuge sperrt, und hier ist kein Werkzeug
beteiligt.

Was es leisten kann, ist die Herkunft zu benennen. ``FormulatedResponse.taints``
wandert deshalb in den Lauf, und ``GET /runs/{id}`` zeigt ``taint_level``. Eine
Oberfläche, die eine Antwort aus kontaminiertem Kontext nicht als solche
kennzeichnet, lässt diese Lücke offen — der Kern kann sie nicht schließen, aber
er kann die Auskunft liefern, ohne die es niemand kann.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from jarvis_contracts import CompletionRequest, ModelUsage, PlanStep, Run
from jarvis_core.orchestrator.plan_context import PlanStepUnavailable, schritt_nachrichten
from jarvis_core.providers.gateway import ModelGateway, ModelNotPermitted

__all__ = ["FormulatedResponse", "PlanResponseSource", "ResponseUnavailable"]

MAX_TOKENS = 2048
"""Eine Antwort an einen Menschen darf länger sein als ein Argumentobjekt —
aber nicht beliebig. ``RunState.partial_output`` fasst 200.000 Zeichen; das ist
die Obergrenze des Speichers, nicht die des Sinnvollen."""

AUFTRAG = (
    "Du formulierst die abschließende Antwort an den Nutzer. Fasse zusammen, was "
    "in diesem Vorgang geschehen ist, und antworte auf sein Ziel. Antworte mit "
    "Text; dir stehen keine Werkzeuge zur Verfügung. Was du nicht weißt, sagst du "
    "— rate nicht."
)


class ResponseUnavailable(PlanStepUnavailable):
    """Für diesen Schritt lässt sich keine Antwort gewinnen."""


class FormulatedResponse(BaseModel):
    """Was das Modell formuliert hat — und woher es kommt."""

    model_config = ConfigDict(frozen=True)

    text: str
    """Die Antwort an den Nutzer. Landet in ``RunState.partial_output``."""

    taints: bool
    """Erbt die Antwort die Kontamination ihres Kontextes?

    Kommt vom Model Gateway. Der Aufrufer schreibt sie in den Lauf, damit die
    Oberfläche den Text kennzeichnen kann — blockieren lässt sich hier nichts,
    denn der Adressat ist ein Mensch und kein Werkzeug.
    """

    usage: ModelUsage = ModelUsage()


class PlanResponseSource:
    """Lässt ein Modell den abschließenden ``llm``-Schritt eines Plans füllen."""

    def __init__(self, *, gateway: ModelGateway) -> None:
        self._gateway = gateway

    async def for_step(
        self,
        *,
        step: PlanStep,
        run: Run,
        goal: str,
        model: str,
    ) -> FormulatedResponse:
        """Fragt das Modell nach der Antwort für diesen Schritt.

        Wie bei der Argumentquelle: ``run`` ganz, nicht in Einzelteilen.
        Datenklasse und Taint-Zustand stammen aus dem persistierten Lauf und
        nicht aus Parametern — ein Parameter dafür wäre die Obergrenze als
        Angabe des Aufrufers.
        """
        anfrage = CompletionRequest(
            model=model,
            messages=schritt_nachrichten(auftrag=AUFTRAG, step=step, run=run, goal=goal),
            # Leer, und das ist die tragende Eigenschaft dieses Schrittes.
            # Nicht „ein Werkzeug" wie bei der Argumentquelle — keines.
            tools=[],
            max_tokens=MAX_TOKENS,
        )

        try:
            antwort = await self._gateway.complete(
                anfrage,
                data_class=run.data_class,
                taint=run.taint_level,
            )
        except ModelNotPermitted as abgelehnt:
            raise ResponseUnavailable(
                f"Schritt {step.seq}: Modellaufruf nicht zulässig — {abgelehnt.reason}"
            ) from abgelehnt

        # Ein etwaiger Werkzeugvorschlag wird hier schlicht nicht gelesen. Es
        # gibt in dieser Datei keinen Weg, aus ``antwort.tool_calls`` etwas zu
        # machen — was das Modell trotz leerem Angebot halluziniert, verfällt.
        text = antwort.text.strip()
        if not text:
            # Ein Lauf, der mit leerem Text als „fertig" gilt, sieht erfolgreich
            # aus und hat nichts geliefert.
            raise ResponseUnavailable(
                f"Schritt {step.seq}: Das Modell hat keinen Text geliefert. "
                "Der Schritt bleibt offen."
            )

        return FormulatedResponse(text=text, taints=antwort.taints_context, usage=antwort.usage)
