"""Port des Kostenhauptbuchs.

**Warum es das gibt, obwohl dagegen ein guter Grund stand.** Der Verbrauch
eines Laufs steht in ``runs.usage``, und eine zweite Tabelle über denselben
Sachverhalt kann davon abweichen — das war das Argument, mit dem dieses
Hauptbuch zweimal nicht gebaut wurde. Drei Fragen haben es widerlegt, und alle
drei brauchen dieselbe Zeile:

* **„Wofür ist das Geld draufgegangen?"** Ein Summenfeld je Lauf beantwortet
  das nicht. Welches Modell, welcher Anbieter, welcher Schritt — nichts davon
  lässt sich aus einer Zahl herauslesen.
* **Der Tageswechsel.** Ein Lauf über Mitternacht belastete bisher den Vortag,
  weil die Zuordnung an seinem Beginn hing. Ein Zeitstempel je Aufruf löst das
  und sonst nichts.
* **Eine belastbare Reservierung.** Sie braucht einen Ort, an dem eine Zusage
  neben dem Verbrauch steht.

**Und die Antwort auf den Einwand:** Geschrieben wird an **einer** Stelle — im
Model Gateway, dem einzigen Weg zu einem Sprachmodell, und zwar genau dort, wo
die Kosten ohnehin errechnet werden. Ein Aufruf, der das Hauptbuch verfehlt,
müsste am Gateway vorbei; das ist dieselbe Aussage, die schon
``model-never-sees-excess-data-class`` trägt. ``runs.usage`` bleibt die
laufende Summe für das Laufbudget — ab jetzt als **abgeleitete** Sicht, und ein
Test rechnet die Übereinstimmung nach.

**Der Nutzer ist kein Argument der Anfrage.** ``SpendContext`` kommt neben der
``CompletionRequest`` herein, nicht darin — dieselbe Bauart wie Datenklasse und
Taint. Ein Feld im Anfrageobjekt wäre eine Identität, die der Aufrufer
mitbringt.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from jarvis_contracts import ModelUsage

__all__ = ["ModelSpendSink", "SpendContext", "SpendPurpose"]

SpendPurpose = str
"""Wofür der Aufruf geschah — ``arguments``, ``response``, ``agent``.

Bewusst eine Zeichenkette und kein Enum: Der Wert ist eine Auskunft für einen
Menschen, keine Fallunterscheidung im Code. Ein Enum verlangte bei jedem neuen
Aufrufort eine Vertragsänderung und verführte dazu, an ihm zu verzweigen.
"""


class SpendContext(BaseModel):
    """Wem ein Modellaufruf zuzurechnen ist.

    Kommt **neben** der Anfrage herein, nicht darin. Der Grund ist derselbe wie
    bei der Datenklasse: Ein Aufrufer, der seine Identität im Anfrageobjekt
    mitbringt, bestimmt sie.
    """

    model_config = ConfigDict(frozen=True)

    user_id: UUID
    run_id: UUID
    purpose: SpendPurpose


class ModelSpendSink(Protocol):
    """Nimmt einen abgerechneten Modellaufruf entgegen.

    **Fehler schlagen durch.** Ein Hauptbuch, dessen Schreibfehler verschluckt
    werden, ist ein Hauptbuch mit Löchern — und es fällt genau dann auf, wenn
    jemand eine Rechnung nachvollziehen will. Der Aufrufer entscheidet, was ein
    fehlgeschlagener Eintrag bedeutet; verschweigen darf ihn niemand.
    """

    async def record(
        self,
        context: SpendContext,
        *,
        provider: str,
        model: str,
        usage: ModelUsage,
        cost_eur: Decimal,
    ) -> None: ...
