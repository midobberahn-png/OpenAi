"""Was ein Nutzer heute ausgegeben hat.

**Kein eigenes Hauptbuch, und das ist die Entscheidung dieses Moduls.** Die
naheliegende Bauart wäre eine Tabelle, in die jeder Modellaufruf eine Zeile
schreibt. Sie wäre eine **zweite** Wahrheit über denselben Sachverhalt: Der
Verbrauch eines Laufs steht bereits in ``runs.usage``, dort wird er nach jedem
Schritt fortgeschrieben, und er überlebt einen Prozessneustart. Zwei Quellen
driften auseinander — und die Frage „welche stimmt?" beantwortet man dann im
Zweifelsfall zugunsten der falschen.

Gezählt wird deshalb über die Läufe. Was das kostet, ist eine Aggregation je
Anfrage; was es spart, ist eine Tabelle, die mit dem Lauf konsistent gehalten
werden müsste.

**Ein Lauf zählt zu dem Tag, an dem er begonnen hat.** Ein Lauf über
Mitternacht verbucht seinen ganzen Verbrauch auf gestern. Das ist eine
Ungenauigkeit von der Größe eines Laufbudgets und dafür eine Regel, die sich
in einem Satz sagen lässt — die Alternative wäre, jeden Modellaufruf einzeln zu
stempeln, also doch das Hauptbuch.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

__all__ = ["PostgresSpendReader"]


_SUMME = text(
    """
    SELECT COALESCE(SUM((usage ->> 'cost_eur')::numeric), 0) AS summe
      FROM runs
     WHERE user_id = :user_id
       AND started_at >= :seit
    """
)
"""``user_id`` steht in der Anweisung, wie überall.

``COALESCE`` fängt den Fall ohne Läufe ab: ``SUM`` über die leere Menge ist
``NULL``, und ``NULL`` als „null Euro" zu lesen wäre eine Annahme, die man
besser hinschreibt.

Der Cast steht hier und nicht im Anwendungscode: ``usage`` ist JSONB, und
``->>`` liefert Text. Ein Vergleich in Python über ``float`` verlöre genau die
Genauigkeit, für die der Rest dieses Pfades ``Decimal`` benutzt."""


class PostgresSpendReader:
    """Tagesverbrauch eines Nutzers."""

    def __init__(self, engine: AsyncEngine, *, user_id: UUID) -> None:
        self._engine = engine
        self._user_id = user_id
        """Wie beim Kalender beim Verdrahten gebunden: Es gibt keine Methode,
        die einen fremden Nutzer entgegennähme."""

    async def spent_since(self, seit: datetime) -> Decimal:
        """Summe der Kosten aller Läufe, die seit ``seit`` begonnen haben."""
        async with self._engine.connect() as conn:
            summe = (
                await conn.execute(_SUMME, {"user_id": self._user_id, "seit": seit})
            ).scalar_one()
        return Decimal(str(summe))
