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
from sqlalchemy.sql.elements import TextClause

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


_VERPFLICHTET = text(
    """
    SELECT COALESCE(SUM(
             CASE
               WHEN status IN ('queued', 'executing')
               THEN GREATEST(
                      COALESCE((usage ->> 'cost_eur')::numeric, 0),
                      COALESCE((budget ->> 'max_cost_eur')::numeric, 0)
                    )
               ELSE COALESCE((usage ->> 'cost_eur')::numeric, 0)
             END
           ), 0) AS summe
      FROM runs
     WHERE user_id = :user_id
       AND started_at >= :seit
    """
)
"""Was heute ausgegeben ist **und was zugesagt wurde**.

**Der Unterschied entscheidet, ob die Tagesgrenze eine Grenze ist.** Ein Blick
auf das bereits Verbuchte beantwortet die falsche Frage: Bei 4,99 € von 5,00 €
darf danach *jeder* neue Lauf in die Wolke, und zehn davon geben zusammen zehn
Laufbudgets aus. Gemeldet von einer Prüfung durch Codex, und der Befund stimmt:
Die Grenze war weich, und die Notiz daneben („höchstens ein Laufbudget
Überschreitung") war zu großzügig.

Ein laufender Lauf zählt deshalb mit **seinem Budget**, nicht mit dem, was er
bisher verbraucht hat — ``GREATEST``, damit ein Lauf, der sein Budget schon
überschritten hat, nicht kleiner gerechnet wird als er ist. Das ist die
vorsichtige Richtung: Die Grenze hält lieber zu früh als zu spät.

**Kein eigenes Hauptbuch, wieder nicht.** Alles steht in ``runs``: der
Verbrauch im ``usage``, die Zusage im ``budget``, der Zustand im ``status``.
Was fehlt, ist damit auch benannt — eine Auskunft je Modell oder je Anbieter
gibt es weiterhin nicht, und Kosten nach Mitternacht fallen weiterhin auf den
Tag, an dem ihr Lauf begonnen hat."""


class PostgresSpendReader:
    """Tagesverbrauch eines Nutzers."""

    def __init__(self, engine: AsyncEngine, *, user_id: UUID) -> None:
        self._engine = engine
        self._user_id = user_id
        """Wie beim Kalender beim Verdrahten gebunden: Es gibt keine Methode,
        die einen fremden Nutzer entgegennähme."""

    async def spent_since(self, seit: datetime) -> Decimal:
        """Summe der Kosten aller Läufe, die seit ``seit`` begonnen haben."""
        return await self._summe(_SUMME, seit)

    async def committed_since(self, seit: datetime) -> Decimal:
        """Ausgegeben **plus** zugesagt — die Zahl, an der die Grenze hängt.

        Siehe ``_VERPFLICHTET``: Ein laufender Lauf zählt mit seinem Budget,
        weil er es ausgeben *darf*. Wer nur das Verbuchte prüft, lässt beliebig
        viele Läufe an einer Grenze vorbei, die noch keiner von ihnen berührt
        hat.
        """
        return await self._summe(_VERPFLICHTET, seit)

    async def _summe(self, anweisung: TextClause, seit: datetime) -> Decimal:
        async with self._engine.connect() as conn:
            summe = (
                await conn.execute(anweisung, {"user_id": self._user_id, "seit": seit})
            ).scalar_one()
        return Decimal(str(summe))
