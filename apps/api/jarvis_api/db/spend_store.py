"""Was ein Nutzer heute ausgegeben hat.

**Gezählt wird im Hauptbuch, zugesagt wird über die Läufe.** Diese Teilung ist
die Entscheidung dieses Moduls, und sie löst den Einwand auf, der das Hauptbuch
zweimal verhindert hat („zweite Wahrheit"):

* ``model_calls`` ist die **Tatsache**: eine Zeile je Modellaufruf, mit
  Zeitstempel aus der Datenbank. Daraus kommt, was heute ausgegeben wurde — und
  zwar ohne die alte Schieflage, dass ein Lauf über Mitternacht seinen ganzen
  Verbrauch auf gestern buchte.
* ``runs`` trägt die **Zusage**: Was ein laufender Lauf noch ausgeben *darf*,
  steht in seinem Budget und nirgends sonst.

``runs.usage`` bleibt die laufende Summe für das Laufbudget, ist aber ab jetzt
eine **abgeleitete** Sicht; ein Test rechnet sie gegen das Hauptbuch nach
(``test_hauptbuch.py``). Geschrieben wird das Hauptbuch an genau einer Stelle,
im Model Gateway — die Begründung steht in ``jarvis_core.ports.spend``.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.sql.elements import TextClause

from jarvis_contracts import ModelUsage
from jarvis_core.ports.spend import SpendContext

__all__ = ["PostgresModelSpendStore", "PostgresSpendReader"]


_SUMME = text(
    """
    SELECT COALESCE(SUM(cost_eur), 0) AS summe
      FROM model_calls
     WHERE user_id = :user_id
       AND occurred_at >= :seit
    """
)
"""Was heute tatsächlich ausgegeben wurde — je **Aufruf**, nicht je Lauf.

``user_id`` steht in der Anweisung, wie überall.

``COALESCE`` fängt den Fall ohne Läufe ab: ``SUM`` über die leere Menge ist
``NULL``, und ``NULL`` als „null Euro" zu lesen wäre eine Annahme, die man
besser hinschreibt.

Der Cast steht hier und nicht im Anwendungscode: ``usage`` ist JSONB, und
``->>`` liefert Text. Ein Vergleich in Python über ``float`` verlöre genau die
Genauigkeit, für die der Rest dieses Pfades ``Decimal`` benutzt."""


_VERPFLICHTET = text(
    """
    SELECT
      (SELECT COALESCE(SUM(cost_eur), 0)
         FROM model_calls
        WHERE user_id = :user_id
          AND occurred_at >= :seit)
      +
      (SELECT COALESCE(SUM(
                 GREATEST(
                   COALESCE((budget ->> 'max_cost_eur')::numeric, 0)
                   - COALESCE((usage ->> 'cost_eur')::numeric, 0),
                   0
                 )
               ), 0)
         FROM runs
        WHERE user_id = :user_id
          AND started_at >= :seit
          AND status IN ('queued', 'executing'))
      AS summe
    """
)
"""Was heute ausgegeben ist **und was zugesagt wurde**.

**Der Unterschied entscheidet, ob die Tagesgrenze eine Grenze ist.** Ein Blick
auf das bereits Verbuchte beantwortet die falsche Frage: Bei 4,99 € von 5,00 €
darf danach *jeder* neue Lauf in die Wolke, und zehn davon geben zusammen zehn
Laufbudgets aus. Gemeldet von einer Prüfung durch Codex, und der Befund stimmt:
Die Grenze war weich, und die Notiz daneben („höchstens ein Laufbudget
Überschreitung") war zu großzügig.

**Zwei Summanden, und die Trennung ist der Punkt.** Links steht, was
tatsächlich geflossen ist — aus dem Hauptbuch, also je Aufruf und mit
Zeitstempel. Rechts steht der **Rest** der Zusagen: Was ein laufender Lauf
noch ausgeben darf, ist sein Budget *abzüglich* dessen, was er schon verbraucht
hat. Ohne diese Subtraktion zählte derselbe Euro zweimal — einmal als Tatsache,
einmal als Zusage —, und die Grenze schlösse deutlich zu früh.

``GREATEST(…, 0)`` fängt den Lauf ab, der sein Budget bereits überschritten
hat: Er hat nichts mehr zuzusagen, aber auch nichts zurückzugeben.

Die Richtung bleibt die vorsichtige: Ein laufender Lauf gilt mit seinem vollen
Anspruch, nicht mit einer Schätzung dessen, was er noch braucht."""


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

    async def by_model_since(self, seit: datetime) -> list[dict[str, object]]:
        """Wofür das Geld draufgegangen ist — je Modell, Anbieter und Zweck."""
        async with self._engine.connect() as conn:
            zeilen = (
                await conn.execute(_JE_MODELL, {"user_id": self._user_id, "seit": seit})
            ).all()
        return [
            {
                "provider": z.provider,
                "model": z.model,
                "purpose": z.purpose,
                "calls": int(z.aufrufe),
                "cost_eur": Decimal(str(z.kosten)),
            }
            for z in zeilen
        ]

    async def _summe(self, anweisung: TextClause, seit: datetime) -> Decimal:
        async with self._engine.connect() as conn:
            summe = (
                await conn.execute(anweisung, {"user_id": self._user_id, "seit": seit})
            ).scalar_one()
        return Decimal(str(summe))


_EINTRAGEN = text(
    """
    INSERT INTO model_calls (
        user_id, run_id, provider, model, purpose,
        tokens_in, tokens_out, cached_tokens_in, cache_write_tokens_in, cost_eur
    ) VALUES (
        :user_id, :run_id, :provider, :model, :purpose,
        :tokens_in, :tokens_out, :cached_tokens_in, :cache_write_tokens_in, :cost_eur
    )
    """
)
"""``occurred_at`` steht **nicht** in der Liste.

Den Zeitstempel setzt die Spaltenvorgabe (``now()``), und das ist nach der
Lehre desselben Tages kein Detail: Was gegen eine Tagesgrenze verglichen wird,
gehört auf die Uhr, die auch vergleicht. Ein Wert aus dem Prozess hätte den
Tageswechsel wieder von zwei Uhren abhängig gemacht."""


class PostgresModelSpendStore:
    """Schreibt das Kostenhauptbuch. Erfüllt ``ModelSpendSink``.

    **Eigene Transaktion**, wie beim Audit-Log und aus demselben Grund: Ein
    Eintrag, der mit dem Request zurückgerollt wird, fehlt genau dann, wenn der
    Request nach einem bezahlten Modellaufruf scheitert. Die Richtung ist:
    lieber ein Eintrag zu viel als einer zu wenig — bezahlt ist bezahlt.

    **Nicht an einen Nutzer gebunden**, anders als der Leser: Wem ein Aufruf
    gehört, steht im ``SpendContext``, und der kommt vom Model Gateway aus dem
    Lauf. Das Gateway wird einmal je Prozess gebaut und kennt keine Sitzung —
    eine Bindung beim Verdrahten wäre hier also gar nicht möglich, und ein
    Feld im Anfrageobjekt wäre die Lücke, gegen die der Port geschnitten ist.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def record(
        self,
        context: SpendContext,
        *,
        provider: str,
        model: str,
        usage: ModelUsage,
        cost_eur: Decimal,
    ) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                _EINTRAGEN,
                {
                    "user_id": context.user_id,
                    "run_id": context.run_id,
                    "provider": provider,
                    "model": model,
                    "purpose": context.purpose,
                    "tokens_in": usage.tokens_in,
                    "tokens_out": usage.tokens_out,
                    "cached_tokens_in": usage.cached_tokens_in,
                    "cache_write_tokens_in": usage.cache_write_tokens_in,
                    "cost_eur": cost_eur,
                },
            )


_JE_MODELL = text(
    """
    SELECT provider, model, purpose,
           COUNT(*) AS aufrufe,
           COALESCE(SUM(cost_eur), 0) AS kosten
      FROM model_calls
     WHERE user_id = :user_id
       AND occurred_at >= :seit
     GROUP BY provider, model, purpose
     ORDER BY kosten DESC, model ASC
    """
)
"""Die Frage, für die es das Hauptbuch überhaupt gibt: **wofür**.

Sortiert nach Kosten, weil die Antwort in der ersten Zeile stehen soll.
``model`` als zweiter Schlüssel, damit die Reihenfolge bei gleichen Kosten
bestimmt ist — sonst wechselt eine Übersicht bei jedem Aufruf ihr Aussehen."""
