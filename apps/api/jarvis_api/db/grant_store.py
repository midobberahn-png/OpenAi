"""Grant-Verbrauch auf PostgreSQL.

Erfüllt ``GrantConsumer``. Die Einmaligkeitszusage liegt in der ``WHERE``-
Klausel und nicht in einer Prüfung davor — dieselbe Bauart wie der
Nonce-Verbrauch und der Ausführungsanspruch der Bestätigung. Ein
``SELECT … if consumed_at is None: UPDATE …`` wäre bei zwei gleichzeitigen
Anfragen ein Doppelverbrauch, und genau dieser Fall ist der interessante.

Warum die Invokationszeile und keine eigene Tabelle: ``invocation_id`` steht
schon im Grant, die Zeile wird vom Executor **vor** der Ausführung angelegt
(``InvocationStore.record()``), und ``pending_actions.invocation_id`` verweist
bereits darauf. Eine zweite Tabelle wäre ein zweiter Ort für dieselbe Wahrheit.

Fehlt die Zeile, liefert das UPDATE nichts und der Verbrauch scheitert. Das ist
beabsichtigt: Ein Grant, dessen Invokation nie protokolliert wurde, gehört zu
keinem nachvollziehbaren Aufruf.

**Eine eigene Transaktion, und warum das der Kern ist.**

Die erste Fassung nahm die Verbindung des laufenden Requests entgegen. Das
UPDATE war unter Nebenläufigkeit korrekt — nur eben nicht dauerhaft: Es lag in
derselben offenen Transaktion, in der anschließend der Handler nach außen
wirkte. Die vierte externe Prüfrunde hat die Lücke benannt und ein Test gegen
echtes PostgreSQL hat sie gezeigt:

    consume() → UPDATE consumed_at   (nicht committed)
    Handler   → Mail ist verschickt  (nicht zurückholbar)
    Absturz vor dem Commit
    PostgreSQL rollt zurück          → consumed_at wieder NULL
    Retry legt denselben Grant vor   → die Mail geht ein zweites Mal hinaus

Atomar und dauerhaft sind zwei verschiedene Zusagen. Das bedingte UPDATE trägt
die erste; für die zweite muss der Anspruch **vor** dem Handler committed sein.
Deshalb nimmt dieser Verbraucher eine ``AsyncEngine`` und öffnet seine eigene
kurze Transaktion, die beim Verlassen committet. Der Anspruch überlebt damit
den Verlust der Verbindung, aus der er angefordert wurde.

Der Typ ist die Absicherung: Eine ``AsyncConnection`` lässt sich hier nicht
mehr übergeben. Wer die Request-Verbindung hereinreichen wollte — der Weg, der
in die Lücke führte —, scheitert an der Signatur und nicht erst an einem Test,
den jemand schreiben müsste.

**Was die eigene Transaktion vom Aufrufer verlangt.**

1. **Die Invokationszeile muss committed sein.** Eine getrennte Transaktion
   sieht keine uncommitteten Zeilen. Steht ``record()`` noch in der offenen
   Request-Transaktion, findet das UPDATE nichts und der Verbrauch scheitert.
   Die Richtung stimmt — abgewiesen, nicht durchgewunken —, aber die Ursache
   ist dann eine Reihenfolge und kein Angriff. ``InvocationStore.record()``
   gehört deshalb vor die Ausführung **und** vor deren Commit.

2. **Die Request-Transaktion darf dieselbe Zeile vorher nicht sperren.** Hat
   sie die committed Zeile bereits geändert, wartet das UPDATE hier auf einen
   Commit, der erst nach der Rückkehr dieses Aufrufs kommt — ein Stillstand,
   den die Verklemmungserkennung von PostgreSQL nicht auflöst, weil das Warten
   in der Anwendung liegt. Im Executor liegt ``mark()`` nach der Ausführung;
   diese Reihenfolge ist Voraussetzung und keine Nebensächlichkeit.

3. **Der Verbindungspool braucht Luft.** Während des Anspruchs hält der Request
   seine Verbindung und dieser Verbraucher eine zweite. Die Transaktion hier
   ist kurz — ein UPDATE, dann Commit —, aber sie ist nicht keine.

Die Semantik bleibt **höchstens einmal**: Stirbt der Prozess zwischen Commit
und Handler, ist der Grant verbraucht und die Aktion vielleicht nicht
geschehen. Das ist die gewollte Richtung. Für Aufrufe, deren Ergebnis über das
Netz unklar bleibt, gehört zusätzlich ein Idempotency-Key auf die Seite des
Anbieters — der Anspruch hier schützt vor der zweiten Ausführung, nicht vor
einer unklaren ersten.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

__all__ = ["PostgresGrantConsumer"]


_CONSUME = text(
    """
    UPDATE tool_invocations
       SET consumed_at = :now
     WHERE id = :id
       AND consumed_at IS NULL
    RETURNING id
    """
)


class PostgresGrantConsumer:
    """Löst einen Grant genau einmal ein — über Prozessgrenzen und Abstürze hinweg."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        """Eine Engine und ausdrücklich keine Verbindung: Der Anspruch braucht
        eine Transaktion, die unabhängig von der des Requests committet."""

    async def consume(self, invocation_id: UUID, *, now: datetime) -> bool:
        async with self._engine.begin() as conn:
            result = await conn.execute(_CONSUME, {"id": invocation_id, "now": now})
            return result.first() is not None
        # ``begin()`` committet beim regulären Verlassen. Erst danach kehrt
        # dieser Aufruf zurück, und erst danach ruft die Registry den Handler.
