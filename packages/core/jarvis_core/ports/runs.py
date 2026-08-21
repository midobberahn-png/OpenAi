"""Port der Laufpersistenz.

Ein ``Run`` ist das zentrale Ausführungsobjekt: Er trägt Kontamination,
Datenklasse, Budget und den Zwischenzustand, aus dem heraus eine Ausführung
wieder aufgenommen wird. Bis hierher lebte er ausschließlich im Arbeitsspeicher
des Orchestrators — die Tabelle existierte, der Weg dorthin nicht.

Drei Gründe, warum das nicht so bleiben konnte:

1. **Wiederaufnahme.** Ein Lauf, der eine Bestätigung erwartet, wartet auf
   einen Menschen. Das kann Minuten dauern oder bis morgen. Ein Zustand im
   Arbeitsspeicher überlebt weder den Neustart noch den zweiten Arbeitsprozess.
2. **Fremdschlüssel.** ``tool_invocations.run_id`` verweist auf ``runs``. Seit
   das Werkzeugprotokoll eigenständig committet, braucht es dort eine
   **committete** Zeile — nicht eine, die es im Arbeitsspeicher des Aufrufers
   gibt.
3. **Kontamination ist eine Eigenschaft des Laufs.** Sie steigt monoton und
   entscheidet mit, welche Werkzeuge noch zulässig sind. Läge sie nur im
   Prozess, wäre sie nach einem Neustart weg — und die Sperre mit ihr.

**Die Zusicherung beim Fortschreiben.**

``save()`` verlangt den Status, den der Aufrufer vorzufinden erwartet, und
schreibt nur, wenn er noch gilt. Der Grund ist derselbe wie beim Nonce-,
Ausführungs- und Grant-Anspruch: Ein ``load()`` … ``save()`` mit einer
Entscheidung dazwischen ist bei zwei Schreibern ein Überschreiben, und der
interessante Fall ist genau dieser. Ein Lauf, der bereits abgebrochen wurde,
darf nicht von einem langsameren Schreiber wieder auf „läuft" gesetzt werden.

Die Zusage liegt deshalb in der ``WHERE``-Klausel und nicht in einer Prüfung
davor. Was sie **nicht** leistet: Zwei Schreiber im selben Status überschreiben
einander weiterhin in den übrigen Feldern. Dagegen hülfe eine Version je
Zeile; solange ein Lauf von genau einem Arbeiter fortgeschrieben wird, ist der
Statusvergleich die Grenze, die trägt — und die falsche Annahme, es wäre mehr,
steht hier ausdrücklich nicht.

Abgegrenzt vom Zustandsautomaten: ``fsm.assert_transition()`` entscheidet, ob
ein Übergang **erlaubt** ist. Dieser Port entscheidet, ob die Zeile noch dort
steht, wo der Aufrufer sie vermutet. Das eine ist Policy, das andere
Nebenläufigkeit; sie an derselben Stelle zu prüfen hieße, zwei verschiedene
Fragen zu verwechseln.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from jarvis_contracts import Run, RunStatus

__all__ = ["RunNotStored", "RunStateConflict", "RunStore"]


class RunStateConflict(Exception):
    """Der Lauf stand nicht mehr in dem Status, den der Schreiber erwartete.

    Kein Programmierfehler und kein Angriff: der Normalfall bei zwei
    Schreibern. Eigene Klasse, weil der Aufrufer darauf sinnvoll reagieren kann
    — neu laden und die Entscheidung wiederholen —, während er bei einer
    Datenbankausnahme nichts Besseres tun kann als abbrechen.
    """


class RunNotStored(Exception):
    """Der Lauf existiert nicht (mehr).

    Getrennt von ``RunStateConflict``: „steht woanders" und „ist nicht da" sind
    verschiedene Lagen. Die erste lädt man neu, die zweite nicht.
    """


class RunStore(Protocol):
    """Persistenz der Läufe."""

    async def create(self, run: Run) -> None:
        """Legt den Lauf an — **bevor** der erste Schritt wirkt.

        Muss committed sein, wenn der Aufruf zurückkehrt: Das
        Werkzeugprotokoll schreibt in einer eigenen Transaktion und braucht die
        Zeile als Fremdschlüssel. Eine, die nur in der Transaktion des
        Aufrufers existiert, gibt es für es nicht.
        """
        ...

    async def load(self, run_id: UUID) -> Run | None:
        """Liest den Lauf, oder ``None``.

        ``None`` und keine Ausnahme: Ein unbekannter Lauf ist eine gewöhnliche
        Antwort auf eine Abfrage, kein Fehler.
        """
        ...

    async def list_for_user(self, user_id: UUID, *, limit: int = 50) -> list[Run]:
        """Die Läufe eines Nutzers, neueste zuerst.

        Der Nutzer ist Pflichtparameter und nicht Filter: Es gibt keine
        Signatur, mit der sich *alle* Läufe abfragen ließen. Eine Übersicht,
        die den Eigentümer optional führt, ist eine Zeile Code davon entfernt,
        fremde Läufe zu zeigen.
        """
        ...

    async def save(self, run: Run, *, erwarteter_status: RunStatus) -> None:
        """Schreibt den Lauf fort, sofern er noch im erwarteten Status steht.

        Der Status wird ausdrücklich übergeben und nicht ``run.status``
        entnommen: Der übergebene Lauf trägt bereits den **neuen** Status, und
        ein Vergleich eines Wertes mit sich selbst prüft nichts. Dieselbe
        Überlegung wie bei ``ToolRegistry.execute()``, die ``run_id`` und
        ``user_id`` vom Aufrufer verlangt, statt sie dem Grant zu entnehmen.

        Wirft ``RunStateConflict``, wenn die Zeile inzwischen woanders steht,
        und ``RunNotStored``, wenn es sie nicht gibt.
        """
        ...

    async def claim_step(self, run_id: UUID, seq: int, *, erwarteter_status: RunStatus) -> bool:
        """Beansprucht einen Planschritt — **bevor** er wirkt.

        Der Anspruch aus einem externen Prüfbefund, und er sitzt an derselben
        Achse wie der Grant-Verbrauch: *Wo entsteht die Wirkung, und wie weit
        ist der Anspruch davon entfernt?*

        Bei ``save()`` ist er einen Schritt zu **spät**. Zwei Requests laden
        denselben Lauf, führen beide aus, und erst danach verliert einer am
        Compare-and-set. Gemessen: sechs parallele Aufrufe eines geplanten
        ``calendar.create`` ergaben sechs Termine — fünf Aufrufer bekamen „neu
        laden und wiederholen", während ihr Termin bereits im Kalender stand.

        **Zwei Zusagen, und beide sind nötig** (die Lehre aus dem vierten
        Replay-Pfad):

        * *Atomar* — genau einer gewinnt. Ein bedingtes ``UPDATE`` trägt das.
        * *Dauerhaft* — der Anspruch gilt, bevor die Wirkung beginnt. Dafür
          braucht er eine **eigene Transaktion**; läge er in der des Requests,
          gäbe ein Absturz nach dem Seiteneffekt ihn zurück. Implementierungen
          nehmen deshalb eine ``AsyncEngine`` und keine Verbindung.

        ``False`` heißt „ein anderer war schneller" und ist keine Ausnahme: Es
        ist der Normalfall bei zwei Schreibern, und der Aufrufer kann sinnvoll
        darauf reagieren.

        **Die Richtung ist höchstens einmal.** Stürzt der Prozess zwischen
        Anspruch und Ausführung ab, bleibt der Schritt beansprucht und der Lauf
        stehen. Das ist gewollt: Ein Termin, der vielleicht nicht angelegt
        wurde, lässt sich erneut anstoßen; einer, der zweimal im Kalender
        steht, nicht. Der Weg zurück ist die Wiederaufnahme abgebrochener
        Läufe.
        """
        ...

    async def release_step(self, run_id: UUID) -> None:
        """Gibt den Anspruch zurück, ohne den Schritt als erledigt zu führen.

        Für den folgenlos gescheiterten Versuch: Argumente passen nicht zum
        Schema, das Modell liefert nichts, die Policy weist ab. Nichts ist
        geschehen, und derselbe Schritt muss erneut versucht werden können.

        Ohne diesen Weg wäre der Anspruch keine Absicherung, sondern eine
        Sperre — und eine Sperre, die man nicht mehr loswird, ist schlimmer als
        der doppelte Termin, den sie verhindern soll.
        """
        ...
