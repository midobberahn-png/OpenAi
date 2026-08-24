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

from datetime import timedelta
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

    async def stale_runs(self, *, frist: timedelta, idle: timedelta, limit: int = 20) -> list[Run]:
        """Läufe, die jemand aufgreifen sollte — **über alle Nutzer**.

        **Zwei Lagen, zwei Fristen, und sie sind verschieden.**

        * *Überfällig beansprucht* (``frist``): Jemand hat einen Schritt
          begonnen und ist nicht zurückgekommen. Ob dabei etwas gewirkt hat,
          weiß nur das Werkzeugprotokoll.
        * *Liegengeblieben* (``idle``): Ein Lauf steht **mitten im Plan** und
          hat keinen Anspruch — er wird nach jedem Schritt freigegeben. Wer den
          Browser schließt, während Schritt zwei von vier fällig ist,
          hinterlässt genau das. Hier ist nichts unklar: Der letzte Schritt ist
          sauber abgeschlossen, der nächste war nur nie dran.

        Die zweite Lage kam später dazu und ist die Kehrseite einer richtigen
        Entscheidung: Ein Lauf ohne Anspruch ist keine Wiederaufnahme. Für
        einen ``queued``-Lauf gilt das weiterhin — dort hat noch nichts
        stattgefunden, und ihn anzustoßen hieße, bei etwas zu handeln, das
        jemand vielleicht liegen gelassen hat. Sobald ein Schritt gelaufen ist,
        ist es kein Liegenlassen mehr, sondern ein halb erledigter Auftrag.

        Die einzige Signatur dieses Ports ohne ``user_id``, und sie braucht
        eine Begründung, weil ``list_for_user`` ausdrücklich das Gegenteil tut:
        Dort ist der Eigentümer Pflicht, damit eine Übersicht nicht eine Zeile
        Code davon entfernt ist, fremde Läufe zu zeigen.

        Hier geht es nicht um eine Übersicht. Ein Arbeiter, der hängende Läufe
        fortsetzt, **kann** keinen Nutzer nennen: Wessen Lauf abgestürzt ist,
        weiß er erst, nachdem er gesucht hat. Die Einschränkung liegt deshalb
        woanders — nicht auf dem Eigentümer, sondern auf dem Zustand: Geliefert
        wird ausschließlich, was überfällig beansprucht ist. Ein Lauf, an dem
        gerade gearbeitet wird, erscheint nicht, ein wartender nicht, ein
        abgeschlossener nicht.

        **Und die Auskunft berechtigt zu nichts.** Sie sagt, wo nachzusehen
        ist; ob übernommen werden darf, entscheidet die Frist in
        ``reclaim_step``, und ob gewirkt werden darf, das Werkzeugprotokoll.
        Der Eigentümer bleibt gebunden, wo er gebraucht wird: Der
        Werkzeugkatalog des Arbeiters wird an ``run.user_id`` gebunden, damit
        ein Handler gar nicht in einen fremden Kalender schreiben kann.

        ``limit`` ist Pflicht mit Vorgabe: Ein Durchgang, der beliebig viele
        Läufe aufgreift, hält die Datenbank fest und macht die Dauer eines
        Durchgangs unvorhersehbar.
        """
        ...

    async def save(
        self, run: Run, *, erwarteter_status: RunStatus, claim_id: UUID | None = None
    ) -> None:
        """Schreibt den Lauf fort, sofern er noch im erwarteten Status steht.

        Der Status wird ausdrücklich übergeben und nicht ``run.status``
        entnommen: Der übergebene Lauf trägt bereits den **neuen** Status, und
        ein Vergleich eines Wertes mit sich selbst prüft nichts. Dieselbe
        Überlegung wie bei ``ToolRegistry.execute()``, die ``run_id`` und
        ``user_id`` vom Aufrufer verlangt, statt sie dem Grant zu entnehmen.

        ``claim_id`` ist das Fencing-Token: Wer sich darauf beruft, schreibt nur,
        solange der Anspruch **noch seiner** ist. Das schützt nicht die Freigabe,
        sondern das Ergebnis — ein abgelaufener Arbeiter, dessen Schritt
        inzwischen neu vergeben wurde, überschriebe sonst die Arbeit des neuen.
        Der Statusvergleich fängt das nicht: Beide stehen in ``executing``, und
        ein Vergleich, der für beide gilt, unterscheidet sie nicht.

        ``None`` heißt „ich berufe mich auf keinen Anspruch" und darf deshalb
        nicht an einem fremden scheitern — sonst wäre der direkte
        Werkzeugschritt blockiert, sobald irgendein Planschritt läuft.

        Wirft ``RunStateConflict``, wenn die Zeile inzwischen woanders steht,
        und ``RunNotStored``, wenn es sie nicht gibt.
        """
        ...

    async def claim_step(
        self, run_id: UUID, seq: int, *, erwarteter_status: RunStatus
    ) -> UUID | None:
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

        Der Rückgabewert ist das **Fencing-Token** des Anspruchs, oder ``None``,
        wenn ein anderer schneller war. Keine Ausnahme: Zwei Schreiber sind der
        Normalfall, und der Aufrufer kann sinnvoll darauf reagieren.

        Warum eine Kennung und nicht ``True``: ``current_step`` sagt, **dass**
        ein Schritt beansprucht ist, nicht **von wem**. Solange nur der Inhaber
        freigibt, genügt das. Sobald eine Wiederaufnahme hängende Läufe neu
        vergibt, gibt es zwei Anwärter auf denselben Schritt — und dann ist „ist
        beansprucht?" die falsche Frage.

        **Die Richtung ist höchstens einmal.** Stürzt der Prozess zwischen
        Anspruch und Ausführung ab, bleibt der Schritt beansprucht und der Lauf
        stehen. Das ist gewollt: Ein Termin, der vielleicht nicht angelegt
        wurde, lässt sich erneut anstoßen; einer, der zweimal im Kalender
        steht, nicht. Der Weg zurück ist die Wiederaufnahme abgebrochener
        Läufe.
        """
        ...

    async def reclaim_step(
        self, run_id: UUID, seq: int, *, erwarteter_status: RunStatus, frist: timedelta
    ) -> UUID | None:
        """Übernimmt einen Anspruch, dessen Frist abgelaufen ist.

        Der Gegenpart zu ``claim_step``, und **bewusst eine zweite Methode**:
        Dort muss der Schritt frei sein, hier muss er belegt sein. Beides in
        einem Aufruf hieße, die Übernahme zum Nebeneffekt eines gewöhnlichen
        Anspruchs zu machen — sie soll eine benannte Entscheidung bleiben, die
        an der Aufrufstelle sichtbar ist.

        ``frist`` ist eine **Obergrenze für die Dauer eines Schrittes**, nicht
        ein Timeout. Der Unterschied entscheidet über den doppelten
        Seiteneffekt: Die Übernahme sperrt den alten Arbeiter vom Schreiben aus
        (sein Token gilt nicht mehr), sie hält ihn nicht davon ab, zu wirken.
        Wer die Frist zu knapp wählt, übernimmt Schritte, die noch laufen.

        Ob nach einer Übernahme überhaupt gewirkt werden darf, beantwortet
        diese Methode **nicht** — dafür ist das Werkzeugprotokoll da
        (``jarvis_core.orchestrator.recovery``). Sie stellt nur sicher, dass
        genau einer übernimmt und der Vorgänger ausgesperrt ist.

        Rückgabe ist das neue Fencing-Token, oder ``None``, wenn nicht
        übernommen wurde.
        """
        ...

    async def mark_unresolved(self, run_id: UUID, seq: int, claim_id: UUID) -> bool:
        """Vermerkt, dass dieser Schritt nur noch ein Mensch auflösen kann.

        Der Gegenstand ist ein **Befund** und keine Absicht: Die Frist war
        abgelaufen, der Anspruch ist übernommen, und das Werkzeugprotokoll
        schließt eine Wirkung nicht aus. Wer das errechnen wollte, bekäme es
        nicht hin — ein laufender Schritt sieht im Protokoll genauso aus, weil
        der Eintrag *vor* dem Handler entsteht. Nur wer die Frist geprüft hat,
        kann die beiden trennen, und geprüft wird sie in der Datenbank.

        ``claim_id`` ist das Fencing und nicht Buchhaltung: Vermerkt wird gegen
        **den Anspruch, den der Vermerkende hält**. Ohne diese Bedingung
        setzte ein langsamer Übernehmer den Vermerk auf einen Anspruch, der
        inzwischen einem anderen gehört — und ein Mensch entschiede später
        gegen einen Vorgang, den es so nicht mehr gibt.

        Rückgabe ``False``, wenn der Anspruch nicht mehr gilt. Keine Ausnahme:
        Das ist der Ausgang, den das Fencing herbeiführen soll, und der
        Aufrufer kann daraus nur eines schließen — die Lage hat sich geändert,
        und sein Urteil ist veraltet.
        """
        ...

    async def release_step(self, run_id: UUID, claim_id: UUID) -> None:
        """Gibt den Anspruch zurück, ohne den Schritt als erledigt zu führen.

        Für den folgenlos gescheiterten Versuch: Argumente passen nicht zum
        Schema, das Modell liefert nichts, die Policy weist ab. Nichts ist
        geschehen, und derselbe Schritt muss erneut versucht werden können.

        Ohne diesen Weg wäre der Anspruch keine Absicherung, sondern eine
        Sperre — und eine Sperre, die man nicht mehr loswird, ist schlimmer als
        der doppelte Termin, den sie verhindern soll.

        ``claim_id`` ist Pflicht und nicht optional: Eine bedingungslose
        Freigabe sieht harmlos aus und trifft, sobald es zwei Anwärter gibt,
        den fremden Anspruch. Der Parameter zwingt jeden Aufrufer, sich
        auszuweisen — auch den, der heute der einzige ist.
        """
        ...
