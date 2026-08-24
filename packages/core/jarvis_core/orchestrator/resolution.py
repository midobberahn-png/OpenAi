"""Der Ausgang aus ``ENTSCHEIDUNG NÖTIG`` — und warum ihn ein Mensch nimmt.

Die Wiederaufnahme hat einen Zustand, aus dem es bisher kein Zurück gab. Sie
erzeugt ihn absichtlich: Ist die Frist eines Schrittes abgelaufen und schließt
das Werkzeugprotokoll eine Wirkung **nicht** aus, dann darf kein Automat
wiederholen. Der Anspruch wird übernommen und **gehalten**, und der Lauf steht.

Das ist sicherheitstechnisch richtig und war betrieblich eine Sackgasse: Es gab
keinen Übergang heraus. Kein Endpunkt, keine Oberfläche, keine Entscheidung.
Ein Termin, der vielleicht im Kalender steht, blockierte den Lauf für immer.

**Genau drei Entscheidungen, und sie stehen hier als Aufzählung.** Ein
allgemeines „setze den Status auf X" wäre der bequemere Weg und die Umkehrung
des Zustandsautomaten: Wer von außen einen Zielzustand nennen darf, hat die
Übergänge abgeschafft, die ihn schützen sollten.

**Warum das eine Sicherheitsgrenze ist und nicht bloß eine Schaltfläche.**
Der Entscheidende hebt eine Sperre auf, die einen doppelten Seiteneffekt
verhindert. Vier Bedingungen tragen sie, und keine ist entbehrlich:

* **Eigentümer** — der Lauf gehört ihm. Der Weg dorthin ist die Sitzung
  (``identity-derives-from-session``); die Kante nimmt keine Nutzerkennung
  entgegen.
* **Vermerk** — es steht überhaupt eine Entscheidung an. Ohne ihn ist der
  Schritt entweder in Ordnung oder läuft gerade; beides ist am Protokoll
  allein nicht zu erkennen, und deshalb wird der Befund persistiert
  (``RunState.unresolved_step``).
* **Fencing** — entschieden wird gegen **den Anspruch, den der Entscheidende
  vor sich sieht**. Ohne diese Bedingung löste eine Browserseite mit
  veraltetem Zustand einen Vorgang auf, den es so nicht mehr gibt: Läuft die
  Frist erneut ab, übernimmt der nächste Durchgang den Schritt und vergibt ein
  **neues** Token — die Lage ist dann eine andere, auch wenn sie gleich
  aussieht.
* **Atomar** — die Prüfung steht in derselben Anweisung, die schreibt. Die
  Freigabe des Anspruchs *ist* die Bedingung des ``UPDATE``, und damit gewinnt
  von zwei gleichzeitigen Entscheidungen genau eine. Eine zweite Entscheidung
  über denselben Vorgang trifft die Zeile nicht mehr.

**Was dieses Modul ausdrücklich nicht kann: nachsehen.** Es weiß, was *versucht*
wurde — Werkzeug, Argumente, Zeit, Zustand —, und nicht, was draußen geschehen
ist. Die Entscheidung „noch einmal versuchen" kann deshalb doppelt wirken, und
das ist keine Schwäche der Umsetzung, sondern die Lage: Ohne Rückfrage beim
Zielsystem ist sie nicht auflösbar. Wer entscheidet, muss das wissen — die
Oberfläche sagt es, und die Spur hält fest, dass es gesagt wurde.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from jarvis_contracts import Run, RunState, RunStatus, StepOutcome
from jarvis_core.ports.runs import RunStore

__all__ = ["Resolution", "ResolutionDenied", "ResolutionOutcome", "StepResolver"]


class Resolution(StrEnum):
    """Was mit einem Schritt geschehen soll, dessen Wirkung unklar ist."""

    ERLEDIGT = "completed"
    """„Ich habe nachgesehen, es ist geschehen." Der Schritt wird abgeschlossen
    und der Lauf geht weiter.

    Die einzige der drei, die eine **Tatsachenbehauptung** enthält, und die
    einzige, die von außen bestätigt sein sollte. Das System kann sie nicht
    prüfen; es hält deshalb fest, dass sie von einem Menschen stammt — die
    Zusammenfassung des Schrittes sagt es, damit auch ein Modell im nächsten
    Schritt nicht mehr Gewissheit unterstellt, als es gibt."""

    WIEDERHOLEN = "retry"
    """„Versuch es noch einmal." Der Anspruch wird freigegeben, der Schritt ist
    wieder fällig.

    **Die Entscheidung mit dem Risiko.** Ist die erste Wirkung doch eingetreten,
    steht der Termin danach zweimal im Kalender. Genau davor schützt die
    Sperre, und wer sie aufhebt, tut es in Kenntnis der Lage."""

    ABBRECHEN = "abort"
    """„Lass es." Der Lauf endet in ``cancelled``.

    Nimmt nichts zurück: Was gewirkt hat, hat gewirkt. Der Weg dafür ist die
    Rücknahme (``POST /invocations/{id}/undo``), solange ihre Frist läuft, und
    sie ist eine eigene Entscheidung mit eigener Spur."""

    def __str__(self) -> str:
        return self.value


class ResolutionDenied(Exception):
    """Die Entscheidung wurde nicht angenommen.

    Fail closed und mit **einem** Text für alle Lagen: kein Vermerk, fremder
    Anspruch, schon entschieden. Die Unterscheidung nach außen zu tragen hieße,
    aus der Ablehnung eine Auskunft über den Zustand fremder Läufe zu machen —
    dieselbe Überlegung wie bei der Rücknahme.
    """


@dataclass(frozen=True)
class ResolutionOutcome:
    """Was aus der Entscheidung geworden ist."""

    resolution: Resolution
    seq: int
    run_status: RunStatus
    detail: str
    """Für Menschen und für die Spur — was entschieden wurde und was daraus
    folgt."""


class StepResolver:
    """Setzt genau eine der drei Entscheidungen um.

    Kein Zustandsautomat und keine zweite Orchestrierung: Die Übergänge sind
    dieselben, die der Ablauf ohnehin kennt (Schritt abschließen, Anspruch
    freigeben, Lauf beenden). Neu ist allein die **Bedingung**, unter der sie
    hier zulässig sind.
    """

    def __init__(self, *, runs: RunStore) -> None:
        self._runs = runs

    async def resolve(
        self, run: Run, *, decision: Resolution, claim_id: UUID, now: datetime
    ) -> ResolutionOutcome:
        """Löst den vermerkten Schritt auf — oder weist ab.

        ``claim_id`` kommt vom Aufrufer und **nicht** aus dem geladenen Lauf.
        Der Unterschied ist der ganze Zweck: Aus der Zeile gelesen vergliche
        die Prüfung einen Wert mit sich selbst. Der Aufrufer nennt das Token,
        das er vor sich gesehen hat, und wenn die Lage inzwischen eine andere
        ist, scheitert er daran — dieselbe Überlegung wie bei
        ``RunStore.save(erwarteter_status=...)``.
        """
        # **Diese Prüfung ist nicht die Zusage — sie ist die Auskunft.** Ob
        # das Token noch gilt, entscheidet das ``UPDATE`` unten, und zwar
        # gegen die Zeile statt gegen eine Kopie im Arbeitsspeicher. Gemessen:
        # Nimmt man den Vergleich hier heraus, fällt kein Test — nimmt man ihn
        # zusätzlich beim Schreiben heraus, fallen drei. Er steht hier, weil
        # eine Ablehnung mit Grund besser ist als ein Konflikt, und weil das
        # Fehlen des **Vermerks** ausschließlich hier auffällt.
        seq = run.state.unresolved_step
        if seq is None or run.state.claim_id is None or run.state.claim_id != claim_id:
            raise ResolutionDenied(
                "Für diesen Schritt steht keine Entscheidung (mehr) an. Neu laden und "
                "nachsehen, was daraus geworden ist."
            )

        if decision is Resolution.ERLEDIGT:
            neuer = run.model_copy(update={"state": self._verbucht(run, seq, now)})
            folge = (
                f"Schritt {seq} ist als erledigt verbucht — der Lauf geht weiter. "
                "Was der Schritt bewirkt hat, ist dem System weiterhin nicht bekannt."
            )
        elif decision is Resolution.WIEDERHOLEN:
            neuer = run.model_copy(update={"state": self._freigegeben(run)})
            folge = (
                f"Schritt {seq} ist wieder fällig. Sollte der erste Versuch doch "
                "gewirkt haben, wirkt der zweite ein zweites Mal."
            )
        else:
            neuer = run.model_copy(
                update={
                    "state": self._freigegeben(run),
                    "status": RunStatus.CANCELLED,
                    "finished_at": now,
                }
            )
            folge = (
                f"Der Lauf ist abgebrochen. Was Schritt {seq} bewirkt hat, bleibt "
                "bestehen — abbrechen nimmt nichts zurück."
            )

        # **Die Prüfung steht in der Anweisung, die schreibt.** ``claim_id``
        # geht als Fencing mit: Das ``UPDATE`` trifft die Zeile nur, solange
        # der Anspruch derselbe ist. Damit gewinnt von zwei gleichzeitigen
        # Entscheidungen genau eine, und eine zweite über denselben Vorgang
        # findet nichts mehr vor — der neue Zustand trägt keinen Anspruch.
        await self._runs.save(neuer, erwarteter_status=run.status, claim_id=claim_id)

        return ResolutionOutcome(
            resolution=decision, seq=seq, run_status=neuer.status, detail=folge
        )

    @staticmethod
    def _verbucht(run: Run, seq: int, now: datetime) -> RunState:
        return run.state.with_step_done(
            StepOutcome(
                seq=seq,
                ok=True,
                summary="Nach einer Unterbrechung als erledigt verbucht.",
                # **Auch das Modell soll hier nichts unterstellen.** Ein
                # folgender Schritt liest diese Zeile; stünde dort „erledigt",
                # rechnete er mit einem Ergebnis, das niemand kennt.
                model_view=(
                    "Dieser Schritt wurde nach einer Unterbrechung von der Person, "
                    "der der Lauf gehört, als erledigt verbucht. Sein Ergebnis ist "
                    "nicht bekannt."
                ),
                finished_at=now,
            )
        )

    @staticmethod
    def _freigegeben(run: Run) -> RunState:
        """Anspruch und Vermerk fallen gemeinsam.

        Getrennt wären sie ein Zustand, den ``RunState`` ohnehin wieder
        einsammelt — ein Vermerk ohne Anspruch ist bedeutungslos, weil gegen
        nichts mehr entschieden werden kann.
        """
        return run.state.model_copy(
            update={
                "current_step": None,
                "claim_id": None,
                "claimed_at": None,
                "unresolved_step": None,
            }
        )
