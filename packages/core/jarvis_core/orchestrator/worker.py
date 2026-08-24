"""Der Arbeiter: findet hängengebliebene Läufe und bringt sie weiter.

Die Wiederaufnahme war bis hierher gebaut und hatte **einen** Aufrufer: den
nächsten ``POST /runs/{id}/advance``. Wer denselben Lauf noch einmal anfasste,
bekam ihn zurück; wer es nicht tat, hatte einen Lauf, der bis in alle Ewigkeit
in ``executing`` stand. Niemand sah nach. Dieses Modul sieht nach.

**Was es dafür ausdrücklich nicht tut: orchestrieren.** Es sucht Läufe und ruft
für jeden ``RunAdvancer.advance()`` — dieselbe Reihenfolge *Anspruch → Wirkung
→ Festschreiben*, die auch über HTTP gilt, mitsamt Übernahme und
Protokollprüfung. Ein zweiter Ablauf neben dem ersten wäre die dritte Stelle,
an der diese Reihenfolge steht, und an genau dieser Grenze sind bereits zwei
Sicherheitslücken entstanden.

**Der Arbeiter hat keine Sitzung, und das ist eine Zusage und kein Mangel.**

Er übergibt ``session_id=None``. Ein Schritt, der eine Bestätigung braucht,
wird deshalb nicht ausgeführt, und es entsteht auch keine Bestätigung: Eine
Anfrage ist an die Sitzung gebunden, in der ihre Vorschau erschien — eine ohne
Sitzung könnte niemand einlösen, sie stünde in der Übersicht des Nutzers und
ließe den Lauf endgültig stehen. Der Schritt bleibt stattdessen unerledigt und
wiederholbar, bis ihn jemand angemeldet anstößt.

**Was der Arbeiter dagegen sehr wohl tut: wirken.** Ein Schritt, der ohne
Bestätigung durchginge, während ein Mensch zusieht, geht auch hier durch — der
Lauf wurde von einem Menschen begonnen, sein Plan war angekündigt, und der
Schritt war bereits beansprucht, als der Arbeiter abstürzte. Die Wiederaufnahme
führt zu Ende, was jemand angefangen hat; sie fängt nichts an.

Der Gegenentwurf wäre, jeden vom Arbeiter getriebenen Schritt als
unbeaufsichtigt zu behandeln (``PolicyRequest.trigger_is_supervised``). Er
klingt strenger und macht die Wiederaufnahme wertlos: Genau der Fall, für den
sie gebaut ist — ein hängengebliebenes ``calendar.create`` —, bräuchte dann
eine Bestätigung, die der Arbeiter nicht einholen kann. Die Beaufsichtigung ist
eine Eigenschaft der **Herkunft** eines Laufs, nicht dessen, wer den Rückstand
abarbeitet.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from datetime import timedelta

from jarvis_contracts import Run
from jarvis_core.orchestrator.advance import AdvanceRejected, RunAdvancer
from jarvis_core.orchestrator.recovery import DEFAULT_IDLE, DEFAULT_LEASE
from jarvis_core.ports.runs import RunStore

__all__ = ["RunWorker", "SweepReport", "SweepResult"]


@dataclass(frozen=True)
class SweepResult:
    """Was aus einem einzelnen Lauf wurde."""

    run_id: str
    outcome: str
    """``executed``, ``blocked``, ``awaiting_confirmation`` … oder die
    Ablehnungskennung des Ablaufs (``step-unresolved``, ``step-claimed``)."""

    detail: str


@dataclass(frozen=True)
class SweepReport:
    """Das Ergebnis eines Durchgangs — zum Mitschreiben, nicht zum Entscheiden.

    Ein Bericht und keine Kennzahl: Wer einen Arbeiter betreibt, muss sehen
    können, *warum* ein Lauf nicht weiterkam. „3 von 5 fortgesetzt" beantwortet
    genau die Frage nicht, die man dann stellt.
    """

    gefunden: int = 0
    fortgesetzt: int = 0
    ergebnisse: list[SweepResult] = field(default_factory=list)

    @property
    def liegen_geblieben(self) -> int:
        return self.gefunden - self.fortgesetzt


class RunWorker:
    """Ein Durchgang über die überfällig beanspruchten Läufe."""

    def __init__(
        self,
        *,
        runs: RunStore,
        advancer_for: Callable[[Run], AbstractAsyncContextManager[RunAdvancer]],
        lease: timedelta = DEFAULT_LEASE,
        idle: timedelta = DEFAULT_IDLE,
        batch: int = 20,
    ) -> None:
        self._runs = runs
        self._advancer_for = advancer_for
        """Eine Fabrik und kein fertiger Ablauf, weil der Werkzeugkatalog an
        einen **Eigentümer** gebunden werden muss: Der Kalender eines Laufs
        gehört ``run.user_id``, und ein Handler darf den Adressaten nicht
        benennen können. Ein für alle Läufe gemeinsamer ``RunAdvancer`` hieße
        ein Katalog, der niemandem gehört — oder schlimmer: allen.

        Und ein **Kontextmanager**, weil diese Zusammensetzung eine Lebensdauer
        hat: In der HTTP-Fassung ist es die Transaktion des Requests, die mit
        ihm endet und bei einer Ausnahme zurückrollt. Ein Lauf im Durchgang ist
        genau dasselbe, nur ohne Request — und ein Arbeiter, der eine
        Transaktion über alle Läufe hinweg offen hielte, machte aus jedem
        Fehler einen, der auch die anderen trifft."""

        self._lease = lease
        self._idle = idle
        """Wie lange ein begonnener Lauf stillstehen darf — die zweite Frist.

        Getrennt von ``lease``, weil sie eine andere Frage beantwortet; die
        Begründung steht bei ``DEFAULT_IDLE``."""

        self._batch = batch

    async def sweep(self) -> SweepReport:
        """Sucht überfällige Läufe und bringt jeden um höchstens einen Schritt weiter.

        **Einen Schritt, nicht bis zum Ende.** Ein Durchgang, der einen Lauf
        auslaufen ließe, hinge an einem einzelnen Lauf fest, während die
        übrigen warten — und die Dauer eines Durchgangs wäre nicht mehr
        abschätzbar. Der nächste Durchgang findet den Lauf wieder; er ist dann
        entweder weiter oder erneut überfällig.

        **Ein Fehler in einem Lauf beendet den Durchgang nicht.** Der Zweck
        dieses Arbeiters ist, dass etwas Steckengebliebenes weitergeht; ein
        Durchgang, den der erste kaputte Lauf abbricht, ließe alle dahinter für
        immer liegen. Deshalb wird hier breit gefangen — die einzige Stelle im
        Kern, an der das richtig ist, und sie ist deshalb auch die einzige.
        """
        kandidaten = await self._runs.stale_runs(
            frist=self._lease, idle=self._idle, limit=self._batch
        )
        bericht = SweepReport(gefunden=len(kandidaten))
        fortgesetzt = 0

        for lauf in kandidaten:
            ergebnis = await self._einen_schritt(lauf)
            bericht.ergebnisse.append(ergebnis)
            if ergebnis.outcome == "executed":
                fortgesetzt += 1

        return SweepReport(
            gefunden=bericht.gefunden, fortgesetzt=fortgesetzt, ergebnisse=bericht.ergebnisse
        )

    async def _einen_schritt(self, lauf: Run) -> SweepResult:
        try:
            async with self._advancer_for(lauf) as advancer:
                ausgang = await advancer.advance(
                    lauf,
                    # Kein Bestätigungskanal. Siehe Modulkopf — der Typ trägt
                    # die Zusage, nicht eine Prüfung an dieser Stelle.
                    session_id=None,
                    # Keine vorgegebenen Argumente: Es ist niemand da, der sie
                    # tippen könnte. Wo die Anfrage die Information enthält,
                    # trägt die Argumentquelle; wo nicht, scheitert der Schritt
                    # fail-closed und bleibt für den Nutzer liegen.
                    vorgegeben=None,
                )
        except AdvanceRejected as abgewiesen:
            return SweepResult(str(lauf.id), abgewiesen.code, abgewiesen.reason)
        except Exception as fehler:
            return SweepResult(str(lauf.id), "error", f"{type(fehler).__name__}: {fehler}")

        return SweepResult(str(lauf.id), ausgang.status, ausgang.reason)
