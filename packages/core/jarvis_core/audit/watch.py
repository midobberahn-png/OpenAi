"""Die Kette prüft sich selbst — und ein Fund hat eine Folge.

Siehe ADR-018 (docs/23-kettenbruch-adr.md).

Die Invariante ``audit-tamper-evident`` lautet „Manipulation ist
**erkennbar**". Sie war es auch: ``verify_chain`` rechnet nach, der Trigger
hält dagegen, Tests belegen beides. Nur hatte ``verify()`` genau einen
Aufrufer — einen Endpunkt, den niemand aufruft. Eine Prüfung, die niemand
liest, ist keine Prüfung; dieses Modul ist ihr Leser.

**Was hier eine Entscheidung ist und was nur Takt:** Die Entscheidung ist
``pruefen()`` — wann fällig, was ein Fund bedeutet, was einmal gemeldet wird
und was nicht mehr. Der Takt steht im Arbeiter
(``jarvis_api.worker.run_forever``). Dieselbe Trennung wie zwischen
``RunWorker`` und seiner Schleife: In der Schleife soll nichts stehen, was zu
prüfen wäre.

**Und gemeldet wird hier nichts.** Der Kern protokolliert an keiner Stelle —
er gibt einen Bericht zurück, und die Schicht darüber schreibt ihn ins
Protokoll. Deshalb trägt ``ChainReport`` auch einen fehlgeschlagenen
Schreibversuch als Feld und nicht als Logzeile: Was niemand zurückbekommt,
kann auch niemand prüfen.

**Warum ein eigener Port und nicht ``AuditSink``.** Der Prüfer liest die ganze
Kette *und* schreibt den Fund hinein. Beides in ``AuditSink`` zu legen hieße,
dem ``ToolExecutor`` — dem einzigen anderen Halter — das Lesen der gesamten
Audit-Historie mitzugeben. Nicht weil es ihm erlaubt wäre, sondern weil das
Objekt es könnte, und das ist bei jedem künftigen Handler die Einladung.
Dieselbe Überlegung wie beim Kalender, dessen Werkzeugseite kein
``list_events`` hat.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from jarvis_core.audit.chain import AuditEntry, ChainBreak

__all__ = [
    "CHAIN_BREAK_ACTION",
    "DEFAULT_AUDIT_INTERVAL",
    "ChainInspector",
    "ChainReport",
    "ChainWatch",
]

DEFAULT_AUDIT_INTERVAL = timedelta(hours=1)
"""Wie oft die ganze Kette nachgerechnet wird.

Ein eigener Takt neben dem des Laufdurchgangs (eine Minute), weil beide
verschiedene Fragen stellen: „hängt ein Lauf?" liest wenige Zeilen, „ist etwas
verändert worden?" liest alle. Eine Stunde ist die Größenordnung, in der ein
Fund noch früh genug kommt, um etwas zu bedeuten, und die Prüfung noch selten
genug läuft, um mit der Tabelle zu wachsen."""

CHAIN_BREAK_ACTION = "audit.chain-break"
"""Die Aktion, unter der ein Fund in der Kette selbst steht."""


class ChainInspector(Protocol):
    """Port des Prüfers: die Kette lesen, nachrechnen, den Fund anfügen."""

    async def verify(self, *, limit: int | None = None) -> list[ChainBreak]:
        """Prüft die Kette. Leere Liste heißt: unversehrt."""
        ...

    async def count(self, *, limit: int | None = None) -> int:
        """Wie viele Einträge die Prüfung gelesen hat."""
        ...

    async def append(self, entry: AuditEntry) -> bytes:
        """Schreibt einen Eintrag und gibt seinen ``entry_hash`` zurück."""
        ...


@dataclass(frozen=True)
class ChainReport:
    """Das Ergebnis einer Prüfung.

    ``geprueft`` steht daneben, weil „unversehrt" ohne die Anzahl nichts sagt:
    Über einer leeren Tabelle ist jede Kette unversehrt.
    """

    geprueft: int
    brueche: list[ChainBreak]
    gemeldet: bool
    """Ob dieser Durchgang einen Eintrag in die Kette geschrieben hat.

    Falsch auch dann, wenn Brüche vorliegen — nämlich bei denselben wie beim
    letzten Mal. Siehe ``ChainWatch``."""

    melde_fehler: str | None = None
    """Warum der Eintrag nicht geschrieben werden konnte, falls er es nicht wurde.

    Ein Fund, dessen Spur nicht geschrieben werden kann, ist der unangenehmste
    Ausgang — und der einzige, den niemand bemerkt, wenn er nur verschluckt
    wird. Der Halt steht davon unabhängig."""

    @property
    def unversehrt(self) -> bool:
        return not self.brueche


class ChainWatch:
    """Prüft die Audit-Kette in eigenem Takt und urteilt über den Fund.

    Ein Fund hält den Arbeiter an (``darf_wirken`` wird endgültig falsch) und
    steht danach in der Kette, die er betrifft. Die Begründung für beides steht
    in ADR-018.
    """

    def __init__(
        self,
        inspector: ChainInspector,
        *,
        intervall: timedelta = DEFAULT_AUDIT_INTERVAL,
    ) -> None:
        self._inspector = inspector
        self._intervall = intervall
        self._zuletzt: datetime | None = None
        self._gemeldete_zeilen: frozenset[int] = frozenset()
        """Welche Zeilen-IDs schon einen Eintrag ausgelöst haben.

        Prozesslokal und ausdrücklich nicht persistiert: Der Zweck ist, dass
        **eine** Manipulation nicht stündlich einen Eintrag erzeugt und das
        Audit-Log in ihr eigenes Rauschen verwandelt. Nach einem Neustart wird
        derselbe Fund einmal erneut geschrieben — das ist kein Verlust, sondern
        die Information, dass er einen Neustart überlebt hat."""

        self._gebrochen = False

    @property
    def darf_wirken(self) -> bool:
        """Ob der Arbeiter noch wirken darf.

        Einmal falsch, immer falsch: Es gibt keinen Weg zurück, der nicht durch
        eine Untersuchung führt, und ein Automat kann sie nicht führen.
        """
        return not self._gebrochen

    def faellig(self, jetzt: datetime | None = None) -> bool:
        """Ob eine Prüfung ansteht — beim ersten Mal immer."""
        if self._zuletzt is None:
            return True
        return (jetzt or datetime.now(UTC)) - self._zuletzt >= self._intervall

    async def pruefen(self, jetzt: datetime | None = None) -> ChainReport:
        """Rechnet die **ganze** Kette nach und zieht die Folgerung.

        Ohne ``limit``: Ein Ausschnitt beantwortet „ist seit Eintrag N etwas
        verändert worden?" — gefragt ist „ist irgendetwas verändert worden?".
        """
        moment = jetzt or datetime.now(UTC)
        self._zuletzt = moment

        brueche = await self._inspector.verify()
        geprueft = await self._inspector.count()

        if not brueche:
            return ChainReport(geprueft=geprueft, brueche=[], gemeldet=False)

        # Ab hier wirkt der Arbeiter nicht mehr — und zwar *bevor* der Eintrag
        # geschrieben wird. Ein Fehlschlag beim Schreiben darf den Halt nicht
        # verhindern; das Anfügen ist die Spur, nicht die Folge.
        self._gebrochen = True

        zeilen = frozenset(bruch.row_id for bruch in brueche)
        if zeilen <= self._gemeldete_zeilen:
            return ChainReport(geprueft=geprueft, brueche=brueche, gemeldet=False)

        fehler = await self._anfuegen(brueche, geprueft, moment)
        self._gemeldete_zeilen = self._gemeldete_zeilen | zeilen
        return ChainReport(
            geprueft=geprueft,
            brueche=brueche,
            gemeldet=fehler is None,
            melde_fehler=fehler,
        )

    async def _anfuegen(
        self, brueche: list[ChainBreak], geprueft: int, moment: datetime
    ) -> str | None:
        """Schreibt den Fund in die Kette, die er betrifft.

        In eine beschädigte Kette zu schreiben klingt verkehrt und ist es
        nicht: Das Anfügen hängt nicht vom Prüfen ab, und wer den Fund später
        entfernt, bricht die Kette ein zweites Mal. Ein Logeintrag hat diese
        Eigenschaft nicht.

        **Ein Fehlschlag hier wird zurückgegeben und nicht geworfen.** Der Halt
        steht bereits; eine Ausnahme an dieser Stelle beendete den Prozess und
        machte aus dem sichtbaren Zustand „läuft und wirkt nicht" den
        unsichtbaren „ist weg".
        """
        eintrag = AuditEntry(
            occurred_at=moment,
            actor="scheduler",
            action=CHAIN_BREAK_ACTION,
            resource="audit_log",
            details={
                "geprueft": geprueft,
                "brueche": len(brueche),
                "zeilen": sorted({bruch.row_id for bruch in brueche}),
                "gruende": sorted({bruch.reason for bruch in brueche}),
            },
        )
        try:
            await self._inspector.append(eintrag)
        except Exception as fehler:
            return f"{type(fehler).__name__}: {fehler}"
        return None
