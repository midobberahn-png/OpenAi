"""Die Kettenprüfung — und was ein Fund auslöst.

Bis hierher war die Audit-Kette *erkennbar* manipulierbar: ``verify_chain``
rechnet nach, der Trigger hält dagegen, und der einzige Aufrufer der
Nachrechnung war ein Endpunkt, den niemand aufruft. Diese Suite prüft die
beiden Zusagen, die daraus eine Erkennung machen (ADR-018):

1. Es sieht jemand nach — in eigenem Takt, über die **ganze** Kette.
2. Ein Fund hat eine Folge: Der Arbeiter wirkt nicht mehr, und der Fund steht
   danach in der Kette, die er betrifft.

Was hier ausdrücklich **nicht** geprüft wird, ist die Verkettung selbst; die
hat ihre eigene Suite. Hier steht die Attrappe für die Datenbank, und sie
antwortet, was der Test ihr sagt — der echte Durchstich mit einer am Trigger
vorbei veränderten Zeile steht in ``tests/integration/test_audit_kette.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from jarvis_core.audit import (
    CHAIN_BREAK_ACTION,
    AuditEntry,
    ChainBreak,
    ChainWatch,
)

pytestmark = pytest.mark.security

JETZT = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)


def _bruch(row_id: int) -> ChainBreak:
    return ChainBreak(
        row_id=row_id,
        reason="Inhalt wurde nach dem Schreiben verändert",
        expected="aaaa",
        found="bbbb",
    )


class FakeInspector:
    """Antwortet, was der Test vorgibt — und schreibt mit, was ankommt."""

    def __init__(self, brueche: list[ChainBreak] | None = None, *, anzahl: int = 7) -> None:
        self.brueche = brueche or []
        self.anzahl = anzahl
        self.geschrieben: list[AuditEntry] = []
        self.limits: list[int | None] = []
        self.wirft: Exception | None = None

    async def verify(self, *, limit: int | None = None) -> list[ChainBreak]:
        self.limits.append(limit)
        return list(self.brueche)

    async def count(self, *, limit: int | None = None) -> int:
        return self.anzahl

    async def append(self, entry: AuditEntry) -> bytes:
        if self.wirft is not None:
            raise self.wirft
        self.geschrieben.append(entry)
        return b"\x00" * 32


class TestEineUnversehrteKette:
    async def test_der_bericht_sagt_wie_viel_geprueft_wurde(self) -> None:
        """„Unversehrt" ohne Anzahl ist keine Aussage: Eine leere Tabelle ist
        immer unversehrt."""
        wache = ChainWatch(FakeInspector(anzahl=42))

        bericht = await wache.pruefen(JETZT)

        assert bericht.unversehrt
        assert bericht.geprueft == 42

    async def test_es_wird_nichts_geschrieben(self) -> None:
        senke = FakeInspector()
        wache = ChainWatch(senke)

        await wache.pruefen(JETZT)

        assert senke.geschrieben == []

    async def test_der_arbeiter_darf_weiter_wirken(self) -> None:
        wache = ChainWatch(FakeInspector())

        await wache.pruefen(JETZT)

        assert wache.darf_wirken

    async def test_geprueft_wird_die_ganze_kette(self) -> None:
        """Ein Ausschnitt beantwortet „seit Eintrag N", gefragt ist „überhaupt"."""
        senke = FakeInspector()
        wache = ChainWatch(senke)

        await wache.pruefen(JETZT)

        assert senke.limits == [None]


class TestEinFundHatEineFolge:
    @pytest.mark.invariant("audit-chain-break-is-detected")
    async def test_der_arbeiter_wirkt_nicht_mehr(self) -> None:
        wache = ChainWatch(FakeInspector([_bruch(17)]))

        await wache.pruefen(JETZT)

        assert not wache.darf_wirken

    @pytest.mark.invariant("audit-chain-break-is-detected")
    async def test_der_fund_steht_in_der_kette(self) -> None:
        senke = FakeInspector([_bruch(17), _bruch(18)], anzahl=99)
        wache = ChainWatch(senke)

        bericht = await wache.pruefen(JETZT)

        assert bericht.gemeldet
        (eintrag,) = senke.geschrieben
        assert eintrag.action == CHAIN_BREAK_ACTION
        assert eintrag.actor == "scheduler"
        assert eintrag.details["zeilen"] == [17, 18]
        assert eintrag.details["geprueft"] == 99

    async def test_der_halt_gilt_auch_ohne_eintrag(self) -> None:
        """Der Halt ist die Folge, das Anfügen nur die Spur.

        Wäre es umgekehrt, hinge die Sicherheitszusage an einem Schreibvorgang
        in genau der Tabelle, deren Unversehrtheit gerade widerlegt wurde.
        """
        senke = FakeInspector([_bruch(17)])
        senke.wirft = RuntimeError("Tabelle nicht schreibbar")
        wache = ChainWatch(senke)

        bericht = await wache.pruefen(JETZT)

        assert not wache.darf_wirken
        assert not bericht.gemeldet
        assert bericht.melde_fehler is not None
        assert "RuntimeError" in bericht.melde_fehler

    async def test_einmal_gebrochen_bleibt_gebrochen(self) -> None:
        """Auch wenn die nächste Prüfung sauber meldet.

        Eine Kette, die wieder stimmt, heißt nicht, dass nichts geschehen ist —
        sie heißt, dass jemand nachgebessert hat. Zurück führt nur eine
        Untersuchung, und die kann ein Automat nicht führen.
        """
        senke = FakeInspector([_bruch(17)])
        wache = ChainWatch(senke)
        await wache.pruefen(JETZT)

        senke.brueche = []
        bericht = await wache.pruefen(JETZT + timedelta(hours=2))

        assert bericht.unversehrt
        assert not wache.darf_wirken


class TestDerselbeFundWirdNichtZurMeldung:
    async def test_zweimal_dieselben_zeilen_ergeben_einen_eintrag(self) -> None:
        """Sonst füllt eine einzige Manipulation die Kette stündlich mit sich selbst."""
        senke = FakeInspector([_bruch(17)])
        wache = ChainWatch(senke)

        erst = await wache.pruefen(JETZT)
        dann = await wache.pruefen(JETZT + timedelta(hours=1))

        assert erst.gemeldet
        assert not dann.gemeldet
        assert len(senke.geschrieben) == 1

    async def test_eine_neue_zeile_wird_gemeldet(self) -> None:
        """Ein zweiter Eingriff ist eine neue Information — auch nach dem Halt."""
        senke = FakeInspector([_bruch(17)])
        wache = ChainWatch(senke)
        await wache.pruefen(JETZT)

        senke.brueche = [_bruch(17), _bruch(23)]
        bericht = await wache.pruefen(JETZT + timedelta(hours=1))

        assert bericht.gemeldet
        assert len(senke.geschrieben) == 2
        assert senke.geschrieben[-1].details["zeilen"] == [17, 23]


class TestDerTakt:
    async def test_beim_ersten_mal_ist_immer_faellig(self) -> None:
        """Ein Bruch, der auf die erste volle Stunde wartet, obwohl der Prozess
        gerade hochkam, wäre eine selbst gewählte Verzögerung."""
        assert ChainWatch(FakeInspector()).faellig(JETZT)

    async def test_danach_erst_nach_dem_intervall(self) -> None:
        wache = ChainWatch(FakeInspector(), intervall=timedelta(hours=1))
        await wache.pruefen(JETZT)

        assert not wache.faellig(JETZT + timedelta(minutes=59))
        assert wache.faellig(JETZT + timedelta(hours=1))

    async def test_eine_gescheiterte_pruefung_bleibt_faellig(self) -> None:
        """**Die Umkehr einer Entscheidung, die falsch war.**

        Die erste Fassung verschob den Takt auch bei einem Fehlschlag — mit dem
        Argument, ein Fehlversuch je Minute sei kein Ersatz für einen je Stunde.
        Ein externes Review hat gezeigt, was das kostet: Nach einem einzigen
        Datenbankfehler galt die Prüfung eine Stunde lang als erledigt, und der
        Arbeiter wirkte in dieser Stunde weiter, ohne dass die Kette je
        nachgerechnet worden wäre. Ein Fail-open, eingebaut aus Sparsamkeit.

        Eine Abfrage je Minute ist der billigere Preis.
        """

        class Kaputt(FakeInspector):
            async def verify(self, *, limit: int | None = None) -> list[ChainBreak]:
                raise RuntimeError("keine Verbindung")

        wache = ChainWatch(Kaputt(), intervall=timedelta(hours=1))
        with pytest.raises(RuntimeError):
            await wache.pruefen(JETZT)

        assert wache.faellig(JETZT + timedelta(minutes=1)), (
            "Nach einem Fehlschlag muss die Prüfung fällig bleiben — sonst gilt sie "
            "als erledigt, ohne stattgefunden zu haben."
        )


class SpionRunStore:
    """Merkt sich, ob jemand nach überfälligen Läufen gefragt hat.

    Nur die eine Methode: Der Durchgang ruft ``stale_runs`` als Erstes, und
    genau das ist die Frage dieser Klasse — *hat* er? Ein vollständiger
    Speicher wäre hier mehr Nachbau als Nachweis.
    """

    def __init__(self) -> None:
        self.gefragt = 0

    async def stale_runs(
        self, *, frist: timedelta, idle: timedelta, limit: int = 20
    ) -> list[object]:
        self.gefragt += 1
        return []


class TestDerHaltVerhindertDasWirken:
    """Der Durchgang, nicht die Wache: Hier wird gemessen, was folgt.

    ``ChainWatch.darf_wirken`` ist eine Aussage; sie wird erst zur Zusage,
    wenn jemand sie liest. Diese Klasse ist der Nachweis, dass ihn jemand
    liest — der Durchgang steht deshalb in ``jarvis_api.worker`` als eigene
    Funktion und nicht als ``if`` in der Schleife.
    """

    def _arbeiter(self, speicher: SpionRunStore) -> object:
        from jarvis_core.orchestrator import RunWorker

        return RunWorker(
            runs=speicher,  # type: ignore[arg-type]
            advancer_for=lambda lauf: None,  # type: ignore[arg-type,return-value]
        )

    @pytest.mark.invariant("audit-chain-break-is-detected")
    async def test_nach_einem_bruch_findet_kein_durchgang_mehr_statt(self) -> None:
        from jarvis_api.worker import durchgang

        speicher = SpionRunStore()
        arbeiter = self._arbeiter(speicher)
        wache = ChainWatch(FakeInspector([_bruch(17)]))

        await durchgang(wache, arbeiter)  # type: ignore[arg-type]

        assert speicher.gefragt == 0

    @pytest.mark.invariant("audit-chain-break-is-detected")
    async def test_nach_einer_gescheiterten_pruefung_wird_nicht_gewirkt(self) -> None:
        """**Die Lücke, die das Review offengelegt hat — jetzt gemessen.**

        Der Fall stand zwischen zwei Tests und fiel deshalb durch: Der eine
        prüfte einen *erkannten* Bruch, der andere den Takt nach einem
        Fehlschlag. Was fehlte, war die Verbindung — scheitert die Prüfung,
        darf im selben Takt nichts gewirkt werden, und im nächsten wird sie
        erneut versucht.
        """
        from jarvis_api.worker import durchgang

        class Kaputt(FakeInspector):
            async def verify(self, *, limit: int | None = None) -> list[ChainBreak]:
                raise RuntimeError("keine Verbindung")

        speicher = SpionRunStore()
        arbeiter = self._arbeiter(speicher)
        wache = ChainWatch(Kaputt())

        with pytest.raises(RuntimeError):
            await durchgang(wache, arbeiter)  # type: ignore[arg-type]

        assert speicher.gefragt == 0, (
            "Es wurde gewirkt, obwohl die Kette nicht nachgerechnet werden konnte."
        )
        assert wache.faellig(JETZT + timedelta(minutes=1))

    async def test_ohne_bruch_laeuft_der_durchgang(self) -> None:
        """Die Gegenprobe — sonst belegte der Test oben auch einen Arbeiter,
        der grundsätzlich nichts tut."""
        from jarvis_api.worker import durchgang

        speicher = SpionRunStore()
        arbeiter = self._arbeiter(speicher)
        wache = ChainWatch(FakeInspector())

        await durchgang(wache, arbeiter)  # type: ignore[arg-type]

        assert speicher.gefragt == 1
